from __future__ import annotations

from pathlib import Path

import pytest

from agent.config import AgentSettings
from agent.state import CapabilityContext
from agent.state.database import StateDatabase
from agent.state.schemas import AgentReportInput, ChallengeDispatchInput, ChallengeImport
from agent.state.service import StateService


def settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AgentSettings:
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9000")
    monkeypatch.setenv("LLM_MODEL", "stub")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("AION_RUN_DURATION_MINUTES", "10")
    return AgentSettings(_env_file=None)


async def service_for(
    tmp_path: Path,
    *,
    flag_count: int = 0,
    correct_flag_count: int = 0,
) -> StateService:
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path / "workspace",
    )
    await service.initialize()
    await service.create_run(
        "run",
        challenges=[
            ChallengeImport(
                unique_code="challenge-a",
                description="a bounded test challenge",
                container_status="running",
                container_addr=["http://127.0.0.1:8000"],
                flag_count=flag_count,
                correct_flag_count=correct_flag_count,
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    return service


@pytest.mark.asyncio
async def test_bootstrap_is_default_and_can_be_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert settings(monkeypatch, tmp_path).bootstrap_enabled is True
    monkeypatch.setenv("AION_BOOTSTRAP_ENABLED", "false")
    assert settings(monkeypatch, tmp_path).bootstrap_enabled is False


@pytest.mark.asyncio
async def test_challenge_bootstrap_is_atomic_and_shared_reports_replay(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    assert created["bootstrap"]["enabled"] is True
    assert created["bootstrap"]["status"] == "queued"
    overview = await service.get_overview("run")
    bootstrap = next(
        item for item in overview["agents"] if item["agent_id"] == "execution-bootstrap"
    )
    assert bootstrap["kind"] == "bootstrap"
    assert bootstrap["priority"] == 100
    assert bootstrap["timeout_seconds"] is None
    assert bootstrap["task_key"] is None

    execution = await service.register_agent(
        "run",
        agent_id="execution-sibling",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="collect one fact",
    )
    await service.submit_report(
        "run",
        execution["agent_id"],
        CapabilityContext(
            run_id="run",
            agent_id=execution["agent_id"],
            role="execution",
            unique_code="challenge-a",
        ),
        AgentReportInput(status="completed", summary="sibling fact"),
    )
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id="execution-bootstrap",
        role="execution",
        unique_code="challenge-a",
    )
    update = await service.prepare_bootstrap_shared_update(
        "run", bootstrap_context
    )
    assert update is not None
    assert update["reports"][0]["summary"] == "sibling fact"
    replay = await service.prepare_bootstrap_shared_update(
        "run", bootstrap_context
    )
    assert replay is not None
    assert replay["replayed"] is True
    await service.acknowledge_bootstrap_shared_update(
        "run", bootstrap_context, int(update["through_sequence"])
    )
    assert await service.prepare_bootstrap_shared_update("run", bootstrap_context) is None
    await service.close()


@pytest.mark.asyncio
async def test_disabled_bootstrap_creates_no_execution_or_admission(tmp_path: Path) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
        bootstrap_enabled=False,
    )
    assert created["bootstrap"] == {"enabled": False, "agent_id": None, "status": None}
    overview = await service.get_overview("run")
    assert all(item["kind"] != "bootstrap" for item in overview["agents"])
    await service.close()


@pytest.mark.asyncio
async def test_empty_dispatch_creates_one_deterministic_followup_per_high_value_finding(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=created["bootstrap"]["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="http",
        source="system_http_response",
        content="confirmed vulnerability",
    )
    await service.submit_report(
        "run",
        bootstrap_context.agent_id,
        bootstrap_context,
        AgentReportInput.model_validate(
            {
                "status": "completed",
                "summary": "Bootstrap found a verified vulnerability",
                "findings": [
                    {
                        "summary": "Verified traversal",
                        "category": "vulnerability",
                        "confidence": 0.95,
                        "verification_status": "verified",
                        "evidence_refs": [evidence["evidence_ref"]],
                    },
                    {
                        "summary": "Low-value service note",
                        "category": "service",
                        "confidence": 0.99,
                        "verification_status": "verified",
                        "evidence_refs": [evidence["evidence_ref"]],
                    },
                    {
                        "summary": "Exact flag candidate",
                        "category": "flag",
                        "confidence": 0.99,
                        "verification_status": "verified",
                        "evidence_refs": [evidence["evidence_ref"]],
                    },
                    {
                        "summary": "Unbacked credential note",
                        "category": "credential",
                        "confidence": 0.99,
                    },
                ],
                "candidate_flag": "FLAG-123",
            }
        ),
    )
    challenge_context = CapabilityContext(
        run_id="run",
        agent_id="challenge",
        role="challenge",
        unique_code="challenge-a",
    )
    observed = await service.observe_challenge(
        "run", "challenge-a", challenge_context, max_reports=20
    )
    assert observed["report_count"] == 1

    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="follow up Bootstrap evidence", tasks=[]),
    )
    assert len(dispatched["admissions"]) == 1
    task_agent = next(
        item
        for item in (await service.get_overview("run"))["agents"]
        if item["agent_id"] == dispatched["admissions"][0]["agent_id"]
    )
    assert task_agent["kind"] == "exploit"
    assert task_agent["task_stage"] == "exploitation"
    assert task_agent["task_key"].startswith("bootstrap:finding:")
    assert task_agent["branch_key"].endswith(":exploitation")
    assert task_agent["context_refs"][0].startswith("finding:finding_")

    repeated = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="no duplicate follow-up", tasks=[]),
    )
    assert repeated["admissions"] == []
    await service.close()


@pytest.mark.asyncio
async def test_explicit_dispatch_tasks_take_precedence_over_bootstrap_fallback(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=created["bootstrap"]["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="http",
        source="system_http_response",
        content="candidate evidence",
    )
    await service.submit_report(
        "run",
        bootstrap_context.agent_id,
        bootstrap_context,
        AgentReportInput(
            status="completed",
            summary="candidate",
            findings=[
                {
                    "summary": "Candidate credential",
                    "category": "credential",
                    "confidence": 0.9,
                    "evidence_refs": [evidence["evidence_ref"]],
                }
            ],
        ),
    )
    challenge_context = CapabilityContext(
        run_id="run",
        agent_id="challenge",
        role="challenge",
        unique_code="challenge-a",
    )
    await service.observe_challenge("run", "challenge-a", challenge_context)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(
            summary="explicit different task",
            tasks=[{"objective": "test an independent branch", "task_key": "independent"}],
        ),
    )
    assert len(dispatched["admissions"]) == 1
    assert dispatched["admissions"][0]["task_key"] == "independent"
    assert dispatched["bootstrap_followup_task_count"] == 0
    overview = await service.get_overview("run")
    assert sum(
        item["task_key"] == "independent"
        for item in overview["agents"]
        if item["role"] == "execution"
    ) == 1
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_reactivates_after_report_and_stops_at_terminal_conditions(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path, flag_count=1)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    first_id = created["bootstrap"]["agent_id"]
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=first_id,
        role="execution",
        unique_code="challenge-a",
    )
    await service.submit_report(
        "run",
        first_id,
        bootstrap_context,
        AgentReportInput(status="completed", summary="one Bootstrap cycle"),
    )
    next_bootstrap = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="bootstrap-next",
    )
    assert next_bootstrap["enabled"] is True
    assert next_bootstrap["created"] is True
    assert next_bootstrap["agent_id"] != first_id
    assert next_bootstrap["status"] == "queued"

    await service.close_challenge("run", "challenge-a")
    stopped = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="must-not-start",
    )
    assert stopped == {
        "enabled": False,
        "agent_id": None,
        "status": None,
        "reason": "challenge_stopped",
    }
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_is_not_created_when_all_flags_are_already_submitted(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path, flag_count=1, correct_flag_count=1)
    created = await service.register_challenge_with_bootstrap(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    assert created["bootstrap"] == {
        "enabled": False,
        "agent_id": None,
        "status": None,
        "reason": "all_flags_submitted",
    }
    await service.close()
