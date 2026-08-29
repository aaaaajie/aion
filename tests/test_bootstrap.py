from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from sqlalchemy import func, select

from agent.config import AgentSettings
from agent.state import (
    BOOTSTRAP_CYCLE_TIMEOUT_SECONDS,
    BOOTSTRAP_SUCCESS_CRITERIA,
    CapabilityContext,
)
from agent.state.database import StateDatabase
from agent.state.errors import StateConflict, StatePermission
from agent.state.models import (
    AdmissionRecord,
    AgentRecord,
    ChallengeRecord,
    StateEventRecord,
)
from agent.state.schemas import AgentReportInput, ChallengeDispatchInput, ChallengeImport
from agent.state.blackboard import blackboard_content_digest
from agent.state.service import StateService
from agent.subagents.supervisor import AgentSupervisor


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


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
    clock: _Clock | None = None,
) -> StateService:
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path / "workspace",
        clock=clock or (lambda: datetime.now(timezone.utc)),
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
async def test_bootstrap_cycle_yield_preserves_lane_and_resets_route_budget(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    context = CapabilityContext(
        run_id="run", agent_id=bootstrap_id, role="execution", unique_code="challenge-a"
    )
    evidence = await service.persist_evidence(
        "run", context, evidence_type="observation", source="fixture", content="route"
    )
    for route_key in ("route-a", "route-b"):
        await service.submit_bootstrap_checkpoint(
            "run",
            bootstrap_id,
            context,
            route_key=route_key,
            summary=route_key,
            next_step="validate route",
            task_stage="validation",
            evidence_refs=[evidence["evidence_ref"]],
        )
    with pytest.raises(StateConflict, match="at most 2 checkpoints"):
        await service.submit_bootstrap_checkpoint(
            "run",
            bootstrap_id,
            context,
            route_key="route-c",
            summary="route-c",
            next_step="validate route",
            task_stage="validation",
            evidence_refs=[evidence["evidence_ref"]],
        )
    yielded = await service.yield_bootstrap_cycle(
        "run", bootstrap_id, context, summary="cycle yielded with two verified routes"
    )
    assert yielded["next_cycle"] == 1
    runtime = await service.get_agent_runtime("run", bootstrap_id)
    assert runtime["agent"]["agent_id"] == bootstrap_id
    assert runtime["agent"]["status"] == "running"
    assert runtime["agent"]["terminal_report_id"] is None
    assert runtime["agent"]["report_cursors"]["bootstrap_cycle"] == 1
    next_route = await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_id,
        context,
        route_key="route-c",
        summary="route-c",
        next_step="validate route",
        task_stage="validation",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert next_route["idempotent"] is False
    duplicate = await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_id,
        context,
        route_key="route-c",
        summary="different summary is still the same route",
        next_step="validate route",
        task_stage="validation",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert duplicate["idempotent"] is True
    await service.close()


@pytest.mark.asyncio
async def test_challenge_bootstrap_is_atomic_and_shared_reports_replay(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
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
    assert bootstrap["timeout_seconds"] == BOOTSTRAP_CYCLE_TIMEOUT_SECONDS
    assert bootstrap["success_criteria"] == list(BOOTSTRAP_SUCCESS_CRITERIA)
    assert bootstrap["task_key"] is None
    assert len(created["initial_executions"]) == 1
    assert created["initial_executions"][0]["kind"] == "recon"
    assert created["initial_executions"][0]["task_stage"] == "discovery"
    assert created["initial_executions"][0]["priority"] == 90
    assert created["initial_executions"][0]["timeout_seconds"] == 900
    assert created["initial_executions"][0]["task_key"] == "initial-recon"
    bootstraps = [
        item for item in overview["agents"] if item["kind"] == "bootstrap"
    ]
    assert len(bootstraps) == 1
    assert {item["agent_id"] for item in bootstraps} >= {"execution-bootstrap"}
    assert all(
        item["task_key"] is None
        and item["hypothesis_key"] is None
        and item["branch_key"] is None
        for item in bootstraps
    )

    execution = await service.register_agent(
        "run",
        agent_id="execution-sibling",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="collect one fact",
    )
    execution_context = CapabilityContext(
        run_id="run",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    sibling_evidence = await service.persist_evidence(
        "run",
        execution_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified sibling route",
    )
    await service.submit_execution_checkpoint(
        "run",
        execution["agent_id"],
        execution_context,
        summary="sibling fact",
        next_step="validate the sibling route",
        task_stage="validation",
        urgency="inform",
        evidence_refs=[sibling_evidence["evidence_ref"]],
    )
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=bootstraps[0]["agent_id"],
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
    for bootstrap in bootstraps[1:]:
        sibling_context = CapabilityContext(
            run_id="run",
            agent_id=bootstrap["agent_id"],
            role="execution",
            unique_code="challenge-a",
        )
        sibling_update = await service.prepare_bootstrap_shared_update(
            "run", sibling_context
        )
        assert sibling_update is not None
        assert sibling_update["reports"][0]["summary"] == "sibling fact"
        await service.acknowledge_bootstrap_shared_update(
            "run", sibling_context, int(sibling_update["through_sequence"])
        )
    restarted = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge-restart",
        bootstrap_agent_id="execution-bootstrap-restart",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller restart",
        bootstrap_prompt="bootstrap restart",
    )
    assert restarted["idempotent"] is True
    assert [item["task_key"] for item in restarted["initial_executions"]] == [
        "initial-recon"
    ]
    assert restarted["initial_executions"][0]["agent_id"] == created[
        "initial_executions"
    ][0]["agent_id"]
    await service.close()


@pytest.mark.asyncio
async def test_parallel_execution_checkpoint_reaches_bootstrap_without_ending_task(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    execution = await service.register_agent(
        "run",
        agent_id="execution-sibling",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="collect one high-value fact",
    )
    execution_context = CapabilityContext(
        run_id="run",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        execution_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified extraction-capable route",
    )
    saved = await service.submit_execution_checkpoint(
        "run",
        execution["agent_id"],
        execution_context,
        summary="Verified authenticated route can reach the Flag-producing endpoint",
        next_step="Replay the authenticated request and extract the exact Flag",
        task_stage="validation",
        urgency="interrupt",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert saved["terminal"] is False
    assert saved["idempotent"] is False
    runtime = await service.get_agent_runtime("run", execution["agent_id"])
    assert runtime["agent"]["terminal_report_id"] is None

    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=created["bootstrap"]["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    update = await service.prepare_bootstrap_shared_update(
        "run", bootstrap_context
    )
    assert update is not None
    assert update["reports"][0]["type"] == "execution_checkpoint"
    assert update["reports"][0]["urgency"] == "interrupt"
    assert update["reports"][0]["next_step"].startswith("Replay")

    repeated = await service.submit_execution_checkpoint(
        "run",
        execution["agent_id"],
        execution_context,
        summary="Verified authenticated route can reach the Flag-producing endpoint",
        next_step="Replay the authenticated request and extract the exact Flag",
        task_stage="validation",
        urgency="interrupt",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert repeated["idempotent"] is True
    await service.close()


def test_blackboard_content_digest_ignores_transport_fields_and_order() -> None:
    first = {
        "through_sequence": 10,
        "replayed": False,
        "reports": [
            {
                "report_ref": "report:a",
                "summary": "  verified route  ",
                "candidate_flag": "opaque-candidate",
            },
            {"report_ref": "report:b", "summary": "second"},
        ],
        "hints": [{"hint": "look here", "reason": "route"}],
    }
    second = {
        "through_sequence": 99,
        "report_cursor": 99,
        "replayed": True,
        "reports": [
            {"report_ref": "report:b", "summary": "second"},
            {
                "report_ref": "report:a",
                "summary": "verified route",
                "candidate_flag": "opaque-candidate",
            },
        ],
        "hints": [{"reason": "route", "hint": "look here"}],
    }
    assert blackboard_content_digest(first) == blackboard_content_digest(second)


@pytest.mark.asyncio
async def test_bootstrap_does_not_persist_repeated_empty_snapshot(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
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
    assert await service.prepare_bootstrap_shared_update("run", bootstrap_context) is None
    assert await service.prepare_bootstrap_shared_update("run", bootstrap_context) is None
    async with service.db.sessions() as session:
        count = await session.scalar(
            select(func.count(StateEventRecord.sequence)).where(
                StateEventRecord.run_id == "run",
                StateEventRecord.agent_id == created["bootstrap"]["agent_id"],
                StateEventRecord.event_type == "bootstrap_shared_snapshot",
            )
        )
    assert count == 0
    await service.close()


@pytest.mark.asyncio
async def test_challenge_deduplicates_same_compact_controller_snapshot(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    challenge_context = CapabilityContext(
        run_id="run",
        agent_id="challenge",
        role="challenge",
        unique_code="challenge-a",
    )
    first = await service.observe_challenge(
        "run", "challenge-a", challenge_context
    )
    second = await service.observe_challenge(
        "run", "challenge-a", challenge_context
    )
    assert first["reports"] == []
    assert second["reports"] == []
    await service.set_challenge_control_state("run", "challenge-a", "degraded")
    await service.observe_challenge("run", "challenge-a", challenge_context)
    async with service.db.sessions() as session:
        count = await session.scalar(
            select(func.count(StateEventRecord.sequence)).where(
                StateEventRecord.run_id == "run",
                StateEventRecord.agent_id == "challenge",
                StateEventRecord.event_type == "controller_snapshot",
            )
        )
    assert count == 2
    await service.close()


@pytest.mark.asyncio
async def test_interrupt_checkpoint_stops_stale_execution_siblings(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    caller = await service.register_agent(
        "run",
        agent_id="execution-caller",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="checkpoint route",
    )
    sibling = await service.register_agent(
        "run",
        agent_id="execution-stale",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="stale parallel route",
    )
    validation = await service.register_agent(
        "run",
        agent_id="execution-validation",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        task_stage="validation",
        mission="active validation route",
    )
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="http://127.0.0.1:9000",
            llm_model="stub",
            llm_api_key="test-key",
        ),
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        state_service=service,
    )
    supervisor.run_id = "run"
    await supervisor._stop_competing_executions(
        unique_code="challenge-a", exclude_agent_id=caller["agent_id"]
    )
    stale = await service.get_agent_runtime("run", sibling["agent_id"])
    assert stale["agent"]["status"] == "stopped"
    active_validation = await service.get_agent_runtime(
        "run", validation["agent_id"]
    )
    assert active_validation["agent"]["status"] not in supervisor.TERMINAL_AGENT_STATES
    bootstrap = await service.get_agent_runtime("run", created["bootstrap"]["agent_id"])
    assert bootstrap["agent"]["status"] not in supervisor.TERMINAL_AGENT_STATES
    await service.close()


@pytest.mark.asyncio
async def test_execution_checkpoint_dispatches_one_deterministic_followup(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    execution = await service.register_agent(
        "run",
        agent_id="execution-sibling",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="collect one high-value fact",
    )
    execution_context = CapabilityContext(
        run_id="run",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        execution_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified discovery route",
    )
    checkpoint = await service.submit_execution_checkpoint(
        "run",
        execution["agent_id"],
        execution_context,
        summary="Verified discovery route",
        next_step="Validate the route and extract the exact result",
        task_stage="discovery",
        urgency="interrupt",
        evidence_refs=[evidence["evidence_ref"]],
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
    assert observed["reports"][0]["payload"]["type"] == "execution_checkpoint"
    assert observed["reports"][0]["payload"]["urgency"] == "interrupt"
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="follow up execution checkpoint", tasks=[]),
    )
    assert len(dispatched["admissions"]) == 1
    followup = next(
        item
        for item in (await service.get_overview("run"))["agents"]
        if item["agent_id"] == dispatched["admissions"][0]["agent_id"]
    )
    assert followup["task_key"] == f"execution-checkpoint:{checkpoint['report_id']}"
    assert followup["task_stage"] == "validation"
    assert followup["kind"] == "verification"
    repeated = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="no duplicate checkpoint", tasks=[]),
    )
    assert repeated["admissions"] == []
    await service.close()


@pytest.mark.asyncio
async def test_discovery_interrupt_checkpoint_hands_off_origin_lane(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    caller = created["initial_executions"][0]
    sibling = await service.register_agent(
        "run",
        agent_id="execution-stale",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="stale discovery route",
    )
    validation = await service.register_agent(
        "run",
        agent_id="execution-validation",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        task_stage="validation",
        mission="active validation route",
    )
    caller_context = CapabilityContext(
        run_id="run",
        agent_id=caller["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        caller_context,
        evidence_type="observation",
        source="fixture",
        content="bounded route evidence",
    )
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="http://127.0.0.1:9000",
            llm_model="stub",
            llm_api_key="test-key",
        ),
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        state_service=service,
    )
    supervisor.run_id = "run"
    await supervisor._sync_nodes()
    supervisor._issue_capabilities()
    result = await supervisor.report_execution_checkpoint(
        caller["agent_id"],
        summary="verified route",
        next_step="validate the route",
        task_stage="discovery",
        urgency="interrupt",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert result["data"]["handoff_terminal"] is True
    assert (await service.get_agent_runtime("run", caller["agent_id"]))["agent"]["status"] == "completed"
    assert (await service.get_agent_runtime("run", sibling["agent_id"]))["agent"]["status"] == "stopped"
    assert (await service.get_agent_runtime("run", validation["agent_id"]))["agent"]["status"] not in supervisor.TERMINAL_AGENT_STATES

    challenge_context = CapabilityContext(
        run_id="run", agent_id="challenge", role="challenge", unique_code="challenge-a"
    )
    await service.observe_challenge(
        "run", "challenge-a", challenge_context, max_reports=20
    )
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput.model_validate({}),
    )
    assert len(dispatched["admissions"]) == 1
    assert dispatched["admissions"][0]["task_key"].startswith("execution-checkpoint:")
    await service.close()


@pytest.mark.asyncio
async def test_execution_checkpoint_resets_challenge_stagnation_clock(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = await service_for(tmp_path, clock=clock)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    execution = created["initial_executions"][0]
    context = CapabilityContext(
        run_id="run", agent_id=execution["agent_id"], role="execution", unique_code="challenge-a"
    )
    clock.value += timedelta(seconds=600)
    evidence = await service.persist_evidence(
        "run", context, evidence_type="observation", source="fixture", content="route"
    )
    await service.submit_execution_checkpoint(
        "run",
        execution["agent_id"],
        context,
        summary="verified route",
        next_step="validate route",
        task_stage="discovery",
        urgency="interrupt",
        evidence_refs=[evidence["evidence_ref"]],
    )
    async with service.db.sessions() as session:
        challenge_record = await session.get(ChallengeRecord, ("run", "challenge-a"))
    assert challenge_record is not None
    assert challenge_record.last_progress_at.replace(tzinfo=timezone.utc) == clock.value
    assert challenge_record.stagnation_level == 0
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_shared_update_filters_low_value_reports_and_bounds_snapshot(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
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
    low = await service.register_agent(
        "run",
        agent_id="execution-low",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="collect a routine service note",
    )
    low_context = CapabilityContext(
        run_id="run",
        agent_id=low["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    await service.submit_report(
        "run",
        low["agent_id"],
        low_context,
        AgentReportInput(
            status="completed",
            summary="routine reconnaissance summary",
            findings=[
                {
                    "summary": "service note",
                    "category": "service",
                    "confidence": 0.99,
                    "verification_status": "verified",
                }
            ],
        ),
    )
    assert await service.prepare_bootstrap_shared_update("run", bootstrap_context) is None
    low_runtime = await service.get_agent_runtime("run", created["bootstrap"]["agent_id"])
    assert low_runtime["agent"]["report_cursors"]["bootstrap_shared"] > 0

    high = await service.register_agent(
        "run",
        agent_id="execution-high",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="verify one route",
    )
    high_context = CapabilityContext(
        run_id="run",
        agent_id=high["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        high_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified high-value route",
    )
    await service.submit_execution_checkpoint(
        "run",
        high["agent_id"],
        high_context,
        summary="x" * 1_500,
        next_step="y" * 1_500,
        task_stage="validation",
        urgency="inform",
        evidence_refs=[evidence["evidence_ref"]],
    )
    update = await service.prepare_bootstrap_shared_update(
        "run", bootstrap_context, max_chars=1_000
    )
    assert update is not None
    assert len(json.dumps(update, ensure_ascii=False)) <= 1_000
    assert [item["type"] for item in update["reports"]] == ["execution_checkpoint"]
    assert update["reports"][0]["findings"] == []
    await service.acknowledge_bootstrap_shared_update(
        "run", bootstrap_context, int(update["through_sequence"])
    )
    assert await service.prepare_bootstrap_shared_update("run", bootstrap_context) is None

    finding_agent = await service.register_agent(
        "run",
        agent_id="execution-finding",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="verify one vulnerability",
    )
    finding_context = CapabilityContext(
        run_id="run",
        agent_id=finding_agent["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    finding_evidence = await service.persist_evidence(
        "run",
        finding_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified vulnerability evidence",
    )
    await service.submit_report(
        "run",
        finding_agent["agent_id"],
        finding_context,
        AgentReportInput(
            status="completed",
            summary="verified vulnerability and routine service note",
            findings=[
                {
                    "summary": "verified vulnerability",
                    "category": "vulnerability",
                    "confidence": 0.95,
                    "verification_status": "verified",
                    "evidence_refs": [finding_evidence["evidence_ref"]],
                },
                {
                    "summary": "routine service note",
                    "category": "service",
                    "confidence": 0.99,
                    "verification_status": "verified",
                    "evidence_refs": [finding_evidence["evidence_ref"]],
                },
            ],
        ),
    )
    finding_update = await service.prepare_bootstrap_shared_update(
        "run", bootstrap_context
    )
    assert finding_update is not None
    assert [
        item["category"] for item in finding_update["reports"][0]["findings"]
    ] == ["vulnerability"]
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_checkpoint_is_non_terminal_and_dispatches_once(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=bootstrap_id,
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="observation",
        source="local_fixture",
        content="verified route evidence",
    )
    before = await service.get_agent_runtime("run", bootstrap_id)
    async with service.db.sessions() as session:
        before_admission = await session.scalar(
            select(AdmissionRecord).where(AdmissionRecord.agent_id == bootstrap_id)
        )
        assert before_admission is not None
        before_admission_status = before_admission.status
    saved = await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_id,
        bootstrap_context,
        route_key="verified.route",
        summary="A verified extraction-capable route",
        next_step="Validate the narrowest route step and extract the exact result",
        task_stage="validation",
        evidence_refs=[evidence["evidence_ref"]],
    )
    after = await service.get_agent_runtime("run", bootstrap_id)
    assert saved["status"] == "working"
    assert saved["idempotent"] is False
    assert saved["terminal"] is False
    assert after["agent"]["status"] == before["agent"]["status"]
    assert after["agent"]["terminal_report_id"] is None
    async with service.db.sessions() as session:
        after_admission = await session.scalar(
            select(AdmissionRecord).where(AdmissionRecord.agent_id == bootstrap_id)
        )
        assert after_admission is not None
        assert after_admission.status == before_admission_status

    challenge_context = CapabilityContext(
        run_id="run",
        agent_id="challenge",
        role="challenge",
        unique_code="challenge-a",
    )
    observed = await service.observe_challenge(
        "run", "challenge-a", challenge_context, max_reports=20
    )
    checkpoint = observed["reports"][0]["payload"]
    assert checkpoint["type"] == "bootstrap_checkpoint"
    assert checkpoint["route_key"] == "verified.route"
    assert checkpoint["next_step"].startswith("Validate the narrowest")

    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="handoff verified Bootstrap route", tasks=[]),
    )
    assert len(dispatched["admissions"]) == 1
    overview = await service.get_overview("run")
    followup = next(
        item
        for item in overview["agents"]
        if item["agent_id"] == dispatched["admissions"][0]["agent_id"]
    )
    assert followup["task_key"] == "bootstrap-checkpoint:verified.route"
    assert followup["branch_key"] == "bootstrap:verified.route:handoff"
    assert followup["task_stage"] == "validation"
    assert followup["context_refs"][0].startswith("report:report_")

    repeated_checkpoint = await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_id,
        bootstrap_context,
        route_key="verified.route",
        summary="same route replay",
        next_step="same next step",
        task_stage="validation",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert repeated_checkpoint["idempotent"] is True
    repeated_dispatch = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge_context,
        ChallengeDispatchInput(summary="do not duplicate route", tasks=[]),
    )
    assert repeated_dispatch["admissions"] == []

    second_checkpoint = await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_id,
        bootstrap_context,
        route_key="second.route",
        summary="second route",
        next_step="second next step",
        task_stage="exploitation",
        evidence_refs=[evidence["evidence_ref"]],
    )
    assert second_checkpoint["idempotent"] is False
    with pytest.raises(StateConflict, match="at most 2"):
        await service.submit_bootstrap_checkpoint(
            "run",
            bootstrap_id,
            bootstrap_context,
            route_key="third.route",
            summary="third route",
            next_step="third next step",
            task_stage="validation",
            evidence_refs=[evidence["evidence_ref"]],
        )
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_checkpoint_rejects_non_bootstrap_agents(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    execution = await service.register_agent(
        "run",
        agent_id="execution-sibling",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="bounded execution",
    )
    execution_context = CapabilityContext(
        run_id="run",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="challenge-a",
    )
    with pytest.raises(StatePermission, match="Only a Bootstrap"):
        await service.submit_bootstrap_checkpoint(
            "run",
            execution["agent_id"],
            execution_context,
            route_key="normal.execution",
            summary="not allowed",
            next_step="not allowed",
            task_stage="validation",
            evidence_refs=["evidence:evidence_00000000000000000000000000000000"],
        )
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_capacity_allows_three_lanes(tmp_path: Path) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
        bootstrap_count=2,
    )
    assert len(created["bootstraps"]) == 2
    ensured = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="third",
        bootstrap_count=3,
    )
    assert len(ensured["bootstraps"]) == 3
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_is_not_recycled_after_eight_minutes(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    agent_id = created["bootstrap"]["agent_id"]
    await service.transition_agent("run", agent_id, "running")
    async with service.db.sessions.begin() as session:
        agent = await session.get(AgentRecord, agent_id)
        assert agent is not None
        agent.started_at = service.clock() - timedelta(seconds=8 * 60 + 1)
        challenge = await session.get(ChallengeRecord, ("run", "challenge-a"))
        assert challenge is not None
        challenge.work_status = "active"
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        state_service=service,
        run_root=tmp_path / "runs",
        catalog_reconcile_interval_seconds=0,
    )
    supervisor.run_id = "run"
    assert await supervisor.scale_bootstraps() == []
    overview = await service.get_overview("run")
    active = [
        item
        for item in overview["agents"]
        if item["agent_id"] == agent_id
        and item["status"] not in supervisor.TERMINAL_AGENT_STATES
    ]
    assert len(active) == 1
    assert not any(
        event["event_type"] == "bootstrap_recycled"
        for event in await service.list_agent_events("run", agent_id)
    )
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_scales_after_productive_fifteen_minute_windows(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = await service_for(tmp_path, clock=clock, flag_count=2)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    await service.transition_agent("run", bootstrap_id, "running")
    await service.start_challenge("run", "challenge-a")
    bootstrap_context = CapabilityContext(
        run_id="run",
        agent_id=bootstrap_id,
        role="execution",
        unique_code="challenge-a",
    )
    clock.value += timedelta(minutes=15)
    decision = await service.maybe_scale_bootstrap_capacity(
        "run", "challenge-a", parent_id="challenge"
    )
    assert decision["reason"] == "no_productive_output"
    await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="observation",
        source="local_fixture",
        content="new durable observation",
    )
    decision = await service.maybe_scale_bootstrap_capacity(
        "run", "challenge-a", parent_id="challenge"
    )
    assert decision["target_count"] == 2
    ensured = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="bootstrap",
        bootstrap_count=2,
    )
    assert len(ensured["bootstraps"]) == 2
    second_id = next(
        item["agent_id"] for item in ensured["bootstraps"] if item["agent_id"] != bootstrap_id
    )
    await service.transition_agent("run", second_id, "running")
    clock.value += timedelta(minutes=1)
    operation_id = await service.mark_operation_started(
        "run",
        "benchmark_submit_flag",
        agent_id="challenge",
        unique_code="challenge-a",
    )
    await service.complete_operation(
        "run",
        operation_id,
        result_code="accepted",
        result_payload={"ok": True},
        challenge_updates={
            "flag_count": 2,
            "correct_flag_count": 1,
            "is_completed": False,
            "progress_kind": "flag_accepted",
        },
    )
    clock.value += timedelta(minutes=14)
    await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="observation",
        source="local_fixture",
        content="too early after accepted result",
    )
    decision = await service.maybe_scale_bootstrap_capacity(
        "run", "challenge-a", parent_id="challenge"
    )
    assert decision["reason"] == "scale_window_open"
    clock.value += timedelta(minutes=1)
    await service.persist_evidence(
        "run",
        bootstrap_context,
        evidence_type="observation",
        source="local_fixture",
        content="second new durable observation",
    )
    decision = await service.maybe_scale_bootstrap_capacity(
        "run", "challenge-a", parent_id="challenge"
    )
    assert decision["target_count"] == 3
    ensured = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="bootstrap",
        bootstrap_count=3,
    )
    assert len(ensured["bootstraps"]) == 3
    clock.value += timedelta(minutes=30)
    assert (
        await service.maybe_scale_bootstrap_capacity(
            "run", "challenge-a", parent_id="challenge"
        )
    )["reason"] == "capacity_limit"
    overview = await service.get_overview("run")
    active = [
        item
        for item in overview["agents"]
        if item["kind"] == "bootstrap"
        and item["status"] not in {"failed", "stopped", "completed", "cancelled", "interrupted"}
    ]
    assert len(active) == 3
    await service.close()


@pytest.mark.asyncio
async def test_disabled_bootstrap_still_creates_initial_execution(tmp_path: Path) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
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
    assert len(created["initial_executions"]) == 1
    assert created["initial_executions"][0]["task_key"] == "initial-recon"
    overview = await service.get_overview("run")
    assert all(item["kind"] != "bootstrap" for item in overview["agents"])
    assert sum(item["task_key"] == "initial-recon" for item in overview["agents"]) == 1
    await service.close()


@pytest.mark.asyncio
async def test_empty_dispatch_creates_one_deterministic_followup_per_checkpoint(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path)
    created = await service.register_challenge_workgroup(
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
    await service.submit_bootstrap_checkpoint(
        "run",
        bootstrap_context.agent_id,
        bootstrap_context,
        route_key="verified.route",
        summary="Bootstrap found a verified vulnerability",
        next_step="Validate the verified route and extract the exact result",
        task_stage="exploitation",
        evidence_refs=[evidence["evidence_ref"]],
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
    assert task_agent["task_key"] == "bootstrap-checkpoint:verified.route"
    assert task_agent["branch_key"] == "bootstrap:verified.route:handoff"
    assert task_agent["context_refs"][0].startswith("report:report_")

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
    created = await service.register_challenge_workgroup(
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
    assert dispatched["high_value_followup_task_count"] == 0
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
    created = await service.register_challenge_workgroup(
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
    async with service.db.sessions() as session:
        admission = await session.scalar(
            select(AdmissionRecord).where(AdmissionRecord.agent_id == first_id)
        )
        assert admission is not None
        assert admission.status == "queued"
    next_bootstrap = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="bootstrap-next",
    )
    assert next_bootstrap["enabled"] is True
    assert next_bootstrap["created"] is False
    assert next_bootstrap["agent_id"] == first_id
    assert next_bootstrap["status"] == "running"
    active_bootstraps = [
        item
        for item in (await service.get_overview("run"))["agents"]
        if item["kind"] == "bootstrap"
        and item["status"] not in {"failed", "stopped", "completed", "cancelled", "interrupted"}
    ]
    assert len(active_bootstraps) == 1

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
async def test_bootstrap_candidate_is_not_recycled_before_flag_submission(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path, flag_count=1)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    context = CapabilityContext(
        run_id="run",
        agent_id=bootstrap_id,
        role="execution",
        unique_code="challenge-a",
    )
    await service.submit_report(
        "run",
        bootstrap_id,
        context,
        AgentReportInput(
            status="completed",
            summary="verified candidate",
            candidate_flag="flag{candidate}",
        ),
    )

    pending = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="must-not-start-yet",
    )
    assert pending == {
        "enabled": False,
        "agent_id": None,
        "status": None,
        "reason": "candidate_pending_submission",
    }

    await service.publish_control_report(
        "run",
        sender_id="challenge",
        recipient_id="chief",
        unique_code="challenge-a",
        report_type="challenge_status",
        status="flag_submitted",
        payload={"type": "challenge_flag", "accepted": False},
    )
    retried = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="retry-after-rejection",
    )
    assert retried["enabled"] is True
    assert retried["created"] is True
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_retry_waits_for_active_execution_lane(tmp_path: Path) -> None:
    service = await service_for(tmp_path, flag_count=1)
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="execution-bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="controller",
        bootstrap_prompt="bootstrap",
    )
    bootstrap_id = created["bootstrap"]["agent_id"]
    context = CapabilityContext(
        run_id="run",
        agent_id=bootstrap_id,
        role="execution",
        unique_code="challenge-a",
    )
    await service.submit_report(
        "run",
        bootstrap_id,
        context,
        AgentReportInput(status="failed", summary="no candidate"),
    )
    execution = await service.register_agent(
        "run",
        agent_id="execution-web",
        role="execution",
        kind="web",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="test the web route",
    )
    assert execution["status"] in {"pending", "queued"}

    resumed = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="must-wait-for-web-lane",
    )
    assert resumed["enabled"] is True
    assert resumed["created"] is True
    assert resumed["status"] == "queued"
    await service.submit_report(
        "run",
        "execution-web",
        CapabilityContext(
            run_id="run",
            agent_id="execution-web",
            role="execution",
            unique_code="challenge-a",
        ),
        AgentReportInput(status="failed", summary="web lane exhausted"),
    )
    retried = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="retry-after-web-lane",
    )
    assert retried["created"] is False
    assert retried["agent_id"] == resumed["agent_id"]
    await service.close()


@pytest.mark.asyncio
async def test_bootstrap_is_not_created_when_all_flags_are_already_submitted(
    tmp_path: Path,
) -> None:
    service = await service_for(tmp_path, flag_count=1, correct_flag_count=1)
    created = await service.register_challenge_workgroup(
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
