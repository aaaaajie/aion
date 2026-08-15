from __future__ import annotations

from pathlib import Path

import pytest

from agent.state import CapabilityContext, ChallengeDispatchInput
from agent.state.database import SCHEMA_VERSION, StateDatabase
from agent.state.errors import StatePermission
from agent.state.schemas import AgentReportInput, ChallengeImport
from agent.state.service import StateService
from agent.subagents.models import ExecutionReport


async def build_state(tmp_path: Path) -> tuple[StateService, CapabilityContext, CapabilityContext]:
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
                description="test target",
                container_status="running",
                container_addr=["http://127.0.0.1:8000"],
            )
        ],
    )
    await service.register_agent("run", agent_id="chief", role="chief", initial_prompt="chief")
    await service.register_agent(
        "run",
        agent_id="challenge",
        role="challenge",
        parent_id="chief",
        unique_code="challenge-a",
        initial_prompt="challenge",
    )
    chief = CapabilityContext(run_id="run", agent_id="chief", role="chief")
    challenge = CapabilityContext(
        run_id="run",
        agent_id="challenge",
        role="challenge",
        unique_code="challenge-a",
    )
    await service.start_challenge("run", "challenge-a", chief)
    return service, chief, challenge


@pytest.mark.asyncio
async def test_schema_15_and_dispatch_is_append_only_and_idempotent(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    assert SCHEMA_VERSION == 15

    first = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput.model_validate(
            {
                "summary": "baseline",
                "tasks": [
                    {
                        "objective": "collect the HTTP baseline",
                        "task_key": "baseline",
                        "hypothesis_key": "http-baseline",
                    }
                ],
            }
        ),
    )
    assert first["decision_number"] == 1
    assert len(first["admissions"]) == 1

    repeated = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput.model_validate(
            {
                "summary": "same task is already useful",
                "tasks": [
                    {
                        "objective": "collect the HTTP baseline",
                        "task_key": "baseline",
                    }
                ],
            }
        ),
    )
    assert repeated["admissions"] == []
    assert repeated["idempotent_tasks"][0]["agent_id"] == first["admissions"][0]["agent_id"]
    await service.close()


@pytest.mark.asyncio
async def test_dispatch_derives_stable_keys_when_model_omits_them(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    payload = ChallengeDispatchInput.model_validate(
        {"summary": "stable decision", "tasks": [{"objective": "collect baseline"}]}
    )
    first = await service.dispatch_challenge("run", "challenge-a", challenge, payload)
    second = await service.dispatch_challenge("run", "challenge-a", challenge, payload)

    assert len(first["admissions"]) == 1
    assert second["admissions"] == []
    assert second["idempotent_tasks"][0]["task_key"].startswith("task:")
    overview = await service.get_overview("run")
    execution_agents = [item for item in overview["agents"] if item["role"] == "execution"]
    assert len(execution_agents) == 1
    assert execution_agents[0]["hypothesis_key"].startswith("hypothesis:")
    assert execution_agents[0]["branch_key"].endswith(":discovery")
    await service.close()


def test_controller_report_projection_is_reference_oriented_and_bounded() -> None:
    projected = StateService._controller_report_projection(
        {
            "report_id": "report-1",
            "report_ref": "report:report-1",
            "sequence": 4,
            "agent_id": "execution-1",
            "status": "completed",
            "payload": {
                "summary": "s" * 5_000,
                "evidence_refs": [f"evidence:evidence_{index:032d}" for index in range(20)],
                "findings": [
                    {
                        "finding_ref": "finding:finding_" + "a" * 32,
                        "category": "vulnerability",
                        "summary": "f" * 5_000,
                        "detail": {"must_not_be_injected": "x" * 5_000},
                        "confidence": 0.9,
                        "verification_status": "verified",
                        "evidence_refs": [f"evidence:evidence_{index:032d}" for index in range(20)],
                    }
                ],
            },
        }
    )

    assert len(projected["payload"]["summary"]) == 1_000
    assert len(projected["payload"]["evidence_refs"]) == 10
    finding = projected["payload"]["findings"][0]
    assert len(finding["summary"]) == 1_000
    assert len(finding["evidence_refs"]) == 10
    assert "detail" not in finding


@pytest.mark.asyncio
async def test_late_report_keeps_original_cycle_and_is_consumed_once(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    first = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput.model_validate(
            {"summary": "first", "tasks": [{"objective": "slow task"}]}
        ),
    )
    execution_id = first["admissions"][0]["agent_id"]
    overview = await service.get_overview("run")
    original_cycle_id = next(
        item["cycle_id"]
        for item in overview["agents"]
        if item["agent_id"] == execution_id
    )
    await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="independent follow-up", tasks=[]),
    )
    execution = CapabilityContext(
        run_id="run",
        agent_id=execution_id,
        role="execution",
        unique_code="challenge-a",
    )
    await service.submit_report(
        "run",
        execution_id,
        execution,
        AgentReportInput(status="completed", summary="slow result arrived"),
    )
    observed = await service.observe_challenge(
        "run", "challenge-a", challenge, max_reports=20
    )
    assert observed["report_count"] == 1
    assert "cycle_id" not in observed["reports"][0]
    overview = await service.get_overview("run")
    assert next(
        item["cycle_id"]
        for item in overview["agents"]
        if item["agent_id"] == execution_id
    ) == original_cycle_id
    again = await service.observe_challenge(
        "run", "challenge-a", challenge, max_reports=20
    )
    assert again["report_count"] == 0
    await service.close()


@pytest.mark.asyncio
async def test_controller_snapshot_replays_after_model_failure_until_dispatch(
    tmp_path: Path,
) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="first", tasks=[{"objective": "quick task"}]),
    )
    execution_id = dispatched["admissions"][0]["agent_id"]
    await service.submit_report(
        "run",
        execution_id,
        CapabilityContext(
            run_id="run",
            agent_id=execution_id,
            role="execution",
            unique_code="challenge-a",
        ),
        AgentReportInput(status="completed", summary="useful result"),
    )

    first = await service.observe_challenge(
        "run",
        "challenge-a",
        challenge,
        replay_pending_snapshot=True,
    )
    assert first["report_count"] == 1
    replayed = await service.observe_challenge(
        "run",
        "challenge-a",
        challenge,
        replay_pending_snapshot=True,
    )
    assert replayed["report_count"] == 1
    assert replayed["snapshot_replayed"] is True

    await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="acted on the report", tasks=[]),
    )
    acknowledged = await service.observe_challenge(
        "run",
        "challenge-a",
        challenge,
        replay_pending_snapshot=True,
    )
    assert acknowledged["report_count"] == 0
    await service.close()


@pytest.mark.asyncio
async def test_controller_cannot_wait_on_consumed_but_undecided_snapshot(
    tmp_path: Path,
) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="first", tasks=[{"objective": "quick task"}]),
    )
    execution_id = dispatched["admissions"][0]["agent_id"]
    await service.submit_report(
        "run",
        execution_id,
        CapabilityContext(
            run_id="run",
            agent_id=execution_id,
            role="execution",
            unique_code="challenge-a",
        ),
        AgentReportInput(status="completed", summary="new result"),
    )
    snapshot = await service.observe_challenge(
        "run", "challenge-a", challenge, max_reports=20
    )
    assert snapshot["report_count"] == 1

    ready = await service.record_controller_wait("run", "challenge", "too early")
    assert ready["status"] == "ready"
    assert ready["pending_snapshot"] is True

    await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="no new independent work", tasks=[]),
    )
    waiting = await service.record_controller_wait("run", "challenge", "done")
    assert waiting["status"] == "waiting"
    await service.close()


@pytest.mark.asyncio
async def test_optional_report_items_warn_but_terminal_report_commits(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="run", tasks=[{"objective": "test"}]),
    )
    execution_id = dispatched["admissions"][0]["agent_id"]
    execution = CapabilityContext(
        run_id="run",
        agent_id=execution_id,
        role="execution",
        unique_code="challenge-a",
    )
    result = await service.submit_report(
        "run",
        execution_id,
        execution,
        AgentReportInput.model_validate(
            {
                "status": "completed",
                "summary": "top level is valid",
                "hypothesis_outcome": "invented",
                "findings": [{"not_a_finding": True}],
                "evidence_refs": [123, "evidence:evidence_" + "f" * 32],
            }
        ),
    )
    assert result["report_id"].startswith("report_")
    assert {item["code"] for item in result["warnings"]} >= {
        "invalid_hypothesis_outcome",
        "invalid_finding_dropped",
        "invalid_evidence_ref",
        "evidence_not_accessible",
    }
    runtime = await service.get_agent_runtime("run", execution_id)
    assert runtime["agent"]["status"] == "completed"
    assert runtime["agent"]["terminal_report_id"] == result["report_id"]
    await service.close()


@pytest.mark.asyncio
async def test_cloud_shaped_finding_is_normalized_and_persisted(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="run", tasks=[{"objective": "test traversal"}]),
    )
    execution_id = dispatched["admissions"][0]["agent_id"]
    execution = CapabilityContext(
        run_id="run",
        agent_id=execution_id,
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        execution,
        evidence_type="http",
        source="system_http_response",
        content="root:x:0:0",
    )
    result = await service.submit_report(
        "run",
        execution_id,
        execution,
        AgentReportInput.model_validate(
            {
                "status": "completed",
                "summary": "confirmed traversal",
                "hypothesis_outcome": "confirmed",
                "candidate_flag": "task-name-is-still-preserved-as-an-opaque-value",
                "findings": [
                    {
                        "finding_id": "client-traversal-1",
                        "title": "Traversal reads arbitrary files",
                        "detail": "download.php accepted ../../../../etc/passwd",
                        "severity": "high",
                        "confidence": "high",
                        "verification_status": "confirmed",
                        "evidence_refs": [evidence["evidence_ref"]],
                    }
                ],
            }
        ),
    )
    assert result["hypothesis_outcome"] == "supported"
    assert result["warnings"] == []
    assert result["progress_kinds"] == ["finding_verified"]
    assert result["findings"][0]["summary"] == "Traversal reads arbitrary files"
    assert result["findings"][0]["confidence"] == 0.9
    assert result["findings"][0]["detail"] == {
        "description": "download.php accepted ../../../../etc/passwd",
        "client_label": "client-traversal-1",
        "severity": "high",
        "evidence_refs": [evidence["evidence_ref"]],
    }

    events = await service.list_agent_events("run", execution_id)
    report_event = next(item for item in events if item["event_type"] == "agent_report")
    assert report_event["payload"] | {
        "findings_received": 1,
        "findings_persisted": 1,
        "findings_dropped": 0,
        "findings_normalized": 1,
        "candidate_flag_present": True,
    } == report_event["payload"]

    observed = await service.observe_challenge(
        "run", "challenge-a", challenge, max_reports=20
    )
    assert observed["candidate_flags"][0]["candidate_flag"].startswith("task-name")
    await service.close()


@pytest.mark.asyncio
async def test_only_assigned_candidate_finding_ref_is_updated(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    first_dispatch = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="discover", tasks=[{"objective": "discover"}]),
    )
    first_id = first_dispatch["admissions"][0]["agent_id"]
    first_context = CapabilityContext(
        run_id="run",
        agent_id=first_id,
        role="execution",
        unique_code="challenge-a",
    )
    discovered = await service.submit_report(
        "run",
        first_id,
        first_context,
        AgentReportInput(
            status="completed",
            summary="candidate found",
            findings=[
                {
                    "summary": "Candidate traversal",
                    "verification_status": "candidate",
                }
            ],
        ),
    )
    finding_ref = discovered["findings"][0]["finding_ref"]

    second_dispatch = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(
            summary="validate",
            tasks=[
                {
                    "objective": "validate traversal",
                    "context_refs": [finding_ref],
                }
            ],
        ),
    )
    second_id = second_dispatch["admissions"][0]["agent_id"]
    second_context = CapabilityContext(
        run_id="run",
        agent_id=second_id,
        role="execution",
        unique_code="challenge-a",
    )
    evidence = await service.persist_evidence(
        "run",
        second_context,
        evidence_type="http",
        source="system_http_response",
        content="root:x:0:0",
    )
    verified = await service.submit_report(
        "run",
        second_id,
        second_context,
        AgentReportInput(
            status="completed",
            summary="candidate verified",
            hypothesis_outcome="supported",
            findings=[
                {
                    "finding_ref": finding_ref,
                    "summary": "Candidate traversal",
                    "verification_status": "verified",
                    "evidence_refs": [evidence["evidence_ref"]],
                }
            ],
        ),
    )
    assert verified["warnings"] == []
    assert verified["findings"][0]["finding_ref"] == finding_ref
    assert verified["findings"][0]["verification_status"] == "verified"
    assert verified["progress_kinds"] == ["finding_verified"]
    await service.close()


def test_execution_report_schema_is_typed_but_optional_items_remain_best_effort() -> None:
    schema = ExecutionReport.model_json_schema()
    outcome = schema["properties"]["hypothesis_outcome"]
    assert outcome["enum"] == ["supported", "rejected", "inconclusive"]
    finding_ref = schema["properties"]["findings"]["items"]["$ref"]
    assert finding_ref.endswith("/ReportFindingInput")
    parsed = ExecutionReport.model_validate(
        {
            "status": "completed",
            "summary": "terminal report survives",
            "hypothesis_outcome": "provider-specific-value",
            "findings": [{"title": "cloud-shaped"}, "malformed"],
        }
    )
    assert parsed.hypothesis_outcome == "provider-specific-value"
    assert parsed.findings[-1] == "malformed"


@pytest.mark.asyncio
async def test_evidence_scope_and_paging(tmp_path: Path) -> None:
    service, _chief, challenge = await build_state(tmp_path)
    dispatched = await service.dispatch_challenge(
        "run",
        "challenge-a",
        challenge,
        ChallengeDispatchInput(summary="run", tasks=[{"objective": "test"}]),
    )
    execution_id = dispatched["admissions"][0]["agent_id"]
    execution = CapabilityContext(
        run_id="run",
        agent_id=execution_id,
        role="execution",
        unique_code="challenge-a",
    )
    saved = await service.persist_evidence(
        "run",
        execution,
        evidence_type="http",
        source="system_http_response",
        content="0123456789",
    )
    first = await service.read_evidence(
        "run", execution, saved["evidence_ref"], offset=0, limit_chars=4
    )
    second = await service.read_evidence(
        "run", challenge, saved["evidence_ref"], offset=first["next_offset"], limit_chars=8
    )
    assert first["content"] + second["content"] == "0123456789"

    await service.register_agent(
        "run",
        agent_id="other-execution",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="other",
        initial_prompt="other",
    )
    other = CapabilityContext(
        run_id="run",
        agent_id="other-execution",
        role="execution",
        unique_code="challenge-a",
    )
    with pytest.raises(StatePermission) as error:
        await service.read_evidence("run", other, saved["evidence_ref"])
    assert error.value.code == "evidence_not_accessible"
    await service.close()
