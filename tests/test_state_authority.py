"""Offline tests for the SQLite/FastAPI authoritative run state."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, insert, select

from agent.api import create_state_app
from agent.state import (
    CapabilityRegistry,
    StateService,
    container_capacity_summary,
    container_slot_occupied,
)
from agent.state.errors import StateConflict
from agent.state.models import AuditOutboxRecord, RunRecord, StateEventRecord
from agent.state.schemas import (
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    ChallengeImport,
    CreateCycleInput,
    FindingInput,
    StagnationExtensionInput,
    VerificationUpdateInput,
)
from agent.state.scheduling import ResourceController, StagnationManager


def test_container_capacity_only_releases_explicit_terminal_states() -> None:
    assert container_slot_occupied("stopped") is False
    assert container_slot_occupied("closed") is False
    assert container_slot_occupied("available") is True
    assert container_slot_occupied("running") is True
    assert container_slot_occupied("future-status") is True
    assert container_slot_occupied("STOPPED") is True
    assert container_slot_occupied(None) is True
    assert container_capacity_summary(
        [
            {
                "unique_code": "completed-live",
                "is_completed": True,
                "container_status": "available",
            },
            {
                "unique_code": "running",
                "is_completed": False,
                "container_status": "running",
            },
            {
                "unique_code": "released",
                "is_completed": True,
                "container_status": "stopped",
            },
        ]
    ) == {
        "limit": 3,
        "occupied_count": 2,
        "free_count": 1,
        "occupied_codes": ["completed-live", "running"],
        "completed_pending_release_codes": ["completed-live"],
    }


@pytest.mark.asyncio
async def test_api_cycle_report_cursor_and_flag_redaction(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run("run-1", challenges=[ChallengeImport(unique_code="web-1")])
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent("run-1", role="challenge", parent_id=chief["agent_id"], unique_code="web-1")
    registry = CapabilityRegistry()
    chief_cap = registry.issue("run-1", chief["agent_id"], "chief")
    challenge_cap = registry.issue("run-1", challenge["agent_id"], "challenge", "web-1")
    app = create_state_app(service, registry)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://state") as client:
        headers = {"X-Aion-Capability": challenge_cap.token}
        created = await client.post(
            "/internal/v1/runs/run-1/challenges/web-1/cycles",
            headers=headers,
            json={"expected_challenge_version": 1},
        )
        assert created.status_code == 200
        cycle = created.json()
        planned = await client.put(
            f"/internal/v1/runs/run-1/cycles/{cycle['cycle_id']}/analysis-plan",
            headers=headers,
            json={
                "expected_version": cycle["version"],
                "analysis_summary": "map the current evidence",
                "tasks": [{"objective": "inspect the assigned service", "kind": "recon"}],
            },
        )
        assert planned.status_code == 200
        execution_id = planned.json()["admissions"][0]["agent_id"]

        execution_cap = registry.issue("run-1", execution_id, "execution", "web-1")
        reported = await client.post(
            f"/internal/v1/runs/run-1/agents/{execution_id}/reports",
            headers={"X-Aion-Capability": execution_cap.token},
            json={
                "status": "completed",
                "summary": "candidate found",
                "candidate_flag": "flag{never-durable}",
            },
        )
        assert reported.status_code == 200

        reports = await client.get(
            "/internal/v1/runs/run-1/reports?after_sequence=0",
            headers=headers,
        )
        assert reports.status_code == 200
        assert reports.json()["reports"][0]["payload"]["candidate_flag"] == "flag{never-durable}"
        assert b"flag{never-durable}" not in (tmp_path / "state.sqlite3").read_bytes()

        stale = await client.put(
            f"/internal/v1/runs/run-1/cycles/{cycle['cycle_id']}/analysis-plan",
            headers=headers,
            json={"expected_version": 1, "analysis_summary": "stale"},
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "state_conflict"

        unauthorized = await client.get(
            "/internal/v1/runs/run-1/overview",
            headers=headers,
        )
        assert unauthorized.status_code == 403

    assert await service.db.pragma("journal_mode") == "wal"
    assert await service.db.pragma("foreign_keys") == 1
    await service.close()


@pytest.mark.asyncio
async def test_concurrent_scheduler_and_runner_events_keep_one_sequence_stream(
    tmp_path: Path,
) -> None:
    """Admission and Runner lifecycle events may commit from different sessions."""

    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run("run-1", challenges=[ChallengeImport(unique_code="web-1")])
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    execution = await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="web-1",
    )
    await service.enqueue_agent("run-1", execution["agent_id"])
    controller = ResourceController(service, "run-1")

    admission, runner_event = await asyncio.gather(
        controller.admit(
            execution["agent_id"],
            sample={"cpu_percent": 1.0, "memory_percent": 1.0},
        ),
        service.append_agent_event(
            "run-1",
            execution["agent_id"],
            "agent_runner_started",
            {"role": "execution"},
        ),
    )

    assert admission["status"] == "starting"
    assert isinstance(runner_event, int)
    async with service.db.sessions() as session:
        events = (
            await session.scalars(
                select(StateEventRecord)
                .where(StateEventRecord.run_id == "run-1")
                .order_by(StateEventRecord.sequence)
            )
        ).all()
        outbox = (
            await session.scalars(
                select(AuditOutboxRecord)
                .where(AuditOutboxRecord.run_id == "run-1")
                .order_by(AuditOutboxRecord.sequence)
            )
        ).all()

    event_sequences = [item.sequence for item in events]
    outbox_sequences = [item.sequence for item in outbox]
    assert len(event_sequences) == len(set(event_sequences))
    assert event_sequences == outbox_sequences
    await service.close()


@pytest.mark.asyncio
async def test_cycle_completed_does_not_mark_challenge_solved(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="multi-flag", flag_count=2)],
    )
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="multi-flag",
    )
    registry = CapabilityRegistry()
    context = registry.issue(
        "run-1", challenge["agent_id"], "challenge", "multi-flag"
    ).context

    cycle = await service.begin_cycle(
        "run-1",
        "multi-flag",
        context,
        CreateCycleInput(expected_challenge_version=1),
    )
    planned = await service.submit_analysis_plan(
        "run-1",
        cycle["cycle_id"],
        context,
        AnalysisPlanInput(
            expected_version=cycle["version"],
            analysis_summary="record the current evidence",
        ),
    )
    await service.commit_cycle(
        "run-1",
        cycle["cycle_id"],
        context,
        VerificationUpdateInput(
            expected_version=planned["version"],
            summary="this cycle is complete, but more Flags may remain",
            outcome="completed",
        ),
    )

    overview = await service.get_overview("run-1")
    challenge_state = overview["challenges"][0]
    assert challenge_state["is_completed"] is False
    assert challenge_state["work_status"] != "completed"
    await service.close()


@pytest.mark.asyncio
async def test_stagnation_thresholds_use_active_clock(tmp_path: Path) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.value

        def advance(self, seconds: int) -> None:
            self.value += timedelta(seconds=seconds)

    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run("run-1", challenges=[ChallengeImport(unique_code="web-1")], started_at=clock.value)
    chief = await service.register_agent("run-1", role="chief")
    challenge_agent = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    execution = await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge_agent["agent_id"],
        unique_code="web-1",
        mission="stagnation fixture",
    )
    await service.transition_agent("run-1", challenge_agent["agent_id"], "running")
    await service.transition_agent("run-1", execution["agent_id"], "running")
    await service.start_challenge("run-1", "web-1")
    manager = StagnationManager(service, clock=clock)
    clock.advance(480)
    assert (await manager.evaluate("run-1", "web-1"))["level"] == 1
    clock.advance(420)
    result = await manager.evaluate("run-1", "web-1")
    assert result["level"] == 2
    assert result["action"] == "pause"
    overview = await service.get_overview("run-1")
    challenge = overview["challenges"][0]
    assert challenge["work_status"] == "paused"
    assert challenge["container_status"] == "running"
    assert challenge["hint_eligible"] is False
    assert next(
        item for item in overview["agents"] if item["agent_id"] == challenge_agent["agent_id"]
    )["status"] == "running"
    assert all(
        item["status"] == "running"
        for item in overview["agents"]
        if item["role"] == "execution"
    )
    await service.close()


@pytest.mark.asyncio
async def test_resource_admission_uses_strict_limits_priority_and_throttle(
    tmp_path: Path,
) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.value

        def advance(self, seconds: int) -> None:
            self.value += timedelta(seconds=seconds)

    class Resources:
        cpu = 10.0
        memory = 20.0

        @classmethod
        def cpu_percent(cls, interval: object = None) -> float:
            return cls.cpu

        @classmethod
        def virtual_memory(cls) -> object:
            return type("Memory", (), {"percent": cls.memory})()

    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="web-1")],
        started_at=clock.value,
    )
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    low = await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="web-1",
        priority=10,
        mission="low",
    )
    high = await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="web-1",
        priority=90,
        mission="high",
    )
    await service.enqueue_agent("run-1", low["agent_id"])
    await service.enqueue_agent("run-1", high["agent_id"])
    controller = ResourceController(
        service,
        "run-1",
        psutil_module=Resources,
        clock=clock,
        start_interval_seconds=5,
    )
    assert await controller.next_queued_agent_id() == high["agent_id"]

    Resources.cpu = 70.0
    denied = await controller.admit(high["agent_id"])
    assert denied["ok"] is False and denied["reason"] == "cpu_limit"
    Resources.cpu = 10.0
    first = await controller.admit(high["agent_id"])
    assert first["status"] == "starting"
    await controller.mark_started(high["agent_id"])
    throttled = await controller.admit(low["agent_id"])
    assert throttled["ok"] is False and throttled["reason"] == "start_interval"
    clock.advance(5)
    second = await controller.admit(low["agent_id"])
    assert second["status"] == "starting"
    await service.close()


@pytest.mark.asyncio
async def test_stagnation_pause_time_is_not_counted(tmp_path: Path) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.value

        def advance(self, seconds: int) -> None:
            self.value += timedelta(seconds=seconds)

    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="web-1")],
        started_at=clock.value,
    )
    await service.start_challenge("run-1", "web-1")
    clock.advance(300)
    await service.close_challenge("run-1", "web-1")
    clock.advance(3_600)
    await service.start_challenge("run-1", "web-1")
    clock.advance(299)
    manager = StagnationManager(service, clock=clock)
    before = await manager.evaluate("run-1", "web-1")
    assert before["level"] == 1 and before["elapsed_seconds"] == 599
    clock.advance(1)
    warning = await manager.evaluate("run-1", "web-1")
    assert warning["level"] == 1 and warning["status"] == "warning"
    await service.close()


@pytest.mark.asyncio
async def test_only_structured_valid_progress_resets_stagnation_clock(
    tmp_path: Path,
) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.value

        def advance(self, seconds: int) -> None:
            self.value += timedelta(seconds=seconds)

    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")], started_at=clock.value
    )
    chief = await service.register_agent("run-1", role="chief")
    challenge_agent = await service.register_agent(
        "run-1", role="challenge", parent_id=chief["agent_id"], unique_code="web-1"
    )
    context = CapabilityContext(
        run_id="run-1", agent_id=challenge_agent["agent_id"], role="challenge", unique_code="web-1"
    )
    await service.start_challenge("run-1", "web-1")
    manager = StagnationManager(service, clock=clock)
    clock.advance(479)
    assert (await manager.evaluate("run-1", "web-1"))["level"] == 0
    clock.advance(1)
    assert (await manager.evaluate("run-1", "web-1"))["status"] == "warning"

    challenge = (await service.list_challenges("run-1"))[0]
    cycle = await service.begin_cycle(
        "run-1",
        "web-1",
        context,
        CreateCycleInput(expected_challenge_version=challenge["version"]),
    )
    await service.submit_analysis_plan(
        "run-1",
        cycle["cycle_id"],
        context,
        AnalysisPlanInput(
            expected_version=cycle["version"],
            analysis_summary="verify the current evidence",
        ),
    )
    committed = await service.commit_cycle(
        "run-1",
        cycle["cycle_id"],
        context,
        VerificationUpdateInput(
            expected_version=cycle["version"] + 1,
            summary="verified evidence",
            outcome="progress",
            findings=[
                FindingInput(
                    category="vulnerability",
                    summary="new verified fact",
                    verification_status="verified",
                    evidence_paths=["report://evidence-1"],
                )
            ],
        ),
    )
    assert committed["valid_progress"] is True
    progress_at = (await service.list_challenges("run-1"))[0]["last_progress_at"]
    clock.advance(479)
    assert (await manager.evaluate("run-1", "web-1"))["level"] == 0

    duplicate = await service.begin_cycle(
        "run-1",
        "web-1",
        context,
        CreateCycleInput(expected_challenge_version=(await service.list_challenges("run-1"))[0]["version"]),
    )
    await service.submit_analysis_plan(
        "run-1",
        duplicate["cycle_id"],
        context,
        AnalysisPlanInput(
            expected_version=duplicate["version"],
            analysis_summary="repeat the same report",
        ),
    )
    duplicate_result = await service.commit_cycle(
        "run-1",
        duplicate["cycle_id"],
        context,
        VerificationUpdateInput(
            expected_version=duplicate["version"] + 1,
            summary="duplicate report",
            outcome="no_progress",
            findings=[
                FindingInput(
                    category="vulnerability",
                    summary="new verified fact",
                    verification_status="verified",
                    evidence_paths=["report://evidence-1"],
                )
            ],
        ),
    )
    assert duplicate_result["valid_progress"] is False
    assert (await service.list_challenges("run-1"))[0]["last_progress_at"] == progress_at
    await service.close()


@pytest.mark.asyncio
async def test_stagnation_extension_is_structured_and_hard_capped(tmp_path: Path) -> None:
    class FakeClock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> datetime:
            return self.value

        def advance(self, seconds: int) -> None:
            self.value += timedelta(seconds=seconds)

    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")], started_at=clock.value
    )
    chief = await service.register_agent("run-1", role="chief")
    context = CapabilityContext(run_id="run-1", agent_id=chief["agent_id"], role="chief")
    await service.start_challenge("run-1", "web-1")
    clock.advance(480)
    operation_id = await service.mark_operation_started(
        "run-1", "benchmark_wait_for_remote", unique_code="web-1"
    )
    granted = await service.grant_stagnation_extension(
        "run-1",
        "web-1",
        context,
        StagnationExtensionInput(
            reason="waiting_remote", evidence_refs=[operation_id], note="remote polling"
        ),
    )
    assert granted["reason"] == "waiting_remote"
    assert (await service.list_challenges("run-1"))[0]["extension_active"] is True
    with pytest.raises(StateConflict) as duplicate:
        await service.grant_stagnation_extension(
            "run-1",
            "web-1",
            context,
            StagnationExtensionInput(reason="waiting_remote", evidence_refs=[operation_id]),
        )
    assert duplicate.value.code == "stagnation_extension_used"

    manager = StagnationManager(service, clock=clock)
    clock.advance(420)
    assert (await manager.evaluate("run-1", "web-1"))["action"] == "extension_active"
    clock.advance(300)
    capped = await manager.evaluate("run-1", "web-1")
    assert capped["action"] == "pause"
    assert capped["elapsed_seconds"] == 1_200
    await service.close()


@pytest.mark.asyncio
async def test_typed_report_cursors_survive_out_of_order_consumption(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")]
    )
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    execution = await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="web-1",
        mission="report",
    )
    challenge_context = CapabilityContext(
        run_id="run-1",
        agent_id=challenge["agent_id"],
        role="challenge",
        unique_code="web-1",
    )
    execution_context = CapabilityContext(
        run_id="run-1",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="web-1",
    )
    hint = await service.publish_control_report(
        "run-1",
        sender_id=chief["agent_id"],
        recipient_id=challenge["agent_id"],
        unique_code="web-1",
        report_type="hint",
        status="received",
        payload={"type": "hint_received", "hint": "offline hint"},
    )
    report = await service.submit_report(
        "run-1",
        execution["agent_id"],
        execution_context,
        AgentReportInput(status="completed", summary="done"),
    )
    execution_reports = await service.consume_reports(
        "run-1", challenge_context, report_type="execution"
    )
    assert execution_reports["next_sequence"] == report["sequence"]
    hints = await service.consume_reports(
        "run-1", challenge_context, report_type="hint"
    )
    assert hints["reports"][0]["sequence"] == hint["sequence"]
    runtime = await service.get_agent_runtime("run-1", challenge["agent_id"])
    assert runtime["agent"]["report_cursors"] == {
        "execution": report["sequence"],
        "hint": hint["sequence"],
    }
    await service.close()


@pytest.mark.asyncio
async def test_projection_failure_does_not_rollback_and_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("run-1")
    assert await service.project_pending_events(
        "run-1", run_dir=tmp_path / "run-1"
    ) == 1
    await service.append_agent_event(
        "run-1",
        (await service.register_agent("run-1", role="chief"))["agent_id"],
        "projection_fixture",
    )
    original = service._write_checkpoint

    async def fail_once(session: object, run_id: str, target_dir: Path) -> None:
        raise OSError("projection fixture failure")

    monkeypatch.setattr(service, "_write_checkpoint", fail_once)
    with pytest.raises(OSError):
        await service.project_pending_events("run-1", run_dir=tmp_path / "run-1")
    assert (await service.get_overview("run-1"))["run"]["last_sequence"] == 3
    async with service.db.sessions() as session:
        pending = (
            await session.scalars(
                select(AuditOutboxRecord).where(
                    AuditOutboxRecord.run_id == "run-1"
                )
            )
        ).all()
    assert {item.attempts for item in pending} == {1}
    assert {item.last_error for item in pending} == {"projection_failed"}

    monkeypatch.setattr(service, "_write_checkpoint", original)
    assert await service.project_pending_events(
        "run-1", run_dir=tmp_path / "run-1"
    ) == 2
    lines = (tmp_path / "run-1" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2, 3]
    async with service.db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuditOutboxRecord)) == 0
    await service.close()


@pytest.mark.asyncio
async def test_catalog_sync_is_material_and_idempotent(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    initial = ChallengeImport(unique_code="web-1", total_score=10)
    await service.create_run("run-1", challenges=[initial])
    chief = await service.register_agent("run-1", role="chief")
    challenge = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    before = await service.get_overview("run-1")
    version = before["challenges"][0]["version"]
    sequence = before["run"]["last_sequence"]
    chief_key = service.agent_signal_key("run-1", chief["agent_id"])
    challenge_key = service.agent_signal_key("run-1", challenge["agent_id"])
    chief_signal = await service.notifier.current(chief_key)
    challenge_signal = await service.notifier.current(challenge_key)

    unchanged = await service.import_challenges("run-1", [initial])
    unchanged_overview = await service.get_overview("run-1")
    assert unchanged.changed_codes == []
    assert unchanged.event_sequence is None
    assert unchanged_overview["run"]["last_sequence"] == sequence
    assert unchanged_overview["challenges"][0]["version"] == version
    assert await service.notifier.current(chief_key) == chief_signal
    assert await service.notifier.current(challenge_key) == challenge_signal

    changed = await service.import_challenges(
        "run-1", [initial.model_copy(update={"total_score": 20})]
    )
    changed_overview = await service.get_overview("run-1")
    assert changed.changed_codes == ["web-1"]
    assert changed.event_sequence == sequence + 1
    assert changed_overview["run"]["last_sequence"] == sequence + 1
    assert changed_overview["challenges"][0]["version"] == version + 1
    assert await service.notifier.current(chief_key) == sequence + 1
    assert await service.notifier.current(challenge_key) == sequence + 1
    async with service.db.sessions() as session:
        events = (
            await session.scalars(
                select(StateEventRecord).where(StateEventRecord.run_id == "run-1")
            )
        ).all()
    assert [item.event_type for item in events].count(
        "challenge_catalog_changed"
    ) == 1
    await service.close()


@pytest.mark.asyncio
async def test_heartbeat_updates_timestamp_without_version_or_event(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run("run-1")
    chief = await service.register_agent("run-1", role="chief")
    context = CapabilityContext(
        run_id="run-1", agent_id=chief["agent_id"], role="chief"
    )
    before = await service.get_overview("run-1")
    version = before["agents"][0]["version"]
    updated_at = before["agents"][0]["updated_at"]
    sequence = before["run"]["last_sequence"]

    first = await service.heartbeat("run-1", chief["agent_id"], context)
    second = await service.heartbeat("run-1", chief["agent_id"], context)
    after = await service.get_overview("run-1")
    assert first["last_heartbeat_at"] is not None
    assert second["version"] == version
    assert second["updated_at"] == updated_at
    assert after["run"]["last_sequence"] == sequence

    sampled = await service.heartbeat(
        "run-1", chief["agent_id"], context, sample_event=True
    )
    assert sampled["version"] == version
    events = await service.list_agent_events("run-1", chief["agent_id"], limit=100)
    assert [item["event_type"] for item in events].count("agent_heartbeat") == 1
    await service.close()


@pytest.mark.asyncio
async def test_projection_database_confirmation_retry_has_no_duplicate_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run-1"
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("run-1")
    await service.project_pending_events("run-1", run_dir=run_dir)
    chief = await service.register_agent("run-1", role="chief")
    original = service._confirm_projection

    async def fail_confirmation(run_id: str, sequence: int) -> None:
        raise OSError("database confirmation fixture failure")

    monkeypatch.setattr(service, "_confirm_projection", fail_confirmation)
    with pytest.raises(OSError):
        await service.project_pending_events("run-1", run_dir=run_dir)
    monkeypatch.setattr(service, "_confirm_projection", original)

    assert await service.project_pending_events("run-1", run_dir=run_dir) == 1
    lines = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["sequence"] for line in lines] == [1, 2]
    async with service.db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuditOutboxRecord)) == 0
    assert chief["role"] == "chief"
    await service.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("schema_version", [2, 5])
async def test_old_database_is_rejected_without_mutation(
    tmp_path: Path, schema_version: int
) -> None:
    database_path = tmp_path / "state.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(schema_version),),
        )
    before = database_path.read_bytes()
    service = StateService(database_path)
    with pytest.raises(RuntimeError, match="unsupported state database schema version"):
        await service.initialize()
    assert database_path.read_bytes() == before
    await service.close()


@pytest.mark.asyncio
async def test_projection_handles_twenty_thousand_events_incrementally(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-load"
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("run-load")
    await service.project_pending_events("run-load", run_dir=run_dir, limit=1_000)

    event_count = 20_000
    async with service.db.sessions.begin() as session:
        run = await session.get(RunRecord, "run-load")
        assert run is not None
        await session.execute(
            insert(StateEventRecord),
            [
                {
                    "event_id": f"event-load-{sequence}",
                    "run_id": "run-load",
                    "sequence": sequence,
                    "event_type": "load_fixture",
                    "payload": {"index": sequence - 2},
                }
                for sequence in range(2, event_count + 2)
            ],
        )
        await session.execute(
            insert(AuditOutboxRecord),
            [
                {"run_id": "run-load", "sequence": sequence}
                for sequence in range(2, event_count + 2)
            ],
        )
        run.last_sequence = event_count + 1

    projected = 0
    while batch := await service.project_pending_events(
        "run-load", run_dir=run_dir, limit=1_000
    ):
        projected += batch
    assert projected == event_count
    lines = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == event_count + 1
    assert json.loads(lines[-1])["sequence"] == event_count + 1
    assert "payload" not in AuditOutboxRecord.__table__.columns
    async with service.db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuditOutboxRecord)) == 0
    await service.close()
