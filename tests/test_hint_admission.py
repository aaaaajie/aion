"""Competition-mode tests for stagnation signaling and pause control."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.state import StateService
from agent.state.models import ChallengeRecord
from agent.state.scheduling import ChallengeScheduler, StagnationManager
from agent.state.schemas import CapabilityContext, ChallengeImport


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


@pytest.mark.asyncio
async def test_low_yield_is_a_soft_signal_and_reports_to_chief(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-low-yield",
        challenges=[ChallengeImport(unique_code="target")],
    )
    chief = await service.register_agent("run-low-yield", role="chief")
    controller = await service.register_agent(
        "run-low-yield",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="target",
    )
    await service.start_challenge("run-low-yield", "target")
    async with service.db.sessions.begin() as session:
        challenge = await session.get(
            ChallengeRecord, ("run-low-yield", "target")
        )
        assert challenge is not None
        challenge.last_progress_at = clock.value - timedelta(minutes=9)

    result = await StagnationManager(service, clock=clock).evaluate(
        "run-low-yield", "target"
    )

    assert result["action"] == "low_yield"
    overview = await service.get_overview("run-low-yield")
    challenge = overview["challenges"][0]
    assert challenge["work_status"] == "active"
    assert challenge["low_yield"] is True

    reports = await service.consume_reports(
        "run-low-yield",
        CapabilityContext(
            run_id="run-low-yield",
            agent_id=chief["agent_id"],
            role="chief",
        ),
        report_type="challenge_status",
    )
    assert reports["count"] == 1
    assert reports["reports"][0]["status"] == "low_yield"
    assert reports["reports"][0]["agent_id"] == controller["agent_id"]
    repeated = await StagnationManager(service, clock=clock).evaluate(
        "run-low-yield", "target"
    )
    assert repeated["action"] == "none"
    await service.close()


@pytest.mark.asyncio
async def test_prolonged_low_yield_pauses_challenge_and_reports_to_chief(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-stagnation-pause",
        challenges=[ChallengeImport(unique_code="target")],
    )
    chief = await service.register_agent("run-stagnation-pause", role="chief")
    controller = await service.register_agent(
        "run-stagnation-pause",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="target",
    )
    await service.start_challenge("run-stagnation-pause", "target")
    async with service.db.sessions.begin() as session:
        challenge = await session.get(
            ChallengeRecord, ("run-stagnation-pause", "target")
        )
        assert challenge is not None
        challenge.last_progress_at = clock.value - timedelta(minutes=16)

    result = await StagnationManager(service, clock=clock).evaluate(
        "run-stagnation-pause", "target"
    )

    assert result["action"] == "pause_stagnation"
    assert result["pause_reason"] == "stagnation_timeout"
    overview = await service.get_overview("run-stagnation-pause")
    challenge = overview["challenges"][0]
    assert challenge["work_status"] == "paused"
    assert challenge["pause_reason"] == "stagnation_timeout"
    assert challenge["low_yield"] is True

    reports = await service.consume_reports(
        "run-stagnation-pause",
        CapabilityContext(
            run_id="run-stagnation-pause",
            agent_id=chief["agent_id"],
            role="chief",
        ),
        report_type="challenge_status",
    )
    assert reports["count"] == 1
    assert reports["reports"][0]["status"] == "stagnation_paused"
    assert reports["reports"][0]["agent_id"] == controller["agent_id"]

    repeated = await StagnationManager(service, clock=clock).evaluate(
        "run-stagnation-pause", "target"
    )
    assert repeated["action"] == "none"
    await service.close()


@pytest.mark.asyncio
async def test_scheduler_marks_paused_unfinished_challenges_for_next_round(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-next-round",
        challenges=[
            ChallengeImport(unique_code="first", container_status="running"),
            ChallengeImport(unique_code="second", container_status="running"),
        ],
    )
    await service.start_challenge("run-next-round", "first")
    await service.start_challenge("run-next-round", "second")
    async with service.db.sessions.begin() as session:
        for code in ("first", "second"):
            challenge = await session.get(ChallengeRecord, ("run-next-round", code))
            assert challenge is not None
            challenge.work_status = "paused"
            challenge.stagnation_level = 2
            challenge.active_since = None

    scheduled = await ChallengeScheduler(service, clock=clock).select(
        "run-next-round"
    )

    assert {item["unique_code"] for item in scheduled} == {"first", "second"}
    assert all(item["restart_required"] is True for item in scheduled)

    await service.start_challenge("run-next-round", "first")
    resumed = await service.list_challenges("run-next-round")
    first = next(item for item in resumed if item["unique_code"] == "first")
    assert first["work_status"] == "active"
    assert first["low_yield"] is False
    await service.close()
