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
async def test_validation_work_defers_hard_stagnation_pause(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-validation-grace",
        challenges=[ChallengeImport(unique_code="target")],
    )
    chief = await service.register_agent("run-validation-grace", role="chief")
    controller = await service.register_agent(
        "run-validation-grace",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="target",
    )
    await service.start_challenge("run-validation-grace", "target")
    await service.register_agent(
        "run-validation-grace",
        agent_id="validation",
        role="execution",
        parent_id=controller["agent_id"],
        unique_code="target",
        task_stage="validation",
        mission="validate checkpoint",
    )
    async with service.db.sessions.begin() as session:
        challenge = await session.get(
            ChallengeRecord, ("run-validation-grace", "target")
        )
        assert challenge is not None
        challenge.last_progress_at = clock.value - timedelta(minutes=16)

    result = await StagnationManager(service, clock=clock).evaluate(
        "run-validation-grace", "target"
    )

    assert result["action"] == "low_yield"
    overview = await service.get_overview("run-validation-grace")
    assert overview["challenges"][0]["work_status"] == "active"
    await service.close()


@pytest.mark.asyncio
async def test_evidence_activity_does_not_reset_stagnation_clock(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(
        tmp_path / "state.sqlite3",
        run_root=tmp_path / "runs",
        clock=clock,
    )
    await service.create_run(
        "run-evidence-activity",
        challenges=[ChallengeImport(unique_code="target")],
    )
    chief = await service.register_agent("run-evidence-activity", role="chief")
    controller = await service.register_agent(
        "run-evidence-activity",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="target",
    )
    await service.start_challenge("run-evidence-activity", "target")
    execution = await service.register_agent(
        "run-evidence-activity",
        agent_id="execution",
        role="execution",
        parent_id=controller["agent_id"],
        unique_code="target",
        mission="observe target",
    )
    old_progress = clock.value - timedelta(minutes=16)
    async with service.db.sessions.begin() as session:
        challenge = await session.get(
            ChallengeRecord, ("run-evidence-activity", "target")
        )
        assert challenge is not None
        challenge.last_progress_at = old_progress
        challenge.stagnation_level = 1

    await service.persist_evidence(
        "run-evidence-activity",
        CapabilityContext(
            run_id="run-evidence-activity",
            agent_id=execution["agent_id"],
            role="execution",
            unique_code="target",
        ),
        evidence_type="http",
        source="system_http_response",
        content="ordinary polling output",
    )

    challenge_view = (await service.list_challenges("run-evidence-activity"))[0]
    assert challenge_view["last_progress_at"] == old_progress.isoformat()
    assert challenge_view["low_yield"] is True
    result = await StagnationManager(service, clock=clock).evaluate(
        "run-evidence-activity", "target"
    )
    assert result["action"] == "pause_stagnation"
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


@pytest.mark.asyncio
async def test_scheduler_early_fills_all_slots_with_high_score_easy_challenges(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-early-easy",
        challenges=[
            ChallengeImport(unique_code="easy-low", difficulty="easy", total_score=10),
            ChallengeImport(unique_code="easy-high", difficulty="easy", total_score=100),
            ChallengeImport(unique_code="easy-mid", difficulty="easy", total_score=50),
            ChallengeImport(unique_code="easy-high-2", difficulty="easy", total_score=100),
            ChallengeImport(unique_code="hard", difficulty="hard", total_score=999),
        ],
    )

    scheduled = await ChallengeScheduler(service, clock=clock).select(
        "run-early-easy", limit=3
    )

    assert [item["unique_code"] for item in scheduled] == [
        "easy-high",
        "easy-high-2",
        "easy-mid",
    ]
    await service.close()


@pytest.mark.asyncio
async def test_scheduler_early_uses_medium_then_hard_to_fill_easy_shortage(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-early-fallback",
        challenges=[
            ChallengeImport(unique_code="easy", difficulty="easy", total_score=1),
            ChallengeImport(unique_code="easy-2", difficulty="easy", total_score=2),
            ChallengeImport(unique_code="medium-low", difficulty="medium", total_score=10),
            ChallengeImport(unique_code="medium-high", difficulty="medium", total_score=100),
            ChallengeImport(unique_code="hard", difficulty="hard", total_score=1_000),
        ],
    )

    scheduled = await ChallengeScheduler(service, clock=clock).select(
        "run-early-fallback", limit=3
    )

    assert [item["unique_code"] for item in scheduled] == [
        "easy-2",
        "easy",
        "medium-high",
    ]
    await service.close()


@pytest.mark.asyncio
async def test_scheduler_early_falls_back_to_hard_before_unknown_difficulty(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-early-hard",
        challenges=[
            ChallengeImport(unique_code="easy", difficulty="easy", total_score=1),
            ChallengeImport(unique_code="hard", difficulty="hard", total_score=2),
            ChallengeImport(unique_code="unknown", difficulty="other", total_score=999),
        ],
    )

    scheduled = await ChallengeScheduler(service, clock=clock).select(
        "run-early-hard", limit=3
    )

    assert [item["unique_code"] for item in scheduled] == [
        "easy",
        "hard",
        "unknown",
    ]
    await service.close()


@pytest.mark.asyncio
async def test_scheduler_non_early_phases_keep_their_existing_ordering(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-phase-ordering",
        duration_minutes=360,
        challenges=[
            ChallengeImport(unique_code="easy", difficulty="easy", total_score=10),
            ChallengeImport(unique_code="hard", difficulty="hard", total_score=100),
        ],
    )

    clock.value += timedelta(minutes=300)
    mid = await ChallengeScheduler(service, clock=clock).select(
        "run-phase-ordering", limit=2
    )
    assert [item["unique_code"] for item in mid] == ["hard", "easy"]

    clock.value += timedelta(minutes=45)
    late = await ChallengeScheduler(service, clock=clock).select(
        "run-phase-ordering", limit=2
    )
    assert [item["unique_code"] for item in late] == ["hard", "easy"]
    await service.close()


@pytest.mark.asyncio
async def test_hint_eligibility_uses_competition_windows_and_boundaries(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-hint-windows",
        duration_minutes=360,
        challenges=[ChallengeImport(unique_code="target")],
    )
    await service.start_challenge("run-hint-windows", "target")
    async with service.db.sessions.begin() as session:
        challenge = await session.get(
            ChallengeRecord, ("run-hint-windows", "target")
        )
        assert challenge is not None
        challenge.last_progress_at = clock.value - timedelta(minutes=15)

    expected = {
        89: (False, None),
        90: (True, "hard_stagnation"),
        269: (True, "hard_stagnation"),
        270: (True, "low_yield"),
        329: (True, "low_yield"),
        330: (True, "final_30_minutes"),
    }
    for minute, (eligible, reason) in expected.items():
        clock.value = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
            minutes=minute
        )
        result = await service.evaluate_hint_eligibility(
            "run-hint-windows", "target"
        )
        assert result["hint_signal"]["eligible"] is eligible
        if eligible:
            assert result["hint_signal"]["reason"] == reason
        async with service.db.sessions.begin() as session:
            challenge = await session.get(
                ChallengeRecord, ("run-hint-windows", "target")
            )
            assert challenge is not None
            challenge.hint_eligible = False
            challenge.hint_requested = False

    await service.close()
