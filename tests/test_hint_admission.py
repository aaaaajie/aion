"""Focused tests for the transactional Hint admission policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent.state import StateService
from agent.state.schemas import CapabilityContext, ChallengeImport
from agent.state.models import AgentRecord, ChallengeRecord, RunRecord


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


async def _hint_fixture(tmp_path: Path) -> tuple[StateService, _Clock, CapabilityContext, str, str]:
    clock = _Clock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-hint-policy",
        duration_minutes=120,
        challenges=[ChallengeImport(unique_code="target"), ChallengeImport(unique_code="other")],
    )
    chief = await service.register_agent("run-hint-policy", role="chief")
    challenge_agent = await service.register_agent(
        "run-hint-policy",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="target",
    )
    await service.start_challenge("run-hint-policy", "target")
    clock.advance(480)
    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run-hint-policy", "target"))
        assert challenge is not None
        challenge.work_status = "warning"
        challenge.stagnation_level = 1
        challenge.hint_eligible = True
        challenge.control_since = clock.value

    prior = await service.publish_control_report(
        "run-hint-policy",
        sender_id=challenge_agent["agent_id"],
        recipient_id=chief["agent_id"],
        unique_code="target",
        report_type="challenge_status",
        status="analyzing",
        payload={"summary": "prior evidence"},
    )
    await service.publish_control_report(
        "run-hint-policy",
        sender_id=challenge_agent["agent_id"],
        recipient_id=chief["agent_id"],
        unique_code="target",
        report_type="challenge_status",
        status="ready_for_hint",
        payload={
            "summary": "complete convergence proof",
            "hint_recommended": True,
            "blocker": "one concrete path remains unverified",
            "evidence_refs": [f"report:{prior['report_id']}"],
        },
    )
    return (
        service,
        clock,
        CapabilityContext(
            run_id="run-hint-policy", agent_id=chief["agent_id"], role="chief"
        ),
        chief["agent_id"],
        f"report:{prior['report_id']}",
    )


@pytest.mark.asyncio
async def test_hint_requires_warning_level_and_structured_basis(tmp_path: Path) -> None:
    service, clock, context, _, evidence_ref = await _hint_fixture(tmp_path)

    rejected = await service.evaluate_hint_admission(
        "run-hint-policy",
        "target",
        context,
        basis="second_pass_convergence",
        evidence_refs=[evidence_ref],
    )
    assert rejected["eligible"] is False
    assert rejected["rejection_code"] == "second_pass_required"

    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run-hint-policy", "target"))
        assert challenge is not None
        challenge.stagnation_level = 0
    level_zero = await service.evaluate_hint_admission(
        "run-hint-policy",
        "target",
        context,
        basis="high_probability_path",
        evidence_refs=[evidence_ref],
    )
    assert level_zero["rejection_code"] == "stagnation_level_required"

    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run-hint-policy", "target"))
        assert challenge is not None
        challenge.stagnation_level = 1
    allowed = await service.evaluate_hint_admission(
        "run-hint-policy",
        "target",
        context,
        basis="high_probability_path",
        evidence_refs=[evidence_ref],
    )
    assert allowed["eligible"] is True
    assert allowed["remaining_stagnation_seconds"] >= 300
    await service.close()


@pytest.mark.asyncio
async def test_hint_rejects_active_execution_and_late_stagnation_window(
    tmp_path: Path,
) -> None:
    service, clock, context, _, evidence_ref = await _hint_fixture(tmp_path)
    challenge = await service.get_overview("run-hint-policy")
    challenge_id = next(
        item["agent_id"]
        for item in challenge["agents"]
        if item["role"] == "challenge"
    )
    execution = await service.register_agent(
        "run-hint-policy",
        role="execution",
        parent_id=challenge_id,
        unique_code="target",
        hypothesis_key="late-path",
        task_key="late-path-1",
        task_stage="validation",
        context_refs=[evidence_ref],
        mission="verify the blocker",
    )
    active = await service.evaluate_hint_admission(
        "run-hint-policy",
        "target",
        context,
        basis="high_probability_path",
        evidence_refs=[evidence_ref],
    )
    assert active["rejection_code"] == "execution_active"

    # The fixture is now converged.  Move the run close to its deadline and
    # keep the challenge's active clock at eight minutes so the five-minute
    # action window remains available.
    async with service.db.sessions.begin() as session:
        agent = await session.get(AgentRecord, execution["agent_id"])
        assert agent is not None
        agent.status = "completed"
        run = await session.get(RunRecord, "run-hint-policy")
        assert run is not None
        run.deadline_at = clock.value + timedelta(minutes=20)
        row = await session.get(ChallengeRecord, ("run-hint-policy", "target"))
        assert row is not None
        row.active_since = clock.value - timedelta(seconds=480)
    await service.close_challenge("run-hint-policy", "other")

    near_deadline = await service.evaluate_hint_admission(
        "run-hint-policy",
        "target",
        context,
        basis="near_deadline",
        evidence_refs=[evidence_ref],
    )
    assert near_deadline["eligible"] is True
    assert near_deadline["remaining_run_seconds"] <= 30 * 60
    await service.close()
