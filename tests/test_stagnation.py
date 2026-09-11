from datetime import timedelta

import pytest

from agent.config import StagnationPolicy
from agent.state import AgentReportInput, CapabilityContext
from agent.state.errors import StatePermission
from tests.solver_state import build_state


@pytest.mark.asyncio
async def test_stagnation_stages_are_idempotent_and_worker_is_singleton(tmp_path):
    service, _, solver = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    policy = StagnationPolicy(8, 14, 22, 8, 1)
    try:
        now[0] += timedelta(seconds=7)
        await service.heartbeat("run", "solver", solver, sample_event=True)
        assert await service.scan_stagnation("run", policy) == []
        now[0] += timedelta(seconds=1)
        first = await service.scan_stagnation("run", policy)
        assert first[0]["kind"] == "strategy_reset"
        assert await service.scan_stagnation("run", policy) == []

        now[0] += timedelta(seconds=6)
        assert (await service.scan_stagnation("run", policy))[0]["kind"] == "alternate_worker"
        worker = await service.create_stagnation_worker(
            "run", unique_code="a", solver_id="solver", timeout_seconds=8
        )
        assert worker is not None
        duplicate = await service.create_stagnation_worker(
            "run", unique_code="a", solver_id="solver", timeout_seconds=8
        )
        assert duplicate["agent_id"] == worker["agent_id"]

        worker_context = CapabilityContext(
            run_id="run", agent_id=worker["agent_id"], role="worker", unique_code="a"
        )
        await service.finalize_worker(
            "run",
            worker["agent_id"],
            worker_context,
            AgentReportInput(
                status="completed",
                summary="No new path verified",
                tested=["alternate entry"],
                untested=["different trust boundary"],
            ),
        )
        events = await service.list_agent_events("run", worker["agent_id"])
        assert any(e["event_type"] == "solver_stagnation_worker_finished" for e in events)
        now[0] += timedelta(seconds=8)
        assert (await service.scan_stagnation("run", policy))[0]["kind"] == "rotate"
        retry = await service.scan_stagnation("run", policy)
        assert retry[0]["kind"] == "rotate"
        run_events = await service.list_agent_events("run", "solver")
        assert sum(
            event["event_type"] == "solver_stagnation_rotation_requested"
            for event in run_events
        ) == 1
    finally:
        await service.close()


@pytest.mark.asyncio
async def test_evidence_does_not_reset_stagnation_clock_or_revision(tmp_path):
    service, _, solver = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    policy = StagnationPolicy(8, 14, 22, 8, 1)
    try:
        now[0] += timedelta(seconds=8)
        await service.scan_stagnation("run", policy)
        before = (await service.get_overview("run", unique_code="a"))["challenges"][0]
        now[0] += timedelta(seconds=4)
        await service.persist_evidence(
            "run",
            solver,
            evidence_type="text",
            source="fixture",
            content="verified response difference",
        )
        after = (await service.get_overview("run", unique_code="a"))["challenges"][0]
        assert after["strategy_revision"] == before["strategy_revision"]
        assert after["stagnation_stage"] == "review_due"
        assert after["last_progress_at"] == before["last_progress_at"]
        now[0] += timedelta(seconds=5)
        assert (await service.scan_stagnation("run", policy))[0]["kind"] == "alternate_worker"
    finally:
        await service.close()


@pytest.mark.asyncio
async def test_solver_review_rejects_stale_strategy_revision(tmp_path):
    service, _, solver = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    try:
        now[0] += timedelta(seconds=8)
        await service.scan_stagnation("run", StagnationPolicy(8, 14, 22, 8, 1))
        from agent.subagents.models import SolverReviewArguments

        review = SolverReviewArguments(
            hypothesis_id="old",
            covered_sequences=[],
            assessment="inconclusive",
            summary="old revision",
            next_test="new test",
            strategy_revision=1,
        )
        with pytest.raises(StatePermission, match="expired"):
            await service.record_solver_review("run", solver, review)
    finally:
        await service.close()


async def test_only_new_validated_conclusions_reset_progress(tmp_path):
    from tests.test_solver_review import evidence, record
    service, _, solver = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]

    async def challenge():
        return (await service.get_overview('run', unique_code='a'))['challenges'][0]

    try:
        before = (await challenge())['last_progress_at']
        now[0] += timedelta(seconds=5)
        source = await service.append_agent_event('run', 'solver', 'tool_result', {'result': 'new response'})
        await service.record_solver_review('run', solver, record(assessment='new_information', covered_sequences=[source]))
        await service.record_observation('run', 'a', category='fixture', summary='another output', source='fixture')
        assert (await challenge())['last_progress_at'] == before
        control = await evidence(service, solver)
        validated = record(control, conclusion_sequences=[source], assessment='new_information',
            acquired_capabilities=[{'kind': 'file_read', 'target_environment': 'fixture service',
                'scope': 'Session A; four parent segments; known control readable',
                'limitations': 'Original candidate must be retested after repairing the client'}])
        await service.record_solver_review('run', solver, validated)
        progress = (await challenge())['last_progress_at']
        assert progress == now[0].isoformat()
        now[0] += timedelta(seconds=4)
        await service.record_solver_review('run', solver, validated)
        assert (await challenge())['last_progress_at'] == progress
        events = await service.list_agent_events('run', 'solver')
        assert sum(e['event_type'] == 'challenge_progress_recorded' for e in events) == 1
        now[0] += timedelta(seconds=4)
        assert (await service.scan_stagnation('run', StagnationPolicy(8, 14, 22, 8, 1)))[0]['kind'] == 'strategy_reset'
        packet = await service.get_stagnation_packet('run', 'a')
        assert packet['acquired_capabilities'][0]['scope'] == validated.acquired_capabilities[0].scope
        assert packet['directions'][0]['validation']['control_evidence_refs'] == [control]
        assert packet['directions'][0]['next_test'] == validated.next_test
    finally:
        await service.close()


async def test_continuous_evidence_cannot_prevent_review_or_revive_completion(tmp_path):
    service, _, solver = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    policy = StagnationPolicy(8, 14, 22, 8, 1)
    try:
        for i in range(8):
            now[0] += timedelta(seconds=1)
            await service.persist_evidence('run', solver, evidence_type='text', source='fixture', content=f'same response {i}')
        assert (await service.scan_stagnation('run', policy))[0]['kind'] == 'strategy_reset'
        from agent.state.models import ChallengeRecord
        async with service.db.sessions.begin() as session:
            row = await session.get(ChallengeRecord, ('run', 'a'))
            row.is_completed = True
            row.work_status = 'completed'
        await service.persist_evidence('run', solver, evidence_type='text', source='fixture', content='late output')
        now[0] += timedelta(seconds=60)
        assert await service.scan_stagnation('run', policy) == []
    finally:
        await service.close()
