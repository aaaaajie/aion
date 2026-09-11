import asyncio
import json

import httpx
import pytest
from pydantic import ValidationError

from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.state.errors import StatePermission
from agent.state.solver_review import project_reviews
from agent.subagents.models import SolverReviewArguments, SolverProgressArguments
from agent.tooling import ToolRegistry, ToolExecutor
from agent.skills import SkillCatalog, SkillSessionContext, SkillTools
from agent.memory.summarizer import SessionMemorySummarizer
from tests.solver_state import build_state
from tests.test_report_delivery import settings
from tests.test_skills import _root, _skill
from tests.test_solver_lifecycle import harness, completion


def record(ref=None, *, conclusion_sequences=None, calibration_basis="Known local fixture validates implementation",
           calibration_sequences=None, **changes):
    sources = conclusion_sequences or []
    validation = {
        "conclusion_sequences": sources, "control_evidence_refs": [ref],
        "calibration_basis": calibration_basis, "calibration_sequences": calibration_sequences or [],
    } if sources else None
    return SolverReviewArguments.model_validate({
        "hypothesis_id": "fixture-path", "covered_sequences": sources,
        "assessment": "no_new_information" if sources else "inconclusive",
        "summary": "Fixture session A with all statuses retained",
        "validation": validation, "next_test": "Recheck known fixture with the same base",
        **changes,
    })


async def evidence(service, context):
    ref = (await service.persist_evidence("run", context, evidence_type="text", source="fixture",
        content="Known fixture returned expected bytes under session A"))["evidence_ref"]
    await service.append_agent_event("run", context.agent_id, "tool_result", {
        "tool_name": "system_shell", "result": {"ok": True, "data": {
            "status": "completed", "exit_code": 0, "output": "expected fixture bytes",
            "evidence_refs": [ref]}}})
    return ref


@pytest.mark.parametrize("summary", ["not run", "timeout", "unread", "control failed", "conditions unknown"])
async def test_review_without_new_sources_does_not_count_and_source_validation(tmp_path, summary):
    service, _, solver = await build_state(tmp_path)
    try:
        await service.record_solver_review("run", solver, record(summary=summary))
        state = await service.solver_review_state("run", "solver")
        assert state["hypotheses"]["fixture-path"]["stagnation_count"] == 0
        assert record(assessment="new_information").validation is None
        foreign = await service.append_agent_event("run", "chief", "assistant_response", {"content": "other"})
        with pytest.raises(StatePermission):
            await service.record_solver_review("run", solver, record(revoked_sequences=[foreign]))
        with pytest.raises(ValidationError):
            record(skill_ids=["common/not-active"])
    finally:
        await service.close()


async def test_review_delivery_restart_revocation_and_checkpoint(tmp_path):
    service, _, solver = await build_state(tmp_path)
    runner = AgentRunner(settings(), ToolRegistry([]), role="solver", state_service=service)
    try:
        ref = await evidence(service, solver)
        source = await service.append_agent_event("run", "solver", "tool_result", {"result": "fixture absent"})
        first = await service.record_solver_review("run", solver, record(ref, conclusion_sequences=[source]))
        await service.record_solver_review("run", solver, record(ref, conclusion_sequences=[source]))
        duplicate = await service.solver_review_state("run", "solver")
        assert duplicate["hypotheses"]["fixture-path"]["stagnation_count"] == 1
        await service.record_solver_review("run", solver, record(ref, conclusion_sequences=[await service.append_agent_event("run", "solver", "tool_result", {"result": "second calibrated fixture"})]))
        store = await AgentStateStore.open(service, run_id="run", agent_id="solver", run_dir=tmp_path / "solver")
        message, delivery = await runner._review_context(store)
        assert '"review_recommended": ["fixture-path"]' in message["content"]
        # A failed model response does not acknowledge the reminder.
        assert (await runner._review_context(store))[1] == delivery
        await store.append_event("solver_review_delivered", delivery)
        assert (await runner._review_context(store)) == (None, None)
        await service.record_solver_review("run", solver, record(ref,
            revoked_sequences=[first],
            summary="Fixture session B: old base no longer calibrated; filter omitted a status"))
        restored = await AgentStateStore.open(service, run_id="run", agent_id="solver", run_dir=tmp_path / "solver")
        state = restored.model_checkpoint()["experiment_reviews"]
        assert source in state["revoked_sequences"]
        assert state["hypotheses"]["fixture-path"]["pending_since"] is None
        message, _ = await runner._review_context(restored)
        assert '"review_recommended": []' in message["content"]
    finally:
        await runner.close()
        await service.close()


async def test_real_solver_review_chain_delivers_and_clears_reminder(tmp_path):
    control = None
    sources = []
    ready = asyncio.Event()
    reached = asyncio.Event()

    async def solve(role, index, body):
        await ready.wait()
        if index == 0:
            return completion("tool_search", {"name": "solver_review"})
        if index < 3:
            return completion("solver_review", record(control, conclusion_sequences=[sources[index - 1]]).model_dump())
        if index == 3:
            assert '"review_recommended": ["fixture-path"]' in body["messages"][-1]["content"]
            return completion("solver_review", record(summary="Review fixture controls before another attempt").model_dump())
        assert '"review_recommended": []' in body["messages"][-1]["content"]
        reached.set()
        return completion("solver_wait")

    sup, service, _, _, chief = await harness(tmp_path, solve, solver_observation=False)
    try:
        solver_id = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        control = await evidence(service, sup._state_context(solver_id))
        for i in range(2):
            sources.append(await service.append_agent_event("run", solver_id, "tool_result", {"result": f"calibrated fixture {i}"}))
        ready.set()
        await asyncio.wait_for(reached.wait(), 5)
        state = await service.solver_review_state("run", solver_id)
        assert state["hypotheses"]["fixture-path"]["stagnation_count"] == 2
    finally:
        await sup.close()
        await service.close()


async def test_skill_registry_activation_survives_real_memory_summary(tmp_path):
    service, _, solver = await build_state(tmp_path)
    root = _root(tmp_path)
    _skill(root, "common", "fixture-calibration", body="Verify fixture controls before generalizing.")
    catalog = SkillCatalog(root)
    context = SkillSessionContext(catalog, role="solver", service=service, run_id="run", agent_id="solver")

    async def call(ctx, name, args):
        result = await ToolExecutor(ToolRegistry([SkillTools(ctx)])).execute([
            {"id": name, "function": {"name": name, "arguments": json.dumps(args)}}])
        assert result[0].result["ok"]
        return result[0].result["data"]

    try:
        found = await call(context, "skill_search", {"query": "fixture calibration"})
        skill_id = found["skills"][0]["skill_id"]
        activated = await call(context, "skill_invoke", {"skill_id": skill_id})
        assert activated["activation_status"] == "activated"
        ref = await evidence(service, solver)
        await service.record_solver_review("run", solver, record(summary="New behavior; active fixture skill guides next test"))
        store = await AgentStateStore.open(service, run_id="run", agent_id="solver", run_dir=tmp_path / "solver")
        async def respond(request):
            prompt = json.dumps(json.loads(request.content)["messages"])
            assert skill_id in prompt
            assert "Verify fixture controls before generalizing." not in prompt
            return httpx.Response(200, json=completion(content="# Current State\nFixture controls retained."))
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            summary = await SessionMemorySummarizer(settings(), client=client).summarize(
                current_memory="", checkpoint=store.model_checkpoint(), recent_messages=AgentRunner._compact_skill_messages([
                    {"role": "system", "content": context.render_system_context()}]), recent_events=[])
            await store.write_memory(summary)
        restored = await AgentStateStore.open(service, run_id="run", agent_id="solver", run_dir=tmp_path / "solver")
        restored_context = SkillSessionContext(catalog, role="solver", service=service, run_id="run", agent_id="solver",
            active_skills=restored.model_checkpoint()["active_skills"])
        assert restored_context.render_system_context() == context.render_system_context()
        assert (await call(restored_context, "skill_invoke", {"skill_id": skill_id}))["activation_status"] == "already_active"
        assert restored.model_checkpoint()["experiment_reviews"]["hypotheses"]["fixture-path"]["review"]["assessment"] == "inconclusive"
    finally:
        await service.close()


def test_only_new_review_schema_is_exposed():
    minimal = record().model_dump()
    assert SolverReviewArguments.model_validate(minimal).validation is None
    for field in ('hypothesis_id', 'covered_sequences', 'assessment', 'summary', 'next_test'):
        with pytest.raises(ValidationError):
            SolverReviewArguments.model_validate({k: v for k, v in minimal.items() if k != field})
    with pytest.raises(ValidationError):
        SolverProgressArguments.model_validate({'summary': 'progress', 'review': minimal})
    for assessment in ('new_information', 'no_new_information'):
        assert record(assessment=assessment).validation is None
    with pytest.raises(ValidationError):
        record(observation_revision=1)


async def test_revoked_source_invalidates_calibration_chain_and_count(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        sources = [await service.append_agent_event('run', 'solver', 'tool_result', {'result': str(i)}) for i in range(3)]
        first = await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[sources[0]]))
        second = await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[sources[1]],
            calibration_basis=None, calibration_sequences=[first]))
        third = await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[sources[2]],
            calibration_basis=None, calibration_sequences=[second]))
        await service.record_solver_review('run', solver, record(hypothesis_id='withdrawal', revoked_sequences=[sources[0]]))
        state = await service.solver_review_state('run', 'solver')
        assert {first, second, third, *sources} <= set(state['revoked_sequences'])
        assert state['hypotheses']['fixture-path']['stagnation_count'] == 0
        assert state['hypotheses']['fixture-path']['pending_since'] is None
        with pytest.raises(StatePermission):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[sources[2]]))
    finally:
        await service.close()


async def test_inconclusive_cannot_be_reused_as_calibration(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        calibration = await service.record_solver_review('run', solver, record())
        source = await service.append_agent_event('run', 'solver', 'tool_result', {'result': 'fixture'})
        with pytest.raises(StatePermission, match='Calibration'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source],
                calibration_basis=None, calibration_sequences=[calibration]))
    finally:
        await service.close()


async def test_new_information_resets_count_and_environment_independent_review_survives(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        sources = [await service.append_agent_event('run', 'solver', 'tool_result', {'result': str(i)}) for i in range(3)]
        for source in sources[:2]:
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source], environment_dependent=False))
        state = await service.solver_review_state('run', 'solver')
        assert state['hypotheses']['fixture-path']['stagnation_count'] == 2
        await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[sources[2]],
            assessment='new_information', environment_dependent=False))
        await service.invalidate_agent_resources('run', 'solver', reason='environment replaced')
        state = await service.solver_review_state('run', 'solver')
        assert not state['revoked_sequences']
        assert state['hypotheses']['fixture-path']['stagnation_count'] == 0
        assert state['hypotheses']['fixture-path']['pending_since'] is None
    finally:
        await service.close()


async def test_validated_sources_must_be_owned_results_not_replayed_or_self_revoked(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        foreign = await service.append_agent_event('run', 'chief', 'tool_result', {'result': 'foreign'})
        assistant = await service.append_agent_event('run', 'solver', 'assistant_response', {'content': 'claim'})
        replayed = await service.append_agent_event('run', 'solver', 'tool_result', {'result': 'old', 'replayed': True})
        source = await service.append_agent_event('run', 'solver', 'tool_result', {'result': 'fixture'})
        for seq in (foreign, assistant, replayed):
            with pytest.raises(StatePermission):
                await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[seq]))
        with pytest.raises(StatePermission):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source], revoked_sequences=[source]))
    finally:
        await service.close()


async def test_observer_assessment_requires_owned_snapshot(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        foreign = await service.append_agent_event('run', 'chief', 'solver_observation_snapshot', {})
        wrong_kind = await service.append_agent_event('run', 'solver', 'assistant_response', {})
        for revision in (foreign, wrong_kind):
            with pytest.raises(StatePermission, match='owned observation'):
                await service.record_solver_review('run', solver, record(
                    observation_revision=revision, observation_assessment='uncertain'))
        revision = await service.append_agent_event('run', 'solver', 'solver_observation_snapshot', {})
        await service.record_solver_review('run', solver, record(
            observation_revision=revision, observation_assessment='dismissed'))
        state = await service.solver_review_state('run', 'solver')
        assert state['hypotheses']['fixture-path']['review']['observation_revision'] == revision
    finally:
        await service.close()


@pytest.mark.parametrize('stage', ['parse', 'schema', 'semantic', 'permission', 'conflict'])
async def test_rejected_call_cannot_validate_conclusions_or_calibration(tmp_path, stage):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        source = await service.append_agent_event('run', 'solver', 'tool_result', {
            'tool_name': 'system_shell',
            'result': {'ok': False, 'error': {'stage': stage, 'code': 'rejected', 'message': 'Not executed'}},
        })
        for assessment in ('new_information', 'no_new_information'):
            with pytest.raises(StatePermission, match='Rejected tool calls'):
                await service.record_solver_review('run', solver, record(
                    ref, conclusion_sequences=[source], assessment=assessment))
        assert not (await service.solver_review_state('run', 'solver'))['hypotheses']

        # A rejected call can be acknowledged, but that review cannot calibrate a later result.
        acknowledged = await service.record_solver_review('run', solver, record(covered_sequences=[source]))
        valid_source = await service.append_agent_event('run', 'solver', 'tool_result', {'result': 'fixture'})
        with pytest.raises(StatePermission, match='Calibration'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[valid_source],
                calibration_basis=None, calibration_sequences=[acknowledged]))
    finally:
        await service.close()


def test_stagnation_count_requires_a_new_source_not_a_new_combination():
    rows = []
    for sequence, (sources, count) in enumerate([
        ([1, 2], 1), ([1], 1), ([2, 1], 1),
        ([1, 2, 3], 2), ([3], 2), ([1, 2, 3, 4], 3),
    ], start=10):
        rows.append({'sequence': sequence, 'payload': {'review': record(
            'evidence:fixture', conclusion_sequences=sources).model_dump()}})
        hypothesis = project_reviews(rows)['hypotheses']['fixture-path']
        assert hypothesis['stagnation_count'] == count
        assert hypothesis['pending_since'] == (13 if count >= 2 else None)


async def test_uncertain_attempts_stall_without_becoming_calibration(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        sources = [await service.append_agent_event('run', 'solver', 'tool_result',
            {'result': str(i)}) for i in range(4)]
        first = await service.record_solver_review('run', solver, record(
            covered_sequences=[sources[0]], assessment='new_information'))
        for source in sources[1:3]:
            await service.record_solver_review('run', solver, record(covered_sequences=[source]))
        await service.record_solver_review('run', solver, record())
        await service.record_solver_review('run', solver, record(covered_sequences=[sources[1]]))
        state = await service.solver_review_state('run', 'solver')
        assert state['hypotheses']['fixture-path']['stagnation_count'] == 2
        assert state['hypotheses']['fixture-path']['pending_since'] is not None
        with pytest.raises(StatePermission, match='Calibration'):
            await service.record_solver_review('run', solver, record(await evidence(service, solver),
                conclusion_sequences=[sources[3]], calibration_basis=None, calibration_sequences=[first]))
        await service.record_solver_review('run', solver, record(
            covered_sequences=[sources[3]], assessment='new_information'))
        state = await service.solver_review_state('run', 'solver')
        assert state['hypotheses']['fixture-path']['stagnation_count'] == 0
        assert state['hypotheses']['fixture-path']['pending_since'] is None
    finally:
        await service.close()
