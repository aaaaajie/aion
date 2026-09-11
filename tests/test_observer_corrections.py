"""Offline state/Runner contracts; no model or target network access."""
import asyncio
import json
from datetime import timedelta

import httpx
import pytest

from agent.config import AgentSettings
from agent.observation import SolverObserver
from agent.observation_models import ObservationMap, validate_observation_output
from agent.subagents.models import SolverReviewArguments
from agent.state.errors import StatePermission
from agent.state.observer_corrections import latest_correction
from tests.solver_state import build_state
from tests.test_solver_observation import settings, trace, map_response
from tests.test_solver_lifecycle import completion, harness


def proposal(sources, assessment='open', category='repeated_expansion'):
    return {'category': category, 'claim': '相同假设继续扩大而未验证前提',
            'sources': sources, 'suggestion': '核对小样本和目标检查是否已完成', 'assessment': assessment}


async def execution(service, *, status='completed', output='calibrated', exit_code=0):
    return await service.append_agent_event('run', 'solver', 'tool_result', {
        'tool_name': 'system_shell', 'tool_call_id': f'exec-{service.clock().isoformat()}',
        'result': {'ok': True, 'data': {'status': status, 'output': output, 'exit_code': exit_code}},
    })


async def save(service, context, sources, assessment='open', category='repeated_expansion'):
    snapshot = await service.solver_observation_state('run', context)
    return await service.save_solver_observation('run', context,
        generation=snapshot['generation'], expected_revision=snapshot['revision'],
        through_sequence=max(sources),
        observation={**ObservationMap().model_dump(), 'correction': proposal(sources, assessment, category)})


async def state(service):
    async with service.db.sessions() as session:
        return await latest_correction(session, 'run', 'solver')


async def deliver(service, context):
    current = await state(service)
    await service.append_agent_event('run', 'solver', 'assistant_response',
        {'observation_correction_id': current['id'], 'content': 'received'})
    await service.maintain_observer_correction('run', context)


async def test_feedback_is_not_resolution_and_real_execution_resolves(tmp_path):
    service, _, context = await build_state(tmp_path)
    try:
        await service.transition_agent('run', 'solver', 'running')
        seq = await execution(service)
        revision = await save(service, context, [seq])
        original = await state(service)
        await deliver(service, context)
        assertion = await service.record_solver_review('run', context, SolverReviewArguments(
            hypothesis_id='h', covered_sequences=[seq], assessment='inconclusive',
            summary='已经改了', next_test='verify', observation_revision=revision, observation_assessment='corrected'))
        with pytest.raises(StatePermission, match='new completed execution'):
            await save(service, context, [assertion], 'resolved')
        assert (await state(service))['status'] == 'open'
        started = await execution(service, status='running')
        with pytest.raises(StatePermission):
            await save(service, context, [started], 'resolved')
        completed = await execution(service)
        await save(service, context, [completed], 'resolved')
        final = await state(service)
        assert final['id'] == original['id'] and final['status'] == 'resolved'
    finally:
        await service.close()


async def test_fresh_evidence_and_delivery_required_for_single_escalation_after_restart(tmp_path):
    service, _, context = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    try:
        await service.transition_agent('run', 'solver', 'running')
        seq = await execution(service)
        await save(service, context, [seq])
        first_id = (await state(service))['id']
        # Failed response / old evidence / a differently named category cannot restart the clock.
        now[0] += timedelta(seconds=400)
        await save(service, context, [await execution(service)])
        assert (await state(service))['persistent_checks'] == 0
        await deliver(service, context)
        await save(service, context, [await execution(service)], category='goal_drift')
        assert (await state(service))['id'] == first_id
        assert (await state(service))['persistent_checks'] == 0
        await save(service, context, [await execution(service)])
        await save(service, context, [await execution(service)])
        await service.maintain_observer_correction('run', context)
        assert not (await state(service))['escalated']
        now[0] += timedelta(seconds=301)
        await service.maintain_observer_correction('run', context)
        assert (await state(service))['escalated']
        dbpath, runroot, workspace = service.db.path, service.run_root, service.workspace_root
    finally:
        await service.close()
    from agent.state import StateService, StateDatabase
    restored = StateService(StateDatabase(dbpath), run_root=runroot, workspace_root=workspace)
    restored.clock = lambda: now[0]
    try:
        await restored.maintain_observer_correction('run', context)
        from sqlalchemy import select
        from agent.state.models import ReportRecord
        async with restored.db.sessions() as session:
            reports = (await session.scalars(select(ReportRecord).where(ReportRecord.report_type == 'observer_correction'))).all()
            assert len(reports) == 1 and reports[0].parent_id == 'chief'
        from scripts.analyze_run_performance import analyze_run
        metrics = analyze_run(dbpath, 'run')['observer']
        assert metrics['corrections']['created'] == 1
        assert metrics['corrections']['delivered'] == 1
        assert metrics['corrections']['escalated'] == 1
        assert metrics['verified_correction_count'] == 0
    finally:
        await restored.close()


async def test_revocation_hides_and_retires_old_concern(tmp_path):
    service, _, context = await build_state(tmp_path)
    try:
        await service.transition_agent('run', 'solver', 'running')
        seq = await execution(service)
        await save(service, context, [seq])
        await service.record_solver_review('run', context, SolverReviewArguments(
            hypothesis_id='h', covered_sequences=[seq], assessment='inconclusive',
            summary='对照失效', next_test='verify', revoked_sequences=[seq]))
        assert (await service.solver_observation_state('run', context))['correction'] is None
        await service.maintain_observer_correction('run', context)
        assert (await state(service))['status'] == 'revoked'
    finally:
        await service.close()


async def test_failure_and_uncertainty_do_not_count_and_stale_suggestions_hidden(tmp_path):
    service, _, context = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))) as client:
        observer = SolverObserver(settings(), service, context, client)
        try:
            await service.transition_agent('run', 'solver', 'running')
            await save(service, context, [await execution(service)])
            await observer.refresh()
            assert observer.context_message() and observer.delivery_correction_id
            await deliver(service, context)
            await save(service, context, [await execution(service)], 'uncertain')
            assert (await state(service))['persistent_checks'] == 0
            snap = await service.solver_observation_state('run', context)
            seq = await execution(service)
            await service.save_solver_observation('run', context, generation=0,
                expected_revision=snap['revision'], through_sequence=seq, observation=None, error='bad output')
            await observer.refresh()
            assert '旧图谱' in observer.context_message()['content']
            assert observer.delivery_correction_id is None
            await save(service, context, [await execution(service)])
            now[0] += timedelta(seconds=181)
            await observer.refresh()
            assert '旧图谱' in observer.context_message()['content']
            assert observer.delivery_revision is None
        finally:
            await observer.close()
            await service.close()


async def test_waiting_observer_runs_without_runner_and_urgent_review_respects_cooldown(tmp_path):
    service, _, context = await build_state(tmp_path)
    now = [service.clock()]
    service.clock = lambda: now[0]
    started = asyncio.Event()
    requests = []
    async def respond(request):
        body = json.loads(request.content); requests.append(body); started.set()
        return httpx.Response(200, json=map_response(body))
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = SolverObserver(settings(), service, context, client)
        try:
            await service.transition_agent('run', 'solver', 'running')
            await service.transition_agent('run', 'solver', 'waiting')
            old = await trace(service)
            observer.start()
            await asyncio.wait_for(started.wait(), 2)
            await asyncio.wait_for(observer.task, 2)
            await observer.poll()
            started.clear()
            await service.record_solver_review('run', context, SolverReviewArguments(
                hypothesis_id='h', covered_sequences=[old[0]], assessment='inconclusive',
                summary='条件无效', next_test='verify', revoked_sequences=[old[0]]))
            await observer.poll()
            assert len(requests) == 1
            now[0] += timedelta(seconds=61)
            observer.wake()
            await asyncio.wait_for(started.wait(), 2)
            await asyncio.wait_for(observer.task, 2)
            assert len(requests) == 2
            assert 'evidence' in json.loads(requests[1]['messages'][-1]['content'])
        finally:
            await observer.close()
            await service.close()


def test_default_enabled_and_explicit_disabled(monkeypatch):
    monkeypatch.delenv('AION_SOLVER_OBSERVATION', raising=False)
    assert AgentSettings(llm_api_key='test', llm_base_url='https://model.test', llm_model='fixture', _env_file=None).solver_observation
    assert not AgentSettings(llm_api_key='test', llm_base_url='https://model.test', llm_model='fixture', solver_observation=False, _env_file=None).solver_observation


def test_policy_preserves_goal_and_valid_common_checks():
    from agent.prompts.loader import load_prompt
    solver = load_prompt('solver_system.txt')
    memory = load_prompt('session_memory_system.txt')
    observer = load_prompt('solver_observation_system.txt')
    assert 'shortest goal-related check' in solver
    assert 'two valid tests' in solver and 'Small evidence-based checks' in solver
    assert 'verified capabilities' in memory
    assert '同条件结果矛盾' in observer and '少量有依据' in observer


async def test_reading_same_background_completion_twice_is_not_two_checks(tmp_path):
    service, _, context = await build_state(tmp_path)
    try:
        await service.transition_agent('run', 'solver', 'running')
        await save(service, context, [await execution(service)])
        await deliver(service, context)
        await service.create_shell_task('run', 'solver', task_id='background', pid=1,
            process_started_at=1, cwd='.', temp_dir='tmp', output_path='out', capture_limit=100)
        await service.finish_shell_task('run', 'solver', 'background', status='completed',
            exit_code=0, output_chars=6, truncated=False, timed_out=False)
        for _ in range(2):
            seq = await service.append_agent_event('run', 'solver', 'tool_result', {
                'tool_name': 'system_task_output',
                'result': {'ok': True, 'data': {'status': 'completed', 'task_id': 'background',
                          'output': 'sample', 'exit_code': 0, 'truncated': False}},
            })
            await save(service, context, [seq])
        assert (await state(service))['persistent_checks'] == 1
    finally:
        await service.close()


async def test_supervisor_observes_during_long_foreground_tool(tmp_path):
    observation_finished = asyncio.Event()
    main_finished = asyncio.Event()
    async def observe(body):
        # The model response deliberately waits for the foreground tool to start.
        # If observation ran only between Solver rounds this would deadlock.
        async with asyncio.timeout(3):
            while not (await service.list_shell_tasks('run', statuses=['running'])):
                await asyncio.sleep(0.01)
        observation_finished.set()
        return map_response(body)
    async def model(role, index, body):
        if index < 6:
            return completion('system_read_file', {'file_path': 'shared/answer.txt'})
        if index == 6:
            return completion('system_shell', {'command': 'sleep 1', 'timeout': 3})
        assert observation_finished.is_set()
        assert any('<solver_observation>' in str(message.get('content', '')) for message in body['messages'])
        main_finished.set()
        await asyncio.Event().wait()
    sup, service, _, _, chief = await harness(tmp_path, model, observation_model=observe)
    try:
        await sup.create_solver(chief, 'a')
        await asyncio.wait_for(main_finished.wait(), 5)
    finally:
        await sup.close()
        await service.close()


async def test_concurrent_polls_have_one_request_and_late_result_cannot_revive(tmp_path):
    service, _, context = await build_state(tmp_path)
    started, release = asyncio.Event(), asyncio.Event()
    calls = []
    async def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        started.set()
        await release.wait()
        return httpx.Response(200, json=map_response(body))
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = SolverObserver(settings(), service, context, client)
        try:
            await service.transition_agent('run', 'solver', 'running')
            await trace(service)
            await asyncio.gather(*(observer.poll() for _ in range(8)))
            await asyncio.wait_for(started.wait(), 2)
            assert len(calls) == 1
            await service.transition_agent('run', 'solver', 'stopped')
            release.set()
            await asyncio.wait_for(observer.task, 2)
            await observer.poll()
            assert not observer.snapshot['active']
            assert observer.snapshot['revision'] == 0
            assert await state(service) is None
        finally:
            await observer.close()
            await service.close()
