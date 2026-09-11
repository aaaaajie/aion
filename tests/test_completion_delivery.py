"""Offline regressions for durable completion delivery and waiter races."""
import asyncio

import pytest

from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.tooling import ToolRegistry
from tests.solver_state import build_state
from tests.test_report_delivery import settings


@pytest.mark.parametrize('kind', ['shell_task_finished', 'network_task_status_changed', 'http_interaction_status_changed'])
async def test_completion_before_wait_and_delivery_paging(tmp_path, kind):
    service, _, _ = await build_state(tmp_path)
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        for i in range(23):
            payload = ({'interaction_id': str(i), 'execution_status': 'completed'}
                       if kind.startswith('http') else {'task_id': str(i), 'status': 'completed'})
            await service.append_agent_event('run', 'solver', kind, payload)
        assert (await service.record_controller_wait('run', 'solver', None))['status'] == 'ready'
        assert not await service.pending_execution_completions('run', 'chief')
        message, delivery = await runner._review_context(store)
        assert 'new_completions' in message['content']
        assert len(delivery['completion_sequences']) == 20
        # A failed model call does not persist a response and cannot consume the batch.
        assert (await runner._review_context(store))[1] == delivery
        await store.append_event('assistant_response', {'completion_sequences': delivery['completion_sequences']})
        # No separate acknowledgement is needed, including after reopening the store.
        restored = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        _, remainder = await runner._review_context(restored)
        assert len(remainder['completion_sequences']) == 3
        await restored.append_event('assistant_response', {'completion_sequences': remainder['completion_sequences']})
        assert not await service.pending_execution_completions('run', 'solver')
        assert (await service.record_controller_wait('run', 'solver', None))['code'] == 'no_wait_source'
        execution = (await service.solver_review_state('run', 'solver'))['execution']
        assert len(execution['tasks']) == 23  # Unread is independent of delivery.
        assert all(task['status'] == 'completed' for task in execution['tasks'])
    finally:
        await runner.close()
        await service.close()


@pytest.mark.parametrize('kind', ['shell', 'network'])
async def test_native_finish_notifies_after_wait_once(tmp_path, kind):
    service, _, _ = await build_state(tmp_path)
    try:
        if kind == 'shell':
            await service.create_shell_task('run', 'solver', task_id='task', pid=123,
                process_started_at=1, cwd=str(tmp_path), temp_dir=str(tmp_path),
                output_path=str(tmp_path/'output'), capture_limit=100)
            async def finish():
                await service.finish_shell_task('run', 'solver', 'task', status='completed',
                    exit_code=0, output_chars=0, truncated=False, timed_out=False)
        else:
            await service.create_network_task('run', 'solver', task_id='task', scan_intent='discover',
                result_path=str(tmp_path/'output'), estimated_hosts=1, estimated_ports=1,
                estimated_requests=1, requested_concurrency=1, priority=50)
            async def finish():
                await service.update_network_task('run', 'solver', 'task', status='completed')
        waiting = await service.record_controller_wait('run', 'solver', None)
        assert waiting['status'] == 'waiting'
        key = service.agent_signal_key('run', 'solver')
        # Complete before the condition is subscribed: generations must retain the signal.
        await finish()
        signal = await service.notifier.wait(key, waiting['sequence'], .01)
        assert signal > waiting['sequence']
        await finish()
        assert await service.notifier.current(key) == signal
        pending = await service.pending_execution_completions('run', 'solver')
        assert len(pending) == 1
        # A fresh signal bus simulates a restart/lost notification; persistent state wins.
        from agent.state.wakeup import StateSignalBus
        service.notifier = StateSignalBus()
        assert (await service.record_controller_wait('run', 'solver', None))['status'] == 'ready'
        await service.transition_agent('run', 'solver', 'paused')
        assert (await service.record_controller_wait('run', 'solver', None))['status'] == 'paused'
    finally:
        await service.close()


async def test_http_analysis_completion_each_revision_once(tmp_path):
    service, _, _ = await build_state(tmp_path)
    try:
        for status in ('not_requested', 'queued', 'running', 'completed', 'completed', 'queued', 'failed'):
            await service.append_agent_event('run', 'solver', 'http_interaction_status_changed', {
                'interaction_id': 'http', 'execution_status': 'completed', 'analysis_status': status,
            })
        pending = await service.pending_execution_completions('run', 'solver')
        assert len(pending) == 3
        assert [item['status'] for item in pending] == ['completed', 'completed', 'failed']
        assert pending[1]['phase'] == pending[2]['phase'] == 'analysis'
        await service.append_agent_event('run', 'solver', 'http_interaction_status_changed', {
            'interaction_id': 'simultaneous', 'execution_status': 'failed', 'analysis_status': 'failed',
        })
        pending = await service.pending_execution_completions('run', 'solver')
        assert len(pending) == 4
        assert pending[-1]['phase'] == 'execution_and_analysis'

        await service.append_agent_event('run', 'solver', 'assistant_response', {
            'completion_sequences': [item['sequence'] for item in pending]})
        assert (await service.record_controller_wait('run', 'solver', None))['code'] == 'no_wait_source'
    finally:
        await service.close()


@pytest.mark.parametrize('drop_signal', [False, True])
async def test_real_controller_resumes_once_for_completion(tmp_path, monkeypatch, drop_signal):
    from tests.test_solver_lifecycle import harness, completion
    ready = asyncio.Event()
    async def model(*_):
        await ready.wait()
        return completion('solver_wait')
    supervisor, service, platform, calls, chief = await harness(
        tmp_path, model, solver_observation=False)
    try:
        original_wait = service.notifier.wait
        async def fast_health_check(key, cursor, timeout):
            return await original_wait(key, cursor, min(timeout, .02))
        monkeypatch.setattr(service.notifier, 'wait', fast_health_check)
        solver = (await supervisor.create_solver(chief, 'a'))['data']['agent_id']
        for task in ('task', 'remaining'):
            await service.create_shell_task('run', solver, task_id=task, pid=123,
                process_started_at=1, cwd=str(tmp_path), temp_dir=str(tmp_path),
                output_path=str(tmp_path/task), capture_limit=100)
        ready.set()
        async with asyncio.timeout(5):
            while (await service.get_agent_runtime('run', solver))['agent']['status'] != 'waiting':
                await asyncio.sleep(.005)
        if drop_signal:
            async def dropped(*args):
                return 0
            monkeypatch.setattr(service.notifier, 'notify', dropped)
        await service.finish_shell_task('run', solver, 'task', status='completed',
            exit_code=0, output_chars=0, truncated=False, timed_out=False)
        async with asyncio.timeout(5):
            while calls['solver'] < 2 or await service.pending_execution_completions('run', solver):
                await asyncio.sleep(.005)
        await asyncio.sleep(.08)  # Several accelerated health checks must not run the model again.
        assert calls['solver'] == 2
        assert (await service.get_agent_runtime('run', solver))['agent']['status'] == 'waiting'
    finally:
        await supervisor.close()
        await service.close()
