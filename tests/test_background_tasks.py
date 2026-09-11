"""Named background work and the monitor's durable task projection."""
import asyncio
import json

import pytest
from pydantic import ValidationError

from scripts.runtime_web.server import _ReadOnlyStore
from tools.system.models import ShellArguments, TaskStartArguments
from tests.test_system_tools import make_tools
from tests.solver_state import build_state


def test_distinct_foreground_and_background_contracts():
    with pytest.raises(ValidationError):
        ShellArguments(command='true', run_in_background=True)
    assert TaskStartArguments(name='scan', command='true').timeout == 1800
    with pytest.raises(ValidationError):
        TaskStartArguments(name='scan', command='true', timeout=86401)


async def test_background_allows_independent_work_and_readable_notification(make_tools):
    harness = make_tools()
    async with harness as tools:
        started = await tools.task_start('sleep 2; printf completed', timeout=86400)
        assert started['ok'], started
        task_id = started['data']['task_id']
        assert 0 < started['data']['timeout'] <= 360 * 60
        assert started['data']['completion_notification']
        independent = await tools.shell('printf independent')
        assert 'independent' in independent['data']['output']
        assert (await tools.task_output(task_id))['data']['status'] == 'running'
        result = await tools.task_output(task_id, wait_seconds=5)
        assert result['data']['status'] == 'completed'
        notices = await harness.service.pending_execution_completions(harness.run_id, harness.agent_id)
        notice = next(n for n in notices if n['task_id'] == task_id)
        assert notice['name'] == 'Fixture task'
        assert notice['exit_code'] == 0
        assert notice['read_result']['arguments'] == {'task_id': task_id}
        from agent.runner import AgentRunner
        from agent.state import AgentStateStore
        from agent.tooling import ToolRegistry
        from tests.test_report_delivery import settings
        runner = AgentRunner(settings(), ToolRegistry([]), role='worker', state_service=harness.service)
        try:
            agent_store = await AgentStateStore.open(harness.service, run_id=harness.run_id,
                agent_id=harness.agent_id, run_dir=harness.root)
            message, delivery = await runner._review_context(agent_store)
            assert 'Fixture task' in message['content']
            assert notice['sequence'] in delivery['completion_sequences']
        finally:
            await runner.close()
        store = _ReadOnlyStore(harness.service.db.path, harness.run_id, harness.root)
        assert [t['task_id'] for t in store.snapshot()['background_tasks']] == [task_id]
        detail = store.task_detail('shell', task_id)
        assert detail['output_available'] and detail['output'] == 'completed'
        assert not _ReadOnlyStore(harness.service.db.path, harness.run_id).task_detail('shell', task_id)['output_available']


async def test_projection_all_types_survives_event_window_and_output_paging(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        output = tmp_path / 'shell.log'; output.write_text('中' * 10005)
        await service.create_shell_task('run', 'solver', task_id='shell', pid=1,
            process_started_at=1, cwd='.', temp_dir='tmp', output_path='shell.log', capture_limit=20000,
            task_name='Named scan', background=True, timeout=1800,
            resource_limits={'enforced': True, 'memory_bytes': 536870912, 'cpu_cores': 1})
        await service.finish_shell_task('run', 'solver', 'shell', status='failed',
            exit_code=-9, output_chars=10005, truncated=False, timed_out=False,
            cleanup={'termination_reason': 'memory_limit_exceeded', 'resource_usage': {'memory_peak_bytes': 536870912}})
        await service.append_agent_event('run', 'solver', 'tool_call', {
            'tool_call_id': 'start-call', 'tool_name': 'system_task_start',
            'arguments': {'command': 'printf "<script>literal</script>"', 'name': 'Named scan'}})
        await service.append_agent_event('run', 'solver', 'tool_result', {
            'tool_call_id': 'start-call', 'execution_fact': {'execution': True, 'task_id': 'shell'}})
        await service.append_agent_event('run', 'solver', 'tool_call', {
            'tool_call_id': 'read-call', 'tool_name': 'system_task_output', 'arguments': {'task_id': 'shell'}})
        await service.append_agent_event('run', 'solver', 'tool_result', {
            'tool_call_id': 'read-call', 'execution_fact': {'execution': False, 'task_id': 'shell'}})
        from agent.state.models import NetworkTaskRecord, HttpInteractionRecord
        async with service.db.sessions.begin() as session:
            session.add(NetworkTaskRecord(task_id='network', run_id='run', agent_id='solver',
                result_path='network.jsonl', requested_concurrency=1))
            session.add(HttpInteractionRecord(interaction_id='http', run_id='run', agent_id='solver',
                kind='path_probe', result_path='http', estimated_requests=2, requested_concurrency=1,
                estimated_disk_bytes=0, estimated_memory_bytes=0, estimated_analysis_work=0,
                execution_status='completed', analysis_status='running'))
        import scripts.runtime_web.server as server
        old = server.GLOBAL_EVENT_LIMIT
        server.GLOBAL_EVENT_LIMIT = 1
        try:
            await service.append_agent_event('run', 'solver', 'assistant_response', {'content': 'later'})
            store = _ReadOnlyStore(service.db.path, 'run', tmp_path)
            tasks = store.snapshot()['background_tasks']
            assert {t['kind'] for t in tasks} == {'shell', 'http', 'network'}
            assert all(t['unique_code'] == 'a' for t in tasks)
            http = next(t for t in tasks if t['kind'] == 'http')
            assert http['status'] == 'completed' and http['analysis_status'] == 'running'
            page = store.task_detail('shell', 'shell', limit=999999)
            assert page['invocation']['tool'] == 'system_task_start'
            assert page['invocation']['arguments']['command'] == 'printf "<script>literal</script>"'
            assert page['cwd'] == '.'
            assert page['task']['launch_mode'] == 'background'
            assert http['launch_mode'] == 'execution'
            assert page['task']['resource_limits']['memory_bytes'] > 0
            assert page['task']['termination_reason'] == 'memory_limit_exceeded'
            assert page['task']['resource_usage']['memory_peak_bytes'] == 536870912
            notices = await service.pending_execution_completions('run', 'solver')
            notice = next(item for item in notices if item.get('task_id') == 'shell')
            assert notice['termination_reason'] == 'memory_limit_exceeded'
            assert notice['resource_limits']['memory_bytes'] > 0
            assert len(page['output']) == 10000 and page['next_offset'] == 10000
            assert store.task_detail('shell', 'shell', offset=10000)['output'] == '中'*5
            with pytest.raises(LookupError):
                _ReadOnlyStore(service.db.path, 'another-run', tmp_path).task_detail('shell', 'shell')
            assert not store.task_detail('network', 'network')['output_available']
        finally:
            server.GLOBAL_EVENT_LIMIT = old
    finally:
        await service.close()


async def test_real_solver_continues_then_wakes_on_named_completion(tmp_path):
    from tests.test_solver_lifecycle import harness, completion
    reached = asyncio.Event()
    async def model(role, index, body):
        if index == 0:
            return completion('system_task_start', {'name': 'Async fixture', 'command': 'sleep 2; printf ready', 'timeout': 60})
        if index == 1:
            return completion('system_shell', {'command': 'printf independent'})
        if index == 2:
            return completion('solver_wait')
        messages = '\n'.join(str(m.get('content', '')) for m in body['messages'])
        assert 'Async fixture' in messages and 'new_completions' in messages
        reached.set()
        return completion('solver_wait')
    sup, service, _, _, chief = await harness(tmp_path, model, solver_observation=False)
    try:
        await sup.create_solver(chief, 'a')
        await asyncio.wait_for(reached.wait(), 15)
    finally:
        await sup.close()
        await service.close()
