"""Regression of the observed malformed probe/gateway/pre-execution failures."""
import json

import httpx

from agent.config import AgentSettings
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.tooling import ToolExecutor, ToolRegistry, map_exception
from tests.solver_state import build_state
from tests.resource_runtime import install_resource_runtime
from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
from tools.system.policy import SystemToolError, WorkspacePolicy


def wire(name, arguments, key='test'):
    return {'id': key, 'function': {'name': name, 'arguments': json.dumps(arguments)}}


async def test_runner_keeps_probe_available_after_multiple_parameter_errors(tmp_path):
    service, _, _ = await build_state(tmp_path)
    requests = []
    async def respond(request):
        requests.append(request.url.path)
        return httpx.Response(200, text='fixture')
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(policy, service, 'run', engine=HttpInteractionEngine(
        policy, transport=httpx.MockTransport(respond)))
    await manager.initialize()
    install_resource_runtime(manager, service, 'run', root=tmp_path)
    registry = ToolRegistry([HttpTools(manager.bind('solver'))], compact=True)
    runner = AgentRunner(AgentSettings(), registry, role='solver', agent_id='solver',
        state_service=service, run_root=tmp_path / 'runs')
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'runs/run')
        await runner._tool_executor.execute([wire('tool_search', {'name': 'system_http_probe'})])
        bad = [ {'cases': [{'url': 'http://fixture.test/', 'body': 'wrong'}]},
                {'cases': [{'url': 'http://fixture.test/{{p}}', 'variables': {'p': ['health']}}]} ]
        for index, args in enumerate([bad[0], bad[1], bad[1]]):
            messages, _ = await runner._execute_tool_calls(store, [wire('system_http_probe', args, str(index))])
            result = json.loads(messages[0]['content'])
            error = result['error']
            assert error['code'] == 'invalid_arguments'
            assert error['details']['fields']
            assert error['details']['next_tool'] == 'tool_search'
            assert error['details']['next_arguments'] == {'name': 'system_http_probe'}
            assert error['details']['execution_status'] == 'not_started'
            assert error['details'].get('repeated_arguments', False) == (index > 0)
        assert not requests
        messages, _ = await runner._execute_tool_calls(store, [wire('system_http_probe', {
            'cases': [{'url': 'http://fixture.test/{{missing}}'}]}, 'template')])
        error = json.loads(messages[0]['content'])['error']
        assert error['code'] == 'unknown_template_variable'
        assert error['details']['fields']
        assert error['details']['next_tool'] == 'tool_search'
        assert not requests
        valid = {'cases': [{'url': 'http://fixture.test/health'}]}
        messages, _ = await runner._execute_tool_calls(store, [wire('system_http_probe', valid, 'valid')])
        assert json.loads(messages[0]['content'])['ok']
        assert requests == ['/health']
        assert runner._active_tool_definitions(registry.definitions()) == registry.definitions()
    finally:
        await runner.close()
        await manager.finish_run()
        await service.close()


async def test_removed_gateway_is_unknown_without_executing(tmp_path):
    from agent.tooling import ToolSpec, AccessClaim
    from tools.http.models import HttpRequestArguments
    called = []
    class Provider:
        def tool_specs(self):
            return [ToolSpec('system_http_request', 'fixture', HttpRequestArguments,
                lambda a: called.append(a), lambda _: (AccessClaim('write', 'fixture'),))]
    executor = ToolExecutor(ToolRegistry([Provider()], compact=True))
    result = (await executor.execute([wire('tool_call', {})]))[0].result
    assert not result['ok'] and not called
    assert result['error']['code'] == 'unknown_tool'
    assert result['error']['details']['execution_status'] == 'not_started'


def test_execution_failure_does_not_claim_command_never_started():
    result = map_exception(SystemToolError(error_type='execution', code='fixture_failed',
        message='failed after starting'), tool_name='system_shell')
    assert 'execution_status' not in result['error']['details']


async def test_native_schema_errors_and_search_are_distinct_and_suggestions_validate():
    from tests.test_compact_tools import Tools
    provider = Tools()
    executor = ToolExecutor(ToolRegistry([provider], compact=True))
    await executor.execute([wire('tool_search', {'name': 'special_tool'})])
    raw_cases = [
        ('{"value":', 'parse', 'json_error'),
        (json.dumps({'value': 'bad'}), 'schema', 'fields'),
    ]
    for raw, stage, detail_key in raw_cases:
        result = (await executor.execute([{'id': 'bad', 'function': {'name': 'special_tool', 'arguments': raw}}]))[0].result
        error = result['error']
        assert error['stage'] == stage
        assert error['details']['execution_status'] == 'not_started'
        if detail_key:
            assert error['details'][detail_key]
        assert 'localhost' not in json.dumps(error)
        assert error['details']['next_tool'] == 'tool_search'
        corrected = (await executor.execute([wire(error['details']['next_tool'], error['details']['next_arguments'])]))[0].result
        assert corrected['ok']
        assert not provider.calls
    corrected = (await executor.execute([wire('special_tool', {'value': 7})]))[0].result
    assert corrected['ok'] and provider.calls == [7]


async def test_extra_arguments_wrapper_suggests_valid_call_without_executing():
    from agent.tooling import ToolSpec, AccessClaim
    from tools.network.models import NetworkOutputArguments
    called = []
    class Provider:
        def tool_specs(self):
            return [ToolSpec('system_network_output', 'fixture', NetworkOutputArguments,
                lambda a: called.append(a) or {'ok': True}, lambda _: (AccessClaim('read', 'fixture'),))]
    executor = ToolExecutor(ToolRegistry([Provider()], compact=True))
    await executor.execute([wire('tool_search', {'name': 'system_network_output'})])
    result = (await executor.execute([wire('system_network_output', {'arguments': {'task_id': 'owned-task'}})]))[0].result
    assert not called
    assert result['error']['details']['next_tool'] == 'system_network_output'
    corrected = (await executor.execute([wire(
        result['error']['details']['next_tool'],
        result['error']['details']['next_arguments'],
    )]))[0].result
    assert corrected['ok'] and len(called) == 1


async def test_repeated_search_errors_are_annotated_without_disabling_tools(tmp_path):
    service, _, _ = await build_state(tmp_path)
    runner = AgentRunner(AgentSettings(), ToolRegistry([], compact=True), role='solver', state_service=service)
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        for index in range(2):
            messages, _ = await runner._execute_tool_calls(store, [wire('tool_search', {'name': 'missing', 'extra': 1})])
            error = json.loads(messages[0]['content'])['error']
            assert error['details'].get('repeated_arguments', False) == bool(index)
        messages, _ = await runner._execute_tool_calls(store, [wire('tool_search', {})])
        assert json.loads(messages[0]['content'])['ok']
    finally:
        await runner.close()
        await service.close()
