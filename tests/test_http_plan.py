"""Offline HTTP preflight contract and execution parity."""
from __future__ import annotations

import asyncio
import base64
import copy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from agent.tool_examples import examples_for
from agent.tooling import ToolExecutor, ToolRegistry
from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
from tools.http.models import HttpPlanArguments, HttpProbeArguments, HttpProbeCase, HttpRequestSpec
from tools.system.policy import SystemToolError, WorkspacePolicy


class ReadOnlyService:
    def __init__(self):
        self.rows = []

    async def list_http_interactions(self, run_id, agent_id=None):
        return [row for row in self.rows if agent_id is None or row['agent_id'] == agent_id]

    def __getattr__(self, name):
        raise AssertionError(f"Unexpected state operation: {name}")


@pytest.fixture
def manager(tmp_path):
    def reject_http(_request):
        raise AssertionError("Preflight sent HTTP")

    policy = WorkspacePolicy(tmp_path)
    return HttpProbeManager(
        policy, ReadOnlyService(), 'run',
        engine=HttpInteractionEngine(policy, transport=httpx.MockTransport(reject_http)),
    )


async def plan(manager, arguments, tool_name='system_http_probe'):
    return await manager.bind('agent').plan(HttpPlanArguments(
        tool_name=tool_name, arguments=arguments,
    ))


@pytest.mark.asyncio
async def test_plan_counts_previews_and_actual_plan_parity(manager, tmp_path, monkeypatch):
    (tmp_path / 'paths.txt').write_text(' a \n\nb\nc\n')
    arguments = {'cases': [
        {'url': 'http://target.test/{{path}}?n={{n}}', 'variables': {
            'path': {'file_path': 'paths.txt'}, 'n': {'range': {'stop': 2}},
        }},
        {'url': 'http://target.test/{{x}}/{{y}}', 'combine': 'zip', 'variables': {
            'x': {'values': ['d', 'e']}, 'y': {'values': [1, 2]},
        }},
        {'url': 'http://target.test/{{empty}}', 'variables': {'empty': {'values': []}}},
    ]}
    result = await plan(manager, arguments)
    assert result['request_count'] == 8
    assert result['cases'] == [
        {'case_index': 0, 'request_count': 6},
        {'case_index': 1, 'request_count': 2},
        {'case_index': 2, 'request_count': 0},
    ]
    assert result['previews_truncated'] is True
    assert len(result['previews']) == result['preview_limit'] == 5
    assert [p['request_index'] for p in result['previews']] == [1, 2, 3, 4, 5]

    captured = []
    original = manager._build_plan

    async def build(*args):
        requests = await original(*args)
        captured.extend(requests)
        return requests

    class BeforePersistence(Exception):
        pass

    async def stop_before_persistence(*args):
        raise BeforePersistence

    monkeypatch.setattr(manager, '_build_plan', build)
    monkeypatch.setattr(manager, '_create_interaction_directories', stop_before_persistence)
    with pytest.raises(BeforePersistence):
        await manager.bind('agent').probe(HttpProbeArguments.model_validate(arguments))
    assert len(captured) == result['request_count']
    assert [manager._preview_request(r.spec) for r in captured[:5]] == [
        p['request'] for p in result['previews']
    ]


@pytest.mark.asyncio
async def test_plan_no_runtime_or_filesystem_mutations(manager, tmp_path, monkeypatch):
    (tmp_path / 'upload.txt').write_text('fixture bytes')
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    state_before = {key: copy.copy(value) for key, value in vars(manager).items() if isinstance(value, dict)}
    stats = manager.engine.connection_stats.copy()

    def forbidden(*args, **kwargs):
        raise AssertionError('Preflight attempted runtime activity')

    for name in ('_load_session', '_session_path', '_create_interaction_directories',
                 '_write_private_json_atomic', '_wait', '_historical_response_estimate'):
        monkeypatch.setattr(manager, name, forbidden)
    monkeypatch.setattr(asyncio, 'create_task', forbidden)
    result = await plan(manager, {
        'url': 'http://target.test/upload', 'session_id': 'login', 'update_session': True,
        'body': {'type': 'multipart', 'value': {'file': {'file_path': 'upload.txt'}}},
    }, 'system_http_request')
    assert result['request_count'] == 1
    assert result['previews_truncated'] is False
    assert result['previews'][0]['request']['session_id'] == 'login'
    assert manager.engine.connection_stats == stats
    assert not manager.engine._clients
    assert {key: value for key, value in vars(manager).items() if isinstance(value, dict)} == state_before
    assert {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()} == before
    assert list(tmp_path.iterdir()) == [tmp_path / 'upload.txt']
    assert not {'interaction_id', 'request_id', 'token', 'execute_token'} & result.keys()


@pytest.mark.asyncio
async def test_plan_masks_only_credentials_and_does_not_change_input(manager):
    arguments = {
        'url': 'http://alice:url-secret@target.test/?access_token=query-secret&q=useful&password=pw-secret',
        'headers': {'Proxy-Authorization': 'proxy-secret', 'X-Api-Key': 'key-secret', 'Accept': 'text/plain'},
        'cookies': {'session': 'cookie-secret'},
        'auth': {'type': 'basic', 'username': 'auth-user', 'password': 'auth-secret'},
        'query': {'token': 'dict-secret', 'page': 2},
        'body': {'type': 'json', 'value': {'nested': [{'password': 'body-secret', 'name': 'visible'}]}},
    }
    original = copy.deepcopy(arguments)
    result = await plan(manager, arguments, 'system_http_request')
    preview = result['previews'][0]['request']
    serialized = json.dumps(result)
    for secret in ('alice', 'url-secret', 'query-secret', 'pw-secret', 'proxy-secret',
                   'key-secret', 'cookie-secret', 'auth-user', 'auth-secret', 'dict-secret', 'body-secret'):
        assert secret not in serialized
    assert preview['headers']['Accept'] == 'text/plain'
    assert preview['query']['page'] == 2
    assert preview['body']['value']['nested'][0]['name'] == 'visible'
    assert parse_qs(urlsplit(preview['url']).query) == {
        'access_token': ['[REDACTED]'], 'q': ['useful'], 'password': ['[REDACTED]'],
        'token': ['[REDACTED]'], 'page': ['2'],
    }
    assert arguments == original


@pytest.mark.asyncio
@pytest.mark.parametrize('body', [
    {'type': 'raw', 'value': '秘密'},
    {'type': 'base64', 'value': base64.b64encode('秘密'.encode()).decode()},
])
async def test_opaque_preview_is_metadata_only(manager, body):
    result = await plan(manager, {'url': 'http://target.test/', 'body': body}, 'system_http_request')
    assert result['previews'][0]['request']['body'] == {'type': body['type'], 'byte_length': 6}


@pytest.mark.asyncio
@pytest.mark.parametrize(('case', 'code'), [
    ({'url': 'http://target.test/{x}', 'variables': {'x': {'values': [1]}}}, 'invalid_template_syntax'),
    ({'url': 'http://target.test/{{x}}'}, 'unknown_template_variable'),
    ({'url': 'http://target.test/', 'variables': {'x': {'values': [1]}}}, 'unused_template_variable'),
    ({'url': 'http://target.test/{{x}}/{{y}}', 'combine': 'zip',
      'variables': {'x': {'values': [1]}, 'y': {'values': [1, 2]}}}, 'zip_length_mismatch'),
    ({'url': 'http://target.test/{{x}}', 'variables': {'x': {'range': {'stop': 5001}}}}, 'http_probe_too_large'),
    ({'url': 'http://target.test/{{x}}', 'variables': {'x': {'values': []}}}, 'empty_http_interaction'),
    ({'url': 'http://target.test:invalid/'}, 'invalid_expanded_url'),
    ({'url': 'http://target.test/', 'body': {'type': 'base64', 'value': '!'}}, 'invalid_base64_body'),
    ({'url': 'http://target.test/{{x}}', 'variables': {'x': {'file_path': 'missing'}}}, 'path_not_found'),
    ({'url': 'http://target.test/{{x}}', 'variables': {'x': {'file_path': '.'}}}, 'variable_file_not_file'),
    ({'url': 'http://target.test/{{x}}', 'variables': {'x': {'file_path': '../outside'}}}, 'path_outside_workspace'),
    ({'url': 'http://target.test/', 'body': {'type': 'multipart', 'value': {'f': {'file_path': '.'}}}}, 'multipart_file_not_file'),
])
async def test_semantic_errors_match_execution_and_include_selected_examples(manager, case, code):
    arguments = {'cases': [case]}
    with pytest.raises(SystemToolError) as dry:
        await plan(manager, arguments)
    with pytest.raises(SystemToolError) as actual:
        await manager.bind('agent').probe(HttpProbeArguments.model_validate(arguments))
    assert dry.value.code == actual.value.code == code
    assert dry.value.message == actual.value.message
    assert dry.value.detail['examples'] == examples_for('system_http_probe')
    expected_paths = {
        'invalid_template_syntax': ['url'],
        'unknown_template_variable': ['url'],
        'unused_template_variable': ['variables.x'],
        'zip_length_mismatch': ['variables'],
        'http_probe_too_large': ['variables.x.range'],
        'empty_http_interaction': ['variables'],
        'invalid_expanded_url': ['url'],
        'invalid_base64_body': ['body.value'],
        'path_not_found': ['variables.x.file_path'],
        'variable_file_not_file': ['variables.x.file_path'],
        'path_outside_workspace': ['variables.x.file_path'],
        'multipart_file_not_file': ['body.value.f.file_path'],
    }[code]
    assert [field['path'] for field in dry.value.detail['fields']] == [
        f'arguments.cases.0.{path}' for path in expected_paths
    ]
    assert dry.value.detail['fields'] == [
        {**field, 'path': 'arguments.' + field['path']}
        for field in actual.value.detail['fields']
    ]
    assert not manager._live and not manager._plan_cache


@pytest.mark.asyncio
async def test_schema_errors_through_complete_registry(manager):
    executor = ToolExecutor(ToolRegistry([HttpTools(manager.bind('agent'))]))
    results = await executor.execute([{
        'id': 'plan', 'function': {'name': 'system_http_plan', 'arguments': json.dumps({
            'tool_name': 'system_http_probe',
            'arguments': {'cases': {'url': 'http://target.test/'}, 'concurrency': 0},
        })},
    }])
    error = results[0].result['error']
    assert error['stage'] == 'schema'
    assert error['code'] == 'invalid_arguments'
    assert error['details']['examples'] == examples_for('system_http_probe')
    assert {f['path'] for f in error['details']['fields']} == {'arguments.cases', 'arguments.concurrency'}
    spec = next(s for s in HttpTools(manager.bind('agent')).tool_specs() if s.name == 'system_http_plan')
    assert spec.access_claims(HttpPlanArguments(tool_name='system_http_request', arguments={})) == ()


@pytest.mark.asyncio
async def test_owned_plan_reads_do_not_populate_cache(manager, tmp_path):
    directory = manager._interaction_dir('foreign', 'existing')
    directory.mkdir(parents=True)
    spec = HttpRequestSpec(url='http://target.test/', request_group_id='foreign-group')
    expanded = manager.engine.expand_cases([HttpProbeCase(request=spec)], id_factory=lambda: 'owned', default_group_id='existing')
    (directory / 'plan.json').write_text(json.dumps({'requests': [manager._request_json(x) for x in expanded]}))
    manager.service.rows.append({'agent_id': 'foreign', 'interaction_id': 'existing'})
    await plan(manager, {'cases': [{'url': 'http://target.test/'}]})
    assert manager._plan_cache == {}
    with pytest.raises(SystemToolError, match='Request group was not found'):
        await manager._build_plan('agent', [HttpProbeCase(request=spec)], 'test')
    parent = HttpRequestSpec(url='http://target.test/', parent_request_id='request-owned')
    with pytest.raises(SystemToolError, match='Parent request was not found'):
        await manager._build_plan('agent', [HttpProbeCase(request=parent)], 'test')
    await manager._build_plan('foreign', [HttpProbeCase(request=parent)], 'test')
    assert manager._plan_cache == {}


@pytest.mark.asyncio
async def test_finite_total_limit_and_encoding(manager):
    case = {'url': 'http://target.test/{{n}}', 'variables': {'n': {'range': {'stop': 5000}}}}
    result = await plan(manager, {'cases': [case]})
    assert result['request_count'] == 5000
    with pytest.raises(SystemToolError) as error:
        await plan(manager, {'cases': [case, {'url': 'http://target.test/extra'}]})
    assert error.value.code == 'http_probe_too_large'
    result = await plan(manager, {'cases': [{
        'url': 'http://target.test/{{path}}',
        'variables': {'path': {'values': ['a b/c'], 'encoding': 'path'}},
    }, {'url': 'http://target.test/second'}]})
    assert result['previews'][0]['request']['url'] == 'http://target.test/a%20b/c'
    assert [p['case_index'] for p in result['previews']] == [0, 1]


@pytest.mark.asyncio
@pytest.mark.parametrize('credentials', [
    {'headers': {'Authorization': 'header-secret', 'Cookie': 'cookie-secret', 'X-Trace': 'keep'}},
    {'auth': {'type': 'bearer', 'token': 'bearer-secret'}},
])
async def test_successful_tool_dispatch_masks_credentials(manager, credentials):
    executor = ToolExecutor(ToolRegistry([HttpTools(manager.bind('agent'))]))
    results = await executor.execute([{
        'id': 'plan-success', 'function': {'name': 'system_http_plan', 'arguments': json.dumps({
            'tool_name': 'system_http_request',
            'arguments': {'url': 'http://target.test/', **credentials},
        })},
    }])
    result = results[0].result
    assert result['ok'] is True
    assert result['data']['request_count'] == 1
    assert '-secret' not in json.dumps(result)
    if 'headers' in credentials:
        assert result['data']['previews'][0]['request']['headers']['X-Trace'] == 'keep'


@pytest.mark.asyncio
async def test_agent_workspace_and_symlink_source_isolation(manager, tmp_path):
    owned = tmp_path / 'owned'
    owned.mkdir()
    (tmp_path / 'foreign.txt').write_text('foreign')
    (owned / 'link.txt').symlink_to(tmp_path / 'foreign.txt')
    client = manager.bind('agent', workspace_root=owned)
    with pytest.raises(SystemToolError) as error:
        await client.plan(HttpPlanArguments(tool_name='system_http_probe', arguments={
            'cases': [{'url': 'http://target.test/{{x}}',
                       'variables': {'x': {'file_path': 'link.txt'}}}],
        }))
    assert error.value.code == 'path_outside_workspace'
    assert error.value.detail['examples'] == examples_for('system_http_probe')


@pytest.mark.asyncio
async def test_closed_manager_error_includes_request_examples(manager):
    manager._closed = True
    with pytest.raises(SystemToolError) as error:
        await plan(manager, {'url': 'http://target.test/'}, 'system_http_request')
    assert error.value.code == 'http_manager_closed'
    assert error.value.detail['examples'] == examples_for('system_http_request')


@pytest.mark.asyncio
@pytest.mark.parametrize(('case', 'paths'), [
    ({'url': 'http://target.test/', 'body': {'type': 'json', 'value': {'items': [{'name': '{{missing}}'}]}}},
     ['body.value.items.0.name']),
    ({'url': 'http://target.test/', 'headers': {'X-Test': '{wrong}'}}, ['headers.X-Test']),
    ({'url': 'http://target.test/', 'variables': {'a': {'values': [1]}, 'b': {'values': [2]}}},
     ['variables.a', 'variables.b']),
    ({'url': 'http://target.test/{{a}}/{{b}}', 'variables': {
        'a': {'values': [1]}, 'b': {'file_path': 'missing'}}}, ['variables.b.file_path']),
    ({'url': 'http://target.test/', 'body': {'type': 'multipart', 'value': {
        'text': 'keep', 'upload': {'file_path': 'missing'}}}}, ['body.value.upload.file_path']),
    ({'url': 'http://target.test:invalid/'}, ['url']),
    ({'url': 'http://target.test/', 'auth': {'type': 'bearer', 'token': '{{unresolved}}'}}, ['auth.token']),
])
async def test_second_case_semantic_paths_are_structural(manager, case, paths):
    with pytest.raises(SystemToolError) as error:
        await plan(manager, {'cases': [{'url': 'http://target.test/valid'}, case]})
    assert [field['path'] for field in error.value.detail['fields']] == [
        f'arguments.cases.1.{path}' for path in paths
    ]
    assert all(field['code'] and field['message'] for field in error.value.detail['fields'])


@pytest.mark.asyncio
@pytest.mark.parametrize(('arguments', 'path'), [
    ({'url': 'http://target.test/', 'body': {'type': 'base64', 'value': '!'}}, 'body.value'),
    ({'url': 'http://target.test/', 'body': {'type': 'multipart', 'value': {
        'upload': {'file_path': 'missing'}}}}, 'body.value.upload.file_path'),
    ({'url': 'http://target.test:invalid/'}, 'url'),
])
async def test_request_semantic_errors_use_flat_argument_paths(manager, arguments, path):
    with pytest.raises(SystemToolError) as error:
        await plan(manager, arguments, 'system_http_request')
    assert [field['path'] for field in error.value.detail['fields']] == [f'arguments.{path}']
    assert error.value.detail['examples'] == examples_for('system_http_request')


@pytest.mark.asyncio
async def test_executor_preserves_semantic_paths_and_examples(manager):
    executor = ToolExecutor(ToolRegistry([HttpTools(manager.bind('agent'))]))
    results = await executor.execute([{
        'id': 'semantic-plan', 'function': {'name': 'system_http_plan', 'arguments': json.dumps({
            'tool_name': 'system_http_probe', 'arguments': {'cases': [
                {'url': 'http://target.test/valid'},
                {'url': 'http://target.test/{{path}}', 'variables': {'path': {'file_path': 'missing'}}},
            ]},
        })},
    }])
    error = results[0].result['error']
    assert error['stage'] == 'semantic'
    assert error['code'] == 'path_not_found'
    assert [field['path'] for field in error['details']['fields']] == [
        'arguments.cases.1.variables.path.file_path'
    ]
    assert error['details']['examples'] == examples_for('system_http_probe')
