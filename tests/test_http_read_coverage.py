"""Reading coverage tracks delivered bytes, including stored-result paging."""
import json
import asyncio

import httpx

from tests.test_http_tools import _manager
from tools.http.models import HttpRequestSpec, HttpOutputFilters, HttpProbeCase

from agent.execution_facts import execution_fact, project_execution


def page(start=0, end=100, boundary=100, *, terminal=True, default=True):
    return {'ok': True, 'data': {
        'interaction_id': 'http', 'execution_status': 'completed' if terminal else 'running',
        'is_terminal': terminal, 'cursor': start, 'next_cursor': end,
        'page_end_cursor': boundary, 'has_more': end < boundary,
        'read_scope': {'default': default, 'filters': {} if default else {'status_codes': [200]}},
        'results': [{'status_code': 200}],
    }}


def row(seq, result, name='system_http_output', **delivery):
    return {'sequence': seq, 'event_type': 'tool_result', 'payload': {
        'tool_name': name, 'tool_call_id': str(seq), 'result': result,
        'execution_fact': execution_fact(name, result, **delivery),
    }}


def state(rows):
    # JSON round-trip represents journal persistence / replay.
    return project_execution(json.loads(json.dumps(rows)), set())


def test_nonzero_eof_and_empty_terminal_page():
    assert not state([row(1, page())])['tasks']
    empty = page(0, 0, 0)
    empty['data']['results'] = []
    assert not state([row(1, empty)])['tasks']


def test_rejected_request_is_not_an_execution():
    for stage in ('parse', 'schema', 'semantic', 'permission', 'conflict'):
        assert execution_fact('system_http_probe', {'ok': False, 'error': {'stage': stage}}) is None


def test_contiguous_pages_gaps_and_filtered_pages():
    rows = [row(1, page(50, 100))]
    assert state(rows)['tasks']
    rows.append(row(2, page(0, 50, default=False)))
    assert state(rows)['tasks']
    rows.append(row(3, page(0, 30)))
    assert state(rows)['tasks']
    rows.append(row(4, page(30, 50)))
    assert not state(rows)['tasks']


def test_running_eof_and_later_growth_require_new_coverage():
    rows = [row(1, page(terminal=False))]
    assert state(rows)['tasks']
    rows.append(row(2, page(100, 150, 200)))
    assert state(rows)['tasks']
    rows.append(row(3, page(150, 200, 200)))
    assert not state(rows)['tasks']


def test_filtered_page_reveals_growth_without_claiming_it_read():
    rows = [row(1, page()), row(2, page(100, 200, 200, default=False))]
    assert state(rows)['tasks']
    rows.append(row(3, page(100, 200, 200)))
    assert not state(rows)['tasks']


def test_delayed_running_page_cannot_revert_observed_terminal_state():
    rows = [row(1, page(0, 50, 50, terminal=False),
                result_ref='tool_result:old-page', result_chars=10),
            row(2, page(50, 100, 100))]
    assert state(rows)['tasks']  # The first half has not reached the model.
    rows.append(row(3, {'ok': True, 'data': {
        'result_ref': 'tool_result:old-page', 'offset': 0, 'content': 'x' * 10,
        'original_chars': 10, 'next_offset': 10, 'eof': True}}, 'tool_result_read'))
    assert not state(rows)['tasks']
    assert state(rows)['http_reads'][0]['output_read']


def test_body_ranges_are_separate_and_hash_scoped():
    def body(start, size, sha='sha'):
        return {'data': {'interaction_id': 'http', 'request_id': 'request', 'body_sha256': sha,
            'body_bytes': 10, 'offset_bytes': start, 'bytes_returned': size,
            'content': 'x' * size, 'eof': start + size == 10}}
    rows = [row(1, body(5, 5), 'system_http_response')]
    assert not state(rows)['body_reads'][0]['complete']
    rows.append(row(2, body(0, 5, 'other'), 'system_http_response'))
    assert all(not item['complete'] for item in state(rows)['body_reads'])
    rows.append(row(3, body(0, 5), 'system_http_response'))
    assert state(rows)['body_reads'][0]['complete']
    assert state(rows)['tasks']  # Body reading does not imply list coverage.


def test_large_result_reference_does_not_count_until_all_chars_delivered():
    rows = [row(1, page(), result_ref='tool_result:test', result_chars=20)]
    assert state(rows)['tasks']
    def read(seq, offset, text):
        return row(seq, {'ok': True, 'data': {
            'result_ref': 'tool_result:test', 'offset': offset, 'content': text,
            'original_chars': 20, 'next_offset': offset + len(text),
            'eof': offset + len(text) == 20}}, 'tool_result_read')
    rows.append(read(2, 10, 'x' * 10))
    assert state(rows)['tasks']
    rows.append(read(3, 0, 'x' * 5))
    assert state(rows)['tasks']
    rows.append(read(4, 5, 'x' * 5))
    assert not state(rows)['tasks']


def test_repeated_big_result_reads_do_not_repeat_execution():
    rows = [row(1, page(), 'system_http_request', result_ref='tool_result:test', result_chars=1)]
    rows += [row(i, {'data': {'result_ref': 'tool_result:test', 'offset': 0,
              'original_chars': 1, 'content': 'x', 'eof': True}}, 'tool_result_read') for i in (2, 3)]
    assert state(rows)['unreviewed_results'] == [1]


async def test_real_manager_eof_and_filtered_scope(tmp_path):
    async def respond(request):
        return httpx.Response(200, text='fixture')
    service, manager, agent = await _manager(tmp_path, respond)
    try:
        result = await manager.start_request(agent, request=HttpRequestSpec(url='https://fixture.test/'), wait_seconds=None)
        assert result['next_cursor'] == result['page_end_cursor'] > 0
        assert result['has_more'] is False
        assert result['read_scope']['default'] is True
        assert not state([row(1, {'data': result}, 'system_http_request')])['tasks']
        filtered = await manager.output(agent, interaction_id=result['interaction_id'], filters=HttpOutputFilters(max_body_bytes=0))
        assert not filtered['results']
        assert filtered['read_scope']['default'] is False
        assert filtered['has_more'] is False
        body = await manager.response(agent, interaction_id=result['interaction_id'], request_id=result['request_id'])
        assert body['body_bytes'] == 7
        assert state([row(1, {'data': body}, 'system_http_response')])['body_reads'][0]['complete']
    finally:
        await manager.finish_run()
        await service.close()


async def test_real_initial_page_and_default_output_share_scope(tmp_path):
    async def respond(request):
        return httpx.Response(200, text='fixture')
    service, manager, agent = await _manager(tmp_path, respond)
    try:
        first = await manager.start_probe(agent, cases=[HttpProbeCase(request=HttpRequestSpec(
            url=f'https://fixture.test/{i}')) for i in range(3)], wait_seconds=None, result_limit=1)
        assert first['has_more']
        rows = [row(1, {'data': first}, 'system_http_probe')]
        second = await manager.output(agent, interaction_id=first['interaction_id'],
            cursor=first['next_cursor'], limit=100, filters=HttpOutputFilters())
        assert first['read_scope'] == second['read_scope']
        rows.append(row(2, {'data': second}))
        assert not state(rows)['tasks']
    finally:
        await manager.finish_run()
        await service.close()


async def test_runner_large_result_requires_actual_paging(tmp_path):
    from tests.test_solver_lifecycle import harness, completion
    reached = asyncio.Event()
    stored_ref = None

    async def model(role, index, body):
        nonlocal stored_ref
        if index == 0:
            return completion('system_shell', {
                'command': "python3 -c \"print('x' * 15000)\"", 'max_output_chars': 20000})
        result = json.loads(next(message['content'] for message in reversed(body['messages']) if message['role'] == 'tool'))
        if index == 1:
            stored_ref = result['result_ref']
            return completion('tool_result_read', {'result_ref': stored_ref, 'limit_chars': 10000})
        data = result['data']
        if not data['eof']:
            return completion('tool_result_read', {'result_ref': stored_ref,
                'offset': data['next_offset'], 'limit_chars': 10000})
        runtime = await sup._service().get_overview('run')
        solver_id = next(a['agent_id'] for a in runtime['agents'] if a['role'] == 'solver')
        projected = (await service.solver_review_state('run', solver_id))['execution']
        assert not projected['tasks']
        assert len(projected['unreviewed_results']) == 1
        reached.set()
        return completion('solver_wait')

    sup, service, _, _, chief = await harness(tmp_path, model, solver_observation=False)
    try:
        await sup.create_solver(chief, 'a')
        await asyncio.wait_for(reached.wait(), 10)
    finally:
        await sup.close()
        await service.close()


async def test_database_reopen_preserves_deferred_list_and_body_coverage(tmp_path):
    from agent.state import StateDatabase, StateService
    from tests.solver_state import build_state

    service, _, _ = await build_state(tmp_path)

    async def append(item):
        await service.append_agent_event('run', 'solver', 'tool_result', item['payload'])

    def chunk(offset):
        return row(1, {'ok': True, 'data': {'result_ref': 'tool_result:stored',
            'offset': offset, 'next_offset': offset + 10, 'original_chars': 20,
            'content': 'x' * 10, 'eof': offset == 10}}, 'tool_result_read')

    def body(offset):
        return row(1, {'ok': True, 'data': {'interaction_id': 'http',
            'request_id': 'response', 'body_sha256': 'sha', 'body_bytes': 10,
            'offset_bytes': offset, 'bytes_returned': 5, 'content': 'x' * 5,
            'eof': offset == 5}}, 'system_http_response')

    def reopened():
        return StateService(StateDatabase(tmp_path / 'state.sqlite3'),
            run_root=tmp_path / 'runs', workspace_root=tmp_path)

    try:
        await append(row(1, page(), result_ref='tool_result:stored', result_chars=20))
        await append(chunk(10))
        await append(body(5))
        before = (await service.solver_review_state('run', 'solver'))['execution']
        assert before['tasks'] and not before['body_reads'][0]['complete']
        await service.close()
        service = reopened()
        assert (await service.solver_review_state('run', 'solver'))['execution'] == before
        await append(chunk(0))
        await append(body(0))
        after = (await service.solver_review_state('run', 'solver'))['execution']
        assert not after['tasks'] and not after['unread_result_refs']
        assert after['body_reads'][0]['complete']
        await service.close()
        service = reopened()
        assert (await service.solver_review_state('run', 'solver'))['execution'] == after
    finally:
        await service.close()
