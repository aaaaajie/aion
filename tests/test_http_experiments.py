import httpx
import pytest
from tests.test_http_tools import _manager
from tools.http.experiments import HttpReplayArguments, HttpCompareArguments, replay, compare
from tools.http.models import HttpRequestSpec


async def test_replay_compare_and_missing_body(tmp_path):
    seen = []
    async def handler(request):
        seen.append(request)
        return httpx.Response(500 if len(seen) == 1 else 200,
                              headers={'set-cookie': 'session=valid; HttpOnly; Path=/'},
                              json={'authenticated': True, 'count': len(seen)})
    service, manager, agent = await _manager(tmp_path, handler)
    manager.disk_reserve_bytes = 0
    manager.disk_reserve_percent = 0
    client = manager.bind(agent)
    try:
        await manager.start_request(agent, request=HttpRequestSpec(
            url='http://fixture.test/login', session_id='login', update_session=True,
            headers={'x-old': 'remove'}), wait_seconds=20, result_limit=1)
        rows = await service.list_http_interactions('run-1', agent_id=agent)
        first = rows[0]['interaction_id']
        request = manager._load_plan(agent, first)[0]
        ref = {'interaction_id': first, 'request_id': request.request_id}
        result = await replay(client, HttpReplayArguments(**ref, overrides={'headers': {'x-new': 'keep'}}))
        assert result['replay']['session_state'] == 'current_cookie_jar'
        assert 'x-old' not in seen[1].headers
        assert seen[1].headers['cookie'] == 'session=valid'
        assert manager._load_plan(agent, first)[0].spec.headers == {'x-old': 'remove'}
        rows = await service.list_http_interactions('run-1', agent_id=agent)
        second = next(r['interaction_id'] for r in rows if r['interaction_id'] != first)
        second_request = manager._load_plan(agent, second)[0]
        assert second_request.spec.parent_request_id == request.request_id
        args = HttpCompareArguments(left=ref, right={'interaction_id': second, 'request_id': second_request.request_id})
        output = await compare(client, args)
        assert output['left']['status_code'] == 500
        assert output['right']['status_code'] == 200
        assert output['json_changes'] == [{'path': '/count', 'change': 'changed'}]
        assert len(seen) == 2
        record = manager._response_record(agent, first, request.request_id)
        (manager._response_dir(agent, first) / record['body_file']).unlink()
        assert (await compare(client, args))['left']['body_state'] == 'missing'
        with pytest.raises(Exception):
            await replay(manager.bind('another-agent'), HttpReplayArguments(**ref))
    finally:
        await manager.finish_run()
        await service.close()


async def test_uniform_403_does_not_claim_equivalence(tmp_path):
    async def handler(request):
        return httpx.Response(403, text='Forbidden')
    service, manager, agent = await _manager(tmp_path, handler)
    manager.disk_reserve_bytes = manager.disk_reserve_percent = 0
    try:
        refs = []
        for path in ('admin', 'random-not-present'):
            await manager.start_request(agent, request=HttpRequestSpec(url='http://fixture.test/' + path), wait_seconds=20)
        for row in await service.list_http_interactions('run-1', agent_id=agent):
            iid = row['interaction_id']
            refs.append({'interaction_id': iid, 'request_id': manager._load_plan(agent, iid)[0].request_id})
        result = await compare(manager.bind(agent), HttpCompareArguments(left=refs[0], right=refs[1]))
        assert result['body_diff'] == ''
        assert result['business_equivalence'] == 'not_determined'
    finally:
        await manager.finish_run()
        await service.close()
