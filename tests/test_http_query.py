"""Query merge parity tested at the actual HTTP transport, without networking."""
import httpx
import pytest

from tests.test_http_tools import _manager
from tools.http.models import HttpProbeCase, HttpRequestSpec


@pytest.mark.parametrize('query,expected', [
    ({}, [('a', '1'), ('a', '2'), ('empty', ''), ('keep', 'a/b')]),
    ({'b': '3'}, [('a', '1'), ('a', '2'), ('empty', ''), ('keep', 'a/b'), ('b', '3')]),
    ({'a': ['8', '9']}, [('a', '8'), ('a', '9'), ('empty', ''), ('keep', 'a/b')]),
    ({'a': ''}, [('a', ''), ('empty', ''), ('keep', 'a/b')]),
])
async def test_query_preview_matches_sent_request(tmp_path, query, expected):
    received = []
    async def handler(request):
        received.append(request)
        return httpx.Response(200, text='fixture')
    service, manager, agent_id = await _manager(tmp_path, handler)
    try:
        spec = HttpRequestSpec(url='http://fixture.test/item?a=1&a=2&empty=&keep=a%2Fb', query=query)
        preview = manager._preview_request(spec)
        await manager.start_probe(agent_id, cases=[HttpProbeCase(request=spec)], concurrency=1, wait_seconds=None)
        assert len(received) == 1
        assert received[0].url.params.multi_items() == expected
        assert preview['url'] == str(received[0].url)
        if not query:
            assert str(received[0].url) == spec.url
        # Native completion notification is emitted once, not for each response or poll.
        signal = await service.notifier.current(service.agent_signal_key('run-1', agent_id))
        assert signal > 0
        item = (await service.list_http_interactions('run-1', agent_id=agent_id))[0]
        await service.update_http_interaction('run-1', agent_id, item['interaction_id'], execution_status='completed')
        assert await service.notifier.current(service.agent_signal_key('run-1', agent_id)) == signal
    finally:
        await manager.finish_run()
        await service.close()


def test_query_preview_masks_merged_secrets():
    from tools.http.manager import HttpProbeManager
    spec = HttpRequestSpec(url='http://fixture.test/?token=old&keep=yes', query={'token': 'new-secret', 'password': 'hidden'})
    preview = HttpProbeManager._preview_request(spec)
    assert 'new-secret' not in str(preview) and 'hidden' not in str(preview)
    assert httpx.URL(preview['url']).params['keep'] == 'yes'


async def test_variables_expand_before_query_merge(tmp_path):
    from tools.http.models import HttpVariableSource
    seen = []
    async def handler(request):
        seen.append(request.url)
        return httpx.Response(200, text='fixture')
    service, manager, agent_id = await _manager(tmp_path, handler)
    try:
        case = HttpProbeCase(request=HttpRequestSpec(
            url='http://fixture.test/?keep=yes&replace=old', query={'replace': '{{value}}'}),
            variables={'value': HttpVariableSource(values=['a/b', 'space value'])})
        await manager.start_probe(agent_id, cases=[case], concurrency=1, wait_seconds=None)
        assert [url.params['replace'] for url in seen] == ['a/b', 'space value']
        assert all(url.params['keep'] == 'yes' for url in seen)
    finally:
        await manager.finish_run()
        await service.close()
