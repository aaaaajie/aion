"""Local protocol fixture plus real tool discovery/Runner integration."""
import asyncio
import base64
from contextlib import asynccontextmanager
import json
import struct

import pytest
from pydantic import ValidationError

from tools.fastcgi import FastCGITools
from tools.fastcgi.wrapper import FastCGIArguments
from agent.subagents.policy import AgentPolicy
from agent.tooling import ToolRegistry, ToolExecutor
from tests.test_compact_tools import wire
from tests.test_solver_lifecycle import harness, completion


def frame(kind, body=b'', request_id=1, version=1):
    return struct.pack('!BBHHBB', version, kind, request_id, len(body), 3, 0) + body + b'pad'


def end(app=0, protocol=0):
    return frame(3, struct.pack('!IB3x', app, protocol))


async def receive_request(reader):
    streams = {4: bytearray(), 5: bytearray()}
    lengths = {4: [], 5: []}
    begin = None
    while True:
        version, kind, req, length, padding, _ = struct.unpack('!BBHHBB', await reader.readexactly(8))
        assert version == 1 and req == 1
        body = await reader.readexactly(length)
        await reader.readexactly(padding)
        if kind == 1:
            begin = body
        else:
            streams[kind].extend(body)
            lengths[kind].append(length)
        if kind == 5 and not length:
            return begin, streams, lengths


def decode_pairs(data):
    position = 0
    def length():
        nonlocal position
        n = data[position]
        if n & 128:
            n = int.from_bytes(data[position:position+4], 'big') & 0x7fffffff
            position += 4
        else:
            position += 1
        return n
    params = {}
    while position < len(data):
        a, b = length(), length()
        key = bytes(data[position:position+a]).decode()
        position += a
        value = bytes(data[position:position+b]).decode()
        position += b
        params[key] = value
    return params


@asynccontextmanager
async def server(handler):
    tasks = set()
    failures = []
    async def connected(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            request = await receive_request(reader)
            await handler(request, reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            failures.append(exc)
        finally:
            writer.close()
            await writer.wait_closed()
            tasks.discard(task)
    listener = await asyncio.start_server(connected, '127.0.0.1', 0)
    try:
        yield listener.sockets[0].getsockname()[1]
    finally:
        listener.close()
        await listener.wait_closed()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)
        assert not failures, failures


async def invoke(provider, port, **args):
    registry = ToolRegistry([provider])
    result = (await ToolExecutor(registry).execute([wire('system_fastcgi_request', {
        'host': '127.0.0.1', 'port': port, **args,
    })]))[0].result
    if not result['ok']:
        assert result['error']['retry'] == {
            'allowed': False, 'action': 'none', 'tool': None, 'same_arguments': False,
        }
        assert result['error']['code'] != 'invalid_tool_result'
    return result


async def test_fragmentation_padding_large_params_and_binary_stdin():
    params = {'NAME': 'x'*70000, '非ASCII': 'value', 'N'*128: 'long name'}
    data = b'\xff\x00'*40000
    async def handle(request, reader, writer):
        begin, streams, lengths = request
        assert begin == b'\x00\x01\x00\x00\x00\x00\x00\x00'
        assert decode_pairs(streams[4]) == params
        assert bytes(streams[5]) == data
        assert lengths[4][-1] == lengths[5][-1] == 0
        assert max(lengths[4]) == max(lengths[5]) == 65535
        response = frame(6, b'Status: 200 OK\r\n\r\nfixture') + frame(7, b'note') + frame(7) + frame(6) + end()
        for start in range(0, len(response), 5):
            writer.write(response[start:start+5])
            await writer.drain()
    provider = FastCGITools()
    async with server(handle) as port:
        result = await invoke(provider, port, params=params, stdin=base64.b64encode(data).decode(), stdin_encoding='base64')
        assert result['ok'] and result['data']['complete']
        assert result['data']['stdout']['content'].endswith('fixture')
        assert result['data']['stderr']['content'] == 'note'
        assert result['data']['protocol_status'] == result['data']['app_status'] == 0
        assert not provider.client._writers
    await provider.close()


@pytest.mark.parametrize('response,code', [
    (frame(6, b'partial'), 'fastcgi_incomplete'),
    (frame(6, b'12345'), 'fastcgi_output_limit'),
    (frame(6, b'ok', request_id=2), 'fastcgi_protocol_error'),
    (frame(6, b'ok', version=2), 'fastcgi_protocol_error'),
    (frame(6) + end(7), 'fastcgi_application_status'),
    (end(protocol=2), 'fastcgi_protocol_status'),
    (frame(3, b'bad'), 'fastcgi_protocol_error'),
])
async def test_incomplete_limit_and_protocol_failures(response, code):
    async def handle(request, reader, writer):
        writer.write(response)
        await writer.drain()
    provider = FastCGITools()
    async with server(handle) as port:
        result = await invoke(provider, port, max_output_bytes=4 if code == 'fastcgi_output_limit' else 100)
        assert not result['ok'] and result['error']['code'] == code
        expected = response[:8] if response[0] != 1 or int.from_bytes(response[2:4], 'big') != 1 else response
        assert raw_bytes(result['data']) == expected
        assert result['data']['bytes_received'] == len(expected)
        if code in {'fastcgi_incomplete', 'fastcgi_output_limit'}:
            assert result['data']['outcome_unknown'] and not result['data']['complete']
            assert result['data']['stdout']['content'] == ('partial' if code == 'fastcgi_incomplete' else '1234')
    await provider.close()


async def test_binary_output_is_lossless():
    async def handle(request, reader, writer):
        writer.write(frame(6, b'\xff\x00') + frame(6) + end())
        await writer.drain()
    provider = FastCGITools()
    async with server(handle) as port:
        result = await invoke(provider, port)
        assert result['data']['stdout'] == {'encoding': 'base64', 'content': '/wA=', 'bytes': 2}
    await provider.close()


async def test_closed_provider_preserves_error_through_executor():
    provider = FastCGITools()
    await provider.close()
    result = await invoke(provider, 9000)
    assert result['error']['code'] == 'fastcgi_closed'


async def test_timeout_cancellation_and_provider_close_release_connection():
    started = asyncio.Queue()
    disconnected = asyncio.Queue()
    async def handle(request, reader, writer):
        await started.put(True)
        assert await reader.read() == b''
        await disconnected.put(True)
    provider = FastCGITools()
    async with server(handle) as port:
        result = await invoke(provider, port, timeout_seconds=0.1)
        assert result['error']['code'] == 'fastcgi_timeout'
        assert result['data']['outcome_unknown']
        await asyncio.wait_for(disconnected.get(), 1)
        await started.get()
        task = asyncio.create_task(invoke(provider, port))
        await started.get()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(disconnected.get(), 1)
        task = asyncio.create_task(invoke(provider, port))
        await started.get()
        await provider.close()
        assert not (await task)['ok']
        await asyncio.wait_for(disconnected.get(), 1)
        assert not provider.client._writers


@pytest.mark.parametrize('values', [
    {'stdin': '!', 'stdin_encoding': 'base64'}, {'host': 'https://example.test'},
    {'params': {'BAD\x00KEY': 'x'}}, {'params': {'x': 3}},
    {'stdin': 'x'*1048577}, {'timeout_seconds': 600},
])
def test_invalid_request_rejected_before_network(values):
    with pytest.raises(ValidationError):
        FastCGIArguments.model_validate({'host': '127.0.0.1', **values})


async def test_compact_discovery_and_role_permissions():
    provider = FastCGITools()
    try:
        for role, mode, allowed in [('solver', 'execute', True), ('worker', 'execute', True), ('worker', 'review', False), ('chief', 'execute', False)]:
            registry = ToolRegistry([provider], allowed_tools=AgentPolicy(role, mode).allowed_tools, compact=True)
            definitions = registry.definitions()
            assert all(d['function']['name'] != 'system_fastcgi_request' for d in definitions)
            found = (await ToolExecutor(registry).execute([wire('tool_search', {'query': 'fastcgi'})]))[0].result
            assert bool(found['data']['tools']) == allowed
    finally:
        await provider.close()


@pytest.mark.parametrize('incomplete', [False, True])
async def test_real_runner_discovers_calls_and_persists_evidence(tmp_path, incomplete):
    reached = asyncio.Event()
    async def handle(request, reader, writer):
        assert decode_pairs(request[1][4]) == {'REQUEST_METHOD': 'GET'}
        response = frame(6, b'Content-Type: text/plain\r\n\r\nfixture')
        writer.write(response if incomplete else response + frame(6) + end())
        await writer.drain()
    async with server(handle) as port:
        async def model(role, index, body):
            names = {t['function']['name'] for t in body['tools']}
            assert ('system_fastcgi_request' not in names) if index == 0 else ('system_fastcgi_request' in names)
            if index == 0:
                return completion('tool_search', {'name': 'system_fastcgi_request'})
            if index == 1:
                return completion('system_fastcgi_request', {
                    'host': '127.0.0.1', 'port': port, 'params': {'REQUEST_METHOD': 'GET'}})
            reply = json.loads(body['messages'][-1]['content'])
            if incomplete:
                assert reply['error']['code'] == 'fastcgi_incomplete'
                assert reply['error']['retry']['allowed'] is False
                assert reply['data']['outcome_unknown'] and not reply['data']['complete']
                assert reply['data']['stdout']['content'].endswith('fixture')
            else:
                assert reply['data']['complete'] and reply['data']['evidence_refs']
            reached.set()
            return completion('solver_wait')
        sup, service, _, _, chief = await harness(tmp_path, model, solver_observation=False)
        try:
            await sup.create_solver(chief, 'a')
            await asyncio.wait_for(reached.wait(), 5)
        finally:
            await sup.close()
            await service.close()


@pytest.mark.parametrize('response,stdout,code', [
    (frame(6, b'fixture') + end(), 'fixture', None),
    (end(), '', None),
    (frame(6, b'fixture') + end(app=7), 'fixture', 'fastcgi_application_status'),
])
async def test_end_request_completes_without_empty_stdout_record(response, stdout, code):
    async def handle(request, reader, writer):
        # Fragment the PHP-style response, including the final record.
        for start in range(0, len(response), 5):
            writer.write(response[start:start+5])
            await writer.drain()
    provider = FastCGITools()
    async with server(handle) as port:
        result = await invoke(provider, port)
        assert result['ok'] == (code is None)
        assert result['data']['complete'] and not result['data']['outcome_unknown']
        assert result['data']['end_request_received']
        assert not result['data']['stdout_terminated']
        assert result['data']['stdout']['content'] == stdout
        assert raw_bytes(result['data']) == response
        assert result['data']['transport']['status'] == 'end_request'
        if code:
            assert result['error']['code'] == code
    await provider.close()


def raw_bytes(data):
    value = data['raw_response']
    return (base64.b64decode(value['content']) if value['encoding'] == 'base64'
            else value['content'].encode('utf-8'))


@pytest.mark.parametrize('stop', ['eof', 'timeout'])
@pytest.mark.parametrize('response', [b'', b'\x01\x06', frame(6, b'hello')[:10],
                                      frame(6, b'hello')[:-1], frame(6, b'<RST-after-data>')])
async def test_actual_bytes_survive_partial_reads(response, stop):
    async def handle(request, reader, writer):
        writer.write(response)
        await writer.drain()
        if stop == 'timeout':
            await reader.read()
    provider = FastCGITools()
    try:
        async with server(handle) as port:
            result = await invoke(provider, port, timeout_seconds=0.1)
        data = result['data']
        assert not result['ok'] and not data['complete']
        assert data['transport']['status'] == stop
        assert data['transport']['phase'] == 'receive'
        assert data['bytes_received'] == data['raw_response']['bytes'] == len(response)
        assert raw_bytes(data) == response
        # A marker sent by the fixture really is data; do not strip by spelling.
        expected = '<RST-after-data>' if response == frame(6, b'<RST-after-data>') else ''
        assert data['stdout']['content'] == expected
        assert data['stdout']['bytes'] == len(expected)
        assert data['stderr']['bytes'] == 0
        from agent.observation_input import observation_data
        observed = observation_data(result)['data']
        assert observed['bytes_received'] == len(response)
        assert observed['transport']['status'] == stop
    finally:
        await provider.close()


@pytest.mark.parametrize('response', [b'', frame(6, b'actual') + b'\x01\x03'])
async def test_reset_diagnostic_never_becomes_received_bytes(monkeypatch, response):
    # Script the socket failure to avoid platform-specific TCP RST timing.
    class Reader:
        def __init__(self):
            self.pending = response

        async def read(self, size):
            if not self.pending:
                raise ConnectionResetError('<RST-after-data>')
            chunk, self.pending = self.pending[:size], self.pending[size:]
            return chunk

    class Writer:
        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def connect(*args):
        return Reader(), Writer()

    monkeypatch.setattr(asyncio, 'open_connection', connect)
    provider = FastCGITools()
    try:
        result = await invoke(provider, 9000)
        data = result['data']
        assert result['error']['code'] == 'fastcgi_connection_error'
        assert data['transport'] == {'status': 'reset', 'phase': 'receive', 'error_type': 'ConnectionResetError'}
        assert data['bytes_received'] == len(response)
        assert raw_bytes(data) == response
        assert data['stdout']['content'] == ('actual' if response else '')
        assert data['outcome_unknown'] and not data['complete']
        assert '<RST-after-data>' not in data['stdout']['content']
    finally:
        await provider.close()
