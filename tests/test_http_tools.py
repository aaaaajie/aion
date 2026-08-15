"""Contract tests for the durable generic HTTP interaction engine."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import httpx
import pytest

from agent.memory.redaction import redact_tool_payload
from agent.state import ResourceController, StateService
from agent.tooling import ToolExecutor, ToolRegistry
from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
from tools.http.models import (
    HttpOutputArguments,
    HttpOutputFilters,
    HttpProbeArguments,
    HttpProbeInputCase,
    HttpProbeCase,
    HttpRequestArguments,
    HttpRequestSpec,
    HttpVariableSource,
)
from tools.system.policy import SystemToolError, WorkspacePolicy
from tests.resource_runtime import install_resource_runtime


def _tool_call(name: str, arguments: dict[str, object], call_id: str) -> dict[str, object]:
    return {
        "id": call_id,
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def test_probe_normalizes_only_unambiguous_shapes() -> None:
    wrapped = HttpProbeArguments.model_validate(
        {
            "arguments": {
                "cases": {
                    "url": "https://target.test/{{path}}",
                    "variables": {"path": {"values": ["/", "/admin"]}},
                },
                "concurrency": 2,
            }
        }
    )
    assert len(wrapped.cases) == 1
    assert wrapped.concurrency == 2

    moved = HttpProbeArguments.model_validate(
        {
            "cases": [
                {
                    "url": "https://target.test/{{path}}",
                    "variables": {"path": {"values": ["/"]}},
                    "wait_seconds": 4,
                }
            ]
        }
    )
    assert moved.wait_seconds == 4
    assert "wait_seconds" not in moved.cases[0].model_fields_set

    with pytest.raises(ValueError, match="ambiguous"):
        HttpProbeArguments.model_validate(
            {
                "cases": [
                    {"url": "https://target.test/a", "concurrency": 2},
                    {"url": "https://target.test/b"},
                ]
            }
        )
    with pytest.raises(ValueError, match="cannot appear"):
        HttpProbeArguments.model_validate(
            {
                "cases": [
                    {"url": "https://target.test/a", "wait_seconds": 4}
                ],
                "wait_seconds": 5,
            }
        )
    with pytest.raises(ValueError):
        HttpProbeArguments.model_validate(
            {
                "cases": [{"url": "https://target.test/a"}],
                "session_id": "ordered",
            }
        )


@pytest.mark.asyncio
async def test_probe_argument_errors_include_one_canonical_rewrite() -> None:
    class RecordingClient:
        def __getattr__(self, name: str):
            async def operation(_arguments):
                raise AssertionError(f"unexpected HTTP operation: {name}")

            return operation

        async def probe(self, _arguments):
            raise AssertionError("invalid Probe arguments reached the handler")

        async def close(self) -> None:
            return None

    executor = ToolExecutor(ToolRegistry([HttpTools(RecordingClient())]))
    results = await executor.execute(
        [
            {
                "id": "invalid-json",
                "function": {
                    "name": "system_http_probe",
                    "arguments": '{"cases": [',
                },
            },
            _tool_call(
                "system_http_probe",
                {
                    "cases": [{"url": "https://target.test/a"}],
                    "session_id": "ordered",
                },
                "invalid-schema",
            ),
        ]
    )
    assert all(item.result and item.result["ok"] is False for item in results)
    for item in results:
        assert "canonical_shape" in item.result["error"]["details"]
        assert "system_http_request" in item.result["error"]["message"]


@pytest.mark.asyncio
async def test_http_tool_executor_preserves_validated_nested_models() -> None:
    received: list[tuple[str, object]] = []

    class RecordingClient:
        def __getattr__(self, name: str):
            async def operation(arguments):
                received.append((name, arguments))
                return {"interaction_id": "interaction-test", "results": []}

            return operation

        async def close(self) -> None:
            return None

    executor = ToolExecutor(ToolRegistry([HttpTools(RecordingClient())]))
    results = await executor.execute(
        [
            _tool_call(
                "system_http_request",
                {"url": "https://target.test/", "body": {"type": "json", "value": {"a": 1}}},
                "request",
            ),
            _tool_call(
                "system_http_probe",
                {"cases": [{"url": "https://target.test/{{id}}", "variables": {"id": {"values": [1, 2]}}}]},
                "probe",
            ),
            _tool_call(
                "system_http_output",
                {"interaction_id": "interaction-test", "filters": {}},
                "empty-filter",
            ),
            _tool_call(
                "system_http_output",
                {"interaction_id": "interaction-test", "filters": {"body_contains": "needle"}},
                "body-filter",
            ),
            _tool_call(
                "system_http_output",
                {"interaction_id": "interaction-test", "filters": {"body_regex": "n.*e"}},
                "regex-filter",
            ),
        ]
    )
    assert all(item.result and item.result["ok"] for item in results)
    by_name = [(name, type(arguments)) for name, arguments in received]
    assert ("request", HttpRequestArguments) in by_name
    assert ("probe", HttpProbeArguments) in by_name
    assert sum(name == "output" for name, _arguments in received) == 3
    probe = next(arguments for name, arguments in received if name == "probe")
    assert isinstance(probe.cases[0], HttpProbeInputCase)
    outputs = [arguments for name, arguments in received if name == "output"]
    assert all(isinstance(item, HttpOutputArguments) for item in outputs)
    assert all(isinstance(item.filters, HttpOutputFilters) for item in outputs)

    rejected = await executor.execute(
        [
            _tool_call(
                "system_http_request",
                {"request": {"url": "https://target.test/"}},
                "old-nested-request",
            )
        ]
    )
    assert rejected[0].result["error"]["stage"] == "schema"
    assert len(received) == 5


async def _manager(
    root: Path, handler
) -> tuple[StateService, HttpProbeManager, str]:
    run_root = root / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent(
        "run-1", role="chief", initial_prompt="http test"
    )
    policy = WorkspacePolicy(root)
    engine = HttpInteractionEngine(policy, transport=httpx.MockTransport(handler))
    manager = HttpProbeManager(policy, service, "run-1", engine=engine)
    await manager.initialize()
    install_resource_runtime(manager, service, "run-1", root=root)
    return service, manager, agent["agent_id"]


async def _wait_for_http_start(
    manager: HttpProbeManager, agent_id: str, interaction_id: str
) -> None:
    while True:
        result = await manager.output(
            agent_id, interaction_id=interaction_id, wait_seconds=0
        )
        if result["execution_status"] == "running":
            return
        await asyncio.sleep(0.001)


@pytest.mark.asyncio
async def test_real_http_loopback_smoke(
    tmp_path: Path, unused_tcp_port: int
) -> None:
    body = b"loopback-http-ok"

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", unused_tcp_port)
    run_root = tmp_path / "runs"
    service = StateService(
        run_root / "loopback" / "state.sqlite3", run_root=run_root
    )
    await service.create_run("loopback")
    agent = await service.register_agent(
        "loopback", role="chief", initial_prompt="http loopback"
    )
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(policy, service, "loopback")
    await manager.initialize()
    install_resource_runtime(manager, service, "loopback", root=tmp_path)
    try:
        result = await manager.start_request(
            agent["agent_id"],
            request=HttpRequestSpec(
                request_intent="loopback_smoke",
                url=f"http://127.0.0.1:{unused_tcp_port}/health",
            ),
            wait_seconds=None,
        )
        response = next(
            item for item in result["results"] if item["type"] == "response"
        )
        assert response["status_code"] == 200
        assert response["body_bytes"] == len(body)
        assert response["outcome"] == "response"
    finally:
        await manager.finish_run()
        await service.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_request_persists_full_body_and_runs_analysis_on_demand(tmp_path: Path) -> None:
    payload = b"<html><title>Probe</title><form action='/x'><input name='id'></form></html>"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["cache-control"] == "no-cache"
        return httpx.Response(200, headers={"content-type": "text/html"}, content=payload)

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(
            request_intent="page_probe", url="https://target.test/index"
        ),
        wait_seconds=None,
    )
    assert result["execution_status"] == "completed"
    assert result["completed_requests"] == 1
    request_id = result["results"][0]["request_id"]

    assert result["analysis_status"] == "not_requested"
    assert result["recommended_action"] == "analyze_or_cleanup"
    analyzed = await manager.analyze(
        agent_id,
        interaction_id=result["interaction_id"],
        wait_seconds=None,
    )
    analysis = next(item for item in analyzed["results"] if item["type"] == "analysis")
    assert analysis["summary"]["kind"] == "html"
    assert analysis["summary"]["input_names"] == ["id"]
    assert analysis["similarity_hash"]

    body = await manager.response(
        agent_id,
        interaction_id=result["interaction_id"],
        request_id=request_id,
        offset_bytes=0,
        length_bytes=len(payload),
    )
    assert body["content"].encode() == payload
    assert body["eof"] is True
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_template_matrix_file_range_and_typed_json(tmp_path: Path) -> None:
    (tmp_path / "paths.txt").write_text("a\nb\n", encoding="utf-8")
    seen: list[tuple[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, json.loads(request.content)))
        return httpx.Response(204)

    service, manager, agent_id = await _manager(tmp_path, handler)
    case = HttpProbeCase(
        request=HttpRequestSpec(
            request_intent="parameter_analysis",
            method="POST",
            url="https://target.test/{{path}}",
            body={"type": "json", "value": {"id": "{{id}}"}},
        ),
        variables={
            "path": HttpVariableSource(file_path="paths.txt", encoding="path"),
            "id": HttpVariableSource(range={"start": 1, "stop": 3}),
        },
        combine="product",
    )
    result = await manager.start_probe(
        agent_id, cases=[case], concurrency=3, wait_seconds=None
    )
    assert result["estimated_requests"] == 4
    assert sorted(seen, key=lambda item: (item[0], item[1]["id"])) == [
        ("/a", {"id": 1}),
        ("/a", {"id": 2}),
        ("/b", {"id": 1}),
        ("/b", {"id": 2}),
    ]
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_probe_size_limit_rejects_before_files_or_state(tmp_path: Path) -> None:
    service, manager, agent_id = await _manager(
        tmp_path, lambda _request: httpx.Response(200)
    )
    oversized = HttpProbeCase(
        request=HttpRequestSpec(
            request_intent="oversized",
            url="https://target.test/{{left}}/{{right}}",
        ),
        variables={
            "left": HttpVariableSource(range={"start": 0, "stop": 100}),
            "right": HttpVariableSource(range={"start": 0, "stop": 51}),
        },
    )
    with pytest.raises(SystemToolError) as caught:
        await manager.start_probe(agent_id, cases=[oversized], wait_seconds=0)
    assert caught.value.code == "http_probe_too_large"
    assert await service.list_http_interactions("run-1", agent_id=agent_id) == []
    interactions_root = manager._agent_root(agent_id) / "http-interactions"
    assert not interactions_root.exists() or list(interactions_root.iterdir()) == []
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_http_creation_transaction_rolls_back_and_cleans_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, manager, agent_id = await _manager(
        tmp_path, lambda _request: httpx.Response(200)
    )
    original_event = service._event

    async def fail_second_event(session, run_id, event_type, payload, **kwargs):
        if event_type == "resource_work_queued":
            raise RuntimeError("injected enqueue failure")
        return await original_event(session, run_id, event_type, payload, **kwargs)

    monkeypatch.setattr(service, "_event", fail_second_event)
    with pytest.raises(RuntimeError, match="injected enqueue failure"):
        await manager.start_request(
            agent_id,
            request=HttpRequestSpec(
                request_intent="rollback", url="https://target.test/"
            ),
            wait_seconds=0,
        )
    assert await service.list_http_interactions("run-1", agent_id=agent_id) == []
    assert await service.list_resource_work("run-1") == []
    interactions_root = manager._agent_root(agent_id) / "http-interactions"
    assert not interactions_root.exists() or list(interactions_root.iterdir()) == []
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_probe_reuses_pool_and_does_not_queue_automatic_analysis(
    tmp_path: Path,
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_probe(
        agent_id,
        cases=[
            HttpProbeCase(
                request=HttpRequestSpec(
                    request_intent="pool",
                    url="https://target.test/{{id}}",
                ),
                variables={"id": HttpVariableSource(range={"start": 0, "stop": 50})},
            )
        ],
        concurrency=8,
        wait_seconds=None,
    )
    work = await service.list_resource_work(
        "run-1", owner_id=result["interaction_id"]
    )
    assert [item["phase"] for item in work] == ["execution"]
    assert result["analysis_status"] == "not_requested"
    assert result["connection_pool"]["pool_count"] == 1
    assert result["connection_pool"]["network_requests"] == 50
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_redirect_cookies_are_local_and_independent_requests_do_not_inherit(
    tmp_path: Path,
) -> None:
    observed: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed[request.url.path] = request.headers.get("cookie", "")
        if request.url.path == "/redirect":
            return httpx.Response(
                302,
                headers={"location": "/final", "set-cookie": "sid=redirect; Path=/"},
            )
        return httpx.Response(200, text="ok")

    service, manager, agent_id = await _manager(tmp_path, handler)
    await manager.start_probe(
        agent_id,
        cases=[
            HttpProbeCase(
                request=HttpRequestSpec(
                    request_intent="redirect",
                    url="https://target.test/redirect",
                    follow_redirects=True,
                )
            ),
            HttpProbeCase(
                request=HttpRequestSpec(
                    request_intent="independent",
                    url="https://target.test/independent",
                )
            ),
        ],
        concurrency=2,
        wait_seconds=None,
    )
    assert observed["/redirect"] == ""
    assert observed["/final"] == "sid=redirect"
    assert observed["/independent"] == ""
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_keep_alive_probe_uses_no_more_connections_than_concurrency(
    tmp_path: Path, unused_tcp_port: int
) -> None:
    accepted_connections = 0

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal accepted_connections
        accepted_connections += 1
        try:
            while True:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Connection: keep-alive\r\n\r\nok"
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", unused_tcp_port)
    run_root = tmp_path / "runs"
    service = StateService(
        run_root / "keepalive" / "state.sqlite3", run_root=run_root
    )
    await service.create_run("keepalive")
    agent = await service.register_agent(
        "keepalive", role="chief", initial_prompt="keepalive"
    )
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(
        policy,
        service,
        "keepalive",
        engine=HttpInteractionEngine(
            policy, transport=httpx.AsyncHTTPTransport()
        ),
    )
    await manager.initialize()
    install_resource_runtime(manager, service, "keepalive", root=tmp_path)
    try:
        result = await manager.start_probe(
            agent["agent_id"],
            cases=[
                HttpProbeCase(
                    request=HttpRequestSpec(
                        request_intent="keepalive",
                        url=f"http://127.0.0.1:{unused_tcp_port}/{{{{id}}}}",
                    ),
                    variables={
                        "id": HttpVariableSource(range={"start": 0, "stop": 50})
                    },
                )
            ],
            concurrency=8,
            wait_seconds=None,
        )
        assert result["completed_requests"] == 50
        assert accepted_connections <= 8
        assert result["connection_pool"]["observed_connections"] <= 8
        assert result["connection_pool"]["connection_reuses"] >= 42
    finally:
        await manager.finish_run()
        await service.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_session_is_private_and_tracks_cookie_updates(tmp_path: Path) -> None:
    observed_cookie: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sid=abc; Path=/"})
        observed_cookie.append(request.headers.get("cookie", ""))
        return httpx.Response(200)

    service, manager, agent_id = await _manager(tmp_path, handler)
    login = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(
            request_intent="login",
            method="POST",
            url="https://target.test/login",
            session_id="main",
            update_session=True,
        ),
        wait_seconds=None,
    )
    await manager.start_request(
        agent_id,
        request=HttpRequestSpec(
            request_intent="authenticated_status",
            url="https://target.test/private",
            session_id="main",
            parent_request_id=login["results"][0]["request_id"],
        ),
        wait_seconds=None,
    )
    assert observed_cookie == ["sid=abc"]
    session_path = manager._session_path(agent_id, "main")
    session = json.loads(session_path.read_text(encoding="utf-8"))
    assert session["created_by"]["interaction_id"] == login["interaction_id"]
    await manager.finish_run()
    assert not session_path.exists()
    await service.close()


@pytest.mark.asyncio
async def test_zero_wait_returns_running_and_output_does_not_repeat_request(tmp_path: Path) -> None:
    release = asyncio.Event()
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await release.wait()
        return httpx.Response(200, text="done")

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(request_intent="status", url="https://target.test/"),
        wait_seconds=0,
    )
    assert result["status"] == "queued"
    await asyncio.wait_for(
        asyncio.create_task(_wait_for_http_start(manager, agent_id, result["interaction_id"])),
        timeout=1,
    )
    assert result["recommended_wait_seconds"] == 20
    assert result["request_id"].startswith("request-")
    release.set()
    live = manager._live[result["interaction_id"]]
    await live.execution_done.wait()
    first = await manager.output(agent_id, interaction_id=result["interaction_id"])
    second = await manager.output(agent_id, interaction_id=result["interaction_id"])
    assert first["results"] == second["results"]
    assert first["analysis_status"] == "not_requested"
    assert first["recommended_action"] == "analyze_or_cleanup"
    finished = await manager.output(agent_id, interaction_id=result["interaction_id"])
    assert finished["recommended_wait_seconds"] == 0
    assert calls == 1
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_pause_marks_active_request_interrupted_without_replay(tmp_path: Path) -> None:
    started = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.Event().wait()
        return httpx.Response(200)

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(request_intent="long", url="https://target.test/"),
        wait_seconds=0,
    )
    await started.wait()
    await manager.pause_run()
    row = await service.get_http_interaction("run-1", agent_id, result["interaction_id"])
    assert row["status"] == "interrupted"
    assert row["execution_status"] == "interrupted"
    output = await manager.output(agent_id, interaction_id=result["interaction_id"])
    interrupted = next(item for item in output["results"] if item["type"] == "response")
    assert interrupted["outcome"] == "interrupted"
    assert interrupted["body_complete"] is False
    resumed = HttpProbeManager(WorkspacePolicy(tmp_path), service, "run-1")
    await resumed.initialize(resume=True)
    row = await service.get_http_interaction("run-1", agent_id, result["interaction_id"])
    assert row["status"] == "interrupted"
    await service.close()


@pytest.mark.asyncio
async def test_ownership_and_resource_disk_admission(tmp_path: Path) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    service, manager, agent_id = await _manager(tmp_path, handler)
    other = await service.register_agent("run-1", role="chief", initial_prompt="other")
    result = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(request_intent="owner", url="https://target.test/"),
        wait_seconds=None,
    )
    with pytest.raises(Exception):
        await manager.output(other["agent_id"], interaction_id=result["interaction_id"])

    work = await service.create_resource_work(
        "run-1",
        agent_id,
        work_id="disk-work",
        owner_type="test",
        owner_id="test-owner",
        phase="execution",
        priority=50,
        requested_concurrency=1,
        estimated_requests=1,
        estimated_disk_bytes=10**30,
        estimated_memory_bytes=1,
    )
    controller = ResourceController(service, "run-1", storage_root=tmp_path)
    decision = await controller.admit_resource_work(
        work["work_id"], sample={"cpu_percent": 0.0, "memory_percent": 0.0}
    )
    assert decision["status"] == "queued"
    assert decision["reason"] == "disk_reservation"
    await manager.finish_run()
    await service.close()


def test_http_tool_contract_and_plaintext_audit(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(policy, service, "run-1")
    from agent.tooling import ToolRegistry

    definitions = ToolRegistry([HttpTools(manager.bind("execution-test"))]).definitions()
    schema_chars = sum(
        len(json.dumps(item["function"]["parameters"], separators=(",", ":")))
        for item in definitions
    )
    assert schema_chars <= 17_500
    names = [item["function"]["name"] for item in definitions]
    assert names == [
        "system_http_request",
        "system_http_probe",
        "system_web_path_probe",
        "system_web_fingerprint",
        "system_http_analyze",
        "system_http_output",
        "system_http_response",
        "system_http_stop",
    ]
    descriptions = {
        item["function"]["name"]: item["function"]["description"]
        for item in definitions
    }
    assert "one fresh HTTP request" in descriptions["system_http_request"]
    assert "finite matrix" in descriptions["system_http_probe"]
    assert "bounded web path discovery" in descriptions["system_web_path_probe"]
    assert "web technology stack" in descriptions["system_web_fingerprint"]
    assert "never resends traffic" in descriptions["system_http_output"]
    request_schema = next(
        item["function"]["parameters"]
        for item in definitions
        if item["function"]["name"] == "system_http_request"
    )
    request_properties = request_schema["properties"]
    assert "http://" in request_properties["url"]["description"]
    assert "request" not in request_properties
    assert "request_intent" not in request_properties
    assert "connection_context_id" not in request_properties
    probe_definition = next(
        item["function"]
        for item in definitions
        if item["function"]["name"] == "system_http_probe"
    )
    assert "variables/combine" in probe_definition["description"]
    assert "ordered multi-step protocols" in probe_definition["description"]
    assert "variables" not in probe_definition["parameters"]["properties"]
    assert "session_id" not in probe_definition["parameters"]["properties"]
    plaintext = redact_tool_payload(
        "system_http_request",
        {
            "url": "https://x.test/?token=secret",
            "headers": {"Authorization": "Bearer secret", "Cookie": "sid=secret"},
            "body": {"type": "raw", "value": "secret"},
        },
    )
    encoded = json.dumps(plaintext)
    assert "Bearer secret" in encoded
    assert "sid=secret" in encoded
    assert '"value": "secret"' in encoded

    path_plaintext = redact_tool_payload(
        "system_web_path_probe",
        {
            "url": "https://x.test/",
            "profile": "quick",
            "auth": {"type": "basic", "username": "u", "password": "secret"},
            "headers": {"Authorization": "Bearer secret"},
            "cookies": {"sid": "secret"},
        },
    )
    assert "secret" in json.dumps(path_plaintext)

    fingerprint_plaintext = redact_tool_payload(
        "system_web_fingerprint",
        {
            "url": "https://x.test/",
            "auth": {"type": "bearer", "token": "secret"},
            "cookies": {"sid": "secret"},
        },
    )
    assert "secret" in json.dumps(fingerprint_plaintext)


def test_zip_expansion_and_unresolved_variables_are_validated(tmp_path: Path) -> None:
    engine = HttpInteractionEngine(WorkspacePolicy(tmp_path))
    case = HttpProbeCase(
        request=HttpRequestSpec(
            request_intent="zip",
            url="https://target.test/{{path}}?copy={{copy}}",
        ),
        variables={
            "path": HttpVariableSource(values=["a b", "c"], encoding="path"),
            "copy": HttpVariableSource(values=[1, 2]),
        },
        combine="zip",
    )
    expanded = engine.expand_cases(
        [case], id_factory=lambda: "fixed", default_group_id="group"
    )
    assert [item.spec.url for item in expanded] == [
        "https://target.test/a%20b?copy=1",
        "https://target.test/c?copy=2",
    ]

    unresolved = HttpProbeCase(
        request=HttpRequestSpec(
            request_intent="bad", url="https://target.test/{{missing}}"
        )
    )
    with pytest.raises(SystemToolError) as caught:
        engine.expand_cases(
            [unresolved], id_factory=lambda: "fixed", default_group_id="group"
        )
    assert caught.value.code == "unknown_template_variable"


@pytest.mark.asyncio
async def test_similarity_groups_force_revision_and_analysis_field_selection(
    tmp_path: Path,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["id"]
        return httpx.Response(
            200,
            headers={"content-type": "text/plain; charset=utf-8"},
            text=f"stable account page id {value} generated 987654",
        )

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_probe(
        agent_id,
        cases=[
            HttpProbeCase(
                request=HttpRequestSpec(
                    request_intent="similarity",
                    url="https://target.test/page",
                    query={"id": "{{id}}"},
                ),
                variables={"id": HttpVariableSource(values=[123, 456])},
            )
        ],
        wait_seconds=None,
    )
    analyzed = await manager.analyze(
        agent_id, interaction_id=result["interaction_id"], wait_seconds=None
    )
    assert analyzed["similarity_groups"][0]["count"] == 2
    request_id = analyzed["results"][0]["request_id"]

    forced = await manager.analyze(
        agent_id,
        interaction_id=result["interaction_id"],
        request_ids=[request_id],
        force=True,
        similarity=False,
        features=False,
        summary=False,
        wait_seconds=None,
    )
    assert max(item["revision"] for item in forced["results"]) == 2
    assert forced["similarity_groups"] == []
    assert all("similarity_hash" not in item for item in forced["results"])
    assert all("features" not in item for item in forced["results"])
    assert all("summary" not in item for item in forced["results"])
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_output_filters_and_binary_body_chunks(tmp_path: Path) -> None:
    payload = b"\x89PNG\r\n\x1a\n\x00binary-secret"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201, headers={"content-type": "image/png", "x-test": "needle"}, content=payload
        )

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(request_intent="binary", url="https://target.test/x"),
        wait_seconds=None,
    )
    page = await manager.output(
        agent_id,
        interaction_id=result["interaction_id"],
        filters=HttpOutputFilters(
            status_codes=[201],
            header_contains={"x-test": "need"},
            body_contains="binary-secret",
        ),
    )
    assert len(page["results"]) == 1
    request_id = page["results"][0]["request_id"]
    chunk = await manager.response(
        agent_id,
        interaction_id=result["interaction_id"],
        request_id=request_id,
        length_bytes=len(payload),
    )
    assert chunk["encoding"] == "base64"
    assert base64.b64decode(chunk["content"]) == payload
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_request_group_isolation_and_terminal_cleanup_metadata(
    tmp_path: Path,
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    service, manager, agent_id = await _manager(tmp_path, handler)
    first = await manager.start_request(
        agent_id,
        request=HttpRequestSpec(
            request_intent="group owner",
            request_group_id="shared-chain",
            url="https://target.test/one",
        ),
        wait_seconds=None,
    )
    other = await service.register_agent("run-1", role="chief", initial_prompt="other")
    with pytest.raises(SystemToolError) as caught:
        await manager.start_request(
            other["agent_id"],
            request=HttpRequestSpec(
                request_intent="foreign group",
                request_group_id="shared-chain",
                url="https://target.test/two",
            ),
            wait_seconds=None,
        )
    assert caught.value.code == "request_group_not_found"

    cleaned = await manager.cleanup(agent_id, interaction_id=first["interaction_id"])
    repeated = await manager.cleanup(agent_id, interaction_id=first["interaction_id"])
    stopped = await manager.stop(agent_id, interaction_id=first["interaction_id"])
    row = await service.get_http_interaction(
        "run-1", agent_id, first["interaction_id"]
    )
    assert cleaned["cleaned"] is True
    assert repeated["already_cleaned"] is True
    assert stopped["output_cleaned"] is True
    assert row["output_cleaned_at"] is not None
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_batch_session_updates_are_serialized_and_agent_private(
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers.get("cookie", ""))
        step = request.url.params["step"]
        return httpx.Response(200, headers={"set-cookie": f"step={step}; Path=/"})

    service, manager, agent_id = await _manager(tmp_path, handler)
    result = await manager.start_probe(
        agent_id,
        cases=[
            HttpProbeCase(
                request=HttpRequestSpec(
                    request_intent="session sequence",
                    url="https://target.test/session",
                    query={"step": "{{step}}"},
                    session_id="batch",
                    update_session=True,
                ),
                variables={"step": HttpVariableSource(values=["one", "two"])},
            )
        ],
        concurrency=2,
        wait_seconds=None,
    )
    assert observed == ["", "step=one"]
    session_path = manager._session_path(agent_id, "batch")
    session = json.loads(session_path.read_text(encoding="utf-8"))
    assert session["updated_by"]["request_id"] == result["results"][-1]["request_id"]
    sqlite_dump = " ".join(
        json.dumps(item)
        for item in await service.list_agent_events(
            "run-1", agent_id, after_sequence=0
        )
    )
    assert "step=one" not in sqlite_dump
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_runtime_resource_queue_exposes_reason_and_resumes(
    tmp_path: Path,
) -> None:
    class Memory:
        percent = 10.0
        available = 10**9

    class FakePsutil:
        cpu = 95.0

        @classmethod
        def cpu_percent(cls, interval=None):
            return cls.cpu

        @staticmethod
        def virtual_memory():
            return Memory()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="admitted")

    run_root = tmp_path / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent("run-1", role="chief", initial_prompt="http")
    policy = WorkspacePolicy(tmp_path)
    controller = ResourceController(
        service,
        "run-1",
        storage_root=tmp_path,
        psutil_module=FakePsutil,
    )
    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=HttpInteractionEngine(policy, transport=httpx.MockTransport(handler)),
        resource_guard=controller.check_resource_work,
    )
    result = await manager.start_request(
        agent["agent_id"],
        request=HttpRequestSpec(
            request_intent="resource admission", url="https://target.test/"
        ),
        wait_seconds=0,
    )
    assert result["status"] == "queued"
    work = (await service.list_resource_work("run-1", owner_id=result["interaction_id"]))[0]
    denied = await controller.admit_resource_work(work["work_id"])
    assert denied["reason"] == "cpu_limit"

    FakePsutil.cpu = 0.0
    decision = await controller.admit_resource_work(work["work_id"])
    assert decision["ok"] is True
    claim = await controller.claim_resource_work(work["work_id"])
    assert claim["claimed"] is True
    await manager.launch_work(
        result["interaction_id"], work["phase"], work_id=work["work_id"]
    )
    await controller.mark_resource_started(work["work_id"])
    await manager._live[result["interaction_id"]].execution_done.wait()
    completed = await manager.output(
        agent["agent_id"], interaction_id=result["interaction_id"]
    )
    assert completed["execution_status"] == "completed"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_resume_keeps_landed_response_and_analysis_remains_on_demand(
    tmp_path: Path,
) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text="persisted response")

    run_root = tmp_path / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent("run-1", role="chief", initial_prompt="http")
    policy = WorkspacePolicy(tmp_path)
    engine = HttpInteractionEngine(policy, transport=httpx.MockTransport(handler))

    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=engine,
    )
    result = await manager.start_request(
        agent["agent_id"],
        request=HttpRequestSpec(
            request_intent="resume analysis", url="https://target.test/"
        ),
        wait_seconds=0,
    )
    controller = ResourceController(service, "run-1", storage_root=tmp_path)
    execution_work = (await service.list_resource_work(
        "run-1", owner_id=result["interaction_id"], statuses={"queued"}
    ))[0]
    await controller.admit_resource_work(
        execution_work["work_id"], sample={"cpu_percent": 0.0, "memory_percent": 0.0}
    )
    assert (await controller.claim_resource_work(execution_work["work_id"]))["claimed"]
    await manager.launch_work(
        result["interaction_id"], execution_work["phase"], work_id=execution_work["work_id"]
    )
    await controller.mark_resource_started(execution_work["work_id"])
    await manager._live[result["interaction_id"]].execution_done.wait()
    result = await manager.output(agent["agent_id"], interaction_id=result["interaction_id"])
    assert result["execution_status"] == "completed"
    assert result["analysis_status"] == "not_requested"
    await manager.pause_run()

    resumed = HttpProbeManager(policy, service, "run-1", engine=engine)
    await resumed.initialize(resume=True)
    install_resource_runtime(resumed, service, "run-1", root=tmp_path)
    output = await resumed.analyze(
        agent["agent_id"], interaction_id=result["interaction_id"], wait_seconds=None
    )
    assert output["status"] == "completed"
    assert output["analysis_status"] == "completed"
    assert calls == 1
    await resumed.finish_run()
    await service.close()
