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
from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
from tools.http.models import (
    HttpOutputFilters,
    HttpProbeCase,
    HttpRequestSpec,
    HttpVariableSource,
)
from tools.system.policy import SystemToolError, WorkspacePolicy


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
    return service, manager, agent["agent_id"]


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
async def test_request_persists_full_body_and_runs_async_analysis(tmp_path: Path) -> None:
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

    live = manager._live[result["interaction_id"]]
    await live.analysis_done.wait()
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
    assert result["status"] == "running"
    assert result["recommended_wait_seconds"] == 20
    assert result["request_id"].startswith("request-")
    release.set()
    live = manager._live[result["interaction_id"]]
    await live.execution_done.wait()
    first = await manager.output(agent_id, interaction_id=result["interaction_id"])
    second = await manager.output(agent_id, interaction_id=result["interaction_id"])
    assert first["results"] == second["results"]
    assert first["recommended_wait_seconds"] == 20
    await live.analysis_done.wait()
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


def test_http_tool_contract_and_audit_redaction() -> None:
    definitions = HttpTools.tool_definitions()
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
        "system_http_cleanup",
    ]
    descriptions = {
        item["function"]["name"]: item["function"]["description"]
        for item in definitions
    }
    assert "one new HTTP request" in descriptions["system_http_request"]
    assert "response-dependent request chains" in descriptions["system_http_probe"]
    assert "high-throughput web path discovery" in descriptions["system_web_path_probe"]
    assert "web technology stack" in descriptions["system_web_fingerprint"]
    assert "never sends network traffic" in descriptions["system_http_output"]
    request_schema = next(
        item["function"]["parameters"]
        for item in definitions
        if item["function"]["name"] == "system_http_request"
    )
    request_properties = request_schema["$defs"]["HttpRequestSpec"]["properties"]
    assert "http://" in request_properties["url"]["description"]
    assert "request_intent" in request_properties
    redacted = redact_tool_payload(
        "system_http_request",
        {
            "request": {
                "url": "https://x.test/?token=secret",
                "headers": {"Authorization": "Bearer secret", "Cookie": "sid=secret"},
                "body": {"type": "raw", "value": "secret"},
            }
        },
    )
    encoded = json.dumps(redacted)
    assert "Bearer secret" not in encoded
    assert "sid=secret" not in encoded
    assert '"value": "secret"' not in encoded

    path_redacted = redact_tool_payload(
        "system_web_path_probe",
        {
            "url": "https://x.test/",
            "profile": "quick",
            "auth": {"type": "basic", "username": "u", "password": "secret"},
            "headers": {"Authorization": "Bearer secret"},
            "cookies": {"sid": "secret"},
        },
    )
    assert "secret" not in json.dumps(path_redacted)

    fingerprint_redacted = redact_tool_payload(
        "system_web_fingerprint",
        {
            "url": "https://x.test/",
            "auth": {"type": "bearer", "token": "secret"},
            "cookies": {"sid": "secret"},
        },
    )
    assert "secret" not in json.dumps(fingerprint_redacted)


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
    live = manager._live[result["interaction_id"]]
    await live.analysis_done.wait()
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

    await manager._live[first["interaction_id"]].analysis_done.wait()
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
        start_interval_seconds=0,
        psutil_module=FakePsutil,
    )
    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=HttpInteractionEngine(policy, transport=httpx.MockTransport(handler)),
        admission_callback=controller.admit_resource_work,
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
    assert result["resource_admission"]["reason"] == "cpu_limit"

    FakePsutil.cpu = 0.0
    work = (await service.list_resource_work("run-1", owner_id=result["interaction_id"]))[0]
    decision = await controller.admit_resource_work(work["work_id"])
    assert decision["ok"] is True
    await manager.launch_work(
        result["interaction_id"], work["phase"], work_id=work["work_id"]
    )
    await manager._live[result["interaction_id"]].execution_done.wait()
    completed = await manager.output(
        agent["agent_id"], interaction_id=result["interaction_id"]
    )
    assert completed["execution_status"] == "completed"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_resume_reanalyzes_landed_response_without_replaying_request(
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

    async def queue_analysis(work_id: str) -> dict:
        if "-analysis-" in work_id:
            queued = await service.update_resource_work(
                "run-1", work_id, status="queued", reason="test_pause"
            )
            return {"ok": False, **queued}
        reserved = await service.update_resource_work(
            "run-1", work_id, status="reserved"
        )
        return {"ok": True, **reserved}

    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=engine,
        admission_callback=queue_analysis,
    )
    result = await manager.start_request(
        agent["agent_id"],
        request=HttpRequestSpec(
            request_intent="resume analysis", url="https://target.test/"
        ),
        wait_seconds=None,
    )
    assert result["execution_status"] == "completed"
    assert result["analysis_status"] == "queued"
    await manager.pause_run()

    resumed = HttpProbeManager(policy, service, "run-1", engine=engine)
    await resumed.initialize(resume=True)
    live = resumed._live[result["interaction_id"]]
    await live.analysis_done.wait()
    output = await resumed.output(
        agent["agent_id"], interaction_id=result["interaction_id"]
    )
    assert output["status"] == "completed"
    assert output["analysis_status"] == "completed"
    assert calls == 1
    await resumed.finish_run()
    await service.close()
