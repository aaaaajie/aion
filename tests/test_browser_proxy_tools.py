from __future__ import annotations

import asyncio
import base64
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from agent.runner import ToolRegistry
from agent.subagents.policy import AgentPolicy
from agent.subagents.supervisor import _browser_proxy_environment
from agent.tooling import ToolExecutor
from tools.browser import BrowserManager, BrowserTools
from tools.browser.manager import (
    _build_argv,
    _browser_runtime_dir,
    _browser_shell_command,
    _session_name,
)
from tools.browser.models import BrowserArguments
from tools.proxy import CaidoProxyManager, ProxyTools
from tools.proxy.caido_api import (
    CaidoGraphQLClient,
    apply_modifications,
    full_url_from_components,
    format_request_connection,
    build_raw_request,
    ensure_project_with_client,
    format_search_hits,
    get_request_with_client,
    list_requests_with_client,
    list_sitemap_with_client,
    parse_raw_request,
    replay_request_with_client,
    scope_rules_with_client,
)
from tools.proxy.models import ProxyArguments
from tools.system.policy import SystemToolError


class FakeShell:
    def __init__(self, *, output: str = "ok", exit_code: int | None = 0) -> None:
        self.output = output
        self.exit_code = exit_code
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def run_shell(self, command: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((command, kwargs))
        return {
            "status": "completed" if self.exit_code in {None, 0} else "failed",
            "exit_code": self.exit_code,
            "output": self.output,
            "truncated": False,
        }


class FakeCaidoClient:
    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class FakeGraphQLClient:
    def __init__(self, *, reject_project_creation: bool = False) -> None:
        self.graphql = self
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.mutations: list[tuple[str, dict[str, Any]]] = []
        self.replay_poll_count = 0
        self.reject_project_creation = reject_project_creation

    async def query(self, document: str, *, variables: dict[str, Any]) -> dict[str, Any]:
        self.queries.append((document, variables))
        if "query Requests(" in document:
            return {
                "requests": {
                    "edges": [],
                    "pageInfo": {
                        "hasNextPage": False,
                        "hasPreviousPage": False,
                        "startCursor": None,
                        "endCursor": None,
                    },
                }
            }
        if "query Request(" in document:
            return {
                "request": {
                    "id": "req-1",
                    "host": "fixture.test",
                    "port": 80,
                    "method": "POST",
                    "path": "/users/1",
                    "query": "",
                    "isTls": False,
                    "createdAt": 1,
                    "raw": base64.b64encode(
                        b"POST /users/1 HTTP/1.1\r\nHost: fixture.test\r\n\r\na=1"
                    ).decode(),
                    "response": None,
                }
            }
        if "query ReplayEntry(" in document:
            self.replay_poll_count += 1
            return {
                "replayEntry": {
                    "id": "entry-1",
                    "error": None,
                    "request": {
                        "response": {
                            "statusCode": 200,
                            "raw": base64.b64encode(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                            ).decode(),
                        }
                    },
                }
            }
        if "query Scopes" in document:
            return {"scopes": [{"id": "scope-1", "name": "fixture", "allowlist": [], "denylist": [], "indexed": True}]}
        if "query GetSitemapRoots" in document:
            return {
                "sitemapRootEntries": {
                    "edges": [
                        {
                            "node": {
                                "id": "root-1",
                                "kind": "DOMAIN",
                                "label": "fixture.test",
                                "hasDescendants": True,
                                "metadata": {"isTls": False, "port": 80},
                                "request": {
                                    "method": "GET",
                                    "path": "/",
                                    "response": {"statusCode": 200},
                                },
                            }
                        }
                    ],
                    "count": {"value": 1},
                }
            }
        raise AssertionError(f"unexpected query: {document}")

    async def mutation(self, document: str, *, variables: dict[str, Any]) -> dict[str, Any]:
        self.mutations.append((document, variables))
        if "CreateProject" in document:
            if self.reject_project_creation:
                return {
                    "createProject": {
                        "project": None,
                        "error": {"__typename": "PermissionDeniedUserError"},
                    }
                }
            return {
                "createProject": {
                    "project": {"id": "project-1", "name": "fixture", "temporary": True},
                    "error": None,
                }
            }
        if "SelectProject" in document:
            return {
                "selectProject": {
                    "currentProject": {
                        "project": {"id": "project-1", "name": "fixture", "temporary": True}
                    },
                    "error": None,
                }
            }
        if "CreateReplaySession" in document:
            return {"createReplaySession": {"session": {"id": "session-1"}}}
        if "StartReplayTask" in document:
            return {"startReplayTask": {"error": None, "task": {"id": "task-1", "replayEntry": {"id": "entry-1"}}}}
        raise AssertionError(f"unexpected mutation: {document}")


@pytest.mark.asyncio
async def test_proxy_bootstraps_and_selects_a_temporary_project() -> None:
    client = FakeGraphQLClient()
    project = await ensure_project_with_client(client, "fixture")
    assert project == {"id": "project-1", "name": "fixture", "temporary": True}
    assert client.mutations[0][1] == {"input": {"name": "fixture", "temporary": True}}
    assert client.mutations[1][1] == {"id": "project-1"}


@pytest.mark.asyncio
async def test_proxy_reuses_current_project_for_guest_sessions() -> None:
    client = FakeGraphQLClient(reject_project_creation=True)

    async def query(document: str, *, variables: dict[str, Any]) -> dict[str, Any]:
        if "query CurrentProject" in document:
            client.queries.append((document, variables))
            return {
                "currentProject": {
                    "project": {
                        "id": "current-project",
                        "name": "aion-online",
                        "temporary": True,
                        "readOnly": False,
                    }
                }
            }
        return await FakeGraphQLClient.query(client, document, variables=variables)

    client.query = query  # type: ignore[method-assign]
    project = await ensure_project_with_client(client, "aion-next")
    assert project == {
        "id": "current-project",
        "name": "aion-online",
        "temporary": True,
    }
    assert any("query CurrentProject" in document for document, _ in client.queries)


@pytest.mark.asyncio
async def test_proxy_manager_bootstraps_project_on_lazy_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeGraphQLClient()

    async def connect(_: str, *, token: str | None) -> FakeGraphQLClient:
        assert token == "TOKEN"
        return client

    monkeypatch.setattr("tools.proxy.manager.caido_api.connect_client", connect)
    manager = CaidoProxyManager(
        base_url="http://fixture.test:48080",
        token="TOKEN",
        project_name="aion-e2e",
    )
    assert await manager.call(lambda _: _completed()) == "ok"
    assert client.mutations[0][1] == {"input": {"name": "aion-e2e", "temporary": True}}
    await manager.close()


async def _completed() -> str:
    return "ok"


def test_browser_schema_rejects_action_mismatch() -> None:
    with pytest.raises(ValidationError):
        BrowserArguments.model_validate({"action": "open"})
    with pytest.raises(ValidationError):
        BrowserArguments.model_validate(
            {"action": "interact", "interaction": "fill", "target": "@e1"}
        )
    assert BrowserArguments.model_validate(
        {"action": "wait", "wait_mode": "ms", "wait_value": "1000"}
    )


@pytest.mark.asyncio
async def test_browser_uses_agent_session_and_shell_quoting() -> None:
    shell = FakeShell(output="Page: fixture")
    manager = BrowserManager("run-1")
    client = manager.bind("agent-a", shell)  # type: ignore[arg-type]

    result = await client.dispatch(
        BrowserArguments.model_validate(
            {"action": "open", "url": "http://fixture.test/a b"}
        )
    )
    assert result["session_id"] == "aion-run-1-agent-a"
    command, options = shell.calls[-1]
    tokens = shlex.split(command)
    browser_index = tokens.index("agent-browser")
    assert tokens[browser_index:] == [
        "agent-browser",
        "--session",
        "aion-run-1-agent-a",
        "open",
        "http://fixture.test/a b",
    ]
    assert options["cwd"] == "."

    script = "document.title + ': fixture'"
    await client.dispatch(BrowserArguments.model_validate({"action": "eval", "script": script}))
    eval_argv = shlex.split(shell.calls[-1][0])
    assert base64.b64decode(eval_argv[-1]).decode() == script
    await manager.finish_agent("agent-a")
    close_tokens = shlex.split(shell.calls[-1][0])
    close_index = close_tokens.index("agent-browser")
    assert close_tokens[close_index : close_index + 3] == [
        "agent-browser",
        "--session",
        "aion-run-1-agent-a",
    ]
    assert close_tokens[close_index + 3].removesuffix(";") == "close"


@pytest.mark.asyncio
async def test_browser_missing_cli_is_reported_as_backend_error() -> None:
    shell = FakeShell(output="agent-browser: command not found", exit_code=127)
    manager = BrowserManager("run")
    client = manager.bind("agent", shell)  # type: ignore[arg-type]
    with pytest.raises(Exception) as caught:
        await client.dispatch(
            BrowserArguments.model_validate({"action": "open", "url": "http://fixture.test"})
        )
    assert getattr(caught.value, "code", None) == "browser_backend_unavailable"


def test_browser_tool_is_execution_only() -> None:
    assert "system_browser" in AgentPolicy("execution").allowed_tools
    assert "system_browser" not in AgentPolicy("chief").allowed_tools
    assert _build_argv(
        BrowserArguments.model_validate(
            {"action": "snapshot", "snapshot_include_urls": True}
        )
    )[0] == ["snapshot", "-i", "-u"]


def test_browser_file_paths_stay_in_the_agent_workspace(tmp_path: Path) -> None:
    upload = BrowserArguments.model_validate(
        {
            "action": "interact",
            "interaction": "upload",
            "target": "@e1",
            "value": "files/input.txt",
        }
    )
    assert _build_argv(upload, workspace=tmp_path)[0] == [
        "upload",
        "@e1",
        "files/input.txt",
    ]
    outside = BrowserArguments.model_validate(
        {
            "action": "interact",
            "interaction": "upload",
            "target": "@e1",
            "value": "../input.txt",
        }
    )
    with pytest.raises(SystemToolError) as caught:
        _build_argv(outside, workspace=tmp_path)
    assert caught.value.code == "browser_workspace_path_rejected"


def test_browser_tab_switch_uses_agent_browser_cli_shape() -> None:
    args = BrowserArguments.model_validate(
        {"action": "tabs", "tab_action": "switch", "tab_id": "t2"}
    )
    assert _build_argv(args)[0] == ["tab", "t2"]


def test_browser_commands_use_short_session_temp_paths() -> None:
    session = _session_name("r" * 128, "agent" * 32)
    command = _browser_shell_command(session, ["open", "http://fixture.test"])
    assert len(session) <= 48
    assert _browser_runtime_dir(session) in command
    assert "TMPDIR=/tmp/aion-ab-" in command
    assert "/tmp/aion-ab-" in command


def test_browser_runtime_settings_are_explicitly_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AION_CAIDO_PROXY_URL", "http://127.0.0.1:48080")
    monkeypatch.setenv("AION_CAIDO_NO_PROXY", "localhost,fixture.test")
    monkeypatch.setenv("AGENT_BROWSER_EXECUTABLE_PATH", "/usr/bin/chromium")
    monkeypatch.setenv("AGENT_BROWSER_ARGS", "--disable-dev-shm-usage")
    monkeypatch.setenv("AGENT_BROWSER_CA_CERT", "/etc/ssl/certs/ca.crt")
    monkeypatch.setenv("AGENT_BROWSER_IGNORE_HTTPS_ERRORS", "1")
    monkeypatch.setenv("AGENT_BROWSER_DEFAULT_TIMEOUT", "25000")
    monkeypatch.setenv("AGENT_BROWSER_CONFIG", "/outside/config.json")

    environment = _browser_proxy_environment()

    assert environment["HTTP_PROXY"] == "http://127.0.0.1:48080"
    assert environment["AGENT_BROWSER_PROXY"] == "http://127.0.0.1:48080"
    assert environment["AGENT_BROWSER_PROXY_BYPASS"] == "localhost,fixture.test"
    assert environment["NO_PROXY"] == "localhost,fixture.test"
    assert environment["AGENT_BROWSER_EXECUTABLE_PATH"] == "/usr/bin/chromium"
    assert environment["AGENT_BROWSER_ARGS"] == "--disable-dev-shm-usage"
    assert environment["AGENT_BROWSER_CA_CERT"] == "/etc/ssl/certs/ca.crt"
    assert environment["AGENT_BROWSER_IGNORE_HTTPS_ERRORS"] == "1"
    assert environment["AGENT_BROWSER_DEFAULT_TIMEOUT"] == "25000"
    assert "AGENT_BROWSER_CONFIG" not in environment


def test_proxy_schema_and_request_modifications() -> None:
    with pytest.raises(ValidationError):
        ProxyArguments.model_validate({"action": "view_request"})
    args = ProxyArguments.model_validate(
        {
            "action": "replay_request",
            "request_id": "req-1",
            "modifications": {
                "url": "https://fixture.test/users/2?old=yes",
                "params": {"old": "no", "id": 2},
                "headers": {"X-Test": "one"},
                "cookies": {"sid": "new"},
                "body": "{}",
            },
        }
    )
    raw = "POST /users/1?old=yes HTTP/1.1\r\nHost: fixture.test\r\nCookie: sid=old; theme=dark\r\nContent-Length: 3\r\n\r\na=1"
    components = parse_raw_request(raw)
    modified = apply_modifications(
        components,
        args.modifications.model_dump(exclude_unset=True),  # type: ignore[union-attr]
        full_url_from_components(
            {"host": "fixture.test", "is_tls": False},
            components,
            args.modifications.model_dump(exclude_unset=True),  # type: ignore[union-attr]
        ),
    )
    assert modified["url"] == "https://fixture.test/users/2?old=no&id=2"
    assert modified["headers"]["X-Test"] == "one"
    assert modified["headers"]["Cookie"] == "sid=new; theme=dark"
    assert modified["body"] == "{}"


def test_replay_preserves_raw_body_and_updates_cross_host_connection() -> None:
    raw = (
        b"POST http://old.fixture.test/users/1 HTTP/1.1\r\n"
        b"Host: old.fixture.test\r\n"
        b"Content-Length: 8\r\n\r\n"
        b"  a\x00b \r\n"
    )
    components = parse_raw_request(raw)
    assert components["body_bytes"] == b"  a\x00b \r\n"
    assert components["body"] == "  a\x00b \r\n"
    full_url = full_url_from_components(
        {"host": "old.fixture.test", "is_tls": False}, components, {}
    )
    assert full_url == "http://old.fixture.test/users/1"

    modified = apply_modifications(
        components,
        {"url": "https://new.fixture.test:8443/users/2"},
        "https://new.fixture.test:8443/users/2",
    )
    assert modified["headers"]["Host"] == "new.fixture.test:8443"
    connection, replay_raw = build_raw_request(
        method=modified["method"],
        url=modified["url"],
        headers=modified["headers"],
        body=modified["body"],
        body_bytes=modified["body_bytes"],
    )
    assert connection["port"] == 8443
    assert connection["SNI"] == "new.fixture.test"
    assert b"POST /users/2 HTTP/1.1\r\n" in replay_raw
    assert b"Host: new.fixture.test:8443\r\n" in replay_raw
    assert b"Connection: close\r\n" in replay_raw
    assert replay_raw.endswith(b"  a\x00b \r\n")


def test_proxy_result_formatters_keep_history_compact() -> None:
    assert format_search_hits("GET /api?id=1\nGET /api?id=2", r"id=\d+")["total_hits"] == 2
    connection = {
        "edges": [
            {
                "cursor": "cursor-1",
                "node": {
                    "request": {
                        "id": "req-1",
                        "host": "fixture.test",
                        "port": 443,
                        "method": "GET",
                        "path": "/",
                        "query": "",
                        "is_tls": True,
                        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    },
                    "response": {
                        "id": "resp-1",
                        "status_code": 200,
                        "length": 2,
                        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    },
                },
            }
        ],
        "page_info": {
            "has_next_page": False,
            "has_previous_page": False,
            "start_cursor": "cursor-1",
            "end_cursor": "cursor-1",
        },
    }
    result = format_request_connection(connection)
    assert result["entries"][0]["response"]["status_code"] == 200
    assert result["page_info"]["end_cursor"] == "cursor-1"

    graphql_connection = {
        "edges": [
            {
                "cursor": "graphql-cursor-1",
                "node": {
                    "id": "req-2",
                    "host": "fixture.test",
                    "port": 80,
                    "method": "POST",
                    "path": "/login",
                    "query": "",
                    "isTls": False,
                    "createdAt": 1,
                    "response": {"statusCode": 302, "length": 0},
                },
            }
        ],
        "pageInfo": {"endCursor": "graphql-cursor-1"},
    }
    graphql_result = format_request_connection(graphql_connection)
    assert graphql_result["entries"][0]["request"]["id"] == "req-2"
    assert graphql_result["entries"][0]["response"]["status_code"] == 302


@pytest.mark.asyncio
async def test_proxy_graphql_adapter_runs_without_caido_sdk() -> None:
    client = FakeGraphQLClient()
    connection = await list_requests_with_client(
        client,
        httpql_filter='req.method.eq:"POST"',
        first=10,
        sort_by="path",
    )
    assert connection["pageInfo"]["hasNextPage"] is False
    assert connection["pageInfo"]["hasPreviousPage"] is False
    assert client.queries[0][1]["filter"] == {"code": 'req.method.eq:"POST"'}
    assert client.queries[0][1]["order"] == {"by": "PATH", "ordering": "DESC"}

    request = await get_request_with_client(client, "req-1")
    assert request["request"]["raw"].startswith(b"POST /users/1")
    replay = await replay_request_with_client(
        client,
        "req-1",
        {"body": "a=2"},
    )
    assert replay["status"] == "DONE"
    assert replay["response_raw"].startswith(b"HTTP/1.1 200")
    assert client.replay_poll_count == 1
    replay_mutation = next(
        variables for document, variables in client.mutations if "StartReplayTask" in document
    )
    create_mutation = next(
        variables for document, variables in client.mutations if "CreateReplaySession" in document
    )
    assert create_mutation["input"]["kind"] == "HTTP"
    assert create_mutation["input"]["settings"]["http"]["connectionClose"] is True
    assert (
        create_mutation["input"]["requestSource"]["raw"]["connectionInfo"]["SNI"]
        == "fixture.test"
    )
    assert replay_mutation == {"sessionId": "session-1"}

    scopes = await scope_rules_with_client(client, "list")
    assert scopes[0]["id"] == "scope-1"
    sitemap = await list_sitemap_with_client(client)
    assert sitemap["entries"][0]["id"] == "root-1"


@pytest.mark.asyncio
async def test_direct_graphql_client_parses_http_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []
    real_async_client = httpx.AsyncClient

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"data": {"fixture": {"id": "req-1"}}})

    def make_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("tools.proxy.caido_api.httpx.AsyncClient", make_client)
    client = CaidoGraphQLClient("http://fixture.test", "TOKEN")
    try:
        result = await client.query(
            "query Fixture($id: ID!) { fixture(id: $id) { id } }",
            variables={"id": "req-1"},
        )
    finally:
        await client.aclose()
    assert result == {"fixture": {"id": "req-1"}}
    assert requests[0].headers["Authorization"] == "Bearer TOKEN"
    assert json.loads(requests[0].content)["variables"] == {"id": "req-1"}


@pytest.mark.asyncio
async def test_proxy_manager_serializes_shared_client_calls_and_closes() -> None:
    client = FakeCaidoClient()
    manager = CaidoProxyManager(client=client)
    active = 0
    peak = 0

    async def operation(_: Any) -> str:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return "ok"

    assert await asyncio.gather(manager.call(operation), manager.call(operation)) == ["ok", "ok"]
    assert peak == 1
    await manager.close()
    assert client.closed is True


@pytest.mark.asyncio
async def test_proxy_tool_definition_is_role_scoped() -> None:
    manager = CaidoProxyManager(client=FakeCaidoClient())
    provider = ProxyTools(manager)
    registry = ToolRegistry(
        [provider], allowed_tools=AgentPolicy("execution").allowed_tools
    )
    assert registry.has_tool("system_proxy")
    assert not ToolRegistry(
        [provider], allowed_tools=AgentPolicy("challenge").allowed_tools
    ).has_tool("system_proxy")
    await manager.close()
