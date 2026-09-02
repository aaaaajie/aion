"""Small, lazy Caido GraphQL adapter extracted from Strix's proxy toolbox."""

from __future__ import annotations

import dataclasses
import asyncio
import base64
import binascii
import os
import re
import time
from dataclasses import is_dataclass
from datetime import datetime, timezone
from typing import Any, Literal, TypeVar
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx


RequestPart = Literal["request", "response"]
SortBy = Literal[
    "timestamp",
    "host",
    "method",
    "path",
    "status_code",
    "response_time",
    "response_size",
    "source",
]
SortOrder = Literal["asc", "desc"]
ScopeAction = Literal["get", "list", "create", "update", "delete"]
SitemapDepth = Literal["DIRECT", "ALL"]

_DEFAULT_CAIDO_URL = "http://127.0.0.1:48080"
_SITEMAP_PAGE_SIZE = 30
_RESPONSE_BODY_MAX_CHARS = 8_192
_FRAMING_HEADERS = frozenset({"content-length", "transfer-encoding"})
T = TypeVar("T")

_REQ_FIELD_MAP: dict[SortBy, tuple[str, str]] = {
    "timestamp": ("req", "created_at"),
    "host": ("req", "host"),
    "method": ("req", "method"),
    "path": ("req", "path"),
    "source": ("req", "source"),
    "status_code": ("resp", "code"),
    "response_time": ("resp", "roundtrip"),
    "response_size": ("resp", "length"),
}


class CaidoGraphQLError(RuntimeError):
    """Raised when Caido returns a GraphQL or transport error."""


class CaidoGraphQLClient:
    """Minimal async GraphQL client for the Python 3.11 Bootstrap runtime.

    The upstream Caido SDK currently requires Python 3.12.  Keeping this
    adapter on the already-installed ``httpx`` dependency preserves the
    existing runtime contract while retaining the SDK-compatible GraphQL
    operations used by Strix.
    """

    def __init__(self, base_url: str, token: str) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Caido URL must use http or https")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=30.0,
            trust_env=False,
        )
        # Keep the shape consumed by the sitemap adapter.
        self.graphql = self

    async def query(
        self,
        document: str,
        *,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self._http.post(
            "/graphql",
            json={"query": document, "variables": variables or {}},
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise CaidoGraphQLError("Caido returned a non-JSON response") from exc
        if response.is_error:
            raise CaidoGraphQLError(f"Caido GraphQL HTTP status {response.status_code}")
        if not isinstance(payload, dict):
            raise CaidoGraphQLError("Caido GraphQL response is not an object")
        errors = payload.get("errors")
        if errors:
            raise CaidoGraphQLError("Caido GraphQL operation returned errors")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise CaidoGraphQLError("Caido GraphQL response has no data object")
        return data

    async def mutation(
        self,
        document: str,
        *,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self.query(document, variables=variables)

    async def aclose(self) -> None:
        await self._http.aclose()


_CREATE_PROJECT_MUTATION = """
mutation CreateProject($input: CreateProjectInput!) {
    createProject(input: $input) {
        project { id name temporary }
        error { __typename }
    }
}
"""

_SELECT_PROJECT_MUTATION = """
mutation SelectProject($id: ID!) {
    selectProject(id: $id) {
        currentProject { project { id name temporary } }
        error { __typename }
    }
}
"""

_CURRENT_PROJECT_QUERY = """
query CurrentProject {
    currentProject { project { id name temporary readOnly } }
}
"""


async def ensure_project_with_client(client: Any, name: str) -> dict[str, Any]:
    """Create a run project, or reuse Caido's current guest project."""

    if not name or len(name) > 256:
        raise ValueError("Caido project name must be non-empty and at most 256 characters")
    try:
        created = await _graphql_mutation(
            client,
            _CREATE_PROJECT_MUTATION,
            variables={"input": {"name": name, "temporary": True}},
        )
    except CaidoGraphQLError:
        existing = await _current_project_with_client(client)
        if existing is not None:
            return existing
        raise
    payload = created.get("createProject") or {}
    if payload.get("error"):
        existing = await _current_project_with_client(client)
        if existing is not None:
            return existing
        raise CaidoGraphQLError("Caido rejected temporary project creation")
    project = payload.get("project") or {}
    project_id = _value(project, "id")
    if not project_id:
        existing = await _current_project_with_client(client)
        if existing is not None:
            return existing
        raise CaidoGraphQLError("Caido did not return the temporary project")

    selected = await _graphql_mutation(
        client,
        _SELECT_PROJECT_MUTATION,
        variables={"id": str(project_id)},
    )
    select_payload = selected.get("selectProject") or {}
    if select_payload.get("error"):
        existing = await _current_project_with_client(client)
        if existing is not None:
            return existing
        raise CaidoGraphQLError("Caido rejected temporary project selection")
    current = select_payload.get("currentProject") or {}
    current_project = current.get("project") or {}
    if str(_value(current_project, "id")) != str(project_id):
        existing = await _current_project_with_client(client)
        if existing is not None:
            return existing
        raise CaidoGraphQLError("Caido did not select the temporary project")
    return {
        "id": str(project_id),
        "name": _value(project, "name", default=name),
        "temporary": _value(project, "temporary", default=True),
    }


async def _current_project_with_client(client: Any) -> dict[str, Any] | None:
    try:
        result = await _graphql_query(client, _CURRENT_PROJECT_QUERY)
    except Exception:
        return None
    payload = result.get("currentProject") or {}
    project = payload.get("project") or {}
    project_id = _value(project, "id")
    if not project_id or _value(project, "read_only", "readOnly", default=False):
        return None
    return {
        "id": str(project_id),
        "name": _value(project, "name", default="current"),
        "temporary": _value(project, "temporary", default=True),
    }


def caido_url() -> str:
    return (
        os.environ.get("AION_CAIDO_URL")
        or os.environ.get("STRIX_CAIDO_URL")
        or _DEFAULT_CAIDO_URL
    ).rstrip("/")


async def connect_client(base_url: str, *, token: str | None = None) -> Any:
    """Connect lazily without adding a Python version constraint to AION."""

    if token is not None:
        token = token.strip()
    if not token:
        token = await _login_as_guest(base_url)
    return CaidoGraphQLClient(base_url, token)


async def _login_as_guest(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Caido URL must use http or https")
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/graphql",
            json={"query": "mutation { loginAsGuest { token { accessToken } } }"},
        )
        response.raise_for_status()
        payload = response.json()
    try:
        value = payload["data"]["loginAsGuest"]["token"]["accessToken"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("Caido guest login did not return an access token") from exc
    return str(value)


_REQUEST_LIST_QUERY = """
query Requests(
    $first: Int
    $after: String
    $filter: HTTPQLInput
    $order: RequestResponseOrderInput
    $scopeId: ID
) {
    requests(
        first: $first
        after: $after
        filter: $filter
        order: $order
        scopeId: $scopeId
    ) {
        edges {
            cursor
            node {
                id host port method path query isTls createdAt
                response { id statusCode roundtripTime length createdAt }
            }
        }
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
    }
}
"""

_REQUEST_GET_QUERY = """
query Request($id: ID!) {
    request(id: $id) {
        id host port method path query isTls createdAt
        metadata { id color }
        raw
        response { id statusCode roundtripTime length createdAt raw }
    }
}
"""

_REQUEST_ORDER_BY: dict[SortBy, str] = {
    "timestamp": "CREATED_AT",
    "host": "HOST",
    "method": "METHOD",
    "path": "PATH",
    "status_code": "RESP_STATUS_CODE",
    "response_time": "RESP_ROUNDTRIP_TIME",
    "response_size": "RESP_LENGTH",
    "source": "SOURCE",
}


async def _graphql_query(
    client: Any,
    document: str,
    *,
    variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    graphql = getattr(client, "graphql", client)
    query = getattr(graphql, "query", None)
    if query is None:
        raise TypeError("Caido client does not expose a GraphQL query method")
    return await query(document, variables=variables or {})


async def _graphql_mutation(
    client: Any,
    document: str,
    *,
    variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    mutation = getattr(client, "mutation", None)
    if mutation is None:
        graphql = getattr(client, "graphql", None)
        mutation = getattr(graphql, "mutation", None) if graphql is not None else None
    if mutation is None:
        return await _graphql_query(client, document, variables=variables)
    return await mutation(document, variables=variables or {})


def _is_sdk_client(client: Any) -> bool:
    return hasattr(client, "request") and hasattr(client, "scope")


async def list_requests_with_client(
    client: Any,
    *,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> Any:
    if not _is_sdk_client(client):
        raw = await _graphql_query(
            client,
            _REQUEST_LIST_QUERY,
            variables={
                "first": first,
                "after": after,
                "filter": {"code": httpql_filter} if httpql_filter else None,
                "order": {
                    "by": _REQUEST_ORDER_BY[sort_by],
                    "ordering": "DESC" if sort_order == "desc" else "ASC",
                },
                "scopeId": scope_id,
            },
        )
        return raw.get("requests") or {"edges": [], "pageInfo": {}}

    builder = client.request.list().first(first)
    if httpql_filter:
        builder = builder.filter(httpql_filter)
    if after:
        builder = builder.after(after)
    if scope_id:
        builder = builder.scope(scope_id)
    target, field = _REQ_FIELD_MAP[sort_by]
    builder = (
        builder.descending if sort_order == "desc" else builder.ascending
    )(target, field)
    return await builder.execute()


async def get_request_with_client(client: Any, request_id: str, *, part: RequestPart = "request") -> Any:
    if not _is_sdk_client(client):
        raw = await _graphql_query(
            client,
            _REQUEST_GET_QUERY,
            variables={"id": request_id},
        )
        node = raw.get("request")
        if not isinstance(node, dict):
            return None
        request = dict(node)
        request["raw"] = _decode_raw(request.get("raw"))
        response = request.get("response")
        if isinstance(response, dict):
            response = dict(response)
            response["raw"] = _decode_raw(response.get("raw"))
            request["response"] = response
        return {"request": request, "response": response}

    del part  # The SDK query must request both raw fields; callers select one below.
    try:
        from caido_sdk_client.types import RequestGetOptions
    except ModuleNotFoundError:
        return await client.request.get(
            request_id,
            {"request_raw": True, "response_raw": True},
        )
    return await client.request.get(
        request_id,
        RequestGetOptions(request_raw=True, response_raw=True),
    )


def format_request_connection(connection: Any) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for edge in _value(connection, "edges", []) or []:
        node = _value(edge, "node", {})
        # The SDK exposes ``edge.node.request`` while the direct GraphQL
        # fallback queries the request fields directly on ``edge.node``.
        request = _value(node, "request", default=node)
        response = _value(node, "response")
        response_payload = None
        if response is not None:
            response_payload = {
                "id": _string(_value(response, "id")),
                "status_code": _value(response, "status_code", "statusCode"),
                "length": _value(response, "length"),
                "created_at": _iso(_value(response, "created_at", "createdAt")),
            }
            roundtrip = _value(response, "roundtrip_time", "roundtripTime")
            if roundtrip:
                response_payload["roundtrip_ms"] = roundtrip
        entries.append(
            {
                "cursor": _string(_value(edge, "cursor")),
                "request": {
                    "id": _string(_value(request, "id")),
                    "host": _value(request, "host"),
                    "port": _value(request, "port"),
                    "method": _value(request, "method"),
                    "path": _value(request, "path"),
                    "query": _value(request, "query"),
                    "is_tls": _value(request, "is_tls", "isTls"),
                    "created_at": _iso(_value(request, "created_at", "createdAt")),
                },
                "response": response_payload,
            }
        )
    page_info = _value(connection, "page_info", "pageInfo") or {}
    return {
        "success": True,
        "entries": entries,
        "page_info": {
            "has_next_page": _value(page_info, "has_next_page", "hasNextPage"),
            "has_previous_page": _value(page_info, "has_previous_page", "hasPreviousPage"),
            "start_cursor": _string(_value(page_info, "start_cursor", "startCursor")),
            "end_cursor": _string(_value(page_info, "end_cursor", "endCursor")),
        },
    }


def parse_raw_request(raw_content: str | bytes) -> dict[str, Any]:
    """Split a captured request without normalizing its body bytes."""

    raw_bytes = (
        raw_content.encode("utf-8")
        if isinstance(raw_content, str)
        else bytes(raw_content)
    )
    head, separator, body_bytes = raw_bytes.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body_bytes = raw_bytes.partition(b"\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("captured request is empty")
    request_line = lines[0].decode("iso-8859-1", errors="replace").strip().split(" ", 2)
    if len(request_line) < 2:
        raise ValueError("captured request line is invalid")
    headers: dict[str, str] = {}
    for line_bytes in lines[1:]:
        line = line_bytes.decode("iso-8859-1", errors="replace")
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return {
        "method": request_line[0],
        "url_path": request_line[1],
        "headers": headers,
        "body": body_bytes.decode("utf-8", errors="replace"),
        "body_bytes": body_bytes,
    }


def full_url_from_components(original: Any, components: dict[str, Any], modifications: dict[str, Any]) -> str:
    if modifications.get("url") is not None:
        return str(modifications["url"])
    url_path = str(components["url_path"])
    if url_path.lower().startswith(("http://", "https://")):
        return url_path
    headers = components["headers"]
    host_header = next(
        (value for key, value in headers.items() if key.lower() == "host"),
        _value(original, "host", default=""),
    )
    scheme = "https" if _value(original, "is_tls", "isTls") else "http"
    return f"{scheme}://{host_header}{url_path}"


def apply_modifications(
    components: dict[str, Any],
    modifications: dict[str, Any],
    full_url: str,
) -> dict[str, Any]:
    headers = dict(components["headers"])
    body = components["body"]
    body_bytes = components.get("body_bytes")
    if body_bytes is None:
        body_bytes = body.encode("utf-8")
    final_url = full_url
    params = modifications.get("params")
    if params is not None:
        parsed = urlparse(final_url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        existing = dict(query)
        existing.update({str(key): value for key, value in params.items()})
        final_url = urlunparse(parsed._replace(query=urlencode(existing, doseq=True)))
    header_modifications = modifications.get("headers")
    if header_modifications is not None:
        headers.update(header_modifications)
    if modifications.get("url") is not None and not any(
        str(key).lower() == "host" for key in (header_modifications or {})
    ):
        parsed_url = urlparse(final_url)
        if parsed_url.netloc:
            host_key = next((key for key in headers if key.lower() == "host"), "Host")
            headers[host_key] = parsed_url.netloc
    if modifications.get("body") is not None:
        body = str(modifications["body"])
        body_bytes = body.encode("utf-8")
    cookies = modifications.get("cookies")
    if cookies is not None:
        cookie_key = next((key for key in headers if key.lower() == "cookie"), "Cookie")
        parsed_cookies: dict[str, str] = {}
        for cookie in headers.get(cookie_key, "").split(";"):
            if "=" in cookie:
                key, value = cookie.split("=", 1)
                parsed_cookies[key.strip()] = value.strip()
        parsed_cookies.update({str(key): str(value) for key, value in cookies.items()})
        headers[cookie_key] = "; ".join(f"{key}={value}" for key, value in parsed_cookies.items())
    return {
        "method": components["method"],
        "url": final_url,
        "headers": headers,
        "body": body,
        "body_bytes": body_bytes,
    }


def build_raw_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
    body_bytes: bytes | None = None,
) -> tuple[Any, bytes]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"replay URL is invalid: {url}")
    is_tls = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    final_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in _FRAMING_HEADERS
    }
    final_headers.setdefault("Host", parsed.netloc)
    final_headers["Connection"] = "close"
    final_headers.setdefault(
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    )
    if body_bytes is None:
        body_bytes = body.encode("utf-8")
    if body_bytes:
        final_headers["Content-Length"] = str(len(body_bytes))
    raw = (
        "\r\n".join(
            [f"{method.upper()} {path} HTTP/1.1"]
            + [f"{key}: {value}" for key, value in final_headers.items()]
        ).encode("iso-8859-1", errors="replace")
        + b"\r\n\r\n"
        + body_bytes
    )
    connection: Any = {
        "host": host,
        "port": port,
        "isTLS": is_tls,
        "SNI": host,
    }
    try:
        from caido_sdk_client.types import ConnectionInfoInput
    except ModuleNotFoundError:
        pass
    else:
        for candidate in (
            {"host": host, "port": port, "is_tls": is_tls, "sni": host},
            {"host": host, "port": port, "is_tls": is_tls, "SNI": host},
            {"host": host, "port": port, "is_tls": is_tls},
        ):
            try:
                connection = ConnectionInfoInput(**candidate)
                break
            except (TypeError, ValueError):
                continue
    return connection, raw


_CREATE_REPLAY_SESSION_MUTATION = """
mutation CreateReplaySession($input: CreateReplaySessionInput!) {
    createReplaySession(input: $input) {
        error { __typename }
        session { id }
    }
}
"""

_START_REPLAY_TASK_MUTATION = """
mutation StartReplayTask($sessionId: ID!) {
    startReplayTask(sessionId: $sessionId) {
        error { __typename }
        task { id replayEntry { id } }
    }
}
"""

_REPLAY_ENTRY_QUERY = """
query ReplayEntry($id: ID!, $sessionKind: ReplaySessionKind!) {
    replayEntry(id: $id, sessionKind: $sessionKind) {
        id
        error
        ... on ReplayEntryHttp {
            request {
                response { id statusCode roundtripTime length createdAt raw }
            }
        }
    }
}
"""


def _connection_input(connection: Any) -> dict[str, Any]:
    return {
        "host": _value(connection, "host", default=""),
        "port": _value(connection, "port", default=80),
        "isTLS": _value(connection, "is_tls", "isTLS", default=False),
        "SNI": _value(connection, "sni", "SNI"),
    }


async def replay_request_with_client(client: Any, request_id: str, modifications: dict[str, Any]) -> dict[str, Any]:
    result = await get_request_with_client(client, request_id, part="request")
    request = _value(result, "request") if result is not None else None
    raw = _value(request, "raw") if request is not None else None
    if raw is None:
        raise ValueError(f"captured request {request_id} was not found")
    raw_content = raw if isinstance(raw, (str, bytes, bytearray)) else str(raw)
    components = parse_raw_request(raw_content)
    full_url = full_url_from_components(request, components, modifications)
    modified = apply_modifications(components, modifications, full_url)
    connection, raw_request = build_raw_request(
        method=modified["method"],
        url=modified["url"],
        headers=modified["headers"],
        body=modified["body"],
        body_bytes=modified.get("body_bytes"),
    )
    return await replay_send_raw(client, raw=raw_request, connection=connection)


async def replay_send_raw(client: Any, *, raw: bytes, connection: Any) -> dict[str, Any]:
    if _is_sdk_client(client):
        try:
            from caido_sdk_client.types import ReplaySendOptions
        except ModuleNotFoundError as exc:
            raise RuntimeError("Caido SDK replay support is not installed") from exc
        started = time.time()
        session = await client.replay.sessions.create()
        try:
            result = await asyncio.wait_for(
                client.replay.send(
                    session.id,
                    ReplaySendOptions(raw=raw, connection=connection),
                ),
                timeout=30.0,
            )
        except TimeoutError:
            return {
                "session_id": _string(session.id),
                "status": "ERROR",
                "error": "Caido replay dispatch timed out",
                "elapsed_ms": int((time.time() - started) * 1_000),
                "response_raw": None,
            }
        response = _value(_value(result, "entry"), "response")
        return {
            "session_id": _string(session.id),
            "status": _string(_value(result, "status")),
            "error": _value(result, "error"),
            "elapsed_ms": int((time.time() - started) * 1_000),
            "response_raw": _value(response, "raw") if response is not None else None,
        }

    create_result = await _graphql_mutation(
        client,
        _CREATE_REPLAY_SESSION_MUTATION,
        variables={
            "input": {
                "kind": "HTTP",
                "requestSource": {
                    "raw": {
                        "connectionInfo": _connection_input(connection),
                        "raw": base64.b64encode(raw).decode("ascii"),
                    }
                },
                "settings": {
                    "http": {
                        "connectionClose": True,
                        "updateContentLength": True,
                    }
                },
            }
        },
    )
    session = create_result.get("createReplaySession") or {}
    if session.get("error"):
        raise CaidoGraphQLError("Caido rejected the replay session")
    session_id = _value(_value(session, "session"), "id")
    if not session_id:
        raise CaidoGraphQLError("Caido did not create a replay session")

    start_result = await _graphql_mutation(
        client,
        _START_REPLAY_TASK_MUTATION,
        variables={"sessionId": str(session_id)},
    )
    task_payload = start_result.get("startReplayTask") or {}
    if task_payload.get("error"):
        raise CaidoGraphQLError("Caido rejected the replay task")
    task = task_payload.get("task") or {}
    entry_id = _value(_value(task, "replayEntry", "replay_entry"), "id")
    if not entry_id:
        raise CaidoGraphQLError("Caido replay task did not return an entry")

    started = time.time()
    deadline = started + 30.0
    while True:
        result = await _graphql_query(
            client,
            _REPLAY_ENTRY_QUERY,
            variables={"id": str(entry_id), "sessionKind": "HTTP"},
        )
        entry = result.get("replayEntry") or {}
        request = entry.get("request") or {}
        response = request.get("response")
        if response is not None or entry.get("error"):
            return {
                "session_id": str(session_id),
                "status": "ERROR" if entry.get("error") else "DONE",
                "error": entry.get("error"),
                "elapsed_ms": int((time.time() - started) * 1_000),
                "response_raw": _decode_raw(
                    response.get("raw") if isinstance(response, dict) else None
                ),
            }
        if time.time() >= deadline:
            return {
                "session_id": str(session_id),
                "status": "ERROR",
                "error": "Caido replay dispatch timed out",
                "elapsed_ms": int((time.time() - started) * 1_000),
                "response_raw": None,
            }
        await asyncio.sleep(0.25)


def parse_raw_response(raw_bytes: bytes | str | None) -> dict[str, Any] | None:
    if not raw_bytes:
        return None
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8")
    try:
        head, _, body_bytes = raw_bytes.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            return None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        body = body_bytes.decode("utf-8", errors="replace")
        truncated = len(body) > _RESPONSE_BODY_MAX_CHARS
        return {
            "status_code": int(status_parts[1]),
            "length": len(body_bytes),
            "headers": headers,
            "body": body[:_RESPONSE_BODY_MAX_CHARS],
            "body_truncated": truncated,
        }
    except Exception:
        return None


def format_replay_result(replay: dict[str, Any]) -> dict[str, Any]:
    status = _string(replay.get("status"))
    payload: dict[str, Any] = {
        "success": status == "DONE",
        "status": status,
        "session_id": _string(replay.get("session_id")),
        "elapsed_ms": replay.get("elapsed_ms"),
        "response": parse_raw_response(replay.get("response_raw")),
    }
    if replay.get("error"):
        payload["error"] = _to_json(replay["error"])
    return payload


_SCOPES_QUERY = """
query Scopes {
    scopes { id name allowlist denylist indexed }
}
"""

_SCOPE_QUERY = """
query Scope($id: ID!) {
    scope(id: $id) { id name allowlist denylist indexed }
}
"""

_CREATE_SCOPE_MUTATION = """
mutation CreateScope($input: CreateScopeInput!) {
    createScope(input: $input) {
        error { __typename }
        scope { id name allowlist denylist indexed }
    }
}
"""

_UPDATE_SCOPE_MUTATION = """
mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
    updateScope(id: $id, input: $input) {
        error { __typename }
        scope { id name allowlist denylist indexed }
    }
}
"""

_DELETE_SCOPE_MUTATION = """
mutation DeleteScope($id: ID!) {
    deleteScope(id: $id) { deletedId }
}
"""


async def scope_rules_with_client(
    client: Any,
    action: ScopeAction,
    *,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> Any:
    if not _is_sdk_client(client):
        if action == "list":
            result = await _graphql_query(client, _SCOPES_QUERY)
            return result.get("scopes") or []
        if action == "get":
            result = await _graphql_query(
                client,
                _SCOPE_QUERY,
                variables={"id": scope_id},
            )
            return result.get("scope")
        if action == "delete":
            await _graphql_mutation(
                client,
                _DELETE_SCOPE_MUTATION,
                variables={"id": scope_id},
            )
            return {"deleted": scope_id}
        variables = {
            "input": {
                "name": scope_name,
                "allowlist": list(allowlist or []),
                "denylist": list(denylist or []),
            }
        }
        if action == "create":
            result = await _graphql_mutation(
                client,
                _CREATE_SCOPE_MUTATION,
                variables=variables,
            )
            payload = result.get("createScope") or {}
        else:
            variables["id"] = scope_id
            result = await _graphql_mutation(
                client,
                _UPDATE_SCOPE_MUTATION,
                variables=variables,
            )
            payload = result.get("updateScope") or {}
        if payload.get("error"):
            raise CaidoGraphQLError("Caido rejected the scope operation")
        return payload.get("scope")

    if action == "list":
        return _to_json(await client.scope.list())
    if action == "get":
        return _to_json(await client.scope.get(scope_id))
    if action == "delete":
        await client.scope.delete(scope_id)
        return {"deleted": scope_id}
    try:
        from caido_sdk_client.types import CreateScopeOptions, UpdateScopeOptions
    except ModuleNotFoundError as exc:
        raise RuntimeError("caido-sdk-client is not installed") from exc
    options = {"name": scope_name, "allowlist": list(allowlist or []), "denylist": list(denylist or [])}
    if action == "create":
        return _to_json(await client.scope.create(CreateScopeOptions(**options)))
    return _to_json(await client.scope.update(scope_id, UpdateScopeOptions(**options)))


_SITEMAP_ROOTS_QUERY = """
query GetSitemapRoots($scopeId: ID) {
    sitemapRootEntries(scopeId: $scopeId) {
        edges { node {
            id kind label hasDescendants
            metadata { ... on SitemapEntryMetadataDomain { isTls port } }
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
"""
_SITEMAP_DESCENDANTS_QUERY = """
query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
    sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
        edges { node {
            id kind label hasDescendants
            request { method path response { statusCode } }
        } }
        count { value }
    }
}
"""
_SITEMAP_ENTRY_QUERY = """
query GetSitemapEntry($id: ID!) {
    sitemapEntry(id: $id) {
        id kind label hasDescendants
        metadata { ... on SitemapEntryMetadataDomain { isTls port } }
        request { method path response { statusCode length roundtripTime } }
        requests(first: 30, order: {by: CREATED_AT, ordering: DESC}) {
            edges { node { method path response { statusCode length } } }
            count { value }
        }
    }
}
"""


async def list_sitemap_with_client(
    client: Any,
    *,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
    page_size: int = _SITEMAP_PAGE_SIZE,
) -> dict[str, Any]:
    if parent_id:
        raw = await _graphql_query(
            client,
            _SITEMAP_DESCENDANTS_QUERY,
            variables={"parentId": parent_id, "depth": depth},
        )
        data = raw.get("sitemapDescendantEntries") or {}
    else:
        raw = await _graphql_query(
            client,
            _SITEMAP_ROOTS_QUERY,
            variables={"scopeId": scope_id},
        )
        data = raw.get("sitemapRootEntries") or {}
    edges = data.get("edges") or []
    total = (data.get("count") or {}).get("value", 0)
    start = max(0, (page - 1) * page_size)
    entries = [_clean_sitemap_entry(edge["node"]) for edge in edges[start : start + page_size]]
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        "success": True,
        "entries": entries,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_count": total,
        "has_more": page < total_pages,
    }


async def view_sitemap_entry_with_client(client: Any, entry_id: str) -> dict[str, Any]:
    raw = await _graphql_query(client, _SITEMAP_ENTRY_QUERY, variables={"id": entry_id})
    entry = raw.get("sitemapEntry")
    if not entry:
        return {"success": False, "error": f"Sitemap entry {entry_id} not found"}
    cleaned = _clean_sitemap_entry(entry)
    related = entry.get("requests") or {}
    cleaned["related_requests"] = {
        "requests": [
            summary
            for summary in (_request_summary(edge.get("node")) for edge in related.get("edges") or [])
            if summary is not None
        ],
        "total_count": (related.get("count") or {}).get("value", 0),
    }
    return {"success": True, "entry": cleaned}


def _clean_sitemap_entry(node: dict[str, Any]) -> dict[str, Any]:
    result = {
        "id": node.get("id"),
        "kind": node.get("kind"),
        "label": node.get("label"),
        "has_descendants": node.get("hasDescendants"),
    }
    metadata = node.get("metadata")
    if isinstance(metadata, dict):
        result["metadata"] = {
            key: metadata[key]
            for key in ("isTls", "port")
            if key in metadata and metadata[key] is not None
        }
    request = _request_summary(node.get("request"))
    if request:
        result["request"] = request
    return result


def _request_summary(request: dict[str, Any] | None) -> dict[str, Any] | None:
    if not request:
        return None
    result: dict[str, Any] = {}
    if request.get("method"):
        result["method"] = request["method"]
    if request.get("path"):
        result["path"] = request["path"]
    response = request.get("response") or {}
    if response.get("statusCode"):
        result["status_code"] = response["statusCode"]
    return result or None


def _value(value: Any, *names: str, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
        return default
    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return default


def _string(value: Any) -> str | None:
    return None if value is None else str(getattr(value, "value", value))


def _decode_raw(value: Any) -> Any:
    if value is None or isinstance(value, (bytes, bytearray)):
        return bytes(value) if isinstance(value, bytearray) else value
    if not isinstance(value, str):
        return value
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return value


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1_000, tz=timezone.utc).isoformat()
    return str(value)


def _to_json(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _to_json(item) for key, item in dataclasses.asdict(value).items()}
    if hasattr(value, "model_dump"):
        return _to_json(value.model_dump())
    if isinstance(value, dict):
        return {str(key): _to_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_json(item) for item in value]
    return str(value)


def format_search_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"invalid regex: {exc}"}
    hits: list[dict[str, Any]] = []
    for match in regex.finditer(content):
        start, end = match.span()
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": content[max(0, start - 40) : start],
                "after": content[end : end + 40],
            }
        )
        if len(hits) >= 20:
            break
    return {"success": True, "hits": hits, "total_hits": len(hits)}


def format_text_page(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }
