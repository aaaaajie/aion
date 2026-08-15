"""Business-neutral HTTP request construction, execution, and analysis."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import json
import os
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookiejar import Cookie
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit

import httpx

from tools.system.policy import SystemToolError, WorkspacePolicy

from .models import HttpProbeCase, HttpRequestSpec, HttpVariableSource


MAX_HTTP_PROBE_REQUESTS = 5_000


@dataclass(frozen=True)
class ExpandedRequest:
    request_id: str
    ordinal: int
    spec: HttpRequestSpec
    variables: dict[str, Any]
    request_group_id: str


class _HtmlFeatures(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []
        self.title_chars = 0
        self.forms: list[dict[str, Any]] = []
        self.inputs: list[str] = []
        self.form_count = 0
        self.input_count = 0
        self.links = 0
        self.scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self.form_count += 1
            if len(self.forms) < 100:
                self.forms.append(
                    {
                        "method": (values.get("method") or "GET").upper(),
                        "action": values.get("action"),
                    }
                )
        elif tag == "input" and values.get("name"):
            self.input_count += 1
            if len(self.inputs) < 100:
                self.inputs.append(str(values["name"]))
        elif tag == "a":
            self.links += 1
        elif tag == "script":
            self.scripts += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and self.title_chars < 1024:
            value = data[: 1024 - self.title_chars]
            self.title_parts.append(value)
            self.title_chars += len(value)

    @property
    def title(self) -> str | None:
        value = " ".join(" ".join(self.title_parts).split())
        return value or None


class HttpInteractionEngine:
    """Expand generic request templates and execute them without business logic."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.policy = policy
        self.transport = transport
        self._clients: dict[tuple[bool, str | None], httpx.AsyncClient] = {}
        self._clients_lock = asyncio.Lock()
        self._network_request_count = 0
        self._connection_ids: set[int] = set()
        self._connection_reuse_count = 0

    @property
    def connection_stats(self) -> dict[str, int]:
        return {
            "pool_count": len(self._clients),
            "network_requests": self._network_request_count,
            "observed_connections": len(self._connection_ids),
            "connection_reuses": self._connection_reuse_count,
        }

    async def aclose(self) -> None:
        """Close the Run-scoped connection pools."""

        async with self._clients_lock:
            clients = list(self._clients.values())
            self._clients.clear()
        if clients:
            await asyncio.gather(
                *(client.aclose() for client in clients),
                return_exceptions=True,
            )

    async def _client_for(self, spec: HttpRequestSpec) -> httpx.AsyncClient:
        key = (spec.verify_tls, spec.proxy)
        client = self._clients.get(key)
        if client is not None:
            return client
        async with self._clients_lock:
            client = self._clients.get(key)
            if client is None:
                client = httpx.AsyncClient(
                    verify=spec.verify_tls,
                    proxy=spec.proxy,
                    transport=self.transport,
                    trust_env=spec.proxy is None,
                    limits=httpx.Limits(
                        max_connections=64,
                        max_keepalive_connections=32,
                        keepalive_expiry=30.0,
                    ),
                )
                self._clients[key] = client
            return client

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        request: httpx.Request,
        *,
        auth: httpx.Auth | tuple[str, str] | None,
        follow_redirects: bool,
        cookies: httpx.Cookies,
    ) -> tuple[httpx.Response, httpx.Cookies]:
        """Send with a request-local cookie jar while reusing the connection pool."""

        response = await client.send(
            request,
            stream=True,
            auth=auth,
            follow_redirects=False,
        )
        self._record_connection(response)
        redirects = 0
        while True:
            cookies.extract_cookies(response)
            next_request = response.next_request if follow_redirects else None
            if next_request is None:
                client.cookies.clear()
                return response, cookies
            redirects += 1
            if redirects > 20:
                await response.aclose()
                client.cookies.clear()
                raise httpx.TooManyRedirects(
                    "Exceeded maximum allowed redirects", request=request
                )
            # httpx constructs a standards-compliant replay request. Replace
            # its Client cookie jar with the interaction-local jar before use.
            next_request.headers.pop("cookie", None)
            cookies.set_cookie_header(next_request)
            await response.aread()
            await response.aclose()
            response = await client.send(
                next_request,
                stream=True,
                auth=None,
                follow_redirects=False,
            )
            self._record_connection(response)

    def _record_connection(self, response: httpx.Response) -> None:
        self._network_request_count += 1
        stream = response.extensions.get("network_stream")
        if stream is None:
            return
        connection_id = id(stream)
        if connection_id in self._connection_ids:
            self._connection_reuse_count += 1
        else:
            self._connection_ids.add(connection_id)

    def expand_cases(
        self,
        cases: list[HttpProbeCase],
        *,
        id_factory: Any,
        default_group_id: str,
    ) -> list[ExpandedRequest]:
        expanded: list[ExpandedRequest] = []
        ordinal = 0
        for case_index, case in enumerate(cases):
            names = list(case.variables)
            self._preflight_template(case, declared_names=set(names))
            sources = [self._source_values(case.variables[name]) for name in names]
            if case.combine == "zip":
                lengths = {len(values) for values in sources}
                if len(lengths) > 1:
                    raise self._validation(
                        "zip_length_mismatch",
                        "All zip variable sources must contain the same number of values",
                    )
                combination_count = next(iter(lengths), 1)
                combinations = zip(*sources, strict=True) if sources else [()]
            else:
                combination_count = 1
                for values in sources:
                    combination_count *= len(values)
                    if combination_count > MAX_HTTP_PROBE_REQUESTS:
                        break
                combinations = itertools.product(*sources) if sources else [()]
            if len(expanded) + combination_count > MAX_HTTP_PROBE_REQUESTS:
                raise self._validation(
                    "http_probe_too_large",
                    f"HTTP probe expands beyond {MAX_HTTP_PROBE_REQUESTS} requests",
                )
            group_id = case.request.request_group_id or f"{default_group_id}-case-{case_index}"
            for combination in combinations:
                bindings = dict(zip(names, combination, strict=True))
                ordinal += 1
                spec = self._render_request(case.request, bindings, case.variables)
                self._validate_expanded_url(spec.url, case_index=case_index, ordinal=ordinal)
                expanded.append(
                    ExpandedRequest(
                        request_id=f"request-{id_factory()}",
                        ordinal=ordinal,
                        spec=spec,
                        variables=bindings,
                        request_group_id=group_id,
                    )
                )
        return expanded

    @classmethod
    def _preflight_template(
        cls, case: HttpProbeCase, *, declared_names: set[str]
    ) -> None:
        """Validate matrix placeholders before reading sources or creating work."""

        model = case.request.model_dump(mode="python")
        strings: list[tuple[str, bool]] = []

        def collect(value: Any, *, reject_single: bool = True) -> None:
            if isinstance(value, str):
                strings.append((value, reject_single))
            elif isinstance(value, dict):
                for key, item in value.items():
                    collect(key, reject_single=reject_single)
                    collect(item, reject_single=reject_single)
            elif isinstance(value, list):
                for item in value:
                    collect(item, reject_single=reject_single)

        # A raw body is opaque application data; braces there are not
        # necessarily template syntax. All request-construction fields and
        # structured body types are unambiguous template locations.
        for key in ("method", "url", "query", "headers", "cookies"):
            collect(model.get(key))
        body = model.get("body")
        if isinstance(body, dict):
            collect(body.get("value"), reject_single=body.get("type") != "raw")

        single = re.compile(r"(?<!\{)\{([A-Za-z_]\w*)\}(?!\})")
        double = re.compile(r"\{\{([A-Za-z_]\w*)\}\}")
        used: set[str] = set()
        for value, reject_single in strings:
            malformed = single.search(value) if reject_single else None
            if malformed:
                raise cls._validation(
                    "invalid_template_syntax",
                    f"Use {{{{{malformed.group(1)}}}}} for matrix variables; single-brace placeholders are not accepted",
                )
            for match in double.finditer(value):
                name = match.group(1)
                if name not in declared_names:
                    raise cls._validation(
                        "unknown_template_variable",
                        f"Template variable '{name}' is not declared in variables",
                    )
                used.add(name)
        unused = sorted(declared_names - used)
        if unused:
            raise cls._validation(
                "unused_template_variable",
                f"Declared template variables are not used: {', '.join(unused)}",
            )

    async def execute(
        self,
        request: ExpandedRequest,
        *,
        body_path: Path,
        session_cookies: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        spec = request.spec
        headers = dict(spec.headers)
        lowered = {name.lower() for name in headers}
        if "cache-control" not in lowered:
            headers["Cache-Control"] = "no-cache"
        if "pragma" not in lowered:
            headers["Pragma"] = "no-cache"
        if (
            spec.body is not None
            and spec.body.content_type is not None
            and "content-type" not in lowered
        ):
            headers["Content-Type"] = spec.body.content_type
        auth: httpx.Auth | tuple[str, str] | None = None
        if spec.auth is not None:
            if spec.auth.type == "basic":
                auth = (spec.auth.username or "", spec.auth.password or "")
            else:
                headers["Authorization"] = f"Bearer {spec.auth.token}"
        cookies = httpx.Cookies()
        for cookie in session_cookies:
            if str(cookie["name"]) in spec.cookies:
                continue
            domain = str(cookie.get("domain") or "")
            cookies.jar.set_cookie(
                Cookie(
                    version=int(cookie.get("version") or 0),
                    name=str(cookie["name"]),
                    value=str(cookie["value"]),
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=bool(domain),
                    domain_initial_dot=domain.startswith("."),
                    path=str(cookie.get("path") or "/"),
                    path_specified=True,
                    secure=bool(cookie.get("secure", False)),
                    expires=(
                        int(cookie["expires"])
                        if cookie.get("expires") is not None
                        else None
                    ),
                    discard=bool(cookie.get("discard", False)),
                    comment=None,
                    comment_url=None,
                    rest=dict(cookie.get("rest") or {}),
                    rfc2109=False,
                )
            )
        for name, value in spec.cookies.items():
            cookies.set(name, value)
        kwargs, opened = self._body_arguments(spec)
        timeout = httpx.Timeout(spec.timeout_seconds)
        started = time.perf_counter()
        partial_path = body_path.with_suffix(body_path.suffix + ".part")
        partial_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        digest = hashlib.sha256()
        body_bytes = 0
        line_count = 0
        preview = bytearray()
        response_headers: dict[str, str] = {}
        status_code: int | None = None
        final_url = spec.url
        outcome = "response"
        error_detail: str | None = None
        response_cookies: list[dict[str, Any]] = []
        last_body_byte: int | None = None
        try:
            client = await self._client_for(spec)
            http_request = httpx.Request(
                spec.method.upper(),
                spec.url,
                params=spec.query,
                headers=headers,
                cookies=cookies,
                extensions={"timeout": timeout.as_dict()},
                **kwargs,
            )
            response, response_cookie_jar = await self._send_request(
                client,
                http_request,
                auth=auth,
                follow_redirects=spec.follow_redirects,
                cookies=cookies,
            )
            try:
                status_code = response.status_code
                final_url = str(response.url)
                response_headers = dict(response.headers)
                with partial_path.open("wb") as output:
                    async for chunk in response.aiter_bytes():
                        output.write(chunk)
                        digest.update(chunk)
                        body_bytes += len(chunk)
                        line_count += chunk.count(b"\n")
                        if chunk:
                            last_body_byte = chunk[-1]
                        if len(preview) < 65_536:
                            preview.extend(chunk[: 65_536 - len(preview)])
                    output.flush()
                    os.fsync(output.fileno())
                partial_path.replace(body_path)
                os.chmod(body_path, 0o600)
                response_cookies = [
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "expires": cookie.expires,
                        "discard": cookie.discard,
                        "version": cookie.version,
                        "rest": dict(getattr(cookie, "_rest", {})),
                    }
                    for cookie in response_cookie_jar.jar
                ]
            finally:
                await response.aclose()
        except httpx.TimeoutException as exc:
            outcome, error_detail = "timeout", type(exc).__name__
        except httpx.ConnectError as exc:
            message = str(exc).lower()
            if any(
                marker in message
                for marker in ("name or service not known", "nodename nor servname", "getaddrinfo")
            ):
                outcome = "dns_error"
            else:
                outcome = "tls_error" if "ssl" in message or "certificate" in message else "connect_error"
            error_detail = type(exc).__name__
        except httpx.ProtocolError as exc:
            outcome, error_detail = "protocol_error", type(exc).__name__
        except OSError as exc:
            outcome, error_detail = "storage_error", type(exc).__name__
        except httpx.HTTPError as exc:
            outcome, error_detail = "http_error", type(exc).__name__
        finally:
            for handle in opened:
                handle.close()
        body_complete = outcome == "response"
        if not body_complete and partial_path.exists():
            try:
                partial_path.replace(body_path)
                os.chmod(body_path, 0o600)
            except OSError:
                pass
        if body_bytes and last_body_byte != ord("\n"):
            line_count += 1
        title = self._extract_title(bytes(preview), response_headers.get("content-type", ""))
        result = {
            "type": "response",
            "request_id": request.request_id,
            "ordinal": request.ordinal,
            "request_intent": spec.request_intent,
            "parent_request_id": spec.parent_request_id,
            "request_group_id": request.request_group_id,
            "connection_context_id": spec.connection_context_id,
            "sequence_id": spec.sequence_id,
            "variables": request.variables,
            "outcome": outcome,
            "status_code": status_code,
            "final_url": final_url,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "body_bytes": body_bytes,
            "content_length": self._int_header(response_headers.get("content-length")),
            "body_sha256": digest.hexdigest(),
            "line_count": line_count,
            "body_complete": body_complete,
            "content_type": response_headers.get("content-type"),
            "location": response_headers.get("location"),
            "title": title,
            "headers": response_headers,
            "error": error_detail,
            "body_file": body_path.name if body_path.exists() else None,
        }
        return result, response_cookies

    def analyze(self, response: dict[str, Any], body_path: Path, *, revision: int) -> dict[str, Any]:
        data = body_path.read_bytes() if body_path.exists() else b""
        content_type = str(response.get("content_type") or "").lower()
        binary = self._is_binary(data, content_type)
        summary: dict[str, Any]
        features: dict[str, Any]
        similarity_hash: str | None = None
        if not binary:
            charset = self._charset(content_type)
            try:
                text = data.decode(charset, errors="replace")
            except LookupError:
                charset = "utf-8"
                text = data.decode(charset, errors="replace")
            if "html" in content_type or re.search(r"(?i)<(?:html|body|form)\b", text[:4096]):
                parser = _HtmlFeatures()
                parser.feed(text)
                summary = {
                    "kind": "html",
                    "title": parser.title,
                    "forms": parser.forms,
                    "form_count": parser.form_count,
                    "input_names": sorted(set(parser.inputs))[:100],
                    "input_count": parser.input_count,
                    "link_count": parser.links,
                    "script_count": parser.scripts,
                }
                features = {
                    "content_kind": "html",
                    "form_count": parser.form_count,
                    "input_count": parser.input_count,
                    "link_count": parser.links,
                    "script_count": parser.scripts,
                }
            elif "json" in content_type or text.lstrip().startswith(("{", "[")):
                try:
                    value = json.loads(text)
                    summary = self._json_summary(value)
                    features = {
                        "content_kind": "json",
                        "shape": summary.get("shape"),
                    }
                except (TypeError, ValueError):
                    summary = self._text_summary(text, encoding=charset)
                    features = {
                        "content_kind": "text",
                        "common_tokens": summary["common_tokens"],
                    }
            else:
                summary = self._text_summary(text, encoding=charset)
                features = {
                    "content_kind": "text",
                    "common_tokens": summary["common_tokens"],
                }
            similarity_hash = self._simhash(text)
        else:
            summary = {
                "kind": "binary",
                "bytes": len(data),
                "magic_hex": data[:16].hex(),
            }
            features = {
                "content_kind": "binary",
                "content_type": response.get("content_type"),
                "magic_hex": data[:16].hex(),
            }
        return {
            "type": "analysis",
            "request_id": response["request_id"],
            "request_group_id": response.get("request_group_id"),
            "request_intent": response.get("request_intent"),
            "revision": revision,
            "similarity_hash": similarity_hash,
            "features": features,
            "summary": summary,
        }

    def _source_values(self, source: HttpVariableSource) -> list[Any]:
        if source.values is not None:
            return list(source.values)
        if source.range is not None:
            values = range(source.range.start, source.range.stop, source.range.step)
            if len(values) > MAX_HTTP_PROBE_REQUESTS:
                raise self._validation(
                    "http_probe_too_large",
                    f"HTTP probe source contains more than {MAX_HTTP_PROBE_REQUESTS} values",
                )
            return list(values)
        assert source.file_path is not None
        path = self.policy.resolve(source.file_path, must_exist=True)
        if not path.is_file():
            raise self._validation("variable_file_not_file", "Variable source must be a file")
        values: list[str] = []
        with path.open("r", encoding="utf-8") as source_file:
            for line in source_file:
                line = line.rstrip("\r\n")
                value = line.strip() if source.trim else line
                if source.skip_empty and not value:
                    continue
                values.append(value)
                if len(values) > MAX_HTTP_PROBE_REQUESTS:
                    raise self._validation(
                        "http_probe_too_large",
                        f"HTTP probe source contains more than {MAX_HTTP_PROBE_REQUESTS} values",
                    )
        return values

    def _render_request(
        self,
        request: HttpRequestSpec,
        bindings: dict[str, Any],
        sources: dict[str, HttpVariableSource],
    ) -> HttpRequestSpec:
        values = request.model_dump(mode="python")
        values["method"] = self._render(values["method"], bindings, sources, "none")
        values["url"] = self._render(values["url"], bindings, sources, "url")
        values["query"] = self._render(values["query"], bindings, sources, "query")
        values["headers"] = self._render(values["headers"], bindings, sources, "none")
        values["cookies"] = self._render(values["cookies"], bindings, sources, "none")
        if values.get("body") is not None:
            body_type = values["body"]["type"]
            location = "form" if body_type in {"form", "multipart"} else "json"
            values["body"]["value"] = self._render(
                values["body"]["value"], bindings, sources, location
            )
        self._assert_resolved(values)
        rendered = HttpRequestSpec.model_validate(values)
        self._validate_body(rendered)
        return rendered

    def _render(
        self,
        value: Any,
        bindings: dict[str, Any],
        sources: dict[str, HttpVariableSource],
        location: str,
    ) -> Any:
        if isinstance(value, dict):
            return {
                str(self._render(key, bindings, sources, location)): self._render(
                    item, bindings, sources, location
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._render(item, bindings, sources, location) for item in value]
        if not isinstance(value, str):
            return value
        exact = re.fullmatch(r"\{\{([A-Za-z_]\w*)\}\}", value)
        if exact and location == "json" and exact.group(1) in bindings:
            return bindings[exact.group(1)]
        rendered = value
        for name, raw in bindings.items():
            source = sources[name]
            replacement = str(raw)
            if source.encoding == "path":
                # Encode path segments without escaping the separators. A
                # value such as /druid/index.html must remain a path, not
                # become %2Fdruid%2Findex.html in the URL authority.
                replacement = quote(replacement, safe="/")
            elif source.encoding == "query" and location != "query":
                replacement = quote_plus(replacement)
            elif source.encoding == "form" and location != "form":
                replacement = quote_plus(replacement)
            rendered = rendered.replace(f"{{{{{name}}}}}", replacement)
        return rendered

    def _body_arguments(self, spec: HttpRequestSpec) -> tuple[dict[str, Any], list[Any]]:
        if spec.body is None:
            return {}, []
        body = spec.body
        if body.type == "json":
            return {"json": body.value}, []
        if body.type == "form":
            return {"data": body.value}, []
        if body.type == "raw":
            return {"content": str(body.value).encode()}, []
        if body.type == "base64":
            try:
                decoded = base64.b64decode(str(body.value), validate=True)
            except ValueError as exc:
                raise self._validation("invalid_base64_body", "Raw base64 body is invalid") from exc
            return {"content": decoded}, []
        if not isinstance(body.value, dict):
            raise self._validation("invalid_multipart", "Multipart body must be an object")
        files: dict[str, Any] = {}
        opened: list[Any] = []
        for name, item in body.value.items():
            if isinstance(item, dict) and "file_path" in item:
                path = self.policy.resolve(str(item["file_path"]), must_exist=True)
                handle = path.open("rb")
                opened.append(handle)
                files[name] = (
                    str(item.get("filename") or path.name),
                    handle,
                    item.get("content_type"),
                )
            else:
                files[name] = (None, str(item))
        return {"files": files}, opened

    def _validate_body(self, spec: HttpRequestSpec) -> None:
        body = spec.body
        if body is None:
            return
        if body.type == "form" and not isinstance(body.value, dict):
            raise self._validation(
                "invalid_form_body", "Form body must be a key/value object"
            )
        if body.type == "base64":
            try:
                base64.b64decode(str(body.value), validate=True)
            except ValueError as exc:
                raise self._validation(
                    "invalid_base64_body", "Raw base64 body is invalid"
                ) from exc
        if body.type != "multipart":
            return
        if not isinstance(body.value, dict):
            raise self._validation(
                "invalid_multipart", "Multipart body must be an object"
            )
        for item in body.value.values():
            if not isinstance(item, dict) or "file_path" not in item:
                continue
            path = self.policy.resolve(str(item["file_path"]), must_exist=True)
            if not path.is_file():
                raise self._validation(
                    "multipart_file_not_file",
                    "Multipart file source must be a file",
                )

    @staticmethod
    def _extract_title(preview: bytes, content_type: str) -> str | None:
        if "html" not in content_type.lower() and b"<title" not in preview.lower():
            return None
        charset = HttpInteractionEngine._charset(content_type)
        try:
            text = preview.decode(charset, errors="replace")
        except LookupError:
            text = preview.decode("utf-8", errors="replace")
        match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
        return None if match is None else " ".join(re.sub(r"<[^>]+>", " ", match.group(1)).split())

    @staticmethod
    def _charset(content_type: str) -> str:
        match = re.search(r"(?i)charset=([A-Za-z0-9._-]+)", content_type)
        return match.group(1) if match else "utf-8"

    @staticmethod
    def _is_binary(data: bytes, content_type: str) -> bool:
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type.startswith("text/") or media_type in {
            "application/json",
            "application/javascript",
            "application/xml",
            "application/xhtml+xml",
            "application/x-www-form-urlencoded",
        } or media_type.endswith(("+json", "+xml")):
            return False
        if media_type.startswith(("image/", "audio/", "video/", "font/")):
            return True
        if media_type in {
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/gzip",
        }:
            return True
        return b"\x00" in data[:8192]

    @staticmethod
    def _int_header(value: str | None) -> int | None:
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    @staticmethod
    def _json_summary(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            keys = sorted(map(str, value))
            return {
                "kind": "json",
                "root_type": "object",
                "keys": keys[:100],
                "keys_truncated": len(keys) > 100,
                "size": len(value),
                "shape": HttpInteractionEngine._json_shape(value),
            }
        if isinstance(value, list):
            shapes = sorted({type(item).__name__ for item in value[:100]})
            return {
                "kind": "json",
                "root_type": "array",
                "size": len(value),
                "item_types": shapes,
                "shape": HttpInteractionEngine._json_shape(value),
            }
        return {
            "kind": "json",
            "root_type": type(value).__name__,
            "shape": HttpInteractionEngine._json_shape(value),
        }

    @staticmethod
    def _json_shape(value: Any, depth: int = 0) -> Any:
        if depth >= 4:
            return type(value).__name__
        if isinstance(value, dict):
            items = sorted(value.items(), key=lambda pair: str(pair[0]))
            shape = {
                str(key): HttpInteractionEngine._json_shape(item, depth + 1)
                for key, item in items[:50]
            }
            if len(items) > 50:
                shape["<truncated_keys>"] = len(items) - 50
            return shape
        if isinstance(value, list):
            shapes = {
                json.dumps(
                    HttpInteractionEngine._json_shape(item, depth + 1),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                for item in value[:100]
            }
            return [json.loads(item) for item in sorted(shapes)]
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        return "string"

    @staticmethod
    def _text_summary(text: str, *, encoding: str) -> dict[str, Any]:
        line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        frequencies: dict[str, int] = {}
        for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_-]{2,}", text.lower()):
            word = match.group(0)
            frequencies[word] = frequencies.get(word, 0) + 1
        common = sorted(frequencies, key=lambda key: (-frequencies[key], key))[:20]
        return {
            "kind": "text",
            "encoding": encoding,
            "line_count": line_count,
            "common_tokens": common,
        }

    @staticmethod
    def _assert_resolved(value: Any) -> None:
        if isinstance(value, str) and re.search(r"\{\{[A-Za-z_]\w*\}\}", value):
            raise HttpInteractionEngine._validation(
                "unknown_template_variable",
                "HTTP request contains an unresolved template variable",
            )
        if isinstance(value, dict):
            for key, item in value.items():
                HttpInteractionEngine._assert_resolved(key)
                HttpInteractionEngine._assert_resolved(item)
        elif isinstance(value, list):
            for item in value:
                HttpInteractionEngine._assert_resolved(item)

    @staticmethod
    def _validate_expanded_url(url: str, *, case_index: int, ordinal: int) -> None:
        """Reject malformed matrix output before any Interaction is created."""
        if "{{" in url or "}}" in url:
            raise HttpInteractionEngine._validation(
                "invalid_expanded_url",
                f"Expanded URL for case {case_index}, request {ordinal} still contains a template",
            )
        try:
            parts = urlsplit(url)
            _ = parts.port  # force validation of malformed/overflowing ports
        except ValueError as exc:
            raise HttpInteractionEngine._validation(
                "invalid_expanded_url",
                f"Expanded URL for case {case_index}, request {ordinal} has an invalid port",
            ) from exc
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise HttpInteractionEngine._validation(
                "invalid_expanded_url",
                f"Expanded URL for case {case_index}, request {ordinal} must have an http(s) scheme and host",
            )

    @staticmethod
    def _simhash(text: str) -> str:
        normalized = re.sub(r"\b\d+\b", "<number>", text.lower())
        normalized = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", normalized)
        vector = [0] * 64
        found = False
        for match in re.finditer(r"[a-z0-9_<>-]+", normalized):
            found = True
            token = match.group(0)
            value = int.from_bytes(hashlib.sha256(token.encode()).digest()[:8], "big")
            for bit in range(64):
                vector[bit] += 1 if value & (1 << bit) else -1
        if not found:
            value = int.from_bytes(hashlib.sha256(b"").digest()[:8], "big")
            for bit in range(64):
                vector[bit] += 1 if value & (1 << bit) else -1
        result = sum(1 << bit for bit, score in enumerate(vector) if score >= 0)
        return f"{result:016x}"

    @staticmethod
    def _validation(code: str, message: str) -> SystemToolError:
        return SystemToolError(error_type="validation", code=code, message=message)
