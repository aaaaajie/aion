"""High-throughput web path discovery engine built on the dirsearch fork.

The engine owns the shared connection pool, wildcard calibration, response
classification and hit-only persistence of bodies. All Run-level lifecycle,
resource admission, journaling and cleanup stay in ``HttpProbeManager``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx

from third_party.dirsearch import (
    WordlistTemplate,
)
from third_party.dirsearch.wordlist import expand_template_line
from third_party.dirsearch.scanner import (
    AUTO_CALIBRATION_DUPLICATE_THRESHOLD,
    AUTO_CALIBRATION_FORCED_THRESHOLD,
    AUTO_CALIBRATION_MIN_CONTENT_LENGTH,
    ProbeResponse,
    WildcardScanner,
    applicable_scanners,
    build_scanner_map,
    response_fingerprint,
)
from third_party.dirsearch.settings import MAX_CONSECUTIVE_REQUEST_ERRORS
from third_party.dirsearch.urlutils import (
    append_query_string,
    clean_path,
    ensure_trailing_path_slash,
    safequote,
)
from tools.system.policy import SystemToolError, WorkspacePolicy

from .models import HttpAuth


QUICK_TEMPLATES = ("admin", "api", "auth", "backups", "db", "logs")
QUICK_PLACEHOLDERS = {
    "SUBJECT": ("admin", "user", "config", "upload"),
    "ADMIN_OP": ("admin", "panel", "dashboard"),
    "AUTH_OP": ("login", "logout", "signin", "signup", "register", "password"),
    "CRUD_OP": ("list", "get", "add", "edit", "delete"),
    "API_VERSION": ("v1", "v2"),
    "ENV": ("dev", "test", "prod"),
    "ARCHIVE": ("zip", "bak"),
    "DB": ("mysql", "sqlite"),
}
TARGETED_TEMPLATES = ("admin", "api", "auth", "backups", "crud", "db", "logs")
TARGETED_CATEGORIES = ("web", "conf")
DEEP_CATEGORIES = ("common", "vcs", "backups", "db", "logs", "keys")

PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "quick": {
        "templates": QUICK_TEMPLATES,
        "placeholders": QUICK_PLACEHOLDERS,
        "categories": (),
        "extensions": ("php", "jsp", "asp", "aspx"),
        "concurrency": 8,
        "timeout_seconds": 8.0,
        "max_body_bytes": 64 * 1024,
        "prefixes": (".", ".ht"),
        "suffixes": (),
        "auto_calibration": False,
    },
    "targeted": {
        "templates": TARGETED_TEMPLATES,
        "placeholders": None,
        "categories": TARGETED_CATEGORIES,
        "extensions": ("php", "jsp", "asp", "aspx", "html", "json"),
        "concurrency": 16,
        "timeout_seconds": 10.0,
        "max_body_bytes": 128 * 1024,
        "prefixes": (".", ".ht"),
        "suffixes": ("/", "~"),
        "auto_calibration": False,
    },
    "deep": {
        "templates": TARGETED_TEMPLATES,
        "placeholders": None,
        "categories": TARGETED_CATEGORIES + DEEP_CATEGORIES,
        "extensions": ("php", "jsp", "asp", "aspx", "html", "json"),
        "concurrency": 24,
        "timeout_seconds": 12.0,
        "max_body_bytes": 256 * 1024,
        "prefixes": (".", ".ht"),
        "suffixes": ("/", "~"),
        "auto_calibration": True,
    },
}

@dataclass(frozen=True)
class PathProbeOptions:
    profile: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth: HttpAuth | None = None
    session_id: str | None = None
    follow_redirects: bool = False
    verify_tls: bool = False
    timeout_seconds: float = 10.0
    concurrency: int = 8
    rate_limit_per_second: float | None = None
    extensions: tuple[str, ...] = ()
    force_extensions: bool = False
    wordlist_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    include_status_codes: frozenset[int] = frozenset()
    exclude_status_codes: frozenset[int] = frozenset({404})
    recursion_depth: int = 0
    recursion_status_codes: frozenset[int] = frozenset({200, 301, 302})
    max_body_bytes: int = 262144
    request_intent: str = "path_discovery"
    parent_request_id: str | None = None
    request_group_id: str | None = None

    def to_plan(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "url": self.url,
            "method": self.method,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "auth": self.auth.model_dump(mode="json") if self.auth is not None else None,
            "session_id": self.session_id,
            "follow_redirects": self.follow_redirects,
            "verify_tls": self.verify_tls,
            "timeout_seconds": self.timeout_seconds,
            "concurrency": self.concurrency,
            "rate_limit_per_second": self.rate_limit_per_second,
            "extensions": list(self.extensions),
            "force_extensions": self.force_extensions,
            "wordlist_paths": list(self.wordlist_paths),
            "exclude_paths": list(self.exclude_paths),
            "include_status_codes": sorted(self.include_status_codes),
            "exclude_status_codes": sorted(self.exclude_status_codes),
            "recursion_depth": self.recursion_depth,
            "recursion_status_codes": sorted(self.recursion_status_codes),
            "max_body_bytes": self.max_body_bytes,
            "request_intent": self.request_intent,
            "parent_request_id": self.parent_request_id,
            "request_group_id": self.request_group_id,
        }

    @classmethod
    def from_plan(cls, data: dict[str, Any]) -> "PathProbeOptions":
        auth = data.get("auth")
        return cls(
            profile=str(data["profile"]),
            url=str(data["url"]),
            method=str(data.get("method") or "GET"),
            headers=dict(data.get("headers") or {}),
            cookies=dict(data.get("cookies") or {}),
            auth=HttpAuth.model_validate(auth) if auth is not None else None,
            session_id=data.get("session_id"),
            follow_redirects=bool(data.get("follow_redirects", False)),
            verify_tls=bool(data.get("verify_tls", False)),
            timeout_seconds=float(data.get("timeout_seconds") or 10.0),
            concurrency=int(data.get("concurrency") or 8),
            rate_limit_per_second=data.get("rate_limit_per_second"),
            extensions=tuple(data.get("extensions") or ()),
            force_extensions=bool(data.get("force_extensions", False)),
            wordlist_paths=tuple(data.get("wordlist_paths") or ()),
            exclude_paths=tuple(data.get("exclude_paths") or ()),
            include_status_codes=frozenset(data.get("include_status_codes") or ()),
            exclude_status_codes=frozenset(data.get("exclude_status_codes") or {404}),
            recursion_depth=int(data.get("recursion_depth") or 0),
            recursion_status_codes=frozenset(data.get("recursion_status_codes") or ()),
            max_body_bytes=int(data.get("max_body_bytes") or 262144),
            request_intent=str(data.get("request_intent") or "path_discovery"),
            parent_request_id=data.get("parent_request_id"),
            request_group_id=data.get("request_group_id"),
        )


@dataclass(frozen=True)
class PathProbeMatch:
    request_id: str
    ordinal: int
    directory: str
    path: str
    depth: int
    url: str
    status: int
    content_type: str
    length: int
    body_sha256: str
    redirect: str
    title: str | None
    elapsed_ms: int
    header_features: dict[str, str]
    body_file: str | None
    body_complete: bool
    line_count: int
    request_group_id: str


@dataclass
class PathProbeRunResult:
    started: int = 0
    completed: int = 0
    matched: int = 0
    body_bytes: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    calibration_requests: int = 0
    recursion_skipped: int = 0
    stopped: bool = False
    storage_failure: bool = False
    abort_reason: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int = 0


@dataclass
class _Job:
    request_id: str
    directory: str
    path: str
    depth: int
    ordinal: int
    group_id: str


@dataclass
class _Counters:
    started: int = 0
    completed: int = 0
    matched: int = 0
    body_bytes: int = 0
    calibration_requests: int = 0
    consecutive_errors: int = 0
    recursion_skipped: int = 0
    by_status: Counter = field(default_factory=Counter)
    errors: Counter = field(default_factory=Counter)
    storage_failure: bool = False
    stopped: bool = False
    abort_reason: str | None = None

    def result(self) -> PathProbeRunResult:
        return PathProbeRunResult(
            started=self.started,
            completed=self.completed,
            matched=self.matched,
            body_bytes=self.body_bytes,
            by_status=dict(self.by_status),
            errors=dict(self.errors),
            calibration_requests=self.calibration_requests,
            recursion_skipped=self.recursion_skipped,
            stopped=self.stopped,
            storage_failure=self.storage_failure,
            abort_reason=self.abort_reason,
        )


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class PathProbeCalibrationError(Exception):
    """Raised when a wildcard calibration request itself fails."""


def join_path_url(base_url: str, full_path: str) -> str:
    parsed = urlsplit(ensure_trailing_path_slash(base_url))
    base = urlunsplit(parsed._replace(query="", fragment=""))
    return append_query_string(urljoin(base, safequote(full_path)), parsed.query)


class PathProbeEngine:
    """Generate path lists and scan them with one shared async client."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        options: PathProbeOptions,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.policy = policy
        self.options = options
        self.transport = transport
        self._similar_fingerprints: dict[tuple, int] = {}
        self._auto_calibrated: set[tuple] = set()
        self._cookies_jar: httpx.Cookies = httpx.Cookies()

    def iter_paths(self) -> Iterator[str]:
        """Yield a finite de-duplicated wordlist without materializing a request plan."""

        excluded = self._excluded_set()
        seen: set[str] = set()
        extensions = self._effective_extensions()

        def emit(raw: str) -> Iterator[str]:
            value = raw.strip().lstrip("/")
            if not value or value.startswith("#"):
                return
            variants = [value]
            if (
                self.options.force_extensions
                and "." not in value
                and not value.endswith("/")
            ):
                variants.extend([value + "/", *(f"{value}.{ext}" for ext in extensions)])
            for candidate in variants:
                if candidate in excluded or candidate in seen:
                    continue
                seen.add(candidate)
                yield candidate

        if self.options.wordlist_paths:
            for raw_path in self.options.wordlist_paths:
                source = self.policy.resolve(raw_path, must_exist=True)
                if not source.is_file():
                    raise _validation("wordlist_not_file", "Wordlist source must be a file")
                with source.open("r", encoding="utf-8") as lines:
                    for line in lines:
                        for expanded in expand_template_line(
                            line.rstrip("\r\n"), extensions=extensions
                        ):
                            yield from emit(expanded)
            return

        preset = PROFILE_PRESETS[self.options.profile]
        for name in preset["templates"]:
            template = WordlistTemplate.from_builtin(
                name, placeholders=preset["placeholders"]
            )
            for rendered in template.render(extensions=extensions):
                yield from emit(rendered)
        for category in preset["categories"]:
            template = WordlistTemplate([f"%CATEGORY:{category}%"])
            for rendered in template.render(extensions=extensions):
                yield from emit(rendered)

    def build_paths(self) -> list[str]:
        return list(self.iter_paths())

    def calibration_budget(self) -> int:
        preset = PROFILE_PRESETS[self.options.profile]
        scanners = (
            1
            + len(preset["prefixes"])
            + len(preset["suffixes"])
            + len(self._effective_extensions())
        )
        return scanners * 2

    async def run(
        self,
        *,
        plan_path: Path,
        root_count: int,
        body_dir: Path,
        session_cookies: list[dict[str, Any]],
        on_match: Callable[[PathProbeMatch], Awaitable[None]],
        on_progress: Callable[[int, int, int, int], Awaitable[None]] | None = None,
        on_estimate: Callable[[int], Awaitable[None]] | None = None,
        stop_requested: Callable[[], bool] | None = None,
        resource_guard: Callable[[], Awaitable[None]] | None = None,
    ) -> PathProbeRunResult:
        clock_started = time.perf_counter()
        started_at = _now()
        if root_count <= 0:
            return PathProbeRunResult(
                started_at=started_at,
                finished_at=started_at,
                duration_ms=0,
            )
        self._cookies_jar = self._build_cookies(session_cookies)
        client = httpx.AsyncClient(
            verify=self.options.verify_tls,
            follow_redirects=self.options.follow_redirects,
            timeout=httpx.Timeout(self.options.timeout_seconds),
            transport=self.transport,
            trust_env=True,
        )
        try:
            result = await self._run_scan(
                client,
                plan_path=plan_path,
                root_count=root_count,
                body_dir=body_dir,
                on_match=on_match,
                on_progress=on_progress,
                on_estimate=on_estimate,
                stop_requested=stop_requested,
                resource_guard=resource_guard,
            )
        finally:
            await client.aclose()
        result.started_at = started_at
        result.finished_at = _now()
        result.duration_ms = int((time.perf_counter() - clock_started) * 1000)
        return result

    def _excluded_set(self) -> set[str]:
        excluded: set[str] = set()
        for raw in self.options.exclude_paths:
            path = self.policy.resolve(raw, must_exist=True)
            if not path.is_file():
                raise _validation("exclude_file_not_found", "Exclude list must be a file")
            for line in path.read_text(encoding="utf-8").splitlines():
                value = line.strip().lstrip("/")
                if value and not value.startswith("#"):
                    excluded.add(value)
        return excluded

    async def _run_scan(
        self,
        client: httpx.AsyncClient,
        *,
        plan_path: Path,
        root_count: int,
        body_dir: Path,
        on_match: Callable[[PathProbeMatch], Awaitable[None]],
        on_progress: Callable[[int, int, int, int], Awaitable[None]] | None,
        on_estimate: Callable[[int], Awaitable[None]] | None,
        stop_requested: Callable[[], bool] | None,
        resource_guard: Callable[[], Awaitable[None]] | None,
    ) -> PathProbeRunResult:
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=max(4, self.options.concurrency * 4))
        directories: asyncio.Queue[Any] = asyncio.Queue()
        counters = _Counters()
        ordinal = 0
        group_id = self.options.request_group_id or f"interaction-{uuid4().hex}"
        directories.put_nowait(("", 0, group_id))
        total_requests = root_count
        passed_directories: set[str] = set()
        scanners: dict[str, dict[str, dict[str, WildcardScanner]]] = {}
        calibration_locks: dict[str, asyncio.Lock] = {}
        semaphore = asyncio.Semaphore(self.options.concurrency)
        rate_lock = asyncio.Lock()
        next_start = 0.0

        def is_stopped() -> bool:
            if counters.stopped or counters.storage_failure or counters.abort_reason:
                return True
            return bool(stop_requested and stop_requested())

        async def calibrate(directory: str) -> dict[str, dict[str, WildcardScanner]]:
            preset = PROFILE_PRESETS[self.options.profile]
            scanner_map = build_scanner_map(
                directory,
                extensions=self._effective_extensions(),
                prefixes=preset["prefixes"],
                suffixes=preset["suffixes"],
                auto_calibration=preset["auto_calibration"],
            )

            async def requester(path: str) -> ProbeResponse:
                response = await self._request(client, path)
                if response.outcome != "response":
                    raise PathProbeCalibrationError(
                        response.error or "calibration_request_failed"
                    )
                return response

            for category in ("default", "prefixes", "suffixes"):
                for name in scanner_map[category]:
                    scanner = scanner_map[category][name]
                    await scanner.setup(requester)
                    counters.calibration_requests += scanner.sample_count
            return scanner_map

        async def maybe_progress() -> None:
            if on_progress is None:
                return
            if counters.completed % 50 == 0 or (
                queue.empty() and counters.completed == counters.started
            ):
                await on_progress(
                    counters.started,
                    counters.completed,
                    counters.matched,
                    counters.body_bytes,
                )

        async def process(job: _Job) -> None:
            nonlocal next_start
            if is_stopped():
                return
            async with semaphore:
                if resource_guard is not None:
                    await resource_guard()
                if is_stopped():
                    return
                if self.options.rate_limit_per_second:
                    async with rate_lock:
                        loop = asyncio.get_running_loop()
                        delay = max(0.0, next_start - loop.time())
                        if delay:
                            await asyncio.sleep(delay)
                        next_start = loop.time() + 1.0 / self.options.rate_limit_per_second
                directory = job.directory
                lock = calibration_locks.setdefault(directory, asyncio.Lock())
                async with lock:
                    scan = scanners.get(directory)
                    if scan is None:
                        try:
                            scan = await calibrate(directory)
                        except PathProbeCalibrationError:
                            counters.abort_reason = "calibration_failed"
                            counters.errors["calibration_failed"] += 1
                            return
                        scanners[directory] = scan
                if is_stopped():
                    return
                full_path = f"{directory}{job.path}" if directory else job.path
                response = await self._request(client, full_path)
                counters.started += 1
                if response.outcome != "response":
                    counters.errors[response.outcome] += 1
                    counters.consecutive_errors += 1
                    if counters.consecutive_errors >= MAX_CONSECUTIVE_REQUEST_ERRORS:
                        counters.abort_reason = "too_many_errors"
                    await maybe_progress()
                    return
                counters.consecutive_errors = 0
                counters.completed += 1
                if self._is_excluded(response):
                    await maybe_progress()
                    return
                if not self._is_unique(scan, job.path, response):
                    await maybe_progress()
                    return
                match, storage_error = await self._make_match(job, response, body_dir)
                if storage_error:
                    counters.storage_failure = True
                    counters.abort_reason = "storage_error"
                    counters.errors["storage_error"] += 1
                    await maybe_progress()
                    return
                counters.matched += 1
                counters.body_bytes += len(response.body)
                counters.by_status[str(response.status)] += 1
                await on_match(match)
                await enqueue_recursion(job, match)
                await maybe_progress()

        async def enqueue_recursion(job: _Job, match: PathProbeMatch) -> None:
            nonlocal total_requests
            if job.depth >= self.options.recursion_depth:
                return
            if match.status not in self.options.recursion_status_codes:
                return
            full_path = f"{job.directory}{job.path}" if job.directory else job.path
            if not full_path.endswith("/"):
                return
            subdirectory = full_path.lstrip("/")
            if subdirectory in passed_directories:
                return
            passed_directories.add(subdirectory)
            total_requests += root_count
            if on_estimate is not None:
                await on_estimate(
                    total_requests
                    + (len(passed_directories) + 1) * self.calibration_budget()
                )
            await directories.put((subdirectory, job.depth + 1, job.group_id))

        async def produce() -> None:
            nonlocal ordinal
            while True:
                batch = await directories.get()
                try:
                    if batch is None:
                        return
                    directory, depth, batch_group = batch
                    with plan_path.open("r", encoding="utf-8") as source:
                        for raw in source:
                            if is_stopped():
                                break
                            item = json.loads(raw)
                            if depth == 0:
                                request_id = str(item["request_id"])
                                item_ordinal = int(item["ordinal"])
                                ordinal = max(ordinal, item_ordinal)
                            else:
                                ordinal += 1
                                request_id = f"request-{uuid4().hex}"
                                item_ordinal = ordinal
                            await queue.put(
                                _Job(
                                    request_id=request_id,
                                    directory=str(directory),
                                    path=str(item["path"]),
                                    depth=int(depth),
                                    ordinal=item_ordinal,
                                    group_id=str(batch_group),
                                )
                            )
                finally:
                    directories.task_done()

        async def worker() -> None:
            while True:
                job = await queue.get()
                try:
                    if job is None:
                        return
                    await process(job)
                except Exception as exc:
                    counters.abort_reason = type(exc).__name__
                    counters.errors["execution_error"] += 1
                finally:
                    queue.task_done()

        async def sweep() -> None:
            while True:
                await directories.join()
                await queue.join()
                if (
                    getattr(directories, "_unfinished_tasks", 0) == 0
                    and getattr(queue, "_unfinished_tasks", 0) == 0
                ):
                    break
            await directories.put(None)
            await producer
            for _ in range(self.options.concurrency):
                await queue.put(None)

        producer = asyncio.create_task(produce(), name="aion-path-plan-producer")
        workers = [
            asyncio.create_task(worker(), name=f"aion-path-probe-{uuid4().hex}")
            for _ in range(self.options.concurrency)
        ]
        try:
            await sweep()
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            counters.stopped = True
            producer.cancel()
            for task in workers:
                task.cancel()
            await asyncio.gather(producer, *workers, return_exceptions=True)
        return counters.result()

    async def _request(
        self,
        client: httpx.AsyncClient,
        full_path: str,
        *,
        absolute_url: str | None = None,
    ) -> ProbeResponse:
        url = absolute_url if absolute_url is not None else self._join_url(full_path)
        headers = dict(self.options.headers)
        lowered = {name.lower() for name in headers}
        if "cache-control" not in lowered:
            headers["Cache-Control"] = "no-cache"
        if "pragma" not in lowered:
            headers["Pragma"] = "no-cache"
        if "user-agent" not in lowered:
            headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
            )
        auth: httpx.Auth | tuple[str, str] | None = None
        if self.options.auth is not None:
            if self.options.auth.type == "basic":
                auth = (
                    self.options.auth.username or "",
                    self.options.auth.password or "",
                )
            else:
                headers["Authorization"] = f"Bearer {self.options.auth.token}"
        timeout = httpx.Timeout(self.options.timeout_seconds)
        started = time.perf_counter()
        try:
            async with client.stream(
                self.options.method.upper(),
                url,
                headers=headers,
                cookies=self._cookies_jar,
                auth=auth,
            ) as response:
                status = response.status_code
                final_url = str(response.url)
                response_headers = dict(response.headers)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= self.options.max_body_bytes:
                        break
        except httpx.TimeoutException as exc:
            return self._error_response(url, full_path, "timeout", type(exc).__name__)
        except httpx.ConnectError as exc:
            message = str(exc).lower()
            if any(
                marker in message
                for marker in ("name or service not known", "nodename nor servname", "getaddrinfo")
            ):
                outcome = "dns_error"
            else:
                outcome = (
                    "tls_error"
                    if "ssl" in message or "certificate" in message
                    else "connect_error"
                )
            return self._error_response(url, full_path, outcome, type(exc).__name__)
        except httpx.ProtocolError as exc:
            return self._error_response(url, full_path, "protocol_error", type(exc).__name__)
        except httpx.HTTPError as exc:
            return self._error_response(url, full_path, "http_error", type(exc).__name__)
        except OSError as exc:
            return self._error_response(url, full_path, "protocol_error", type(exc).__name__)
        body_bytes = bytes(body)
        content_type = response_headers.get("content-type", "")
        content = self._decode(body_bytes, content_type)
        content_length = self._int_header(response_headers.get("content-length"))
        length = content_length if content_length is not None else len(body_bytes)
        body_complete = len(body_bytes) < self.options.max_body_bytes or (
            content_length is not None and len(body_bytes) >= content_length
        )
        line_count = body_bytes.count(b"\n")
        if body_bytes and body_bytes[-1:] != b"\n":
            line_count += 1
        return ProbeResponse(
            url=url,
            path=full_path,
            status=status,
            headers=response_headers,
            body=body_bytes,
            content=content,
            redirect=response_headers.get("location", ""),
            length=length,
            type=(content_type or "unknown").split(";")[0],
            elapsed=time.perf_counter() - started,
            final_url=final_url,
            body_complete=body_complete,
            line_count=line_count,
        )

    def _error_response(self, url: str, full_path: str, outcome: str, error: str) -> ProbeResponse:
        return ProbeResponse(
            url=url,
            path=full_path,
            status=None,
            headers={},
            body=b"",
            content="",
            redirect="",
            length=0,
            type="unknown",
            elapsed=0.0,
            outcome=outcome,
            error=error,
        )

    def _join_url(self, full_path: str) -> str:
        return join_path_url(self.options.url, full_path)

    def _build_cookies(self, session_cookies: list[dict[str, Any]]) -> httpx.Cookies:
        from http.cookiejar import Cookie

        jar = httpx.Cookies()
        for cookie in session_cookies:
            if str(cookie.get("name") or "") in self.options.cookies:
                continue
            domain = str(cookie.get("domain") or "")
            jar.jar.set_cookie(
                Cookie(
                    version=int(cookie.get("version") or 0),
                    name=str(cookie["name"]),
                    value=str(cookie.get("value") or ""),
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=bool(domain),
                    domain_initial_dot=domain.startswith("."),
                    path=str(cookie.get("path") or "/"),
                    path_specified=True,
                    secure=bool(cookie.get("secure", False)),
                    expires=(
                        int(cookie["expires"]) if cookie.get("expires") is not None else None
                    ),
                    discard=bool(cookie.get("discard", False)),
                    comment=None,
                    comment_url=None,
                    rest=dict(cookie.get("rest") or {}),
                    rfc2109=False,
                )
            )
        for name, value in self.options.cookies.items():
            jar.set(name, value)
        return jar

    async def _make_match(
        self,
        job: _Job,
        response: ProbeResponse,
        body_dir: Path,
    ) -> tuple[PathProbeMatch | None, bool]:
        body_file: str | None = None
        if response.body and self.options.method.upper() != "HEAD":
            partial = body_dir / f"{job.request_id}.body.part"
            final = body_dir / f"{job.request_id}.body"
            try:
                with partial.open("wb") as output:
                    output.write(response.body)
                    output.flush()
                    os.fsync(output.fileno())
                partial.replace(final)
                os.chmod(final, 0o600)
                body_file = final.name
            except OSError:
                try:
                    partial.unlink(missing_ok=True)
                except OSError:
                    pass
                return None, True
        selected = {
            name: response.headers[name]
            for name in (
                "content-type",
                "content-length",
                "location",
                "server",
                "allow",
                "www-authenticate",
            )
            if name in response.headers
        }
        match = PathProbeMatch(
            request_id=job.request_id,
            ordinal=job.ordinal,
            directory=job.directory,
            path=job.path,
            depth=job.depth,
            url=response.final_url or self._join_url(f"{job.directory}{job.path}"),
            status=response.status,
            content_type=response.type,
            length=response.length,
            body_sha256=hashlib.sha256(response.body).hexdigest(),
            redirect=response.redirect,
            title=self._extract_title(response.body[:65_536], response.type),
            elapsed_ms=int(response.elapsed * 1000),
            header_features=selected,
            body_file=body_file,
            body_complete=response.body_complete,
            line_count=response.line_count,
            request_group_id=job.group_id,
        )
        return match, False

    def _effective_extensions(self) -> tuple[str, ...]:
        if self.options.extensions:
            return self.options.extensions
        return PROFILE_PRESETS[self.options.profile]["extensions"]

    def _is_excluded(self, response: ProbeResponse) -> bool:
        if response.status in self.options.exclude_status_codes:
            return True
        if (
            self.options.include_status_codes
            and response.status not in self.options.include_status_codes
        ):
            return True
        return self._is_repeated(response)

    def _is_repeated(self, response: ProbeResponse) -> bool:
        fingerprint = response_fingerprint(response)
        if fingerprint in self._auto_calibrated:
            return True
        if not self._should_record_auto_calibration(response):
            return False
        self._similar_fingerprints[fingerprint] = (
            self._similar_fingerprints.get(fingerprint, 0) + 1
        )
        preset = PROFILE_PRESETS[self.options.profile]
        threshold = (
            AUTO_CALIBRATION_FORCED_THRESHOLD
            if preset["auto_calibration"]
            else AUTO_CALIBRATION_DUPLICATE_THRESHOLD
        )
        if self._similar_fingerprints[fingerprint] >= threshold:
            self._auto_calibrated.add(fingerprint)
            return True
        return False

    def _should_record_auto_calibration(self, response: ProbeResponse) -> bool:
        if response.length < AUTO_CALIBRATION_MIN_CONTENT_LENGTH:
            return False
        if PROFILE_PRESETS[self.options.profile]["auto_calibration"]:
            return True
        if 400 <= response.status <= 599:
            return True
        path = clean_path(response.path).strip("/")
        if path and path in response.content:
            return True
        return bool(response.redirect)

    def _is_unique(
        self,
        scan: dict[str, dict[str, WildcardScanner]],
        path: str,
        response: ProbeResponse,
    ) -> bool:
        for tester in applicable_scanners(scan, path):
            if not tester.check(path, response):
                return False
        return True

    @staticmethod
    def _decode(data: bytes, content_type: str) -> str:
        if not data or PathProbeEngine._is_binary(data, content_type):
            return ""
        charset = PathProbeEngine._charset(content_type)
        try:
            return data.decode(charset, errors="replace")
        except LookupError:
            return data.decode("utf-8", errors="replace")

    @staticmethod
    def _is_binary(data: bytes, content_type: str) -> bool:
        lowered = (content_type or "").lower()
        if any(
            marker in lowered
            for marker in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "html")
        ):
            return False
        return b"\x00" in data

    @staticmethod
    def _charset(content_type: str) -> str:
        match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type or "", re.IGNORECASE)
        return match.group(1) if match else "utf-8"

    @staticmethod
    def _int_header(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_title(preview: bytes, content_type: str) -> str | None:
        if not preview:
            return None
        match = _TITLE_RE.search(preview)
        if not match:
            return None
        text = match.group(1).decode("utf-8", errors="replace").strip()
        normalized = re.sub(r"\s+", " ", text)
        return normalized[:1024] or None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validation(code: str, message: str) -> SystemToolError:
    return SystemToolError(
        error_type="validation",
        code=code,
        message=message,
    )
