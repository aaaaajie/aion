"""Run-owned persistence and lifecycle for generic HTTP interactions."""

from __future__ import annotations

import asyncio
import base64
import errno
import hashlib
import json
import logging
import os
import re
import shutil
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from pydantic import ValidationError

from agent.tooling import tool_error, validation_details

from agent.state import StateService
from agent.state.errors import StateNotFound
from tools.system.policy import SystemToolError, WorkspacePolicy

from .engine import ExpandedRequest, HttpInteractionEngine
from .fingerprint import (
    ActiveFingerprintEngine,
    FingerprintEngine,
    FingerprintMatch,
    FingerprintOptions,
    FingerprintScanResult,
    FingerprintScanner,
)
from .urls import effective_url
from .models import (
    FingerprintArguments,
    HttpAnalyzeArguments,
    HttpCleanupArguments,
    HttpOutputArguments,
    HttpOutputFilters,
    HttpPlanArguments,
    HttpProbeArguments,
    HttpProbeCase,
    HttpRequestArguments,
    HttpRequestInput,
    HttpRequestSpec,
    HttpResponseArguments,
    HttpStopArguments,
    PathProbeArguments,
)
from .path_probe import (
    PROFILE_PRESETS,
    PathProbeEngine,
    PathProbeMatch,
    PathProbeOptions,
    PathProbeRunResult,
)

ResourceGuard = Callable[[str], Awaitable[dict[str, Any]]]
TERMINAL = {"completed", "failed", "stopped", "interrupted"}
RECLAIM_HEADROOM_BYTES = 64 * 1024 * 1024

LOGGER = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LiveInteraction:
    interaction_id: str
    agent_id: str
    requests: list[ExpandedRequest]
    execution_done: asyncio.Event = field(default_factory=asyncio.Event)
    analysis_done: asyncio.Event = field(default_factory=asyncio.Event)
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    stop_requested: bool = False
    execution_task: asyncio.Task[None] | None = None
    analysis_task: asyncio.Task[None] | None = None
    journal_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class AgentHttpClient:
    """Agent-owned view over one Run-level HTTP manager."""

    def __init__(self, manager: "HttpProbeManager", agent_id: str) -> None:
        self.manager = manager
        self.agent_id = agent_id

    async def request(self, arguments: HttpRequestArguments) -> dict[str, Any]:
        return await self.manager.start_request(
            self.agent_id,
            request=arguments.to_request_spec(),
            wait_seconds=arguments.wait_seconds,
            result_limit=1,
        )

    async def probe(self, arguments: HttpProbeArguments) -> dict[str, Any]:
        return await self.manager.start_probe(
            self.agent_id,
            cases=[case.to_case() for case in arguments.cases],
            concurrency=arguments.concurrency,
            rate_limit_per_second=arguments.rate_limit_per_second,
            wait_seconds=arguments.wait_seconds,
            result_limit=20,
        )

    async def plan(self, arguments: HttpPlanArguments) -> dict[str, Any]:
        return await self.manager.plan(self.agent_id, arguments)

    async def path_probe(self, arguments: PathProbeArguments) -> dict[str, Any]:
        return await self.manager.start_path_probe(
            self.agent_id,
            url=arguments.url,
            profile=arguments.profile,
            session_id=arguments.session_id,
            extensions=arguments.extensions,
            wordlist_paths=arguments.wordlist_paths,
            packaged_wordlists=arguments.packaged_wordlists,
            max_candidates=arguments.max_candidates,
            exclude_paths=arguments.exclude_paths,
            force_extensions=arguments.force_extensions,
            include_status_codes=arguments.include_status_codes,
            exclude_status_codes=arguments.exclude_status_codes,
            recursion_depth=arguments.recursion_depth,
            recursion_status_codes=arguments.recursion_status_codes,
            method=arguments.method,
            headers=arguments.headers,
            cookies=arguments.cookies,
            auth=arguments.auth,
            follow_redirects=arguments.follow_redirects,
            verify_tls=arguments.verify_tls,
            timeout_seconds=arguments.timeout_seconds,
            max_body_bytes=arguments.max_body_bytes,
            concurrency=arguments.concurrency,
            rate_limit_per_second=arguments.rate_limit_per_second,
            wait_seconds=arguments.wait_seconds,
            result_limit=100,
        )

    async def fingerprint(self, arguments: FingerprintArguments) -> dict[str, Any]:
        return await self.manager.start_fingerprint(
            self.agent_id,
            url=arguments.url,
            session_id=arguments.session_id,
            passive=arguments.passive,
            active=arguments.active,
            minimum_confidence=arguments.minimum_confidence,
            include_favicon=arguments.include_favicon,
            headers=arguments.headers,
            cookies=arguments.cookies,
            auth=arguments.auth,
            follow_redirects=arguments.follow_redirects,
            verify_tls=arguments.verify_tls,
            timeout_seconds=arguments.timeout_seconds,
            concurrency=arguments.concurrency,
            wait_seconds=arguments.wait_seconds,
            result_limit=100,
        )

    async def analyze(self, arguments: HttpAnalyzeArguments) -> dict[str, Any]:
        return await self.manager.analyze(
            self.agent_id,
            interaction_id=arguments.interaction_id,
            request_ids=arguments.request_ids,
            request_group_id=arguments.request_group_id,
            similarity=arguments.similarity,
            features=arguments.features,
            summary=arguments.summary,
            force=arguments.force,
            wait_seconds=arguments.wait_seconds,
            cursor=arguments.cursor,
            limit=arguments.limit,
        )

    async def output(self, arguments: HttpOutputArguments) -> dict[str, Any]:
        return await self.manager.output(
            self.agent_id,
            interaction_id=arguments.interaction_id,
            cursor=arguments.cursor,
            limit=arguments.limit,
            wait_seconds=arguments.wait_seconds,
            filters=arguments.filters,
        )

    async def response(self, arguments: HttpResponseArguments) -> dict[str, Any]:
        return await self.manager.response(
            self.agent_id,
            interaction_id=arguments.interaction_id,
            request_id=arguments.request_id,
            offset_bytes=arguments.offset_bytes,
            length_bytes=arguments.length_bytes,
        )

    async def stop(self, arguments: HttpStopArguments) -> dict[str, Any]:
        return await self.manager.stop(
            self.agent_id, interaction_id=arguments.interaction_id
        )

    async def cleanup(self, arguments: HttpCleanupArguments) -> dict[str, Any]:
        return await self.manager.cleanup(
            self.agent_id, interaction_id=arguments.interaction_id
        )


class HttpProbeManager:
    """Persist and coordinate all HTTP interactions for one Runtime Run."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        service: StateService,
        run_id: str,
        *,
        engine: HttpInteractionEngine | None = None,
        path_transport: httpx.AsyncBaseTransport | None = None,
        resource_guard: ResourceGuard | None = None,
        disk_reserve_bytes: int = 1_073_741_824,
        disk_reserve_percent: float = 5.0,
    ) -> None:
        self.policy = policy
        self.service = service
        self.run_id = run_id
        self.engine = engine or HttpInteractionEngine(policy)
        self._agent_engines: dict[str, HttpInteractionEngine] = {}
        self.path_transport = path_transport
        self.resource_guard = resource_guard
        self.disk_reserve_bytes = max(0, disk_reserve_bytes)
        self.disk_reserve_percent = max(0.0, disk_reserve_percent)
        self._live: dict[str, LiveInteraction] = {}
        self._analysis_scopes: dict[tuple[str, int], tuple[set[str], str | None]] = {}
        self._session_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._interaction_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._plan_cache: dict[tuple[str, str], list[ExpandedRequest]] = {}
        self._response_cache: dict[
            tuple[str, str], tuple[int, list[dict[str, Any]]]
        ] = {}
        self._group_cache: dict[tuple[str, str], tuple[int, list[dict[str, Any]]]] = {}
        self._similarity_cache: dict[
            tuple[str, str], tuple[int, list[dict[str, Any]]]
        ] = {}
        self._response_size_estimates: dict[
            tuple[str, str | None, int | None], tuple[int, int]
        ] = {}
        self._reclaim_lock = asyncio.Lock()
        self._closed = False

    def bind(
        self, agent_id: str, *, workspace_root: Path | None = None
    ) -> AgentHttpClient:
        if workspace_root is not None and agent_id not in self._agent_engines:
            self._agent_engines[agent_id] = HttpInteractionEngine(
                WorkspacePolicy(workspace_root), transport=self.engine.transport
            )
        return AgentHttpClient(self, agent_id)

    def _engine(self, agent_id: str) -> HttpInteractionEngine:
        return self._agent_engines.get(agent_id, self.engine)

    async def initialize(self, *, resume: bool = False) -> None:
        await self._remove_orphan_interaction_directories()
        await self._reclaim_terminal_response_bodies()
        await self._load_response_size_estimates()
        if not resume:
            return
        works = await self.service.list_resource_work(
            self.run_id, statuses={"queued", "reserved", "starting", "running"}
        )
        for work in works:
            if work["owner_type"] != "http_interaction":
                continue
            await self.service.update_resource_work(
                self.run_id, work["work_id"], status="interrupted"
            )
        active = await self.service.list_http_interactions(self.run_id)
        resume_analysis: list[tuple[dict[str, Any], int]] = []
        for row in active:
            self._repair_journal(row["agent_id"], row["interaction_id"])
            was_active = row["status"] in {"queued", "running", "analyzing"}
            can_resume_analysis = (
                row["status"] in {"queued", "running", "analyzing", "interrupted"}
                and row["execution_status"] == "completed"
                and row["analysis_status"] in {"queued", "running"}
                and row["output_cleaned_at"] is None
            )
            if not was_active and not can_resume_analysis:
                continue
            if was_active and row["execution_status"] != "completed":
                live = LiveInteraction(
                    row["interaction_id"],
                    row["agent_id"],
                    self._load_plan(row["agent_id"], row["interaction_id"]),
                )
                await self._record_unfinished_requests(live, outcome="interrupted")
                if row["kind"] in {"path_probe", "fingerprint"}:
                    self._write_stopped_summary_if_missing(
                        row["agent_id"], row["interaction_id"], reason="interrupted"
                    )
            await self.service.update_http_interaction(
                self.run_id,
                row["agent_id"],
                row["interaction_id"],
                status="interrupted",
                execution_status=(
                    "completed"
                    if row["execution_status"] == "completed"
                    else ("interrupted" if was_active else row["execution_status"])
                ),
                analysis_status=(
                    "queued" if can_resume_analysis else row["analysis_status"]
                ),
                resource_status="interrupted",
            )
            if can_resume_analysis:
                revisions = [
                    self._phase_revision(item["phase"])
                    for item in await self.service.list_resource_work(
                        self.run_id, owner_id=row["interaction_id"]
                    )
                    if item["phase"].startswith("analysis")
                ]
                resume_analysis.append((row, max(revisions, default=0) + 1))
        for row, revision in resume_analysis:
            live = LiveInteraction(
                row["interaction_id"],
                row["agent_id"],
                self._load_plan(row["agent_id"], row["interaction_id"]),
            )
            live.execution_done.set()
            self._live[row["interaction_id"]] = live
            await self._queue_analysis(live, revision=revision)

    async def start_request(
        self,
        agent_id: str,
        *,
        request: HttpRequestSpec,
        concurrency: int = 1,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
    ) -> dict[str, Any]:
        return await self.start_probe(
            agent_id,
            cases=[HttpProbeCase(request=request)],
            concurrency=concurrency,
            rate_limit_per_second=None,
            wait_seconds=wait_seconds,
            result_limit=result_limit,
            kind="request",
        )

    async def _build_plan(
        self, agent_id: str, cases: list[HttpProbeCase], interaction_id: str
    ) -> list[ExpandedRequest]:
        """Expand and check ownership without creating work or changing runtime state."""
        self._require_open()
        requests = self._engine(agent_id).expand_cases(
            cases,
            id_factory=lambda: uuid4().hex,
            default_group_id=interaction_id,
        )
        if not requests:
            error = self._error(
                "validation",
                "empty_http_interaction",
                "HTTP interaction must expand to at least one request",
            )
            error.detail["fields"] = [
                {"path": f"cases.{index}.variables", "code": error.code, "message": error.message}
                for index in range(len(cases))
            ]
            raise error
        expanded: list[ExpandedRequest] = []
        for item in requests:
            if (
                item.spec.parent_request_id is not None
                and not await self._request_owned(agent_id, item.spec.parent_request_id)
            ):
                raise self._error(
                    "not_found",
                    "parent_request_not_found",
                    "Parent request was not found",
                )
            if not await self._request_group_allowed(agent_id, item.request_group_id):
                raise self._error(
                    "not_found",
                    "request_group_not_found",
                    "Request group was not found",
                )
            context_id = item.spec.connection_context_id
            if context_id:
                sequence = item.spec.sequence_id
                if sequence is None:
                    sequence = await self._next_context_sequence(agent_id, context_id)
                item = replace(
                    item,
                    spec=item.spec.model_copy(
                        update={
                            "connection_context_id": context_id,
                            "sequence_id": sequence,
                        }
                    ),
                )
            expanded.append(item)
        return expanded

    async def plan(
        self, agent_id: str, arguments: HttpPlanArguments
    ) -> dict[str, Any]:
        from agent.tool_examples import examples_for

        try:
            if arguments.tool_name == "system_http_request":
                validated = HttpRequestArguments.model_validate(arguments.arguments)
                cases = [HttpProbeCase(request=validated.to_request_spec())]
            else:
                probe = HttpProbeArguments.model_validate(arguments.arguments)
                cases = [case.to_case() for case in probe.cases]
            group_id = f"plan-{uuid4().hex}"
            requests = await self._build_plan(agent_id, cases, group_id)
        except ValidationError as exc:
            fields = validation_details(exc)
            for item in fields:
                item["path"] = "arguments." + item["path"]
            return tool_error(
                "schema", "invalid_arguments", "Tool arguments failed schema validation",
                retry_allowed=True, retry_action="rewrite_arguments",
                retry_tool="system_http_plan",
                details={"fields": fields, "examples": examples_for(arguments.tool_name)},
            )
        except SystemToolError as exc:
            fields = exc.detail.get("fields") or [
                {"path": "", "code": exc.code, "message": exc.message}
            ]
            located = []
            for field in fields:
                path = field["path"]
                if arguments.tool_name == "system_http_request":
                    path = path.removeprefix("cases.0.")
                located.append({**field, "path": "arguments" + (f".{path}" if path else "")})
            exc.detail = {
                **exc.detail, "fields": located, "examples": examples_for(arguments.tool_name)
            }
            raise

        indices = {f"{group_id}-case-{index}": index for index in range(len(cases))}
        counts = [0] * len(cases)
        for item in requests:
            counts[indices[item.request_group_id]] += 1
        return {
            "tool_name": arguments.tool_name,
            "case_count": len(cases),
            "request_count": len(requests),
            "cases": [
                {"case_index": index, "request_count": count}
                for index, count in enumerate(counts)
            ],
            "previews": [
                {
                    "case_index": indices[item.request_group_id],
                    "request_index": item.ordinal,
                    "request": self._preview_request(item.spec),
                }
                for item in requests[:5]
            ],
            "preview_limit": 5,
            "previews_truncated": len(requests) > 5,
        }

    @staticmethod
    def _preview_request(spec: HttpRequestSpec) -> dict[str, Any]:
        """Mask credentials in a detached preview; opaque bodies are metadata only."""
        def sensitive(key: str) -> bool:
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            return (
                normalized in {
                    "authorization", "proxyauthorization", "cookie", "setcookie",
                    "password", "passwd", "pwd", "secret", "clientsecret",
                    "apikey", "xapikey", "credential", "credentials",
                }
                or normalized.endswith(("token", "password", "secret", "apikey"))
            )

        def mask(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    key: "[REDACTED]" if sensitive(str(key)) else mask(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [mask(item) for item in value]
            return value

        preview = mask({
            name: getattr(spec, name)
            for name in HttpRequestInput.model_fields
            if name not in {"auth", "body", "cookies"}
        })
        parts = urlsplit(str(effective_url(spec.url, spec.query)))
        netloc = parts.netloc
        if "@" in netloc:
            netloc = "%5BREDACTED%5D@" + netloc.rsplit("@", 1)[1]
        query = parts.query
        if any(sensitive(key) for key, _ in parse_qsl(query, keep_blank_values=True)):
            query = urlencode([
                (key, "[REDACTED]" if sensitive(key) else value)
                for key, value in parse_qsl(query, keep_blank_values=True)
            ])
        preview["url"] = urlunsplit(parts._replace(netloc=netloc, query=query))
        preview["cookies"] = {key: "[REDACTED]" for key in spec.cookies}
        preview["auth"] = (
            {key: value if key == "type" else "[REDACTED]"
             for key, value in spec.auth.model_dump(exclude_none=True).items()}
            if spec.auth else None
        )
        if spec.body is None:
            preview["body"] = None
        elif spec.body.type in {"raw", "base64"}:
            raw = (base64.b64decode(spec.body.value, validate=True)
                   if spec.body.type == "base64" else spec.body.value.encode("utf-8"))
            preview["body"] = {"type": spec.body.type, "byte_length": len(raw)}
        else:
            preview["body"] = mask(spec.body.model_dump(mode="json"))
        if spec.session_id is not None:
            preview["session_id"] = spec.session_id
            preview["update_session"] = spec.update_session
        return preview

    async def start_probe(
        self,
        agent_id: str,
        *,
        cases: list[HttpProbeCase],
        concurrency: int = 8,
        rate_limit_per_second: float | None = None,
        wait_seconds: float | None = 20.0,
        result_limit: int = 10,
        kind: str = "probe",
    ) -> dict[str, Any]:
        self._require_open()
        interaction_id = f"interaction-{uuid4().hex}"
        requests = await self._build_plan(agent_id, cases, interaction_id)
        template_summary = {
            "case_count": len(cases),
            "variable_names": sorted(
                {name for case in cases for name in case.variables}
            ),
            "combinations": [case.combine for case in cases],
            "expanded_requests": len(requests),
            "url_samples": [item.spec.url for item in requests[:3]],
        }
        interaction_dir, response_dir = await self._create_interaction_directories(
            agent_id, interaction_id
        )
        journal = interaction_dir / "results.jsonl"
        journal.touch(mode=0o600, exist_ok=False)
        plan_path = interaction_dir / "plan.json"
        self._write_private_json_atomic(
            plan_path,
            {
                "concurrency": concurrency,
                "rate_limit_per_second": rate_limit_per_second,
                "requests": [self._request_json(item) for item in requests],
                "template_summary": template_summary,
            },
        )
        estimate_per_response = await self._historical_response_estimate(requests)
        estimated_disk = len(requests) * estimate_per_response
        relative = self.policy.relative_lexical(interaction_dir)
        try:
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_http_interaction_with_work(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                work_id=work_id,
                kind=kind,
                result_path=relative,
                estimated_requests=len(requests),
                requested_concurrency=concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=concurrency * 65_536,
                estimated_analysis_work=len(requests),
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, requests)
        self._plan_cache[(agent_id, interaction_id)] = requests
        self._live[interaction_id] = live
        await self._wait(live.execution_done, wait_seconds)
        return await self._result_page(
            agent_id, interaction_id, cursor=0, limit=result_limit
        )

    async def start_path_probe(
        self,
        agent_id: str,
        *,
        url: str,
        profile: str,
        request_intent: str = "path_discovery",
        parent_request_id: str | None = None,
        request_group_id: str | None = None,
        session_id: str | None = None,
        extensions: list[str] | None = None,
        wordlist_paths: list[str] | None = None,
        packaged_wordlists: list[str] | None = None,
        max_candidates: int = 256,
        exclude_paths: list[str] | None = None,
        force_extensions: bool = False,
        include_status_codes: list[int] | None = None,
        exclude_status_codes: list[int] | None = None,
        recursion_depth: int = 0,
        recursion_status_codes: list[int] | None = None,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth: Any = None,
        follow_redirects: bool = False,
        verify_tls: bool = False,
        timeout_seconds: float | None = None,
        max_body_bytes: int | None = None,
        concurrency: int | None = None,
        rate_limit_per_second: float | None = None,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
    ) -> dict[str, Any]:
        self._require_open()
        if profile not in PROFILE_PRESETS:
            raise self._error(
                "validation", "invalid_path_probe_profile", "Unknown path probe profile"
            )
        if method.upper() not in {"GET", "HEAD"}:
            raise self._error(
                "validation",
                "invalid_path_probe_method",
                "Path probe supports only GET or HEAD",
            )
        if not url.lower().startswith(("http://", "https://")):
            raise self._error(
                "validation",
                "invalid_path_probe_url",
                "Path probe URL must use http or https",
            )
        if max_candidates < 1 or max_candidates > 1000:
            raise self._error(
                "validation",
                "invalid_path_probe_candidate_limit",
                "max_candidates must be between 1 and 1000",
            )
        preset = PROFILE_PRESETS[profile]
        interaction_id = f"interaction-{uuid4().hex}"
        group_id = request_group_id or interaction_id
        if parent_request_id is not None and not await self._request_owned(
            agent_id, parent_request_id
        ):
            raise self._error(
                "not_found", "parent_request_not_found", "Parent request was not found"
            )
        if not await self._request_group_allowed(agent_id, group_id):
            raise self._error(
                "not_found", "request_group_not_found", "Request group was not found"
            )
        options = PathProbeOptions(
            profile=profile,
            url=url,
            method=method.upper(),
            headers=dict(headers or {}),
            cookies=dict(cookies or {}),
            auth=auth,
            session_id=session_id,
            follow_redirects=follow_redirects,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds or preset["timeout_seconds"],
            concurrency=concurrency or preset["concurrency"],
            rate_limit_per_second=rate_limit_per_second,
            extensions=tuple(extensions) if extensions is not None else (),
            force_extensions=bool(force_extensions),
            wordlist_paths=tuple(wordlist_paths or ()),
            packaged_wordlists=tuple(packaged_wordlists or ()),
            max_candidates=int(max_candidates),
            exclude_paths=tuple(exclude_paths or ()),
            include_status_codes=frozenset(include_status_codes or ()),
            exclude_status_codes=frozenset(exclude_status_codes or {404}),
            recursion_depth=int(recursion_depth or 0),
            recursion_status_codes=frozenset(recursion_status_codes or {200, 301, 302}),
            max_body_bytes=max_body_bytes or preset["max_body_bytes"],
            request_intent=request_intent or "path_discovery",
            parent_request_id=parent_request_id,
            request_group_id=group_id,
        )
        engine = PathProbeEngine(
            self._engine(agent_id).policy, options, transport=self.path_transport
        )
        interaction_dir, response_dir = await self._create_interaction_directories(
            agent_id, interaction_id
        )
        journal = interaction_dir / "results.jsonl"
        journal.touch(mode=0o600, exist_ok=False)
        requests_path = interaction_dir / "requests.ndjson"
        request_count = 0
        with requests_path.open("w", encoding="utf-8") as output:
            for request_count, path in enumerate(engine.iter_paths(), start=1):
                output.write(
                    json.dumps(
                        {
                            "request_id": f"request-{uuid4().hex}",
                            "ordinal": request_count,
                            "path": path,
                            "request_group_id": group_id,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
            output.flush()
            os.fsync(output.fileno())
        os.chmod(requests_path, 0o600)
        if request_count == 0:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise self._error(
                "validation", "empty_path_probe", "Path probe wordlist is empty"
            )
        plan_path = interaction_dir / "plan.json"
        self._write_private_json_atomic(
            plan_path,
            {
                "kind": "path_probe",
                "options": options.to_plan(),
                "requests_file": "requests.ndjson",
                "request_count": request_count,
            },
        )
        estimate_per_response = min(65_536, options.max_body_bytes)
        estimated_disk = request_count * estimate_per_response
        relative = self.policy.relative_lexical(interaction_dir)
        estimated_requests = request_count + engine.calibration_budget()
        try:
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_http_interaction_with_work(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                work_id=work_id,
                kind="path_probe",
                result_path=relative,
                estimated_requests=estimated_requests,
                requested_concurrency=options.concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
                estimated_analysis_work=0,
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, [])
        self._plan_cache[(agent_id, interaction_id)] = []
        self._live[interaction_id] = live
        await self._wait(live.execution_done, wait_seconds)
        return await self._result_page(
            agent_id, interaction_id, cursor=0, limit=result_limit
        )

    async def start_fingerprint(
        self,
        agent_id: str,
        *,
        url: str,
        request_intent: str = "technology_fingerprint",
        parent_request_id: str | None = None,
        request_group_id: str | None = None,
        session_id: str | None = None,
        passive: bool = True,
        active: bool = True,
        minimum_confidence: str = "medium",
        include_favicon: bool = True,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth: Any = None,
        follow_redirects: bool = False,
        verify_tls: bool = False,
        timeout_seconds: float | None = None,
        concurrency: int | None = None,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
    ) -> dict[str, Any]:
        self._require_open()
        if not url.lower().startswith(("http://", "https://")):
            raise self._error(
                "validation",
                "invalid_fingerprint_url",
                "Fingerprint URL must use http or https",
            )
        interaction_id = f"interaction-{uuid4().hex}"
        group_id = request_group_id or interaction_id
        if parent_request_id is not None and not await self._request_owned(
            agent_id, parent_request_id
        ):
            raise self._error(
                "not_found", "parent_request_not_found", "Parent request was not found"
            )
        if not await self._request_group_allowed(agent_id, group_id):
            raise self._error(
                "not_found", "request_group_not_found", "Request group was not found"
            )
        options = FingerprintOptions(
            url=url,
            passive=bool(passive),
            active=bool(active),
            minimum_confidence=minimum_confidence,
            include_favicon=bool(include_favicon),
            headers=dict(headers or {}),
            cookies=dict(cookies or {}),
            auth=auth,
            session_id=session_id,
            follow_redirects=follow_redirects,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds or 10.0,
            concurrency=concurrency or 8,
            request_intent=request_intent or "technology_fingerprint",
            parent_request_id=parent_request_id,
            request_group_id=group_id,
        )
        active_paths = ActiveFingerprintEngine().all_paths() if options.active else []
        passive_requests = (
            1 + (1 if options.include_favicon else 0) if options.passive else 0
        )
        estimated_requests = passive_requests + len(active_paths)
        interaction_dir, response_dir = await self._create_interaction_directories(
            agent_id, interaction_id
        )
        journal = interaction_dir / "results.jsonl"
        journal.touch(mode=0o600, exist_ok=False)
        plan_path = interaction_dir / "plan.json"
        self._write_private_json_atomic(
            plan_path,
            {
                "kind": "fingerprint",
                "options": options.to_plan(),
                "requests": [{"path": path} for path in active_paths],
            },
        )
        relative = self.policy.relative_lexical(interaction_dir)
        estimated_disk = max(1, estimated_requests) * 65_536
        try:
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_http_interaction_with_work(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                work_id=work_id,
                kind="fingerprint",
                result_path=relative,
                estimated_requests=estimated_requests,
                requested_concurrency=options.concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
                estimated_analysis_work=0,
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, [])
        self._plan_cache[(agent_id, interaction_id)] = []
        self._live[interaction_id] = live
        await self._wait(live.execution_done, wait_seconds)
        return await self._result_page(
            agent_id, interaction_id, cursor=0, limit=result_limit
        )

    async def launch_work(
        self, interaction_id: str, phase: str, *, work_id: str | None = None
    ) -> None:
        row = await self._interaction_any_owner(interaction_id)
        live = self._live.get(interaction_id)
        if live is None:
            requests = self._load_plan(row["agent_id"], interaction_id)
            live = LiveInteraction(interaction_id, row["agent_id"], requests)
            self._live[interaction_id] = live
        if phase.startswith("execution"):
            if live.execution_task is not None and not live.execution_task.done():
                return
            work_id = work_id or self._work_id(interaction_id, "execution", 1)
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                interaction_id,
                status="running",
                execution_status="running",
                resource_status="running",
            )
            if row["kind"] == "fingerprint":
                runner = self._run_fingerprint_execution
            elif row["kind"] == "path_probe":
                runner = self._run_path_execution
            else:
                runner = self._run_execution
            live.execution_task = asyncio.create_task(
                self._run_with_reclamation(live, runner(live, work_id)),
                name=f"aion-http-execution-{interaction_id}",
            )
        else:
            if live.analysis_task is not None and not live.analysis_task.done():
                return
            revision = self._phase_revision(phase)
            work_id = work_id or self._work_id(interaction_id, "analysis", revision)
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                interaction_id,
                status="analyzing",
                analysis_status="running",
                resource_status="running",
            )
            live.analysis_task = asyncio.create_task(
                self._run_with_reclamation(
                    live,
                    self._run_analysis(live, work_id, revision=revision),
                ),
                name=f"aion-http-analysis-{interaction_id}-{revision}",
            )

    async def _run_with_reclamation(
        self,
        live: LiveInteraction,
        operation: Awaitable[None],
    ) -> None:
        cancelled = False
        try:
            await operation
        except asyncio.CancelledError:
            cancelled = True
            raise
        finally:
            if not cancelled:
                try:
                    await self._reclaim_terminal_response_bodies(
                        exclude_interaction_ids={live.interaction_id}
                    )
                except Exception:
                    LOGGER.exception(
                        "http_body_reclaim_failed run_id=%s trigger=work_finished",
                        self.run_id,
                    )

    async def output(
        self,
        agent_id: str,
        *,
        interaction_id: str,
        cursor: int = 0,
        limit: int = 100,
        wait_seconds: float | None = 0.0,
        filters: HttpOutputFilters | None = None,
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        live = self._live.get(interaction_id)
        if row["output_cleaned_at"] is None and live is not None and wait_seconds != 0:
            live.changed.clear()
            # Close the clear/read/wait lost-wakeup window: after clearing the
            # signal, reread both the journal cursor and authoritative state.
            row = await self._owned(agent_id, interaction_id)
            before = self._journal_path(agent_id, interaction_id).stat().st_size
            active = row["status"] not in TERMINAL or row["analysis_status"] in {
                "queued",
                "running",
            }
            if before <= cursor and active:
                await self._wait(live.changed, wait_seconds)
        return await self._result_page(
            agent_id,
            interaction_id,
            cursor=cursor,
            limit=limit,
            filters=filters,
        )

    async def response(
        self,
        agent_id: str,
        *,
        interaction_id: str,
        request_id: str,
        offset_bytes: int = 0,
        length_bytes: int = 30_000,
    ) -> dict[str, Any]:
        await self._owned(agent_id, interaction_id)
        record = self._response_record(agent_id, interaction_id, request_id)
        if record is None or record.get("body_file") is None:
            raise self._error(
                "not_found",
                "http_response_not_found",
                "HTTP response body was not found",
                detail={
                    "interaction_id": interaction_id,
                    "requested_request_id": request_id,
                    "available_request_ids": [
                        item["request_id"]
                        for item in self._request_catalog(agent_id, interaction_id)
                        if item.get("response_available")
                    ][:200],
                    "retry_action": "rewrite_arguments",
                },
            )
        path = self._response_dir(agent_id, interaction_id) / str(record["body_file"])
        if not path.exists():
            raise self._error(
                "not_found",
                "http_response_body_reclaimed",
                "HTTP response body was reclaimed under disk pressure",
                detail={
                    "interaction_id": interaction_id,
                    "requested_request_id": request_id,
                    "recommended_action": "repeat_request_if_still_required",
                },
            )
        with path.open("rb") as source:
            source.seek(offset_bytes)
            data = source.read(length_bytes)
        content_type = str(record.get("content_type") or "")
        if self.engine._is_binary(data, content_type):
            content = base64.b64encode(data).decode("ascii")
            encoding = "base64"
        else:
            charset = self.engine._charset(content_type)
            try:
                content = data.decode(charset)
                encoding = "utf-8"
            except (LookupError, UnicodeDecodeError):
                try:
                    content = data.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    content = base64.b64encode(data).decode("ascii")
                    encoding = "base64"
        result = {
            "interaction_id": interaction_id,
            "request_id": request_id,
            "offset_bytes": offset_bytes,
            "bytes_returned": len(data),
            "next_offset": offset_bytes + len(data),
            "eof": offset_bytes + len(data) >= path.stat().st_size,
            "encoding": encoding,
            "content": content,
            "body_sha256": record.get("body_sha256"),
            "body_bytes": path.stat().st_size,
        }
        if offset_bytes == 0:
            result["headers"] = record.get("headers", {})
        return result

    async def analyze(
        self,
        agent_id: str,
        *,
        interaction_id: str,
        request_ids: list[str] | None = None,
        request_group_id: str | None = None,
        similarity: bool = True,
        features: bool = True,
        summary: bool = True,
        force: bool = False,
        wait_seconds: float | None = 20.0,
        cursor: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        if row["kind"] in {"path_probe", "fingerprint"}:
            raise self._error(
                "validation",
                "scan_analysis_not_supported",
                "Path probe and fingerprint interactions do not support asynchronous analysis",
            )
        live = self._live.get(interaction_id)
        if row["analysis_status"] in {"queued", "running"}:
            if live is not None:
                await self._wait(live.analysis_done, wait_seconds)
            row = await self._owned(agent_id, interaction_id)

        create_analysis = row["analysis_status"] == "not_requested" or (
            force and row["analysis_status"] == "completed"
        )
        if force and row["analysis_status"] not in {
            "not_requested",
            "completed",
            "queued",
            "running",
        }:
            raise self._error(
                "conflict",
                "http_analysis_not_repeatable",
                "A new analysis revision requires a previously completed analysis",
            )
        if create_analysis:
            if row["execution_status"] != "completed":
                raise self._error(
                    "conflict",
                    "http_execution_not_completed",
                    "HTTP response analysis requires a completed request phase",
                )
            responses = self._response_records(agent_id, interaction_id)
            response_ids = {str(item["request_id"]) for item in responses}
            unknown_ids = set(request_ids or []) - response_ids
            if unknown_ids:
                raise self._error(
                    "not_found",
                    "http_request_not_found",
                    "HTTP request was not found in this interaction",
                )
            if request_group_id is not None and not any(
                item.get("request_group_id") == request_group_id for item in responses
            ):
                raise self._error(
                    "not_found",
                    "request_group_not_found",
                    "Request group was not found in this interaction",
                )
            selected_responses = responses
            if request_ids:
                selected = set(request_ids)
                selected_responses = [
                    item
                    for item in selected_responses
                    if item.get("request_id") in selected
                ]
            if request_group_id is not None:
                selected_responses = [
                    item
                    for item in selected_responses
                    if item.get("request_group_id") == request_group_id
                ]
            lock = self._interaction_locks.setdefault(
                (agent_id, interaction_id), asyncio.Lock()
            )
            async with lock:
                reclaimed_ids = [
                    str(item["request_id"])
                    for item in selected_responses
                    if item.get("body_file")
                    and not self._response_body_available(
                        agent_id, interaction_id, item
                    )
                ]
                if reclaimed_ids:
                    raise self._error(
                        "not_found",
                        "http_response_body_reclaimed",
                        "HTTP response bodies were reclaimed under disk pressure",
                        detail={
                            "interaction_id": interaction_id,
                            "request_ids": reclaimed_ids[:200],
                            "recommended_action": "repeat_request_if_still_required",
                        },
                    )
                revision = await self._next_analysis_revision(agent_id, interaction_id)
                self._analysis_scopes[(interaction_id, revision)] = (
                    set(request_ids or []),
                    request_group_id,
                )
                if live is None:
                    live = LiveInteraction(
                        interaction_id,
                        agent_id,
                        self._load_plan(agent_id, interaction_id),
                    )
                    self._live[interaction_id] = live
                live.analysis_done.clear()
                try:
                    await self._queue_analysis(live, revision=revision)
                except Exception:
                    self._analysis_scopes.pop((interaction_id, revision), None)
                    live.analysis_done.set()
                    live.changed.set()
                    raise
        if live is not None:
            await self._wait(live.analysis_done, wait_seconds)
        filters = HttpOutputFilters(
            request_ids=list(request_ids or []),
            request_group_id=request_group_id,
        )
        page = await self._result_page(
            agent_id,
            interaction_id,
            cursor=cursor,
            limit=limit,
            filters=filters,
            record_types={"analysis"},
        )
        if not similarity:
            page["similarity_groups"] = []
            for item in page["results"]:
                item.pop("similarity_hash", None)
                item.pop("similarity_group", None)
        if not features:
            for item in page["results"]:
                item.pop("features", None)
        if not summary:
            for item in page["results"]:
                item.pop("summary", None)
        return page

    async def stop(self, agent_id: str, *, interaction_id: str) -> dict[str, Any]:
        lock = self._interaction_locks.setdefault(
            (agent_id, interaction_id), asyncio.Lock()
        )
        async with lock:
            return await self._stop_interaction(agent_id, interaction_id)

    async def _stop_interaction(
        self, agent_id: str, interaction_id: str
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        if row["status"] in TERMINAL:
            if row["output_cleaned_at"] is not None:
                return {
                    "interaction_id": interaction_id,
                    "status": row["status"],
                    "stopped": row["status"] == "stopped",
                    "output_cleaned": True,
                }
            return await self._result_page(agent_id, interaction_id, cursor=0, limit=1)
        live = self._live.get(interaction_id)
        if live is not None:
            live.stop_requested = True
            for task in (live.execution_task, live.analysis_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (live.execution_task, live.analysis_task) if task),
                return_exceptions=True,
            )
            await self._record_unfinished_requests(live, outcome="stopped")
            live.execution_done.set()
            live.analysis_done.set()
            live.changed.set()
            row = await self._owned(agent_id, interaction_id)
        if row["kind"] in {"path_probe", "fingerprint"}:
            self._write_stopped_summary_if_missing(
                agent_id, interaction_id, reason="stopped"
            )
        works = await self.service.list_resource_work(
            self.run_id,
            owner_id=interaction_id,
            statuses={"queued", "reserved", "starting", "running"},
        )
        for work in works:
            await self.service.update_resource_work(
                self.run_id, work["work_id"], status="stopped"
            )
        await self.service.update_http_interaction(
            self.run_id,
            agent_id,
            interaction_id,
            status="stopped",
            execution_status=(
                row["execution_status"]
                if row["execution_status"] == "completed"
                else "stopped"
            ),
            analysis_status=(
                row["analysis_status"]
                if row["analysis_status"] in {"completed", "not_requested"}
                else "interrupted"
            ),
            resource_status="stopped",
        )
        return await self._result_page(agent_id, interaction_id, cursor=0, limit=1)

    async def cleanup(self, agent_id: str, *, interaction_id: str) -> dict[str, Any]:
        lock = self._interaction_locks.setdefault(
            (agent_id, interaction_id), asyncio.Lock()
        )
        async with lock:
            return await self._cleanup_interaction(agent_id, interaction_id)

    async def _cleanup_interaction(
        self, agent_id: str, interaction_id: str
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        if row["status"] not in TERMINAL:
            raise self._error(
                "conflict",
                "http_interaction_running",
                "Active HTTP interaction must be stopped before cleanup",
                detail={
                    "interaction_id": interaction_id,
                    "required_tool": "system_http_stop",
                    "recommended_action": "stop_then_cleanup",
                    "recommended_wait_seconds": 20,
                },
            )
        if row["output_cleaned_at"] is not None:
            return {
                "interaction_id": interaction_id,
                "cleaned": False,
                "already_cleaned": True,
            }
        path = self._interaction_dir(agent_id, interaction_id)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
        self._drop_interaction_caches(agent_id, interaction_id)
        await self.service.mark_http_interaction_cleaned(
            self.run_id, agent_id, interaction_id, reason="explicit"
        )
        return {
            "interaction_id": interaction_id,
            "cleaned": True,
            "already_cleaned": False,
        }

    async def finish_agent(self, agent_id: str) -> None:
        rows = await self.service.list_http_interactions(self.run_id, agent_id=agent_id)
        results = await asyncio.gather(
            *(
                self._finish_agent_interaction(agent_id, str(row["interaction_id"]))
                for row in rows
            ),
            self._engine(agent_id).close_agent(agent_id),
            return_exceptions=True,
        )
        failures = [result for result in results if isinstance(result, Exception)]
        session_dir = self._agent_root(agent_id) / "http-sessions"
        try:
            if session_dir.exists():
                shutil.rmtree(session_dir)
        except FileNotFoundError:
            pass
        except OSError as exc:
            failures.append(exc)
        if failures:
            raise ExceptionGroup("HTTP Agent cleanup failed", failures)

    async def _finish_agent_interaction(
        self, agent_id: str, interaction_id: str
    ) -> None:
        lock = self._interaction_locks.setdefault(
            (agent_id, interaction_id), asyncio.Lock()
        )
        async with lock:
            current = await self._owned(agent_id, interaction_id)
            try:
                if current["status"] not in TERMINAL:
                    await self._stop_interaction(agent_id, interaction_id)
            except (FileNotFoundError, NotADirectoryError):
                # A request worker may have removed its private directory
                # just before terminal cleanup acquired the interaction
                # lock. The durable row is still authoritative, so this
                # interaction is already stopped for cleanup purposes.
                pass
            path = self._interaction_dir(agent_id, interaction_id)
            try:
                if path.exists():
                    shutil.rmtree(path)
            except (FileNotFoundError, NotADirectoryError):
                pass
            self._drop_interaction_caches(agent_id, interaction_id)
            current = await self._owned(agent_id, interaction_id)
            if current["output_cleaned_at"] is None:
                await self.service.mark_http_interaction_cleaned(
                    self.run_id,
                    agent_id,
                    interaction_id,
                    reason="agent_terminal",
                )

    async def finish_run(self) -> None:
        rows = await self.service.list_http_interactions(self.run_id)
        for agent_id in sorted({str(row["agent_id"]) for row in rows}):
            await self.finish_agent(agent_id)
        await asyncio.gather(
            self.engine.aclose(),
            *(engine.aclose() for engine in self._agent_engines.values()),
        )
        self._closed = True

    async def pause_run(self) -> None:
        rows = await self.service.list_http_interactions(
            self.run_id, statuses={"queued", "running", "analyzing"}
        )
        for row in rows:
            live = self._live.get(row["interaction_id"])
            if live is not None:
                for task in (live.execution_task, live.analysis_task):
                    if task is not None and not task.done():
                        task.cancel()
                await asyncio.gather(
                    *(
                        task
                        for task in (live.execution_task, live.analysis_task)
                        if task
                    ),
                    return_exceptions=True,
                )
                await self._record_unfinished_requests(live, outcome="interrupted")
            if row["kind"] in {"path_probe", "fingerprint"}:
                self._write_stopped_summary_if_missing(
                    row["agent_id"], row["interaction_id"], reason="interrupted"
                )
            current = await self._owned(row["agent_id"], row["interaction_id"])
            works = await self.service.list_resource_work(
                self.run_id,
                owner_id=row["interaction_id"],
                statuses={"queued", "reserved", "starting", "running"},
            )
            for work in works:
                await self.service.update_resource_work(
                    self.run_id, work["work_id"], status="interrupted"
                )
            await self.service.update_http_interaction(
                self.run_id,
                row["agent_id"],
                row["interaction_id"],
                status="interrupted",
                execution_status=(
                    "completed"
                    if current["execution_status"] == "completed"
                    else "interrupted"
                ),
                analysis_status=(
                    current["analysis_status"]
                    if current["analysis_status"] in {"completed", "not_requested"}
                    else "interrupted"
                ),
                resource_status="interrupted",
            )
        self._live.clear()
        await asyncio.gather(
            self.engine.aclose(),
            *(engine.aclose() for engine in self._agent_engines.values()),
        )
        self._closed = True

    async def _run_execution(self, live: LiveInteraction, work_id: str) -> None:
        row = await self._owned(live.agent_id, live.interaction_id)
        plan = self._plan(live.agent_id, live.interaction_id)
        concurrency = int(plan.get("concurrency", row["requested_concurrency"]))
        rate = plan.get("rate_limit_per_second")
        semaphore = asyncio.Semaphore(concurrency)
        rate_lock = asyncio.Lock()
        next_start = 0.0
        started = 0
        completed = 0
        response_bytes = 0
        storage_failure = False
        await self.service.update_http_interaction(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            status="running",
            execution_status="running",
            resource_status="running",
        )

        async def one(item: ExpandedRequest) -> None:
            nonlocal started, completed, response_bytes, next_start, storage_failure
            async with semaphore:
                if live.stop_requested:
                    return
                await self._await_resources(live, work_id)
                if live.stop_requested:
                    return
                if rate:
                    async with rate_lock:
                        loop = asyncio.get_running_loop()
                        delay = max(0.0, next_start - loop.time())
                        if delay:
                            await asyncio.sleep(delay)
                        next_start = loop.time() + 1.0 / float(rate)
                await self._append(
                    live, {"type": "request_started", **self._request_json(item)}
                )
                started += 1
                if started == 1 or started % 25 == 0:
                    await self.service.update_http_interaction(
                        self.run_id,
                        live.agent_id,
                        live.interaction_id,
                        started_requests=started,
                    )
                body_path = (
                    self._response_dir(live.agent_id, live.interaction_id)
                    / f"{item.request_id}.body"
                )
                if item.spec.session_id:
                    lock = self._session_locks.setdefault(
                        (live.agent_id, item.spec.session_id), asyncio.Lock()
                    )
                    async with lock:
                        session = self._load_session(
                            live.agent_id, item.spec.session_id
                        )
                        result, response_cookies = await self._engine(
                            live.agent_id
                        ).execute(
                            item,
                            body_path=body_path,
                            agent_id=live.agent_id,
                            session_cookies=list(session.get("cookies", [])),
                        )
                        if item.spec.update_session:
                            self._save_session(
                                live.agent_id,
                                item.spec.session_id,
                                response_cookies,
                                interaction_id=live.interaction_id,
                                request_id=item.request_id,
                            )
                else:
                    session = self._load_session(live.agent_id, item.spec.session_id)
                    result, _ = await self._engine(live.agent_id).execute(
                        item,
                        body_path=body_path,
                        agent_id=live.agent_id,
                        session_cookies=list(session.get("cookies", [])),
                    )
                await self._append(live, result)
                if result["outcome"] == "response":
                    self._observe_response_size(
                        item.spec.url, int(result.get("body_bytes") or 0)
                    )
                if result["outcome"] == "storage_error":
                    storage_failure = True
                    live.stop_requested = True
                completed += 1
                response_bytes += int(result["body_bytes"])
                if completed % 25 == 0:
                    await self.service.update_http_interaction(
                        self.run_id,
                        live.agent_id,
                        live.interaction_id,
                        started_requests=started,
                        completed_requests=completed,
                        response_bytes=response_bytes,
                    )

        try:
            session_requests: dict[str, list[ExpandedRequest]] = {}
            context_requests: dict[str, list[ExpandedRequest]] = {}
            independent: list[ExpandedRequest] = []
            for item in live.requests:
                if item.spec.connection_context_id:
                    context_requests.setdefault(
                        item.spec.connection_context_id, []
                    ).append(item)
                elif item.spec.session_id:
                    session_requests.setdefault(item.spec.session_id, []).append(item)
                else:
                    independent.append(item)

            async def ordered_sequence(
                items: list[ExpandedRequest],
                *,
                key: Callable[[ExpandedRequest], Any],
            ) -> None:
                for item in sorted(items, key=key):
                    await one(item)

            await asyncio.gather(
                *(one(item) for item in independent),
                *(
                    ordered_sequence(items, key=lambda value: value.ordinal)
                    for items in session_requests.values()
                ),
                *(
                    ordered_sequence(
                        items,
                        key=lambda value: (
                            value.spec.sequence_id
                            if value.spec.sequence_id is not None
                            else value.ordinal
                        ),
                    )
                    for items in context_requests.values()
                ),
            )
            if storage_failure:
                raise OSError("HTTP response storage failed")
            await self.service.update_resource_work(
                self.run_id, work_id, status="completed"
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="completed",
                execution_status="completed",
                analysis_status="not_requested",
                resource_status="completed",
                started_requests=started,
                completed_requests=completed,
                response_bytes=response_bytes,
            )
            live.execution_done.set()
            live.changed.set()
        except asyncio.CancelledError:
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                started_requests=started,
                completed_requests=completed,
                response_bytes=response_bytes,
            )
            live.execution_done.set()
            live.changed.set()
            raise
        except Exception as exc:
            await self.service.update_resource_work(
                self.run_id, work_id, status="failed", reason=type(exc).__name__
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="failed",
                execution_status="failed",
                analysis_status="not_requested",
                resource_status="failed",
                error_code=type(exc).__name__,
                started_requests=started,
                completed_requests=completed,
                response_bytes=response_bytes,
            )
            live.execution_done.set()
            live.analysis_done.set()
            live.changed.set()

    async def _run_path_execution(self, live: LiveInteraction, work_id: str) -> None:
        row = await self._owned(live.agent_id, live.interaction_id)
        plan = self._plan(live.agent_id, live.interaction_id)
        options = PathProbeOptions.from_plan(plan["options"])
        engine = PathProbeEngine(
            self._engine(live.agent_id).policy,
            options,
            transport=self.path_transport,
        )
        interaction_dir = self._interaction_dir(live.agent_id, live.interaction_id)
        requests_path = interaction_dir / str(plan["requests_file"])
        request_count = int(plan["request_count"])
        session = self._load_session(live.agent_id, options.session_id)
        body_dir = self._response_dir(live.agent_id, live.interaction_id)
        body_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        await self.service.update_http_interaction(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            status="running",
            execution_status="running",
            resource_status="running",
        )
        started = 0
        completed = 0
        matched = 0
        body_bytes = 0

        async def on_match(match: PathProbeMatch) -> None:
            nonlocal matched, body_bytes
            await self._append(live, self._path_probe_record(match, options))
            matched += 1
            body_bytes += int(match.length or 0)

        async def on_progress(
            current_started: int,
            current_completed: int,
            current_matched: int,
            current_bytes: int,
        ) -> None:
            nonlocal started, completed, matched, body_bytes
            started, completed, matched, body_bytes = (
                current_started,
                current_completed,
                current_matched,
                current_bytes,
            )
            if current_completed % 50 == 0:
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    started_requests=started,
                    completed_requests=completed,
                    response_bytes=body_bytes,
                )

        async def on_estimate(total_requests: int) -> None:
            estimate_per_response = min(65_536, options.max_body_bytes)
            await self.service.update_resource_work_estimate(
                self.run_id,
                work_id,
                estimated_requests=total_requests,
                estimated_disk_bytes=total_requests * estimate_per_response,
            )

        try:
            result = await engine.run(
                plan_path=requests_path,
                root_count=request_count,
                body_dir=body_dir,
                session_cookies=session.get("cookies", []),
                on_match=on_match,
                on_progress=on_progress,
                on_estimate=on_estimate,
                stop_requested=lambda: live.stop_requested,
                resource_guard=lambda: self._await_resources(live, work_id),
            )
        except asyncio.CancelledError:
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                started_requests=started,
                completed_requests=completed,
                response_bytes=body_bytes,
            )
            live.execution_done.set()
            live.changed.set()
            raise
        except Exception as exc:
            await self.service.update_resource_work(
                self.run_id, work_id, status="failed", reason=type(exc).__name__
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="failed",
                execution_status="failed",
                analysis_status="interrupted",
                resource_status="failed",
                error_code=type(exc).__name__,
                started_requests=started,
                completed_requests=completed,
                response_bytes=body_bytes,
            )
            live.execution_done.set()
            live.analysis_done.set()
            live.changed.set()
            return
        try:
            summary = self._path_probe_summary(
                options,
                result,
                estimated_requests=request_count,
            )
            self._write_summary(live.agent_id, live.interaction_id, summary)
            if result.stopped:
                await self.service.update_resource_work(
                    self.run_id, work_id, status="stopped"
                )
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    status="stopped",
                    execution_status="stopped",
                    analysis_status="completed",
                    resource_status="stopped",
                    started_requests=result.started,
                    completed_requests=result.completed,
                    response_bytes=result.body_bytes,
                )
            elif result.storage_failure or result.abort_reason:
                reason = result.abort_reason or "storage_error"
                await self.service.update_resource_work(
                    self.run_id, work_id, status="failed", reason=reason
                )
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    status="failed",
                    execution_status="failed",
                    analysis_status="interrupted",
                    resource_status="failed",
                    error_code=reason,
                    started_requests=result.started,
                    completed_requests=result.completed,
                    response_bytes=result.body_bytes,
                )
            else:
                await self.service.update_resource_work(
                    self.run_id, work_id, status="completed"
                )
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    status="completed",
                    execution_status="completed",
                    analysis_status="completed",
                    resource_status="completed",
                    started_requests=result.started,
                    completed_requests=result.completed,
                    response_bytes=result.body_bytes,
                )
        except Exception as exc:
            await self.service.update_resource_work(
                self.run_id, work_id, status="failed", reason=type(exc).__name__
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="failed",
                execution_status="failed",
                analysis_status="interrupted",
                resource_status="failed",
                error_code=type(exc).__name__,
                started_requests=result.started,
                completed_requests=result.completed,
                response_bytes=result.body_bytes,
            )
        finally:
            live.execution_done.set()
            live.analysis_done.set()
            live.changed.set()

    @staticmethod
    def _path_probe_record(
        match: PathProbeMatch, options: PathProbeOptions
    ) -> dict[str, Any]:
        full_path = f"{match.directory}{match.path}" if match.directory else match.path
        return {
            "type": "response",
            "request_id": match.request_id,
            "ordinal": match.ordinal,
            "request_intent": options.request_intent,
            "parent_request_id": options.parent_request_id,
            "request_group_id": match.request_group_id,
            "variables": {
                "path": match.path,
                "directory": match.directory,
                "depth": match.depth,
            },
            "outcome": "response",
            "status_code": match.status,
            "final_url": match.url,
            "elapsed_ms": match.elapsed_ms,
            "body_bytes": match.length,
            "content_length": match.header_features.get("content-length"),
            "body_sha256": match.body_sha256,
            "line_count": match.line_count,
            "body_complete": match.body_complete,
            "content_type": match.content_type,
            "location": match.redirect,
            "title": match.title,
            "headers": match.header_features,
            "error": None,
            "body_file": match.body_file,
            "path": full_path,
            "profile": options.profile,
        }

    @staticmethod
    def _path_probe_summary(
        options: PathProbeOptions,
        result: PathProbeRunResult,
        *,
        estimated_requests: int,
    ) -> dict[str, Any]:
        return {
            "kind": "path_probe",
            "profile": options.profile,
            "url": options.url,
            "estimated_requests": estimated_requests,
            "started_requests": result.started,
            "completed_requests": result.completed,
            "matched_requests": result.matched,
            "response_bytes": result.body_bytes,
            "by_status": result.by_status,
            "errors": result.errors,
            "calibration_requests": result.calibration_requests,
            "recursion_skipped": result.recursion_skipped,
            "stopped": result.stopped,
            "storage_failure": result.storage_failure,
            "abort_reason": result.abort_reason,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_ms": result.duration_ms,
        }

    def _write_summary(
        self, agent_id: str, interaction_id: str, summary: dict[str, Any]
    ) -> None:
        path = self._interaction_dir(agent_id, interaction_id) / "summary.json"
        self._write_private_json_atomic(path, summary)

    def _load_summary(
        self, agent_id: str, interaction_id: str
    ) -> dict[str, Any] | None:
        path = self._interaction_dir(agent_id, interaction_id) / "summary.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_stopped_summary_if_missing(
        self, agent_id: str, interaction_id: str, *, reason: str
    ) -> None:
        if self._load_summary(agent_id, interaction_id) is not None:
            return
        try:
            plan = self._plan(agent_id, interaction_id)
        except (FileNotFoundError, NotADirectoryError):
            # Agent cleanup may have already removed this private interaction.
            # Stop and Run cleanup are idempotent, so no synthetic summary is
            # needed once the authoritative state has been marked terminal.
            return
        if plan.get("kind") == "fingerprint":
            options = FingerprintOptions.from_plan(plan["options"])
            result = FingerprintScanResult(
                stopped=True,
                started_at=_now_iso(),
                finished_at=_now_iso(),
            )
            summary = self._fingerprint_summary(options, result)
            summary["stopped_reason"] = reason
            self._write_summary(agent_id, interaction_id, summary)
            return
        options = PathProbeOptions.from_plan(plan["options"])
        result = PathProbeRunResult(
            stopped=True,
            started_at=_now_iso(),
            finished_at=_now_iso(),
        )
        summary = self._path_probe_summary(options, result, estimated_requests=0)
        summary["stopped_reason"] = reason
        self._write_summary(agent_id, interaction_id, summary)

    async def _run_fingerprint_execution(
        self, live: LiveInteraction, work_id: str
    ) -> None:
        plan = self._plan(live.agent_id, live.interaction_id)
        options = FingerprintOptions.from_plan(plan["options"])
        scanner = FingerprintScanner(options, transport=self.path_transport)
        session = self._load_session(live.agent_id, options.session_id)
        await self.service.update_http_interaction(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            status="running",
            execution_status="running",
            resource_status="running",
        )
        ordinal = 0

        async def on_match(match: FingerprintMatch) -> None:
            nonlocal ordinal
            ordinal += 1
            await self._append(
                live,
                self._fingerprint_record(match, options, ordinal=ordinal),
            )

        try:
            result = await scanner.scan(
                session_cookies=session.get("cookies", []),
                on_match=on_match,
                stop_requested=lambda: live.stop_requested,
                resource_guard=lambda: self._await_resources(live, work_id),
            )
        except asyncio.CancelledError:
            live.execution_done.set()
            live.changed.set()
            raise
        except Exception as exc:
            await self.service.update_resource_work(
                self.run_id, work_id, status="failed", reason=type(exc).__name__
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="failed",
                execution_status="failed",
                analysis_status="interrupted",
                resource_status="failed",
                error_code=type(exc).__name__,
            )
            live.execution_done.set()
            live.analysis_done.set()
            live.changed.set()
            return
        summary = self._fingerprint_summary(options, result)
        self._write_summary(live.agent_id, live.interaction_id, summary)
        if result.stopped:
            await self.service.update_resource_work(
                self.run_id, work_id, status="stopped"
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="stopped",
                execution_status="stopped",
                analysis_status="completed",
                resource_status="stopped",
            )
        else:
            await self.service.update_resource_work(
                self.run_id, work_id, status="completed"
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="completed",
                execution_status="completed",
                analysis_status="completed",
                resource_status="completed",
            )
        live.execution_done.set()
        live.analysis_done.set()
        live.changed.set()

    @staticmethod
    def _fingerprint_record(
        match: FingerprintMatch,
        options: FingerprintOptions,
        *,
        ordinal: int,
    ) -> dict[str, Any]:
        return {
            "type": "fingerprint",
            "request_id": f"fingerprint-{uuid4().hex}",
            "ordinal": ordinal,
            "request_intent": options.request_intent,
            "parent_request_id": options.parent_request_id,
            "request_group_id": options.request_group_id or "",
            "source": match.source,
            "rule_id": match.rule_id,
            "rule_sources": match.rule_sources,
            "name": match.name,
            "category": match.category,
            "version": match.version,
            "matched_path": match.matched_path,
            "evidence": match.evidence,
            "confidence_score": match.confidence_score,
            "confidence_level": match.confidence_level,
            "confidence_reasons": match.confidence_reasons,
            "url": options.url,
        }

    @staticmethod
    def _fingerprint_summary(
        options: FingerprintOptions,
        result: FingerprintScanResult,
    ) -> dict[str, Any]:
        matched = result.passive_matched + result.active_matched
        return {
            "kind": "fingerprint",
            "url": options.url,
            "matched_requests": matched,
            "matched": matched,
            "passive": {
                "enabled": options.passive,
                "requests": result.passive_requests,
                "matched": result.passive_matched,
            },
            "active": {
                "enabled": options.active,
                "requests": result.active_requests,
                "matched": result.active_matched,
            },
            "errors": result.errors,
            "by_category": result.by_category,
            "rule_diagnostics": result.rule_diagnostics,
            "minimum_confidence": options.minimum_confidence,
            "suppressed_match_count": result.suppressed_match_count,
            "stopped": result.stopped,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_ms": result.duration_ms,
        }

    async def _queue_analysis(self, live: LiveInteraction, *, revision: int) -> None:
        row = await self._owned(live.agent_id, live.interaction_id)
        response_records = self._response_records(live.agent_id, live.interaction_id)
        largest_response = max(
            (int(item.get("body_bytes") or 0) for item in response_records),
            default=0,
        )
        work_id = self._work_id(live.interaction_id, "analysis", revision)
        await self.service.queue_http_analysis_work(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            work_id=work_id,
            revision=revision,
            estimated_requests=row["completed_requests"],
            estimated_memory_bytes=max(65_536, largest_response),
        )
        return None

    async def _run_analysis(
        self, live: LiveInteraction, work_id: str, *, revision: int
    ) -> None:
        await self.service.update_http_interaction(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            status="analyzing",
            analysis_status="running",
            resource_status="running",
        )
        responses = [
            item
            for item in self._response_records(live.agent_id, live.interaction_id)
            if item.get("outcome") == "response" and item.get("body_file")
        ]
        selected_ids, selected_group = self._analysis_scopes.get(
            (live.interaction_id, revision), (set(), None)
        )
        if selected_ids:
            responses = [
                item for item in responses if item.get("request_id") in selected_ids
            ]
        if selected_group is not None:
            responses = [
                item
                for item in responses
                if item.get("request_group_id") == selected_group
            ]
        representatives: list[tuple[int, str]] = []
        similarity_buckets: dict[tuple[int, int], list[int]] = {}
        analyzed = 0
        analyzed_request_ids = {
            str(item["request_id"])
            for item in self._all_records(live.agent_id, live.interaction_id)
            if item.get("type") == "analysis" and item.get("request_id")
        }
        try:
            for response in responses:
                if live.stop_requested:
                    break
                body_file = response.get("body_file")
                body_path = (
                    self._response_dir(live.agent_id, live.interaction_id)
                    / str(body_file)
                    if body_file
                    else Path("/nonexistent")
                )
                analysis = self.engine.analyze(response, body_path, revision=revision)
                simhash = analysis.get("similarity_hash")
                if simhash is not None:
                    value = int(simhash, 16)
                    analysis["similarity_group"] = self._assign_similarity_group(
                        value, representatives, similarity_buckets
                    )
                await self._append(live, analysis)
                analyzed += 1
                analyzed_request_ids.add(str(response["request_id"]))
                if analyzed == 1 or analyzed % 25 == 0:
                    await self.service.update_http_interaction(
                        self.run_id,
                        live.agent_id,
                        live.interaction_id,
                        analyzed_responses=len(analyzed_request_ids),
                    )
            await self.service.update_resource_work(
                self.run_id, work_id, status="completed"
            )
            execution = await self._owned(live.agent_id, live.interaction_id)
            execution_status = execution["execution_status"]
            final_status = (
                "completed"
                if execution_status == "completed"
                else (
                    execution_status
                    if execution_status in {"failed", "stopped", "interrupted"}
                    else "analyzing"
                )
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status=final_status,
                analysis_status="completed",
                resource_status="completed",
                analyzed_responses=len(analyzed_request_ids),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self.service.update_resource_work(
                self.run_id, work_id, status="failed", reason=type(exc).__name__
            )
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                status="failed",
                analysis_status="failed",
                resource_status="failed",
                error_code=type(exc).__name__,
            )
        finally:
            self._analysis_scopes.pop((live.interaction_id, revision), None)
            live.analysis_done.set()
            live.changed.set()

    async def _result_page(
        self,
        agent_id: str,
        interaction_id: str,
        *,
        cursor: int,
        limit: int,
        filters: HttpOutputFilters | None = None,
        record_types: set[str] | None = None,
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        if row["output_cleaned_at"] is not None:
            raise self._error(
                "not_found",
                "http_interaction_output_cleaned",
                "HTTP interaction output has been cleaned",
            )
        default_types: set[str] = {"response", "analysis"}
        if row["kind"] == "fingerprint":
            default_types = {"fingerprint"}
        elif row["kind"] == "path_probe":
            default_types = {"response", "fingerprint"}
        records, next_cursor, page_end_cursor = self._read_records(
            agent_id,
            interaction_id,
            cursor=cursor,
            limit=limit,
            filters=filters,
            record_types=record_types or default_types,
        )
        resource_work = await self.service.list_resource_work(
            self.run_id, owner_id=interaction_id
        )
        latest_work = resource_work[-1] if resource_work else None
        try:
            planned_requests = self._load_plan(agent_id, interaction_id)
            plan = self._plan(agent_id, interaction_id)
        except (FileNotFoundError, NotADirectoryError):
            if row["status"] not in TERMINAL:
                raise
            planned_requests = []
            plan = {}
        started_requests = int(row["started_requests"])
        completed_requests = int(row["completed_requests"])
        execution_active = row["execution_status"] in {"queued", "running"}
        analysis_active = row["analysis_status"] in {"queued", "running"}
        page = {
            "interaction_id": interaction_id,
            "request_id": (
                planned_requests[0].request_id
                if row["kind"] == "request" and planned_requests
                else None
            ),
            "kind": row["kind"],
            "status": row["status"],
            "execution_status": row["execution_status"],
            "analysis_status": row["analysis_status"],
            "resource_status": row["resource_status"],
            "estimated_requests": row["estimated_requests"],
            "queued_requests": (
                max(0, int(row["estimated_requests"]) - started_requests)
                if execution_active
                else 0
            ),
            "running_requests": (
                max(0, started_requests - completed_requests) if execution_active else 0
            ),
            "started_requests": started_requests,
            "completed_requests": completed_requests,
            "analyzed_responses": row["analyzed_responses"],
            "response_bytes": row["response_bytes"],
            "connection_pool": self._engine(agent_id).connection_stats,
            "resource_admission": (
                None
                if latest_work is None
                else {
                    "phase": latest_work["phase"],
                    "status": latest_work["status"],
                    "reason": latest_work["reason"],
                    "retry_at": latest_work["retry_at"],
                    "estimated_disk_bytes": latest_work["estimated_disk_bytes"],
                    "estimated_memory_bytes": latest_work["estimated_memory_bytes"],
                }
            ),
            "sessions": self._session_metadata(agent_id, interaction_id),
            "groups": self._groups(agent_id, interaction_id),
            "similarity_groups": self._similarity_groups(agent_id, interaction_id),
            "results": records,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "page_end_cursor": page_end_cursor,
            "has_more": next_cursor < page_end_cursor,
            "read_scope": {
                "filters": filters.model_dump(mode="json", exclude_defaults=True) if filters else {},
                "record_types": sorted(record_types or default_types),
                "default": not (filters and filters.model_dump(exclude_defaults=True))
                and (record_types is None or record_types == default_types),
            },
            "read_result": {
                "tool": "system_http_output",
                "arguments": {
                    "interaction_id": interaction_id, "cursor": cursor, "limit": limit,
                    **({"filters": filters.model_dump(mode="json", exclude_none=True)} if filters else {}),
                },
            },
            "result_state": (
                "partial" if records and (execution_active or analysis_active)
                else "available" if records
                else "pending" if execution_active or analysis_active
                else "empty"
            ),
            "recommended_wait_seconds": (
                20 if row["status"] not in TERMINAL or analysis_active else 0
            ),
            "is_terminal": row["status"] in TERMINAL and not analysis_active,
            "can_cleanup": row["status"] in TERMINAL and not analysis_active,
            "recommended_action": "read_results_before_cleanup",
            "template_summary": plan.get("template_summary"),
            "request_catalog": self._request_catalog(agent_id, interaction_id),
        }
        if row["kind"] in {"path_probe", "fingerprint"}:
            summary = self._load_summary(agent_id, interaction_id)
            page["summary"] = summary
            page["matched_requests"] = (
                int(summary.get("matched_requests") or 0) if summary is not None else 0
            )
        return page

    def _request_catalog(
        self, agent_id: str, interaction_id: str
    ) -> list[dict[str, Any]]:
        """Return bounded authoritative request IDs for follow-up body reads."""

        response_records = {
            str(item.get("request_id")): item
            for item in self._response_records(agent_id, interaction_id)
            if item.get("request_id")
        }
        try:
            planned = self._load_plan(agent_id, interaction_id)
        except (OSError, KeyError, ValueError):
            planned = []
        catalog: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ordinal, item in enumerate(planned, start=1):
            request_id = str(item.request_id)
            record = response_records.get(request_id, {})
            response_available = self._response_body_available(
                agent_id, interaction_id, record
            )
            catalog.append(
                {
                    "request_id": request_id,
                    "sequence": int(item.ordinal or ordinal),
                    "method": item.spec.method,
                    "status": (
                        "completed"
                        if record.get("outcome") == "response"
                        else record.get("outcome") or "pending"
                    ),
                    "response_available": response_available,
                    "read_response": (
                        {"tool": "system_http_response", "arguments": {
                            "interaction_id": interaction_id, "request_id": request_id,
                        }} if response_available else None
                    ),
                }
            )
            seen.add(request_id)
        for ordinal, (request_id, record) in enumerate(
            response_records.items(), start=len(catalog) + 1
        ):
            if request_id in seen:
                continue
            response_available = self._response_body_available(
                agent_id, interaction_id, record
            )
            catalog.append(
                {
                    "request_id": request_id,
                    "sequence": ordinal,
                    "method": record.get("method"),
                    "status": record.get("outcome") or "completed",
                    "response_available": response_available,
                    "read_response": (
                        {"tool": "system_http_response", "arguments": {
                            "interaction_id": interaction_id, "request_id": request_id,
                        }} if response_available else None
                    ),
                }
            )
        return catalog[:256]

    def _read_records(
        self,
        agent_id: str,
        interaction_id: str,
        *,
        cursor: int,
        limit: int,
        filters: HttpOutputFilters | None,
        record_types: set[str],
    ) -> tuple[list[dict[str, Any]], int, int]:
        path = self._journal_path(agent_id, interaction_id)
        records: list[dict[str, Any]] = []
        with path.open("rb") as source:
            page_end_cursor = os.fstat(source.fileno()).st_size
            source.seek(min(cursor, page_end_cursor))
            while source.tell() < page_end_cursor:
                start = source.tell()
                line = source.readline(page_end_cursor - start)
                if not line:
                    break
                if not line.endswith(b"\n"):
                    source.seek(start)
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("type") not in record_types:
                    continue
                if filters is not None and not self._matches_filter(record, filters):
                    continue
                if filters is not None and not self._matches_content_filter(
                    agent_id, interaction_id, record, filters
                ):
                    continue
                if len(records) == limit:
                    source.seek(start)
                    break
                records.append(self._compact_record(record))
            next_cursor = source.tell()
        return records, next_cursor, page_end_cursor

    @staticmethod
    def _compact_record(record: dict[str, Any]) -> dict[str, Any]:
        if record.get("type") != "response" or "headers" not in record:
            return record
        compact = dict(record)
        headers = {
            str(name).lower(): value
            for name, value in record.get("headers", {}).items()
        }
        selected = {
            name: headers[name]
            for name in (
                "content-type",
                "content-length",
                "location",
                "server",
                "allow",
                "www-authenticate",
            )
            if name in headers
        }
        compact.pop("headers", None)
        compact["header_features"] = selected
        return compact

    @staticmethod
    def _matches_filter(record: dict[str, Any], filters: HttpOutputFilters) -> bool:
        if filters.request_ids and record.get("request_id") not in filters.request_ids:
            return False
        if (
            filters.status_codes
            and record.get("status_code") not in filters.status_codes
        ):
            return False
        if filters.outcomes and record.get("outcome") not in filters.outcomes:
            return False
        if (
            filters.request_group_id
            and record.get("request_group_id") != filters.request_group_id
        ):
            return False
        size = record.get("body_bytes")
        if filters.min_body_bytes is not None and (
            size is None or size < filters.min_body_bytes
        ):
            return False
        if filters.max_body_bytes is not None and (
            size is None or size > filters.max_body_bytes
        ):
            return False
        return True

    def _matches_content_filter(
        self,
        agent_id: str,
        interaction_id: str,
        record: dict[str, Any],
        filters: HttpOutputFilters,
    ) -> bool:
        if filters.header_contains or filters.header_regex:
            response = (
                record
                if record.get("type") == "response"
                else self._response_record(
                    agent_id, interaction_id, str(record.get("request_id") or "")
                )
            )
            headers = {
                str(name).lower(): str(value)
                for name, value in (response or {}).get("headers", {}).items()
            }
            for name, expected in filters.header_contains.items():
                if expected not in headers.get(name.lower(), ""):
                    return False
            for name, pattern in filters.header_regex.items():
                if re.search(pattern, headers.get(name.lower(), "")) is None:
                    return False
        if filters.body_contains is None and filters.body_regex is None:
            return True
        response = (
            record
            if record.get("type") == "response"
            else self._response_record(
                agent_id, interaction_id, str(record.get("request_id") or "")
            )
        )
        if response is None or response.get("body_file") is None:
            return False
        path = self._response_dir(agent_id, interaction_id) / str(response["body_file"])
        if not path.exists():
            return False
        data = path.read_bytes()
        if (
            filters.body_contains is not None
            and filters.body_contains.encode() not in data
        ):
            return False
        if filters.body_regex is not None:
            try:
                if re.search(filters.body_regex.encode(), data) is None:
                    return False
            except re.error as exc:
                raise self._error(
                    "validation", "invalid_body_regex", "Body filter regex is invalid"
                ) from exc
        return True

    async def _append(self, live: LiveInteraction, record: dict[str, Any]) -> None:
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        async with live.journal_lock:
            with self._journal_path(live.agent_id, live.interaction_id).open(
                "a", encoding="utf-8"
            ) as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
        live.changed.set()

    async def _record_unfinished_requests(
        self, live: LiveInteraction, *, outcome: str
    ) -> None:
        records = self._all_records(live.agent_id, live.interaction_id)
        started = {
            str(item["request_id"]): item
            for item in records
            if item.get("type") == "request_started" and item.get("request_id")
        }
        finished = {
            str(item["request_id"])
            for item in records
            if item.get("type") == "response" and item.get("request_id")
        }
        requests = {item.request_id: item for item in live.requests}
        for request_id in sorted(
            started,
            key=lambda value: (
                requests[value].ordinal if value in requests else 2**63 - 1
            ),
        ):
            if request_id in finished:
                continue
            request = requests.get(request_id)
            if request is None:
                continue
            response_dir = self._response_dir(live.agent_id, live.interaction_id)
            partial = response_dir / f"{request_id}.body.part"
            body_path = response_dir / f"{request_id}.body"
            if partial.exists() and not body_path.exists():
                try:
                    partial.replace(body_path)
                    os.chmod(body_path, 0o600)
                except OSError:
                    pass
            body_bytes, body_sha256, line_count = self._file_metrics(body_path)
            await self._append(
                live,
                {
                    "type": "response",
                    "request_id": request_id,
                    "ordinal": request.ordinal,
                    "request_intent": request.spec.request_intent,
                    "parent_request_id": request.spec.parent_request_id,
                    "request_group_id": request.request_group_id,
                    "variables": request.variables,
                    "outcome": outcome,
                    "status_code": None,
                    "final_url": request.spec.url,
                    "elapsed_ms": None,
                    "body_bytes": body_bytes,
                    "content_length": None,
                    "body_sha256": body_sha256,
                    "line_count": line_count,
                    "body_complete": False,
                    "content_type": None,
                    "location": None,
                    "title": None,
                    "headers": {},
                    "error": (
                        "RuntimeInterrupted" if outcome == "interrupted" else "Stopped"
                    ),
                    "body_file": body_path.name if body_path.exists() else None,
                },
            )
        response_bytes = sum(
            int(item.get("body_bytes") or 0)
            for item in self._response_records(live.agent_id, live.interaction_id)
        )
        row = await self._owned(live.agent_id, live.interaction_id)
        if response_bytes != row["response_bytes"]:
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                response_bytes=response_bytes,
            )

    @staticmethod
    def _file_metrics(path: Path) -> tuple[int, str, int]:
        digest = hashlib.sha256()
        size = 0
        lines = 0
        last_byte: int | None = None
        if path.exists():
            with path.open("rb") as source:
                while chunk := source.read(65_536):
                    digest.update(chunk)
                    size += len(chunk)
                    lines += chunk.count(b"\n")
                    last_byte = chunk[-1]
        if size and last_byte != ord("\n"):
            lines += 1
        return size, digest.hexdigest(), lines

    def _repair_journal(self, agent_id: str, interaction_id: str) -> None:
        path = self._journal_path(agent_id, interaction_id)
        if not path.exists():
            return
        valid_end = 0
        with path.open("rb") as source:
            while True:
                line = source.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    break
                try:
                    json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    break
                valid_end = source.tell()
        if valid_end != path.stat().st_size:
            with path.open("r+b") as output:
                output.truncate(valid_end)
                output.flush()
                os.fsync(output.fileno())
            self._drop_result_caches(agent_id, interaction_id)

    def _journal_size(self, agent_id: str, interaction_id: str) -> int:
        path = self._journal_path(agent_id, interaction_id)
        return path.stat().st_size if path.exists() else 0

    def _drop_result_caches(self, agent_id: str, interaction_id: str) -> None:
        key = (agent_id, interaction_id)
        self._response_cache.pop(key, None)
        self._group_cache.pop(key, None)
        self._similarity_cache.pop(key, None)

    def _drop_interaction_caches(self, agent_id: str, interaction_id: str) -> None:
        self._drop_result_caches(agent_id, interaction_id)
        self._plan_cache.pop((agent_id, interaction_id), None)

    async def _await_resources(self, live: LiveInteraction, work_id: str) -> None:
        if self.resource_guard is None:
            return
        while not live.stop_requested:
            decision = await self.resource_guard(work_id)
            if decision.get("ok"):
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    resource_status="running",
                )
                return
            if decision.get("reason") in {"disk_pressure", "disk_reservation"}:
                reclaimed = await self._reclaim_terminal_response_bodies(
                    exclude_interaction_ids={live.interaction_id}
                )
                if reclaimed["reclaimed_bytes"]:
                    continue
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                resource_status="waiting",
            )
            live.changed.set()
            await asyncio.sleep(float(decision.get("retry_after_seconds", 1.0)))

    async def _create_interaction_directories(
        self, agent_id: str, interaction_id: str
    ) -> tuple[Path, Path]:
        await self._reclaim_terminal_response_bodies()
        interaction_dir = self._interaction_dir(agent_id, interaction_id)
        response_dir = interaction_dir / "responses"
        try:
            response_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        except OSError as exc:
            storage_errnos = {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}
            if exc.errno not in storage_errnos:
                raise
            reclaimed = await self._reclaim_terminal_response_bodies(force=True)
            try:
                response_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
            except OSError as retry_exc:
                if retry_exc.errno not in storage_errnos:
                    raise
                raise self._error(
                    "resource",
                    "http_storage_exhausted",
                    "HTTP response storage is exhausted",
                    detail={
                        "reclaimed_bytes": reclaimed["reclaimed_bytes"],
                        "free_bytes": reclaimed["free_bytes_after"],
                        "recommended_action": "wait_for_terminal_work_cleanup",
                    },
                ) from retry_exc
        for private_dir in (
            self._agent_root(agent_id),
            self._agent_root(agent_id) / "http-interactions",
            interaction_dir,
            response_dir,
        ):
            os.chmod(private_dir, 0o700)
        return interaction_dir, response_dir

    async def _reclaim_terminal_response_bodies(
        self,
        *,
        force: bool = False,
        exclude_interaction_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Evict old terminal response blobs while preserving interaction metadata."""

        excluded = exclude_interaction_ids or set()
        async with self._reclaim_lock:
            usage = shutil.disk_usage(self.policy.root)
            reserve_floor = max(
                self.disk_reserve_bytes,
                int(usage.total * self.disk_reserve_percent / 100.0),
            )
            if not force and usage.free > reserve_floor:
                return {
                    "triggered": False,
                    "reclaimed_bytes": 0,
                    "reclaimed_files": 0,
                    "reclaimed_interactions": 0,
                    "free_bytes_before": usage.free,
                    "free_bytes_after": usage.free,
                    "reserve_floor_bytes": reserve_floor,
                }

            free_before = usage.free
            target_free = min(
                usage.total,
                max(reserve_floor, usage.free) + RECLAIM_HEADROOM_BYTES,
            )
            rows = await self.service.list_http_interactions(self.run_id)

            def reclaim_order(row: dict[str, Any]) -> tuple[int, str, str]:
                if row["status"] in {"failed", "stopped", "interrupted"}:
                    priority = 0
                elif row["analysis_status"] in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    priority = 1
                else:
                    priority = 2
                return priority, str(row["created_at"]), str(row["interaction_id"])

            candidates = sorted(
                (
                    row
                    for row in rows
                    if row["interaction_id"] not in excluded
                    and row["status"] in TERMINAL
                    and row["analysis_status"] not in {"queued", "running"}
                    and row["output_cleaned_at"] is None
                ),
                key=reclaim_order,
            )
            reclaimed_bytes = 0
            reclaimed_files = 0
            reclaimed_interactions = 0
            for row in candidates:
                agent_id = str(row["agent_id"])
                interaction_id = str(row["interaction_id"])
                lock = self._interaction_locks.setdefault(
                    (agent_id, interaction_id), asyncio.Lock()
                )
                if lock.locked():
                    continue
                interaction_bytes = 0
                interaction_files = 0
                async with lock:
                    current = await self._owned(agent_id, interaction_id)
                    if (
                        current["status"] not in TERMINAL
                        or current["analysis_status"] in {"queued", "running"}
                        or current["output_cleaned_at"] is not None
                    ):
                        continue
                    response_dir = self._response_dir(agent_id, interaction_id)
                    if not response_dir.is_dir() or response_dir.is_symlink():
                        continue
                    for body_path in response_dir.iterdir():
                        if body_path.is_symlink() or not body_path.is_file():
                            continue
                        if not body_path.name.endswith((".body", ".body.part")):
                            continue
                        try:
                            size = body_path.stat().st_size
                            body_path.unlink()
                        except FileNotFoundError:
                            continue
                        interaction_bytes += size
                        interaction_files += 1
                if interaction_files:
                    reclaimed_bytes += interaction_bytes
                    reclaimed_files += interaction_files
                    reclaimed_interactions += 1
                usage = shutil.disk_usage(self.policy.root)
                if usage.free >= target_free:
                    break

            free_after = shutil.disk_usage(self.policy.root).free
            if reclaimed_files:
                LOGGER.warning(
                    "http_body_storage_reclaimed run_id=%s bytes=%s files=%s interactions=%s free_before=%s free_after=%s reserve_floor=%s",
                    self.run_id,
                    reclaimed_bytes,
                    reclaimed_files,
                    reclaimed_interactions,
                    free_before,
                    free_after,
                    reserve_floor,
                )
            return {
                "triggered": True,
                "reclaimed_bytes": reclaimed_bytes,
                "reclaimed_files": reclaimed_files,
                "reclaimed_interactions": reclaimed_interactions,
                "free_bytes_before": free_before,
                "free_bytes_after": free_after,
                "reserve_floor_bytes": reserve_floor,
            }

    async def _wait(self, event: asyncio.Event, seconds: float | None) -> None:
        if event.is_set() or seconds == 0:
            return
        if seconds is None:
            await event.wait()
            return
        try:
            await asyncio.wait_for(event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def _owned(self, agent_id: str, interaction_id: str) -> dict[str, Any]:
        try:
            return await self.service.get_http_interaction(
                self.run_id, agent_id, interaction_id
            )
        except StateNotFound as exc:
            raise self._error(
                "not_found",
                "http_interaction_not_found",
                "HTTP interaction was not found",
            ) from exc

    async def _interaction_any_owner(self, interaction_id: str) -> dict[str, Any]:
        rows = await self.service.list_http_interactions(self.run_id)
        row = next(
            (item for item in rows if item["interaction_id"] == interaction_id), None
        )
        if row is None:
            raise self._error(
                "not_found",
                "http_interaction_not_found",
                "HTTP interaction was not found",
            )
        return row

    async def _request_owned(self, agent_id: str, request_id: str) -> bool:
        for row in await self.service.list_http_interactions(
            self.run_id, agent_id=agent_id
        ):
            try:
                plan = self._plan(agent_id, row["interaction_id"])
                if any(
                    item.request_id == request_id
                    for item in [self._request_from_json(raw) for raw in plan.get("requests", [])]
                ):
                    return True
                if plan.get("kind") == "path_probe":
                    request_path = self._interaction_dir(
                        agent_id, row["interaction_id"]
                    ) / str(plan["requests_file"])
                    with request_path.open("r", encoding="utf-8") as requests:
                        for line in requests:
                            if json.loads(line).get("request_id") == request_id:
                                return True
            except (OSError, KeyError, ValueError):
                pass
            path = self._journal_path(agent_id, row["interaction_id"])
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as source:
                for line in source:
                    try:
                        if json.loads(line).get("request_id") == request_id:
                            return True
                    except json.JSONDecodeError:
                        continue
        return False

    async def _request_group_allowed(self, agent_id: str, group_id: str) -> bool:
        found_foreign = False
        for row in await self.service.list_http_interactions(self.run_id):
            try:
                plan = self._plan(row["agent_id"], row["interaction_id"])
                requests = [self._request_from_json(raw) for raw in plan.get("requests", [])]
            except (OSError, KeyError, ValueError):
                continue
            option_group = None
            if plan.get("kind") in {"path_probe", "fingerprint"}:
                option_group = (plan.get("options") or {}).get("request_group_id")
            if option_group != group_id and not any(
                item.request_group_id == group_id for item in requests
            ):
                continue
            if row["agent_id"] == agent_id:
                return True
            found_foreign = True
        return not found_foreign

    async def _next_context_sequence(self, agent_id: str, context_id: str) -> int:
        """Assign the next monotonic position for one Agent connection context."""

        maximum = -1
        for (owner_agent, _), items in self._plan_cache.items():
            if owner_agent != agent_id:
                continue
            for item in items:
                if (
                    item.spec.connection_context_id == context_id
                    and item.spec.sequence_id is not None
                ):
                    maximum = max(maximum, int(item.spec.sequence_id))
        base = self._agent_root(agent_id) / "http-interactions"
        if base.is_dir():
            for plan_path in base.glob("*/plan.json"):
                try:
                    plan = json.loads(plan_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                for raw in plan.get("requests", []):
                    spec = raw.get("spec") if isinstance(raw, Mapping) else None
                    if not isinstance(spec, Mapping):
                        continue
                    if spec.get("connection_context_id") != context_id:
                        continue
                    try:
                        maximum = max(maximum, int(spec.get("sequence_id") or 0))
                    except (TypeError, ValueError):
                        continue
        return maximum + 1

    async def _historical_response_estimate(
        self, requests: list[ExpandedRequest]
    ) -> int:
        values: list[int] = []
        for item in requests:
            total_count = self._response_size_estimates.get(
                self._origin_key(item.spec.url)
            )
            if total_count is not None and total_count[1]:
                values.append(total_count[0] // total_count[1])
        return sum(values) // len(values) if values else 65_536

    async def _load_response_size_estimates(self) -> None:
        self._response_size_estimates.clear()
        for row in await self.service.list_http_interactions(self.run_id):
            if row["output_cleaned_at"] is not None:
                continue
            for response in self._response_records(
                row["agent_id"], row["interaction_id"]
            ):
                if response.get("outcome") == "response":
                    self._observe_response_size(
                        str(response.get("final_url") or ""),
                        int(response.get("body_bytes") or 0),
                    )

    def _observe_response_size(self, url: str, body_bytes: int) -> None:
        key = self._origin_key(url)
        total, count = self._response_size_estimates.get(key, (0, 0))
        # Bound historical influence while keeping the estimate cheap and
        # stable for a competition Run with many repeated probes.
        if count >= 256:
            total //= 2
            count //= 2
        self._response_size_estimates[key] = (total + max(0, body_bytes), count + 1)

    @staticmethod
    def _origin_key(url: str) -> tuple[str, str | None, int | None]:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            # A malformed historical/final URL must never escape as an
            # internal tool failure. Expanded requests are validated before
            # persistence; this guard covers only external redirect metadata.
            return "", None, None
        return parts.scheme.lower(), parts.hostname, port

    def _groups(self, agent_id: str, interaction_id: str) -> list[dict[str, Any]]:
        cache_key = (agent_id, interaction_id)
        journal_size = self._journal_size(agent_id, interaction_id)
        cached = self._group_cache.get(cache_key)
        if cached is not None and cached[0] == journal_size:
            return cached[1]
        similarity = {
            item["request_id"]: item.get("similarity_hash")
            for item in self._all_records(agent_id, interaction_id)
            if item.get("type") == "analysis"
        }
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        for response in self._response_records(agent_id, interaction_id):
            key = (
                response.get("status_code"),
                response.get("body_bytes"),
                response.get("body_sha256"),
            )
            group = groups.setdefault(
                key,
                {
                    "status_code": key[0],
                    "body_bytes": key[1],
                    "body_sha256": key[2],
                    "similarity_hash": similarity.get(response["request_id"]),
                    "count": 0,
                    "request_ids": [],
                },
            )
            group["count"] += 1
            if len(group["request_ids"]) < 5:
                group["request_ids"].append(response["request_id"])
        result = sorted(
            groups.values(),
            key=lambda item: (-item["count"], str(item["status_code"])),
        )
        self._group_cache[cache_key] = (journal_size, result)
        return result

    def _similarity_groups(
        self, agent_id: str, interaction_id: str
    ) -> list[dict[str, Any]]:
        cache_key = (agent_id, interaction_id)
        journal_size = self._journal_size(agent_id, interaction_id)
        cached = self._similarity_cache.get(cache_key)
        if cached is not None and cached[0] == journal_size:
            return cached[1]
        latest: dict[str, dict[str, Any]] = {}
        for item in self._all_records(agent_id, interaction_id):
            if item.get("type") != "analysis" or item.get("similarity_hash") is None:
                continue
            request_id = str(item["request_id"])
            if int(item.get("revision", 0)) >= int(
                latest.get(request_id, {}).get("revision", -1)
            ):
                latest[request_id] = item
        groups: dict[str, dict[str, Any]] = {}
        representatives: list[tuple[int, str]] = []
        similarity_buckets: dict[tuple[int, int], list[int]] = {}
        for request_id, item in sorted(latest.items()):
            value = int(item["similarity_hash"], 16)
            name = self._assign_similarity_group(
                value, representatives, similarity_buckets
            )
            group = groups.setdefault(
                name,
                {
                    "similarity_group": name,
                    "similarity_hash": item.get("similarity_hash"),
                    "count": 0,
                    "request_ids": [],
                },
            )
            group["count"] += 1
            if len(group["request_ids"]) < 5:
                group["request_ids"].append(request_id)
        result = sorted(
            groups.values(),
            key=lambda item: (-item["count"], item["similarity_group"]),
        )
        self._similarity_cache[cache_key] = (journal_size, result)
        return result

    @staticmethod
    def _assign_similarity_group(
        value: int,
        representatives: list[tuple[int, str]],
        buckets: dict[tuple[int, int], list[int]],
    ) -> str:
        candidate_indexes: set[int] = set()
        for segment in range(4):
            segment_value = (value >> (segment * 16)) & 0xFFFF
            candidate_indexes.update(buckets.get((segment, segment_value), ()))
        for index in sorted(candidate_indexes):
            representative, name = representatives[index]
            if (value ^ representative).bit_count() <= 3:
                return name
        name = f"similar-{len(representatives) + 1}"
        index = len(representatives)
        representatives.append((value, name))
        for segment in range(4):
            segment_value = (value >> (segment * 16)) & 0xFFFF
            buckets.setdefault((segment, segment_value), []).append(index)
        return name

    def _response_records(
        self, agent_id: str, interaction_id: str
    ) -> list[dict[str, Any]]:
        path = self._journal_path(agent_id, interaction_id)
        if not path.exists():
            return []
        cache_key = (agent_id, interaction_id)
        journal_size = path.stat().st_size
        cached = self._response_cache.get(cache_key)
        if cached is not None and cached[0] == journal_size:
            return cached[1]
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("type") == "response":
                    records.append(item)
        self._response_cache[cache_key] = (journal_size, records)
        return records

    def _response_record(
        self, agent_id: str, interaction_id: str, request_id: str
    ) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in self._response_records(agent_id, interaction_id)
                if item.get("request_id") == request_id
            ),
            None,
        )

    def _response_body_available(
        self,
        agent_id: str,
        interaction_id: str,
        record: Mapping[str, Any],
    ) -> bool:
        body_file = record.get("body_file")
        if not body_file:
            return False
        path = self._response_dir(agent_id, interaction_id) / str(body_file)
        return not path.is_symlink() and path.is_file()

    async def _next_analysis_revision(self, agent_id: str, interaction_id: str) -> int:
        revisions = [
            int(item.get("revision", 0))
            for item in self._all_records(agent_id, interaction_id)
            if item.get("type") == "analysis"
        ]
        revisions.extend(
            self._phase_revision(item["phase"])
            for item in await self.service.list_resource_work(
                self.run_id, owner_id=interaction_id
            )
            if item["phase"].startswith("analysis")
        )
        return max(revisions, default=0) + 1

    def _all_records(self, agent_id: str, interaction_id: str) -> list[dict[str, Any]]:
        path = self._journal_path(agent_id, interaction_id)
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    def _load_session(self, agent_id: str, session_id: str | None) -> dict[str, Any]:
        if session_id is None:
            return {"cookies": []}
        path = self._session_path(agent_id, session_id)
        if not path.exists():
            return {"cookies": []}
        return json.loads(path.read_text(encoding="utf-8"))

    def _session_metadata(
        self, agent_id: str, interaction_id: str
    ) -> list[dict[str, Any]]:
        try:
            requests = self._load_plan(agent_id, interaction_id)
        except (OSError, KeyError, ValueError):
            return []
        metadata: list[dict[str, Any]] = []
        for session_id in sorted(
            {item.spec.session_id for item in requests if item.spec.session_id}
        ):
            session = self._load_session(agent_id, session_id)
            metadata.append(
                {
                    "session_id": session_id,
                    "created_by": session.get("created_by"),
                    "updated_by": session.get("updated_by"),
                    "cookie_count": len(session.get("cookies", [])),
                }
            )
        return metadata

    def _save_session(
        self,
        agent_id: str,
        session_id: str,
        cookies: list[dict[str, Any]],
        *,
        interaction_id: str,
        request_id: str,
    ) -> None:
        path = self._session_path(agent_id, session_id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        previous = self._load_session(agent_id, session_id)
        created = previous.get("created_by") or {
            "interaction_id": interaction_id,
            "request_id": request_id,
        }
        self._write_private_json_atomic(
            path,
            {
                "cookies": cookies,
                "created_by": created,
                "updated_by": {
                    "interaction_id": interaction_id,
                    "request_id": request_id,
                },
            },
        )

    @staticmethod
    def _write_private_json_atomic(path: Path, value: Any) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(
                    value,
                    output,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _session_path(self, agent_id: str, session_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", session_id):
            raise self._error(
                "validation", "invalid_http_session_id", "HTTP session ID is invalid"
            )
        return self._agent_root(agent_id) / "http-sessions" / f"{session_id}.json"

    def _load_plan(self, agent_id: str, interaction_id: str) -> list[ExpandedRequest]:
        cache_key = (agent_id, interaction_id)
        cached = self._plan_cache.get(cache_key)
        if cached is not None:
            return cached
        plan = self._plan(agent_id, interaction_id)
        if plan.get("kind") == "fingerprint":
            requests = []
        elif plan.get("kind") == "path_probe":
            requests = []
        else:
            requests = [self._request_from_json(item) for item in plan["requests"]]
        self._plan_cache[cache_key] = requests
        return requests

    def _plan(self, agent_id: str, interaction_id: str) -> dict[str, Any]:
        return json.loads(
            (self._interaction_dir(agent_id, interaction_id) / "plan.json").read_text(
                encoding="utf-8"
            )
        )

    @staticmethod
    def _request_json(item: ExpandedRequest) -> dict[str, Any]:
        return {
            "request_id": item.request_id,
            "ordinal": item.ordinal,
            "spec": item.spec.model_dump(mode="json"),
            "variables": item.variables,
            "request_group_id": item.request_group_id,
            "connection_context_id": item.spec.connection_context_id,
            "sequence_id": item.spec.sequence_id,
        }

    @staticmethod
    def _request_from_json(item: dict[str, Any]) -> ExpandedRequest:
        return ExpandedRequest(
            request_id=item["request_id"],
            ordinal=int(item["ordinal"]),
            spec=HttpRequestSpec.model_validate(item["spec"]),
            variables=dict(item.get("variables", {})),
            request_group_id=item["request_group_id"],
        )

    def _agent_root(self, agent_id: str) -> Path:
        return (
            self.policy.root
            / ".system-tools"
            / "runs"
            / self.run_id
            / "agents"
            / agent_id
        )

    async def _remove_orphan_interaction_directories(self) -> None:
        """Remove only Run-scoped directories that have no authoritative row."""

        known = {
            (str(row["agent_id"]), str(row["interaction_id"]))
            for row in await self.service.list_http_interactions(self.run_id)
        }
        agents_root = (
            self.policy.root / ".system-tools" / "runs" / self.run_id / "agents"
        )
        if not agents_root.is_dir():
            return
        for agent_dir in agents_root.iterdir():
            interactions_root = agent_dir / "http-interactions"
            if not interactions_root.is_dir() or interactions_root.is_symlink():
                continue
            for child in interactions_root.iterdir():
                if (
                    child.is_dir()
                    and not child.is_symlink()
                    and (agent_dir.name, child.name) not in known
                ):
                    shutil.rmtree(child)

    def _interaction_dir(self, agent_id: str, interaction_id: str) -> Path:
        return self._agent_root(agent_id) / "http-interactions" / interaction_id

    def _journal_path(self, agent_id: str, interaction_id: str) -> Path:
        return self._interaction_dir(agent_id, interaction_id) / "results.jsonl"

    def _response_dir(self, agent_id: str, interaction_id: str) -> Path:
        return self._interaction_dir(agent_id, interaction_id) / "responses"

    @staticmethod
    def _work_id(interaction_id: str, phase: str, revision: int) -> str:
        return f"http-work-{interaction_id.removeprefix('interaction-')}-{phase}-{revision}"

    @staticmethod
    def _phase_revision(phase: str) -> int:
        match = re.search(r"-(\d+)$", phase)
        return int(match.group(1)) if match else 1

    def _require_open(self) -> None:
        if self._closed:
            raise self._error(
                "conflict", "http_manager_closed", "HTTP manager is closed"
            )

    @staticmethod
    def _error(
        error_type: str,
        code: str,
        message: str,
        *,
        detail: Any = None,
    ) -> SystemToolError:
        return SystemToolError(
            error_type=error_type,
            code=code,
            message=message,
            detail=detail,
        )
