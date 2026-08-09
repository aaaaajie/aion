"""Run-owned persistence and lifecycle for generic HTTP interactions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

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
from .models import HttpOutputFilters, HttpProbeCase, HttpRequestSpec
from .path_probe import (
    PROFILE_PRESETS,
    PathProbeEngine,
    PathProbeMatch,
    PathProbeOptions,
    PathProbeRunResult,
)

AdmissionCallback = Callable[[str], Awaitable[dict[str, Any]]]
ResourceGuard = Callable[[str], Awaitable[dict[str, Any]]]
TERMINAL = {"completed", "failed", "stopped", "interrupted"}


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

    async def request(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.start_request(self.agent_id, **kwargs)

    async def probe(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.start_probe(self.agent_id, **kwargs)

    async def path_probe(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.start_path_probe(self.agent_id, **kwargs)

    async def fingerprint(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.start_fingerprint(self.agent_id, **kwargs)

    async def analyze(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.analyze(self.agent_id, **kwargs)

    async def output(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.output(self.agent_id, **kwargs)

    async def response(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.response(self.agent_id, **kwargs)

    async def stop(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.stop(self.agent_id, **kwargs)

    async def cleanup(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.cleanup(self.agent_id, **kwargs)

    async def close(self) -> None:
        """The Supervisor owns the manager; session close is a no-op."""


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
        admission_callback: AdmissionCallback | None = None,
        resource_guard: ResourceGuard | None = None,
    ) -> None:
        self.policy = policy
        self.service = service
        self.run_id = run_id
        self.engine = engine or HttpInteractionEngine(policy)
        self.path_transport = path_transport
        self.admission_callback = admission_callback
        self.resource_guard = resource_guard
        self._live: dict[str, LiveInteraction] = {}
        self._analysis_scopes: dict[tuple[str, int], tuple[set[str], str | None]] = {}
        self._session_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self._plan_cache: dict[tuple[str, str], list[ExpandedRequest]] = {}
        self._response_cache: dict[
            tuple[str, str], tuple[int, list[dict[str, Any]]]
        ] = {}
        self._group_cache: dict[
            tuple[str, str], tuple[int, list[dict[str, Any]]]
        ] = {}
        self._similarity_cache: dict[
            tuple[str, str], tuple[int, list[dict[str, Any]]]
        ] = {}
        self._closed = False

    def bind(self, agent_id: str) -> AgentHttpClient:
        return AgentHttpClient(self, agent_id)

    def set_admission_callback(self, callback: AdmissionCallback) -> None:
        self.admission_callback = callback

    async def initialize(self, *, resume: bool = False) -> None:
        if not resume:
            return
        works = await self.service.list_resource_work(
            self.run_id, statuses={"queued", "reserved", "running"}
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
                and
                row["execution_status"] == "completed"
                and row["analysis_status"] != "completed"
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
                    else (
                        "interrupted" if was_active else row["execution_status"]
                    )
                ),
                analysis_status=(
                    "queued"
                    if can_resume_analysis
                    else row["analysis_status"]
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
        expected_response_bytes: int | None = None,
        priority: int = 50,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
    ) -> dict[str, Any]:
        return await self.start_probe(
            agent_id,
            cases=[HttpProbeCase(request=request)],
            concurrency=concurrency,
            rate_limit_per_second=None,
            expected_response_bytes=expected_response_bytes,
            priority=priority,
            wait_seconds=wait_seconds,
            result_limit=result_limit,
            kind="request",
        )

    async def start_probe(
        self,
        agent_id: str,
        *,
        cases: list[HttpProbeCase],
        concurrency: int = 8,
        rate_limit_per_second: float | None = None,
        expected_response_bytes: int | None = None,
        priority: int = 50,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
        kind: str = "probe",
    ) -> dict[str, Any]:
        self._require_open()
        interaction_id = f"interaction-{uuid4().hex}"
        requests = self.engine.expand_cases(
            cases,
            id_factory=lambda: uuid4().hex,
            default_group_id=interaction_id,
        )
        if not requests:
            raise self._error(
                "validation",
                "empty_http_interaction",
                "HTTP interaction must expand to at least one request",
            )
        for item in requests:
            if item.spec.parent_request_id is not None and not await self._request_owned(
                agent_id, item.spec.parent_request_id
            ):
                raise self._error(
                    "not_found",
                    "parent_request_not_found",
                    "Parent request was not found",
                )
            if not await self._request_group_allowed(
                agent_id, item.request_group_id
            ):
                raise self._error(
                    "not_found",
                    "request_group_not_found",
                    "Request group was not found",
                )
        interaction_dir = self._interaction_dir(agent_id, interaction_id)
        response_dir = interaction_dir / "responses"
        response_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        for private_dir in (
            self._agent_root(agent_id),
            self._agent_root(agent_id) / "http-interactions",
            interaction_dir,
            response_dir,
        ):
            os.chmod(private_dir, 0o700)
        journal = interaction_dir / "results.jsonl"
        journal.touch(mode=0o600, exist_ok=False)
        plan_path = interaction_dir / "plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "concurrency": concurrency,
                    "rate_limit_per_second": rate_limit_per_second,
                    "requests": [self._request_json(item) for item in requests],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.chmod(plan_path, 0o600)
        estimate_per_response = (
            expected_response_bytes
            if expected_response_bytes is not None
            else await self._historical_response_estimate(requests)
        )
        estimated_disk = len(requests) * estimate_per_response
        relative = self.policy.relative_lexical(interaction_dir)
        try:
            await self.service.create_http_interaction(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                kind=kind,
                result_path=relative,
                estimated_requests=len(requests),
                requested_concurrency=concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=concurrency * 65_536,
                estimated_analysis_work=len(requests),
                priority=priority,
            )
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_resource_work(
                self.run_id,
                agent_id,
                work_id=work_id,
                owner_type="http_interaction",
                owner_id=interaction_id,
                phase="execution",
                priority=priority,
                requested_concurrency=concurrency,
                estimated_requests=len(requests),
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=concurrency * 65_536,
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, requests)
        self._plan_cache[(agent_id, interaction_id)] = requests
        self._live[interaction_id] = live
        decision = await self._admit(work_id)
        if decision.get("ok"):
            await self.launch_work(interaction_id, "execution", work_id=work_id)
        else:
            await self.service.update_http_interaction(
                self.run_id,
                agent_id,
                interaction_id,
                status="queued",
                execution_status="queued",
                resource_status="waiting",
            )
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
        priority: int = 50,
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
                "validation", "invalid_path_probe_url", "Path probe URL must use http or https"
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
            exclude_paths=tuple(exclude_paths or ()),
            include_status_codes=frozenset(include_status_codes or ()),
            exclude_status_codes=frozenset(exclude_status_codes or {404}),
            recursion_depth=int(recursion_depth or 0),
            recursion_status_codes=frozenset(
                recursion_status_codes or {200, 301, 302}
            ),
            max_body_bytes=max_body_bytes or preset["max_body_bytes"],
            request_intent=request_intent or "path_discovery",
            parent_request_id=parent_request_id,
            request_group_id=group_id,
        )
        engine = PathProbeEngine(self.policy, options, transport=self.path_transport)
        interaction_dir = self._interaction_dir(agent_id, interaction_id)
        response_dir = interaction_dir / "responses"
        response_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        for private_dir in (
            self._agent_root(agent_id),
            self._agent_root(agent_id) / "http-interactions",
            interaction_dir,
            response_dir,
        ):
            os.chmod(private_dir, 0o700)
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
        os.chmod(requests_path, 0o600)
        if request_count == 0:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise self._error(
                "validation", "empty_path_probe", "Path probe wordlist is empty"
            )
        plan_path = interaction_dir / "plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "kind": "path_probe",
                    "options": options.to_plan(),
                    "requests_file": "requests.ndjson",
                    "request_count": request_count,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.chmod(plan_path, 0o600)
        estimate_per_response = min(65_536, options.max_body_bytes)
        estimated_disk = request_count * estimate_per_response
        relative = self.policy.relative_lexical(interaction_dir)
        estimated_requests = request_count + engine.calibration_budget()
        try:
            await self.service.create_http_interaction(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                kind="path_probe",
                result_path=relative,
                estimated_requests=estimated_requests,
                requested_concurrency=options.concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
                estimated_analysis_work=0,
                priority=priority,
            )
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_resource_work(
                self.run_id,
                agent_id,
                work_id=work_id,
                owner_type="http_interaction",
                owner_id=interaction_id,
                phase="execution",
                priority=priority,
                requested_concurrency=options.concurrency,
                estimated_requests=estimated_requests,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, [])
        self._plan_cache[(agent_id, interaction_id)] = []
        self._live[interaction_id] = live
        decision = await self._admit(work_id)
        if decision.get("ok"):
            await self.launch_work(interaction_id, "execution", work_id=work_id)
        else:
            await self.service.update_http_interaction(
                self.run_id,
                agent_id,
                interaction_id,
                status="queued",
                execution_status="queued",
                resource_status="waiting",
            )
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
        include_favicon: bool = True,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        auth: Any = None,
        follow_redirects: bool = False,
        verify_tls: bool = False,
        timeout_seconds: float | None = None,
        concurrency: int | None = None,
        priority: int = 50,
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
        interaction_dir = self._interaction_dir(agent_id, interaction_id)
        response_dir = interaction_dir / "responses"
        response_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        for private_dir in (
            self._agent_root(agent_id),
            self._agent_root(agent_id) / "http-interactions",
            interaction_dir,
            response_dir,
        ):
            os.chmod(private_dir, 0o700)
        journal = interaction_dir / "results.jsonl"
        journal.touch(mode=0o600, exist_ok=False)
        plan_path = interaction_dir / "plan.json"
        plan_path.write_text(
            json.dumps(
                {
                    "kind": "fingerprint",
                    "options": options.to_plan(),
                    "requests": [{"path": path} for path in active_paths],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.chmod(plan_path, 0o600)
        relative = self.policy.relative_lexical(interaction_dir)
        estimated_disk = max(1, estimated_requests) * 65_536
        try:
            await self.service.create_http_interaction(
                self.run_id,
                agent_id,
                interaction_id=interaction_id,
                kind="fingerprint",
                result_path=relative,
                estimated_requests=estimated_requests,
                requested_concurrency=options.concurrency,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
                estimated_analysis_work=0,
                priority=priority,
            )
            work_id = self._work_id(interaction_id, "execution", 1)
            await self.service.create_resource_work(
                self.run_id,
                agent_id,
                work_id=work_id,
                owner_type="http_interaction",
                owner_id=interaction_id,
                phase="execution",
                priority=priority,
                requested_concurrency=options.concurrency,
                estimated_requests=estimated_requests,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=options.concurrency * 65_536,
            )
        except Exception:
            shutil.rmtree(interaction_dir, ignore_errors=True)
            raise
        live = LiveInteraction(interaction_id, agent_id, [])
        self._plan_cache[(agent_id, interaction_id)] = []
        self._live[interaction_id] = live
        decision = await self._admit(work_id)
        if decision.get("ok"):
            await self.launch_work(interaction_id, "execution", work_id=work_id)
        else:
            await self.service.update_http_interaction(
                self.run_id,
                agent_id,
                interaction_id,
                status="queued",
                execution_status="queued",
                resource_status="waiting",
            )
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
            await self.service.update_resource_work(self.run_id, work_id, status="running")
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
                runner(live, work_id),
                name=f"aion-http-execution-{interaction_id}",
            )
        else:
            if live.analysis_task is not None and not live.analysis_task.done():
                return
            revision = self._phase_revision(phase)
            work_id = work_id or self._work_id(interaction_id, "analysis", revision)
            await self.service.update_resource_work(self.run_id, work_id, status="running")
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                interaction_id,
                status="analyzing",
                analysis_status="running",
                resource_status="running",
            )
            live.analysis_task = asyncio.create_task(
                self._run_analysis(live, work_id, revision=revision),
                name=f"aion-http-analysis-{interaction_id}-{revision}",
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
        if (
            row["output_cleaned_at"] is None
            and live is not None
            and wait_seconds != 0
        ):
            live.changed.clear()
            before = self._journal_path(agent_id, interaction_id).stat().st_size
            if before <= cursor and row["status"] not in TERMINAL:
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
                "not_found", "http_response_not_found", "HTTP response body was not found"
            )
        path = self._response_dir(agent_id, interaction_id) / str(record["body_file"])
        if not path.exists():
            raise self._error(
                "not_found", "http_response_not_found", "HTTP response body was not found"
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
        if force:
            if row["execution_status"] != "completed":
                raise self._error(
                    "conflict",
                    "http_execution_not_completed",
                    "HTTP response analysis requires a completed request phase",
                )
            if row["analysis_status"] in {"queued", "running"}:
                if live is not None:
                    await self._wait(live.analysis_done, wait_seconds)
                row = await self._owned(agent_id, interaction_id)
                if row["analysis_status"] in {"queued", "running"}:
                    raise self._error(
                        "conflict",
                        "http_analysis_running",
                        "HTTP response analysis is already running",
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
            except Exception as exc:
                self._analysis_scopes.pop((interaction_id, revision), None)
                try:
                    await self.service.update_resource_work(
                        self.run_id,
                        self._work_id(interaction_id, "analysis", revision),
                        status="failed",
                        reason=type(exc).__name__,
                    )
                except StateNotFound:
                    pass
                await self.service.update_http_interaction(
                    self.run_id,
                    agent_id,
                    interaction_id,
                    status="failed",
                    execution_status="completed",
                    analysis_status="failed",
                    resource_status="failed",
                    error_code=type(exc).__name__,
                )
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
            statuses={"queued", "reserved", "running"},
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
                if row["analysis_status"] == "completed"
                else "interrupted"
            ),
            resource_status="stopped",
        )
        return await self._result_page(agent_id, interaction_id, cursor=0, limit=1)

    async def cleanup(self, agent_id: str, *, interaction_id: str) -> dict[str, Any]:
        row = await self._owned(agent_id, interaction_id)
        if row["status"] not in TERMINAL:
            raise self._error(
                "conflict",
                "http_interaction_running",
                "Active HTTP interaction must be stopped before cleanup",
            )
        if row["output_cleaned_at"] is not None:
            return {"interaction_id": interaction_id, "cleaned": False, "already_cleaned": True}
        path = self._interaction_dir(agent_id, interaction_id)
        if path.exists():
            shutil.rmtree(path)
        self._drop_interaction_caches(agent_id, interaction_id)
        await self.service.mark_http_interaction_cleaned(
            self.run_id, agent_id, interaction_id, reason="explicit"
        )
        return {"interaction_id": interaction_id, "cleaned": True, "already_cleaned": False}

    async def finish_agent(self, agent_id: str) -> None:
        rows = await self.service.list_http_interactions(self.run_id, agent_id=agent_id)
        for row in rows:
            if row["status"] not in TERMINAL:
                await self.stop(agent_id, interaction_id=row["interaction_id"])
            path = self._interaction_dir(agent_id, row["interaction_id"])
            if path.exists():
                shutil.rmtree(path)
            self._drop_interaction_caches(agent_id, row["interaction_id"])
            current = await self._owned(agent_id, row["interaction_id"])
            if current["output_cleaned_at"] is None:
                await self.service.mark_http_interaction_cleaned(
                    self.run_id,
                    agent_id,
                    row["interaction_id"],
                    reason="agent_terminal",
                )
        session_dir = self._agent_root(agent_id) / "http-sessions"
        if session_dir.exists():
            shutil.rmtree(session_dir)

    async def finish_run(self) -> None:
        rows = await self.service.list_http_interactions(self.run_id)
        for agent_id in sorted({str(row["agent_id"]) for row in rows}):
            await self.finish_agent(agent_id)
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
                    *(task for task in (live.execution_task, live.analysis_task) if task),
                    return_exceptions=True,
                )
                await self._record_unfinished_requests(
                    live, outcome="interrupted"
                )
            if row["kind"] in {"path_probe", "fingerprint"}:
                self._write_stopped_summary_if_missing(
                    row["agent_id"], row["interaction_id"], reason="interrupted"
                )
            current = await self._owned(row["agent_id"], row["interaction_id"])
            works = await self.service.list_resource_work(
                self.run_id,
                owner_id=row["interaction_id"],
                statuses={"queued", "reserved", "running"},
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
                    "completed"
                    if current["analysis_status"] == "completed"
                    else "interrupted"
                ),
                resource_status="interrupted",
            )
        self._live.clear()
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
                await self._append(live, {"type": "request_started", **self._request_json(item)})
                started += 1
                if started == 1 or started % 25 == 0:
                    await self.service.update_http_interaction(
                        self.run_id,
                        live.agent_id,
                        live.interaction_id,
                        started_requests=started,
                    )
                body_path = self._response_dir(
                    live.agent_id, live.interaction_id
                ) / f"{item.request_id}.body"
                if item.spec.session_id:
                    lock = self._session_locks.setdefault(
                        (live.agent_id, item.spec.session_id), asyncio.Lock()
                    )
                    async with lock:
                        session = self._load_session(
                            live.agent_id, item.spec.session_id
                        )
                        result, response_cookies = await self.engine.execute(
                            item,
                            body_path=body_path,
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
                    session = self._load_session(
                        live.agent_id, item.spec.session_id
                    )
                    result, _ = await self.engine.execute(
                        item,
                        body_path=body_path,
                        session_cookies=list(session.get("cookies", [])),
                    )
                await self._append(live, result)
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
            independent: list[ExpandedRequest] = []
            for item in live.requests:
                if item.spec.session_id:
                    session_requests.setdefault(item.spec.session_id, []).append(item)
                else:
                    independent.append(item)

            async def session_sequence(items: list[ExpandedRequest]) -> None:
                for item in sorted(items, key=lambda value: value.ordinal):
                    await one(item)

            await asyncio.gather(
                *(one(item) for item in independent),
                *(session_sequence(items) for items in session_requests.values()),
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
                status="analyzing",
                execution_status="completed",
                analysis_status="queued",
                resource_status="queued",
                started_requests=started,
                completed_requests=completed,
                response_bytes=response_bytes,
            )
            live.execution_done.set()
            live.changed.set()
            try:
                await self._queue_analysis(live, revision=1)
            except Exception as exc:
                analysis_work_id = self._work_id(
                    live.interaction_id, "analysis", 1
                )
                try:
                    await self.service.update_resource_work(
                        self.run_id,
                        analysis_work_id,
                        status="failed",
                        reason=type(exc).__name__,
                    )
                except StateNotFound:
                    pass
                await self.service.update_http_interaction(
                    self.run_id,
                    live.agent_id,
                    live.interaction_id,
                    status="failed",
                    execution_status="completed",
                    analysis_status="failed",
                    resource_status="failed",
                    error_code=type(exc).__name__,
                )
                live.analysis_done.set()
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
                analysis_status="interrupted",
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
            self.policy,
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

    def _write_summary(self, agent_id: str, interaction_id: str, summary: dict[str, Any]) -> None:
        path = self._interaction_dir(agent_id, interaction_id) / "summary.json"
        temporary = path.with_suffix(".json.part")
        temporary.write_text(
            json.dumps(summary, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    def _load_summary(self, agent_id: str, interaction_id: str) -> dict[str, Any] | None:
        path = self._interaction_dir(agent_id, interaction_id) / "summary.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_stopped_summary_if_missing(
        self, agent_id: str, interaction_id: str, *, reason: str
    ) -> None:
        if self._load_summary(agent_id, interaction_id) is not None:
            return
        plan = self._plan(agent_id, interaction_id)
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
        summary = self._path_probe_summary(
            options, result, estimated_requests=0
        )
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
            "stopped": result.stopped,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "duration_ms": result.duration_ms,
        }

    async def _queue_analysis(self, live: LiveInteraction, *, revision: int) -> None:
        row = await self._owned(live.agent_id, live.interaction_id)
        response_records = self._response_records(
            live.agent_id, live.interaction_id
        )
        largest_response = max(
            (int(item.get("body_bytes") or 0) for item in response_records),
            default=0,
        )
        await self.service.update_http_interaction(
            self.run_id,
            live.agent_id,
            live.interaction_id,
            status="analyzing",
            analysis_status="queued",
            resource_status="waiting",
        )
        work_id = self._work_id(live.interaction_id, "analysis", revision)
        await self.service.create_resource_work(
            self.run_id,
            live.agent_id,
            work_id=work_id,
            owner_type="http_interaction",
            owner_id=live.interaction_id,
            phase=f"analysis-{revision}",
            priority=row["priority"],
            requested_concurrency=1,
            estimated_requests=row["completed_requests"],
            estimated_disk_bytes=0,
            estimated_memory_bytes=max(65_536, largest_response),
        )
        decision = await self._admit(work_id)
        if decision.get("ok"):
            await self.launch_work(
                live.interaction_id, f"analysis-{revision}", work_id=work_id
            )

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
                    self._response_dir(live.agent_id, live.interaction_id) / str(body_file)
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
        records, next_cursor = self._read_records(
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
        planned_requests = self._load_plan(agent_id, interaction_id)
        started_requests = int(row["started_requests"])
        completed_requests = int(row["completed_requests"])
        execution_active = row["execution_status"] in {"queued", "running"}
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
                max(0, started_requests - completed_requests)
                if execution_active
                else 0
            ),
            "started_requests": started_requests,
            "completed_requests": completed_requests,
            "analyzed_responses": row["analyzed_responses"],
            "response_bytes": row["response_bytes"],
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
        }
        if row["kind"] in {"path_probe", "fingerprint"}:
            summary = self._load_summary(agent_id, interaction_id)
            page["summary"] = summary
            page["matched_requests"] = (
                int(summary.get("matched_requests") or 0)
                if summary is not None
                else 0
            )
        return page

    def _read_records(
        self,
        agent_id: str,
        interaction_id: str,
        *,
        cursor: int,
        limit: int,
        filters: HttpOutputFilters | None,
        record_types: set[str],
    ) -> tuple[list[dict[str, Any]], int]:
        path = self._journal_path(agent_id, interaction_id)
        records: list[dict[str, Any]] = []
        with path.open("rb") as source:
            source.seek(min(cursor, path.stat().st_size))
            while len(records) < limit:
                line = source.readline()
                if not line:
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
                records.append(self._compact_record(record))
            next_cursor = source.tell()
        return records, next_cursor

    @staticmethod
    def _compact_record(record: dict[str, Any]) -> dict[str, Any]:
        if record.get("type") != "response" or "headers" not in record:
            return record
        compact = dict(record)
        headers = {
            str(name).lower(): value for name, value in record.get("headers", {}).items()
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
        if filters.status_codes and record.get("status_code") not in filters.status_codes:
            return False
        if filters.outcomes and record.get("outcome") not in filters.outcomes:
            return False
        if filters.request_group_id and record.get("request_group_id") != filters.request_group_id:
            return False
        size = record.get("body_bytes")
        if filters.min_body_bytes is not None and (size is None or size < filters.min_body_bytes):
            return False
        if filters.max_body_bytes is not None and (size is None or size > filters.max_body_bytes):
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
        if filters.body_contains is not None and filters.body_contains.encode() not in data:
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
                    "error": "RuntimeInterrupted" if outcome == "interrupted" else "Stopped",
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

    async def _admit(self, work_id: str) -> dict[str, Any]:
        if self.admission_callback is None:
            return await self.service.update_resource_work(
                self.run_id, work_id, status="reserved"
            ) | {"ok": True}
        return await self.admission_callback(work_id)

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
            await self.service.update_http_interaction(
                self.run_id,
                live.agent_id,
                live.interaction_id,
                resource_status="waiting",
            )
            live.changed.set()
            await asyncio.sleep(float(decision.get("retry_after_seconds", 1.0)))

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
                "not_found", "http_interaction_not_found", "HTTP interaction was not found"
            ) from exc

    async def _interaction_any_owner(self, interaction_id: str) -> dict[str, Any]:
        rows = await self.service.list_http_interactions(self.run_id)
        row = next((item for item in rows if item["interaction_id"] == interaction_id), None)
        if row is None:
            raise self._error(
                "not_found", "http_interaction_not_found", "HTTP interaction was not found"
            )
        return row

    async def _request_owned(self, agent_id: str, request_id: str) -> bool:
        for row in await self.service.list_http_interactions(self.run_id, agent_id=agent_id):
            try:
                plan = self._plan(agent_id, row["interaction_id"])
                if any(
                    item.request_id == request_id
                    for item in self._load_plan(agent_id, row["interaction_id"])
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
                requests = self._load_plan(row["agent_id"], row["interaction_id"])
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

    async def _historical_response_estimate(
        self, requests: list[ExpandedRequest]
    ) -> int:
        from urllib.parse import urlsplit

        origins = {
            (parts.scheme.lower(), parts.hostname, parts.port)
            for item in requests
            for parts in [urlsplit(item.spec.url)]
        }
        rows = await self.service.list_http_interactions(self.run_id)
        values: list[int] = []
        for row in rows:
            for response in self._response_records(row["agent_id"], row["interaction_id"]):
                if response.get("outcome") != "response":
                    continue
                parts = urlsplit(str(response.get("final_url") or ""))
                if (parts.scheme.lower(), parts.hostname, parts.port) in origins:
                    values.append(int(response.get("body_bytes") or 0))
        values.sort()
        return values[len(values) // 2] if values else 65_536

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

    def _response_records(self, agent_id: str, interaction_id: str) -> list[dict[str, Any]]:
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

    async def _next_analysis_revision(
        self, agent_id: str, interaction_id: str
    ) -> int:
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
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "cookies": cookies,
                    "created_by": created,
                    "updated_by": {
                        "interaction_id": interaction_id,
                        "request_id": request_id,
                    },
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(path)

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
        return self.policy.root / ".system-tools" / "runs" / self.run_id / "agents" / agent_id

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
            raise self._error("conflict", "http_manager_closed", "HTTP manager is closed")

    @staticmethod
    def _error(error_type: str, code: str, message: str) -> SystemToolError:
        return SystemToolError(error_type=error_type, code=code, message=message)
