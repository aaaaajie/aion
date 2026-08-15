"""Fail-soft two-stage Skill discovery for Execution Agents."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import logging
from time import monotonic
from typing import Any
from uuid import uuid4

import httpx

from agent.config import (
    AgentSettings,
    completions_url,
    deepseek_auxiliary_request_options,
)

from .catalog import MAX_DISCOVERY_CANDIDATES, SkillCatalog


LOGGER = logging.getLogger("aion.skill_discovery")
MAX_PRESENTED_CANDIDATES = 5
MAX_REASON_CHARS = 160
DISCOVERY_TIMEOUT_SECONDS = 5.0
DISCOVERY_MAX_TOKENS = 512
DISCOVERY_CONCURRENCY = 4
DISCOVERY_CACHE_SIZE = 256


@dataclass(frozen=True)
class SkillCandidate:
    skill_id: str
    description: str
    when_to_use: str
    relevance_reason: str
    confidence: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "description": self.description,
            "when_to_use": self.when_to_use,
            "relevance_reason": self.relevance_reason,
        }


@dataclass(frozen=True)
class SkillDiscoveryResult:
    candidates: tuple[SkillCandidate, ...]
    source: str
    latency_ms: int
    cache_hit: bool
    discovery_call_id: str


class SkillDiscoveryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class SkillDiscovery:
    """Run-scoped prefilter that never activates Skills or blocks admission."""

    def __init__(
        self,
        settings: AgentSettings,
        catalog: SkillCatalog,
        service: Any,
        run_id: str,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.catalog = catalog
        self.service = service
        self.run_id = run_id
        self._client = client
        self._owns_client = client is None
        self._semaphore = asyncio.Semaphore(DISCOVERY_CONCURRENCY)
        self._cache: OrderedDict[str, SkillDiscoveryResult] = OrderedDict()
        self._tasks: dict[str, asyncio.Task[SkillDiscoveryResult]] = {}

    def prefetch(
        self,
        agent_id: str,
        *,
        objective: str,
        task_stage: str | None,
        hypothesis: str | None,
        excluded_ids: tuple[str, ...] = (),
    ) -> asyncio.Task[SkillDiscoveryResult]:
        existing = self._tasks.get(agent_id)
        if existing is not None:
            return existing
        task = asyncio.create_task(
            self._discover(
                agent_id,
                objective=objective,
                task_stage=task_stage,
                hypothesis=hypothesis,
                excluded_ids=excluded_ids,
            ),
            name=f"skill-discovery-{agent_id}",
        )
        self._tasks[agent_id] = task
        return task

    async def candidates_for(
        self,
        agent_id: str,
        *,
        objective: str,
        task_stage: str | None,
        hypothesis: str | None,
        excluded_ids: tuple[str, ...] = (),
    ) -> SkillDiscoveryResult:
        return await self.prefetch(
            agent_id,
            objective=objective,
            task_stage=task_stage,
            hypothesis=hypothesis,
            excluded_ids=excluded_ids,
        )

    async def close(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        client = self._client
        self._client = None
        if self._owns_client and client is not None and not client.is_closed:
            await client.aclose()

    async def _discover(
        self,
        agent_id: str,
        *,
        objective: str,
        task_stage: str | None,
        hypothesis: str | None,
        excluded_ids: tuple[str, ...],
    ) -> SkillDiscoveryResult:
        started = monotonic()
        call_id = f"skill_discovery_{uuid4().hex}"
        recovered = await self._recover(
            agent_id, call_id=call_id, excluded_ids=excluded_ids
        )
        if recovered is not None:
            return recovered

        task_text = self._task_text(objective, task_stage, hypothesis)
        local = self.catalog.discovery_candidates(
            task_text,
            limit=MAX_DISCOVERY_CANDIDATES,
        )
        cache_key = sha256(
            f"{self.catalog.content_sha256}\n{task_text}".encode("utf-8")
        ).hexdigest()
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            result = self._without_excluded(
                SkillDiscoveryResult(
                    candidates=cached.candidates,
                    source=cached.source,
                    latency_ms=int((monotonic() - started) * 1_000),
                    cache_hit=True,
                    discovery_call_id=call_id,
                ),
                excluded_ids,
            )
            await self._emit_completed(agent_id, result)
            return result

        await self._emit(
            agent_id,
            "skill_discovery_started",
            {
                "discovery_call_id": call_id,
                "catalog_sha256": self.catalog.content_sha256,
                "local_candidate_count": len(local),
            },
        )
        if not self.settings.skill_discovery_model:
            cached_result = SkillDiscoveryResult(
                candidates=tuple(
                    SkillCandidate(
                        skill_id=str(item["skill_id"]),
                        description=str(item["description"]),
                        when_to_use=str(item["when_to_use"]),
                        relevance_reason=(
                            "Deterministic capability-pack routing; confirm "
                            "applicability before invoking."
                        ),
                    )
                    for item in local[:MAX_PRESENTED_CANDIDATES]
                ),
                source="local_capability_pack",
                latency_ms=int((monotonic() - started) * 1_000),
                cache_hit=False,
                discovery_call_id=call_id,
            )
            self._remember(cache_key, cached_result)
            result = self._without_excluded(cached_result, excluded_ids)
            await self._emit(
                agent_id,
                "skill_discovery_fallback",
                self._event_payload(result, failure_code="local_capability_pack"),
            )
            await self._emit_completed(agent_id, result)
            return result

        try:
            remaining = DISCOVERY_TIMEOUT_SECONDS - (monotonic() - started)
            if remaining <= 0:
                raise SkillDiscoveryError("timeout", "Skill discovery timed out")
            async with asyncio.timeout(remaining):
                async with self._semaphore:
                    remaining = DISCOVERY_TIMEOUT_SECONDS - (monotonic() - started)
                    if remaining <= 0:
                        raise SkillDiscoveryError(
                            "timeout", "Skill discovery timed out"
                        )
                    response = await asyncio.wait_for(
                        self._http_client().post(
                            completions_url(self.settings.llm_base_url),
                            headers={
                                "Authorization": (
                                    "Bearer "
                                    + self.settings.llm_api_key.get_secret_value()
                                ),
                                "Content-Type": "application/json",
                            },
                            json=self._request_payload(task_text, local),
                        ),
                        timeout=remaining,
                    )
            if response.status_code == 429:
                raise SkillDiscoveryError("rate_limited", "Discovery was rate limited")
            if response.status_code >= 500:
                raise SkillDiscoveryError(
                    "provider_unavailable", "Discovery provider was unavailable"
                )
            if response.status_code >= 400:
                raise SkillDiscoveryError(
                    "provider_rejected", "Discovery provider rejected the request"
                )
            candidates = self._parse_response(response, local)
            cached_result = SkillDiscoveryResult(
                candidates=tuple(candidates),
                source="model",
                latency_ms=int((monotonic() - started) * 1_000),
                cache_hit=False,
                discovery_call_id=call_id,
            )
            self._remember(cache_key, cached_result)
            result = self._without_excluded(cached_result, excluded_ids)
            await self._emit_completed(agent_id, result)
            return result
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            failure_code = "timeout"
        except httpx.TimeoutException:
            failure_code = "timeout"
        except httpx.HTTPError:
            failure_code = "connection_error"
        except SkillDiscoveryError as exc:
            failure_code = exc.code
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            failure_code = "invalid_response"
        except Exception:
            LOGGER.exception(
                "skill_discovery_unexpected_error run_id=%s agent_id=%s call_id=%s",
                self.run_id,
                agent_id,
                call_id,
            )
            failure_code = "unexpected_error"
        return await self._fallback(
            agent_id,
            local,
            started=started,
            call_id=call_id,
            cache_key=cache_key,
            failure_code=failure_code,
            excluded_ids=excluded_ids,
        )

    async def _fallback(
        self,
        agent_id: str,
        local: list[dict[str, Any]],
        *,
        started: float,
        call_id: str,
        cache_key: str,
        failure_code: str,
        excluded_ids: tuple[str, ...],
    ) -> SkillDiscoveryResult:
        latency_ms = int((monotonic() - started) * 1_000)
        await self._emit(
            agent_id,
            "skill_discovery_failed",
            {
                "discovery_call_id": call_id,
                "failure_code": failure_code,
                "latency_ms": latency_ms,
            },
        )
        candidates = tuple(
            SkillCandidate(
                skill_id=str(item["skill_id"]),
                description=str(item["description"]),
                when_to_use=str(item["when_to_use"]),
                relevance_reason="Local catalog match; confirm applicability before invoking.",
            )
            for item in local[:MAX_PRESENTED_CANDIDATES]
        )
        cached_result = SkillDiscoveryResult(
            candidates=candidates,
            source="local_fallback",
            latency_ms=latency_ms,
            cache_hit=False,
            discovery_call_id=call_id,
        )
        self._remember(cache_key, cached_result)
        result = self._without_excluded(cached_result, excluded_ids)
        await self._emit(
            agent_id,
            "skill_discovery_fallback",
            self._event_payload(result, failure_code=failure_code),
        )
        return result

    async def _recover(
        self,
        agent_id: str,
        *,
        call_id: str,
        excluded_ids: tuple[str, ...],
    ) -> SkillDiscoveryResult | None:
        try:
            event = await self.service.latest_agent_event(
                self.run_id,
                agent_id,
                event_types={
                    "skill_discovery_completed",
                    "skill_discovery_fallback",
                },
            )
        except Exception:
            return None
        if not isinstance(event, Mapping):
            return None
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            return None
        if payload.get("catalog_sha256") != self.catalog.content_sha256:
            return None
        ids = payload.get("candidate_ids")
        if not isinstance(ids, list) or len(ids) > MAX_PRESENTED_CANDIDATES:
            return None
        candidates: list[SkillCandidate] = []
        try:
            for skill_id in ids:
                record = self.catalog.get("execution", str(skill_id))
                candidates.append(
                    SkillCandidate(
                        skill_id=record.skill_id,
                        description=record.description,
                        when_to_use=record.when_to_use,
                        relevance_reason="Recovered completed Skill discovery candidate.",
                    )
                )
        except Exception:
            return None
        return self._without_excluded(
            SkillDiscoveryResult(
                candidates=tuple(candidates),
                source="recovered",
                latency_ms=0,
                cache_hit=True,
                discovery_call_id=(
                    str(payload["discovery_call_id"])
                    if isinstance(payload.get("discovery_call_id"), str)
                    else call_id
                ),
            ),
            excluded_ids,
        )

    def _parse_response(
        self, response: httpx.Response, local: list[dict[str, Any]]
    ) -> list[SkillCandidate]:
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise SkillDiscoveryError("invalid_response", "Missing model content")
        decoded = json.loads(content)
        values = decoded.get("candidates") if isinstance(decoded, Mapping) else None
        if not isinstance(values, list) or len(values) > MAX_PRESENTED_CANDIDATES:
            raise SkillDiscoveryError("invalid_response", "Invalid candidate list")
        allowed = {str(item["skill_id"]): item for item in local}
        seen: set[str] = set()
        result: list[SkillCandidate] = []
        for value in values:
            if not isinstance(value, Mapping):
                raise SkillDiscoveryError("invalid_response", "Invalid candidate")
            skill_id = value.get("skill_id")
            confidence = value.get("confidence")
            reason = value.get("reason")
            if (
                not isinstance(skill_id, str)
                or skill_id not in allowed
                or skill_id in seen
                or isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= float(confidence) <= 1
                or not isinstance(reason, str)
            ):
                raise SkillDiscoveryError("invalid_response", "Invalid candidate fields")
            normalized_reason = " ".join(reason.split())
            if not normalized_reason or len(normalized_reason) > MAX_REASON_CHARS:
                raise SkillDiscoveryError("invalid_response", "Invalid candidate reason")
            seen.add(skill_id)
            source = allowed[skill_id]
            result.append(
                SkillCandidate(
                    skill_id=skill_id,
                    description=str(source["description"]),
                    when_to_use=str(source["when_to_use"]),
                    relevance_reason=normalized_reason,
                    confidence=float(confidence),
                )
            )
        return result

    def _request_payload(
        self, task_text: str, local: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "model": self.settings.skill_discovery_model,
            **deepseek_auxiliary_request_options(),
            "max_tokens": DISCOVERY_MAX_TOKENS,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Select zero to five genuinely relevant skills for the bounded "
                        "execution task. Do not select a skill from generic word overlap. "
                        "Return strict JSON only: {\"candidates\":[{\"skill_id\":\"...\","
                        "\"confidence\":0.0,\"reason\":\"...\"}]}. Use only IDs in "
                        "the supplied catalog and keep each reason under 160 characters."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {"task": task_text, "catalog": local},
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
            ],
        }

    @staticmethod
    def _task_text(
        objective: str, task_stage: str | None, hypothesis: str | None
    ) -> str:
        return "\n".join(
            (
                f"objective: {' '.join(objective.split())}",
                f"task_stage: {' '.join((task_stage or '').split())}",
                f"hypothesis: {' '.join((hypothesis or '').split())}",
            )
        )[:8_000]

    def _http_client(self) -> httpx.AsyncClient:
        client = self._client
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(DISCOVERY_TIMEOUT_SECONDS),
                limits=httpx.Limits(
                    max_connections=DISCOVERY_CONCURRENCY,
                    max_keepalive_connections=DISCOVERY_CONCURRENCY,
                ),
            )
            self._client = client
            self._owns_client = True
        return client

    def _remember(self, cache_key: str, result: SkillDiscoveryResult) -> None:
        self._cache[cache_key] = result
        self._cache.move_to_end(cache_key)
        while len(self._cache) > DISCOVERY_CACHE_SIZE:
            self._cache.popitem(last=False)

    @staticmethod
    def _without_excluded(
        result: SkillDiscoveryResult, excluded_ids: tuple[str, ...]
    ) -> SkillDiscoveryResult:
        if not excluded_ids:
            return result
        excluded = set(excluded_ids)
        return SkillDiscoveryResult(
            candidates=tuple(
                item for item in result.candidates if item.skill_id not in excluded
            ),
            source=result.source,
            latency_ms=result.latency_ms,
            cache_hit=result.cache_hit,
            discovery_call_id=result.discovery_call_id,
        )

    async def _emit_completed(
        self, agent_id: str, result: SkillDiscoveryResult
    ) -> None:
        await self._emit(
            agent_id,
            "skill_discovery_completed",
            self._event_payload(result),
        )

    def _event_payload(
        self,
        result: SkillDiscoveryResult,
        *,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "discovery_call_id": result.discovery_call_id,
            "catalog_sha256": self.catalog.content_sha256,
            "candidate_ids": [item.skill_id for item in result.candidates],
            "candidate_count": len(result.candidates),
            "source": result.source,
            "latency_ms": result.latency_ms,
            "cache_hit": result.cache_hit,
        }
        if failure_code is not None:
            payload["failure_code"] = failure_code
        return payload

    async def _emit(
        self, agent_id: str, event_type: str, payload: dict[str, Any]
    ) -> None:
        try:
            await self.service.append_agent_event(
                self.run_id, agent_id, event_type, payload
            )
        except Exception:
            LOGGER.warning(
                "skill_discovery_event_failed run_id=%s agent_id=%s event_type=%s",
                self.run_id,
                agent_id,
                event_type,
            )
