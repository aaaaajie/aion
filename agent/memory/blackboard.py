"""Bounded, projection-only LLM compaction for controller blackboards."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from time import monotonic
from typing import Any

import httpx

from agent.config import (
    AgentSettings,
    completions_url,
    deepseek_auxiliary_request_options,
)
from agent.prompts import load_prompt


class BlackboardCompactionError(RuntimeError):
    """Raised when a blackboard compaction response cannot be trusted."""


def _report_payload(report: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = report.get("payload")
    return payload if isinstance(payload, Mapping) else report


def _protected_report(report: Mapping[str, Any]) -> bool:
    payload = _report_payload(report)
    report_type = payload.get("type") or report.get("type")
    return bool(
        payload.get("candidate_flag")
        or report.get("candidate_flag")
        or report_type in {"bootstrap_checkpoint", "execution_checkpoint"}
        or payload.get("urgency") == "interrupt"
        or report.get("urgency") == "interrupt"
    )


def _compactable_item(report: Mapping[str, Any]) -> dict[str, Any] | None:
    payload = _report_payload(report)
    report_ref = report.get("report_ref")
    if not isinstance(report_ref, str) or not report_ref:
        return None
    item: dict[str, Any] = {
        "report_ref": report_ref,
        "type": payload.get("type") or report.get("type"),
        "status": payload.get("status") or report.get("status"),
        "summary": str(payload.get("summary") or report.get("summary") or "")[:1_000],
        "next_step": str(
            payload.get("next_step") or report.get("next_step") or ""
        )[:1_000],
        "finding_refs": [],
    }
    for finding in list(payload.get("findings") or []):
        if not isinstance(finding, Mapping):
            continue
        finding_ref = finding.get("finding_ref")
        if not isinstance(finding_ref, str) or not finding_ref:
            continue
        item["finding_refs"].append(
            {
                "finding_ref": finding_ref,
                "category": finding.get("category"),
            }
        )
    return item


def _merge_text(report: Mapping[str, Any], item: Mapping[str, Any]) -> None:
    payload = report.get("payload")
    target = payload if isinstance(payload, dict) else report
    for key, limit in (("summary", 1_000), ("next_step", 1_000)):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            target[key] = value.strip()[:limit]


class BlackboardCompactor:
    """Use the configured model only to shorten safe, non-authoritative text."""

    def __init__(
        self,
        settings: AgentSettings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.client = client
        self.last_metrics: dict[str, Any] = {}

    async def compact(
        self,
        payload: Mapping[str, Any],
        *,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]:
        reports = list(payload.get("reports") or [])
        if not reports:
            raise BlackboardCompactionError("blackboard has no compressible reports")
        candidates = [
            item
            for report in reports
            if isinstance(report, Mapping)
            and not _protected_report(report)
            for item in [_compactable_item(report)]
            if item is not None
        ]
        if not candidates:
            raise BlackboardCompactionError("blackboard has no compressible reports")
        prompt = self._build_prompt(candidates)
        client = self.client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0))
        started = monotonic()
        attempts = 0
        try:
            while attempts < 1:
                attempts += 1
                timeout = 20.0
                if deadline_monotonic is not None:
                    timeout = min(
                        timeout,
                        max(0.0, deadline_monotonic - asyncio.get_running_loop().time()),
                    )
                if timeout <= 0:
                    raise BlackboardCompactionError("blackboard compaction deadline expired")
                response = await asyncio.wait_for(
                    client.post(
                        completions_url(self.settings.llm_base_url),
                        headers={
                            "Authorization": (
                                "Bearer "
                                + self.settings.llm_api_key.get_secret_value()
                            ),
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": self.settings.llm_model,
                            "messages": [
                                {
                                    "role": "system",
                                    "content": load_prompt(
                                        "blackboard_compactor_system.txt"
                                    ),
                                },
                                {"role": "user", "content": prompt},
                            ],
                            **deepseek_auxiliary_request_options(),
                            "max_tokens": min(
                                self.settings.context_budget.summary_max_output_tokens,
                                2_048,
                            ),
                        },
                    ),
                    timeout=timeout,
                )
                response.raise_for_status()
                try:
                    content = response.json()["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise BlackboardCompactionError(
                        "blackboard compaction response was invalid"
                    ) from exc
                if not isinstance(content, str) or not content.strip():
                    raise BlackboardCompactionError(
                        "blackboard compaction response was empty"
                    )
                return self._apply(payload, content, candidates)
        except BlackboardCompactionError:
            raise
        except (httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
            raise BlackboardCompactionError(
                "blackboard compaction request failed"
            ) from exc
        finally:
            self.last_metrics = {
                "attempts": attempts,
                "latency_ms": int((monotonic() - started) * 1_000),
            }
            if owns_client:
                await client.aclose()

    @staticmethod
    def _build_prompt(items: Sequence[Mapping[str, Any]]) -> str:
        return (
            "Compress only the safe controller projection below. Return strict JSON "
            "with an `items` array. Each item must use an existing report_ref and "
            "may contain only report_ref, summary, and next_step. Do not invent "
            "facts, refs, findings, candidates, credentials, Evidence, tasks, or "
            "status changes. Preserve meaning and make text concise.\n\n"
            + json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))
        )

    @staticmethod
    def _apply(
        payload: Mapping[str, Any],
        content: str,
        candidates: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            raise BlackboardCompactionError(
                "blackboard compaction response was not JSON"
            ) from exc
        if not isinstance(decoded, Mapping) or not isinstance(decoded.get("items"), list):
            raise BlackboardCompactionError("blackboard compaction schema was invalid")
        allowed = {
            item.get("report_ref")
            for item in candidates
            if isinstance(item.get("report_ref"), str)
        }
        updates: dict[str, Mapping[str, Any]] = {}
        for item in decoded["items"]:
            if not isinstance(item, Mapping):
                raise BlackboardCompactionError("blackboard compaction item was invalid")
            report_ref = item.get("report_ref")
            if report_ref not in allowed or report_ref in updates:
                raise BlackboardCompactionError(
                    "blackboard compaction returned an unknown report reference"
                )
            if any(
                key not in {"report_ref", "summary", "next_step"}
                for key in item
            ):
                raise BlackboardCompactionError(
                    "blackboard compaction changed protected fields"
                )
            updates[report_ref] = item
        result = json.loads(json.dumps(payload, ensure_ascii=False, default=str))
        for report in result.get("reports") or []:
            if not isinstance(report, dict):
                continue
            report_ref = report.get("report_ref")
            item = updates.get(report_ref)
            if item is not None:
                _merge_text(report, item)
        result["compacted"] = True
        return result
