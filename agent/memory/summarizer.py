"""Same-model Session Memory updater."""

from __future__ import annotations

import asyncio
from agent.model_usage import post_model
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from time import monotonic

import httpx

from agent.config import (
    AgentSettings,
    completions_url,
    deepseek_auxiliary_request_options,
)
from agent.prompts import load_prompt

from .context import normalize_session_memory, rough_token_count, truncate_text


class SummarizerError(RuntimeError):
    """A safe error raised when the Session Memory request fails."""


class SessionMemorySummarizer:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        client: httpx.AsyncClient | None = None,
        event_writer=None,
    ) -> None:
        self.settings = settings
        self.event_writer = event_writer
        self._client = client
        self._owns_client = client is None
        self.last_metrics: dict[str, Any] = {}

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def summarize(
        self,
        *,
        current_memory: str,
        checkpoint: Mapping[str, Any],
        recent_messages: Sequence[Mapping[str, Any]],
        recent_events: Sequence[Mapping[str, Any]],
        deadline_monotonic: float | None = None,
    ) -> str:
        client = self._client
        if client is None:
            client = httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=20.0))
            self._client = client
        prompt = self._build_prompt(
            current_memory=current_memory,
            checkpoint=checkpoint,
            recent_messages=recent_messages,
            recent_events=recent_events,
        )
        payload: Any = None
        attempts = 1
        response_status: int | None = None
        started = monotonic()
        summary_deadline = asyncio.get_running_loop().time() + 20.0
        if deadline_monotonic is not None:
            summary_deadline = min(summary_deadline, deadline_monotonic)
        try:
            remaining = summary_deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise SummarizerError("The Run deadline has expired")
            response = await asyncio.wait_for(
                post_model(
                    client,
                    completions_url(self.settings.llm_base_url),
                    event_writer=self.event_writer,
                    purpose="memory",
                    headers={
                        "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.settings.llm_model,
                        "messages": [
                            {"role": "system", "content": load_prompt("session_memory_system.txt")},
                            {"role": "user", "content": prompt},
                        ],
                        **deepseek_auxiliary_request_options(),
                        "max_tokens": self.settings.context_budget.summary_max_output_tokens,
                    },
                ),
                timeout=remaining,
            )
            response_status = response.status_code
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
            status = (
                exc.response.status_code
                if isinstance(exc, httpx.HTTPStatusError)
                else None
            )
            self.last_metrics = {
                "attempts": attempts,
                "http_status": status,
                "latency_ms": int((monotonic() - started) * 1_000),
            }
            raise SummarizerError(
                f"session memory request failed ({status or 'transport'})"
            ) from exc
        except SummarizerError:
            self.last_metrics = {
                "attempts": attempts,
                "http_status": response_status,
                "latency_ms": int((monotonic() - started) * 1_000),
            }
            raise

        self.last_metrics = {
            "attempts": attempts,
            "http_status": response_status,
            "latency_ms": int((monotonic() - started) * 1_000),
        }
        try:
            choice = payload["choices"][0]
            finish_reason = choice.get("finish_reason")
            if finish_reason in {"length", "max_tokens", "truncated"}:
                raise SummarizerError(
                    f"session memory response was truncated ({finish_reason})"
                )
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise SummarizerError("session memory response was invalid") from exc
        if not isinstance(content, str) or not content.strip():
            raise SummarizerError("session memory response was empty")
        if rough_token_count(content) > self.settings.context_budget.summary_max_output_tokens:
            raise SummarizerError("session memory response exceeded its output budget")
        normalized, _ = normalize_session_memory(
            content,
            max_tokens=self.settings.context_budget.session_memory_max_tokens,
        )
        return normalized

    @staticmethod
    def _build_prompt(
        *,
        current_memory: str,
        checkpoint: Mapping[str, Any],
        recent_messages: Sequence[Mapping[str, Any]],
        recent_events: Sequence[Mapping[str, Any]],
    ) -> str:
        compact_events = [SessionMemorySummarizer._compact_event(event) for event in recent_events[-60:]]
        compact_messages = [
            item
            for item in (
                SessionMemorySummarizer._compact_message(message)
                for message in recent_messages[-60:]
            )
            if item
        ]
        compact_events, compact_messages = SessionMemorySummarizer._bound_recent(
            compact_events, compact_messages, max_tokens=8_000
        )
        return "\n\n".join(
            [
                "Current memory:\n" + truncate_text(current_memory, 24_000),
                "Checkpoint:\n" + truncate_text(json.dumps(checkpoint, ensure_ascii=False, default=str), 8_000),
                "Recent events:\n" + json.dumps(compact_events, ensure_ascii=False, default=str),
                "Recent conversation:\n" + json.dumps(compact_messages, ensure_ascii=False, default=str),
            ]
        )

    @staticmethod
    def _bound_recent(
        events: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        *,
        max_tokens: int,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Keep the newest compact records under the shared recent-input budget."""
        while rough_token_count((events, messages)) > max_tokens:
            if events and (not messages or len(events) >= len(messages)):
                events.pop(0)
            elif messages:
                messages.pop(0)
            else:
                break
        return events, messages

    @staticmethod
    def _compact_event(event: Mapping[str, Any]) -> dict[str, Any]:
        # Persisted events use ``payload``; replay fixtures and a few legacy
        # records carry their useful text in ``content``.  Keep that text in
        # the compact input so corrections/revocations remain auditable.
        payload = event.get("payload", event.get("content"))
        if isinstance(payload, Mapping):
            keep = {
                key: SessionMemorySummarizer._compact_value(payload[key], max_chars=2_000)
                for key in (
                    "tool_name", "tool_call_id", "execution_fact", "observation_data",
                    "result_ref", "result_persisted", "error_code", "status", "unique_code",
                    "report_type", "through_sequence", "reason", "cleanup", "resource_usage",
                    "task_key", "objective", "success_criteria", "context_refs", "pending",
                    "todo", "next_test", "hypothesis_id", "assessment", "summary",
                    "validation", "revoked_sequences", "correction", "tasks", "task_snapshot",
                    "progress_kind",
                )
                if key in payload
            }
        else:
            keep = {"value": truncate_text(str(payload), 500)} if payload is not None else {}
        return {
            key: event[key]
            for key in ("sequence", "event_type", "agent_id", "created_at")
            if key in event
        } | {"payload": keep}

    @staticmethod
    def _compact_value(value: Any, *, max_chars: int) -> Any:
        encoded = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(encoded) <= max_chars:
            return value
        return truncate_text(encoded, max_chars)

    @staticmethod
    def _compact_message(message: Mapping[str, Any]) -> dict[str, Any]:
        role = message.get("role")
        if role == "system":
            return {}
        content = message.get("content")
        if isinstance(content, str):
            content = re.sub(
                r"<(active_skills|capability_directory|capability_hints)>.*?</\1>",
                "",
                content,
                flags=re.S,
            ).strip()
            try:
                parsed = json.loads(content)
            except (TypeError, ValueError):
                parsed = truncate_text(content, 800)
            else:
                if isinstance(parsed, Mapping):
                    parsed = {
                        key: SessionMemorySummarizer._compact_value(parsed[key], max_chars=1_200)
                        for key in (
                            "ok", "status", "error", "result_ref", "evidence_refs",
                            "event_sequence", "task_id", "tasks", "todo", "next_test",
                            "correction", "review", "summary", "hypothesis_id", "assessment",
                        )
                        if key in parsed
                    }
                content = parsed
        return {"role": role, "content": content}
