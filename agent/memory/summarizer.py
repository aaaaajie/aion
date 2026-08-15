"""Same-model Session Memory updater."""

from __future__ import annotations

import asyncio
import json
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

from .context import normalize_session_memory, truncate_text


class SummarizerError(RuntimeError):
    """A safe error raised when the Session Memory request fails."""


class SessionMemorySummarizer:
    def __init__(
        self,
        settings: AgentSettings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
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
        attempts = 0
        retry_delay_ms = 0
        response_status: int | None = None
        started = monotonic()
        summary_deadline = asyncio.get_running_loop().time() + 20.0
        if deadline_monotonic is not None:
            summary_deadline = min(summary_deadline, deadline_monotonic)
        while attempts < 2:
            attempts += 1
            try:
                remaining = summary_deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    self.last_metrics = {
                        "attempts": attempts,
                        "retry_delay_ms": retry_delay_ms,
                        "http_status": response_status,
                        "latency_ms": int((monotonic() - started) * 1_000),
                    }
                    raise SummarizerError("The Run deadline has expired")
                request = client.post(
                    completions_url(self.settings.llm_base_url),
                    headers={
                        "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.settings.llm_model,
                        "messages": [
                            {
                                "role": "system",
                                "content": load_prompt("session_memory_system.txt"),
                            },
                            {"role": "user", "content": prompt},
                        ],
                        **deepseek_auxiliary_request_options(),
                        "max_tokens": self.settings.context_budget.summary_max_output_tokens,
                    },
                )
                response = (
                    await asyncio.wait_for(request, timeout=remaining)
                    if remaining is not None
                    else await request
                )
                response_status = response.status_code
                response.raise_for_status()
                payload = response.json()
                break
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
                status = (
                    exc.response.status_code
                    if isinstance(exc, httpx.HTTPStatusError)
                    else None
                )
                retryable = isinstance(exc, (httpx.TransportError, asyncio.TimeoutError)) or status in {
                    408,
                    429,
                    500,
                    502,
                    503,
                    504,
                }
                if not retryable or attempts >= 2:
                    self.last_metrics = {
                        "attempts": attempts,
                        "retry_delay_ms": retry_delay_ms,
                        "http_status": status,
                        "latency_ms": int((monotonic() - started) * 1_000),
                    }
                    raise SummarizerError(
                        f"session memory request failed ({status or 'transport'})"
                    ) from exc
                retry_after = 0.0
                if isinstance(exc, httpx.HTTPStatusError):
                    try:
                        retry_after = float(exc.response.headers.get("Retry-After", "0"))
                    except ValueError:
                        retry_after = 0.0
                delay = min(2.0, max(retry_after, 0.25))
                if (
                    asyncio.get_running_loop().time() + delay >= summary_deadline
                ):
                    self.last_metrics = {
                        "attempts": attempts,
                        "retry_delay_ms": retry_delay_ms,
                        "http_status": status,
                        "latency_ms": int((monotonic() - started) * 1_000),
                    }
                    raise SummarizerError(
                        "session memory retry would exceed the Run deadline"
                    ) from exc
                retry_delay_ms += int(delay * 1_000)
                await asyncio.sleep(delay)

        self.last_metrics = {
            "attempts": attempts,
            "retry_delay_ms": retry_delay_ms,
            "http_status": response_status,
            "latency_ms": int((monotonic() - started) * 1_000),
        }
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise SummarizerError("session memory response was invalid") from exc
        if not isinstance(content, str) or not content.strip():
            raise SummarizerError("session memory response was empty")
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
        return "\n\n".join(
            [
                "Current memory:\n" + truncate_text(current_memory, 36_000),
                "Checkpoint:\n" + json.dumps(checkpoint, ensure_ascii=False, default=str),
                "Recent events:\n" + truncate_text(
                    json.dumps(list(recent_events), ensure_ascii=False, default=str),
                    48_000,
                ),
                "Recent conversation:\n" + truncate_text(
                    json.dumps(list(recent_messages), ensure_ascii=False, default=str),
                    48_000,
                ),
            ]
        )
