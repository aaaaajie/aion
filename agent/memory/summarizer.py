"""Same-model Session Memory updater."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import httpx

from agent.config import AgentSettings, completions_url
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
        try:
            response = await client.post(
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
                    "temperature": 0,
                    "max_tokens": self.settings.context_budget.max_output_tokens,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SummarizerError("session memory request failed") from exc

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
