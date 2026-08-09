"""Token estimation, bounded tool results, and context reconstruction."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from agent.config import ContextBudget


REQUIRED_MEMORY_SECTIONS = (
    "Current State",
    "Task Specification",
    "Targets",
    "Important Observations",
    "Workflow",
    "Errors & Corrections",
    "Next Steps",
    "Worklog",
)
MEMORY_SECTION_MAX_TOKENS = 2_000
SUMMARY_INIT_TOKENS = 50_000
SUMMARY_UPDATE_TOKENS = 50_000
SUMMARY_UPDATE_TOOL_CALLS = 20
DEFAULT_MODEL_RESULT_CHARS = 12_000


def rough_token_count(value: Any) -> int:
    """Conservatively estimate tokens without adding a tokenizer dependency."""

    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    byte_count = len(value.encode("utf-8"))
    return max(0, math.ceil(byte_count / 3))


def message_token_count(messages: Sequence[Mapping[str, Any]]) -> int:
    return rough_token_count(list(messages))


def prompt_tokens_from_response(payload: Mapping[str, Any]) -> int | None:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return None
    for key in ("prompt_tokens", "input_tokens"):
        value = usage.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return None


def truncate_text(value: str, max_chars: int) -> str:
    if len(value) <= max_chars:
        return value
    if max_chars < 80:
        return value[:max_chars]
    marker = "\n... [truncated by Agent context manager] ...\n"
    available = max_chars - len(marker)
    head = available // 2
    tail = available - head
    return value[:head] + marker + value[-tail:]


def tool_result_for_model(result: Any, max_chars: int = DEFAULT_MODEL_RESULT_CHARS) -> str:
    """Serialize a tool result while keeping prompt growth bounded."""

    encoded = json.dumps(result, ensure_ascii=False, default=str, separators=(",", ":"))
    if len(encoded) <= max_chars:
        return encoded
    if isinstance(result, Mapping):
        compact: dict[str, Any] = {"ok": result.get("ok"), "truncated": True}
        if result.get("ok") is False:
            compact["error"] = result.get("error", {})
        compact["preview"] = truncate_text(encoded, max_chars - 80)
        return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(
        {
            "truncated": True,
            "preview": truncate_text(encoded, max_chars - 40),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def should_update_memory(
    *,
    current_tokens: int,
    last_summary_tokens: int,
    tool_calls_since_summary: int,
) -> bool:
    if last_summary_tokens == 0:
        return current_tokens >= SUMMARY_INIT_TOKENS
    return (
        current_tokens - last_summary_tokens >= SUMMARY_UPDATE_TOKENS
        or tool_calls_since_summary >= SUMMARY_UPDATE_TOOL_CALLS
    )


def should_autocompact(current_tokens: int, budget: ContextBudget) -> bool:
    return current_tokens >= budget.autocompact_threshold


def normalize_session_memory(
    content: str,
    *,
    max_tokens: int = 12_000,
    section_max_tokens: int = MEMORY_SECTION_MAX_TOKENS,
) -> tuple[str, bool]:
    """Keep required headings and cap each section without adding new facts."""

    sections = _parse_sections(content)
    changed = any(section not in sections for section in REQUIRED_MEMORY_SECTIONS)
    output: list[str] = []
    for section in REQUIRED_MEMORY_SECTIONS:
        body = sections.get(section, "").strip()
        limited = truncate_text(body, section_max_tokens * 3)
        if limited != body:
            changed = True
        output.append(f"# {section}\n\n{limited}".rstrip())
    normalized = "\n\n".join(output) + "\n"
    if rough_token_count(normalized) > max_tokens:
        changed = True
        normalized = truncate_text(normalized, max_tokens * 3)
        normalized = _restore_required_headings(normalized)
    return normalized, changed


def build_runtime_messages(
    *,
    base_system_prompt: str,
    initial_user_message: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    session_memory: str,
    recent_messages: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Rebuild a bounded message list after compaction or recovery."""

    state_text = json.dumps(checkpoint, ensure_ascii=False, default=str, indent=2)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": base_system_prompt},
        {
            "role": "system",
            "content": f"<session_memory>\n{session_memory}\n</session_memory>",
        },
        {
            "role": "system",
            "content": (
                "The following run checkpoint is the latest authoritative state. "
                "It overrides any conflicting statement in session memory.\n"
                f"<run_checkpoint>\n{state_text}\n</run_checkpoint>"
            ),
        },
        dict(initial_user_message),
    ]
    messages.extend(_safe_recent_messages(recent_messages))
    return messages


def _parse_sections(content: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in content.splitlines():
        if line.startswith("# "):
            current = line[2:].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {key: "\n".join(value).strip() for key, value in sections.items()}


def _restore_required_headings(content: str) -> str:
    sections = _parse_sections(content)
    return "\n\n".join(
        f"# {section}\n\n{sections.get(section, '')}".rstrip()
        for section in REQUIRED_MEMORY_SECTIONS
    ) + "\n"


def _safe_recent_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not messages:
        return []
    tail = [dict(message) for message in messages[-80:]]
    while tail and tail[0].get("role") == "tool":
        tail.pop(0)
    return tail
