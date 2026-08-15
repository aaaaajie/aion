"""Token estimation, bounded tool results, and context reconstruction."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from agent.config import ContextBudget, RoleContextProfile


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
SUMMARY_UPDATE_TOOL_CALLS = 20
ROLE_SUMMARY_TOOL_CALL_LIMITS = {
    "chief": 12,
    "challenge": 8,
    "execution": SUMMARY_UPDATE_TOOL_CALLS,
}
DEFAULT_MODEL_RESULT_CHARS = 12_000
REQUEST_CONTEXT_SAFETY_TOKENS = 8_192
REQUEST_PROMPT_CALIBRATION_INITIAL = 1.15
TOOL_TOKEN_ESTIMATE_MULTIPLIER = 1.5


def rough_token_count(value: Any) -> int:
    """Conservatively estimate tokens without adding a tokenizer dependency."""

    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    byte_count = len(value.encode("utf-8"))
    return max(0, math.ceil(byte_count / 3))


def message_token_count(messages: Sequence[Mapping[str, Any]]) -> int:
    return rough_token_count(list(messages))


def request_token_count(
    messages: Sequence[Mapping[str, Any]],
    tool_definitions: Sequence[Mapping[str, Any]],
) -> int:
    """Estimate the provider's prompt size including the tool schema."""

    return message_token_count(messages) + rough_token_count(tool_definitions)


def request_message_budget(
    *,
    context_budget: ContextBudget,
    tool_definitions: Sequence[Mapping[str, Any]],
    role: str | None = None,
    bootstrap: bool = False,
    calibration_ratio: float = REQUEST_PROMPT_CALIBRATION_INITIAL,
) -> int:
    """Return a transcript budget below the provider's absolute input limit."""

    estimated_tools = math.ceil(
        rough_token_count(tool_definitions) * TOOL_TOKEN_ESTIMATE_MULTIPLIER
    )
    calibrated_capacity = math.floor(
        context_budget.absolute_prompt_tokens(role, bootstrap=bootstrap)
        / max(1.0, calibration_ratio * 1.05)
    )
    budget = calibrated_capacity - estimated_tools
    if budget < 8_000:
        raise ValueError("tool definitions leave insufficient model context")
    return budget


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


def summary_tool_call_limit(role: str | None) -> int:
    return ROLE_SUMMARY_TOOL_CALL_LIMITS.get(role or "execution", SUMMARY_UPDATE_TOOL_CALLS)


def should_update_memory(
    *,
    current_tokens: int,
    last_summary_tokens: int,
    tool_calls_since_summary: int,
    threshold_tokens: int,
    tool_call_limit: int = SUMMARY_UPDATE_TOOL_CALLS,
) -> bool:
    if last_summary_tokens == 0:
        return current_tokens >= threshold_tokens
    return (
        current_tokens - last_summary_tokens >= threshold_tokens
        or tool_calls_since_summary >= tool_call_limit
    )


def should_autocompact(
    current_tokens: int,
    *,
    soft_prompt_tokens: int,
) -> bool:
    return current_tokens >= soft_prompt_tokens


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
    max_tokens: int,
    recent_message_tokens: int,
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
    messages.extend(
        _safe_recent_messages(recent_messages, max_tokens=recent_message_tokens)
    )
    while len(messages) > 4 and message_token_count(messages) > max_tokens:
        # Discard the oldest recovered interaction first.  Removing the tail
        # would preserve stale history while dropping the newest model/tool
        # exchange, which is the opposite of the role budget contract.
        messages.pop(4)
    # Trim reconstructable projections only.  The fixed system contract and
    # current goal/Assignment are not historical context; silently clipping
    # either would turn a capacity problem into an incorrect model request.
    # If those immutable envelopes alone exceed the provider budget, the
    # caller observes the oversize result and defers the session.
    for index, minimum_chars in ((1, 200), (2, 1_000)):
        current = message_token_count(messages)
        if current <= max_tokens:
            break
        content = str(messages[index].get("content") or "")
        excess_chars = max(1, (current - max_tokens) * 4)
        messages[index]["content"] = truncate_text(
            content, max(minimum_chars, len(content) - excess_chars)
        )
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


def _safe_recent_messages(
    messages: Sequence[Mapping[str, Any]], *, max_tokens: int
) -> list[dict[str, Any]]:
    if not messages:
        return []
    tail: list[dict[str, Any]] = []
    tokens = 0
    for message in reversed(messages):
        value = dict(message)
        message_tokens = message_token_count([value])
        if tokens + message_tokens > max_tokens:
            break
        tail.append(value)
        tokens += message_tokens
    tail.reverse()
    while tail and tail[0].get("role") == "tool":
        tail.pop(0)
    return tail


def bounded_recent_messages(
    messages: Sequence[Mapping[str, Any]], *, max_tokens: int
) -> list[dict[str, Any]]:
    """Return the most recent complete interaction within a role budget."""

    return _safe_recent_messages(messages, max_tokens=max_tokens)


def role_summary_threshold(profile: RoleContextProfile) -> int:
    """Start background summarization before reaching the role soft target."""

    return max(8_000, int(profile.soft_prompt_tokens * 0.75))
