"""Plaintext payload helpers for local competition analysis.

The runtime is operated inside an isolated competition environment.  Durable
events, model context, tool arguments/results, and reports therefore retain
their original content so that Agent decisions can be audited and analyzed.
The function names remain as small call-site adapters; they no longer redact,
fingerprint, or rewrite values.
"""

from __future__ import annotations

from typing import Any


def redact_text(value: str, secrets: tuple[str, ...] = ()) -> str:
    """Return text unchanged; local run records are intentionally plaintext."""

    del secrets
    return value


def redact_value(
    value: Any,
    *,
    key: str | None = None,
    secrets: tuple[str, ...] = (),
) -> Any:
    """Return a value unchanged; kept for existing persistence call sites."""

    del key, secrets
    return value


def redact_tool_payload(
    tool_name: str,
    payload: Any,
    *,
    secrets: tuple[str, ...] = (),
) -> Any:
    """Return the complete tool payload for local decision analysis."""

    del tool_name, secrets
    return payload
