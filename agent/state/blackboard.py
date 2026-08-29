"""Deterministic, non-authoritative helpers for shared blackboard views.

The blackboard is derived from already-filtered controller projections.  These
helpers deliberately operate on projections only; they never load report or
Evidence bodies and never decide whether a finding is authoritative.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


_TRANSPORT_KEYS = frozenset(
    {
        "through_sequence",
        "next_sequence",
        "report_cursor",
        "sequence",
        "created_at",
        "consumed_at",
        "replayed",
        "snapshot_replayed",
        "content_digest",
        "authority_digest",
    }
)
_WHITESPACE = re.compile(r"\s+")


def normalize_blackboard_text(value: Any) -> str:
    """Normalize text for equality checks without changing the model payload."""

    if not isinstance(value, str):
        return ""
    return _WHITESPACE.sub(" ", value).strip()


def _digest_candidate(value: Any) -> dict[str, Any]:
    """Keep candidate values out of persisted fingerprints and diagnostics."""

    if not isinstance(value, str) or not value.strip():
        return {"present": False}
    return {
        "present": True,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _canonical(value: Any, *, key: str | None = None) -> Any:
    if key == "candidate_flag":
        return _digest_candidate(value)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            name = str(raw_key)
            if name in _TRANSPORT_KEYS:
                continue
            result[name] = _canonical(raw_value, key=name)
        return {name: result[name] for name in sorted(result)}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        values = [_canonical(item) for item in value]
        return sorted(
            values,
            key=lambda item: json.dumps(
                item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ),
        )
    if isinstance(value, str):
        return normalize_blackboard_text(value)
    return value


def blackboard_content_digest(payload: Mapping[str, Any]) -> str:
    """Return a stable digest of the effective, non-transport content."""

    canonical = _canonical(payload)
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def blackboard_projection_without_transport(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a copy suitable for a model context, excluding internal fields."""

    return {
        key: value
        for key, value in payload.items()
        if key not in {"content_digest", "authority_digest"}
    }
