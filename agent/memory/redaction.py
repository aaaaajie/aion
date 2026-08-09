"""Redaction helpers for durable Agent run records."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "benchmark_token",
    "password",
    "secret",
    "token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
}
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[^\s,;]+")
_FLAG_PATTERN = re.compile(r"(?i)\b[a-z0-9_]{0,32}\{[^{}\r\n]{1,512}\}")


def fingerprint(value: str) -> dict[str, Any]:
    return {
        "redacted": True,
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "length": len(value),
    }


def redact_text(value: str, secrets: tuple[str, ...] = ()) -> str:
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, "[REDACTED]")
    result = _BEARER_PATTERN.sub(r"\1[REDACTED]", result)
    return _FLAG_PATTERN.sub("[REDACTED_FLAG]", result)


def redact_value(
    value: Any,
    *,
    key: str | None = None,
    secrets: tuple[str, ...] = (),
) -> Any:
    normalized_key = key.lower() if key else ""
    if normalized_key in {"flag", "flags", "candidate_flag", "flag_candidate"} and isinstance(value, str):
        return fingerprint(value)
    if normalized_key in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_value(item_value, key=str(item_key), secrets=secrets)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item, secrets=secrets) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item, secrets=secrets) for item in value]
    return value


def redact_tool_payload(
    tool_name: str,
    payload: Any,
    *,
    secrets: tuple[str, ...] = (),
) -> Any:
    """Redact known credential fields and Flag arguments before persistence."""

    if (
        tool_name.startswith("system_http_")
        or tool_name in {"system_web_path_probe", "system_web_fingerprint"}
    ):
        return _redact_http_payload(tool_name, payload, secrets=secrets)
    redacted = redact_value(payload, secrets=secrets)
    if tool_name == "benchmark_submit_flag" and isinstance(redacted, Mapping):
        result = dict(redacted)
        original = payload.get("flag") if isinstance(payload, Mapping) else None
        if isinstance(original, str):
            result["flag"] = fingerprint(original)
        return result
    return redacted


def _redact_http_payload(
    tool_name: str,
    payload: Any,
    *,
    secrets: tuple[str, ...],
) -> Any:
    """Keep HTTP lifecycle metadata while excluding request/response secrets."""

    def visit(value: Any, key: str | None = None) -> Any:
        normalized = key.lower() if key else ""
        if normalized in {
            "auth",
            "authorization",
            "cookie",
            "cookies",
            "set-cookie",
            "proxy-authorization",
            "body",
            "proxy",
            "query",
            "variables",
            "summary",
            "features",
            "title",
            "body_contains",
            "body_regex",
            "header_contains",
            "header_regex",
        }:
            return _fingerprint_any(value)
        if tool_name == "system_http_response" and normalized == "content":
            return _fingerprint_any(value)
        if normalized in _SECRET_KEYS:
            return "[REDACTED]"
        if isinstance(value, str):
            result = redact_text(value, secrets)
            result = re.sub(
                r"(?i)([?&](?:token|password|secret|api_key|apikey)=)[^&#\s]*",
                r"\1[REDACTED]",
                result,
            )
            if normalized in {"url", "final_url", "location"}:
                result = _redact_url_query(result)
            return result
        if isinstance(value, Mapping):
            return {
                str(k): (
                    _fingerprint_any(v)
                    if normalized in {"headers", "header_features"}
                    and re.search(r"(?i)(?:auth|cookie|token|secret|api[-_]?key)", str(k))
                    else visit(v, str(k))
                )
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [visit(item) for item in value]
        return value

    return visit(payload)


def _redact_url_query(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    netloc = parts.netloc
    if "@" in netloc:
        netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]
    redacted_query = (
        urlencode(
            [
                (name, "[REDACTED]")
                for name, _ in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
        if parts.query
        else ""
    )
    return urlunsplit((parts.scheme, netloc, parts.path, redacted_query, parts.fragment))


def _fingerprint_any(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        encoded = value
    else:
        encoded = repr(value)
    return fingerprint(encoded)
