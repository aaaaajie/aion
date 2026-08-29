"""Bounded contract discovery and response recovery for the benchmark API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Literal, Protocol


OperationName = Literal[
    "list_challenges",
    "start_challenge",
    "get_hint",
    "submit_flag",
    "close_challenge",
]


@dataclass(frozen=True)
class BenchmarkOperationContract:
    """A validated, same-origin request contract for one benchmark operation."""

    operation: OperationName
    method: str
    path: str
    query_fields: tuple[str, ...] = ()
    body_fields: tuple[str, ...] = ()
    source: Literal["fixed", "openapi", "llm_openapi"] = "fixed"


@dataclass(frozen=True)
class ResponseRecoveryContext:
    """Sanitized context supplied to an optional response recoverer."""

    operation: OperationName
    method: str
    path: str
    status_code: int
    content_type: str | None
    payload: Any
    expected_schema: dict[str, Any]
    response_size: int


@dataclass(frozen=True)
class ResponseRecoveryDecision:
    recoverable: bool
    confidence: float
    data: Any
    reason: str


@dataclass(frozen=True)
class ContractRecoveryContext:
    """Candidate-only context for optional OpenAPI interpretation."""

    candidates: tuple[dict[str, Any], ...]
    missing_operations: tuple[OperationName, ...]


class ResponseRecoverer(Protocol):
    async def recover(
        self, context: ResponseRecoveryContext
    ) -> ResponseRecoveryDecision | None:
        """Return a candidate canonical payload, or ``None``."""


class ContractRecoverer(Protocol):
    async def recover_contract(
        self, context: ContractRecoveryContext
    ) -> Mapping[OperationName, BenchmarkOperationContract] | None:
        """Select only from supplied OpenAPI candidates, or return ``None``."""


DEFAULT_OPERATION_CONTRACTS: dict[OperationName, BenchmarkOperationContract] = {
    "list_challenges": BenchmarkOperationContract(
        "list_challenges", "GET", "/openapi/v1/challenges"
    ),
    "start_challenge": BenchmarkOperationContract(
        "start_challenge",
        "POST",
        "/openapi/v1/challenges/start",
        query_fields=("unique_code",),
    ),
    "get_hint": BenchmarkOperationContract(
        "get_hint",
        "GET",
        "/openapi/v1/challenges/hint",
        query_fields=("unique_code",),
    ),
    "submit_flag": BenchmarkOperationContract(
        "submit_flag",
        "POST",
        "/openapi/v1/challenges/submit",
        body_fields=("unique_code", "flag"),
    ),
    "close_challenge": BenchmarkOperationContract(
        "close_challenge",
        "POST",
        "/openapi/v1/challenges/close",
        query_fields=("unique_code",),
    ),
}


_OPERATION_SUFFIXES: dict[OperationName, str] = {
    "list_challenges": "",
    "start_challenge": "/start",
    "get_hint": "/hint",
    "submit_flag": "/submit",
    "close_challenge": "/close",
}
_HTTP_METHODS: dict[OperationName, str] = {
    "list_challenges": "GET",
    "start_challenge": "POST",
    "get_hint": "GET",
    "submit_flag": "POST",
    "close_challenge": "POST",
}
_SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|passwd|authorization|cookie|set-cookie|api[_-]?key|flag)",
    re.IGNORECASE,
)
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_KEY_ALIASES = {
    "uniquecode": "unique_code",
    "challengecode": "unique_code",
    "taskcode": "unique_code",
    "containeraddress": "container_addr",
    "containeraddresses": "container_addr",
    "addresses": "container_addr",
    "address": "container_addr",
    "containerstatus": "container_status",
    "status": "container_status",
    "totalflagcount": "total_flag_count",
    "correctflagcount": "correct_flag_count",
    "matchedflagindex": "matched_flag_index",
    "cumulativescore": "cumulative_score",
    "totalscore": "total_score",
    "iscompleted": "is_completed",
}


def default_operation_contracts() -> dict[OperationName, BenchmarkOperationContract]:
    return dict(DEFAULT_OPERATION_CONTRACTS)


def normalize_response_payload(
    operation: OperationName,
    payload: Any,
    *,
    unique_code: str | None = None,
) -> Any:
    """Apply bounded, deterministic adaptations before any LLM is considered."""

    value = _unwrap_payload(payload, operation)
    if operation == "get_hint" and isinstance(value, str):
        return {"unique_code": unique_code or "", "hint": value}

    if operation == "list_challenges":
        if isinstance(value, Mapping) and _looks_like_challenge(value):
            value = [value]
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            return payload
        normalized: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, Mapping):
                return payload
            item_value = _canonical_mapping(item)
            _apply_safe_challenge_defaults(item_value)
            normalized.append(item_value)
        return normalized

    if not isinstance(value, Mapping):
        return payload
    normalized = _canonical_mapping(value)
    if operation == "get_hint" and "hint" not in normalized:
        message = normalized.get("message")
        if isinstance(message, str):
            normalized["hint"] = message
    if unique_code and operation in {"start_challenge", "get_hint", "close_challenge"}:
        normalized.setdefault("unique_code", unique_code)
    if operation == "close_challenge" and "closed" not in normalized:
        status = str(normalized.get("container_status") or "").casefold()
        if status in {"closed", "stopped", "released"}:
            normalized["closed"] = True
    return normalized


def response_digest(payload: Any) -> str:
    raw = repr(payload).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]


def sanitize_payload(payload: Any, *, secrets: Sequence[str] = (), limit: int = 65_536) -> Any:
    """Bound and redact untrusted platform data before logging or model use."""

    secret_values = tuple(value for value in secrets if value)

    def visit(value: Any) -> Any:
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                result[key_text] = (
                    "[REDACTED]"
                    if _SENSITIVE_KEY.search(key_text)
                    else visit(item)
                )
            return result
        if isinstance(value, (list, tuple)):
            return [visit(item) for item in value]
        if isinstance(value, bytes):
            return value[:limit].decode("utf-8", errors="replace")
        if isinstance(value, str):
            redacted = value
            for secret in secret_values:
                redacted = redacted.replace(secret, "[REDACTED]")
            return redacted[:limit]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:limit]

    result = visit(payload)
    encoded = repr(result)
    if len(encoded) <= limit:
        return result
    return {"truncated": True, "preview": encoded[: limit - 64]}


def parse_openapi_contracts(payload: Any) -> dict[OperationName, BenchmarkOperationContract]:
    """Extract only the five known operations from an OpenAPI document."""

    paths = payload.get("paths") if isinstance(payload, Mapping) else None
    if not isinstance(paths, Mapping):
        return {}
    candidates: list[tuple[int, OperationName, BenchmarkOperationContract]] = []
    for raw_path, raw_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(raw_item, Mapping):
            continue
        for raw_method, raw_operation in raw_item.items():
            method = str(raw_method).upper()
            if method not in {"GET", "POST", "PUT", "PATCH"} or not isinstance(
                raw_operation, Mapping
            ):
                continue
            operation = _infer_operation(raw_path, method, raw_operation)
            if operation is None:
                continue
            score = _operation_score(operation, raw_path, method, raw_operation)
            if score <= 0:
                continue
            query_fields, body_fields = _request_fields(raw_operation)
            contract = BenchmarkOperationContract(
                operation=operation,
                method=method,
                path=raw_path,
                query_fields=query_fields,
                body_fields=body_fields,
                source="openapi",
            )
            candidates.append((score, operation, contract))
    selected: dict[OperationName, BenchmarkOperationContract] = {}
    for _, operation, contract in sorted(candidates, key=lambda item: -item[0]):
        selected.setdefault(operation, contract)
    return selected


def openapi_candidates(payload: Any) -> tuple[dict[str, Any], ...]:
    """Return bounded candidate metadata suitable for an untrusted LLM prompt."""

    paths = payload.get("paths") if isinstance(payload, Mapping) else None
    if not isinstance(paths, Mapping):
        return ()
    candidates: list[dict[str, Any]] = []
    for raw_path, raw_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(raw_item, Mapping):
            continue
        for raw_method, raw_operation in raw_item.items():
            if not isinstance(raw_operation, Mapping):
                continue
            method = str(raw_method).upper()
            if method not in {"GET", "POST", "PUT", "PATCH"}:
                continue
            query_fields, body_fields = _request_fields(raw_operation)
            candidates.append(
                {
                    "id": len(candidates),
                    "method": method,
                    "path": raw_path,
                    "operation_id": str(raw_operation.get("operationId") or "")[:128],
                    "query_fields": list(query_fields),
                    "body_fields": list(body_fields),
                }
            )
    return tuple(candidates[:128])


def contracts_from_candidates(
    values: Mapping[OperationName, BenchmarkOperationContract],
) -> dict[OperationName, BenchmarkOperationContract]:
    """Validate an LLM-selected contract mapping against the fixed operation set."""

    result: dict[OperationName, BenchmarkOperationContract] = {}
    for operation, contract in values.items():
        if operation not in DEFAULT_OPERATION_CONTRACTS:
            continue
        if not contract.path.startswith("/") or "://" in contract.path:
            continue
        if contract.method not in {"GET", "POST", "PUT", "PATCH"}:
            continue
        result[operation] = BenchmarkOperationContract(
            operation=operation,
            method=contract.method,
            path=contract.path,
            query_fields=tuple(contract.query_fields),
            body_fields=tuple(contract.body_fields),
            source="llm_openapi",
        )
    return result


def payload_is_truncated(value: Any) -> bool:
    if isinstance(value, Mapping):
        return bool(value.get("truncated")) or any(
            payload_is_truncated(item) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(payload_is_truncated(item) for item in value)
    return False


def validate_contract_mapping(
    values: Mapping[Any, Any] | None,
) -> dict[OperationName, BenchmarkOperationContract]:
    """Accept only safe same-origin contracts returned by an adapter."""

    if not isinstance(values, Mapping):
        return {}
    result: dict[OperationName, BenchmarkOperationContract] = {}
    allowed_methods = {"GET", "POST", "PUT", "PATCH"}
    for operation, contract in values.items():
        if operation not in DEFAULT_OPERATION_CONTRACTS or not isinstance(
            contract, BenchmarkOperationContract
        ):
            continue
        if (
            not contract.path.startswith("/")
            or "://" in contract.path
            or contract.method not in allowed_methods
        ):
            continue
        result[operation] = BenchmarkOperationContract(
            operation=operation,
            method=contract.method,
            path=contract.path,
            query_fields=tuple(str(item) for item in contract.query_fields),
            body_fields=tuple(str(item) for item in contract.body_fields),
            source="llm_openapi",
        )
    return result


def _canonical_mapping(value: Mapping[Any, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = _canonical_key(str(raw_key))
        if isinstance(raw_value, Mapping):
            child: Any = _canonical_mapping(raw_value)
        elif isinstance(raw_value, list):
            child = [
                _canonical_mapping(item) if isinstance(item, Mapping) else item
                for item in raw_value
            ]
        else:
            child = raw_value
        result.setdefault(key, child)
    for alias, canonical in _KEY_ALIASES.items():
        if alias in result and canonical not in result:
            result[canonical] = result[alias]
    return result


def _canonical_key(value: str) -> str:
    normalized = _CAMEL_BOUNDARY.sub(r"\1_\2", value)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).strip("_").lower()
    return _KEY_ALIASES.get(normalized.replace("_", ""), normalized)


def _unwrap_payload(payload: Any, operation: OperationName) -> Any:
    value = payload
    wrapper_keys = (
        ("data", "result", "payload", "response", "items", "challenges")
        if operation == "list_challenges"
        else ("data", "result", "payload", "response")
    )
    for _ in range(3):
        if not isinstance(value, Mapping):
            break
        canonical = _canonical_mapping(value)
        if operation == "list_challenges" and any(
            isinstance(canonical.get(key), list) for key in ("items", "challenges", "data", "result")
        ):
            for key in ("items", "challenges", "data", "result"):
                if isinstance(canonical.get(key), list):
                    value = canonical[key]
                    break
            else:
                break
            continue
        next_value = next(
            (
                canonical[key]
                for key in wrapper_keys
                if key in canonical and isinstance(canonical[key], Mapping)
            ),
            None,
        )
        if next_value is None:
            break
        value = next_value
    return value


def _looks_like_challenge(value: Mapping[Any, Any]) -> bool:
    keys = {_canonical_key(str(item)) for item in value}
    return bool(keys & {"unique_code", "challenge_code", "task_code"})


def _apply_safe_challenge_defaults(value: dict[str, Any]) -> None:
    value.setdefault("description", None)
    value.setdefault("difficulty", "unknown")
    value.setdefault("level", 0)
    value.setdefault("total_score", 0)
    value.setdefault("flag_count", 0)
    value.setdefault("correct_flag_count", 0)
    value.setdefault("is_completed", False)
    # Unknown is deliberately treated as occupied by the Runtime resource rules.
    value.setdefault("container_status", "unknown")
    value.setdefault("container_addr", [])


def _infer_operation(
    path: str, method: str, operation: Mapping[str, Any]
) -> OperationName | None:
    text = " ".join(
        [path.casefold(), method.casefold(), str(operation.get("operationId") or "").casefold(), str(operation.get("summary") or "").casefold()]
    )
    for candidate, suffix in _OPERATION_SUFFIXES.items():
        if suffix and path.rstrip("/").casefold().endswith(suffix):
            if method == _HTTP_METHODS[candidate] or candidate == "get_hint":
                return candidate
    if path.rstrip("/").casefold().endswith("/challenges") and method == "GET":
        return "list_challenges"
    if "hint" in text:
        return "get_hint"
    if "submit" in text or "flag" in text:
        return "submit_flag"
    if "close" in text or "stop" in text:
        return "close_challenge"
    if "start" in text or "launch" in text:
        return "start_challenge"
    if "list" in text or "challenge" in text and method == "GET":
        return "list_challenges"
    return None


def _operation_score(
    operation: OperationName,
    path: str,
    method: str,
    raw_operation: Mapping[str, Any],
) -> int:
    score = 1
    if method == _HTTP_METHODS[operation]:
        score += 2
    if _OPERATION_SUFFIXES[operation] and path.rstrip("/").casefold().endswith(
        _OPERATION_SUFFIXES[operation]
    ):
        score += 5
    if operation in str(raw_operation.get("operationId") or "").casefold():
        score += 3
    return score


def _request_fields(raw_operation: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    query: list[str] = []
    for item in raw_operation.get("parameters") or []:
        if isinstance(item, Mapping) and item.get("in") == "query":
            name = item.get("name")
            if isinstance(name, str) and name:
                query.append(_canonical_key(name))
    body: list[str] = []
    request_body = raw_operation.get("requestBody")
    content = request_body.get("content") if isinstance(request_body, Mapping) else None
    if isinstance(content, Mapping):
        schema = next(
            (
                item.get("schema")
                for item in content.values()
                if isinstance(item, Mapping) and isinstance(item.get("schema"), Mapping)
            ),
            None,
        )
        properties = schema.get("properties") if isinstance(schema, Mapping) else None
        if isinstance(properties, Mapping):
            body.extend(_canonical_key(str(name)) for name in properties)
    return tuple(dict.fromkeys(query)), tuple(dict.fromkeys(body))
