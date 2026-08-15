"""Unified Agent tool specifications, validation, scheduling, and result storage."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from time import monotonic
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from challenges_sdk import (
    ChallengesAPIError,
    ChallengesResponseError,
    ChallengesSDKError,
    ChallengesTransportError,
)

from agent.state.errors import StateError


ToolHandler = Callable[[BaseModel], Awaitable[Any]]
ClaimResolver = Callable[[BaseModel], Sequence["AccessClaim"]]
ResultProjector = Callable[[Mapping[str, Any]], Mapping[str, Any]]
LOGGER = logging.getLogger(__name__)
@dataclass(frozen=True)
class AccessClaim:
    """One logical resource read or write used for in-turn scheduling."""

    mode: Literal["read", "write"]
    key: str


@dataclass(frozen=True)
class ToolSpec:
    """The single source of truth for one model-facing tool."""

    name: str
    description: str
    input_model: type[BaseModel]
    handler: ToolHandler
    access_claims: ClaimResolver
    requires_solo: bool = False
    result_projector: ResultProjector | None = None

    def definition(self) -> dict[str, Any]:
        return json.loads(
            _cached_tool_definition(self.name, self.description, self.input_model)
        )


@lru_cache(maxsize=256)
def _cached_tool_definition(
    name: str, description: str, input_model: type[BaseModel]
) -> str:
    """Build stable schema bytes once for each immutable Tool contract."""

    schema = _compact_schema(input_model.model_json_schema())
    schema.setdefault("type", "object")
    schema["additionalProperties"] = False
    definition = {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": schema,
        },
    }
    return json.dumps(
        definition,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _compact_schema(value: Any) -> Any:
    """Drop presentation-only JSON Schema titles, preserving validation."""
    if isinstance(value, dict):
        return {
            key: _compact_schema(item)
            for key, item in value.items()
            if key != "title"
        }
    if isinstance(value, list):
        return [_compact_schema(item) for item in value]
    return value


@dataclass(frozen=True)
class ToolDispatchOutcome:
    """Tool result carrying Runner control outside the model payload."""

    result: dict[str, Any]
    yield_session: bool = False


@dataclass
class PreparedToolCall:
    index: int
    tool_call_id: str
    name: str
    raw_arguments_length: int
    spec: ToolSpec | None = None
    arguments: BaseModel | None = None
    claims: tuple[AccessClaim, ...] = ()
    result_projection: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    evidence_payload: dict[str, Any] | None = None
    yield_session: bool = False
    queue_latency_ms: int = 0
    execution_latency_ms: int = 0
    total_latency_ms: int = 0
    concurrency_wave: int = 0


class ToolRegistry:
    """Collect role-scoped Tool Specs from independent providers."""

    def __init__(
        self,
        providers: Sequence[Any],
        *,
        allowed_tools: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.providers = list(providers)
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self._specs: dict[str, ToolSpec] = {}
        for provider in self.providers:
            for spec in provider.tool_specs():
                if self.allowed_tools is not None and spec.name not in self.allowed_tools:
                    continue
                if spec.name in self._specs:
                    raise ValueError(f"duplicate tool specification: {spec.name}")
                self._specs[spec.name] = spec
        self._definitions = tuple(spec.definition() for spec in self._specs.values())

    def definitions(self) -> list[dict[str, Any]]:
        # Definitions are immutable for a Registry lifetime. A JSON round-trip
        # returns a defensive copy without rebuilding Pydantic schemas on every
        # controller wake.
        return json.loads(
            json.dumps(self._definitions, ensure_ascii=False, separators=(",", ":"))
        )

    def has_tool(self, name: str) -> bool:
        return name in self._specs

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    async def close(self) -> None:
        for provider in self.providers:
            close = getattr(provider, "close", None)
            if close is not None:
                await close()


class ToolExecutor:
    """Parse, validate, schedule and invoke one model turn's tool calls."""

    def __init__(self, registry: ToolRegistry, *, max_concurrency: int = 10) -> None:
        if not 1 <= max_concurrency <= 10:
            raise ValueError("tool concurrency must be between 1 and 10")
        self.registry = registry
        self.max_concurrency = max_concurrency

    async def execute(self, tool_calls: Sequence[Mapping[str, Any]]) -> list[PreparedToolCall]:
        prepared = self.prepare(tool_calls)
        return await self.execute_prepared(prepared)

    def prepare(
        self, tool_calls: Sequence[Mapping[str, Any]]
    ) -> list[PreparedToolCall]:
        """Parse and validate a model turn without invoking any Handler."""

        prepared = [self._prepare(index, item) for index, item in enumerate(tool_calls)]
        self._enforce_solo(prepared)
        return prepared

    async def execute_prepared(
        self, prepared: Sequence[PreparedToolCall]
    ) -> list[PreparedToolCall]:
        """Schedule a previously validated turn after its call audit is durable."""

        batch_started = monotonic()
        prepared = list(prepared)

        pending = [item for item in prepared if item.result is None]
        wave = 0
        failed_write_keys: set[str] = set()
        while pending:
            wave += 1
            selected: list[PreparedToolCall] = []
            deferred: list[PreparedToolCall] = []
            for item in pending:
                if len(selected) >= self.max_concurrency or any(
                    self._claims_conflict(item.claims, other.claims) for other in selected
                ):
                    deferred.append(item)
                    continue
                if self._depends_on_failed_write(item.claims, failed_write_keys):
                    item.result = tool_error(
                        "execution",
                        "blocked_by_prior_tool_error",
                        "A prior tool call failed while holding the same writable resource",
                        retry_allowed=True,
                        retry_action="rewrite_arguments",
                    )
                    item.concurrency_wave = wave
                    continue
                selected.append(item)
            if not selected:
                pending = deferred
                continue
            await asyncio.gather(
                *(self._invoke(item, batch_started=batch_started, wave=wave) for item in selected)
            )
            for item in selected:
                if item.result is not None and item.result.get("ok") is False:
                    failed_write_keys.update(
                        claim.key for claim in item.claims if claim.mode == "write"
                    )
            pending = deferred

        elapsed = int((monotonic() - batch_started) * 1_000)
        for item in prepared:
            if item.total_latency_ms == 0:
                item.total_latency_ms = elapsed
        return prepared

    def _prepare(self, index: int, tool_call: Mapping[str, Any]) -> PreparedToolCall:
        function = tool_call.get("function")
        tool_call_id = str(tool_call.get("id") or "unknown")
        if not isinstance(function, Mapping) or not isinstance(function.get("name"), str):
            return PreparedToolCall(
                index=index,
                tool_call_id=tool_call_id,
                name="unknown",
                raw_arguments_length=0,
                result=tool_error("schema", "invalid_tool_call", "Tool call is missing a function name"),
            )
        name = str(function["name"])
        raw = function.get("arguments", "{}")
        raw_length = len(raw) if isinstance(raw, str) else 0
        spec = self.registry.get(name)
        item = PreparedToolCall(index, tool_call_id, name, raw_length, spec=spec)
        if spec is None:
            item.result = tool_error(
                "permission" if self.registry.allowed_tools is not None else "schema",
                "tool_not_allowed_for_role" if self.registry.allowed_tools is not None else "unknown_tool",
                "This Agent role cannot use that tool" if self.registry.allowed_tools is not None else "Unknown Agent tool",
            )
            return item
        if not isinstance(raw, str):
            item.result = self._argument_error(
                name,
                "parse",
                "Tool arguments must be a JSON-encoded object",
                retry_allowed=True, retry_action="rewrite_arguments",
                details={"raw_length": raw_length, "required": self._required_fields(spec)},
            )
            return item
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            item.result = self._argument_error(
                name,
                "parse",
                "Tool arguments are not valid JSON",
                retry_allowed=True, retry_action="rewrite_arguments",
                details={
                    "line": exc.lineno,
                    "column": exc.colno,
                    "position": exc.pos,
                    "raw_length": raw_length,
                    "required": self._required_fields(spec),
                },
            )
            return item
        if not isinstance(value, Mapping):
            item.result = self._argument_error(
                name,
                "schema",
                "Tool arguments must be a JSON object",
                retry_allowed=True, retry_action="rewrite_arguments",
                details={"required": self._required_fields(spec)},
            )
            return item
        try:
            item.arguments = spec.input_model.model_validate(value)
            item.claims = tuple(spec.access_claims(item.arguments))
        except ValidationError as exc:
            fields = validation_details(exc)
            item.result = self._argument_error(
                name,
                "schema",
                "invalid_arguments",
                "Tool arguments failed schema validation",
                retry_allowed=True, retry_action="rewrite_arguments",
                details={"fields": fields},
            )
        except Exception as exc:
            item.result = map_exception(
                exc,
                tool_call_id=tool_call_id,
                tool_name=name,
            )
        return item

    @staticmethod
    def _argument_error(
        name: str,
        stage: str,
        code_or_message: str,
        message: str | None = None,
        *,
        retry_allowed: bool,
        retry_action: str,
        details: Any,
    ) -> dict[str, Any]:
        if message is None:
            code = "invalid_json"
            error_message = code_or_message
        else:
            code = code_or_message
            error_message = message
        if name == "system_http_probe":
            error_message = (
                f"{error_message}. Rewrite the arguments as a JSON object with "
                "top-level cases: [{method,url,variables,combine}], and keep "
                "concurrency/rate_limit_per_second/wait_seconds at the top level. "
                "Do not retry the same raw arguments; use system_http_request for "
                "an ordered session."
            )
            details = {
                **(dict(details) if isinstance(details, Mapping) else {}),
                "canonical_shape": {
                    "cases": [
                        {
                            "method": "GET",
                            "url": "http://host/{{path}}",
                            "variables": {
                                "path": {
                                    "values": ["/", "/admin"],
                                    "encoding": "path",
                                }
                            },
                            "combine": "product",
                        }
                    ],
                    "concurrency": 8,
                    "wait_seconds": 20,
                },
                "ordered_session_tool": "system_http_request",
            }
        return tool_error(
            stage,
            code,
            error_message,
            retry_allowed=retry_allowed,
            retry_action=retry_action,
            details=details,
        )

    async def _invoke(self, item: PreparedToolCall, *, batch_started: float, wave: int) -> None:
        assert item.spec is not None and item.arguments is not None
        started = monotonic()
        item.queue_latency_ms = int((started - batch_started) * 1_000)
        item.concurrency_wave = wave
        try:
            value = await item.spec.handler(item.arguments)
            if isinstance(value, Mapping) and isinstance(
                value.get("_aion_evidence"), Mapping
            ):
                item.evidence_payload = dict(value["_aion_evidence"])
                value = {
                    key: nested
                    for key, nested in value.items()
                    if key != "_aion_evidence"
                }
            if isinstance(value, ToolDispatchOutcome):
                item.result = validate_tool_result(value.result)
                item.yield_session = value.yield_session
            elif isinstance(value, Mapping) and "ok" in value:
                item.result = validate_tool_result(value)
            else:
                item.result = {"ok": True, "data": value}
        except Exception as exc:
            item.result = map_exception(
                exc,
                tool_call_id=item.tool_call_id,
                tool_name=item.name,
            )
        if item.spec.result_projector is not None and item.result is not None:
            try:
                item.result_projection = dict(item.spec.result_projector(item.result))
            except Exception:
                LOGGER.exception("tool result projection failed for %s", item.name)
                item.result = tool_error(
                    "internal",
                    "result_projection_failed",
                    "The tool result could not be prepared safely",
                )
        item.execution_latency_ms = int((monotonic() - started) * 1_000)
        item.total_latency_ms = int((monotonic() - batch_started) * 1_000)

    @staticmethod
    def _required_fields(spec: ToolSpec) -> list[str]:
        return [name for name, field_info in spec.input_model.model_fields.items() if field_info.is_required()]

    @staticmethod
    def _resource_keys_overlap(left: str, right: str) -> bool:
        if left == right or left == "*" or right == "*":
            return True
        # Directory reads must serialize with writes anywhere below them.
        # Other namespaces intentionally retain exact-key semantics.
        if left.startswith("workspace:") and right.startswith("workspace:"):
            try:
                left_path = Path(left.removeprefix("workspace:")).resolve(strict=False)
                right_path = Path(right.removeprefix("workspace:")).resolve(strict=False)
                return (
                    left_path == right_path
                    or left_path in right_path.parents
                    or right_path in left_path.parents
                )
            except (OSError, RuntimeError, ValueError):
                return left == right
        return False

    @classmethod
    def _claims_conflict(cls, left: Sequence[AccessClaim], right: Sequence[AccessClaim]) -> bool:
        for first in left:
            for second in right:
                same = cls._resource_keys_overlap(first.key, second.key)
                if same and (first.mode == "write" or second.mode == "write"):
                    return True
        return False

    @classmethod
    def _depends_on_failed_write(cls, claims: Sequence[AccessClaim], failed: set[str]) -> bool:
        return any(
            cls._resource_keys_overlap(claim.key, failed_key)
            for claim in claims
            for failed_key in failed
        )

    @staticmethod
    def _enforce_solo(items: Sequence[PreparedToolCall]) -> None:
        if len(items) == 1:
            return
        has_solo = any(
            item.result is None and item.spec is not None and item.spec.requires_solo
            for item in items
        )
        if not has_solo:
            return
        for item in items:
            if item.result is None:
                item.result = tool_error(
                    "semantic",
                    (
                        "solo_tool_must_be_only_call"
                        if item.spec is not None and item.spec.requires_solo
                        else "blocked_by_solo_tool"
                    ),
                    "A context-changing or waiting tool must be the only tool call in the response",
                    retry_allowed=True,
                    retry_action="rewrite_arguments",
                    same_arguments=True,
                )

class ToolResultReadArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    result_ref: str = Field(pattern=r"^tool_result:tool_result_[0-9a-f]{32}$")
    offset: int = Field(default=0, ge=0)
    limit_chars: int = Field(default=8_000, ge=1, le=10_000)


class ToolResultStore:
    """Agent-owned, run-local storage for bounded model tool results."""

    def __init__(self, run_dir: Path, agent_id: str) -> None:
        self.root = run_dir / "agents" / agent_id / "tool-results"

    def persist(self, content: str) -> str:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        result_id = f"tool_result_{uuid4().hex}"
        path = self.root / f"{result_id}.json"
        temporary = self.root / f".{result_id}.{uuid4().hex}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            temporary.unlink(missing_ok=True)
            path.unlink(missing_ok=True)
            raise
        return f"tool_result:{result_id}"

    def read(self, arguments: ToolResultReadArguments) -> dict[str, Any]:
        result_id = arguments.result_ref.removeprefix("tool_result:")
        path = self.root / f"{result_id}.json"
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            from tools.system.policy import SystemToolError

            raise SystemToolError(
                error_type="not_found", code="tool_result_not_found",
                message="Tool result reference does not exist for this Agent",
            ) from exc
        start = min(arguments.offset, len(content))
        end = min(start + arguments.limit_chars, len(content))
        return {
            "result_ref": arguments.result_ref,
            "offset": start,
            "content": content[start:end],
            "next_offset": end if end < len(content) else None,
            "eof": end >= len(content),
            "original_chars": len(content),
        }


class ToolResultTools:
    """Role-neutral provider for paging one Agent's persisted tool results."""

    def __init__(self, store: ToolResultStore) -> None:
        self.store = store

    def tool_specs(self) -> list[ToolSpec]:
        async def read(arguments: BaseModel) -> dict[str, Any]:
            assert isinstance(arguments, ToolResultReadArguments)
            return self.store.read(arguments)

        return [
            ToolSpec(
                "tool_result_read",
                "Read one bounded chunk of a large tool result owned by this Agent. Continue with next_offset until eof; the reference is not a filesystem path.",
                ToolResultReadArguments,
                read,
                access_claims=lambda arguments: (
                    AccessClaim("read", f"tool-result:{arguments.result_ref}"),
                ),
            )
        ]

    async def close(self) -> None:
        return None


def validation_details(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {
            "path": ".".join(str(part) for part in item.get("loc", ())),
            "code": item.get("type", "invalid"),
            "message": item.get("msg", "Invalid value"),
        }
        for item in exc.errors()
    ]


def tool_error(
    stage: str,
    code: str,
    message: str,
    *,
    retry_allowed: bool = False,
    retry_action: str = "none",
    retry_tool: str | None = None,
    same_arguments: bool = False,
    details: Any = None,
) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "stage": stage,
            "code": code,
            "message": message,
            "retry": {
                "allowed": retry_allowed,
                "action": retry_action,
                "tool": retry_tool,
                "same_arguments": same_arguments,
            },
            "details": details if details is not None else {},
        },
    }


def validate_tool_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Accept only the current model-visible result protocol."""

    result = dict(value)
    if result.get("ok") is not False:
        return result
    error = result.get("error")
    if (
        isinstance(error, Mapping)
        and error.get("stage")
        in {
            "parse",
            "schema",
            "semantic",
            "conflict",
            "permission",
            "execution",
            "internal",
        }
        and isinstance(error.get("code"), str)
        and isinstance(error.get("message"), str)
        and isinstance(error.get("retry"), Mapping)
    ):
        return result
    return tool_error(
        "internal",
        "invalid_tool_result",
        "The tool returned an invalid result protocol",
    )


def map_exception(
    exc: Exception,
    *,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
) -> dict[str, Any]:
    from agent.skills.catalog import SkillCatalogError
    from tools.system.policy import SystemToolError

    if isinstance(exc, StateError):
        retry_allowed, retry_action, retry_tool = _conflict_retry(exc.code)
        stage = (
            "conflict"
            if exc.status_code == 409
            else "permission"
            if exc.status_code in {401, 403}
            else "internal"
            if exc.status_code >= 500
            else "semantic"
        )
        return tool_error(
            stage,
            exc.code,
            exc.message,
            retry_allowed=retry_allowed if exc.status_code == 409 else False,
            retry_action=retry_action if exc.status_code == 409 else "none",
            retry_tool=retry_tool if exc.status_code == 409 else None,
            details=dict(exc.detail),
        )
    if isinstance(exc, SystemToolError):
        retry_allowed, retry_action, retry_tool = _conflict_retry(exc.code)
        stage = "permission" if exc.error_type == "permission" else "conflict" if exc.error_type == "conflict" else "semantic" if exc.error_type in {"validation", "not_found"} else "internal" if exc.error_type == "internal" else "execution"
        return tool_error(
            stage,
            exc.code,
            exc.message,
            retry_allowed=retry_allowed if exc.error_type == "conflict" else False,
            retry_action=retry_action if exc.error_type == "conflict" else "none",
            retry_tool=retry_tool if exc.error_type == "conflict" else None,
            details=exc.detail,
        )
    if isinstance(exc, SkillCatalogError):
        return tool_error(
            "permission" if exc.error_type == "permission" else "semantic",
            exc.code,
            exc.message,
            retry_allowed=exc.retry_allowed,
            retry_action=exc.retry_action,
            retry_tool=exc.retry_tool,
            same_arguments=exc.same_arguments,
            details=exc.detail,
        )
    if isinstance(exc, ChallengesAPIError):
        return tool_error(
            "execution",
            str(exc.code or "benchmark_api_error"),
            "The benchmark service rejected the operation",
            details={"status_code": exc.status_code},
        )
    if isinstance(exc, ChallengesTransportError):
        return tool_error(
            "execution",
            "transport_error",
            "Unable to reach the benchmark service",
        )
    if isinstance(exc, ChallengesResponseError):
        return tool_error(
            "execution",
            "invalid_response",
            "The benchmark service returned an invalid response",
        )
    if isinstance(exc, ChallengesSDKError):
        return tool_error(
            "internal", "sdk_error", "The benchmark SDK could not complete the operation"
        )
    error_ref = f"tool_error_{uuid4().hex}"
    LOGGER.exception(
        "unexpected tool execution failure error_ref=%s tool_call_id=%s tool=%s exception_type=%s",
        error_ref,
        tool_call_id or "unknown",
        tool_name or "unknown",
        type(exc).__name__,
        exc_info=exc,
    )
    return tool_error(
        "internal",
        "internal_error",
        "The tool failed unexpectedly",
        details={"error_ref": error_ref},
    )


def read_claim(key: str) -> tuple[AccessClaim, ...]:
    return (AccessClaim("read", key),)


def write_claim(key: str) -> tuple[AccessClaim, ...]:
    return (AccessClaim("write", key),)


def _conflict_retry(code: str) -> tuple[bool, str, str | None]:
    if code.startswith("duplicate_"):
        return True, "rewrite_arguments", None
    if any(marker in code for marker in ("running", "in_progress", "busy")):
        return True, "wait", None
    return False, "none", None
