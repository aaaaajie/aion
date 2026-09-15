"""Unified Agent tool specifications, validation, scheduling, and result storage."""

from __future__ import annotations

import asyncio
from contextvars import ContextVar

current_tool_call_id: ContextVar[str | None] = ContextVar("tool_call_id", default=None)
import hashlib
import inspect
import json
import logging
import os
import difflib
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
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

ToolHandler = Callable[[BaseModel], Awaitable[Any] | Any]
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
            key: _compact_schema(item) for key, item in value.items() if key != "title"
        }
    if isinstance(value, list):
        return [_compact_schema(item) for item in value]
    return value


def serialize_tool_arguments(
    value: Any,
    *,
    exclude_unset: bool = False,
    exclude_none: bool = False,
) -> Any:
    """Serialize tool arguments without invoking Pydantic's typed serializer.

    A few intentionally best-effort tool inputs use ``SkipValidation`` so that
    malformed optional items can be downgraded to warnings.  Calling
    ``BaseModel.model_dump()`` on those models makes Pydantic emit
    ``PydanticSerializationUnexpectedValue`` warnings when the raw value is a
    dict.  Tool audit events only need a JSON-safe projection, so walk the
    already-parsed values directly and avoid re-validating or re-serializing
    them through Pydantic.
    """

    if isinstance(value, BaseModel):
        # Read field metadata from the class.  Accessing ``model_fields`` on
        # an instance is deprecated in Pydantic 2.11 and also needlessly
        # routes SkipValidation values through its typed serializer.
        fields = getattr(type(value), "model_fields", {})
        fields_set = getattr(value, "model_fields_set", set())
        projected: dict[str, Any] = {}
        for name in fields:
            if exclude_unset and name not in fields_set:
                continue
            item = getattr(value, name, None)
            if exclude_none and item is None:
                continue
            projected[name] = serialize_tool_arguments(
                item,
                exclude_unset=exclude_unset,
                exclude_none=exclude_none,
            )
        return projected
    if isinstance(value, Mapping):
        return {
            str(key): serialize_tool_arguments(
                item,
                exclude_unset=exclude_unset,
                exclude_none=exclude_none,
            )
            for key, item in value.items()
            if not (exclude_none and item is None)
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            serialize_tool_arguments(
                item,
                exclude_unset=exclude_unset,
                exclude_none=exclude_none,
            )
            for item in value
        ]
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "get_secret_value"):
        return value.get_secret_value()
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
    raw_arguments_digest: str | None = None
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
    replayed: bool = False


class ToolRegistry:
    """Collect role-scoped Tool Specs from independent providers."""

    def __init__(
        self,
        providers: Sequence[Any],
        *,
        allowed_tools: set[str] | frozenset[str] | None = None,
        compact: bool = False,
    ) -> None:
        self.providers = list(providers)
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self.compact = compact
        self._all_specs: dict[str, ToolSpec] = {}
        self._specs: dict[str, ToolSpec] = {}
        for provider in self.providers:
            for spec in provider.tool_specs():
                if spec.name in self._all_specs:
                    raise ValueError(f"duplicate tool specification: {spec.name}")
                self._all_specs[spec.name] = spec
                if self.allowed_tools is None or spec.name in self.allowed_tools:
                    self._specs[spec.name] = spec
        self._dynamic_exposed: OrderedDict[str, None] = OrderedDict()
        self._base_names: tuple[str, ...] = ()
        self._base_name_set: frozenset[str] = frozenset()
        if compact:
            from .tool_surface import DIRECT_TOOLS, search_spec

            self._base_names = tuple(
                name for name in self._specs if name in DIRECT_TOOLS
            )
            self._base_name_set = frozenset(self._base_names)
            catalog = search_spec(
                dict(self._specs),
                on_exact=self.expose_tool,
                known_specs=self._all_specs,
            )
            self._specs[catalog.name] = catalog
        else:
            self._base_names = tuple(self._specs)
            self._base_name_set = frozenset(self._base_names)
    def definitions(self) -> list[dict[str, Any]]:
        """Return the current role-scoped native tool surface."""
        names = list(self._base_names)
        if self.compact:
            names.append("tool_search")
            names.extend(self._dynamic_exposed)
        else:
            names = list(self._specs)
        definitions = [self._specs[name].definition() for name in names if name in self._specs]
        return json.loads(
            json.dumps(definitions, ensure_ascii=False, separators=(",", ":"))
        )

    admission_closed = False

    def has_tool(self, name: str) -> bool:
        return name in self._specs

    def is_known(self, name: str) -> bool:
        return name in self._all_specs

    def is_exposed(self, name: str) -> bool:
        if not self.compact:
            return name in self._specs
        return name in self._base_name_set or name == "tool_search" or name in self._dynamic_exposed

    def expose_tool(self, name: str) -> dict[str, Any]:
        """Expose one allowed non-base tool for the next model turn."""
        if name not in self._specs:
            return {"surfaced": False, "evicted": None, "slots": list(self._dynamic_exposed)}
        if not self.compact or name in self._base_name_set or name == "tool_search":
            return {"surfaced": True, "evicted": None, "slots": list(self._dynamic_exposed)}
        evicted = None
        if name in self._dynamic_exposed:
            self._dynamic_exposed.move_to_end(name)
        else:
            if len(self._dynamic_exposed) >= 3:
                evicted, _ = self._dynamic_exposed.popitem(last=False)
            self._dynamic_exposed[name] = None
        return {"surfaced": True, "evicted": evicted, "slots": list(self._dynamic_exposed)}

    def restore_exposed(self, names: Sequence[str]) -> None:
        for name in names:
            if name in self._specs:
                self.expose_tool(name)

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    async def close(self) -> None:
        results = await asyncio.gather(
            *(p.close() for p in self.providers if hasattr(p, "close")),
            return_exceptions=True,
        )
        failures = [r for r in results if isinstance(r, Exception)]
        if failures:
            raise ExceptionGroup("Tool resource cleanup failed", failures)


class ToolExecutor:
    """Parse, validate, schedule and invoke one model turn's tool calls."""

    def __init__(self, registry: ToolRegistry, *, max_concurrency: int = 10) -> None:
        if not 1 <= max_concurrency <= 10:
            raise ValueError("tool concurrency must be between 1 and 10")
        self.registry = registry
        self.max_concurrency = max_concurrency

    async def execute(
        self, tool_calls: Sequence[Mapping[str, Any]]
    ) -> list[PreparedToolCall]:
        prepared = self.prepare(tool_calls)
        return await self.execute_prepared(prepared)

    def prepare(
        self, tool_calls: Sequence[Mapping[str, Any]]
    ) -> list[PreparedToolCall]:
        """Parse and validate a model turn without invoking any Handler."""

        prepared = [self._prepare(index, item) for index, item in enumerate(tool_calls)]
        self._enforce_solo(prepared)
        for item in prepared:
            if item.result is not None:
                self._mark_not_started(item.result)
        return prepared

    @staticmethod
    def _mark_not_started(result: dict[str, Any]) -> None:
        error = result.get("error")
        if not isinstance(error, Mapping):
            return
        details = dict(error.get("details")) if isinstance(error.get("details"), Mapping) else {}
        details["execution_status"] = "not_started"
        result["error"] = {
            **dict(error),
            "message": str(error.get("message") or "")
            + " The requested tool was not executed; do not assume its intended changes exist.",
            "details": details,
        }

    def _next_call(self, name: str | None, arguments: Any = None) -> dict[str, Any]:
        """Return a native next call only when its arguments pass validation."""
        search_spec = self.registry.get("tool_search")
        if search_spec is None and name == "tool_search":
            return {"next_tool": None, "next_arguments": {}}
        if name == "tool_search":
            candidate = arguments if isinstance(arguments, dict) else {}
            try:
                search_spec.input_model.model_validate(candidate)
            except (AttributeError, ValidationError):
                candidate = {"query": ""}
            return {"next_tool": "tool_search", "next_arguments": candidate}
        spec = self.registry.get(name or "") if name else None
        if spec is not None and isinstance(arguments, dict):
            try:
                spec.input_model.model_validate(arguments)
            except ValidationError:
                pass
            else:
                return {"next_tool": spec.name, "next_arguments": arguments}
        if isinstance(name, str) and self.registry.has_tool(name):
            return {"next_tool": "tool_search", "next_arguments": {"name": name}}
        return {"next_tool": "tool_search", "next_arguments": {}}

    def _unknown_tool_details(self, name: str) -> dict[str, Any]:
        names = sorted(
            item for item in self.registry._specs
            if item != "tool_search"
        )
        suggestions = difflib.get_close_matches(name, names, n=3, cutoff=0.45)
        details = {"candidates": suggestions}
        if suggestions:
            details.update(self._next_call("tool_search", {"name": suggestions[0]}))
        else:
            details.update(self._next_call("tool_search", {"query": name[:200]}))
        return details

    def _ensure_error_guidance(self, result: dict[str, Any], name: str) -> dict[str, Any]:
        error = result.get("error")
        if not isinstance(error, Mapping) or error.get("stage") not in {"parse", "schema", "semantic"}:
            return result
        raw_details = error.get("details")
        details = dict(raw_details) if isinstance(raw_details, Mapping) else {}
        if "next_tool" not in details:
            details.update(self._next_call("tool_search", {"name": name}))
            error = {**dict(error), "details": details}
            return {**result, "error": error}
        return result

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
                    self._claims_conflict(item.claims, other.claims)
                    for other in selected
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
                    self._mark_not_started(item.result)
                    item.concurrency_wave = wave
                    continue
                selected.append(item)
            if not selected:
                pending = deferred
                continue
            await asyncio.gather(
                *(
                    self._invoke(item, batch_started=batch_started, wave=wave)
                    for item in selected
                )
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
        if not isinstance(function, Mapping) or not isinstance(
            function.get("name"), str
        ):
            return PreparedToolCall(
                index=index,
                tool_call_id=tool_call_id,
                name="unknown",
                raw_arguments_length=0,
                result=tool_error(
                    "schema",
                    "invalid_tool_call",
                    "Tool call is missing a function name",
                    details=self._next_call("tool_search", {}),
                ),
            )
        name = str(function["name"])
        raw = function.get("arguments", "{}")
        raw_length = len(raw) if isinstance(raw, str) else 0
        spec = self.registry.get(name)
        raw_digest = hashlib.sha256(
            (raw if isinstance(raw, str) else repr(raw)).encode("utf-8")
        ).hexdigest()
        item = PreparedToolCall(
            index,
            tool_call_id,
            name,
            raw_length,
            raw_arguments_digest=raw_digest,
            spec=spec,
        )
        if spec is None:
            if self.registry.is_known(name):
                item.result = tool_error(
                    "permission",
                    "tool_not_allowed_for_role",
                    "This Agent role cannot use that tool",
                    details={"tool": name},
                )
            else:
                item.result = tool_error(
                    "schema",
                    "unknown_tool",
                    "Unknown Agent tool",
                    details=self._unknown_tool_details(name),
                )
            return item
        if not self.registry.is_exposed(name):
            item.result = tool_error(
                "permission",
                "tool_not_exposed",
                "Search this exact tool name first; it will be available as a native function on the next model turn",
                retry_allowed=True,
                retry_action="search_tool",
                retry_tool="tool_search",
                details={"tool": name, "next_tool": "tool_search", "next_arguments": {"name": name}},
            )
            return item
        if not isinstance(raw, str):
            item.result = self._argument_error(
                name,
                "parse",
                "Tool arguments must be a JSON-encoded object",
                retry_allowed=True,
                retry_action="rewrite_arguments",
                details={
                    "raw_length": raw_length,
                    "required": self._required_fields(spec),
                },
            )
            return item
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            item.result = self._argument_error(
                name,
                "parse",
                "Tool arguments are not valid JSON",
                retry_allowed=True,
                retry_action="rewrite_arguments",
                details={
                    "json_error": exc.msg,
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
                retry_allowed=True,
                retry_action="rewrite_arguments",
                details={"required": self._required_fields(spec)},
            )
            return item
        try:
            item.arguments = spec.input_model.model_validate(value)
            item.claims = tuple(spec.access_claims(item.arguments))
        except ValidationError as exc:
            fields = validation_details(exc)
            reference_error = None
            if name in {"evidence_read", "report_read"}:
                from agent.state.references import parse_reference
                from agent.state.errors import StateError
                kind = name.removesuffix("_read")
                ref = value.get(f"{kind}_ref")
                if isinstance(ref, str):
                    try:
                        parse_reference(ref, expected=kind)
                    except StateError as error:
                        reference_error = error
            item.result = self._argument_error(
                name,
                "schema",
                reference_error.code if reference_error else "invalid_arguments",
                "Tool arguments failed schema validation",
                retry_allowed=True,
                retry_action="rewrite_arguments",
                details={"fields": fields, "allowed_fields": list(spec.input_model.model_fields)},
                arguments=value,
            )
            if (name == "system_shell" and isinstance(value.get("timeout"), (int, float))
                and value["timeout"] > 30):
                item.result["error"]["message"] = (
                    "Foreground Shell allows at most 30 seconds. Use system_task_start for longer work; nothing was started."
                )
                item.result["error"]["details"].update({
                    "next_tool": "system_task_start",
                    "next_arguments": {**value, "name": "Background command"},
                })
            if "arguments" not in spec.input_model.model_fields and set(value) == {"arguments"}:
                suggestion = self._next_call(name, value["arguments"])
                if suggestion["next_tool"] == name:
                    item.result["error"]["details"].update(suggestion)
                    item.result["error"]["message"] += " Remove the extra arguments wrapper and call the tool directly."
        except Exception as exc:
            item.result = map_exception(
                exc,
                tool_call_id=tool_call_id,
                tool_name=name,
            )
        return item

    def _argument_error(
        self,
        name: str,
        stage: str,
        code_or_message: str,
        message: str | None = None,
        *,
        retry_allowed: bool,
        retry_action: str,
        details: Any,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if message is None:
            code = "invalid_json"
            error_message = code_or_message
        else:
            code = code_or_message
            error_message = message
        details_map = dict(details) if isinstance(details, Mapping) else {"fields": details}
        correction = {
            "system_http_response": " Read response bodies with interaction_id and request_id from receipts, using offset_bytes/length_bytes (bytes), not offset/limit_chars.",
            "system_http_output": " List results with interaction_id from the receipt and cursor/limit; offset is not supported.",
            "system_http_analyze": " Analyze an existing interaction_id; paginate with cursor/limit, not offset. Use system_http_response for response-body bytes.",
            "system_http_probe": " Each case needs its own method and url; put form fields inside body: {type: form, value: {field: value}}.",
            "solver_review": " new_information is a value of assessment, not a separate field; put the finding in summary.",
        }.get(name, "")
        error_message += correction
        if name == "system_http_probe":
            error_message = (
                f"{error_message}. Rewrite the arguments as a JSON object with "
                "top-level cases: [{method,url,variables,combine}], and keep "
                "concurrency/rate_limit_per_second/wait_seconds at the top level. "
                "Do not retry the same raw arguments; use system_http_request for "
                "an ordered session."
            )
            details_map = {
                **details_map,
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
        from .tool_examples import examples_for

        examples = examples_for(name)
        if examples:
            details_map["examples"] = examples
        if name == "solver_review":
            error_message += " Correct the listed fields. Ordinary progress observations may omit validation; use it for verified conclusions or ruled-out hypotheses."
            if arguments is not None and "summary_zh" in arguments:
                error_message += " Use summary, not summary_zh."
            details_map["minimal_example"] = examples[0]
        candidate = dict(arguments) if isinstance(arguments, dict) else None
        if candidate is not None and name in {"system_http_request", "system_http_probe"}:
            if isinstance(candidate.get("wait_seconds"), (int, float)) and candidate["wait_seconds"] > 20:
                candidate["wait_seconds"] = 20
            if name == "system_http_probe":
                for field in ("concurrency", "rate_limit_per_second"):
                    if field in candidate and candidate[field] is None:
                        candidate.pop(field)
        if candidate is not None and name == "tool_result_read":
            if isinstance(candidate.get("limit_chars"), (int, float)) and candidate["limit_chars"] > 10_000:
                candidate["limit_chars"] = 10_000
        semantic_requires_new_input = code in {
            "unknown_template_variable",
            "invalid_workspace_path",
            "file_not_found",
            "tool_result_not_found",
        }
        next_call = (
            self._next_call("tool_search", {"name": name})
            if semantic_requires_new_input
            else self._next_call(name, candidate)
        )
        details_map.update(next_call)
        if next_call["next_tool"] == "tool_search":
            error_message += " Use the exact schema returned by tool_search before retrying."
        else:
            error_message += " Retry with the native tool and the corrected arguments shown."
        return tool_error(
            stage,
            code,
            error_message,
            retry_allowed=retry_allowed,
            retry_action=retry_action,
            retry_tool=name,
            details=details_map,
        )

    async def _invoke(
        self, item: PreparedToolCall, *, batch_started: float, wave: int
    ) -> None:
        assert item.spec is not None and item.arguments is not None
        started = monotonic()
        item.queue_latency_ms = int((started - batch_started) * 1_000)
        item.concurrency_wave = wave
        token = current_tool_call_id.set(item.tool_call_id)
        try:
            if self.registry.admission_closed:
                item.result = tool_error(
                    "conflict", "agent_inactive", "Agent tool admission is closed"
                )
                return
            value = item.spec.handler(item.arguments)
            if inspect.isawaitable(value):
                value = await value
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
        finally:
            current_tool_call_id.reset(token)
        error = (item.result or {}).get("error") or {}
        if (item.name in {"system_http_probe", "system_http_request"}
                and error.get("stage") == "semantic" and error.get("details", {}).get("fields")):
            item.result = self._argument_error(
                item.name, "semantic", error["code"], error["message"],
                retry_allowed=error["retry"]["allowed"], retry_action=error["retry"]["action"],
                details=error["details"],
                arguments=serialize_tool_arguments(item.arguments, exclude_unset=True, exclude_none=True),
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
        if item.result is not None:
            item.result = self._ensure_error_guidance(item.result, item.name)
        item.execution_latency_ms = int((monotonic() - started) * 1_000)
        item.total_latency_ms = int((monotonic() - batch_started) * 1_000)

    @staticmethod
    def _required_fields(spec: ToolSpec) -> list[str]:
        return [
            name
            for name, field_info in spec.input_model.model_fields.items()
            if field_info.is_required()
        ]

    @staticmethod
    def _resource_keys_overlap(left: str, right: str) -> bool:
        if left == right or left == "*" or right == "*":
            return True
        # Directory reads must serialize with writes anywhere below them.
        # Other namespaces intentionally retain exact-key semantics.
        if left.startswith("workspace:") and right.startswith("workspace:"):
            try:
                left_path = Path(left.removeprefix("workspace:")).resolve(strict=False)
                right_path = Path(right.removeprefix("workspace:")).resolve(
                    strict=False
                )
                return (
                    left_path == right_path
                    or left_path in right_path.parents
                    or right_path in left_path.parents
                )
            except (OSError, RuntimeError, ValueError):
                return left == right
        return False

    @classmethod
    def _claims_conflict(
        cls, left: Sequence[AccessClaim], right: Sequence[AccessClaim]
    ) -> bool:
        for first in left:
            for second in right:
                same = cls._resource_keys_overlap(first.key, second.key)
                if same and (first.mode == "write" or second.mode == "write"):
                    return True
        return False

    @classmethod
    def _depends_on_failed_write(
        cls, claims: Sequence[AccessClaim], failed: set[str]
    ) -> bool:
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
    result_ref: str = Field(
        pattern=r"^tool_result:tool_result_[0-9a-f]{32}$",
        description="Exact result_ref returned by a large tool result; copy it verbatim.",
    )
    offset: int = Field(default=0, ge=0, description="Character offset returned by the prior read.")
    limit_chars: int = Field(default=8_000, ge=1, le=10_000, description="Maximum 10,000 characters per read.")


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
                error_type="not_found",
                code="tool_result_not_found",
                message="Tool result reference does not exist for this Agent",
            ) from exc
        start = min(arguments.offset, len(content))
        end = min(start + arguments.limit_chars, len(content))
        return {
            "result_ref": arguments.result_ref,
            "offset": start,
            "content": content[start:end],
            "next_offset": end if end < len(content) else None,
            "read_result": {
                "tool": "tool_result_read",
                "arguments": {"result_ref": arguments.result_ref, "offset": end,
                              "limit_chars": arguments.limit_chars},
            } if end < len(content) else None,
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
            else (
                "permission"
                if exc.status_code in {401, 403}
                else "internal" if exc.status_code >= 500 else "semantic"
            )
        )
        details = dict(exc.detail)
        if exc.code in {"invalid_evidence_ref", "evidence_not_accessible"}:
            details.update(
                {
                    "next_tool": "evidence_search",
                    "next_arguments": {"query": "", "offset": 0, "limit": 20},
                    "reference_rule": "Copy an exact evidence_ref from context_refs or evidence_search; never synthesize one.",
                }
            )
        return tool_error(
            stage,
            exc.code,
            exc.message,
            retry_allowed=retry_allowed if exc.status_code == 409 else False,
            retry_action=retry_action if exc.status_code == 409 else "none",
            retry_tool=retry_tool if exc.status_code == 409 else None,
            details=details,
        )
    if isinstance(exc, SystemToolError):
        retry_allowed, retry_action, retry_tool = _conflict_retry(exc.code)
        message, details = exc.message, dict(exc.detail)
        stage = (
            "permission"
            if exc.error_type == "permission"
            else (
                "conflict"
                if exc.error_type == "conflict"
                else (
                    "semantic"
                    if exc.error_type in {"validation", "not_found"}
                    else "internal" if exc.error_type == "internal" else "execution"
                )
            )
        )
        return tool_error(
            stage,
            exc.code,
            message,
            retry_allowed=retry_allowed if exc.error_type == "conflict" else False,
            retry_action=retry_action if exc.error_type == "conflict" else "none",
            retry_tool=retry_tool if exc.error_type == "conflict" else None,
            details=details,
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
        benchmark_events = getattr(exc, "_benchmark_events", [])
        return tool_error(
            "execution",
            str(exc.code or "benchmark_api_error"),
            "The benchmark service rejected the operation",
            details={
                "status_code": exc.status_code,
                "benchmark_events": benchmark_events,
            },
        )
    if isinstance(exc, ChallengesTransportError):
        benchmark_events = getattr(exc, "_benchmark_events", [])
        return tool_error(
            "execution",
            "transport_error",
            "Unable to reach the benchmark service",
            details={"benchmark_events": benchmark_events},
        )
    if isinstance(exc, ChallengesResponseError):
        benchmark_events = getattr(exc, "_benchmark_events", [])
        return tool_error(
            "execution",
            "invalid_response",
            "The benchmark service returned an invalid response",
            details={
                "status_code": exc.status_code,
                "response_size": exc.response_size,
                "recovery_attempted": exc.recovery_attempted,
                "requires_reconciliation": exc.requires_reconciliation,
                "benchmark_events": benchmark_events,
            },
        )
    if isinstance(exc, ChallengesSDKError):
        return tool_error(
            "internal",
            "sdk_error",
            "The benchmark SDK could not complete the operation",
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
