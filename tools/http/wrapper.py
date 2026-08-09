"""Agent-facing wrapper for generic HTTP interaction capabilities."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from tools.system.policy import SystemToolError

from .manager import AgentHttpClient
from .models import (
    HttpAnalyzeArguments,
    HttpCleanupArguments,
    HttpOutputArguments,
    FingerprintArguments,
    PathProbeArguments,
    HttpProbeArguments,
    HttpRequestArguments,
    HttpResponseArguments,
    HttpStopArguments,
)


def _definition(name: str, description: str, model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema.setdefault("additionalProperties", False)
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": schema},
    }


class HttpTools:
    """Expose one Agent-bound HTTP engine through fixed JSON contracts."""

    _ROUTES: ClassVar[dict[str, tuple[type[BaseModel], str]]] = {
        "system_http_request": (HttpRequestArguments, "request"),
        "system_http_probe": (HttpProbeArguments, "probe"),
        "system_web_path_probe": (PathProbeArguments, "path_probe"),
        "system_web_fingerprint": (FingerprintArguments, "fingerprint"),
        "system_http_analyze": (HttpAnalyzeArguments, "analyze"),
        "system_http_output": (HttpOutputArguments, "output"),
        "system_http_response": (HttpResponseArguments, "response"),
        "system_http_stop": (HttpStopArguments, "stop"),
        "system_http_cleanup": (HttpCleanupArguments, "cleanup"),
    }
    _TOOL_DEFINITIONS: ClassVar[list[dict[str, Any]]] = [
        _definition(
            "system_http_request",
            "Use for one new HTTP request when the method, URL, parameters, body, and optional Session are already known. It always sends a fresh request. Capture the returned interaction_id/request_id; if the result is queued or running, poll with system_http_output instead of calling this tool again.",
            HttpRequestArguments,
        ),
        _definition(
            "system_http_probe",
            "Use for many independent requests generated from finite values, ranges, or workspace files. Choose product for every combination and zip for ordinal pairs. It is for a matrix, not for response-dependent request chains; use separate system_http_request calls with the same session_id for those.",
            HttpProbeArguments,
        ),
        _definition(
            "system_web_path_probe",
            "Use after HTTP services are known, and normally after system_web_fingerprint, for high-throughput web path discovery against one base URL. Pick quick for the first surface pass, targeted from the identified stack, and deep for final coverage. This tool discovers paths only: it does not issue implicit homepage/favicon fingerprint requests. Its wordlist plan streams to disk and Runtime controls resource admission. Keep interaction_id and poll with system_http_output; never create another path task merely to check status. Recursion is explicit and only GET/HEAD is supported.",
            PathProbeArguments,
        ),
        _definition(
            "system_web_fingerprint",
            "Use to identify the web technology stack on each discovered HTTP service before choosing a targeted/deep path profile. The passive phase reuses one homepage/Header/title/favicon response across TscanPlus, Yakit and EHole rules; the active phase probes known component paths. Results include stable rule_id, merged rule_sources and evidence. Keep interaction_id and poll with system_http_output; polling does not resend traffic. Use system_http_probe instead for parameter, Header, Cookie or Body variants.",
            FingerprintArguments,
        ),
        _definition(
            "system_http_analyze",
            "Use after a request or probe to wait for or read deterministic response analysis: content features, structured summaries, exact groups, and similarity groups. Automatic analysis does not resend traffic. Set force=true only to append a new analysis revision for selected requests/groups.",
            HttpAnalyzeArguments,
        ),
        _definition(
            "system_http_output",
            "Use to poll an existing interaction and read compact response/analysis records with a cursor and filters. This tool is idempotent and never sends network traffic; use it for queued, running, analyzing, or background work.",
            HttpOutputArguments,
        ),
        _definition(
            "system_http_response",
            "Use only when structured output is insufficient and exact Body evidence is needed. Read one owned request Body by byte range; continue with the returned next_offset. Text is decoded and binary data is base64 encoded.",
            HttpResponseArguments,
        ),
        _definition(
            "system_http_stop",
            "Use to cancel an owned queued, running, or analyzing interaction. It is idempotent and preserves already stored responses; it does not resend or clean the output.",
            HttpStopArguments,
        ),
        _definition(
            "system_http_cleanup",
            "Use only after an interaction reaches a terminal state and no further output or Body evidence is needed. It deletes private files, keeps audit metadata, and repeated cleanup is safe.",
            HttpCleanupArguments,
        ),
    ]

    def __init__(self, client: AgentHttpClient) -> None:
        self._client = client

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return deepcopy(cls._TOOL_DEFINITIONS)

    async def dispatch(self, name: str, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        route = self._ROUTES.get(name)
        if route is None:
            return self._failure("validation", "unknown_tool", "Unknown HTTP tool")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._failure("validation", "invalid_arguments", "Tool arguments must be an object")
        model, operation_name = route
        try:
            validated = model.model_validate(arguments)
            operation: Callable[..., Awaitable[dict[str, Any]]] = getattr(self._client, operation_name)
            result = await operation(
                **{name: getattr(validated, name) for name in type(validated).model_fields}
            )
            return {"ok": True, "data": result}
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "invalid_arguments",
                    "message": "Invalid HTTP-tool arguments",
                    "status_code": None,
                    "detail": [
                        {key: item[key] for key in ("loc", "msg", "type") if key in item}
                        for item in exc.errors()
                    ],
                },
            }
        except SystemToolError as exc:
            return {
                "ok": False,
                "error": {
                    "type": exc.error_type,
                    "code": exc.code,
                    "message": exc.message,
                    "status_code": None,
                    "detail": exc.detail,
                },
            }
        except (OSError, ValueError):
            return self._failure("internal", "http_operation_failed", "HTTP operation could not be completed")
        except Exception:
            return self._failure("internal", "http_internal_error", "HTTP tool failed unexpectedly")

    async def close(self) -> None:
        await self._client.close()

    @staticmethod
    def _failure(error_type: str, code: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": error_type,
                "code": code,
                "message": message,
                "status_code": None,
                "detail": {},
            },
        }
