"""Agent-facing wrapper for network discovery tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from tools.system.policy import SystemToolError

from .manager import AgentNetworkClient
from .models import (
    NetworkCleanupArguments,
    NetworkDiscoveryArguments,
    NetworkOutputArguments,
    NetworkStopArguments,
)


def _definition(name: str, description: str, model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema.setdefault("additionalProperties", False)
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": schema},
    }


class NetworkTools:
    """Expose aion-fscan capabilities through fixed JSON contracts."""

    _ROUTES: ClassVar[dict[str, tuple[type[BaseModel], str]]] = {
        "system_network_discovery": (NetworkDiscoveryArguments, "discovery"),
        "system_network_output": (NetworkOutputArguments, "output"),
        "system_network_stop": (NetworkStopArguments, "stop"),
        "system_network_cleanup": (NetworkCleanupArguments, "cleanup"),
    }
    _TOOL_DEFINITIONS: ClassVar[list[dict[str, Any]]] = [
        _definition(
            "system_network_discovery",
            "Use first when the target is an address range or its live hosts and ports are unknown. It performs host discovery, TCP port scanning and Nmap-style service identification; web_mark optionally enables only webtitle. Brute force, POC and local-effect plugins are always disabled. The task may be queued or continue in the background: keep its task_id and call system_network_output instead of creating another scan. After HTTP services are known, use system_web_fingerprint for technology identification.",
            NetworkDiscoveryArguments,
        ),
        _definition(
            "system_network_output",
            "Use for every follow-up on a queued or running network task. It long-polls by default, returns progress and structured host/port/service records from the supplied cursor, is idempotent for the same cursor, and never starts or replays a scan.",
            NetworkOutputArguments,
        ),
        _definition(
            "system_network_stop",
            "Use to stop an owned queued or running network discovery task. It preserves already stored results.",
            NetworkStopArguments,
        ),
        _definition(
            "system_network_cleanup",
            "Use only after a network task reaches a terminal state and results are no longer needed. Repeated cleanup is safe.",
            NetworkCleanupArguments,
        ),
    ]

    def __init__(self, client: AgentNetworkClient) -> None:
        self._client = client

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return deepcopy(cls._TOOL_DEFINITIONS)

    async def dispatch(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        route = self._ROUTES.get(name)
        if route is None:
            return self._failure("validation", "unknown_tool", "Unknown network tool")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._failure(
                "validation", "invalid_arguments", "Tool arguments must be an object"
            )
        model, operation_name = route
        try:
            validated = model.model_validate(arguments)
            operation: Callable[..., Awaitable[dict[str, Any]]] = getattr(
                self._client, operation_name
            )
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
                    "message": "Invalid network-tool arguments",
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
            return self._failure(
                "internal", "network_operation_failed", "Network operation could not be completed"
            )
        except Exception:
            return self._failure(
                "internal", "network_internal_error", "Network tool failed unexpectedly"
            )

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
