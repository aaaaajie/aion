"""Agent-friendly wrapper around :class:`challenges_sdk.ChallengesClient`."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from typing import Any, ClassVar, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from challenges_sdk import (
    ChallengesAPIError,
    ChallengesClient,
    ChallengesResponseError,
    ChallengesSDKError,
    ChallengesTransportError,
)

ToolResult: TypeAlias = dict[str, Any]
ToolOperation: TypeAlias = Callable[..., Awaitable[Any]]


class _ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _NoArguments(_ToolArguments):
    pass


class _UniqueCodeArguments(_ToolArguments):
    unique_code: str = Field(min_length=1)

    @field_validator("unique_code")
    @classmethod
    def validate_unique_code(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("unique_code must not be blank")
        return value


class _SubmitFlagArguments(_UniqueCodeArguments):
    flag: str = Field(min_length=1, max_length=4096)


class BenchmarkTools:
    """Expose the Challenges SDK as JSON-compatible Agent tools.

    The wrapper does not own VPN state and does not retry requests. It owns
    the SDK-created HTTP client when built with :meth:`from_env`; injected
    clients remain safe to use because ``ChallengesClient.close`` does not
    close an externally-owned HTTP client.
    """

    _ROUTES: ClassVar[dict[str, tuple[type[_ToolArguments], str]]] = {
        "benchmark_list_challenges": (_NoArguments, "list_challenges"),
        "benchmark_start_challenge": (_UniqueCodeArguments, "start_challenge"),
        "benchmark_get_hint": (_UniqueCodeArguments, "get_hint"),
        "benchmark_submit_flag": (_SubmitFlagArguments, "submit_flag"),
        "benchmark_close_challenge": (_UniqueCodeArguments, "close_challenge"),
    }

    _TOOL_DEFINITIONS: ClassVar[list[dict[str, Any]]] = [
        {
            "type": "function",
            "function": {
                "name": "benchmark_list_challenges",
                "description": "List all benchmark challenges and current progress. This operation is read-only.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "benchmark_start_challenge",
                "description": (
                    "Start a challenge container and return its VPN-reachable addresses. "
                    "This consumes an active container slot; at most 3 challenges may be active."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "unique_code": {
                            "type": "string",
                            "description": "The unique challenge identifier.",
                            "minLength": 1,
                        }
                    },
                    "required": ["unique_code"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "benchmark_get_hint",
                "description": (
                    "Get a hint for a challenge. Warning: viewing a hint reduces the score "
                    "awarded for later flag submissions."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "unique_code": {
                            "type": "string",
                            "description": "The unique challenge identifier.",
                            "minLength": 1,
                        }
                    },
                    "required": ["unique_code"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "benchmark_submit_flag",
                "description": (
                    "Submit one flag for a challenge. A correct duplicate submission may "
                    "return a duplicate error and will not award points again."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "unique_code": {
                            "type": "string",
                            "description": "The unique challenge identifier.",
                            "minLength": 1,
                        },
                        "flag": {
                            "type": "string",
                            "description": "The flag value to submit.",
                            "minLength": 1,
                            "maxLength": 4096,
                        },
                    },
                    "required": ["unique_code", "flag"],
                    "additionalProperties": False,
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "benchmark_close_challenge",
                "description": (
                    "Close a challenge container and release its resources. "
                    "Do this after the challenge is complete."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "unique_code": {
                            "type": "string",
                            "description": "The unique challenge identifier.",
                            "minLength": 1,
                        }
                    },
                    "required": ["unique_code"],
                    "additionalProperties": False,
                },
            },
        },
    ]

    def __init__(self, client: ChallengesClient) -> None:
        self._client = client

    @classmethod
    def from_env(cls, **client_kwargs: Any) -> "BenchmarkTools":
        """Build a wrapper using ``BENCHMARK_BASE_URL`` and ``BENCHMARK_TOKEN``."""

        return cls(ChallengesClient.from_env(**client_kwargs))

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        """Return independent OpenAI-compatible function tool definitions."""

        return deepcopy(cls._TOOL_DEFINITIONS)

    async def __aenter__(self) -> "BenchmarkTools":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close resources owned by the underlying SDK client."""

        await self._client.close()

    async def list_challenges(self) -> ToolResult:
        return await self._invoke(
            "benchmark_list_challenges",
            _NoArguments,
            {},
            self._client.list_challenges,
        )

    async def start_challenge(self, unique_code: str) -> ToolResult:
        return await self._invoke(
            "benchmark_start_challenge",
            _UniqueCodeArguments,
            {"unique_code": unique_code},
            self._client.start_challenge,
        )

    async def get_hint(self, unique_code: str) -> ToolResult:
        return await self._invoke(
            "benchmark_get_hint",
            _UniqueCodeArguments,
            {"unique_code": unique_code},
            self._client.get_hint,
        )

    async def submit_flag(self, unique_code: str, flag: str) -> ToolResult:
        return await self._invoke(
            "benchmark_submit_flag",
            _SubmitFlagArguments,
            {"unique_code": unique_code, "flag": flag},
            self._client.submit_flag,
        )

    async def close_challenge(self, unique_code: str) -> ToolResult:
        return await self._invoke(
            "benchmark_close_challenge",
            _UniqueCodeArguments,
            {"unique_code": unique_code},
            self._client.close_challenge,
        )

    async def dispatch(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> ToolResult:
        """Route an Agent tool call without leaking SDK exceptions."""

        if not isinstance(name, str):
            return self._validation_error(
                "invalid_tool_name",
                "Tool name must be a string",
            )

        route = self._ROUTES.get(name)
        if route is None:
            return self._validation_error(
                "unknown_tool",
                f"Unknown benchmark tool: {name}",
            )

        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._validation_error(
                "invalid_arguments",
                "Tool arguments must be a JSON object",
            )

        argument_model, method_name = route
        return await self._invoke(
            name,
            argument_model,
            arguments,
            getattr(self._client, method_name),
        )

    async def _invoke(
        self,
        tool_name: str,
        argument_model: type[_ToolArguments],
        arguments: Mapping[str, Any],
        operation: ToolOperation,
    ) -> ToolResult:
        try:
            validated = argument_model.model_validate(arguments)
            data = await operation(**validated.model_dump())
            return {"ok": True, "data": self._to_json(data)}
        except Exception as exc:
            return self._error_result(exc, tool_name)

    def _error_result(self, exc: Exception, tool_name: str) -> ToolResult:
        if isinstance(exc, ChallengesAPIError):
            return {
                "ok": False,
                "error": {
                    "type": "api",
                    "code": self._redact(exc.code or "http_error"),
                    "message": self._redact(exc.message),
                    "status_code": exc.status_code,
                    "detail": self._redact(exc.detail),
                },
            }

        if isinstance(exc, ChallengesTransportError):
            return {
                "ok": False,
                "error": {
                    "type": "transport",
                    "code": "transport_error",
                    "message": "Unable to reach the benchmark service",
                    "status_code": None,
                    "detail": {},
                },
            }

        if isinstance(exc, ChallengesResponseError):
            return {
                "ok": False,
                "error": {
                    "type": "internal",
                    "code": "invalid_response",
                    "message": "The benchmark service returned an invalid response",
                    "status_code": None,
                    "detail": self._redact(exc.errors),
                },
            }

        if isinstance(exc, (ValidationError, ValueError)):
            detail = exc.errors() if isinstance(exc, ValidationError) else {}
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "invalid_arguments",
                    "message": f"Invalid arguments for {tool_name}",
                    "status_code": None,
                    "detail": self._safe_validation_detail(detail),
                },
            }

        if isinstance(exc, ChallengesSDKError):
            return {
                "ok": False,
                "error": {
                    "type": "internal",
                    "code": "sdk_error",
                    "message": "The benchmark SDK could not complete the operation",
                    "status_code": None,
                    "detail": {},
                },
            }

        return {
            "ok": False,
            "error": {
                "type": "internal",
                "code": "internal_error",
                "message": "The benchmark tool failed unexpectedly",
                "status_code": None,
                "detail": {},
            },
        }

    @staticmethod
    def _validation_error(code: str, message: str) -> ToolResult:
        return {
            "ok": False,
            "error": {
                "type": "validation",
                "code": code,
                "message": message,
                "status_code": None,
                "detail": {},
            },
        }

    def _safe_validation_detail(self, detail: Any) -> Any:
        if not isinstance(detail, list):
            return detail
        return [
            {
                key: self._redact(item[key])
                for key in ("loc", "msg", "type")
                if key in item
            }
            for item in detail
            if isinstance(item, dict)
        ]

    @staticmethod
    def _to_json(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
        if isinstance(value, list):
            return [BenchmarkTools._to_json(item) for item in value]
        if isinstance(value, tuple):
            return [BenchmarkTools._to_json(item) for item in value]
        if isinstance(value, dict):
            return {key: BenchmarkTools._to_json(item) for key, item in value.items()}
        return value

    def _redact(self, value: Any) -> Any:
        secret = getattr(self._client, "_token", "")
        if isinstance(value, str):
            return value.replace(secret, "[REDACTED]") if secret else value
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, tuple):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        return value
