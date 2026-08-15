"""Tool Specs around :class:`challenges_sdk.ChallengesClient`."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent.tooling import AccessClaim, ToolSpec
from challenges_sdk import ChallengesClient


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _NoArguments(_Arguments):
    pass


class _UniqueCodeArguments(_Arguments):
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
    """Expose benchmark operations through the shared ToolExecutor."""

    def __init__(self, client: ChallengesClient) -> None:
        self._client = client

    @classmethod
    def from_env(cls, **client_kwargs: Any) -> "BenchmarkTools":
        return cls(ChallengesClient.from_env(**client_kwargs))

    def tool_specs(self) -> list[ToolSpec]:
        async def list_challenges(arguments: BaseModel) -> Any:
            assert isinstance(arguments, _NoArguments)
            return _jsonable(await self._client.list_challenges())

        async def start_challenge(arguments: BaseModel) -> Any:
            assert isinstance(arguments, _UniqueCodeArguments)
            return _jsonable(await self._client.start_challenge(arguments.unique_code))

        async def get_hint(arguments: BaseModel) -> Any:
            assert isinstance(arguments, _UniqueCodeArguments)
            return _jsonable(await self._client.get_hint(arguments.unique_code))

        async def submit_flag(arguments: BaseModel) -> Any:
            assert isinstance(arguments, _SubmitFlagArguments)
            return _jsonable(
                await self._client.submit_flag(arguments.unique_code, arguments.flag)
            )

        async def close_challenge(arguments: BaseModel) -> Any:
            assert isinstance(arguments, _UniqueCodeArguments)
            return _jsonable(await self._client.close_challenge(arguments.unique_code))

        return [
            ToolSpec("benchmark_list_challenges", "List benchmark challenges and current progress. This operation is read-only.", _NoArguments, list_challenges, lambda _arguments: (AccessClaim("read", "benchmark"),)),
            ToolSpec("benchmark_start_challenge", "Start a challenge container and return VPN-reachable addresses.", _UniqueCodeArguments, start_challenge, lambda _arguments: (AccessClaim("write", "benchmark"),)),
            ToolSpec("benchmark_get_hint", "Get a challenge hint. Viewing a hint can reduce the awarded score.", _UniqueCodeArguments, get_hint, lambda _arguments: (AccessClaim("write", "benchmark"),)),
            ToolSpec("benchmark_submit_flag", "Submit one flag for a challenge. The operation is never automatically retried.", _SubmitFlagArguments, submit_flag, lambda _arguments: (AccessClaim("write", "benchmark"),)),
            ToolSpec("benchmark_close_challenge", "Close a challenge container and release its resources.", _UniqueCodeArguments, close_challenge, lambda _arguments: (AccessClaim("write", "benchmark"),)),
        ]

    async def close(self) -> None:
        await self._client.close()


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value
