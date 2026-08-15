"""Tool Specs for in-memory Benchmark fakes used by Runtime tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tooling import AccessClaim, ToolSpec


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Empty(_Arguments):
    pass


class _UniqueCode(_Arguments):
    unique_code: str = Field(min_length=1)


class _SubmitFlag(_UniqueCode):
    flag: str = Field(min_length=1, max_length=4096)


def benchmark_tool_specs(
    dispatch: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
) -> list[ToolSpec]:
    specs: list[ToolSpec] = []
    for name, model, mode in (
        ("benchmark_list_challenges", _Empty, "read"),
        ("benchmark_start_challenge", _UniqueCode, "write"),
        ("benchmark_get_hint", _UniqueCode, "write"),
        ("benchmark_submit_flag", _SubmitFlag, "write"),
        ("benchmark_close_challenge", _UniqueCode, "write"),
    ):
        async def handler(arguments: BaseModel, tool_name: str = name) -> dict[str, Any]:
            return await dispatch(tool_name, arguments.model_dump())

        specs.append(
            ToolSpec(
                name,
                f"In-memory test implementation for {name}.",
                model,
                handler,
                access_claims=lambda _arguments, claim_mode=mode: (
                    AccessClaim(claim_mode, "benchmark"),
                ),
            )
        )
    return specs
