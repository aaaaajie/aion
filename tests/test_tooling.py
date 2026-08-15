from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from agent.runner import AgentRunner
from agent.tooling import (
    AccessClaim,
    ToolExecutor,
    ToolRegistry,
    ToolResultReadArguments,
    ToolResultStore,
    ToolSpec,
    PreparedToolCall,
    tool_error,
)


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    value: int = Field(ge=1)
    resource: str = "default"


class Provider:
    def __init__(self, handler: Any, claims: Any = None) -> None:
        self.handler = handler
        self.claims = claims or (
            lambda arguments: (AccessClaim("read", f"resource:{arguments.resource}"),)
        )

    def tool_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                "test_tool",
                "Test one value.",
                Arguments,
                self.handler,
                access_claims=self.claims,
            )
        ]

    async def close(self) -> None:
        return None


def call(name: str, arguments: str, call_id: str = "call") -> dict[str, Any]:
    return {"id": call_id, "function": {"name": name, "arguments": arguments}}


def test_probe_argument_recovery_budget_allows_one_correction() -> None:
    runner = AgentRunner.__new__(AgentRunner)
    runner._probe_argument_failure_streak = 0
    runner._probe_recovery_exhausted = False
    first = PreparedToolCall(
        0,
        "first",
        "system_http_probe",
        10,
        result=tool_error(
            "parse",
            "invalid_json",
            "invalid",
            retry_allowed=True,
            retry_action="rewrite_arguments",
        ),
    )
    runner._apply_probe_recovery_budget([first])
    assert first.result["error"]["retry"]["allowed"] is True

    second = PreparedToolCall(
        0,
        "second",
        "system_http_probe",
        10,
        result=tool_error(
            "schema",
            "invalid_arguments",
            "invalid",
            retry_allowed=True,
            retry_action="rewrite_arguments",
        ),
    )
    runner._apply_probe_recovery_budget([second])
    assert second.result["error"]["code"] == "probe_argument_recovery_exhausted"
    assert second.result["error"]["retry"]["allowed"] is False
    assert runner._probe_recovery_exhausted is True


@pytest.mark.asyncio
async def test_invalid_json_and_schema_errors_never_reach_handler() -> None:
    calls = 0

    async def handler(arguments: BaseModel) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"value": arguments.value}

    executor = ToolExecutor(ToolRegistry([Provider(handler)]))
    invalid_json, invalid_schema = await executor.execute(
        [
            call("test_tool", '{"value":', "json"),
            call("test_tool", '{"value":"1","extra":true}', "schema"),
        ]
    )
    assert calls == 0
    assert invalid_json.result["error"]["stage"] == "parse"
    assert invalid_json.result["error"]["code"] == "invalid_json"
    assert invalid_json.result["error"]["details"]["required"] == ["value"]
    assert invalid_schema.result["error"]["stage"] == "schema"
    paths = {item["path"] for item in invalid_schema.result["error"]["details"]["fields"]}
    assert paths == {"value", "extra"}


def test_tool_definition_is_generated_from_the_input_model() -> None:
    async def handler(arguments: BaseModel) -> dict[str, Any]:
        return {}

    definition = ToolRegistry([Provider(handler)]).definitions()[0]["function"]
    assert definition["name"] == "test_tool"
    assert definition["parameters"]["additionalProperties"] is False
    assert definition["parameters"]["required"] == ["value"]
    assert definition["parameters"]["properties"]["value"]["minimum"] == 1


@pytest.mark.asyncio
async def test_independent_calls_run_concurrently_and_results_keep_model_order() -> None:
    entered = 0
    release = asyncio.Event()

    async def handler(arguments: BaseModel) -> dict[str, Any]:
        nonlocal entered
        entered += 1
        if entered == 2:
            release.set()
        await asyncio.wait_for(release.wait(), timeout=1)
        return {"value": arguments.value}

    executor = ToolExecutor(ToolRegistry([Provider(handler)]))
    results = await executor.execute(
        [
            call("test_tool", '{"value":1,"resource":"a"}', "first"),
            call("test_tool", '{"value":2,"resource":"b"}', "second"),
        ]
    )
    assert entered == 2
    assert [item.tool_call_id for item in results] == ["first", "second"]
    assert {item.concurrency_wave for item in results} == {1}


@pytest.mark.asyncio
async def test_failed_write_blocks_later_same_resource_but_not_independent_work() -> None:
    calls: list[str] = []

    async def handler(arguments: BaseModel) -> dict[str, Any]:
        calls.append(arguments.resource)
        if arguments.value == 1:
            return {
                "ok": False,
                "error": {
                    "stage": "semantic",
                    "code": "failed",
                    "message": "failed",
                    "retry": {
                        "allowed": False,
                        "action": "none",
                        "tool": None,
                        "same_arguments": False,
                    },
                    "details": {},
                },
            }
        return {"ok": True, "data": {"value": arguments.value}}

    provider = Provider(
        handler,
        claims=lambda arguments: (AccessClaim("write", f"resource:{arguments.resource}"),),
    )
    results = await ToolExecutor(ToolRegistry([provider])).execute(
        [
            call("test_tool", '{"value":1,"resource":"same"}', "first"),
            call("test_tool", '{"value":2,"resource":"same"}', "blocked"),
            call("test_tool", '{"value":3,"resource":"other"}', "independent"),
        ]
    )
    assert calls == ["same", "other"]
    assert results[1].result["error"]["code"] == "blocked_by_prior_tool_error"
    assert results[2].result["ok"] is True


@pytest.mark.asyncio
async def test_independent_control_tools_can_share_one_model_response() -> None:
    class Empty(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)

    invoked: list[str] = []

    async def handler(arguments: BaseModel) -> dict[str, Any]:
        invoked.append(type(arguments).__name__)
        return {}

    class StateProvider:
        def tool_specs(self) -> list[ToolSpec]:
            return [
                ToolSpec("challenge_observe", "observe", Empty, handler, lambda _arguments: ()),
                ToolSpec("challenge_dispatch", "dispatch", Empty, handler, lambda _arguments: ()),
            ]

        async def close(self) -> None:
            return None

    results = await ToolExecutor(ToolRegistry([StateProvider()])).execute(
        [call("challenge_observe", "{}", "observe"), call("challenge_dispatch", "{}", "dispatch")]
    )
    assert len(invoked) == 2
    assert all(item.result["ok"] for item in results)


def test_large_result_store_is_private_atomic_and_pageable(tmp_path: Path) -> None:
    owner = ToolResultStore(tmp_path / "run", "agent-a")
    content = json.dumps({"data": "x" * 30_000})
    result_ref = owner.persist(content)
    path = next((tmp_path / "run" / "agents" / "agent-a" / "tool-results").glob("*.json"))
    assert path.read_text(encoding="utf-8") == content
    assert os.stat(path).st_mode & 0o777 == 0o600

    offset = 0
    chunks: list[str] = []
    while True:
        page = owner.read(
            ToolResultReadArguments(result_ref=result_ref, offset=offset, limit_chars=8_000)
        )
        chunks.append(page["content"])
        if page["eof"]:
            break
        offset = page["next_offset"]
    assert "".join(chunks) == content

    other = ToolResultStore(tmp_path / "run", "agent-b")
    with pytest.raises(Exception) as error:
        other.read(ToolResultReadArguments(result_ref=result_ref))
    assert getattr(error.value, "code", None) == "tool_result_not_found"
    other_run = ToolResultStore(tmp_path / "other-run", "agent-a")
    with pytest.raises(Exception) as error:
        other_run.read(ToolResultReadArguments(result_ref=result_ref))
    assert getattr(error.value, "code", None) == "tool_result_not_found"


def test_large_result_keeps_evidence_projection(tmp_path: Path) -> None:
    evidence_ref = "evidence:evidence_" + "a" * 32
    result = {
        "ok": True,
        "data": {
            "evidence_refs": [evidence_ref],
            "reports": [{"summary": "x" * 20_000}],
        },
    }
    projected, result_ref, original_chars = AgentRunner._project_model_result(
        "challenge_observe",
        result,
        ToolResultStore(tmp_path / "run", "agent-a"),
    )
    assert result_ref is not None
    assert original_chars > 12_000
    assert projected["evidence_refs"] == [evidence_ref]
    assert projected["result_ref"] == result_ref
