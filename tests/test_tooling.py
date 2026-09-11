from __future__ import annotations

import asyncio
import json
import os
import warnings
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from agent.runner import AgentRunner
from agent.subagents.models import DelegateArguments
from agent.state import AgentReportInput
from agent.tooling import (
    AccessClaim,
    ToolExecutor,
    ToolRegistry,
    ToolResultReadArguments,
    ToolResultStore,
    ToolSpec,
    PreparedToolCall,
    serialize_tool_arguments,
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


def test_probe_argument_errors_preserve_fields_and_allow_further_corrections() -> None:
    runner = AgentRunner.__new__(AgentRunner)
    runner._invalid_argument_digests = {}
    for digest, stage in (("first", "parse"), ("second", "schema"), ("third", "schema")):
        item = PreparedToolCall(0, digest, "system_http_probe", 10,
            raw_arguments_digest=digest, result=tool_error(stage, "invalid_arguments", "invalid",
                retry_allowed=True, retry_action="rewrite_arguments", details={"fields": ["body"]}))
        runner._annotate_repeated_arguments([item])
        assert item.result["error"]["code"] == "invalid_arguments"
        assert item.result["error"]["details"]["fields"] == ["body"]
        assert item.result["error"]["retry"]["allowed"]
    valid = PreparedToolCall(0, "valid", "system_http_probe", 10, arguments=Arguments(value=1))
    runner._annotate_repeated_arguments([valid])
    assert not runner._invalid_argument_digests


@pytest.mark.asyncio
async def test_tool_executor_accepts_synchronous_and_async_handlers() -> None:
    def synchronous_handler(arguments: BaseModel) -> dict[str, Any]:
        return {"value": arguments.value}

    executor = ToolExecutor(ToolRegistry([Provider(synchronous_handler)]))
    result = (await executor.execute([call("test_tool", '{"value":1}', "sync")]))[0]

    assert result.result == {"ok": True, "data": {"value": 1}}


def test_best_effort_tool_arguments_serialize_without_pydantic_warnings() -> None:
    dispatch = DelegateArguments.model_validate(
        {"tasks": [{"task_key": "baseline", "objective": "collect baseline"}]}
    )
    report = AgentReportInput.model_validate(
        {
            "status": "completed",
            "summary": "done",
            "findings": [{"summary": "a finding", "evidence_refs": []}],
        }
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        dispatch_payload = serialize_tool_arguments(dispatch)
        report_payload = serialize_tool_arguments(report)
    assert not [
        item for item in captured if "PydanticSerialization" in str(item.message)
    ]
    assert dispatch_payload["tasks"][0]["task_key"] == "baseline"
    assert report_payload["findings"][0]["summary"] == "a finding"


def test_repeated_arguments_annotate_an_exact_duplicate() -> None:
    runner = AgentRunner.__new__(AgentRunner)
    runner._invalid_argument_digests = {}
    first = PreparedToolCall(
        0,
        "first",
        "system_http_probe",
        10,
        raw_arguments_digest="same-invalid-call",
        result=tool_error(
            "schema",
            "invalid_arguments",
            "invalid",
            retry_allowed=True,
            retry_action="rewrite_arguments",
        ),
    )
    runner._annotate_repeated_arguments([first])
    duplicate = PreparedToolCall(
        0,
        "duplicate",
        "system_http_probe",
        10,
        raw_arguments_digest="same-invalid-call",
        result=tool_error(
            "schema",
            "invalid_arguments",
            "invalid",
            retry_allowed=True,
            retry_action="rewrite_arguments",
        ),
    )
    runner._annotate_repeated_arguments([duplicate])
    assert duplicate.result["error"]["code"] == "invalid_arguments"
    assert duplicate.result["error"]["details"]["repeated_arguments"] is True
    assert duplicate.result["error"]["retry"]["allowed"] is True


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
    assert invalid_json.result["error"]["details"]["json_error"]
    assert invalid_json.result["error"]["retry"]["tool"] == "test_tool"
    assert invalid_json.result["error"]["details"]["required"] == ["value"]
    assert invalid_schema.result["error"]["stage"] == "schema"
    paths = {
        item["path"] for item in invalid_schema.result["error"]["details"]["fields"]
    }
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
async def test_independent_calls_run_concurrently_and_results_keep_model_order() -> (
    None
):
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
async def test_failed_write_blocks_later_same_resource_but_not_independent_work() -> (
    None
):
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
        claims=lambda arguments: (
            AccessClaim("write", f"resource:{arguments.resource}"),
        ),
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
                ToolSpec(
                    "solver_observe", "observe", Empty, handler, lambda _arguments: ()
                ),
                ToolSpec(
                    "solver_delegate", "dispatch", Empty, handler, lambda _arguments: ()
                ),
            ]

        async def close(self) -> None:
            return None

    results = await ToolExecutor(ToolRegistry([StateProvider()])).execute(
        [
            call("solver_observe", "{}", "observe"),
            call("solver_delegate", "{}", "dispatch"),
        ]
    )
    assert len(invoked) == 2
    assert all(item.result["ok"] for item in results)


def test_large_result_store_is_private_atomic_and_pageable(tmp_path: Path) -> None:
    owner = ToolResultStore(tmp_path / "run", "agent-a")
    content = json.dumps({"data": "x" * 30_000})
    result_ref = owner.persist(content)
    path = next(
        (tmp_path / "run" / "agents" / "agent-a" / "tool-results").glob("*.json")
    )
    assert path.read_text(encoding="utf-8") == content
    assert os.stat(path).st_mode & 0o777 == 0o600

    offset = 0
    chunks: list[str] = []
    while True:
        page = owner.read(
            ToolResultReadArguments(
                result_ref=result_ref, offset=offset, limit_chars=8_000
            )
        )
        chunks.append(page["content"])
        if page["eof"]:
            assert page["read_result"] is None
            break
        followup = page["read_result"]
        assert followup["tool"] == "tool_result_read"
        args = ToolResultReadArguments.model_validate(followup["arguments"])
        assert args.result_ref == result_ref
        assert args.offset == page["next_offset"]
        offset = args.offset
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
        "solver_observe",
        result,
        ToolResultStore(tmp_path / "run", "agent-a"),
    )
    assert result_ref is not None
    assert original_chars > 12_000
    assert projected["evidence_refs"] == [evidence_ref]
    assert projected["result_ref"] == result_ref


def test_deferred_result_has_executable_read_instruction(tmp_path):
    store = ToolResultStore(tmp_path, "solver")
    original = {"ok": True, "data": {"output": "中" * 18000 + "decisive-tail"}}
    projected, ref, _ = AgentRunner._project_model_result("system_shell", original, store)
    compacted = AgentRunner._compact_tool_messages([
        {"role": "tool", "tool_call_id": "shell", "content": json.dumps(projected)}])
    compacted_result = json.loads(compacted[0]["content"])
    assert compacted_result["result_ref"] == ref
    assert compacted_result["read_result"] == projected["read_result"]
    chunks = []
    instruction = compacted_result["read_result"]
    while instruction:
        assert instruction["tool"] == "tool_result_read"
        page = store.read(ToolResultReadArguments.model_validate(instruction["arguments"]))
        chunks.append(page["content"])
        instruction = page["read_result"]
    assert json.loads("".join(chunks)) == original


async def test_long_foreground_shell_rejected_and_background_unblocks_batch():
    from tools.system.models import ShellArguments, TaskStartArguments

    started = []
    released = asyncio.Event()
    running = []

    async def run_task():
        await released.wait()

    async def shell(args):
        started.append(args.command)
        if isinstance(args, TaskStartArguments):
            running.append(asyncio.create_task(run_task()))
            return {'ok': True, 'data': {'task_id': 'owned-task', 'status': 'running'}}
        raise AssertionError('Rejected foreground command must not execute')

    async def probe(args):
        assert len(running) == 1 and not running[0].done()
        return {'ok': True, 'data': 'independent response'}

    class Tools:
        def tool_specs(self):
            return [
                ToolSpec('system_shell', 'short', ShellArguments, shell,
                         lambda _: (AccessClaim('write', '*'),)),
                ToolSpec('system_task_start', 'background', TaskStartArguments, shell,
                         lambda _: (AccessClaim('write', '*'),)),
                ToolSpec('test_tool', 'probe', Arguments, probe,
                         lambda _: (AccessClaim('read', 'http'),)),
            ]

    executor = ToolExecutor(ToolRegistry([Tools()]))
    original = {'command': 'scan fixture', 'timeout': 500.0, 'cwd': '.', 'max_output_chars': 6000}
    rejected = (await executor.execute([call('system_shell', json.dumps(original))]))[0].result
    assert not started
    assert rejected['error']['details']['execution_status'] == 'not_started'
    suggestion = rejected['error']['details']
    assert suggestion['next_tool'] == 'system_task_start'
    assert {k: suggestion['next_arguments'][k] for k in original} == original
    try:
        results = await asyncio.wait_for(executor.execute([
            call('system_task_start', json.dumps(suggestion['next_arguments']), 'background'),
            call('test_tool', json.dumps({'value': 1}), 'probe'),
        ]), 1)
        assert all(item.result['ok'] for item in results)
        assert started == ['scan fixture']
        assert results[1].concurrency_wave > results[0].concurrency_wave
    finally:
        released.set()
        await asyncio.gather(*running)
