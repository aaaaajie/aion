"""Compact entry points retain the real tool protocol and authority checks."""

import json
import asyncio

from pydantic import BaseModel

from agent.tooling import ToolRegistry, ToolExecutor, ToolSpec, AccessClaim
from agent.memory.context import rough_token_count
from tests.test_solver_lifecycle import harness, completion


class Args(BaseModel):
    value: int


class Tools:
    def __init__(self):
        self.calls = []

    def tool_specs(self):
        def call(args):
            self.calls.append(args.value)
            return {"ok": True, "data": {"value": args.value}}

        return [
            ToolSpec(
                "special_tool",
                "A special read operation",
                Args,
                call,
                lambda _: [AccessClaim("write", "one")],
                requires_solo=True,
            )
        ]


class DynamicTools:
    def tool_specs(self):
        return [
            ToolSpec(
                f"dynamic_{index}",
                f"Dynamic tool {index}",
                Args,
                lambda args: {"value": args.value},
                lambda _: (AccessClaim("read", "dynamic"),),
            )
            for index in range(4)
        ]


def wire(name, args, call_id="test"):
    return {"id": call_id, "function": {"name": name, "arguments": json.dumps(args)}}


async def invoke(registry, name, arguments):
    return (await ToolExecutor(registry).execute([wire(name, arguments)]))[0]


async def test_compact_catalog_validation_authority_and_solo():
    provider = Tools()
    registry = ToolRegistry([provider], allowed_tools={"special_tool"}, compact=True)
    before = registry.definitions()
    assert {d["function"]["name"] for d in before} == {"tool_search"}
    listing = await invoke(registry, "tool_search", {"query": "special", "limit": 1})
    assert listing.result["data"]["tools"][0]["name"] == "special_tool"
    schema = await invoke(registry, "tool_search", {"name": "special_tool"})
    assert schema.result["data"]["requires_solo"] is True
    assert schema.result["data"]["tool"]["parameters"]["required"] == ["value"]
    invalid = await invoke(registry, "special_tool", {"value": "bad"})
    assert invalid.result["ok"] is False and not provider.calls
    unknown = await invoke(registry, "tool_call", {})
    assert unknown.result["error"]["code"] == "unknown_tool"
    solo = await ToolExecutor(registry).execute(
        [
            wire("special_tool", {"value": 1}, "one"),
            wire("tool_search", {}, "two"),
        ]
    )
    assert all(item.result["ok"] is False for item in solo) and not provider.calls
    called = await invoke(registry, "special_tool", {"value": 4})
    assert called.name == "special_tool" and called.result["data"]["value"] == 4
    assert provider.calls == [4]
    assert {d["function"]["name"] for d in registry.definitions()} == {"tool_search", "special_tool"}


async def test_exact_search_surfaces_three_native_tools_with_lru_eviction():
    registry = ToolRegistry([DynamicTools()], compact=True)
    executor = ToolExecutor(registry)
    for index in range(4):
        result = await invoke(registry, "tool_search", {"name": f"dynamic_{index}"})
        assert result.result["data"]["available_next_turn"] is True
    names = {d["function"]["name"] for d in registry.definitions()}
    assert "tool_search" in names
    assert {f"dynamic_{index}" for index in range(1, 4)} <= names
    assert "dynamic_0" not in names
    assert result.result["data"]["evicted"] == "dynamic_0"
    blocked = await invoke(registry, "dynamic_0", {"value": 1})
    assert blocked.result["error"]["code"] == "tool_not_exposed"
    called = await invoke(registry, "dynamic_3", {"value": 1})
    assert called.result["ok"]


async def test_compact_real_runner_discovers_delegation_and_solves_without_worker(
    tmp_path,
):
    requests = []

    async def model(role, index, body):
        requests.append(body)
        if index == 0:
            return completion("tool_search", {"name": "solver_delegate"})
        if index == 1:
            schema = json.loads(body["messages"][-1]["content"])["data"]["tool"]
            assert schema["name"] == "solver_delegate"
            return completion("solver_progress", {"summary": "正在读取本题答案"})
        if index == 2:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if index == 3:
            return completion("solver_submit_flag", {"flag": "flag{offline_fixture}"})
        return completion(content="The platform confirmed completion.")

    sup, service, platform, _, chief = await harness(tmp_path, model)
    try:
        launched = await sup.create_solver(chief, "a")
        solver_id = launched["data"]["agent_id"]
        await asyncio.wait_for(sup._tasks[solver_id], 5)
        assert platform.submissions == ["flag{offline_fixture}"]
        assert len(requests) == 4
        names = {d["function"]["name"] for d in requests[0]["tools"]}
        assert "tool_search" in names and "tool_call" not in names
        assert "system_grep" in names and "system_list_directory" in names
        assert "solver_delegate" in {d["function"]["name"] for d in requests[1]["tools"]}
        assert all(
            "<available_skills>" not in request["messages"][0]["content"]
            for request in requests
        )
        events = await service.list_agent_events("run", solver_id)
        assert any(
            e["event_type"] == "tool_call"
            and e["payload"].get("tool_name") == "solver_progress"
            for e in events
        )
        assert not any(e["event_type"] == "solver_observation_started" for e in events)
        assert [a["role"] for a in (await service.get_overview("run"))["agents"]].count(
            "worker"
        ) == 0
    finally:
        await sup.close()
        await service.close()


async def test_same_capabilities_have_smaller_fixed_schema_and_observation_can_be_disabled(
    tmp_path,
):
    measurements = {}
    for compact in (False, True):
        directory = tmp_path / str(compact)
        directory.mkdir()

        async def model(role, index, body):
            measurements[compact] = rough_token_count(body["tools"])
            if index < 6:
                return completion(
                    "system_read_file", {"file_path": "shared/answer.txt"}
                )
            if index == 6:
                return completion(
                    "solver_submit_flag", {"flag": "flag{offline_fixture}"}
                )
            return completion(content="The platform confirmed completion.")

        sup, service, platform, _, chief = await harness(
            directory, model, compact_tools=compact, solver_observation=False
        )
        try:
            started = await sup.create_solver(chief, "a")
            solver_id = started["data"]["agent_id"]
            await asyncio.wait_for(sup._tasks[solver_id], 5)
            assert platform.submissions == ["flag{offline_fixture}"]
            assert (
                await service.latest_agent_event(
                    "run", solver_id, event_types={"solver_observation_started"}
                )
                is None
            )
        finally:
            await sup.close()
            await service.close()
    assert measurements[True] < measurements[False] / 2
