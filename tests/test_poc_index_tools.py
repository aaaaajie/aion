from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import httpx
import pytest

from tools.poc_runtime.index import PocIndex, build_index
from tools.poc_runtime.tools import PocInspectArguments, PocOutputArguments, PocRunArguments, PocSearchArguments, PocTools
from tools.http.engine import HttpInteractionEngine
from tools.http.manager import HttpProbeManager
from agent.state import StateService
from tools.system.policy import SystemToolError, WorkspacePolicy
from tests.resource_runtime import install_resource_runtime
from agent.subagents.policy import AgentPolicy
from agent.tooling import ToolRegistry
from agent.tooling import ToolExecutor


POC = """\
id: CVE-2024-1234
info:
  name: Demo login
  severity: high
rules:
  named_check:
    request:
      method: GET
      path: /login?next=%2F
      headers:
        Accept: text/plain
    expression: response.status == 500 && response.body.bcontains(b'error')
expression: named_check()
"""


def test_index_search_and_inspect_preserve_hash_and_reference_only(tmp_path: Path) -> None:
    source = tmp_path / "tscan"
    source.mkdir()
    (source / "demo.yml").write_text(POC, encoding="utf-8")
    db = tmp_path / "yak.db"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE yak_scripts (id INTEGER PRIMARY KEY, script_name TEXT, type TEXT, content TEXT, level TEXT)")
        connection.execute("INSERT INTO yak_scripts VALUES (1, 'demo', 'mitm', 'println(1)', 'low')")
    output = tmp_path / "index"
    manifest = build_index([("tscan", source), ("yak", db)], output)
    assert manifest["records"] == 2
    index = PocIndex(output)
    result = index.search("CVE-2024-1234", source="tscan")
    assert result["total"] == 1
    row = index.get(result["results"][0]["poc_ref"])
    assert row["sha256"]
    assert "named_check" in row["content"]
    yak = index.search("println", source="yak")["results"][0]
    assert yak["status"] == "reference_only"


def test_index_rejects_output_inside_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="outside"):
        build_index([("tscan", source)], source / "index")


class _Manager:
    def _error(self, error_type, code, message, *, detail=None):
        return SystemToolError(error_type=error_type, code=code, message=message, detail=detail)


def test_tools_expose_four_stable_entries_and_reject_reference_run(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yml").write_text(POC, encoding="utf-8")
    output = tmp_path / "index"
    build_index([("tscan", source)], output)
    tools = PocTools(output, _Manager(), "agent")
    assert {item.name for item in tools.tool_specs()} == {"system_poc_search", "system_poc_inspect", "system_poc_run", "system_poc_output"}
    search = asyncio.run(tools.search(PocSearchArguments(query="Demo")))
    ref = search["results"][0]["poc_ref"]
    inspected = asyncio.run(tools.inspect(PocInspectArguments(poc_ref=ref, target="http://example.test")))
    assert inspected["request_preview"]["target_url"] == "http://example.test/login?next=%2F"
    assert inspected["request_preview"]["headers"]["Accept"] == "text/plain"

    with pytest.raises(SystemToolError) as missing:
        asyncio.run(tools.inspect(PocInspectArguments(poc_ref="missing-ref")))
    assert missing.value.code == "poc_ref_not_found"


def test_reference_only_run_is_rejected_before_http_admission(tmp_path: Path) -> None:
    db = tmp_path / "yak.db"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE yak_scripts (id INTEGER PRIMARY KEY, script_name TEXT, type TEXT, content TEXT)")
        connection.execute("INSERT INTO yak_scripts VALUES (1, 'demo', 'yak', 'println(1)')")
    output = tmp_path / "index"
    build_index([("yak", db)], output)
    tools = PocTools(output, _Manager(), "agent")
    ref = tools._index().search("println")["results"][0]["poc_ref"]
    with pytest.raises(SystemToolError) as error:
        asyncio.run(tools.run(PocRunArguments(poc_ref=ref, target="http://example.test")))
    assert error.value.code == "poc_unsupported"


def test_poc_entries_are_discoverable_only_to_execute_roles(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yml").write_text(POC, encoding="utf-8")
    output = tmp_path / "index"
    build_index([("tscan", source)], output)
    provider = PocTools(output, _Manager(), "agent")
    names = {item.name for item in provider.tool_specs()}
    solver = {item["function"]["name"] for item in ToolRegistry([provider], allowed_tools=AgentPolicy("solver").allowed_tools).definitions()}
    worker = {item["function"]["name"] for item in ToolRegistry([provider], allowed_tools=AgentPolicy("worker").allowed_tools).definitions()}
    review = {item["function"]["name"] for item in ToolRegistry([provider], allowed_tools=AgentPolicy("worker", "review").allowed_tools).definitions()}
    chief = {item["function"]["name"] for item in ToolRegistry([provider], allowed_tools=AgentPolicy("chief").allowed_tools).definitions()}
    assert names <= solver
    assert names <= worker
    assert not (names & review)
    assert not (names & chief)


@pytest.mark.asyncio
async def test_compact_agent_catalog_finds_poc_schema_and_examples(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yml").write_text(POC, encoding="utf-8")
    output = tmp_path / "index"
    build_index([("tscan", source)], output)
    registry = ToolRegistry(
        [PocTools(output, _Manager(), "agent")],
        allowed_tools=AgentPolicy("solver").allowed_tools,
        compact=True,
    )
    call = {"id": "search", "function": {"name": "tool_search", "arguments": json.dumps({"name": "system_poc_run"})}}
    result = (await ToolExecutor(registry).execute([call]))[0].result
    assert result["ok"]
    assert result["data"]["tool"]["name"] == "system_poc_run"
    assert result["data"]["examples"]


@pytest.mark.asyncio
async def test_agent_entrypoint_runs_once_and_reads_persisted_response(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "demo.yml").write_text(POC, encoding="utf-8")
    output = tmp_path / "index"
    build_index([("tscan", source)], output)

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"error", headers={"Location": "/login"})

    service = StateService(tmp_path / "run" / "state.sqlite3", run_root=tmp_path)
    await service.create_run("run")
    agent = await service.register_agent("run", role="chief", initial_prompt="poc")
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(
        policy,
        service,
        "run",
        engine=HttpInteractionEngine(policy, transport=httpx.MockTransport(handler)),
    )
    await manager.initialize()
    pump = install_resource_runtime(manager, service, "run", root=tmp_path)
    try:
        tools = PocTools(output, manager, agent["agent_id"])
        ref = (await tools.search(PocSearchArguments(query="Demo")))["results"][0]["poc_ref"]
        run = await tools.run(PocRunArguments(poc_ref=ref, target="http://target.test", wait_seconds=5))
        result = await tools.output(PocOutputArguments(interaction_id=run["interaction_id"], wait_seconds=1))
        assert result["poc"]["status"] == "matched"
        assert result["poc"]["transport_status"] == "response"
        assert result["poc"]["sha256"]
    finally:
        await pump.close()
        await manager.finish_run()
        await service.close()
