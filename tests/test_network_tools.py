"""Tests for persistent bridge-backed network discovery tools."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent.state import StateService
from agent.subagents.policy import AgentPolicy
from tools.network import NetworkDiscoveryManager, NetworkTools
from tools.network.manager import default_binary_path
from tools.system.policy import SystemToolError, WorkspacePolicy


_FAKE_BRIDGE = r'''#!/usr/bin/env python3
import json
import sys

start = json.loads(sys.stdin.readline())
task_id = start["task_id"]
print(json.dumps({"type":"ready","protocol_version":"1","scanner_version":"test-fscan","task_id":task_id}), flush=True)
print(json.dumps({"type":"progress","tasks_total":3,"tasks_completed":1,"paused":False}), flush=True)
results = [
    {"time":"2026-01-01T00:00:00Z","type":"HOST","target":"127.0.0.1","status":"alive","details":{"host":"127.0.0.1"}},
    {"time":"2026-01-01T00:00:00Z","type":"PORT","target":"127.0.0.1:80","status":"open","details":{"host":"127.0.0.1","port":80}},
    {"time":"2026-01-01T00:00:00Z","type":"SERVICE","target":"127.0.0.1:80","status":"identified","details":{"host":"127.0.0.1","port":80,"service":"http","is_web":True,"title":"Hello","url":"http://127.0.0.1:80","plugin":"webtitle"}},
]
for result in results:
    print(json.dumps({"type":"result","result":result}), flush=True)
if __MODE__ == "complete":
    print(json.dumps({"type":"finished","status":"completed","stats":{"tasks_total":3,"tasks_completed":3}}), flush=True)
    raise SystemExit(0)
if __MODE__ == "eof":
    raise SystemExit(0)
for line in sys.stdin:
    command = json.loads(line)
    if command["type"] == "pause":
        print(json.dumps({"type":"progress","tasks_total":3,"tasks_completed":1,"paused":True}), flush=True)
    elif command["type"] == "resume":
        print(json.dumps({"type":"progress","tasks_total":3,"tasks_completed":1,"paused":False}), flush=True)
    elif command["type"] == "stop":
        print(json.dumps({"type":"finished","status":"stopped","stats":{"tasks_total":3,"tasks_completed":1}}), flush=True)
        raise SystemExit(0)
'''


def _fake_bridge(
    root: Path, *, complete: bool = True, unexpected_eof: bool = False
) -> Path:
    path = root / "fake-fscan-bridge"
    path.write_text(
        _FAKE_BRIDGE.replace(
            "__MODE__",
            repr("eof" if unexpected_eof else ("complete" if complete else "wait")),
        ),
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


async def _harness(
    root: Path,
    binary_path: Path,
    *,
    admission=None,
    resource_guard=None,
) -> tuple[StateService, NetworkDiscoveryManager, str]:
    run_root = root / "runs"
    service = StateService(run_root / "run-1" / "state.sqlite3", run_root=run_root)
    await service.create_run("run-1")
    agent = await service.register_agent(
        "run-1", role="chief", initial_prompt="network test"
    )
    manager = NetworkDiscoveryManager(
        WorkspacePolicy(root),
        service,
        "run-1",
        binary_path=binary_path,
        admission_callback=admission,
        resource_guard=resource_guard,
    )
    await manager.initialize()
    return service, manager, agent["agent_id"]


@pytest.mark.asyncio
async def test_discovery_uses_network_tasks_and_paginates(tmp_path: Path) -> None:
    service, manager, agent_id = await _harness(tmp_path, _fake_bridge(tmp_path))
    result = await manager.start_discovery(
        agent_id,
        targets="127.0.0.1",
        ports="80",
        ping=False,
        scan_intent="initial_surface",
        wait_seconds=None,
    )
    assert result["status"] == "completed"
    assert result["recommended_wait_seconds"] == 0
    assert result["scan_intent"] == "initial_surface"
    assert result["scanner_version"] == "test-fscan"
    assert result["bridge_protocol_version"] == "1"
    assert result["hosts_alive"] == 1
    assert result["open_ports"] == 1
    assert result["services"] == 1
    assert result["web_ports"] == 1
    assert len(result["results"]) == 3

    first = await manager.output(
        agent_id, task_id=result["task_id"], limit=1, wait_seconds=0
    )
    repeated = await manager.output(
        agent_id, task_id=result["task_id"], limit=1, wait_seconds=0
    )
    assert first["results"] == repeated["results"]
    assert first["next_cursor"] == repeated["next_cursor"]
    filtered = await manager.output(
        agent_id,
        task_id=result["task_id"],
        filters={"service": "http"},
        wait_seconds=0,
    )
    assert len(filtered["results"]) == 1
    assert await service.list_shell_tasks("run-1") == []
    assert len(await service.list_network_tasks("run-1")) == 1
    results_path = manager._task_dir(agent_id, result["task_id"]) / "results.jsonl"
    with results_path.open("ab") as output:
        output.write(b'{"partial":')
    repaired = NetworkDiscoveryManager(
        WorkspacePolicy(tmp_path),
        service,
        "run-1",
        binary_path=_fake_bridge(tmp_path),
    )
    await repaired.initialize()
    assert results_path.read_bytes().endswith(b"\n")
    assert len(
        (
            await repaired.output(
                agent_id, task_id=result["task_id"], wait_seconds=0
            )
        )["results"]
    ) == 3
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_running_stop_cleanup_and_ownership_without_sleep(tmp_path: Path) -> None:
    service, manager, agent_id = await _harness(
        tmp_path, _fake_bridge(tmp_path, complete=False)
    )
    result = await manager.start_discovery(
        agent_id, targets="127.0.0.1", ports="80", ping=False, wait_seconds=0
    )
    assert result["status"] == "running"
    with pytest.raises(SystemToolError) as running_cleanup:
        await manager.cleanup(agent_id, result["task_id"])
    assert running_cleanup.value.code == "task_still_running"

    second = await service.register_agent("run-1", role="chief", initial_prompt="second")
    with pytest.raises(SystemToolError) as denied:
        await manager.output(
            second["agent_id"], task_id=result["task_id"], wait_seconds=0
        )
    assert denied.value.code == "task_not_found"

    current = result
    while len(current["results"]) < 3:
        current = await manager.output(
            agent_id,
            task_id=result["task_id"],
            cursor=0,
            wait_seconds=1,
        )
    waiter = asyncio.create_task(
        manager.output(
            agent_id,
            task_id=result["task_id"],
            cursor=current["next_cursor"],
            wait_seconds=5,
        )
    )
    await asyncio.sleep(0)
    stopped = await manager.stop(agent_id, result["task_id"])
    assert stopped["status"] == "stopped"
    assert (await asyncio.wait_for(waiter, timeout=1))["status"] in {
        "running",
        "stopped",
    }
    page = await manager.output(
        agent_id, task_id=result["task_id"], wait_seconds=0
    )
    assert len(page["results"]) == 3
    assert (await manager.cleanup(agent_id, result["task_id"]))["cleaned"] is True
    assert (await manager.cleanup(agent_id, result["task_id"]))["already_cleaned"] is True
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_queued_output_stop_cleanup_and_recovery_are_persistent(tmp_path: Path) -> None:
    async def queued(_work_id: str) -> dict:
        return {"ok": False, "status": "queued", "reason": "cpu_limit"}

    service, manager, agent_id = await _harness(
        tmp_path, _fake_bridge(tmp_path), admission=queued
    )
    first = await manager.start_discovery(
        agent_id, targets="127.0.0.1", ports="80", wait_seconds=0
    )
    assert first["status"] == "queued"
    assert (await manager.output(
        agent_id, task_id=first["task_id"], wait_seconds=0
    ))["status"] == "queued"
    assert (await manager.stop(agent_id, first["task_id"]))["status"] == "stopped"
    assert (await manager.cleanup(agent_id, first["task_id"]))["cleaned"] is True

    second = await manager.start_discovery(
        agent_id, targets="127.0.0.1", ports="80", wait_seconds=0
    )
    resumed = NetworkDiscoveryManager(
        WorkspacePolicy(tmp_path),
        service,
        "run-1",
        binary_path=_fake_bridge(tmp_path),
    )
    await resumed.initialize(resume=True)
    page = await resumed.output(
        agent_id, task_id=second["task_id"], wait_seconds=0
    )
    assert page["status"] == "interrupted"
    assert page["error_code"] == "runtime_recovered"
    await resumed.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_runtime_resource_pause_resume_and_stop_do_not_deadlock(tmp_path: Path) -> None:
    allowed = False

    async def guard(_work_id: str) -> dict:
        return {
            "ok": allowed,
            "reason": None if allowed else "cpu_limit",
            "retry_after_seconds": 0.01,
        }

    service, manager, agent_id = await _harness(
        tmp_path,
        _fake_bridge(tmp_path, complete=False),
        resource_guard=guard,
    )
    result = await manager.start_discovery(
        agent_id, targets="127.0.0.1", ports="80", wait_seconds=0
    )
    for _ in range(100):
        page = await manager.output(
            agent_id, task_id=result["task_id"], wait_seconds=0
        )
        if page["resource_status"] == "waiting":
            break
        await asyncio.sleep(0.01)
    assert page["resource_status"] == "waiting"
    allowed = True
    for _ in range(150):
        page = await manager.output(
            agent_id, task_id=result["task_id"], wait_seconds=0
        )
        if page["resource_status"] == "running":
            break
        await asyncio.sleep(0.01)
    assert page["resource_status"] == "running"
    assert (await manager.stop(agent_id, result["task_id"]))["status"] == "stopped"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_pause_interrupts_without_replay_and_unexpected_eof_fails(
    tmp_path: Path,
) -> None:
    service, manager, agent_id = await _harness(
        tmp_path, _fake_bridge(tmp_path, complete=False)
    )
    running = await manager.start_discovery(
        agent_id, targets="127.0.0.1", ports="80", wait_seconds=0
    )
    await manager.pause_run()
    interrupted = await manager.output(
        agent_id, task_id=running["task_id"], wait_seconds=0
    )
    assert interrupted["status"] == "interrupted"
    assert interrupted["summary"]["interrupted"] is True
    await service.close()

    second_root = tmp_path / "unexpected-eof"
    second_root.mkdir()
    service, manager, agent_id = await _harness(
        second_root, _fake_bridge(second_root, unexpected_eof=True)
    )
    failed = await manager.start_discovery(
        agent_id,
        targets="127.0.0.1",
        ports="80",
        wait_seconds=None,
    )
    assert failed["status"] == "failed"
    assert failed["error_code"] == "bridge_unexpected_eof"
    await manager.finish_run()
    await service.close()


@pytest.mark.asyncio
async def test_real_bridge_loopback_smoke(tmp_path: Path, unused_tcp_port: int) -> None:
    binary = default_binary_path()
    if not binary.is_file():
        pytest.skip("aion-fscan bridge is not built")
    service, manager, agent_id = await _harness(tmp_path, binary)
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.wait_for(reader.read(4096), timeout=1)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 41\r\n\r\n"
                b"<html><title>AION Loopback</title></html>"
            )
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", unused_tcp_port)
    try:
        result = await manager.start_discovery(
            agent_id,
            targets="127.0.0.1",
            ports=str(unused_tcp_port),
            ping=False,
            web_mark=False,
            wait_seconds=None,
        )
        assert result["status"] == "completed"
        assert result["open_ports"] == 1
        assert not any(
            item.get("plugin") == "webtitle" for item in result["results"]
        )
        assert result["scanner_version"]
        marked = await manager.start_discovery(
            agent_id,
            targets="127.0.0.1",
            ports=str(unused_tcp_port),
            ping=False,
            web_mark=True,
            wait_seconds=None,
        )
        assert marked["status"] == "completed"
        assert marked["web_ports"] >= 1
        assert any(item.get("plugin") == "webtitle" for item in marked["results"]), marked[
            "results"
        ]
    finally:
        server.close()
        await server.wait_closed()
    await manager.finish_run()
    await service.close()


def test_tool_definitions_are_execution_only_and_prompted() -> None:
    definitions = NetworkTools.tool_definitions()
    names = {item["function"]["name"] for item in definitions}
    assert names <= AgentPolicy("execution").allowed_tools
    assert names.isdisjoint(AgentPolicy("chief").allowed_tools)
    assert names.isdisjoint(AgentPolicy("challenge").allowed_tools)
    prompt = (
        Path(__file__).resolve().parents[1] / "agent" / "prompts" / "execution_system.txt"
    ).read_text(encoding="utf-8")
    assert "system_network_discovery" in prompt
    assert "system_network_output" in prompt
    discovery_schema = next(
        item["function"]["parameters"]
        for item in definitions
        if item["function"]["name"] == "system_network_discovery"
    )
    assert "maximum" not in discovery_schema["properties"]["concurrency"].get(
        "anyOf", [{}]
    )[0]
    output_schema = next(
        item["function"]["parameters"]
        for item in definitions
        if item["function"]["name"] == "system_network_output"
    )
    assert output_schema["properties"]["wait_seconds"]["default"] == 20.0
