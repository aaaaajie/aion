"""Real technical providers survive model sessions and have one cleanup owner."""

import asyncio
import json
import shutil
from pathlib import Path
import pytest
from agent.runner import AgentRunnerError
from agent.tooling import ToolExecutor, tool_error
from agent.state import AgentReportInput, WorkerTaskInput, WorkerUpdateInput
from tools.binary import BinaryTools
from tools.pentest import PentestTools
from tests.local_targets import LocalHttpTarget, LocalSshTarget
from tests.test_solver_lifecycle import harness, completion, tool


async def until(predicate):
    async with asyncio.timeout(5):
        while not await predicate():
            await asyncio.sleep(0.01)


async def status(service, agent_id, expected):
    return (await service.get_agent_runtime("run", agent_id))["agent"][
        "status"
    ] == expected


async def technical(registry, name, arguments):
    from uuid import uuid4

    result = (
        await ToolExecutor(registry).execute(
            [
                {
                    "id": uuid4().hex,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(arguments)},
                }
            ]
        )
    )[0].result
    return result


def local_process_fixture(registry):
    from tests.test_binary_sessions import FakeSandbox, _elf64

    provider = next(p for p in registry.providers if isinstance(p, BinaryTools))
    manager = provider._sessions
    manager.platform_name = "Linux"
    manager.machine_name = "x86_64"
    manager.sandbox = FakeSandbox()

    async def spawn(*argv, **kwargs):
        return await asyncio.create_subprocess_exec("/bin/cat", **kwargs)

    manager._process_factory = spawn
    _elf64(manager.root / "echo-cat")


@pytest.mark.asyncio
async def test_binary_tcp_ssh_survive_wait_compaction_and_recoverable_model_failure(
    tmp_path,
):
    sup = None

    async def solve(role, index, body):
        if index == 1:
            raise AgentRunnerError(
                "temporary fixture", code="fixture", recoverable=True
            )
        if index == 2:
            solver = next(a for a in sup._runners if a.startswith("solver_"))
            sup._runners[solver]._force_context_compaction = True
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        return completion("solver_wait")

    sup, s, p, c, chief = await harness(tmp_path, solve)
    writers = set()

    async def echo(reader, writer):
        writers.add(writer)
        try:
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            writers.discard(writer)

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    http_target = LocalHttpTarget()
    ssh_target = LocalSshTarget()
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(s, solver, "waiting"))
        registry = sup._registries[solver]
        from tests.resource_runtime import install_resource_runtime

        http_manager = sup._http_interactions
        install_resource_runtime(http_manager, s, "run", root=tmp_path)
        login = await technical(
            registry,
            "system_http_request",
            {
                "method": "POST",
                "url": http_target.url + "/login",
                "session_id": "retained",
                "update_session": True,
                "wait_seconds": 2,
            },
        )
        assert login["ok"], login
        local_process_fixture(registry)
        process = await technical(
            registry,
            "pwn_process_open",
            {"file_path": "echo-cat", "startup_wait_seconds": 0.0},
        )
        tcp = await technical(
            registry,
            "pwn_tcp_open",
            {"host": "127.0.0.1", "port": server.sockets[0].getsockname()[1]},
        )
        ssh = next(p for p in registry.providers if isinstance(p, PentestTools))._ssh
        opened = await technical(
            registry,
            "pentest_ssh_open",
            {
                "host": "127.0.0.1",
                "port": ssh_target.port,
                "username": "player",
                "password": "fixture",
            },
        )
        for result in (process, tcp, opened):
            assert result["ok"], result
        await s.publish_control_report(
            "run",
            sender_id=chief,
            recipient_id=solver,
            unique_code="a",
            report_type="hint",
            status="received",
            payload={"hint": "new event"},
        )

        async def done():
            return c["solver"] >= 4 and await status(s, solver, "waiting")

        await until(done)
        assert sup._registries[solver] is registry
        private = await technical(
            registry,
            "system_http_request",
            {
                "url": http_target.url + "/private",
                "session_id": "retained",
                "wait_seconds": 2,
            },
        )
        assert private["ok"] and http_target.cookies == ["sid=retained"], private
        events = await s.list_agent_events("run", solver, limit=500)
        assert any(e["event_type"] == "agent_model_recovery" for e in events)
        assert any(e["event_type"] == "context_compacted" for e in events)
        for result in (process, tcp):
            io = await technical(
                registry,
                "pwn_session_io",
                {
                    "session_id": result["data"]["session_id"],
                    "send_text": "still live\n",
                    "recv_until_text": "\n",
                    "timeout": 1.0,
                },
            )
            assert io["ok"] and "still live" in io["data"]["output_preview"], io
        executed = await technical(
            registry,
            "pentest_ssh_exec",
            {"session_id": opened["data"]["session_id"], "command": "id"},
        )
        assert executed["ok"], executed
        await sup.pause_challenges(chief, ["a"], reason="test cleanup")
        assert not p.running and not ssh._sessions
        assert ssh_target.commands == [b"id"]
        assert not http_manager._session_path(solver, "retained").exists()
        assert not any(key[0] == solver for key in http_manager.engine._clients)
        assert not next(
            x for x in registry.providers if isinstance(x, BinaryTools)
        )._sessions._sessions
        resumed = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        assert resumed == solver
        invalid = await technical(
            sup._registries[solver],
            "pwn_session_io",
            {"session_id": tcp["data"]["session_id"], "timeout": 0.01},
        )
        assert invalid["error"]["code"] == "session_invalidated"
    finally:
        await sup.close()
        await s.close()
        for writer in list(writers):
            writer.close()
        http_target.close()
        ssh_target.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["retain", "close", "deadline", "fatal"])
async def test_terminal_boundaries_clean_processes_and_confirm_capacity(
    tmp_path, action
):
    fail = False

    def solve(*_):
        if fail:
            raise AgentRunnerError("fixture fatal", code="fixture", recoverable=False)
        return completion("solver_wait")

    sup, s, p, c, chief = await harness(tmp_path, solve)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(s, solver, "waiting"))
        registry = sup._registries[solver]
        local_process_fixture(registry)
        opened = await technical(
            registry,
            "pwn_process_open",
            {"file_path": "echo-cat", "startup_wait_seconds": 0.0},
        )
        assert opened["ok"], opened
        provider = next(x for x in registry.providers if isinstance(x, BinaryTools))
        process = next(iter(provider._sessions._sessions.values())).process
        if action == "retain":
            await sup.pause_challenges(
                chief, ["a"], reason="retain", release_container=False
            )
            assert p.running
            assert (await s.list_challenges("run"))[0]["slot_occupied"]
        elif action == "close":
            result = await sup.close_challenges(chief, ["a"], reason="done")
            assert result["data"]["results"][0]["release"]["released"], result
            assert not p.running
        else:
            if action == "deadline":
                from datetime import timedelta
                from agent.state.models import RunRecord

                async with s.db.sessions.begin() as session:
                    run = await session.get(RunRecord, "run")
                    run.deadline_at = s.clock() - timedelta(seconds=1)
            else:
                fail = True
            await s.publish_control_report(
                "run",
                sender_id=chief,
                recipient_id=solver,
                unique_code="a",
                report_type="hint",
                status="received",
                payload={"wake": action},
            )
            await asyncio.wait_for(
                asyncio.gather(sup._tasks[solver], return_exceptions=True), 5
            )
            if action == "deadline":
                await asyncio.wait_for(
                    asyncio.gather(sup._tasks[chief], return_exceptions=True), 5
                )
            assert not p.running
        assert process.returncode is not None
        assert solver not in sup._registries
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_new_supervisor_recovers_original_solver_and_interrupts_queued_worker_once(
    tmp_path,
):
    sup, s, p, c, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
    await until(lambda: status(s, solver, "waiting"))
    # Abrupt cancellation leaves unfinished durable task state, as a process loss does.
    tasks = list(sup._tasks.values())
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    w = (
        await sup.delegate_workers(
            solver,
            [WorkerTaskInput(task_key="unfinished", objective="queued at crash")],
        )
    )["data"]["admissions"][0]
    context = sup._state_context(w["agent_id"])
    await s.report_worker(
        "run",
        w["agent_id"],
        context,
        WorkerUpdateInput(summary="unacknowledged"),
        terminal=False,
    )
    delivery = await s.consume_reports("run", sup._state_context(solver))
    await s.update_agent_memory(
        "run", solver, "surviving memory", summarized_through_sequence=0
    )
    # A separate Runtime process exits without cleanup, leaving a real target process.
    import sys, psutil

    crash_code = """
import asyncio, os, sys
from pathlib import Path
from agent.state import StateService
async def main():
    service = StateService(sys.argv[1])
    await service.initialize()
    process = await asyncio.create_subprocess_exec(sys.executable, '-c', 'import time; time.sleep(60)', start_new_session=True, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    await service.track_agent_process('run', sys.argv[2], process.pid)
    Path(sys.argv[3]).write_text(str(process.pid))
    os._exit(0)
asyncio.run(main())
"""
    pid_file = tmp_path / "orphan.pid"
    crashed = await asyncio.create_subprocess_exec(
        sys.executable, "-c", crash_code, str(s.db.path), solver, str(pid_file)
    )
    assert await crashed.wait() == 0
    orphan_pid = int(pid_file.read_text())
    assert psutil.pid_exists(orphan_pid)
    sup._release_run_ownership()  # The OS releases this lock when the old process exits.
    await sup._close_model_http_client()
    await s.close()
    received = asyncio.Event()
    release = asyncio.Event()

    async def recovered_model(role, index, body):
        assert "surviving memory" in json.dumps(body)
        assert delivery["delivery_id"] in json.dumps(body)
        received.set()
        await release.wait()
        return completion("solver_wait")

    new, ns, np, nc, nchief = await harness(
        tmp_path, recovered_model, platform=p, resume=True
    )
    try:
        await asyncio.wait_for(received.wait(), 3)
        assert nchief == chief
        agents = (await ns.get_overview("run"))["agents"]
        assert [a["agent_id"] for a in agents if a["role"] == "solver"] == [solver]
        assert (
            next(a for a in agents if a["agent_id"] == w["agent_id"])["status"]
            == "interrupted"
        )
        assert w["agent_id"] not in new._tasks
        assert not psutil.pid_exists(orphan_pid)
        assert await ns.interrupt_workers("run") == 0
        assert (await ns.get_agent_runtime("run", solver))["agent"]["pending_delivery"][
            "delivery_id"
        ] == delivery["delivery_id"]
        release.set()
    finally:
        release.set()
        await new.close()
        await ns.close()


@pytest.mark.asyncio
async def test_cleanup_failure_is_persisted_other_resources_close_and_retry_succeeds(
    tmp_path,
):
    sup, s, p, c, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))

    class Fault:
        calls = 0

        async def close(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("fixture close failed")

    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(s, solver, "waiting"))
        registry = sup._registries[solver]
        fault = Fault()
        registry.providers.append(fault)
        local_process_fixture(registry)
        assert (
            await technical(
                registry,
                "pwn_process_open",
                {"file_path": "echo-cat", "startup_wait_seconds": 0.0},
            )
        )["ok"]
        provider = next(p for p in registry.providers if isinstance(p, BinaryTools))
        process = next(iter(provider._sessions._sessions.values())).process
        await sup.pause_challenges(chief, ["a"], reason="cleanup fault")
        assert process.returncode is not None
        events = await s.list_agent_events("run", solver, limit=100)
        assert any(
            e["event_type"] == "agent_resource_cleanup_failed"
            and e["payload"]["failures"][0]["resource"] == "Fault"
            for e in events
        )
        await sup._finish_agent_resources(solver)
        assert solver not in sup._registries and fault.calls >= 2
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_worker_budget_starts_after_queue_and_timeout_preserves_solver(tmp_path):
    started = asyncio.Event()

    async def model(role, index, body):
        if role == "solver":
            return completion("solver_wait")
        started.set()
        await asyncio.Event().wait()

    sup, s, p, c, chief = await harness(tmp_path, model)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        w = (
            await sup.delegate_workers(
                solver,
                [
                    WorkerTaskInput(
                        task_key="timed", objective="wait", timeout_seconds=1
                    )
                ],
            )
        )["data"]["admissions"][0]
        await asyncio.sleep(1.05)
        assert c["worker"] == 0
        await sup.launch_worker(w["agent_id"])
        await asyncio.wait_for(started.wait(), 0.5)
        assert (await s.get_agent_runtime("run", w["agent_id"]))["agent"][
            "status"
        ] == "running"
        await asyncio.wait_for(sup._tasks[w["agent_id"]], 2)
        assert (await s.get_agent_runtime("run", w["agent_id"]))["agent"][
            "status"
        ] == "interrupted"
        assert not sup._tasks[solver].done() and p.running
        assert w["agent_id"] not in sup._registries
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_batch_pause_release_failure_retains_capacity_and_close_stays_closed(
    tmp_path, monkeypatch,
):
    from tests.test_solver_lifecycle import Platform

    class ReleaseFailure(Platform):
        async def dispatch(self, name, args):
            if name == "benchmark_close_challenge":
                self.close_calls += 1
                return tool_error("execution", "fixture_unavailable", "fixture release failed")
            return await super().dispatch(name, args)

    sup, s, p, c, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait"), platform=ReleaseFailure()
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(s, solver, "waiting"))
        transition = s.transition_agent
        late_waits = []

        async def pause_with_late_controller_wait(run_id, agent_id, new_status, **kwargs):
            result = await transition(run_id, agent_id, new_status, **kwargs)
            if agent_id == solver and new_status == "paused":
                # Force the full-suite race: a session tail reaches wait after
                # the owner's pause transaction commits, before task cancellation.
                late_waits.append(await s.record_controller_wait(run_id, agent_id, "late session tail"))
            return result

        monkeypatch.setattr(s, "transition_agent", pause_with_late_controller_wait)
        paused = (
            await tool(
                sup,
                chief,
                "chief_pause_challenges",
                {"unique_codes": ["a", "missing"], "reason": "batch fixture"},
            )
        ).result
        assert paused["ok"], paused
        results = paused["data"]["results"]
        assert results[0]["status"] == "paused" and not results[1]["ok"]
        assert not results[0]["ok"] and not results[0]["release"]["released"]
        assert (await s.list_challenges("run"))[0]["slot_occupied"]
        assert await status(s, solver, "paused")
        assert late_waits and all(item["status"] == "paused" for item in late_waits)
        await sup.close_challenges(chief, ["a"], reason="permanent")
        await sup.refresh_challenges(chief)
        assert (await s.list_challenges("run"))[0]["work_status"] == "closed"
        rejected = await sup.create_solver(chief, "a")
        assert not rejected["ok"]
    finally:
        # The fixture allows cleanup after verifying occupied capacity.
        p.dispatch = Platform.dispatch.__get__(p, Platform)
        await sup.close()
        await s.close()
