"""Real OS regressions for orphan pipes, cancellation and bounded cleanup."""

import asyncio
import json
import os
import shlex
import signal
import sys
from pathlib import Path

import psutil
import pytest

from tests.test_system_tools import make_tools


def alive(pid):
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def orphan_command(*, detached=False, redirect=False, parent_wait=False):
    # Handshake ensures TERM is ignored before the shell exits or is cancelled.
    child = "trap '' TERM; printf ready > ready; sleep 60"
    launcher = "setsid " if detached else "nohup "
    redirects = " > child.log 2>&1" if redirect else ""
    return (
        f"{launcher}bash -c {shlex.quote(child)}{redirects} & "
        "printf '%s' $! > child.pid; "
        "while [ ! -f ready ]; do sleep 0.01; done; printf parent-exited; "
        + ("wait" if parent_wait else "exit 0")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("redirect", [False, True])
async def test_parent_exit_reaps_term_ignoring_child_with_inherited_pipes(
    make_tools, redirect
):
    harness = make_tools()
    async with harness as tools:
        started = asyncio.get_running_loop().time()
        result = await asyncio.wait_for(
            tools.shell(orphan_command(redirect=redirect), timeout=5), 10
        )
        assert result["ok"], result
        data = result["data"]
        assert data["status"] == "completed", data
        assert data["exit_code"] == 0
        assert "parent-exited" in data["output"]
        assert data["cleanup"]["resources_released"] is True
        pid = int(
            (
                harness.manager.agent_work_root(harness.agent_id) / "child.pid"
            ).read_text()
        )
        assert not alive(pid)
        assert asyncio.get_running_loop().time() - started < 8.0
        events = await harness.service.list_agent_events(
            harness.run_id, harness.agent_id, limit=100
        )
        assert sum(e["event_type"] == "shell_task_finished" for e in events) == 1


@pytest.mark.asyncio
@pytest.mark.skipif(
    sys.platform != "linux", reason="setsid adoption uses Linux subreaper"
)
async def test_linux_independent_session_is_owned_after_parent_exit(make_tools):
    harness = make_tools()
    async with harness as tools:
        result = await asyncio.wait_for(
            tools.shell(orphan_command(detached=True), timeout=5), 10
        )
        assert result["ok"] and result["data"]["cleanup"]["resources_released"], result
        pid = int(
            (
                harness.manager.agent_work_root(harness.agent_id) / "child.pid"
            ).read_text()
        )
        assert not alive(pid)


@pytest.mark.asyncio
async def test_timeout_returns_partial_output_and_next_command_runs(make_tools):
    async with make_tools() as tools:
        result = await asyncio.wait_for(
            tools.shell(orphan_command(parent_wait=True), timeout=1), 6
        )
        assert result["data"]["status"] == "timeout", result
        assert result["data"]["timed_out"] is True
        assert result["data"]["cleanup"]["resources_released"] is True
        assert "parent-exited" in result["data"]["output"]
        following = await tools.shell("printf following-command")
        assert following["data"]["output"] == "following-command"


@pytest.mark.asyncio
async def test_concurrent_stop_is_bounded_and_does_not_kill_other_task(make_tools):
    harness = make_tools()
    async with harness as tools:
        other = await tools.task_start('sleep 60')
        blocked = await tools.task_start(orphan_command(parent_wait=True))
        task_id = blocked["data"]["task_id"]
        await asyncio.sleep(0.1)
        stopped = await asyncio.wait_for(
            asyncio.gather(*(tools.task_stop(task_id) for _ in range(5))), 6
        )
        assert all(r["data"]["status"] == "stopped" for r in stopped), stopped
        assert (await tools.task_output(other["data"]["task_id"]))["data"][
            "status"
        ] == "running"
        events = await harness.service.list_agent_events(
            harness.run_id, harness.agent_id, limit=100
        )
        assert (
            sum(
                e["event_type"] == "shell_task_finished"
                and e["payload"]["task_id"] == task_id
                for e in events
            )
            == 1
        )


@pytest.mark.asyncio
async def test_cancel_during_persistence_never_activates_command(
    make_tools, monkeypatch
):
    harness = make_tools()
    async with harness as tools:
        entered = asyncio.Event()

        async def blocked(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(harness.service, "create_shell_task", blocked)
        before = {p.pid for p in psutil.Process().children(recursive=True)}
        call = asyncio.create_task(tools.shell("touch should-not-exist; sleep 60"))
        await asyncio.wait_for(entered.wait(), 3)
        call.cancel()
        await asyncio.wait_for(asyncio.gather(call, return_exceptions=True), 5)
        assert not (
            harness.manager.agent_work_root(harness.agent_id) / "should-not-exist"
        ).exists()
        assert not [
            p.pid
            for p in psutil.Process().children(recursive=True)
            if p.pid not in before and alive(p.pid)
        ]


@pytest.mark.asyncio
async def test_closed_admission_and_paused_state_reject_new_shell(make_tools):
    harness = make_tools()
    async with harness as tools:
        harness.manager.close_admission(harness.agent_id)
        assert (await tools.shell("printf bad"))["error"]["code"] == "agent_inactive"
        harness.manager.open_admission(harness.agent_id)
        await harness.service.transition_agent(
            harness.run_id, harness.agent_id, "paused"
        )
        assert (await tools.shell("printf bad"))["error"]["code"] == "agent_inactive"


@pytest.mark.asyncio
async def test_owner_dies_with_runtime_control_pipe(make_tools):
    harness = make_tools()
    async with harness as tools:
        result = await tools.task_start(orphan_command(parent_wait=True))
        live = harness.manager._live[result["data"]["task_id"]]
        await asyncio.sleep(0.1)
        live.process.stdin.close()
        await asyncio.wait_for(live.done.wait(), 5)
        assert live.cleanup["resources_released"] is True
        assert not alive(live.process.pid)


@pytest.mark.asyncio
async def test_output_write_failure_preserves_partial_output_and_reaps_command(
    make_tools, monkeypatch
):
    import resource

    original = asyncio.create_subprocess_exec

    async def limited(*args, **kwargs):
        kwargs["preexec_fn"] = lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (4, 4))
        return await original(*args, **kwargs)

    async with make_tools() as tools:
        monkeypatch.setattr(asyncio, "create_subprocess_exec", limited)
        result = await asyncio.wait_for(
            tools.shell("printf 123456789; sleep 60", timeout=10), 12
        )
        assert result["data"]["status"] == "failed", result
        assert result["data"]["output"] == "1234"
        assert result["data"]["output_incomplete"]
        assert result["data"]["cleanup"]["resources_released"]
        monkeypatch.setattr(asyncio, "create_subprocess_exec", original)
        assert (await tools.shell("printf recovered"))["data"]["output"] == "recovered"


@pytest.mark.asyncio
async def test_terminal_persistence_failure_can_be_retried_during_cleanup(
    make_tools, monkeypatch
):
    harness = make_tools()
    async with harness as tools:
        original = harness.service.finish_shell_task
        attempts = 0

        async def fail_once(*args, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("fixture database write failure")
            return await original(*args, **kwargs)

        monkeypatch.setattr(harness.service, "finish_shell_task", fail_once)
        result = await tools.shell("printf persisted-on-retry")
        assert result["error"]["code"] == "shell_task_persistence_failed"
        assert harness.manager._live
        await harness.manager.finish_agent(harness.agent_id)
        assert not harness.manager._live
        events = await harness.service.list_agent_events(
            harness.run_id, harness.agent_id, limit=100
        )
        assert sum(e["event_type"] == "shell_task_finished" for e in events) == 1


@pytest.mark.asyncio
async def test_cancel_during_spawn_closes_unactivated_owner(make_tools, monkeypatch):
    original = asyncio.create_subprocess_exec
    entered, release = asyncio.Event(), asyncio.Event()
    spawned = []

    async def delayed(*args, **kwargs):
        process = await original(*args, **kwargs)
        spawned.append(process)
        entered.set()
        await release.wait()
        return process

    harness = make_tools()
    async with harness as tools:
        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
        call = asyncio.create_task(tools.shell("touch should-not-execute"))
        await asyncio.wait_for(entered.wait(), 3)
        call.cancel()
        await asyncio.gather(call, return_exceptions=True)
        release.set()
        await harness.manager.finish_run()
        await asyncio.wait_for(spawned[0].wait(), 2)
        assert not alive(spawned[0].pid)


@pytest.mark.asyncio
async def test_unresponsive_owner_is_forced_down_within_stop_budget(make_tools):
    harness = make_tools()
    async with harness as tools:
        result = await tools.task_start('printf ready; sleep 60')
        live = harness.manager._live[result["data"]["task_id"]]
        await asyncio.sleep(0.1)
        os.kill(live.process.pid, signal.SIGSTOP)
        started = asyncio.get_running_loop().time()
        stopped = await asyncio.wait_for(tools.task_stop(live.task_id), 5.5)
        assert asyncio.get_running_loop().time() - started < 5.3
        assert stopped["data"]["cleanup"]["resources_released"], stopped
        assert not alive(live.process.pid)


@pytest.mark.asyncio
async def test_missing_owner_ack_is_retained_as_cleanup_failure(make_tools):
    harness = make_tools()
    async with harness as tools:
        result = await tools.task_start('printf ready > ready; exec sleep 60')
        live = harness.manager._live[result["data"]["task_id"]]
        ready = harness.manager.agent_work_root(harness.agent_id) / "ready"
        async with asyncio.timeout(5):
            while not ready.exists():
                await asyncio.sleep(0.02)
        children = psutil.Process(live.process.pid).children(recursive=True)
        try:
            live.process.kill()
            await asyncio.wait_for(live.done.wait(), 2)
            assert live.cleanup["resources_released"] is False
            assert live.cleanup["failure"]["cleanup_error"] == "shell_owner_lost"
            assert (await tools.task_stop(live.task_id))["error"][
                "code"
            ] == "shell_owner_lost"
            assert (await tools.shell("printf forbidden"))["error"][
                "code"
            ] == "agent_inactive"
            row = await harness.service.get_shell_task(
                harness.run_id, harness.agent_id, live.task_id
            )
            assert row["cleanup"]["resources_released"] is False
            assert live.task_id in harness.manager._live
        finally:
            # The fixture knows the exact descendants; production must retain
            # uncertainty when an owner dies before confirming their cleanup.
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            await asyncio.to_thread(psutil.wait_procs, children, timeout=2)
            harness.manager._live.pop(live.task_id, None)


@pytest.mark.asyncio
async def test_confirmed_owner_slow_exit_preserves_result_and_reaps_original_identity(
    make_tools, monkeypatch, tmp_path
):
    from agent import process_resources

    # Run the real owner through its cleanup acknowledgement, then hold Python
    # shutdown indefinitely so the 0.2-second exit wait deterministically expires.
    wrapper = tmp_path / "slow_owner.py"
    wrapper.write_text(
        "import atexit, runpy, signal, sys, time\n"
        "def slow_exit():\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    time.sleep(60)\n"
        "atexit.register(slow_exit)\n"
        "owner = sys.argv.pop(1)\n"
        "runpy.run_path(owner, run_name='__main__')\n"
    )
    original_spawn = asyncio.create_subprocess_exec
    original_terminate = process_resources.terminate_recorded_process
    owners, recoveries = [], []

    async def slow_owner(*args, **kwargs):
        process = await original_spawn(*args[:2], str(wrapper), *args[2:], **kwargs)
        owners.append((process, psutil.Process(process.pid).create_time()))
        return process

    async def record_recovery(record, **kwargs):
        recoveries.append((record, kwargs))
        return await original_terminate(record, **kwargs)

    harness = make_tools()
    async with harness as tools:
        with monkeypatch.context() as patch:
            patch.setattr(asyncio, 'create_subprocess_exec', slow_owner)
            patch.setattr(process_resources, 'terminate_recorded_process', record_recovery)
            result = await asyncio.wait_for(tools.shell('printf confirmed-output'), 6)
        data = result['data']
        assert data['status'] == 'completed', result
        assert data['exit_code'] == 0
        assert data['output'] == 'confirmed-output'
        assert data['output_incomplete'] is False
        assert data['cleanup']['resources_released'] is True
        assert data['cleanup']['failure'] is None
        assert not data['truncated']
        assert len(owners) == len(recoveries) == 1
        process, created_at = owners[0]
        assert recoveries[0] == (
            {'pid': process.pid, 'created_at': created_at},
            {'term_seconds': 0.0, 'kill_seconds': 0.2},
        )
        assert process.returncode is not None
        assert not alive(process.pid)
        events = await harness.service.list_agent_events(harness.run_id, harness.agent_id, limit=100)
        assert sum(event['event_type'] == 'shell_task_finished' for event in events) == 1
        assert (await tools.shell('printf next-command'))['data']['output'] == 'next-command'
