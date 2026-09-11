"""OS-level recovery reaps descendants that survive their group leader."""

import asyncio
import json
import os
import signal
import sys
import psutil
import pytest
from agent.process_resources import terminate_recorded_process


@pytest.mark.asyncio
async def test_recorded_process_cleanup_kills_term_ignoring_descendant(tmp_path):
    pid_file = tmp_path / "child.pid"
    child_code = 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("ready", flush=True); time.sleep(60)'
    parent_code = """
import subprocess, sys, time
from pathlib import Path
child=subprocess.Popen([sys.executable, '-c', sys.argv[1]], stdout=subprocess.PIPE)
child.stdout.readline()
Path(sys.argv[2]).write_text(str(child.pid))
time.sleep(60)
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        parent_code,
        child_code,
        str(pid_file),
        start_new_session=True,
    )
    created_at = psutil.Process(process.pid).create_time()
    try:
        async with asyncio.timeout(5):
            while not pid_file.exists():
                await asyncio.sleep(0.01)
        child_pid = int(pid_file.read_text())
        await terminate_recorded_process({"pid": process.pid, "created_at": created_at})
        await asyncio.wait_for(process.wait(), 3)
        async with asyncio.timeout(3):
            while (
                psutil.pid_exists(child_pid)
                and psutil.Process(child_pid).status() != psutil.STATUS_ZOMBIE
            ):
                await asyncio.sleep(0.01)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await process.wait()


@pytest.mark.asyncio
async def test_recovery_does_not_signal_a_reused_pid_identity():
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "import time; time.sleep(60)", start_new_session=True
    )
    try:
        await terminate_recorded_process(
            {
                "pid": process.pid,
                "created_at": psutil.Process(process.pid).create_time() - 100,
            }
        )
        assert process.returncode is None
    finally:
        process.kill()
        await process.wait()
