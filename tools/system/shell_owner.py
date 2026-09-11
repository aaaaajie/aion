"""One Shell task's OS owner. Only this process owns the control pipe.

The command has separate output pipes: a daemon inheriting those pipes cannot
keep the Runtime's subprocess transport alive. This process stays the session
leader until all its children are reaped, including after the command exits.
It starts the command only after the Runtime has persisted its identity.
"""

from __future__ import annotations

import ctypes
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil

TERM_SECONDS = 2.0
KILL_SECONDS = 2.0
DRAIN_SECONDS = 1.0


def main() -> None:
    config = json.loads(sys.argv[1])
    owner = psutil.Process()
    group = os.getpgrp()
    stopped = False

    def stop(_sig, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # Adopt double-forked / setsid children on Linux. The stable session group
    # also covers orphaned children on Darwin without signalling reused PIDs.
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "Cannot own Shell descendants")

    print(json.dumps({"ready": True, "created_at": owner.create_time()}), flush=True)
    if sys.stdin.buffer.readline() != b"start\n" or stopped:
        return

    from runpy import run_path
    resource_api = run_path(str(Path(__file__).with_name("cgroups.py")))
    cgroup_path = config.get("cgroup_path")
    argv = config["argv"]
    if cgroup_path:
        argv = [sys.executable, "-I", str(Path(__file__).with_name("cgroups.py")), cgroup_path, json.dumps(argv)]
    started = time.monotonic()
    output_file = Path(config["output_path"]).open("a", encoding="utf-8")
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr, sys.stdin.buffer):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    captured = 0
    truncated = False
    output_incomplete = False
    failure = None
    timed_out = False
    termination_reason = None
    known: dict[int, psutil.Process] = {}

    def descendants() -> list[psutil.Process]:
        # Keep identities, not just PIDs, across reparenting and leader exit.
        for child in owner.children(recursive=True):
            known.setdefault(child.pid, child)
        for child in psutil.process_iter():
            try:
                if (
                    child.pid > 0
                    and child.pid != owner.pid
                    and os.getpgid(child.pid) == group
                ):
                    known.setdefault(child.pid, child)
            except (ProcessLookupError, PermissionError):
                continue
        live = []
        for pid, child in list(known.items()):
            try:
                if child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
                    live.append(child)
                else:
                    known.pop(pid, None)
            except psutil.NoSuchProcess:
                known.pop(pid, None)
        return live

    with output_file as output:

        def pump(wait: float) -> None:
            nonlocal stopped, captured, truncated, failure, output_incomplete
            for key, _ in selector.select(wait):
                try:
                    data = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    failure = {"stage": "output", "error": type(exc).__name__}
                    output_incomplete = True
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is sys.stdin.buffer:
                    # EOF means the Runtime died. Any control input means stop.
                    stopped = True
                    selector.unregister(key.fileobj)
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                text = data.decode("utf-8", errors="replace")
                kept = text[: max(0, config["capture_limit"] - captured)]
                truncated |= len(kept) < len(text)
                if kept and failure is None:
                    try:
                        output.write(kept)
                        output.flush()
                        captured += len(kept)
                    except OSError as exc:
                        failure = {"stage": "output", "error": type(exc).__name__}
                        output_incomplete = True

        while process.poll() is None and not stopped and failure is None:
            termination_reason = resource_api["termination_reason"](cgroup_path)
            if termination_reason:
                failure = {"stage": "resource", "error": termination_reason}
                break
            if time.monotonic() - started >= config["timeout"]:
                timed_out = True
                break
            pump(min(0.02, max(0, config["timeout"] - (time.monotonic() - started))))
        termination_reason = termination_reason or resource_api["termination_reason"](cgroup_path)
        if termination_reason:
            failure = {"stage": "resource", "error": termination_reason}
        exit_code = process.poll()
        cleanup_started = time.monotonic()
        # Signal verified Process objects individually; psutil's send_signal
        # checks creation time. Discover again while parents fork or exit.
        for sig, budget in (
            (signal.SIGTERM, TERM_SECONDS),
            (signal.SIGKILL, KILL_SECONDS),
        ):
            end = time.monotonic() + budget
            signalled: set[tuple[int, float]] = set()
            while True:
                children = descendants()
                if not children:
                    break
                for child in children:
                    try:
                        identity = (child.pid, child.create_time())
                        if identity not in signalled:
                            child.send_signal(sig)
                            signalled.add(identity)
                    except psutil.NoSuchProcess:
                        pass
                    except psutil.AccessDenied:
                        failure = {"stage": "terminate", "error": "AccessDenied"}
                if time.monotonic() >= end:
                    break
                pump(min(0.02, max(0, end - time.monotonic())))
                process.poll()
            if not children:
                break
        remaining = descendants()
        if remaining:
            failure = {
                "stage": "terminate",
                "error": "ProcessesSurvived",
                "pids": [child.pid for child in remaining],
            }
        drain_end = time.monotonic() + DRAIN_SECONDS
        while any(
            key.fileobj is not sys.stdin.buffer for key in selector.get_map().values()
        ):
            if time.monotonic() >= drain_end:
                output_incomplete = True
                break
            pump(min(0.02, max(0, drain_end - time.monotonic())))
        exit_code = exit_code if exit_code is not None else process.poll()
        for key in list(selector.get_map().values()):
            if key.fileobj is not sys.stdin.buffer:
                key.fileobj.close()
        selector.close()
        # Reap adopted children after preserving Popen's direct-child status.
        if sys.platform == "linux":
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
        resource_usage = {}
        if cgroup_path:
            cgroup_dir = Path(cgroup_path)
            memory_peak = cgroup_dir / "memory.peak"
            pids_peak = cgroup_dir / "pids.peak"
            if memory_peak.exists():
                resource_usage["memory_peak_bytes"] = int(memory_peak.read_text())
            if pids_peak.exists():
                resource_usage["pids_peak"] = int(pids_peak.read_text())
        print(
            json.dumps(
                {
                    "termination_reason": termination_reason,
                    "resource_usage": resource_usage,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "stopped": stopped,
                    "output_chars": captured,
                    "truncated": truncated,
                    "output_incomplete": output_incomplete,
                    "failure": failure,
                    "cleanup_ms": round((time.monotonic() - cleanup_started) * 1000),
                }
            ),
            flush=True,
        )
        # A failed cleanup must retain its verifiable owner for the Runtime's
        # recovery path. Never let an unknown orphan become an apparent success.
        if remaining:
            while descendants():
                for child in descendants():
                    try:
                        child.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                time.sleep(0.1)


if __name__ == "__main__":
    main()
