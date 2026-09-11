"""Bounded recovery of recorded, creation-time-verified OS process owners."""

import asyncio
import os
import signal

import psutil


async def terminate_recorded_process(record, *, term_seconds=2.0, kill_seconds=2.0):
    try:
        owner = psutil.Process(record["pid"])
        if abs(owner.create_time() - record["created_at"]) > 0.01:
            return
        group = os.getpgid(owner.pid)
    except (psutil.NoSuchProcess, ProcessLookupError):
        return
    known = {owner.pid: owner}

    def remaining():
        # Preserve verified identities when parents exit. Never infer an entire
        # group is dead from its leader's return code, or signal a bare stale PID.
        if owner.is_running():
            try:
                for child in owner.children(recursive=True):
                    known.setdefault(child.pid, child)
                if group == owner.pid:
                    for child in psutil.process_iter():
                        try:
                            if child.pid > 0 and os.getpgid(child.pid) == group:
                                known.setdefault(child.pid, child)
                        except (ProcessLookupError, PermissionError):
                            continue
            except psutil.NoSuchProcess:
                pass
        live = []
        for child in list(known.values()):
            try:
                if child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
                    live.append(child)
            except psutil.NoSuchProcess:
                pass
        return live

    loop = asyncio.get_running_loop()
    for sig, seconds in (
        (signal.SIGTERM, term_seconds),
        (signal.SIGKILL, kill_seconds),
    ):
        deadline = loop.time() + seconds
        sent = set()
        while True:
            children = remaining()
            if not children:
                return
            for child in children:
                identity = (child.pid, child.create_time())
                if identity not in sent:
                    try:
                        child.send_signal(sig)
                    except psutil.NoSuchProcess:
                        pass
                    sent.add(identity)
            if loop.time() >= deadline:
                break
            await asyncio.sleep(min(0.02, max(0, deadline - loop.time())))
    if remaining():
        raise TimeoutError("Recorded processes survived SIGKILL")
