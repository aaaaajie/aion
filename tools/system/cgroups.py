"""Linux cgroup v2 budgets for command trees; supervisors stay outside the pool."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading
import time

import psutil

_LOCK = threading.Lock()


def positive_env(name, default):
    value = float(os.environ.get(name, default))
    if not 0 < value < float('inf'):
        raise ValueError(f'{name} must be finite and positive')
    return value


def positive_int_env(name, default):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{name} must be a positive integer') from exc
    if value <= 0:
        raise ValueError(f'{name} must be a positive integer')
    return value


def budgets():
    mib = 1024 * 1024
    task_pids = positive_int_env('AION_SHELL_TASK_PIDS_MAX', 512)
    pool_pids = positive_int_env('AION_SHELL_POOL_PIDS_MAX', 2048)
    if task_pids > pool_pids:
        raise ValueError('AION_SHELL_TASK_PIDS_MAX must not exceed AION_SHELL_POOL_PIDS_MAX')
    return {
        'enforced': sys.platform == 'linux',
        'backend': 'cgroup_v2' if sys.platform == 'linux' else 'development_unrestricted',
        'memory_bytes': int(positive_env('AION_SHELL_TASK_MEMORY_MIB', 512) * mib),
        'cpu_cores': positive_env('AION_SHELL_TASK_CPU_CORES', 1),
        'pool_memory_bytes': int(positive_env('AION_SHELL_POOL_MEMORY_MIB', min(psutil.virtual_memory().total / mib / 2, 3072)) * mib),
        'pool_cpu_cores': positive_env('AION_SHELL_POOL_CPU_CORES', (os.cpu_count() or 1) / 2),
        'pids_max': task_pids,
        'pool_pids_max': pool_pids,
    }


def prepare(task_id):
    limits = budgets()
    if sys.platform != 'linux':
        return None, limits
    if not task_id or '/' in task_id or task_id in {'.', '..'}:
        raise ValueError('Invalid task identity')
    with _LOCK:
        membership = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
        current = Path('/sys/fs/cgroup') / membership.lstrip('/')
        root = current.parent if current.name == 'aion-control' else current
        if not {'cpu', 'memory', 'pids'} <= set((root / 'cgroup.controllers').read_text().split()):
            raise OSError('Delegated cpu, memory and pids controllers are required')
        control = root / 'aion-control'
        control.mkdir(exist_ok=True)
        # Empty the delegated root before enabling domain controllers. This also
        # moves an already running VPN into the unrestricted control leaf.
        for pid in (root / 'cgroup.procs').read_text().split():
            try:
                (control / 'cgroup.procs').write_text(pid)
            except ProcessLookupError:
                pass
        (root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        pool = root / 'aion-shell-tasks'
        pool.mkdir(exist_ok=True)
        (pool / 'memory.max').write_text(str(limits['pool_memory_bytes']))
        (pool / 'memory.swap.max').write_text('0')
        (pool / 'cpu.max').write_text(f"{int(limits['pool_cpu_cores'] * 100000)} 100000")
        (pool / 'pids.max').write_text(str(limits['pool_pids_max']))
        (pool / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        task = pool / task_id
        task.mkdir()
        try:
            (task / 'memory.max').write_text(str(limits['memory_bytes']))
            (task / 'memory.swap.max').write_text('0')
            (task / 'memory.oom.group').write_text('1')
            (task / 'cpu.max').write_text(f"{int(limits['cpu_cores'] * 100000)} 100000")
            (task / 'pids.max').write_text(str(limits['pids_max']))
            if not (task / 'cgroup.kill').exists():
                raise OSError('cgroup.kill is required')
        except BaseException:
            task.rmdir()
            raise
        return str(task), limits


def counters(path, name):
    file = Path(path) / name
    if not file.exists():
        return {}
    values = {}
    for line in file.read_text().splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            values[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return values


def termination_reason(path):
    if not path:
        return None
    pids_events = Path(path) / 'pids.events'
    if pids_events.exists():
        if counters(path, 'pids.events').get('max', 0):
            return 'process_limit_exceeded'
    memory = counters(path, 'memory.events')
    if memory.get('oom_kill', 0) or memory.get('oom_group_kill', 0):
        return 'memory_limit_exceeded'
    return None


def cleanup(path):
    if not path:
        return
    directory = Path(path)
    if directory.exists():
        (directory / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 1
        while counters(directory, 'cgroup.events').get('populated') and time.monotonic() < deadline:
            time.sleep(0.01)
        directory.rmdir()


if __name__ == '__main__':
    # Trusted launcher joins before executing any user command or spawning its
    # descendants. The owner retains its control channel outside this cgroup.
    group, argv = sys.argv[1], json.loads(sys.argv[2])
    (Path(group) / 'cgroup.procs').write_text(str(os.getpid()))
    os.execv(argv[0], argv)
