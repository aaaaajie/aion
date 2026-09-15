"""Persistent, Run-owned foreground and background Shell execution."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import psutil

from agent.state import StateService
from agent.state.clock import aware, utc_now
from agent.state.errors import StateConflict, StateNotFound

from .policy import SystemToolError, WorkspacePolicy

MAX_PERSISTED_OUTPUT_CHARS = 1_000_000
DEFAULT_REAP_INTERVAL_SECONDS = 60.0
TERMINAL_TASK_STATUSES = {
    "completed",
    "failed",
    "timeout",
    "stopped",
    "cancelled",
    "interrupted",
}
ShellTaskStatus = Literal[
    "running",
    "completed",
    "failed",
    "timeout",
    "stopped",
    "cancelled",
    "interrupted",
]


class SandboxBackend:
    """Build a mandatory host-sandbox or container-isolation command."""

    def __init__(
        self,
        root: Path,
        executable: str | None = None,
        platform_name: str | None = None,
        read_only_paths: Sequence[Path] = (),
        hidden_paths: Sequence[Path] = (),
    ) -> None:
        self.root = root.expanduser().resolve(strict=True)
        self.read_only_paths = tuple(
            dict.fromkeys(
                path.expanduser().resolve(strict=True) for path in read_only_paths
            )
        )
        self.hidden_paths = tuple(
            dict.fromkeys(
                path.expanduser().resolve(strict=False) for path in hidden_paths
            )
        )
        self.platform = platform_name or platform.system()
        self.backend = ""
        if executable is not None:
            if self.platform == "Linux":
                self.backend = "bwrap"
            self.executable = executable
        elif self.platform == "Darwin":
            self.executable = "/usr/bin/sandbox-exec"
        elif self.platform == "Linux":
            self.backend = "bwrap"
            self.executable = shutil.which("bwrap") or "/usr/bin/bwrap"
        else:
            self.executable = ""

    @property
    def available(self) -> bool:
        executable_available = (
            self.platform in {"Darwin", "Linux"}
            and bool(self.executable)
            and Path(self.executable).is_file()
            and os.access(self.executable, os.X_OK)
        )
        return executable_available

    def command(
        self,
        shell_command: str,
        cwd: Path | None = None,
        temp_dir: Path | None = None,
        write_paths: Sequence[Path] = (),
    ) -> list[str]:
        if self.platform not in {"Darwin", "Linux"}:
            raise SystemToolError(
                error_type="execution",
                code="sandbox_unsupported_platform",
                message="System Shell sandboxing is not implemented for this platform",
            )
        if not self.available:
            raise SystemToolError(
                error_type="execution",
                code="sandbox_unavailable",
                message="No supported OS sandbox backend is available",
            )
        if self.platform == "Darwin":
            return [
                self.executable,
                "-p",
                self._macos_profile(write_paths),
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-o", "pipefail",
                "-lc",
                shell_command,
            ]
        return self._linux_command(shell_command, cwd, temp_dir, write_paths)

    def command_argv(
        self,
        argv: Sequence[str],
        cwd: Path | None = None,
        temp_dir: Path | None = None,
        write_paths: Sequence[Path] = (),
    ) -> list[str]:
        """Build a Linux sandbox command without introducing a shell parser."""

        if self.platform != "Linux":
            raise SystemToolError(
                error_type="execution",
                code="linux_execution_required",
                message="ELF process sessions require a Linux sandbox backend",
            )
        if not self.available:
            raise SystemToolError(
                error_type="execution",
                code="sandbox_unavailable",
                message="No supported Linux OS sandbox backend is available",
            )
        if not argv or any(
            not isinstance(item, str) or "\x00" in item for item in argv
        ):
            raise SystemToolError(
                error_type="schema",
                code="invalid_argv",
                message="argv must contain at least one NUL-free string",
            )
        return [*self._linux_prefix(cwd, temp_dir, write_paths), *argv]

    def _macos_profile(self, write_paths: Sequence[Path] = ()) -> str:
        writable_paths = [
            json.dumps(str(path)) for path in self._validated_write_paths(write_paths)
        ]
        read_only_paths = [json.dumps(str(path)) for path in self.read_only_paths]
        system_read_paths = [
            "/System",
            "/Library",
            "/usr",
            "/bin",
            "/sbin",
            "/private/etc",
            "/private/var/db/dyld",
            "/private/var/db/timezone",
            "/dev",
            "/opt/homebrew",
        ]
        container_socket_paths = [
            "/var/run/docker.sock",
            "/private/var/run/docker.sock",
            str(Path.home() / ".docker/run/docker.sock"),
            str(
                Path.home()
                / "Library/Containers/com.docker.docker/Data/docker.raw.sock"
            ),
            "/var/run/podman/podman.sock",
        ]
        lines = [
            "(version 1)",
            "(allow default)",
            # Network-capable target tools (HTTP, TCP, SSH, scanners) own
            # their sessions.  Keep the general-purpose Shell workspace
            # offline so it cannot reach a host daemon through an AF_UNIX
            # socket or bypass the target-tool audit trail.
            "(deny network-outbound)",
            '(deny file-read* (subpath "/"))',
            '(allow file-read* (literal "/"))',
            '(deny file-write* (subpath "/"))',
            '(allow file-write* (literal "/dev/null"))',
            '(allow file-read-metadata (subpath "/"))',
        ]
        lines.extend(f"(allow file-write* (subpath {path}))" for path in writable_paths)
        lines.extend(
            f"(allow file-read* (subpath {json.dumps(path)}))"
            for path in system_read_paths
        )
        lines.extend(f"(allow file-read* (subpath {path}))" for path in read_only_paths)
        lines.extend(f"(deny file-write* (subpath {path}))" for path in read_only_paths)
        lines.extend(
            f"(deny file-read* (subpath {json.dumps(str(path))}))"
            for path in self.hidden_paths
        )
        # Agent-private and Challenge-shared workspaces live below the hidden
        # Runtime directories. Re-open only the exact per-agent paths passed
        # as writable paths; sibling agents and control-plane files stay hidden.
        lines.extend(
            f"(allow file-read* (subpath {json.dumps(str(path))}))"
            for path in self._validated_write_paths(write_paths)
        )
        lines.extend(
            f"(deny file-read* (literal {json.dumps(path)}))\n"
            f"(deny file-write* (literal {json.dumps(path)}))\n"
            f"(deny network-outbound (literal {json.dumps(path)}))"
            for path in container_socket_paths
        )
        return "\n".join(lines)

    def _linux_command(
        self,
        shell_command: str,
        cwd: Path | None,
        temp_dir: Path | None,
        write_paths: Sequence[Path],
    ) -> list[str]:
        return [
            *self._linux_prefix(cwd, temp_dir, write_paths),
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-o", "pipefail",
            "-lc",
            shell_command,
        ]

    def _linux_prefix(
        self,
        cwd: Path | None,
        temp_dir: Path | None,
        write_paths: Sequence[Path] = (),
    ) -> list[str]:
        command = [
            self.executable,
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--cap-drop",
            "ALL",
            "--tmpfs",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        if temp_dir is None:
            command.extend(["--tmpfs", "/tmp"])
        else:
            command.extend(["--dir", "/tmp"])
        bind_paths: list[tuple[str, str]] = []
        for system_path in (
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/services",
            "/etc/protocols",
            "/etc/passwd",
            "/etc/group",
            "/etc/ssl/certs",
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/localtime",
            "/etc/alternatives",
        ):
            if Path(system_path).exists():
                bind_paths.append((system_path, system_path))
        for optional_path in (
            "/usr/local",
            "/opt/homebrew",
            "/home/linuxbrew/.linuxbrew",
        ):
            if Path(optional_path).exists():
                bind_paths.append((optional_path, optional_path))

        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.is_symlink():
            try:
                resolv_target = resolv_conf.resolve(strict=True)
            except OSError:
                resolv_target = None
            if resolv_target is not None:
                bind_paths.append((str(resolv_target), "/etc/resolv.conf"))

        writable_paths = self._validated_write_paths(write_paths)
        read_only_bind_paths = [(str(path), str(path)) for path in self.read_only_paths]
        writable_bind_paths = [(str(path), str(path)) for path in writable_paths]
        destination_parents: set[Path] = set()
        for _, destination in (
            bind_paths
            + read_only_bind_paths
            + writable_bind_paths
            + [(str(self.root), str(self.root))]
        ):
            parent = Path(destination).parent
            while parent != Path("/"):
                destination_parents.add(parent)
                parent = parent.parent
        for parent in sorted(destination_parents, key=lambda item: len(item.parts)):
            command.extend(["--dir", str(parent)])
        for source, destination in bind_paths:
            command.extend(["--ro-bind", source, destination])
        if temp_dir is not None:
            command.extend(["--bind", str(temp_dir), "/tmp"])
        # Re-bind the exact per-agent and shared paths after hiding the parent
        # control-plane directories. This preserves shared evidence without
        # exposing prior runs or other Agents' private workspaces.
        for source, destination in writable_bind_paths:
            command.extend(["--bind", source, destination])
        for source, destination in read_only_bind_paths:
            command.extend(["--ro-bind", source, destination])
        if cwd is not None:
            command.extend(["--chdir", str(cwd)])
        return command

    def _validated_write_paths(self, paths: Sequence[Path]) -> tuple[Path, ...]:
        validated: list[Path] = []
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve(strict=False)
            try:
                path.relative_to(self.root)
            except ValueError as exc:
                raise SystemToolError(
                    error_type="permission",
                    code="sandbox_write_path_invalid",
                    message="Sandbox write paths must be inside the project root",
                ) from exc
            if path == self.root:
                raise SystemToolError(
                    error_type="permission",
                    code="sandbox_write_path_invalid",
                    message="The project root cannot be made writable",
                )
            if path not in validated:
                validated.append(path)
        return tuple(validated)


@dataclass
class LiveShellTask:
    task_id: str
    agent_id: str
    process: asyncio.subprocess.Process
    process_started_at: float
    output_path: Path
    capture_limit: int
    output_chars: int = 0
    truncated: bool = False
    timed_out: bool = False
    stop_requested: bool = False
    interrupted_requested: bool = False
    done: asyncio.Event = field(default_factory=asyncio.Event)
    monitor_task: asyncio.Task[None] | None = None
    persistence_error: Exception | None = None
    cleanup: dict[str, Any] = field(default_factory=dict)
    terminal_result: dict[str, Any] = field(default_factory=dict)
    cgroup_path: str | None = None
    recovery_task: asyncio.Task[None] | None = None
    stop_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    experiment_input: dict[str, Any] = field(default_factory=dict)
    experiment_scope: dict[str, Any] = field(default_factory=dict)
    experiment_saved: bool = False


class AgentShellClient:
    """Agent-bound view of one Run-level task manager."""

    def __init__(
        self,
        manager: "ShellTaskManager",
        agent_id: str,
        *,
        shared_root: Path | None = None,
    ) -> None:
        self.manager = manager
        self.agent_id = agent_id
        self.shared_work_root = (
            manager.validate_workspace_root(shared_root)
            if shared_root is not None
            else None
        )

    @property
    def agent_work_root(self) -> Path:
        return self.manager.agent_work_root(self.agent_id)

    async def run_shell(
        self,
        command: str,
        cwd: str = ".",
        timeout: float = 30.0,
        max_output_chars: int = 30_000,
        run_in_background: bool = False,
        task_name: str | None = None,
    ) -> dict[str, Any]:
        return await self.manager.run_shell(
            self.agent_id,
            command,
            cwd=cwd,
            timeout=timeout,
            max_output_chars=max_output_chars,
            run_in_background=run_in_background,
            task_name=task_name,
            shared_root=self.shared_work_root,
        )

    async def ensure_workspace(self) -> None:
        await self.manager.ensure_workspace(
            self.agent_id, shared_root=self.shared_work_root
        )

    async def record_workspace_event(
        self, event_type: str, payload: Mapping[str, Any] | None = None
    ) -> None:
        await self.manager.record_workspace_event(self.agent_id, event_type, payload)

    async def task_output(
        self,
        task_id: str,
        wait_seconds: float = 0.0,
        tail_chars: int = 30_000,
    ) -> dict[str, Any]:
        return await self.manager.task_output(
            self.agent_id,
            task_id,
            wait_seconds=wait_seconds,
            tail_chars=tail_chars,
        )

    async def task_stop(self, task_id: str) -> dict[str, Any]:
        return await self.manager.task_stop(self.agent_id, task_id)

    async def task_cleanup(self, task_id: str) -> dict[str, Any]:
        return await self.manager.task_cleanup(self.agent_id, task_id)


class ShellTaskManager:
    """Own Shell processes and durable output for one Runtime Run."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        service: StateService,
        run_id: str,
        *,
        sandbox: SandboxBackend | None = None,
        psutil_module: Any = psutil,
        clock: Callable[[], datetime] = utc_now,
        reap_interval_seconds: float = DEFAULT_REAP_INTERVAL_SECONDS,
        read_only_paths: Sequence[Path] = (),
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.policy = policy
        self.service = service
        self.run_id = self._component(run_id, "run_id")
        self.sandbox = sandbox or SandboxBackend(
            policy.root,
            read_only_paths=read_only_paths,
            hidden_paths=(policy.root / ".aion", policy.root / ".system-tools"),
        )
        self.environment = dict(environment or {})
        self.psutil = psutil_module
        self.clock = clock
        self.reap_interval_seconds = reap_interval_seconds
        self.runtime_root = policy.root / ".system-tools" / "runs" / self.run_id
        self._live: dict[str, LiveShellTask] = {}
        self._agent_cleanup_locks: dict[str, asyncio.Lock] = {}
        self._workspace_ready: set[str] = set()
        self._admission_closed: set[str] = set()
        self._pending_starts: set[asyncio.Task] = set()
        self._run_cleanup_lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None
        self._initialized = False
        self._closed = False

    async def initialize(self, *, resume: bool = False) -> None:
        if self._initialized:
            return
        self.runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if resume:
            await self._interrupt_persisted_tasks()
        self._initialized = True
        if self.reap_interval_seconds > 0:
            self._reaper_task = asyncio.create_task(
                self._reaper_loop(), name=f"aion-shell-reaper-{self.run_id}"
            )

    def bind(
        self, agent_id: str, *, shared_root: Path | None = None
    ) -> AgentShellClient:
        return AgentShellClient(
            self,
            self._component(agent_id, "agent_id"),
            shared_root=shared_root,
        )

    def agent_work_root(self, agent_id: str) -> Path:
        return self._owner_root(self._component(agent_id, "agent_id")) / "work"

    def shared_workspace_root(self, unique_code: str) -> Path:
        return (
            self.policy.root
            / ".aion"
            / "runs"
            / self.run_id
            / "shared"
            / self._component(unique_code, "unique_code")
        )

    def validate_workspace_root(self, path: Path | None) -> Path | None:
        if path is None:
            return None
        candidate = Path(path).expanduser().resolve(strict=False)
        try:
            candidate.relative_to(self.policy.root)
        except ValueError as exc:
            raise self._error(
                "permission",
                "workspace_root_invalid",
                "Agent workspace must be inside the project root",
            ) from exc
        if candidate == self.policy.root:
            raise self._error(
                "permission",
                "workspace_root_invalid",
                "Agent workspace cannot be the project root",
            )
        return candidate

    async def ensure_workspace(
        self, agent_id: str, *, shared_root: Path | None = None
    ) -> None:
        agent_id = self._component(agent_id, "agent_id")
        if agent_id in self._admission_closed:
            raise self._error(
                "conflict", "agent_inactive", "Agent workspace admission is closed"
            )
        owner_root, home_dir, temp_dir, task_dir, work_dir = self._owner_directories(
            agent_id
        )
        validated_shared = self.validate_workspace_root(shared_root)
        for directory in (
            owner_root,
            work_dir,
            home_dir,
            temp_dir,
            task_dir,
            home_dir / ".config",
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if validated_shared is not None:
            validated_shared.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._prepare_offline_home(home_dir)
        if agent_id not in self._workspace_ready:
            self._workspace_ready.add(agent_id)
            await self.record_workspace_event(
                agent_id,
                "agent_workspace_created",
                {"path_class": "agent_work"},
            )

    async def record_workspace_event(
        self,
        agent_id: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        safe_payload = {
            key: value
            for key, value in dict(payload or {}).items()
            if key in {"path_class", "operation", "reason"}
            and isinstance(value, (str, int, float, bool))
        }
        try:
            await self.service.append_agent_event(
                self.run_id,
                self._component(agent_id, "agent_id"),
                event_type,
                safe_payload,
            )
        except (StateConflict, StateNotFound):
            # Diagnostics must not make cleanup or a user-facing tool fail.
            return

    async def run_shell(
        self,
        agent_id: str,
        command: str,
        *,
        cwd: str = ".",
        timeout: float = 30.0,
        max_output_chars: int = 30_000,
        run_in_background: bool = False,
        task_name: str | None = None,
        shared_root: Path | None = None,
    ) -> dict[str, Any]:
        self._require_open()
        if self.sandbox.platform not in {"Darwin", "Linux"}:
            raise self._error(
                "execution",
                "sandbox_unsupported_platform",
                "System Shell sandboxing is not implemented for this platform",
            )
        if not self.sandbox.available:
            raise self._error(
                "execution",
                "sandbox_unavailable",
                "No supported OS sandbox backend is available",
            )
        validated_shared = self.validate_workspace_root(shared_root)
        await self.ensure_workspace(agent_id, shared_root=validated_shared)
        working_directory = self._resolve_shell_cwd(
            agent_id, cwd, shared_root=validated_shared
        )
        if not working_directory.is_dir():
            raise self._error(
                "validation", "not_a_directory", "Shell cwd is not a directory"
            )
        if len(command) > 100_000:
            raise self._error(
                "validation", "command_too_long", "Shell command is too long"
            )
        # Registration and cleanup share a lock. The owner cannot execute the
        # command until both its identity and Agent authority are committed.
        async with self._agent_cleanup_lock(agent_id):
            self._require_open()
            owner = await self.service.get_agent_runtime(self.run_id, agent_id)
            if agent_id in self._admission_closed or owner["agent"]["status"] in {
                "paused",
                "completed",
                "failed",
                "blocked",
                "stopped",
                "cancelled",
                "interrupted",
            }:
                raise self._error(
                    "conflict",
                    "agent_inactive",
                    "Inactive Agent cannot start a Shell task",
                )
            deadline = datetime.fromisoformat(owner["run"]["deadline_at"])
            timeout = min(
                timeout, (aware(deadline) - aware(self.clock())).total_seconds()
            )
            if timeout <= 0 or owner["run"]["status"] != "active":
                raise self._error(
                    "conflict", "run_inactive", "Run cannot start a Shell task"
                )
            owner_root, home_dir, temp_dir, task_dir, work_dir = (
                self._owner_directories(agent_id)
            )
            task_id = f"task-{uuid.uuid4().hex}"
            output_path = task_dir / f"{task_id}.log"
            output_path.touch(mode=0o600, exist_ok=False)
            argv = self.sandbox.command(
                command,
                working_directory,
                temp_dir,
                write_paths=(
                    work_dir,
                    home_dir,
                    temp_dir,
                    task_dir,
                    validated_shared or work_dir,
                ),
            )
            # The trusted owner already creates a session. Keeping bwrap in that
            # session makes even fast orphaned children attributable on Darwin
            # and Linux; Linux additionally adopts independent-session children.
            if self.sandbox.backend == "bwrap":
                argv.remove("--new-session")
            from . import cgroups
            try:
                cgroup_path, resource_limits = cgroups.prepare(task_id)
            except (OSError, ValueError, StopIteration) as exc:
                raise self._error("execution", "resource_limits_unavailable",
                                  f"Cannot enforce Shell resource budgets: {exc}") from exc
            config = {
                "cgroup_path": cgroup_path,
                "argv": argv,
                "timeout": timeout,
                "output_path": str(output_path),
                "capture_limit": min(max_output_chars, MAX_PERSISTED_OUTPUT_CHARS),
            }
            process = None
            spawn = asyncio.create_task(
                asyncio.create_subprocess_exec(
                    sys.executable,
                    "-I",
                    str(Path(__file__).with_name("shell_owner.py")),
                    json.dumps(config),
                    cwd=str(working_directory),
                    env=self._safe_environment(
                        home_dir,
                        temp_dir,
                        working_directory,
                        work_dir=work_dir,
                        shared_root=validated_shared,
                    ),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    start_new_session=True,
                )
            )
            self._pending_starts.add(spawn)
            try:
                process = await asyncio.shield(spawn)
                self._pending_starts.discard(spawn)
                assert process.stdout is not None
                ready = json.loads(await asyncio.wait_for(process.stdout.readline(), 2))
                process_started_at = float(ready["created_at"])
                await self.service.create_shell_task(
                    self.run_id,
                    agent_id,
                    task_id=task_id,
                    pid=process.pid,
                    process_started_at=process_started_at,
                    cwd=self._cwd_label(cwd, working_directory),
                    temp_dir=self.policy.relative(temp_dir),
                    output_path=self.policy.relative_lexical(output_path),
                    capture_limit=config["capture_limit"],
                    task_name=task_name, background=run_in_background, timeout=timeout,
                    resource_limits=resource_limits,
                )
            except BaseException:
                cgroups.cleanup(cgroup_path)
                if process is None:
                    # Shielded spawn may complete after cancellation. No command
                    # can run: closing stdin terminates the unactivated owner.
                    def abandon(done):
                        self._pending_starts.discard(done)
                        if not done.cancelled() and done.exception() is None:
                            child = done.result()
                            if child.stdin:
                                child.stdin.close()

                    spawn.add_done_callback(abandon)
                else:
                    if process.stdin:
                        process.stdin.close()
                    await self._terminate_process(process)
                output_path.unlink(missing_ok=True)
                raise
            live = LiveShellTask(
                task_id=task_id,
                agent_id=agent_id,
                process=process,
                process_started_at=process_started_at,
                output_path=output_path,
                cgroup_path=cgroup_path,
                capture_limit=config["capture_limit"],
            )
            self._live[task_id] = live
            from agent.experiment_records import shell_snapshot, digest
            live.experiment_input = await asyncio.to_thread(shell_snapshot, command, working_directory)
            live.experiment_scope = await self.service.capture_experiment_scope(self.run_id, agent_id)
            try:
                await self.service.record_experiment(self.run_id, agent_id, {
                    "tool": "shell_command", "input_digest": digest(live.experiment_input),
                    **live.experiment_scope,
                    "batch_digest": digest(task_id), "requested_input": live.experiment_input,
                    "executed_input": {"availability": "not_yet_executed"},
                    "output": {"status": "queued"},
                })
            except Exception as exc:
                await self.service.append_agent_event(self.run_id, agent_id, "experiment_persistence_failed",
                    {"tool": "shell_command", "error": type(exc).__name__})
            live.monitor_task = asyncio.create_task(
                self._monitor(live, timeout), name=f"aion-shell-{task_id}"
            )
            assert process.stdin is not None
            process.stdin.write(b"start\n")
        if run_in_background:
            row = await self.service.get_shell_task(self.run_id, agent_id, task_id)
            result = await self._result(row, tail_chars=max_output_chars)
            return {**result, "name": task_name, "timeout": timeout, "completion_notification": True}
        try:
            await live.done.wait()
        except asyncio.CancelledError:
            live.interrupted_requested = True
            if process.stdin:
                process.stdin.close()
            raise
        if live.persistence_error is not None:
            raise self._error(
                "internal",
                "shell_task_persistence_failed",
                "The Shell task result could not be persisted",
            )
        return await self.task_output(agent_id, task_id, tail_chars=max_output_chars)

    async def task_output(
        self,
        agent_id: str,
        task_id: str,
        *,
        wait_seconds: float = 0.0,
        tail_chars: int = 30_000,
    ) -> dict[str, Any]:
        self._require_open()
        await self.reap_expired()
        row = await self._owned_task(agent_id, task_id)
        live = self._live.get(task_id)
        if wait_seconds and live is not None and not live.done.is_set():
            try:
                await asyncio.wait_for(live.done.wait(), timeout=wait_seconds)
            except asyncio.TimeoutError:
                pass
            if live.persistence_error is not None:
                raise self._error(
                    "internal",
                    "shell_task_persistence_failed",
                    "The Shell task result could not be persisted",
                )
            row = await self._owned_task(agent_id, task_id)
        if row["output_cleaned_at"] is not None:
            raise self._error(
                "not_found",
                "task_output_expired",
                "Shell task output has been cleaned or expired",
                {"task_id": task_id, "status": row["status"], "result_state": "expired", "output_available": False},
            )
        return await self._result(row, tail_chars=tail_chars)

    async def task_stop(self, agent_id: str, task_id: str) -> dict[str, Any]:
        self._require_open()
        async with self._agent_cleanup_lock(agent_id):
            row = await self._owned_task(agent_id, task_id)
            if (
                row["status"] == "running"
                or row.get("cleanup", {}).get("resources_released") is False
            ):
                live = self._live.get(task_id)
                if live is None:
                    row = await self._finish_persisted(row, status="interrupted")
                else:
                    live.stop_requested = True
                    await self._terminate(live)
                    await live.done.wait()
                    if live.persistence_error is not None:
                        raise self._error(
                            "internal",
                            "shell_task_persistence_failed",
                            "The Shell task result could not be persisted",
                        )
                    row = await self._owned_task(agent_id, task_id)
            return await self._result(row, tail_chars=row["capture_limit"])

    async def task_cleanup(self, agent_id: str, task_id: str) -> dict[str, Any]:
        self._require_open()
        async with self._agent_cleanup_lock(agent_id):
            row = await self._owned_task(agent_id, task_id)
            if row["status"] == "running":
                raise self._error(
                    "conflict",
                    "task_still_running",
                    "Running Shell task must be stopped before cleanup",
                )
            if row["output_cleaned_at"] is not None:
                return {
                    "task_id": task_id,
                    "status": row["status"],
                    "cleaned": False,
                    "already_cleaned": True,
                }
            await self._remove_task_output(row)
            await self.service.mark_shell_task_output_cleaned(
                self.run_id, agent_id, task_id, reason="explicit"
            )
            return {
                "task_id": task_id,
                "status": row["status"],
                "cleaned": True,
                "already_cleaned": False,
            }

    async def pause_run(self) -> None:
        await self._drain_pending_starts()
        await self._stop_live_tasks(status="interrupted")
        await self._interrupt_persisted_tasks()
        await self._stop_reaper()
        self._closed = True

    async def finish_agent(self, agent_id: str) -> None:
        agent_id = self._component(agent_id, "agent_id")
        self.close_admission(agent_id)
        async with self._agent_cleanup_lock(agent_id):
            await self._stop_live_tasks(status="stopped", agent_id=agent_id)
            rows = await self.service.list_shell_tasks(self.run_id, agent_id=agent_id)
            for row in rows:
                if row["status"] == "running":
                    await self._finish_persisted(row, status="stopped")
            work_dir = self.agent_work_root(agent_id)
            had_work = work_dir.exists()
            await asyncio.to_thread(self._remove_tree, self._owner_root(agent_id))
            if had_work:
                await self.record_workspace_event(
                    agent_id,
                    "agent_workspace_cleaned",
                    {"path_class": "agent_work"},
                )
            self._workspace_ready.discard(agent_id)
            await self._mark_rows_cleaned(rows, reason="agent_terminal")

    async def finish_run(self) -> None:
        async with self._run_cleanup_lock:
            if self._closed:
                return
            await self._drain_pending_starts()
            rows = await self.service.list_shell_tasks(self.run_id)
            agent_ids = list(
                dict.fromkeys(
                    [str(row["agent_id"]) for row in rows]
                    + [task.agent_id for task in self._live.values()]
                )
            )
            results = await asyncio.gather(
                *(self.finish_agent(a) for a in agent_ids), return_exceptions=True
            )
            failures = [r for r in results if isinstance(r, BaseException)]
            if failures:
                raise failures[0]
            await asyncio.to_thread(self._remove_tree, self.runtime_root)
            await self._stop_reaper()
            self._closed = True

    async def reap_expired(self) -> int:
        rows = await self.service.list_shell_tasks(
            self.run_id,
            expired_before=self.clock(),
            output_available_only=True,
        )
        cleaned = 0
        for row in rows:
            try:
                await self._remove_task_output(row)
                await self.service.mark_shell_task_output_cleaned(
                    self.run_id,
                    row["agent_id"],
                    row["task_id"],
                    reason="ttl",
                )
                cleaned += 1
            except (OSError, StateConflict, StateNotFound):
                continue
        return cleaned

    async def _monitor(self, task: LiveShellTask, timeout: float) -> None:
        assert task.process.stdout is not None
        result = {}
        try:
            # Only the trusted owner writes this pipe. Command output has its
            # own bounded capture and can never prolong this transport's EOF.
            # Reserve one second of the five-second grace for forced recovery
            # and recording the outcome, including under scheduler contention.
            line = await asyncio.wait_for(task.process.stdout.readline(), timeout + 4.0)
            result = json.loads(line)
            task.timed_out = bool(result["timed_out"])
            task.output_chars = int(result["output_chars"])
            task.truncated = bool(result["truncated"] or result["output_incomplete"])
            task.cleanup = {
                key: result[key]
                for key in ("output_incomplete", "failure", "cleanup_ms", "http_summary")
                if key in result
            }
            task.cleanup["resources_released"] = (
                result.get("failure", {}).get("stage") != "terminate"
                if result.get("failure")
                else True
            )
            if task.cleanup["resources_released"]:
                try:
                    await asyncio.wait_for(task.process.wait(), 0.2)
                except asyncio.TimeoutError:
                    # The trusted owner has already confirmed descendant cleanup.
                    # A slow exit must not turn that acknowledgement into owner
                    # loss. Reap only the originally recorded process identity.
                    from agent.process_resources import terminate_recorded_process

                    await asyncio.wait_for(
                        terminate_recorded_process(
                            {"pid": task.process.pid, "created_at": task.process_started_at},
                            term_seconds=0.0,
                            kill_seconds=0.2,
                        ),
                        0.8,
                    )
                    await asyncio.wait_for(task.process.wait(), 0.2)
        except Exception as exc:
            task.cleanup = {
                "resources_released": False,
                "output_incomplete": True,
                "failure": {"stage": "owner", "error": type(exc).__name__},
            }
            task.truncated = True
            try:
                await self._force_terminate_task(task)
                task.cleanup["resources_released"] = True
            except Exception as cleanup_error:
                task.cleanup["failure"]["cleanup_error"] = getattr(
                    cleanup_error, "code", type(cleanup_error).__name__
                )
        finally:
            if task.interrupted_requested:
                status = "interrupted"
            elif task.timed_out:
                status = "timeout"
            elif task.stop_requested or result.get("stopped"):
                status = "stopped"
            elif task.cleanup.get("failure"):
                status = "failed"
            elif result.get("exit_code") == 0:
                status = "completed"
            else:
                status = "failed"
            from . import cgroups
            reason = result.get("termination_reason") or (
                "runtime_timeout" if task.timed_out else
                "user_stopped" if status == "stopped" else
                "runtime_interrupted" if status == "interrupted" else
                "command_failed" if status == "failed" else None)
            task.cleanup["termination_reason"] = reason
            task.cleanup["resource_usage"] = result.get("resource_usage", {})
            try:
                cgroups.cleanup(task.cgroup_path)
            except OSError as exc:
                task.cleanup["resources_released"] = False
                task.cleanup["failure"] = {"stage": "terminate", "error": str(exc)}
                status = "failed"
            task.terminal_result = {
                "status": status,
                "exit_code": result.get("exit_code"),
                "output_chars": task.output_chars,
                "truncated": task.truncated,
                "timed_out": task.timed_out,
                "cleanup": task.cleanup,
            }
            try:
                await self._persist_terminal(task)
            except Exception:
                pass
            finally:
                task.done.set()
                if not task.cleanup.get("resources_released"):
                    self.close_admission(task.agent_id)
                if (
                    task.cleanup.get("resources_released")
                    and task.persistence_error is None
                ):
                    self._live.pop(task.task_id, None)

    async def _persist_terminal(self, task: LiveShellTask) -> None:
        try:
            await self.service.finish_shell_task(
                self.run_id, task.agent_id, task.task_id, **task.terminal_result
            )
        except Exception as exc:
            task.persistence_error = exc
            raise
        task.persistence_error = None
        if not task.experiment_saved:
            from agent.experiment_records import digest, observation
            from agent.state import CapabilityContext
            try:
                runtime = await self.service.get_agent_runtime(self.run_id, task.agent_id)
                agent = runtime["agent"]
                raw = task.output_path.read_text(errors="replace") if task.output_path.exists() else ""
                artifact = await self.service.persist_evidence(self.run_id, CapabilityContext(
                    run_id=self.run_id, agent_id=task.agent_id, role=agent["role"], unique_code=agent["unique_code"]),
                    evidence_type="shell_output", source="shell_runtime", content=raw,
                    metadata={"interpretation": "unstructured_tool_output_not_a_verified_claim"})
                await self.service.record_experiment(self.run_id, task.agent_id, {
                    "tool": "shell_command", "input_digest": digest(task.experiment_input),
                    "execution_key": digest([task.agent_id, "task", task.task_id]),
                    **task.experiment_scope,
                    "batch_digest": digest(task.task_id),
                    "requested_input": task.experiment_input,
                    "executed_input": {"availability": "process_started", "command": task.experiment_input},
                    "raw_evidence_ref": artifact["evidence_ref"],
                    "output": observation({**task.terminal_result, "output": raw}),
                })
                task.experiment_saved = True
            except Exception as exc:
                await self.service.append_agent_event(self.run_id, task.agent_id, "experiment_persistence_failed",
                    {"tool": "shell_command", "error": type(exc).__name__})

    async def _drain_pending_starts(self) -> None:
        if self._pending_starts:
            _, pending = await asyncio.wait(list(self._pending_starts), timeout=2.0)
            if pending:
                raise self._error(
                    "internal",
                    "shell_spawn_pending",
                    "Shell owner spawn has not settled",
                )

    async def _result(self, row: dict[str, Any], *, tail_chars: int) -> dict[str, Any]:
        output: str | None = None
        if row["output_cleaned_at"] is None:
            output_path = self._output_path(row)
            try:
                if not output_path.exists():
                    raise FileNotFoundError(output_path)
                output = await asyncio.to_thread(
                    self._read_tail, output_path, tail_chars
                )
            except OSError as exc:
                raise self._error(
                    "internal",
                    "task_output_unavailable",
                    "Task output could not be read",
                ) from exc
        return {
            "cleanup": row.get("cleanup", {}),
            "output_incomplete": row.get("cleanup", {}).get("output_incomplete", False),
            "output_available": row["output_cleaned_at"] is None,
            "resource_limits": row.get("resource_limits", {}),
            "termination_reason": row.get("cleanup", {}).get("termination_reason"),
            "resource_usage": row.get("cleanup", {}).get("resource_usage", {}),
            "task_id": row["task_id"],
            "status": row["status"],
            "cwd": row["cwd"],
            "temp_dir": self._logical_task_path(row["agent_id"], row["temp_dir"]),
            "output_path": self._logical_task_path(row["agent_id"], row.get("output_path")),
            "exit_code": row["exit_code"],
            "output": output,
            "read_result": (
                {"tool": "system_task_output", "arguments": {"task_id": row["task_id"]}}
                if row["output_cleaned_at"] is None else None
            ),
            "result_state": (
                "cleaned" if row["output_cleaned_at"] is not None
                else "partial" if output and row["status"] in {"queued", "running"}
                else "available" if output
                else "pending" if row["status"] in {"queued", "running"}
                else "empty"
            ),
            "timed_out": row["timed_out"],
            "truncated": row["truncated"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "expires_at": row["expires_at"],
        }

    def _logical_task_path(self, agent_id: str, value: str | None) -> str | None:
        """Expose persisted task paths through the Agent file namespace."""
        if not value:
            return value
        path = Path(value)
        if not path.is_absolute():
            path = self.policy.root / path
        try:
            relative = path.resolve(strict=False).relative_to(
                self.agent_work_root(agent_id).resolve(strict=False)
            )
        except (ValueError, OSError):
            return value
        return "agent" if str(relative) == "." else f"agent/{relative.as_posix()}"

    async def _owned_task(self, agent_id: str, task_id: str) -> dict[str, Any]:
        try:
            return await self.service.get_shell_task(self.run_id, agent_id, task_id)
        except StateNotFound as exc:
            raise self._error(
                "not_found", "task_not_found", "Shell task does not exist"
            ) from exc

    async def _interrupt_persisted_tasks(self) -> None:
        rows = await self.service.list_shell_tasks(self.run_id)
        for row in rows:
            current = await self.service.get_shell_task(
                self.run_id, row["agent_id"], row["task_id"]
            )
            if (
                current["status"] == "running"
                or current["cleanup"].get("resources_released") is False
            ):
                await self._finish_persisted(current, status="interrupted")

    async def _finish_persisted(
        self, row: dict[str, Any], *, status: str
    ) -> dict[str, Any]:
        await self._terminate_persisted(row)
        output_path = self._output_path(row)
        try:
            output_chars = len(
                await asyncio.to_thread(
                    output_path.read_text, encoding="utf-8", errors="replace"
                )
            )
        except FileNotFoundError:
            output_chars = 0
        await self.service.append_agent_event(
            self.run_id,
            row["agent_id"],
            "shell_task_cleanup_retried",
            {
                "task_id": row["task_id"],
                "cleanup": {"resources_released": True, "output_incomplete": True},
            },
        )
        return await self.service.finish_shell_task(
            self.run_id,
            row["agent_id"],
            row["task_id"],
            status=status,
            exit_code=row["exit_code"],
            output_chars=output_chars,
            truncated=True,
            timed_out=bool(row["timed_out"]),
            cleanup={"resources_released": True, "output_incomplete": True},
        )

    def close_admission(self, agent_id: str) -> None:
        self._admission_closed.add(agent_id)

    def open_admission(self, agent_id: str) -> None:
        if any(t.agent_id == agent_id for t in self._live.values()):
            raise self._error(
                "conflict", "shell_cleanup_pending", "Previous Shell resources remain"
            )
        self._admission_closed.discard(agent_id)

    async def _stop_live_tasks(
        self, *, status: Literal["stopped", "interrupted"], agent_id: str | None = None
    ) -> None:
        tasks = [
            task
            for task in list(self._live.values())
            if agent_id is None or task.agent_id == agent_id
        ]
        for task in tasks:
            if status == "interrupted":
                task.interrupted_requested = True
            else:
                task.stop_requested = True
        results = await asyncio.gather(
            *(self._terminate(task) for task in tasks), return_exceptions=True
        )
        failures = [
            str(result) for result in results if isinstance(result, BaseException)
        ]
        if failures:
            raise self._error(
                "internal",
                "shell_cleanup_failed",
                "Shell resources could not be released",
                {"failures": failures},
            )

    async def _terminate(self, task: LiveShellTask) -> None:
        async with task.stop_lock:
            if not task.done.is_set():
                if task.process.stdin:
                    task.process.stdin.close()
                try:
                    await asyncio.wait_for(task.done.wait(), 4.0)
                except asyncio.TimeoutError:
                    await self._force_terminate_task(task)
                    await asyncio.wait_for(task.done.wait(), 0.1)
            if not task.cleanup.get("resources_released"):
                await self._force_terminate_task(task)
                task.cleanup["resources_released"] = True
                await self.service.append_agent_event(
                    self.run_id,
                    task.agent_id,
                    "shell_task_cleanup_retried",
                    {"task_id": task.task_id, "cleanup": task.cleanup},
                )
            if task.persistence_error:
                await self._persist_terminal(task)
            self._live.pop(task.task_id, None)

    async def _force_terminate_task(self, task: LiveShellTask) -> None:
        # Monitor and stop can observe owner EOF concurrently. Share the verified
        # recovery operation so neither mistakes the other's kill for a crash.
        if task.recovery_task is None:
            task.recovery_task = asyncio.create_task(
                self._terminate_process(
                    task.process,
                    force=True,
                    require_owner=True,
                    expected_created_at=task.process_started_at,
                )
            )
        await asyncio.shield(task.recovery_task)

    async def _terminate_process(
        self,
        process: asyncio.subprocess.Process,
        *,
        force: bool = False,
        require_owner: bool = False,
        expected_created_at: float | None = None,
    ) -> None:
        from agent.process_resources import terminate_recorded_process

        if require_owner and process.returncode is not None:
            raise self._error(
                "internal",
                "shell_owner_lost",
                "Shell owner exited without confirming descendant cleanup",
            )
        if process.returncode is None:
            try:
                owner = self.psutil.Process(process.pid)
                identity = owner.create_time()
                if require_owner and (
                    owner.status() == self.psutil.STATUS_ZOMBIE
                    or abs(identity - expected_created_at) > 0.01
                ):
                    raise self._error(
                        "internal",
                        "shell_owner_lost",
                        "Shell owner identity is no longer live",
                    )
            except self.psutil.NoSuchProcess:
                if require_owner:
                    raise self._error(
                        "internal",
                        "shell_owner_lost",
                        "Shell owner disappeared before cleanup confirmation",
                    )
                return
            await terminate_recorded_process(
                {"pid": process.pid, "created_at": identity},
                term_seconds=0.0 if force else 2.0,
                kill_seconds=0.1 if force else 2.0,
            )
        await asyncio.wait_for(process.wait(), 0.1)

    async def _terminate_persisted(self, row: dict[str, Any]) -> None:
        from agent.process_resources import terminate_recorded_process

        failure = row.get("cleanup", {}).get("failure") or {}
        if failure.get("cleanup_error") == "shell_owner_lost":
            raise self._error(
                "internal",
                "shell_owner_lost",
                "Recorded Shell cleanup remains unconfirmed",
            )
        if float(row["process_started_at"]) > 0:
            await terminate_recorded_process(
                {"pid": int(row["pid"]), "created_at": float(row["process_started_at"])}
            )

    async def _remove_task_output(self, row: dict[str, Any]) -> None:
        output_path = self._output_path(row)
        await asyncio.to_thread(output_path.unlink, missing_ok=True)

    async def _mark_rows_cleaned(
        self, rows: list[dict[str, Any]], *, reason: str
    ) -> None:
        for row in rows:
            current = await self.service.get_shell_task(
                self.run_id, row["agent_id"], row["task_id"]
            )
            if (
                current["status"] == "running"
                or current["output_cleaned_at"] is not None
            ):
                continue
            await self.service.mark_shell_task_output_cleaned(
                self.run_id,
                current["agent_id"],
                current["task_id"],
                reason=reason,
            )

    async def _reaper_loop(self) -> None:
        while True:
            await asyncio.sleep(self.reap_interval_seconds)
            try:
                await self.reap_expired()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def _stop_reaper(self) -> None:
        if self._reaper_task is None:
            return
        self._reaper_task.cancel()
        await asyncio.gather(self._reaper_task, return_exceptions=True)
        self._reaper_task = None

    def _owner_directories(self, agent_id: str) -> tuple[Path, Path, Path, Path, Path]:
        owner_root = self._owner_root(agent_id)
        work_dir = owner_root / "work"
        # Keep the sandbox's /tmp inside the Agent-visible workspace so files
        # created through TMPDIR can be read as agent/.tmp/....
        temp_dir = work_dir / ".tmp" / self._component(agent_id, "agent_id")
        return (
            owner_root,
            owner_root / "home",
            temp_dir,
            temp_dir / "tasks",
            work_dir,
        )

    def _owner_root(self, agent_id: str) -> Path:
        return self.runtime_root / "agents" / self._component(agent_id, "agent_id")

    def _output_path(self, row: dict[str, Any]) -> Path:
        output_path = self.policy.resolve(str(row["output_path"]))
        expected = (
            self._owner_root(str(row["agent_id"]))
            / "work" / ".tmp" / self._component(str(row["agent_id"]), "agent_id") / "tasks"
        )
        try:
            output_path.relative_to(expected)
        except ValueError as exc:
            raise self._error(
                "internal", "invalid_task_output_path", "Task output path is invalid"
            ) from exc
        return output_path

    def _safe_environment(
        self,
        home_dir: Path,
        temp_dir: Path,
        working_directory: Path,
        *,
        work_dir: Path,
        shared_root: Path | None,
    ) -> dict[str, str]:
        venv_bin = self.environment.get("AION_VENV_BIN", "")
        toolchain_bin = self.environment.get("AION_TOOLCHAIN_BIN", "")
        path_entries = [
            entry
            for entry in (
                venv_bin,
                toolchain_bin,
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
                "/sbin",
                "/bin",
            )
            if entry
        ]
        environment = {
            "HOME": str(home_dir),
            "AION_AGENT_WORKDIR": str(work_dir),
            "AION_SHARED_WORKDIR": str(shared_root or ""),
            "AION_PROJECT_ROOT": str(self.policy.root),
            "TMPDIR": str(temp_dir),
            "TMP": str(temp_dir),
            "TEMP": str(temp_dir),
            "XDG_CONFIG_HOME": str(home_dir / ".config"),
            "PWD": str(working_directory),
            "PATH": os.pathsep.join(path_entries),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "SHELL": "/bin/bash",
            "TERM": "dumb",
            "USER": "sandbox",
            "LOGNAME": "sandbox",
        }
        environment.update(self.environment)
        environment.update(
            {
                "AION_AGENT_WORKDIR": str(work_dir),
                "AION_SHARED_WORKDIR": str(shared_root or ""),
                "AION_PROJECT_ROOT": str(self.policy.root),
                # The task namespace is authoritative. A caller-provided
                # host TMPDIR must never redirect writes outside agent/.tmp.
                "TMPDIR": str(temp_dir),
                "TMP": str(temp_dir),
                "TEMP": str(temp_dir),
            }
        )
        return environment

    def _resolve_shell_cwd(
        self,
        agent_id: str,
        raw_cwd: str,
        *,
        shared_root: Path | None,
    ) -> Path:
        if not isinstance(raw_cwd, str) or not raw_cwd or "\x00" in raw_cwd:
            raise self._error(
                "validation", "invalid_path", "Shell cwd must be a non-empty string"
            )
        work_dir = self.agent_work_root(agent_id)
        path = Path(raw_cwd).expanduser()
        if not path.is_absolute() and raw_cwd in {".", "agent"}:
            return work_dir
        if not path.is_absolute() and (
            raw_cwd == "shared" or raw_cwd.startswith("shared/")
        ):
            if shared_root is None:
                raise self._error(
                    "permission",
                    "shared_workspace_unavailable",
                    "The shared Agent workspace is not available",
                )
            suffix = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
            return self._resolve_shell_subpath(shared_root, suffix)
        if not path.is_absolute() and (
            raw_cwd == "project" or raw_cwd.startswith("project/")
        ):
            raise self._error(
                "permission",
                "workspace_path_rejected",
                "Project workspace is not available to Agents",
            )
        if not path.is_absolute() and (
            raw_cwd.startswith("agent/") or raw_cwd == "agent"
        ):
            suffix = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
            return self._resolve_shell_subpath(work_dir, suffix)
        if path.is_absolute():
            resolved = self.policy.resolve(path)
            for base in (work_dir, shared_root):
                if base is not None and resolved.is_relative_to(base.resolve()):
                    return self._resolve_shell_subpath(base, resolved)
            raise self._error(
                "permission",
                "workspace_path_rejected",
                "Shell cwd is outside the assigned workspace",
            )
        return self._resolve_shell_subpath(work_dir, path)

    def _resolve_shell_subpath(self, base: Path, suffix: Path) -> Path:
        base = base.resolve(strict=False)
        candidate = Path(os.path.abspath(os.path.normpath(base / suffix)))
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise self._error(
                "permission",
                "workspace_path_rejected",
                "Shell cwd cannot escape its assigned workspace",
            ) from exc
        resolved = self.policy.resolve(candidate, must_exist=True)
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise self._error(
                "permission",
                "workspace_path_rejected",
                "Shell cwd cannot resolve outside its assigned workspace",
            ) from exc
        if not resolved.is_dir():
            raise self._error(
                "validation", "not_a_directory", "Shell cwd is not a directory"
            )
        return resolved

    def _cwd_label(self, raw_cwd: str, working_directory: Path) -> str:
        if raw_cwd in {"", "."}:
            return "."
        try:
            return self.policy.relative(working_directory)
        except SystemToolError:
            return raw_cwd

    @staticmethod
    def _prepare_offline_home(home_dir: Path) -> None:
        """Disable pwntools' network update check for the offline competition."""

        cache_dir = home_dir / ".cache"
        cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        pwn_cache = (
            cache_dir
            / f".pwntools-cache-{sys.version_info.major}.{sys.version_info.minor}"
        )
        pwn_cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        update_file = pwn_cache / "update"
        if not update_file.is_file():
            update_file.write_text("never\n", encoding="ascii")
            try:
                update_file.chmod(0o600)
            except OSError:
                pass

    def _require_open(self) -> None:
        if not self._initialized or self._closed:
            raise self._error(
                "internal", "shell_manager_closed", "Shell task manager is not active"
            )

    @staticmethod
    def _component(value: str, name: str) -> str:
        if not value or value in {".", ".."} or Path(value).name != value:
            raise ValueError(f"{name} must be one path component")
        return value

    @staticmethod
    def _read_tail(path: Path, tail_chars: int) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[-tail_chars:]

    @staticmethod
    def _remove_tree(path: Path) -> None:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)

    def _agent_cleanup_lock(self, agent_id: str) -> asyncio.Lock:
        agent_id = self._component(agent_id, "agent_id")
        return self._agent_cleanup_locks.setdefault(agent_id, asyncio.Lock())

    @staticmethod
    def _error(
        error_type: str,
        code: str,
        message: str,
        detail: Any = None,
    ) -> SystemToolError:
        return SystemToolError(
            error_type=error_type,
            code=code,
            message=message,
            detail=detail,
        )


__all__ = [
    "AgentShellClient",
    "SandboxBackend",
    "ShellTaskManager",
    "ShellTaskStatus",
]
