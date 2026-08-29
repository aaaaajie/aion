"""Persistent, Run-owned foreground and background Shell execution."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import pwd
import re
import shutil
import signal
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import psutil

from agent.state import StateService
from agent.state.clock import utc_now
from agent.state.errors import StateConflict, StateNotFound

from .policy import SystemToolError, WorkspacePolicy

MAX_PERSISTED_OUTPUT_CHARS = 1_000_000
DEFAULT_REAP_INTERVAL_SECONDS = 60.0
TERMINAL_TASK_STATUSES = {
    "completed",
    "failed",
    "timeout",
    "stopped",
    "interrupted",
}
_OFFLINE_INSTALL_PATTERN = re.compile(
    r"(?ix)"
    r"(?:^|[;&|]\s*)(?:sudo\s+)?"
    r"(?:python(?:3(?:\.\d+)?)?\s+-m\s+pip\b|pip3?\s+(?:install|download|uninstall|upgrade)\b|"
    r"(?:apt(?:-get)?|dnf|yum|apk|brew)\s+(?:install|update|upgrade|add)\b)"
    r"|(?:curl|wget)\b[^\n|;]*\|\s*(?:sh|bash)\b"
)
_CONTAINER_CONTROL_PATTERN = re.compile(
    r"(?ix)"
    r"(?:^|[\s;&|()<>`'\"])"
    r"(?:command\s+)?(?:sudo\s+)?(?:docker|podman|nerdctl|crictl)\b"
    r"|(?:^|[\s;&|()<>`'\"])"
    r"(?:command\s+)?(?:sudo\s+)?kubectl\s+(?:exec|cp|attach|port-forward|debug)\b"
)
_CONTAINER_SOCKET_PATTERN = re.compile(
    r"(?ix)"
    r"(?:docker\.sock|docker\.raw\.sock|com\.docker\.docker|"
    r"\.docker/run/|/var/run/(?:docker|podman)\.sock)"
)
ShellTaskStatus = Literal[
    "running",
    "completed",
    "failed",
    "timeout",
    "stopped",
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
        sandbox_user: str | None = None,
    ) -> None:
        self.root = root.expanduser().resolve(strict=True)
        self.read_only_paths = tuple(
            dict.fromkeys(path.expanduser().resolve(strict=True) for path in read_only_paths)
        )
        self.hidden_paths = tuple(
            dict.fromkeys(path.expanduser().resolve(strict=False) for path in hidden_paths)
        )
        self.platform = platform_name or platform.system()
        self.sandbox_user = (
            sandbox_user
            if sandbox_user is not None
            else os.environ.get("AION_LINUX_SANDBOX_USER", "").strip()
        )
        self.backend = ""
        if self.platform == "Linux" and self.sandbox_user:
            self.backend = "setpriv"
            self.executable = (
                executable or shutil.which("setpriv") or "/usr/bin/setpriv"
            )
        elif executable is not None:
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
        if not executable_available:
            return False
        if self.backend != "setpriv":
            return True
        try:
            pwd.getpwnam(self.sandbox_user)
        except KeyError:
            return False
        return True

    def prepare(self) -> None:
        """Prepare mutable workspace ownership for the container sandbox user."""

        if self.backend != "setpriv":
            return
        try:
            account = pwd.getpwnam(self.sandbox_user)
            for _, directory_names, file_names, directory_fd in os.fwalk(
                self.root,
                topdown=True,
                follow_symlinks=False,
            ):
                os.fchown(directory_fd, account.pw_uid, account.pw_gid)
                for name in (*directory_names, *file_names):
                    try:
                        os.chown(
                            name,
                            account.pw_uid,
                            account.pw_gid,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        continue
        except (KeyError, OSError) as exc:
            raise SystemToolError(
                error_type="execution",
                code="sandbox_workspace_unavailable",
                message="The container sandbox workspace could not be prepared",
            ) from exc

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
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise SystemToolError(
                error_type="schema",
                code="invalid_argv",
                message="argv must contain at least one NUL-free string",
            )
        return [*self._linux_prefix(cwd, temp_dir, write_paths), *argv]

    def _macos_profile(self, write_paths: Sequence[Path] = ()) -> str:
        root = json.dumps(str(self.root))
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
            "/private/var",
            "/dev",
            "/opt/homebrew",
        ]
        container_socket_paths = [
            "/var/run/docker.sock",
            "/private/var/run/docker.sock",
            str(Path.home() / ".docker/run/docker.sock"),
            str(Path.home() / "Library/Containers/com.docker.docker/Data/docker.raw.sock"),
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
            "(deny file-read* (subpath \"/Users\"))",
            f"(allow file-read* (subpath {root}))",
            "(deny file-write* (subpath \"/\"))",
            "(allow file-write* (literal \"/dev/null\"))",
            "(allow file-read-metadata (subpath \"/\"))",
        ]
        # macOS sandbox-exec does not mount the per-Agent TMPDIR at the
        # conventional absolute /tmp path.  Keep the persistent TMPDIR for
        # isolation, but explicitly permit the conventional path so ordinary
        # tools such as curl, grep, and sort do not fail with ENOENT.
        lines.extend(
            f"(allow file-read* (subpath {json.dumps(path)}))"
            for path in ("/tmp", "/private/tmp")
        )
        lines.extend(
            f"(allow file-write* (subpath {json.dumps(path)}))"
            for path in ("/tmp", "/private/tmp")
        )
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
            "-lc",
            shell_command,
        ]

    def _linux_prefix(
        self,
        cwd: Path | None,
        temp_dir: Path | None,
        write_paths: Sequence[Path] = (),
    ) -> list[str]:
        if self.backend == "setpriv":
            account = pwd.getpwnam(self.sandbox_user)
            return [
                self.executable,
                f"--reuid={account.pw_uid}",
                f"--regid={account.pw_gid}",
                "--clear-groups",
                "--no-new-privs",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--bounding-set=-all",
                "/usr/bin/env",
                "-C",
                str(cwd or self.root),
            ]
        command = [
            self.executable,
            "--die-with-parent",
            "--new-session",
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
        for system_path in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
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
        read_only_bind_paths = [
            (str(path), str(path)) for path in self.read_only_paths
        ]
        writable_bind_paths = [(str(path), str(path)) for path in writable_paths]
        destination_parents: set[Path] = set()
        for _, destination in bind_paths + read_only_bind_paths + writable_bind_paths + [
            (str(self.root), str(self.root))
        ]:
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
        command.extend(["--ro-bind", str(self.root), str(self.root)])
        for path in self.hidden_paths:
            command.extend(["--tmpfs", str(path)])
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
    output_path: Path
    capture_limit: int
    output_chars: int = 0
    truncated: bool = False
    timed_out: bool = False
    stop_requested: bool = False
    interrupted_requested: bool = False
    output_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    monitor_task: asyncio.Task[None] | None = None
    persistence_error: Exception | None = None


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
            manager.validate_workspace_root(shared_root) if shared_root is not None else None
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
    ) -> dict[str, Any]:
        return await self.manager.run_shell(
            self.agent_id,
            command,
            cwd=cwd,
            timeout=timeout,
            max_output_chars=max_output_chars,
            run_in_background=run_in_background,
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

    async def close(self) -> None:
        """The Supervisor owns the manager; model session close is a no-op."""


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
        owner_root, home_dir, temp_dir, task_dir, work_dir = self._owner_directories(agent_id)
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
        if _OFFLINE_INSTALL_PATTERN.search(command):
            raise self._error(
                "validation",
                "offline_install_blocked",
                "Package-manager and network installer commands are disabled in the offline runtime",
            )
        if _CONTAINER_CONTROL_PATTERN.search(command) or _CONTAINER_SOCKET_PATTERN.search(command):
            raise self._error(
                "permission",
                "container_control_blocked",
                "Host container-engine control is outside the Agent target scope",
            )
        owner = await self.service.get_agent_runtime(self.run_id, agent_id)
        if owner["agent"]["status"] in {
            "completed",
            "failed",
            "stopped",
            "cancelled",
            "interrupted",
        }:
            raise self._error(
                "conflict",
                "agent_terminal",
                "Finished Agent cannot start a Shell task",
            )

        owner_root, home_dir, temp_dir, task_dir, work_dir = self._owner_directories(agent_id)
        task_id = f"task-{uuid.uuid4().hex}"
        output_path = task_dir / f"{task_id}.log"
        output_path.touch(mode=0o600, exist_ok=False)
        process: asyncio.subprocess.Process | None = None
        try:
            self.sandbox.prepare()
            process = await asyncio.create_subprocess_exec(
                *self.sandbox.command(
                    command,
                    working_directory,
                    temp_dir,
                    write_paths=(work_dir, home_dir, temp_dir, task_dir, validated_shared or work_dir),
                ),
                cwd=str(working_directory),
                env=self._safe_environment(
                    home_dir,
                    temp_dir,
                    working_directory,
                    work_dir=work_dir,
                    shared_root=validated_shared,
                ),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            try:
                process_started_at = float(
                    await asyncio.to_thread(
                        self.psutil.Process(process.pid).create_time
                    )
                )
            except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
                # A very short command can exit before psutil observes it.  A
                # zero identity is safe because recovery will never signal an
                # unverified PID; the monitor still records its real outcome.
                process_started_at = 0.0
            await self.service.create_shell_task(
                self.run_id,
                agent_id,
                task_id=task_id,
                pid=process.pid,
                process_started_at=process_started_at,
                cwd=self._cwd_label(cwd, working_directory),
                temp_dir=self.policy.relative(temp_dir),
                output_path=self.policy.relative_lexical(output_path),
                capture_limit=min(max_output_chars, MAX_PERSISTED_OUTPUT_CHARS),
            )
        except SystemToolError:
            if process is not None:
                await self._terminate_process(process)
            output_path.unlink(missing_ok=True)
            raise
        except FileNotFoundError as exc:
            if process is not None:
                await self._terminate_process(process)
            output_path.unlink(missing_ok=True)
            raise self._error(
                "execution",
                "sandbox_unavailable",
                "The configured sandbox executable could not be started",
            ) from exc
        except OSError as exc:
            if process is not None:
                await self._terminate_process(process)
            output_path.unlink(missing_ok=True)
            raise self._error(
                "execution", "shell_spawn_failed", "The Shell process could not be started"
            ) from exc
        except Exception as exc:
            if process is not None:
                await self._terminate_process(process)
            output_path.unlink(missing_ok=True)
            raise self._error(
                "internal",
                "shell_task_persistence_failed",
                "The Shell task could not be persisted",
            ) from exc

        assert process is not None
        live = LiveShellTask(
            task_id=task_id,
            agent_id=agent_id,
            process=process,
            output_path=output_path,
            capture_limit=min(max_output_chars, MAX_PERSISTED_OUTPUT_CHARS),
        )
        self._live[task_id] = live
        live.monitor_task = asyncio.create_task(
            self._monitor(live, timeout), name=f"aion-shell-{task_id}"
        )
        if run_in_background:
            row = await self.service.get_shell_task(self.run_id, agent_id, task_id)
            return await self._result(row, tail_chars=max_output_chars)
        await live.done.wait()
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
                {"task_id": task_id, "status": row["status"]},
            )
        return await self._result(row, tail_chars=tail_chars)

    async def task_stop(self, agent_id: str, task_id: str) -> dict[str, Any]:
        self._require_open()
        async with self._agent_cleanup_lock(agent_id):
            row = await self._owned_task(agent_id, task_id)
            if row["status"] == "running":
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
        await self._stop_live_tasks(status="interrupted")
        await self._interrupt_persisted_tasks()
        await self._stop_reaper()
        self._closed = True

    async def finish_agent(self, agent_id: str) -> None:
        agent_id = self._component(agent_id, "agent_id")
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
            rows = await self.service.list_shell_tasks(self.run_id)
            agent_ids = list(
                dict.fromkeys(
                    [str(row["agent_id"]) for row in rows]
                    + [task.agent_id for task in self._live.values()]
                )
            )
            for agent_id in agent_ids:
                await self.finish_agent(agent_id)
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
        assert task.process.stderr is not None
        stdout_reader = asyncio.create_task(
            self._consume(task, task.process.stdout, "stdout")
        )
        stderr_reader = asyncio.create_task(
            self._consume(task, task.process.stderr, "stderr")
        )
        try:
            try:
                await asyncio.wait_for(task.process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                task.timed_out = True
                await self._terminate(task)
                await task.process.wait()
        finally:
            await asyncio.gather(stdout_reader, stderr_reader, return_exceptions=True)
            if task.interrupted_requested:
                status = "interrupted"
            elif task.timed_out:
                status = "timeout"
            elif task.stop_requested:
                status = "stopped"
            elif task.process.returncode == 0:
                status = "completed"
            else:
                status = "failed"
            try:
                await self.service.finish_shell_task(
                    self.run_id,
                    task.agent_id,
                    task.task_id,
                    status=status,
                    exit_code=task.process.returncode,
                    output_chars=task.output_chars,
                    truncated=task.truncated,
                    timed_out=task.timed_out,
                )
            except Exception as exc:
                task.persistence_error = exc
            finally:
                task.done.set()
                self._live.pop(task.task_id, None)

    async def _consume(
        self,
        task: LiveShellTask,
        stream: asyncio.StreamReader,
        _stream_name: str,
    ) -> None:
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace")
            async with task.output_lock:
                remaining = task.capture_limit - task.output_chars
                captured = text[: max(0, remaining)]
                if len(captured) < len(text):
                    task.truncated = True
                if captured:
                    await asyncio.to_thread(self._append_output, task.output_path, captured)
                    task.output_chars += len(captured)

    async def _result(
        self, row: dict[str, Any], *, tail_chars: int
    ) -> dict[str, Any]:
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
            "task_id": row["task_id"],
            "status": row["status"],
            "cwd": row["cwd"],
            "temp_dir": row["temp_dir"],
            "exit_code": row["exit_code"],
            "output": output,
            "timed_out": row["timed_out"],
            "truncated": row["truncated"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "expires_at": row["expires_at"],
        }

    async def _owned_task(self, agent_id: str, task_id: str) -> dict[str, Any]:
        try:
            return await self.service.get_shell_task(self.run_id, agent_id, task_id)
        except StateNotFound as exc:
            raise self._error(
                "not_found", "task_not_found", "Shell task does not exist"
            ) from exc

    async def _interrupt_persisted_tasks(self) -> None:
        rows = await self.service.list_shell_tasks(
            self.run_id, statuses={"running"}
        )
        for row in rows:
            await self._terminate_persisted(row)
            await self._finish_persisted(row, status="interrupted")

    async def _finish_persisted(
        self, row: dict[str, Any], *, status: str
    ) -> dict[str, Any]:
        output_path = self._output_path(row)
        try:
            output_chars = len(
                await asyncio.to_thread(
                    output_path.read_text, encoding="utf-8", errors="replace"
                )
            )
        except FileNotFoundError:
            output_chars = 0
        return await self.service.finish_shell_task(
            self.run_id,
            row["agent_id"],
            row["task_id"],
            status=status,
            exit_code=row["exit_code"],
            output_chars=output_chars,
            truncated=bool(row["truncated"]),
            timed_out=bool(row["timed_out"]),
        )

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
            await self._terminate(task)
        if tasks:
            await asyncio.gather(*(task.done.wait() for task in tasks))

    async def _terminate(self, task: LiveShellTask) -> None:
        await self._terminate_process(task.process)

    async def _terminate_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    async def _terminate_persisted(self, row: dict[str, Any]) -> None:
        if float(row["process_started_at"]) <= 0:
            return
        try:
            process = self.psutil.Process(int(row["pid"]))
            started_at = float(await asyncio.to_thread(process.create_time))
            if abs(started_at - float(row["process_started_at"])) > 0.01:
                return
            try:
                os.killpg(int(row["pid"]), signal.SIGTERM)
            except ProcessLookupError:
                return
            try:
                await asyncio.to_thread(process.wait, 2)
            except self.psutil.TimeoutExpired:
                try:
                    os.killpg(int(row["pid"]), signal.SIGKILL)
                except ProcessLookupError:
                    return
                await asyncio.to_thread(process.wait, 2)
        except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
            return

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
            if current["status"] == "running" or current["output_cleaned_at"] is not None:
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

    def _owner_directories(
        self, agent_id: str
    ) -> tuple[Path, Path, Path, Path, Path]:
        owner_root = self._owner_root(agent_id)
        return (
            owner_root,
            owner_root / "home",
            owner_root / "tmp",
            owner_root / "tasks",
            owner_root / "work",
        )

    def _owner_root(self, agent_id: str) -> Path:
        return self.runtime_root / "agents" / self._component(agent_id, "agent_id")

    def _output_path(self, row: dict[str, Any]) -> Path:
        output_path = self.policy.resolve(str(row["output_path"]))
        expected = self._owner_root(str(row["agent_id"])) / "tasks"
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
            raise self._error("validation", "invalid_path", "Shell cwd must be a non-empty string")
        work_dir = self.agent_work_root(agent_id)
        path = Path(raw_cwd).expanduser()
        if not path.is_absolute() and raw_cwd in {".", "agent"}:
            return work_dir
        if not path.is_absolute() and (raw_cwd == "shared" or raw_cwd.startswith("shared/")):
            if shared_root is None:
                raise self._error(
                    "permission",
                    "shared_workspace_unavailable",
                    "The shared Agent workspace is not available",
                )
            suffix = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
            return self._resolve_shell_subpath(shared_root, suffix)
        if not path.is_absolute() and (raw_cwd == "project" or raw_cwd.startswith("project/")):
            suffix = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
            return self._resolve_shell_subpath(self.policy.root, suffix)
        if not path.is_absolute() and (raw_cwd.startswith("agent/") or raw_cwd == "agent"):
            suffix = Path(*path.parts[1:]) if len(path.parts) > 1 else Path()
            return self._resolve_shell_subpath(work_dir, suffix)
        base = self.policy.root if path.is_absolute() else work_dir
        return self._resolve_shell_subpath(base, path)

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
            raise self._error("validation", "not_a_directory", "Shell cwd is not a directory")
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
        pwn_cache = cache_dir / f".pwntools-cache-{sys.version_info.major}.{sys.version_info.minor}"
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
    def _append_output(path: Path, content: str) -> None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(content)

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
