"""Persistent, Run-owned foreground and background Shell execution."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import signal
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
ShellTaskStatus = Literal[
    "running",
    "completed",
    "failed",
    "timeout",
    "stopped",
    "interrupted",
]


class SandboxBackend:
    """Build a mandatory macOS or Linux OS-sandbox command."""

    def __init__(
        self,
        root: Path,
        executable: str | None = None,
        platform_name: str | None = None,
        read_only_paths: Sequence[Path] = (),
    ) -> None:
        self.root = root
        self.read_only_paths = tuple(
            dict.fromkeys(path.expanduser().resolve(strict=True) for path in read_only_paths)
        )
        self.platform = platform_name or platform.system()
        if executable is not None:
            self.executable = executable
        elif self.platform == "Darwin":
            self.executable = "/usr/bin/sandbox-exec"
        elif self.platform == "Linux":
            self.executable = shutil.which("bwrap") or "/usr/bin/bwrap"
        else:
            self.executable = ""

    @property
    def available(self) -> bool:
        return (
            self.platform in {"Darwin", "Linux"}
            and bool(self.executable)
            and Path(self.executable).is_file()
            and os.access(self.executable, os.X_OK)
        )

    def command(
        self,
        shell_command: str,
        cwd: Path | None = None,
        temp_dir: Path | None = None,
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
                self._macos_profile(),
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-lc",
                shell_command,
            ]
        return self._linux_command(shell_command, cwd, temp_dir)

    def _macos_profile(self) -> str:
        root = json.dumps(str(self.root))
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
        lines = [
            "(version 1)",
            "(allow default)",
            "(deny file-read* (subpath \"/Users\"))",
            f"(allow file-read* (subpath {root}))",
            "(deny file-write* (subpath \"/\"))",
            f"(allow file-write* (subpath {root}))",
            "(allow file-write* (literal \"/dev/null\"))",
            "(allow file-read-metadata (subpath \"/\"))",
        ]
        lines.extend(
            f"(allow file-read* (subpath {json.dumps(path)}))"
            for path in system_read_paths
        )
        lines.extend(f"(allow file-read* (subpath {path}))" for path in read_only_paths)
        lines.extend(f"(deny file-write* (subpath {path}))" for path in read_only_paths)
        return "\n".join(lines)

    def _linux_command(
        self,
        shell_command: str,
        cwd: Path | None,
        temp_dir: Path | None,
    ) -> list[str]:
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

        read_only_bind_paths = [
            (str(path), str(path)) for path in self.read_only_paths
        ]
        destination_parents: set[Path] = set()
        for _, destination in bind_paths + read_only_bind_paths + [
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
        command.extend(["--bind", str(self.root), str(self.root)])
        for source, destination in read_only_bind_paths:
            command.extend(["--ro-bind", source, destination])
        if cwd is not None:
            command.extend(["--chdir", str(cwd)])
        command.extend(["/bin/bash", "--noprofile", "--norc", "-lc", shell_command])
        return command


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

    def __init__(self, manager: "ShellTaskManager", agent_id: str) -> None:
        self.manager = manager
        self.agent_id = agent_id

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
        )

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
            policy.root, read_only_paths=read_only_paths
        )
        self.environment = dict(environment or {})
        self.psutil = psutil_module
        self.clock = clock
        self.reap_interval_seconds = reap_interval_seconds
        self.runtime_root = policy.root / ".system-tools" / "runs" / self.run_id
        self._live: dict[str, LiveShellTask] = {}
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

    def bind(self, agent_id: str) -> AgentShellClient:
        return AgentShellClient(self, self._component(agent_id, "agent_id"))

    async def run_shell(
        self,
        agent_id: str,
        command: str,
        *,
        cwd: str = ".",
        timeout: float = 30.0,
        max_output_chars: int = 30_000,
        run_in_background: bool = False,
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
        working_directory = self.policy.resolve(cwd, must_exist=True)
        if not working_directory.is_dir():
            raise self._error(
                "validation", "not_a_directory", "Shell cwd is not a directory"
            )
        if len(command) > 100_000:
            raise self._error(
                "validation", "command_too_long", "Shell command is too long"
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

        owner_root, home_dir, temp_dir, task_dir = self._owner_directories(agent_id)
        for directory in (owner_root, home_dir, temp_dir, task_dir, home_dir / ".config"):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        task_id = f"task-{uuid.uuid4().hex}"
        output_path = task_dir / f"{task_id}.log"
        output_path.touch(mode=0o600, exist_ok=False)
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                *self.sandbox.command(command, working_directory, temp_dir),
                cwd=str(working_directory),
                env=self._safe_environment(home_dir, temp_dir, working_directory),
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
                cwd=self.policy.relative(working_directory),
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
        await self._stop_live_tasks(status="stopped", agent_id=agent_id)
        rows = await self.service.list_shell_tasks(self.run_id, agent_id=agent_id)
        for row in rows:
            if row["status"] == "running":
                await self._finish_persisted(row, status="stopped")
        owner_root = self._owner_root(agent_id)
        if owner_root.exists() or owner_root.is_symlink():
            await asyncio.to_thread(self._remove_tree, owner_root)
        await self._mark_rows_cleaned(rows, reason="agent_terminal")

    async def finish_run(self) -> None:
        if self._closed:
            return
        await self._stop_live_tasks(status="stopped")
        rows = await self.service.list_shell_tasks(self.run_id)
        for row in rows:
            if row["status"] == "running":
                await self._finish_persisted(row, status="stopped")
        if self.runtime_root.exists() or self.runtime_root.is_symlink():
            await asyncio.to_thread(self._remove_tree, self.runtime_root)
        await self._mark_rows_cleaned(rows, reason="run_terminal")
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
    ) -> tuple[Path, Path, Path, Path]:
        owner_root = self._owner_root(agent_id)
        return owner_root, owner_root / "home", owner_root / "tmp", owner_root / "tasks"

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
        self, home_dir: Path, temp_dir: Path, working_directory: Path
    ) -> dict[str, str]:
        path_entries = [
            str(self.policy.root / ".venv" / "bin"),
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/home/linuxbrew/.linuxbrew/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ]
        environment = {
            "HOME": str(home_dir),
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
        return environment

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
            shutil.rmtree(path)

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
