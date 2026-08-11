"""OpenVPN lifecycle management for local Runtime tests.

This module deliberately lives under ``scripts``.  Production Runtime code only
depends on the small asynchronous lifecycle interface and never imports this
OpenVPN implementation.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
from typing import Final


READY_MARKER: Final = "Initialization Sequence Completed"
DEFAULT_STARTUP_TIMEOUT_SECONDS: Final = 60.0
DEFAULT_STOP_TIMEOUT_SECONDS: Final = 10.0


class VPNManagerError(RuntimeError):
    """A safe, user-facing OpenVPN lifecycle error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class VPNStatus:
    """Current state of the managed OpenVPN process."""

    state: str
    config_path: Path
    pid: int | None
    ready: bool
    returncode: int | None


def discover_vpn_config(project_root: Path, explicit: Path | None = None) -> Path:
    """Resolve one local ``.ovpn`` file without guessing between candidates."""

    if explicit is not None:
        config = explicit.expanduser().resolve()
        if config.suffix.lower() != ".ovpn":
            raise VPNManagerError(
                "invalid_vpn_config",
                "VPN config must be an .ovpn file",
            )
        if not config.is_file():
            raise VPNManagerError(
                "vpn_config_not_found",
                f"VPN config was not found: {config}",
            )
        return config

    config_dir = project_root.resolve() / "config" / "vpn"
    candidates = sorted(path.resolve() for path in config_dir.glob("*.ovpn") if path.is_file())
    if not candidates:
        raise VPNManagerError(
            "vpn_config_not_found",
            f"No .ovpn file was found in {config_dir}",
        )
    if len(candidates) > 1:
        raise VPNManagerError(
            "ambiguous_vpn_config",
            "Multiple .ovpn files were found; select one with --vpn-config",
        )
    return candidates[0]


def resolve_openvpn_binary(configured: str | Path | None = None) -> Path:
    """Find the OpenVPN executable from an override, PATH, or Homebrew."""

    override = str(configured) if configured is not None else os.environ.get("OPENVPN_BIN")
    if override:
        resolved = shutil.which(override) if os.sep not in override else override
        if resolved:
            # Keep symlinks intact.  macOS sudoers rules commonly allow the
            # Homebrew shim (for example /opt/homebrew/sbin/openvpn), while
            # resolving it to Cellar/... changes the command being authorized.
            path = Path(resolved).expanduser().absolute()
            if path.is_file() and os.access(path, os.X_OK):
                return path
        raise VPNManagerError(
            "openvpn_not_found",
            "Configured OpenVPN executable was not found or is not executable",
        )
    candidates: list[str | None] = [
        shutil.which("openvpn"),
        "/opt/homebrew/opt/openvpn/sbin/openvpn",
        "/usr/local/opt/openvpn/sbin/openvpn",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(candidate) if os.sep not in candidate else candidate
        if resolved:
            path = Path(resolved).expanduser().absolute()
            if path.is_file() and os.access(path, os.X_OK):
                return path
    raise VPNManagerError(
        "openvpn_not_found",
        "OpenVPN was not found; install it or set OPENVPN_BIN",
    )


class VPNManager:
    """Own exactly one local OpenVPN subprocess and its process group."""

    def __init__(
        self,
        config_path: Path,
        *,
        openvpn_binary: str | Path | None = None,
        startup_timeout_seconds: float = DEFAULT_STARTUP_TIMEOUT_SECONDS,
        stop_timeout_seconds: float = DEFAULT_STOP_TIMEOUT_SECONDS,
        use_sudo: bool = True,
        sudo_binary: str | Path | None = None,
    ) -> None:
        if startup_timeout_seconds <= 0:
            raise ValueError("startup_timeout_seconds must be positive")
        if stop_timeout_seconds <= 0:
            raise ValueError("stop_timeout_seconds must be positive")
        self.config_path = config_path.expanduser().resolve()
        self._configured_openvpn_binary = openvpn_binary
        self.startup_timeout_seconds = startup_timeout_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self.use_sudo = use_sudo
        self._configured_sudo_binary = sudo_binary
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._ready_event: asyncio.Event | None = None
        self._failure_future: asyncio.Future[VPNManagerError] | None = None
        self._startup_error: VPNManagerError | None = None
        self._ready = False
        self._closing = False
        self._lock = asyncio.Lock()
        self._recent_output: deque[str] = deque(maxlen=30)

    @property
    def status(self) -> VPNStatus:
        process = self._process
        if self._closing and process is not None and process.returncode is None:
            state = "stopping"
        elif self._closing:
            state = "stopped"
        elif self._ready and process is not None and process.returncode is None:
            state = "connected"
        elif process is not None and process.returncode is None:
            state = "starting"
        elif process is not None:
            state = "failed"
        else:
            state = "idle"
        return VPNStatus(
            state=state,
            config_path=self.config_path,
            pid=process.pid if process is not None else None,
            ready=self._ready,
            returncode=process.returncode if process is not None else None,
        )

    async def start(self) -> VPNStatus:
        """Start OpenVPN and wait until its initialization sequence completes."""

        async with self._lock:
            process = self._process
            if self._ready and process is not None and process.returncode is None:
                return self.status
            if process is not None:
                raise VPNManagerError(
                    "vpn_session_ended",
                    "This VPN session has already ended and will not be restarted",
                )
            if self.config_path.suffix.lower() != ".ovpn" or not self.config_path.is_file():
                raise VPNManagerError(
                    "vpn_config_not_found",
                    f"VPN config was not found: {self.config_path}",
                )

            openvpn = resolve_openvpn_binary(self._configured_openvpn_binary)
            command = [str(openvpn), "--config", str(self.config_path)]
            if self.use_sudo:
                sudo = self._resolve_sudo_binary()
                await self._check_sudo(sudo, openvpn)
                command = [str(sudo), "-n", *command]

            loop = asyncio.get_running_loop()
            self._ready_event = asyncio.Event()
            self._failure_future = loop.create_future()
            self._startup_error = None
            self._ready = False
            self._closing = False
            self._recent_output.clear()
            try:
                terminal_stdin = self._open_terminal_stdin()
                try:
                    self._process = await asyncio.create_subprocess_exec(
                        *command,
                        stdin=terminal_stdin,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                        process_group=0,
                    )
                finally:
                    if terminal_stdin is not None:
                        os.close(terminal_stdin)
            except OSError as exc:
                raise VPNManagerError(
                    "vpn_start_failed",
                    f"OpenVPN could not be started: {type(exc).__name__}",
                ) from exc

            self._reader_task = asyncio.create_task(
                self._read_output(),
                name=f"aion-openvpn-output-{self._process.pid}",
            )
            try:
                await asyncio.wait_for(
                    self._ready_event.wait(),
                    timeout=self.startup_timeout_seconds,
                )
                await asyncio.sleep(0)
                if self._startup_error is not None:
                    raise self._startup_error
                if not self._ready or self._process.returncode is not None:
                    raise self._process_error("OpenVPN exited before becoming ready")
                return self.status
            except TimeoutError as exc:
                await self._terminate_process()
                raise VPNManagerError(
                    "vpn_start_timeout",
                    f"OpenVPN did not become ready within {self.startup_timeout_seconds:g} seconds",
                ) from exc
            except BaseException:
                await self._terminate_process()
                raise

    async def wait_failure(self) -> None:
        """Wait until a connected process exits unexpectedly, then raise its error."""

        future = self._failure_future
        if future is None:
            raise VPNManagerError("vpn_not_started", "VPN has not been started")
        error = await asyncio.shield(future)
        raise error

    async def close(self) -> None:
        """Stop only the process group created by this manager."""

        async with self._lock:
            if self._process is None:
                return
            self._closing = True
            await self._terminate_process()
            self._ready = False

    async def _read_output(self) -> None:
        process = self._process
        ready_event = self._ready_event
        if process is None or process.stdout is None or ready_event is None:
            return
        try:
            while True:
                raw = await process.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    self._recent_output.append(self._safe_line(line))
                if READY_MARKER in line and not self._ready:
                    self._ready = True
                    ready_event.set()
            returncode = await process.wait()
            if not self._closing:
                error = self._process_error(
                    f"OpenVPN exited unexpectedly with status {returncode}"
                )
                if not self._ready:
                    self._startup_error = error
                    ready_event.set()
                failure = self._failure_future
                if failure is not None and not failure.done():
                    failure.set_result(error)
        except asyncio.CancelledError:
            raise

    async def _terminate_process(self) -> None:
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=self.stop_timeout_seconds,
                )
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        reader = self._reader_task
        if reader is not None and reader is not asyncio.current_task():
            try:
                await reader
            except asyncio.CancelledError:
                pass

    def _resolve_sudo_binary(self) -> Path:
        configured = self._configured_sudo_binary
        candidate = str(configured) if configured is not None else shutil.which("sudo")
        if not candidate:
            raise VPNManagerError("sudo_not_found", "sudo was not found")
        path = Path(candidate).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise VPNManagerError("sudo_not_found", "sudo was not found")
        return path

    async def _check_sudo(self, sudo: Path, openvpn: Path) -> None:
        """Verify sudo can run this exact binary without prompting."""

        terminal_stdin = self._open_terminal_stdin()
        try:
            process = await asyncio.create_subprocess_exec(
                str(sudo),
                "-n",
                str(openvpn),
                "--version",
                stdin=terminal_stdin,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                process_group=0,
            )
            returncode = await process.wait()
        except OSError as exc:
            raise VPNManagerError(
                "sudo_check_failed",
                f"sudo could not be checked: {type(exc).__name__}",
            ) from exc
        finally:
            if terminal_stdin is not None:
                os.close(terminal_stdin)
        if returncode != 0:
            raise VPNManagerError(
                "sudo_auth_required",
                "sudo cannot run OpenVPN without prompting; run `sudo -v` "
                "and verify that this OpenVPN binary is allowed",
            )

    @staticmethod
    def _open_terminal_stdin() -> int | None:
        """Use the caller's TTY when sudo timestamps are TTY-scoped."""

        try:
            return os.open("/dev/tty", os.O_RDONLY)
        except OSError:
            return None

    def _process_error(self, prefix: str) -> VPNManagerError:
        process = self._process
        if (
            process is not None
            and process.returncode == 0
            and any(
                "halt command was pushed by server" in line.lower()
                for line in self._recent_output
            )
        ):
            return VPNManagerError(
                "vpn_remote_halt",
                "The VPN server closed the managed connection",
            )
        if any(
            "sudo: a password is required" in line.lower()
            for line in self._recent_output
        ):
            return VPNManagerError(
                "sudo_auth_required",
                "sudo could not use the cached terminal credentials to run OpenVPN; "
                "run `sudo -v` in this terminal and try again",
            )
        detail = "\n".join(self._recent_output)
        message = f"{prefix}. Recent OpenVPN output:\n{detail}" if detail else prefix
        return VPNManagerError("vpn_process_failed", message)

    def _safe_line(self, line: str) -> str:
        return line.replace(str(self.config_path), "<vpn-config>")[:2_000]
