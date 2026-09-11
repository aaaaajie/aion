"""Stateful Linux ELF and TCP sessions for bounded pwn workflows."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
import os
import signal
import platform
from pathlib import Path
import ssl
import time
from typing import Any
from uuid import uuid4

from tools.system.shell import SandboxBackend, SystemToolError
from tools.workspace import is_runtime_control_plane_path

from .elf import ElfError, parse_elf_header
from .models import (
    PwnProcessOpenArguments,
    PwnSessionIoArguments,
    PwnTcpOpenArguments,
)


class BinarySessionError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


@dataclass
class LiveBinarySession:
    session_id: str
    kind: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    process: asyncio.subprocess.Process | None = None
    buffer: bytearray = field(default_factory=bytearray)
    io_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class BinarySessionManager:
    """Own process/socket lifetime and expose bounded binary-safe I/O."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        sandbox: SandboxBackend | None = None,
        on_process_started: Callable[[int], Awaitable[None]] | None = None,
        platform_name: str | None = None,
        machine_name: str | None = None,
        process_factory: Callable[
            ..., Awaitable[asyncio.subprocess.Process]
        ] = asyncio.create_subprocess_exec,
        connection_factory: Callable[
            ..., Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
        ] = asyncio.open_connection,
    ) -> None:
        self.root = Path(root).resolve()
        self._on_process_started = on_process_started
        self.platform_name = platform_name or platform.system()
        self.machine_name = (machine_name or platform.machine()).lower()
        self.sandbox = sandbox or SandboxBackend(
            self.root, read_only_paths=(self.root,)
        )
        self._process_factory = process_factory
        self._connection_factory = connection_factory
        self._sessions: dict[str, LiveBinarySession] = {}
        self._closed = False

    async def open_process(self, arguments: PwnProcessOpenArguments) -> dict[str, Any]:
        self._ensure_open()
        path = self._resolve(arguments.file_path)
        cwd = self._resolve(arguments.cwd)
        if not path.is_file():
            raise BinarySessionError(
                "file_not_found",
                "The target ELF does not exist",
                details={"file_path": str(path)},
            )
        if not cwd.is_dir():
            raise BinarySessionError(
                "cwd_not_found",
                "The process working directory does not exist",
                details={"cwd": str(cwd)},
            )
        header = self._validate_linux_elf(path)
        try:
            command = self.sandbox.command_argv([str(path), *arguments.argv], cwd=cwd)
        except SystemToolError as exc:
            raise BinarySessionError(exc.code, str(exc)) from exc
        environment = {
            "HOME": "/tmp",
            "LC_ALL": "C",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            **arguments.env,
            "PWD": str(cwd),
        }
        try:
            process = await self._process_factory(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=None,
                env=environment,
                start_new_session=True,
            )
        except OSError as exc:
            raise BinarySessionError(
                "process_start_failed",
                f"The target process could not be started: {exc}",
            ) from exc
        if process.stdin is None or process.stdout is None:
            await self._terminate_process(process)
            raise BinarySessionError(
                "process_stream_unavailable",
                "The target process did not expose stdin/stdout",
            )
        if self._on_process_started:
            try:
                await self._on_process_started(process.pid)
            except BaseException:
                await self._terminate_process(process)
                raise
        session = LiveBinarySession(
            session_id=f"pwn_{uuid4().hex}",
            kind="process",
            reader=process.stdout,
            writer=process.stdin,
            process=process,
        )
        self._sessions[session.session_id] = session
        startup = await self._receive(
            session,
            until=None,
            timeout=arguments.startup_wait_seconds,
            max_bytes=arguments.max_startup_bytes,
        )
        return {
            "session_id": session.session_id,
            "kind": session.kind,
            "pid": process.pid,
            "target": {
                "file_path": str(path),
                "machine": header["machine"],
                "format": header["format"],
            },
            "startup": startup,
        }

    async def open_tcp(self, arguments: PwnTcpOpenArguments) -> dict[str, Any]:
        self._ensure_open()
        context = ssl.create_default_context() if arguments.tls else None
        kwargs: dict[str, Any] = {"ssl": context}
        if arguments.tls and arguments.server_hostname is not None:
            kwargs["server_hostname"] = arguments.server_hostname
        try:
            reader, writer = await asyncio.wait_for(
                self._connection_factory(arguments.host, arguments.port, **kwargs),
                timeout=arguments.timeout,
            )
        except asyncio.TimeoutError as exc:
            raise BinarySessionError(
                "tcp_connect_timeout", "TCP connection timed out"
            ) from exc
        except OSError as exc:
            raise BinarySessionError(
                "tcp_connect_failed", f"TCP connection failed: {exc}"
            ) from exc
        session = LiveBinarySession(
            session_id=f"pwn_{uuid4().hex}",
            kind="tcp_tls" if arguments.tls else "tcp",
            reader=reader,
            writer=writer,
        )
        self._sessions[session.session_id] = session
        return {
            "session_id": session.session_id,
            "kind": session.kind,
            "remote": {
                "host": arguments.host,
                "port": arguments.port,
                "tls": arguments.tls,
            },
        }

    async def io(self, arguments: PwnSessionIoArguments) -> dict[str, Any]:
        session = self._session(arguments.session_id)
        async with session.io_lock:
            payload = self._encode(arguments)
            if payload:
                session.writer.write(payload)
                await session.writer.drain()
            marker = self._decode_marker(arguments)
            return await self._receive(
                session,
                until=marker,
                timeout=arguments.timeout,
                max_bytes=arguments.max_bytes,
            )

    async def close(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            raise BinarySessionError(
                "session_invalidated",
                "This binary handle is invalid or belongs to a previous resource generation; reopen the session",
            )
        await self._close_session(session)
        self._sessions.pop(session_id, None)
        return {"session_id": session_id, "closed": True}

    async def close_all(self) -> None:
        self._closed = True
        sessions = list(self._sessions.values())
        results = await asyncio.gather(
            *(self._close_session(item) for item in sessions), return_exceptions=True
        )
        failures = []
        for session, result in zip(sessions, results):
            if isinstance(result, Exception):
                failures.append(result)
            else:
                self._sessions.pop(session.session_id, None)
        if failures:
            raise ExceptionGroup("Binary resource cleanup failed", failures)

    def _ensure_open(self) -> None:
        if self._closed:
            raise BinarySessionError(
                "manager_closed", "The binary session manager is closed"
            )

    def _session(self, session_id: str) -> LiveBinarySession:
        session = self._sessions.get(session_id)
        if session is None:
            raise BinarySessionError(
                "session_invalidated",
                "This binary handle is invalid or belongs to a previous resource generation; reopen the session",
            )
        if session.writer.is_closing():
            raise BinarySessionError(
                "session_closed", "The binary session is already closed"
            )
        return session

    def _resolve(self, value: str) -> Path:
        path = (self.root / value).resolve(strict=False)
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise BinarySessionError(
                "path_outside_workspace", "Path escapes the workspace"
            ) from exc
        if is_runtime_control_plane_path(self.root, path):
            raise BinarySessionError(
                "path_protected",
                "Runtime control-plane paths are unavailable",
            )
        return path

    def _validate_linux_elf(self, path: Path) -> dict[str, Any]:
        if self.platform_name != "Linux":
            raise BinarySessionError(
                "linux_execution_required",
                "ELF process sessions can only run on Linux",
            )
        try:
            header = parse_elf_header(path)
        except (ElfError, OSError) as exc:
            raise BinarySessionError(
                "not_elf", f"The target is not a supported ELF: {exc}"
            ) from exc
        host = self.machine_name
        if host in {"x86_64", "amd64"}:
            allowed = {"amd64", "x86"}
        elif host in {"aarch64", "arm64"}:
            allowed = {"aarch64", "arm"}
        else:
            allowed = {host}
        if header["machine"] not in allowed:
            raise BinarySessionError(
                "incompatible_elf_architecture",
                "The ELF architecture is incompatible with the Linux runner",
                details={"host": host, "target": header["machine"]},
            )
        return header

    @staticmethod
    def _encode(arguments: PwnSessionIoArguments) -> bytes:
        if arguments.send_base64 is not None:
            try:
                payload = base64.b64decode(arguments.send_base64, validate=True)
            except ValueError as exc:
                raise BinarySessionError(
                    "invalid_base64", "send_base64 is not valid base64"
                ) from exc
        elif arguments.send_text is not None:
            payload = arguments.send_text.encode("utf-8")
        else:
            payload = b""
        return payload + (b"\n" if arguments.append_newline else b"")

    @staticmethod
    def _decode_marker(arguments: PwnSessionIoArguments) -> bytes | None:
        if arguments.recv_until_base64 is not None:
            try:
                return base64.b64decode(arguments.recv_until_base64, validate=True)
            except ValueError as exc:
                raise BinarySessionError(
                    "invalid_base64", "recv_until_base64 is not valid base64"
                ) from exc
        if arguments.recv_until_text is not None:
            return arguments.recv_until_text.encode("utf-8")
        return None

    async def _receive(
        self,
        session: LiveBinarySession,
        *,
        until: bytes | None,
        timeout: float,
        max_bytes: int,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        data = bytearray()
        timed_out = False
        eof = False
        truncated = False
        while len(data) < max_bytes:
            if session.buffer:
                take = min(max_bytes - len(data), len(session.buffer))
                data.extend(session.buffer[:take])
                del session.buffer[:take]
                if until is not None and until in data:
                    return self._finish_receive(
                        session, data, until, eof, timed_out, truncated
                    )
                if len(data) >= max_bytes:
                    truncated = bool(session.buffer)
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = until is not None or not data
                break
            read_timeout = (
                remaining if not data or until is not None else min(remaining, 0.03)
            )
            try:
                chunk = await asyncio.wait_for(
                    session.reader.read(min(16_384, max_bytes - len(data))),
                    timeout=read_timeout,
                )
            except asyncio.TimeoutError:
                timed_out = until is not None or not data
                break
            if not chunk:
                eof = True
                break
            data.extend(chunk)
            if until is not None and until in data:
                return self._finish_receive(
                    session, data, until, eof, timed_out, truncated
                )
        if len(data) >= max_bytes:
            truncated = True
        return self._receive_result(
            data, eof=eof, timed_out=timed_out, truncated=truncated
        )

    @staticmethod
    def _finish_receive(
        session: LiveBinarySession,
        data: bytearray,
        marker: bytes,
        eof: bool,
        timed_out: bool,
        truncated: bool,
    ) -> dict[str, Any]:
        end = data.index(marker) + len(marker)
        session.buffer.extend(data[end:])
        return BinarySessionManager._receive_result(
            data[:end], eof=eof, timed_out=timed_out, truncated=truncated
        )

    @staticmethod
    def _receive_result(
        data: bytes | bytearray,
        *,
        eof: bool,
        timed_out: bool,
        truncated: bool,
    ) -> dict[str, Any]:
        raw = bytes(data)
        return {
            "output_base64": base64.b64encode(raw).decode("ascii"),
            "output_preview": raw[:4_096].decode("utf-8", errors="replace"),
            "received_bytes": len(raw),
            "eof": eof,
            "timed_out": timed_out,
            "truncated": truncated,
        }

    async def _close_session(self, session: LiveBinarySession) -> None:
        if session.process is not None:
            await self._terminate_process(session.process)
        if not session.writer.is_closing():
            session.writer.close()
            try:
                await asyncio.wait_for(session.writer.wait_closed(), timeout=1.0)
            except (asyncio.TimeoutError, OSError):
                pass

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        # A child can ignore TERM even when its group leader has exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await asyncio.gather(process.wait(), return_exceptions=True)
