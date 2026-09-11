from __future__ import annotations

import asyncio
import struct
from pathlib import Path
from typing import Any

import pytest

from tools.binary.models import (
    PwnProcessOpenArguments,
    PwnSessionIoArguments,
    PwnTcpOpenArguments,
)
from tools.binary.session import BinarySessionError, BinarySessionManager


class FakeWriter:
    def __init__(self) -> None:
        self.sent = bytearray()
        self.closed = False

    def write(self, value: bytes) -> None:
        self.sent.extend(value)

    async def drain(self) -> None:
        return None

    def is_closing(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class FakeProcess:
    pid = 1234

    def __init__(self, reader: asyncio.StreamReader, writer: FakeWriter) -> None:
        self.stdout = reader
        self.stdin = writer
        self.returncode: int | None = None

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode or 0


class FakeSandbox:
    def prepare(self) -> None:
        return None

    def command_argv(self, argv: list[str], **_: Any) -> list[str]:
        return ["/usr/bin/bwrap", *argv]


def _elf64(path: Path) -> None:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        0x3E,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 0)
    path.write_bytes(ident + header + program_header)


@pytest.mark.asyncio
async def test_linux_process_session_is_binary_safe_and_stateful(
    tmp_path: Path, monkeypatch
) -> None:
    signals = []
    monkeypatch.setattr(
        "tools.binary.session.os.killpg", lambda pid, sig: signals.append((pid, sig))
    )
    target = tmp_path / "target"
    _elf64(target)
    readers: list[asyncio.StreamReader] = []

    async def process_factory(*_: Any, **__: Any) -> FakeProcess:
        reader = asyncio.StreamReader()
        writer = FakeWriter()
        reader.feed_data(b"ready> ")
        readers.append(reader)
        return FakeProcess(reader, writer)

    manager = BinarySessionManager(
        tmp_path,
        sandbox=FakeSandbox(),
        platform_name="Linux",
        machine_name="x86_64",
        process_factory=process_factory,
    )
    opened = await manager.open_process(
        PwnProcessOpenArguments.model_validate(
            {"file_path": "target", "startup_wait_seconds": 0.05}
        )
    )

    assert opened["kind"] == "process"
    assert opened["startup"]["output_preview"] == "ready> "
    session = manager._sessions[opened["session_id"]]
    readers[0].feed_data(b"\x00\xffdone\n")
    result = await manager.io(
        PwnSessionIoArguments.model_validate(
            {
                "session_id": opened["session_id"],
                "send_base64": "AQI=",
                "recv_until_text": "done",
            }
        )
    )

    assert bytes(session.writer.sent) == b"\x01\x02"
    assert result["output_base64"] == "AP9kb25l"
    await manager.close_all()
    assert len(signals) == 2


@pytest.mark.asyncio
async def test_process_session_rejects_non_linux_runner(tmp_path: Path) -> None:
    target = tmp_path / "target"
    _elf64(target)
    manager = BinarySessionManager(
        tmp_path,
        sandbox=FakeSandbox(),
        platform_name="Darwin",
        machine_name="arm64",
    )

    with pytest.raises(BinarySessionError) as error:
        await manager.open_process(
            PwnProcessOpenArguments.model_validate({"file_path": "target"})
        )

    assert error.value.code == "linux_execution_required"


@pytest.mark.asyncio
async def test_tcp_session_uses_bounded_binary_io() -> None:
    reader = asyncio.StreamReader()
    writer = FakeWriter()
    reader.feed_data(b"OK\x00\xff\n")

    async def connection_factory(
        *_: Any, **__: Any
    ) -> tuple[asyncio.StreamReader, FakeWriter]:
        return reader, writer

    manager = BinarySessionManager(
        ".",
        platform_name="Darwin",
        connection_factory=connection_factory,
    )
    opened = await manager.open_tcp(
        PwnTcpOpenArguments.model_validate({"host": "127.0.0.1", "port": 1})
    )
    result = await manager.io(
        PwnSessionIoArguments.model_validate(
            {"session_id": opened["session_id"], "max_bytes": 32}
        )
    )

    assert opened["kind"] == "tcp"
    assert result["output_base64"] == "T0sA/wo="
    await manager.close_all()
