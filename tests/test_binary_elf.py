from __future__ import annotations

import struct
from pathlib import Path

from tools.binary.elf import parse_elf_header


def test_parse_elf64_program_header_fields(tmp_path: Path) -> None:
    path = tmp_path / "fixture"
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
    program_header = struct.pack(
        "<IIQQQQQQ",
        0x6474E551,
        6,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    path.write_bytes(ident + header + program_header)

    result = parse_elf_header(path)

    assert result["format"] == "ELF64"
    assert result["machine"] == "amd64"
    assert result["program_header_count"] == 1
    assert result["nx"] is True
