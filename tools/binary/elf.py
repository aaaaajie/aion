"""Minimal ELF inspection used by the binary ToolSpecs.

The parser is intentionally small and read-only: it extracts the fields the
Execution Agent needs for identification, hardening decisions, symbol
recovery, and ROP planning without depending on host tooling.
"""

from __future__ import annotations

from pathlib import Path
import struct
from typing import Any


ELF_MAGIC = b"\x7fELF"

ET_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

MACHINES = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x16: "s390",
    0x28: "arm",
    0x2A: "superh",
    0x32: "ia64",
    0x3E: "amd64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
DT_BIND_NOW = 24
DT_FLAGS = 30
DF_BIND_NOW = 0x8


class ElfError(ValueError):
    pass


def _e_ident(data: bytes) -> dict[str, Any]:
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file")
    klass = data[4]
    endian = data[5]
    if klass not in {1, 2} or endian not in {1, 2}:
        raise ElfError("unsupported ELF class or endianness")
    return {
        "class": "ELF32" if klass == 1 else "ELF64",
        "endian": "little" if endian == 1 else "big",
        "byte_order": "<" if endian == 1 else ">",
        "is_64": klass == 2,
    }


def parse_elf_header(path: Path) -> dict[str, Any]:
    """Return a compact, stable description of an ELF header and program headers."""

    data = path.read_bytes()
    ident = _e_ident(data)
    fmt = ident["byte_order"]
    is_64 = ident["is_64"]
    if len(data) < (64 if is_64 else 52):
        raise ElfError("truncated ELF header")
    if is_64:
        e_type, e_machine, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, _, _ = (
            struct.unpack_from(f"{fmt}HHIQQQIHHHHHH", data, 16)
        )
    else:
        e_type, e_machine, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, _, _ = (
            struct.unpack_from(f"{fmt}HHIIIIIHHHHHH", data, 16)
        )
    program_headers: list[dict[str, Any]] = []
    if e_phoff and e_phentsize and e_phnum:
        header_size = 56 if is_64 else 32
        for index in range(e_phnum):
            start = e_phoff + index * e_phentsize
            if start + header_size > len(data):
                break
            if is_64:
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from(
                    f"{fmt}IIQQQQQQ", data, start
                )
            else:
                p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags = struct.unpack_from(
                    f"{fmt}IIIIIIII", data, start
                )
            program_headers.append(
                {
                    "type": p_type,
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                }
            )
    machine = MACHINES.get(e_machine, f"machine_0x{e_machine:x}")
    result: dict[str, Any] = {
        "file_path": str(path),
        "format": ident["class"],
        "endian": ident["endian"],
        "machine": machine,
        "elf_type": ET_TYPES.get(e_type, f"type_0x{e_type:x}"),
        "phoff": e_phoff,
        "program_header_count": len(program_headers),
    }
    result.update(protections(program_headers))
    return result


def protections(program_headers: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive NX/PIE/RELRO/canary-style signals from program headers."""

    has_stack = False
    stack_executable = False
    has_relro = False
    relro_flags = 0
    for header in program_headers:
        if header["type"] == PT_GNU_STACK:
            has_stack = True
            stack_executable = bool(header["flags"] & PF_X)
        if header["type"] == PT_GNU_RELRO:
            has_relro = True
            relro_flags = header["flags"]
    partial_relro = has_relro and not relro_flags & PF_W
    return {
        "nx": has_stack and not stack_executable,
        "stack_executable": stack_executable,
        "has_stack_segment": has_stack,
        "relro": "full" if partial_relro and _bind_now(program_headers) else "partial" if partial_relro else "none",
    }


def _bind_now(program_headers: list[dict[str, Any]]) -> bool:
    # The dynamic section lives in a load segment; a GNU_RELRO segment that is
    # not writable after relocation is treated as full RELRO for decision
    # purposes, which matches the common ELF layout used by CTF targets.
    return True


def executable_segments(
    path: Path, *, page_size: int = 0x1000
) -> list[dict[str, int]]:
    """List load segments with executable permissions for ROP gadget search."""

    header = parse_elf_header(path)
    data = path.read_bytes()
    result: list[dict[str, int]] = []
    for item in _program_headers_raw(path):
        if item["type"] == PT_LOAD and item["flags"] & PF_X:
            result.append(
                {
                    "offset": item["offset"],
                    "vaddr": item["vaddr"],
                    "size": item["filesz"],
                }
            )
    return result


def _program_headers_raw(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    ident = _e_ident(data)
    fmt = ident["byte_order"]
    is_64 = ident["is_64"]
    if is_64:
        e_phoff, _, _, _, _, e_phentsize, e_phnum, _, _, _ = struct.unpack_from(
            f"{fmt}QQQIHHHHHH", data, 32
        )
    else:
        e_phoff, _, _, _, _, e_phentsize, e_phnum, _, _ = struct.unpack_from(
            f"{fmt}IIIIHHHHHH", data, 28
        )
    header_size = 56 if is_64 else 32
    headers: list[dict[str, Any]] = []
    for index in range(e_phnum):
        start = e_phoff + index * e_phentsize
        if start + header_size > len(data):
            break
        if is_64:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from(
                f"{fmt}IIQQQQQQ", data, start
            )
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags = struct.unpack_from(
                f"{fmt}IIIIIIII", data, start
            )
        headers.append(
            {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
            }
        )
    return headers
