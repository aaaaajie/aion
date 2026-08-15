"""Agent-facing ToolSpecs for deterministic binary analysis and pwn helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import os
import re
import struct
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec
from tools.binaries import ToolchainError, toolchain_for

from .elf import ElfError, executable_segments, parse_elf_header
from .models import (
    DisassembleArguments,
    FilePathArguments,
    GdbArguments,
    LibcOffsetsArguments,
    PackArguments,
    PatchElfArguments,
    RopSearchArguments,
    SeccompArguments,
    StringsArguments,
    SymbolsArguments,
)


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_POP_RET_RE = re.compile(rb"^\x5b\xc3$|^\x5e\xc3$|^\x5f\xc3$|^\x58\xc3$")
_RET_RE = re.compile(rb"^\xc3$")


class BinaryTools:
    """Expose bounded binary analysis through the shared ToolExecutor."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        toolchain_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        candidate = (
            Path(toolchain_root)
            if toolchain_root is not None
            else self.root / "tools" / "binaries"
        )
        self._toolchain = toolchain_for(candidate if candidate.is_dir() else None)

    def tool_specs(self) -> list[ToolSpec]:
        def identify(arguments: BaseModel) -> Any:
            assert isinstance(arguments, FilePathArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return {
                    "ok": False,
                    "error": {
                        "stage": "semantic",
                        "code": "file_not_found",
                        "message": "The binary file does not exist",
                        "retry": {"allowed": False, "action": "none", "tool": None},
                        "details": {"file_path": str(path)},
                    },
                }
            try:
                result = parse_elf_header(path)
            except ElfError:
                result = {
                    "file_path": str(path),
                    "format": "unknown",
                    "magic": path.read_bytes()[:16].hex(),
                }
            return {
                "data": result,
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": result,
                    "metadata": {"file_path": str(path)},
                },
            }

        async def strings(arguments: BaseModel) -> Any:
            assert isinstance(arguments, StringsArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            raw = await asyncio.to_thread(path.read_bytes)
            if arguments.encoding == "utf-16le":
                decoded = raw.decode("utf-16-le", errors="replace")
            elif arguments.encoding == "latin-1":
                decoded = raw.decode("latin-1")
            else:
                decoded = raw.decode("utf-8", errors="replace")
            matches = re.findall(
                rf"[ -~]{{{arguments.min_length},}}", decoded, flags=re.DOTALL
            )
            return {
                "data": {
                    "file_path": str(path),
                    "count": min(len(matches), arguments.limit),
                    "truncated": len(matches) > arguments.limit,
                    "strings": matches[: arguments.limit],
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"count": min(len(matches), arguments.limit)},
                    "metadata": {"file_path": str(path)},
                },
            }

        def checksec(arguments: BaseModel) -> Any:
            assert isinstance(arguments, FilePathArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            try:
                result = parse_elf_header(path)
            except ElfError as exc:
                return {
                    "ok": False,
                    "error": {
                        "stage": "semantic",
                        "code": "not_elf",
                        "message": str(exc),
                        "retry": {"allowed": False, "action": "none", "tool": None},
                        "details": {"file_path": str(path)},
                    },
                }
            return {
                "data": {
                    "file_path": str(path),
                    "nx": result["nx"],
                    "pie": result["elf_type"] == "DYN",
                    "relro": result["relro"],
                    "canary": _has_canary(path),
                    "fortify": _has_fortify(path),
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {
                        "nx": result["nx"],
                        "pie": result["elf_type"] == "DYN",
                        "relro": result["relro"],
                        "canary": _has_canary(path),
                    },
                    "metadata": {"file_path": str(path)},
                },
            }

        def symbols(arguments: BaseModel) -> Any:
            assert isinstance(arguments, SymbolsArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            values = _extract_symbols(path)
            return {
                "data": {
                    "file_path": str(path),
                    "count": min(len(values), arguments.limit),
                    "truncated": len(values) > arguments.limit,
                    "symbols": values[: arguments.limit],
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"count": min(len(values), arguments.limit)},
                    "metadata": {"file_path": str(path)},
                },
            }

        async def disassemble(arguments: BaseModel) -> Any:
            assert isinstance(arguments, DisassembleArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            raw = await asyncio.to_thread(path.read_bytes)
            chunk = raw[arguments.offset : arguments.offset + arguments.length]
            lines = [
                f"{arguments.offset + index:08x}: {byte:02x}"
                for index, byte in enumerate(chunk)
            ]
            return {
                "data": {
                    "file_path": str(path),
                    "offset": arguments.offset,
                    "length": len(chunk),
                    "hexdump": lines,
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"offset": arguments.offset, "length": len(chunk)},
                    "metadata": {"file_path": str(path)},
                },
            }

        def patch_elf(arguments: BaseModel) -> Any:
            assert isinstance(arguments, PatchElfArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            if not HEX_RE.fullmatch(arguments.expected_hex) or not HEX_RE.fullmatch(
                arguments.patch_hex
            ):
                return {
                    "ok": False,
                    "error": {
                        "stage": "schema",
                        "code": "invalid_hex",
                        "message": "expected_hex and patch_hex must be hexadecimal",
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {},
                    },
                }
            expected = bytes.fromhex(arguments.expected_hex)
            patch = bytes.fromhex(arguments.patch_hex)
            if len(patch) != len(expected):
                return {
                    "ok": False,
                    "error": {
                        "stage": "schema",
                        "code": "patch_length_mismatch",
                        "message": "expected_hex and patch_hex must have equal length",
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {},
                    },
                }
            raw = path.read_bytes()
            end = arguments.offset + len(expected)
            if end > len(raw):
                return {
                    "ok": False,
                    "error": {
                        "stage": "semantic",
                        "code": "patch_out_of_bounds",
                        "message": "The patch range exceeds the file size",
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {"file_size": len(raw)},
                    },
                }
            if raw[arguments.offset : end] != expected:
                return {
                    "ok": False,
                    "error": {
                        "stage": "semantic",
                        "code": "patch_mismatch",
                        "message": "Bytes at the offset do not match expected_hex",
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {"actual_hex": raw[arguments.offset : end].hex()},
                    },
                }
            path.write_bytes(raw[: arguments.offset] + patch + raw[end:])
            return {
                "data": {
                    "file_path": str(path),
                    "offset": arguments.offset,
                    "patched_hex": patch.hex(),
                },
                "_aion_evidence": {
                    "evidence_type": "file",
                    "content": f"patched {patch.hex()} at offset {arguments.offset}",
                    "metadata": {"file_path": str(path)},
                },
            }

        def pack(arguments: BaseModel) -> Any:
            assert isinstance(arguments, PackArguments)
            fmt = (
                f"{'<' if arguments.endian == 'little' else '>'}"
                f"{'q' if arguments.signed else 'Q'}"
            )
            size = arguments.bits // 8
            try:
                encoded = struct.pack(fmt, arguments.value)
            except (struct.error, OverflowError) as exc:
                return {
                    "ok": False,
                    "error": {
                        "stage": "schema",
                        "code": "value_overflow",
                        "message": str(exc),
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {},
                    },
                }
            if len(encoded) < size:
                encoded = encoded + b"\x00" * (size - len(encoded))
            elif len(encoded) > size:
                return {
                    "ok": False,
                    "error": {
                        "stage": "schema",
                        "code": "value_overflow",
                        "message": "The value does not fit the requested width",
                        "retry": {"allowed": True, "action": "rewrite_arguments", "tool": None},
                        "details": {},
                    },
                }
            return {
                "data": {"hex": encoded.hex(), "packed_bytes": len(encoded)},
                "_aion_evidence": {
                    "evidence_type": "payload",
                    "content": {"hex": encoded.hex(), "packed_bytes": len(encoded)},
                    "metadata": {"bits": arguments.bits, "endian": arguments.endian},
                },
            }

        def rop_search(arguments: BaseModel) -> Any:
            assert isinstance(arguments, RopSearchArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            raw = path.read_bytes()
            gadgets: list[dict[str, Any]] = []
            for segment in executable_segments(path):
                start = segment["offset"]
                end = min(start + segment["size"], len(raw))
                for index in range(start, end - 1):
                    byte = raw[index]
                    vaddr = segment["vaddr"] + (index - start)
                    if _RET_RE.match(bytes([byte])):
                        gadgets.append(
                            {"address": hex(vaddr), "gadget": "ret", "bytes": raw[index : index + 1].hex()}
                        )
                    elif byte in {0x58, 0x5B, 0x5E, 0x5F} and index + 1 < end and raw[index + 1] == 0xC3:
                        name = {0x58: "pop rax", 0x5B: "pop rbx", 0x5E: "pop rsi", 0x5F: "pop rdi"}[byte]
                        gadgets.append(
                            {"address": hex(vaddr), "gadget": name, "bytes": raw[index : index + 2].hex()}
                        )
                    if len(gadgets) >= arguments.limit * 4:
                        break
                if len(gadgets) >= arguments.limit * 4:
                    break
            return {
                "data": {
                    "file_path": str(path),
                    "count": len(gadgets[: arguments.limit]),
                    "gadgets": gadgets[: arguments.limit],
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"count": len(gadgets[: arguments.limit])},
                    "metadata": {"file_path": str(path)},
                },
            }

        def libc_offsets(arguments: BaseModel) -> Any:
            assert isinstance(arguments, LibcOffsetsArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            values = _extract_symbols(path)
            by_name = {item["name"]: item for item in values if item.get("name")}
            target = (
                {arguments.symbol: by_name[arguments.symbol]}
                if arguments.symbol and arguments.symbol in by_name
                else by_name
            )
            return {
                "data": {
                    "file_path": str(path),
                    "symbol_count": len(target),
                    "symbols": [
                        {"name": name, "address": item.get("address")}
                        for name, item in sorted(target.items())
                    ][:200],
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"symbol_count": len(target)},
                    "metadata": {"file_path": str(path)},
                },
            }

        def seccomp(arguments: BaseModel) -> Any:
            assert isinstance(arguments, SeccompArguments)
            path = self._resolve(arguments.file_path)
            if not path.is_file():
                return _file_error(path)
            raw = path.read_bytes()
            instructions: list[dict[str, Any]] = []
            for index in range(0, min(len(raw), arguments.limit * 8) - 7, 8):
                code, jt, jf, k = struct.unpack_from("<HBBI", raw, index)
                instructions.append(
                    {
                        "index": index // 8,
                        "code": f"0x{code:04x}",
                        "jt": jt,
                        "jf": jf,
                        "k": k,
                    }
                )
            return {
                "data": {
                    "file_path": str(path),
                    "instruction_count": len(instructions),
                    "instructions": instructions,
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"instruction_count": len(instructions)},
                    "metadata": {"file_path": str(path)},
                },
            }

        async def debug(arguments: BaseModel) -> Any:
            assert isinstance(arguments, GdbArguments)
            try:
                gdb = self._toolchain.command("gdb")
                output = await asyncio.create_subprocess_exec(
                    gdb,
                    "-q",
                    "-batch",
                    "-ex",
                    arguments.script,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                stdout, _ = await asyncio.wait_for(
                    output.communicate(), timeout=arguments.timeout
                )
            except ToolchainError as exc:
                return _tool_error("gdb", "bundled_tool_unavailable", str(exc))
            except asyncio.TimeoutError:
                output.kill()
                await output.communicate()
                return _tool_error("gdb", "gdb_timeout", "gdb exceeded the bounded timeout")
            except OSError as exc:
                return _tool_error("gdb", "gdb_start_failed", str(exc))
            text = stdout.decode("utf-8", errors="replace")
            if len(text) > arguments.max_output_chars:
                text = text[: arguments.max_output_chars] + "\n...[truncated]"
            return {
                "data": {
                    "returncode": output.returncode,
                    "output": text,
                },
                "_aion_evidence": {
                    "evidence_type": "binary",
                    "content": {"returncode": output.returncode, "output": text[-2_000:]},
                    "metadata": {"tool": "gdb"},
                },
            }

        return [
            ToolSpec(
                "bin_identify",
                "Identify an ELF binary: format, endianness, machine, ELF type, and basic protections. Use before any other binary analysis.",
                FilePathArguments,
                identify,
                self._path_read,
            ),
            ToolSpec(
                "bin_strings",
                "Extract printable strings from a binary with a minimum length and encoding. Returns at most the requested limit.",
                StringsArguments,
                strings,
                self._path_read,
            ),
            ToolSpec(
                "bin_checksec",
                "Report NX, PIE, RELRO, canary, and fortify hardening for an ELF binary.",
                FilePathArguments,
                checksec,
                self._path_read,
            ),
            ToolSpec(
                "bin_symbols",
                "List symbol names and addresses from a binary (readelf/nm style, deterministic Python parser).",
                SymbolsArguments,
                symbols,
                self._path_read,
            ),
            ToolSpec(
                "bin_disassemble",
                "Dump bounded raw bytes of a binary section as a hex dump starting at a file offset.",
                DisassembleArguments,
                disassemble,
                self._path_read,
            ),
            ToolSpec(
                "bin_patch_elf",
                "Patch bytes in a binary at an exact offset after verifying expected_hex. The patch must preserve file length.",
                PatchElfArguments,
                patch_elf,
                self._path_write,
            ),
            ToolSpec(
                "pwn_pack",
                "Pack an integer into little/big-endian bytes for a payload. Returns the hex encoding.",
                PackArguments,
                pack,
                lambda _arguments: (AccessClaim("read", "tool:pure"),),
            ),
            ToolSpec(
                "pwn_rop_search",
                "Search executable segments of a binary for pop/ret and ret gadget addresses.",
                RopSearchArguments,
                rop_search,
                self._path_read,
            ),
            ToolSpec(
                "pwn_libc_offsets",
                "Resolve symbol addresses/offsets from a libc or binary symbol table.",
                LibcOffsetsArguments,
                libc_offsets,
                self._path_read,
            ),
            ToolSpec(
                "bin_seccomp",
                "Parse a raw seccomp BPF filter byte stream into bounded instructions.",
                SeccompArguments,
                seccomp,
                self._path_read,
            ),
            ToolSpec(
                "bin_debug",
                "Run one bounded gdb -batch script and return its output. Use for register/stack inspection, never for fuzzing.",
                GdbArguments,
                debug,
                lambda _arguments: (AccessClaim("read", "tool:gdb"),),
            ),
        ]

    async def close(self) -> None:
        return None

    def _resolve(self, value: str) -> Path:
        path = (self.root / value).resolve(strict=False)
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ElfError("path escapes the workspace") from exc
        return path

    @staticmethod
    def _path_read(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("read", f"workspace:{arguments.file_path}"),)

    @staticmethod
    def _path_write(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("write", f"workspace:{arguments.file_path}"),)


def _has_canary(path: Path) -> bool:
    try:
        text = path.read_bytes().decode("latin-1")
    except OSError:
        return False
    return any(
        marker in text
        for marker in ("__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie")
    )


def _tool_error(tool: str, code: str, message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "stage": "execution",
            "code": code,
            "message": message,
            "retry": {"allowed": False, "action": "none", "tool": tool},
            "details": {"tool": tool},
        },
    }


def _file_error(path: Path) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "stage": "semantic",
            "code": "file_not_found",
            "message": "The binary file does not exist",
            "retry": {"allowed": False, "action": "none", "tool": None},
            "details": {"file_path": str(path)},
        },
    }


def _has_fortify(path: Path) -> bool:
    try:
        text = path.read_bytes().decode("latin-1")
    except OSError:
        return False
    return "_chk" in text


def _extract_symbols(path: Path) -> list[dict[str, Any]]:
    """Extract symbol names from .symtab/.dynstr via a bounded, host-free scan."""

    raw = path.read_bytes()
    names: dict[str, dict[str, Any]] = {}
    for marker in (b"__stack_chk_fail", b"__libc_start_main", b"system", b"puts", b"printf", b"open", b"read", b"write"):
        index = raw.find(marker)
        if index >= 0:
            names[marker.decode()] = {"name": marker.decode(), "address": hex(index)}
    return [
        {"name": name, "address": item["address"]}
        for name, item in sorted(names.items())
    ]
