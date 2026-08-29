"""Bounded, read-only inspection for local bytecode and ABI artifacts.

The provider never contacts a node or constructs a transaction.  It only reads
files already inside the Agent workspace and returns compact evidence for the
Challenge Agent.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec
from tools.workspace import is_runtime_control_plane_path

from .models import ArtifactAbiArguments, ArtifactDisassembleArguments, ArtifactPathArguments


_OPCODES: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x20: "SHA3",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


class ArtifactTools:
    """Expose deterministic artifact inspection through the shared registry."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()

    def tool_specs(self) -> list[ToolSpec]:
        def identify(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ArtifactPathArguments)
            path = self._resolve(arguments.file_path)
            raw = self._read(path)
            if raw is None:
                return _file_error(path)
            abi = _parse_abi(raw)
            if abi is not None:
                return _result(
                    {
                        "file_path": str(path),
                        "format": "abi_json",
                        "items": len(abi),
                        "types": _abi_type_counts(abi),
                    },
                    path,
                )
            bytecode = _decode_hex(raw)
            if bytecode is not None:
                return _result(
                    {
                        "file_path": str(path),
                        "format": "evm_hex",
                        "byte_length": len(bytecode),
                        "opcode_count": len(_decode(bytecode, limit=500)),
                    },
                    path,
                )
            return _result(
                {
                    "file_path": str(path),
                    "format": "binary_blob",
                    "byte_length": len(raw),
                    "note": "Not recognized as ABI JSON or hexadecimal bytecode",
                },
                path,
            )

        def disassemble(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ArtifactDisassembleArguments)
            path = self._resolve(arguments.file_path)
            raw = self._read(path)
            if raw is None:
                return _file_error(path)
            bytecode = _decode_hex(raw)
            if bytecode is None:
                bytecode = raw
            instructions = _decode(bytecode, limit=arguments.limit, offset=arguments.offset)
            return _result(
                {
                    "file_path": str(path),
                    "format": "evm_bytecode",
                    "byte_length": len(bytecode),
                    "offset": arguments.offset,
                    "instruction_count": len(instructions),
                    "instructions": instructions,
                },
                path,
            )

        def abi_summary(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ArtifactAbiArguments)
            path = self._resolve(arguments.file_path)
            raw = self._read(path)
            if raw is None:
                return _file_error(path)
            abi = _parse_abi(raw)
            if abi is None:
                return _error(
                    "invalid_abi",
                    "The file does not contain a JSON ABI array or an object with an abi array",
                    str(path),
                )
            items = [_summarize_abi_item(item) for item in abi]
            return _result(
                {
                    "file_path": str(path),
                    "count": len(items),
                    "items": items[: arguments.limit],
                    "truncated": len(items) > arguments.limit,
                },
                path,
            )

        def static_review(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ArtifactPathArguments)
            path = self._resolve(arguments.file_path)
            raw = self._read(path)
            if raw is None:
                return _file_error(path)
            bytecode = _decode_hex(raw)
            if bytecode is None:
                bytecode = raw
            instructions = _decode(bytecode, limit=2_000)
            observed = {item["name"] for item in instructions}
            checks = (
                ("DELEGATECALL", "delegatecall_present", "review external code context and storage assumptions"),
                ("CALL", "call_present", "review call target, value flow, and return handling"),
                ("STATICCALL", "staticcall_present", "review external read dependencies"),
                ("SSTORE", "storage_write_present", "review authorization around state changes"),
                ("SELFDESTRUCT", "selfdestruct_present", "review reachability and authorization"),
                ("ORIGIN", "tx_origin_present", "review authorization that depends on transaction origin"),
            )
            findings = [
                {"code": code, "opcode": opcode, "message": message}
                for opcode, code, message in checks
                if opcode in observed
            ]
            return _result(
                {
                    "file_path": str(path),
                    "byte_length": len(bytecode),
                    "instructions_examined": len(instructions),
                    "findings": findings,
                    "status": "review_required" if findings else "no_known_markers",
                },
                path,
            )

        return [
            ToolSpec(
                "artifact_identify",
                "Identify a local ABI JSON or hexadecimal bytecode artifact without network access.",
                ArtifactPathArguments,
                identify,
                self._path_read,
            ),
            ToolSpec(
                "artifact_disassemble",
                "Decode bounded local bytecode into opcode records. Read-only and offline.",
                ArtifactDisassembleArguments,
                disassemble,
                self._path_read,
            ),
            ToolSpec(
                "artifact_abi_summary",
                "Summarize functions, events, errors, and mutability from a local JSON ABI.",
                ArtifactAbiArguments,
                abi_summary,
                self._path_read,
            ),
            ToolSpec(
                "artifact_static_review",
                "Run a bounded static marker review over local bytecode and return evidence-backed review items.",
                ArtifactPathArguments,
                static_review,
                self._path_read,
            ),
        ]

    def _resolve(self, value: str) -> Path:
        path = (self.root / value).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("artifact path escapes the workspace") from exc
        if is_runtime_control_plane_path(self.root, path):
            raise ValueError("artifact path is a Runtime control-plane path")
        return path

    @staticmethod
    def _path_read(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("read", f"workspace:{arguments.file_path}"),)

    @staticmethod
    def _read(path: Path) -> bytes | None:
        try:
            return path.read_bytes() if path.is_file() else None
        except OSError:
            return None


def _decode_hex(raw: bytes) -> bytes | None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    compact = "".join(text.split())
    if compact.startswith("0x"):
        compact = compact[2:]
    if not compact or len(compact) % 2 or any(char not in "0123456789abcdefABCDEF" for char in compact):
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def _parse_abi(raw: bytes) -> list[dict[str, Any]] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(value, dict) and isinstance(value.get("abi"), list):
        value = value["abi"]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        return None
    return [dict(item) for item in value]


def _abi_type_counts(abi: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in abi:
        kind = str(item.get("type") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def _summarize_abi_item(item: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": str(item.get("type") or "unknown"),
    }
    for key in ("name", "stateMutability", "anonymous"):
        if key in item:
            result[key] = item[key]
    for key in ("inputs", "outputs"):
        values = item.get(key)
        if isinstance(values, list):
            result[key] = [
                {
                    field: value.get(field)
                    for field in ("name", "type", "internalType", "indexed")
                    if field in value
                }
                for value in values[:64]
                if isinstance(value, dict)
            ]
    return result


def _decode(bytecode: bytes, *, limit: int, offset: int = 0) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    index = min(offset, len(bytecode))
    while index < len(bytecode) and len(instructions) < limit:
        start = index
        opcode = bytecode[index]
        index += 1
        if 0x60 <= opcode <= 0x7F:
            size = opcode - 0x5F
            immediate = bytecode[index : index + size]
            index += len(immediate)
            instructions.append(
                {
                    "offset": start,
                    "opcode": f"0x{opcode:02x}",
                    "name": f"PUSH{size}",
                    "immediate": immediate.hex(),
                }
            )
            continue
        if 0x80 <= opcode <= 0x8F:
            name = f"DUP{opcode - 0x7F}"
        elif 0x90 <= opcode <= 0x9F:
            name = f"SWAP{opcode - 0x8F}"
        else:
            name = _OPCODES.get(opcode, f"OP_0x{opcode:02x}")
        instructions.append(
            {"offset": start, "opcode": f"0x{opcode:02x}", "name": name}
        )
    return instructions


def _result(data: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "data": data,
        "_aion_evidence": {
            "evidence_type": "binary",
            "content": {key: value for key, value in data.items() if key != "instructions"},
            "metadata": {"file_path": str(path), "offline": True},
        },
    }


def _error(code: str, message: str, file_path: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "stage": "semantic",
            "code": code,
            "message": message,
            "retry": {"allowed": False, "action": "none", "tool": None},
            "details": {"file_path": file_path},
        },
    }


def _file_error(path: Path) -> dict[str, Any]:
    return _error("file_not_found", "The artifact file does not exist", str(path))
