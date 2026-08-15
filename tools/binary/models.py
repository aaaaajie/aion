"""Input models for the Agent-facing binary analysis tools."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FilePathArguments(ToolArguments):
    file_path: str = Field(min_length=1)


class StringsArguments(FilePathArguments):
    min_length: int = Field(default=4, ge=1, le=64)
    encoding: str = Field(default="utf-8", pattern=r"^(utf-8|utf-16le|latin-1)$")
    limit: int = Field(default=200, ge=1, le=2_000)


class SymbolsArguments(FilePathArguments):
    limit: int = Field(default=200, ge=1, le=2_000)


class DisassembleArguments(FilePathArguments):
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=256, ge=16, le=65_536)


class PatchElfArguments(FilePathArguments):
    offset: int = Field(ge=0)
    expected_hex: str = Field(min_length=2)
    patch_hex: str = Field(min_length=2)


class PackArguments(ToolArguments):
    value: int
    bits: int = Field(default=64, ge=8, le=128, multiple_of=8)
    endian: str = Field(default="little", pattern=r"^(little|big)$")
    signed: bool = False


class RopSearchArguments(FilePathArguments):
    patterns: list[str] = Field(
        default_factory=lambda: ["pop rdi; ret", "pop rsi; ret", "ret"]
    )
    limit: int = Field(default=50, ge=1, le=500)


class LibcOffsetsArguments(FilePathArguments):
    symbol: str | None = Field(default=None, min_length=1, max_length=128)


class SeccompArguments(FilePathArguments):
    limit: int = Field(default=200, ge=1, le=2_000)


class GdbArguments(ToolArguments):
    script: str = Field(min_length=1, max_length=8_000)
    timeout: float = Field(default=30.0, gt=0, le=300.0)
    max_output_chars: int = Field(default=30_000, gt=0, le=500_000)
