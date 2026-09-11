"""Input models for the Agent-facing binary analysis tools."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FilePathArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/bin/app or shared/bin/app; absolute paths and $TMPDIR belong in Shell only.",
    )


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


class PwnProcessOpenArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        max_length=4_096,
        description="Logical workspace path such as agent/bin/app or shared/bin/app; absolute paths and $TMPDIR belong in Shell only.",
    )
    argv: list[str] = Field(default_factory=list, max_length=32)
    cwd: str = Field(
        default=".",
        min_length=1,
        max_length=4_096,
        description="Logical workspace directory; use . or agent/.../shared/... and use $TMPDIR only through Shell.",
    )
    env: dict[str, str] = Field(default_factory=dict, max_length=64)
    startup_wait_seconds: float = Field(default=0.25, ge=0, le=10.0)
    max_startup_bytes: int = Field(default=8_192, ge=0, le=65_536)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any("\x00" in item or len(item) > 4_096 for item in value):
            raise ValueError("argv entries must be NUL-free and at most 4096 characters")
        return value

    @field_validator("env")
    @classmethod
    def validate_env(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not key or "\x00" in key or "=" in key or "\x00" in item:
                raise ValueError("environment keys and values must be valid NUL-free strings")
            if len(key) > 256 or len(item) > 4_096:
                raise ValueError("environment entries exceed the bounded length")
        return value


class PwnTcpOpenArguments(ToolArguments):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65_535)
    tls: bool = False
    server_hostname: str | None = Field(default=None, min_length=1, max_length=255)
    timeout: float = Field(default=10.0, gt=0, le=60.0)


class PwnSessionIoArguments(ToolArguments):
    session_id: str = Field(min_length=1, max_length=128)
    send_text: str | None = Field(default=None, max_length=16_384)
    send_base64: str | None = Field(default=None, max_length=65_536)
    append_newline: bool = False
    recv_until_text: str | None = Field(default=None, max_length=4_096)
    recv_until_base64: str | None = Field(default=None, max_length=8_192)
    timeout: float = Field(default=5.0, gt=0, le=120.0)
    max_bytes: int = Field(default=65_536, ge=1, le=1_000_000)

    @model_validator(mode="after")
    def validate_exclusive_encodings(self) -> "PwnSessionIoArguments":
        if self.send_text is not None and self.send_base64 is not None:
            raise ValueError("send_text and send_base64 are mutually exclusive")
        if self.recv_until_text is not None and self.recv_until_base64 is not None:
            raise ValueError("recv_until_text and recv_until_base64 are mutually exclusive")
        return self


class PwnSessionCloseArguments(ToolArguments):
    session_id: str = Field(min_length=1, max_length=128)
