"""Typed, discoverable FastCGI tool; no target-specific request defaults."""
from __future__ import annotations

import base64
import binascii
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent.tooling import AccessClaim, ToolSpec
from .client import FastCGIClient


class FastCGIArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    host: str = Field(min_length=1, max_length=253, description="Assigned TCP host, without a URL scheme")
    port: int = Field(default=9000, ge=1, le=65535)
    params: dict[str, str] = Field(default_factory=dict, max_length=128, description="Explicit FastCGI environment parameters; no PHP settings or script paths are inserted")
    stdin: str = Field(default="", max_length=1398104)
    stdin_encoding: Literal["utf-8", "base64"] = "utf-8"
    timeout_seconds: float = Field(default=10.0, ge=0.1, le=30.0)
    max_output_bytes: int = Field(default=16384, ge=1, le=1048576)

    def input_bytes(self) -> bytes:
        if self.stdin_encoding == "base64":
            try:
                return base64.b64decode(self.stdin, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError("stdin must be valid base64") from exc
        return self.stdin.encode("utf-8")

    @model_validator(mode="after")
    def validate_request(self):
        if any(c.isspace() for c in self.host) or any(c in self.host for c in '/\\\x00'):
            raise ValueError("host must be a TCP hostname or IP address")
        params_bytes = 0
        for key, value in self.params.items():
            if not key or '\x00' in key or '\x00' in value:
                raise ValueError("Parameter names must be nonempty and parameters cannot contain NUL")
            key_size, value_size = len(key.encode('utf-8')), len(value.encode('utf-8'))
            params_bytes += key_size + value_size + (1 if key_size < 128 else 4) + (1 if value_size < 128 else 4)
            if key_size > 65535 or params_bytes > 1048576:
                raise ValueError("Parameter exceeds byte limit")
        if len(self.input_bytes()) > 1048576:
            raise ValueError("Parameters and stdin are each limited to 1 MiB")
        return self


class FastCGITools:
    def __init__(self):
        self.client = FastCGIClient()

    def tool_specs(self):
        return [ToolSpec(
            "system_fastcgi_request",
            "Send one FastCGI/1 Responder request to an assigned TCP service (FastCGI, FCGI, PHP-FPM, 快速CGI). Provide params and stdin explicitly. Returns actual raw_response/bytes_received, separate decoded stdout/stderr, transport status, completion and application/protocol statuses. Local error messages are never server bytes. No retries; timeout/reset/incomplete replies are uncertain.",
            FastCGIArguments,
            self.client.request,
            lambda args: (AccessClaim("write", f"network:{args.host}:{args.port}"),),
        )]

    async def close(self):
        await self.client.close()
