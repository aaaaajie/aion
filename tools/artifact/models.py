"""Strict input models for local artifact inspection."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ArtifactPathArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        max_length=512,
        description="Logical workspace path such as agent/bin/app or shared/bin/app; absolute paths and $TMPDIR belong in Shell only.",
    )


class ArtifactDisassembleArguments(ArtifactPathArguments):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=200, ge=1, le=500)


class ArtifactAbiArguments(ArtifactPathArguments):
    limit: int = Field(default=200, ge=1, le=500)
