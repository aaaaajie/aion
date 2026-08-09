"""Input models for the Agent-facing system tools."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReadFileArguments(ToolArguments):
    file_path: str = Field(min_length=1)
    offset: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, gt=0)


class WriteFileArguments(ToolArguments):
    file_path: str = Field(min_length=1)
    content: str


class EditFileArguments(ToolArguments):
    file_path: str = Field(min_length=1)
    old_string: str
    new_string: str
    replace_all: bool = False


class CreateDirectoryArguments(ToolArguments):
    path: str = Field(min_length=1)
    parents: bool = True


class DeletePathArguments(ToolArguments):
    path: str = Field(min_length=1)
    recursive: bool = False


class ListDirectoryArguments(ToolArguments):
    path: str = "."
    recursive: bool = False
    max_entries: int = Field(default=1000, gt=0, le=10_000)


class GlobArguments(ToolArguments):
    pattern: str = Field(min_length=1)
    path: str = "."
    max_results: int = Field(default=100, gt=0, le=10_000)


class GrepArguments(ToolArguments):
    pattern: str = Field(min_length=1)
    path: str = "."
    glob: str | None = None
    ignore_case: bool = False
    max_results: int = Field(default=100, gt=0, le=10_000)


class ShellArguments(ToolArguments):
    command: str = Field(min_length=1)
    cwd: str = "."
    timeout: float = Field(default=30.0, gt=0, le=600.0)
    max_output_chars: int = Field(default=30_000, gt=0, le=1_000_000)
    run_in_background: bool = False


class TaskOutputArguments(ToolArguments):
    task_id: str = Field(min_length=1)
    wait_seconds: float = Field(default=0.0, ge=0, le=30.0)
    tail_chars: int = Field(default=30_000, gt=0, le=1_000_000)


class TaskStopArguments(ToolArguments):
    task_id: str = Field(min_length=1)


class TaskCleanupArguments(ToolArguments):
    task_id: str = Field(min_length=1)
