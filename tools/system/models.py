"""Input models for the Agent-facing system tools."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReadFileArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/output.txt or shared/input.txt; absolute paths and $TMPDIR belong in Shell only.",
    )
    offset: int | None = Field(
        default=None,
        ge=0,
        description="Character offset in the UTF-8 file; omit to start at 0.",
    )
    limit_chars: int | None = Field(
        default=None,
        gt=0,
        description="Maximum characters to return; this field is limit_chars, not limit.",
    )


class WriteFileArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/output.txt or shared/result.txt; do not pass an absolute path or $TMPDIR.",
    )
    content: str


class EditFileArguments(ToolArguments):
    file_path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/output.txt or shared/result.txt; do not pass an absolute path or $TMPDIR.",
    )
    old_string: str
    new_string: str
    replace_all: bool = False


class CreateDirectoryArguments(ToolArguments):
    path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/new-dir or shared/new-dir; absolute paths and $TMPDIR belong in Shell only.",
    )
    parents: bool = True


class DeletePathArguments(ToolArguments):
    path: str = Field(
        min_length=1,
        description="Logical workspace path such as agent/old.txt or shared/old.txt; absolute paths and $TMPDIR belong in Shell only.",
    )
    recursive: bool = False


class ListDirectoryArguments(ToolArguments):
    path: str = Field(
        default=".",
        description="Logical workspace directory such as agent or shared; absolute paths and $TMPDIR are unavailable here.",
    )
    recursive: bool = False
    max_entries: int = Field(default=1000, gt=0, le=10_000)


class GlobArguments(ToolArguments):
    pattern: str = Field(min_length=1)
    path: str = Field(
        default=".",
        description="Logical workspace directory such as agent or shared; absolute paths and $TMPDIR are unavailable here.",
    )
    max_results: int = Field(default=100, gt=0, le=10_000)


class GrepArguments(ToolArguments):
    pattern: str = Field(min_length=1)
    path: str = Field(
        default=".",
        description="Logical workspace directory such as agent or shared; absolute paths and $TMPDIR are unavailable here.",
    )
    glob: str | None = None
    ignore_case: bool = False
    max_results: int = Field(default=100, gt=0, le=10_000)


class ShellArguments(ToolArguments):
    command: str = Field(min_length=1, description="One bounded bash command. Non-zero exit status is a failed command and must be investigated.")
    cwd: str = Field(default=".", description="Use . or a workspace path; $TMPDIR is available to Shell for temporary files only.")
    timeout: float = Field(default=30.0, gt=0, le=30.0, description="Foreground budget, at most 30 seconds. Use system_task_start for longer work; a timeout is inconclusive.")
    max_output_chars: int = Field(default=30_000, gt=0, le=1_000_000)


class TaskStartArguments(ShellArguments):
    name: str = Field(min_length=1, max_length=128)
    timeout: float = Field(default=1800.0, gt=0, le=86400.0)


class TaskOutputArguments(ToolArguments):
    task_id: str = Field(min_length=1, description="Exact task_id returned by system_task_start; never invent or reuse a path as the ID.")
    wait_seconds: float = Field(
        default=0.0,
        ge=0,
        le=30.0,
        description="Read immediately with 0; completion is notified automatically. Wait only when intermediate output is needed.",
    )
    tail_chars: int = Field(default=30_000, gt=0, le=1_000_000, description="Maximum retained output characters to return.")


class TaskStopArguments(ToolArguments):
    task_id: str = Field(min_length=1, description="Exact task_id returned by system_task_start.")


class TaskCleanupArguments(ToolArguments):
    task_id: str = Field(min_length=1)
