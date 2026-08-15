"""Agent-facing Tool Specs for workspace filesystem and Shell operations."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec

from .filesystem import FileSystemService
from .models import (
    CreateDirectoryArguments,
    DeletePathArguments,
    EditFileArguments,
    GlobArguments,
    GrepArguments,
    ListDirectoryArguments,
    ReadFileArguments,
    ShellArguments,
    TaskCleanupArguments,
    TaskOutputArguments,
    TaskStopArguments,
    WriteFileArguments,
)
from .policy import DEFAULT_WORKSPACE_ROOT, WorkspacePolicy
from .shell import AgentShellClient


class SystemTools:
    """Expose system operations through the shared ToolExecutor."""

    def __init__(
        self,
        root: str | os.PathLike[str] = DEFAULT_WORKSPACE_ROOT,
        *,
        shell: AgentShellClient,
    ) -> None:
        self._policy = WorkspacePolicy(root)
        self._filesystem = FileSystemService(self._policy)
        self._shell = shell

    @classmethod
    def from_env(cls, **kwargs: Any) -> "SystemTools":
        return cls(root=os.environ.get("SYSTEM_TOOLS_ROOT", str(DEFAULT_WORKSPACE_ROOT)), **kwargs)

    def tool_specs(self) -> list[ToolSpec]:
        async def read_file(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ReadFileArguments)
            return await self._filesystem.read_file(
                arguments.file_path,
                offset=arguments.offset,
                limit_chars=arguments.limit_chars,
            )

        async def write_file(arguments: BaseModel) -> Any:
            assert isinstance(arguments, WriteFileArguments)
            result = await self._filesystem.write_file(
                arguments.file_path, arguments.content
            )
            return {
                **result,
                "_aion_evidence": {
                    "evidence_type": "file",
                    "content": arguments.content,
                    "metadata": {"file_path": result["file_path"]},
                },
            }

        async def edit_file(arguments: BaseModel) -> Any:
            assert isinstance(arguments, EditFileArguments)
            result = await self._filesystem.edit_file(
                arguments.file_path,
                arguments.old_string,
                arguments.new_string,
                replace_all=arguments.replace_all,
            )
            return {
                **result,
                "_aion_evidence": {
                    "evidence_type": "file",
                    "content": await self._filesystem.evidence_snapshot(
                        arguments.file_path
                    ),
                    "metadata": {"file_path": result["file_path"]},
                },
            }

        async def create_directory(arguments: BaseModel) -> Any:
            assert isinstance(arguments, CreateDirectoryArguments)
            return await self._filesystem.create_directory(
                arguments.path, parents=arguments.parents
            )

        async def delete_path(arguments: BaseModel) -> Any:
            assert isinstance(arguments, DeletePathArguments)
            return await self._filesystem.delete_path(
                arguments.path, recursive=arguments.recursive
            )

        async def list_directory(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ListDirectoryArguments)
            return await self._filesystem.list_directory(
                arguments.path,
                recursive=arguments.recursive,
                max_entries=arguments.max_entries,
            )

        async def glob_paths(arguments: BaseModel) -> Any:
            assert isinstance(arguments, GlobArguments)
            return await self._filesystem.glob(
                arguments.pattern,
                path=arguments.path,
                max_results=arguments.max_results,
            )

        async def grep_files(arguments: BaseModel) -> Any:
            assert isinstance(arguments, GrepArguments)
            return await self._filesystem.grep(
                arguments.pattern,
                path=arguments.path,
                glob=arguments.glob,
                ignore_case=arguments.ignore_case,
                max_results=arguments.max_results,
            )

        async def run_shell(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ShellArguments)
            return await self._shell.run_shell(
                arguments.command,
                cwd=arguments.cwd,
                timeout=arguments.timeout,
                max_output_chars=arguments.max_output_chars,
                run_in_background=arguments.run_in_background,
            )

        async def task_output(arguments: BaseModel) -> Any:
            assert isinstance(arguments, TaskOutputArguments)
            return await self._shell.task_output(
                arguments.task_id,
                wait_seconds=arguments.wait_seconds,
                tail_chars=arguments.tail_chars,
            )

        async def task_stop(arguments: BaseModel) -> Any:
            assert isinstance(arguments, TaskStopArguments)
            return await self._shell.task_stop(arguments.task_id)

        async def task_cleanup(arguments: BaseModel) -> Any:
            assert isinstance(arguments, TaskCleanupArguments)
            return await self._shell.task_cleanup(arguments.task_id)

        return [
            ToolSpec("system_read_file", "Read a UTF-8 text file in the workspace. Page large files with offset and limit_chars (never limit).", ReadFileArguments, read_file, self._path_read("file_path")),
            ToolSpec("system_write_file", "Atomically create or replace a UTF-8 text file. Existing files must have been fully read first.", WriteFileArguments, write_file, self._path_write("file_path")),
            ToolSpec("system_edit_file", "Replace text in a workspace file. The old text must be unique unless replace_all is true.", EditFileArguments, edit_file, self._path_write("file_path")),
            ToolSpec("system_list_directory", "List entries in a workspace directory, optionally recursively.", ListDirectoryArguments, list_directory, self._path_read("path")),
            ToolSpec("system_glob", "Find workspace paths using a relative glob pattern.", GlobArguments, glob_paths, self._path_read("path")),
            ToolSpec("system_grep", "Search UTF-8 text files in the workspace with a regular expression.", GrepArguments, grep_files, self._path_read("path")),
            ToolSpec("system_shell", "Run bash in the shared workspace with Agent-persistent HOME and temp storage. Use background tasks for long work and prefer HTTP tools over representable curl loops.", ShellArguments, run_shell, lambda _arguments: (AccessClaim("write", "*"),)),
            ToolSpec("system_task_output", "Read retained output and status for an owned Shell task without consuming it.", TaskOutputArguments, task_output, self._task_read),
            ToolSpec("system_task_stop", "Stop a running Shell task without deleting retained output.", TaskStopArguments, task_stop, self._task_write),
        ]

    async def close(self) -> None:
        await self._shell.close()

    def _path_read(self, field: str) -> Callable[[BaseModel], tuple[AccessClaim, ...]]:
        return lambda arguments: (
            AccessClaim("read", f"workspace:{self._policy.resolve(getattr(arguments, field))}"),
        )

    def _path_write(self, field: str) -> Callable[[BaseModel], tuple[AccessClaim, ...]]:
        return lambda arguments: (
            AccessClaim("write", f"workspace:{self._policy.resolve(getattr(arguments, field))}"),
        )

    def _directory_write(self, arguments: BaseModel) -> tuple[AccessClaim, ...]:
        if bool(getattr(arguments, "parents", False)):
            return (AccessClaim("write", "*"),)
        return self._path_write("path")(arguments)

    def _delete_claims(self, arguments: BaseModel) -> tuple[AccessClaim, ...]:
        if bool(getattr(arguments, "recursive", False)):
            return (AccessClaim("write", "*"),)
        return self._path_write("path")(arguments)

    @staticmethod
    def _task_read(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("read", f"shell-task:{arguments.task_id}"),)

    @staticmethod
    def _task_write(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("write", f"shell-task:{arguments.task_id}"),)
