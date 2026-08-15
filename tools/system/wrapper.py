"""Agent-facing wrapper for workspace filesystem and sandboxed Shell tools."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from typing import Any, ClassVar, TypeAlias

from pydantic import BaseModel, ValidationError

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
    ToolArguments,
    WriteFileArguments,
)
from .policy import DEFAULT_WORKSPACE_ROOT, SystemToolError, WorkspacePolicy
from .shell import AgentShellClient

ToolResult: TypeAlias = dict[str, Any]
ToolOperation: TypeAlias = Callable[..., Awaitable[Any]]


def _definition(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str],
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


class SystemTools:
    """Expose system operations as JSON-compatible Agent tools."""

    _ROUTES: ClassVar[dict[str, tuple[type[ToolArguments], str]]] = {
        "system_read_file": (ReadFileArguments, "read_file"),
        "system_write_file": (WriteFileArguments, "write_file"),
        "system_edit_file": (EditFileArguments, "edit_file"),
        "system_create_directory": (CreateDirectoryArguments, "create_directory"),
        "system_delete_path": (DeletePathArguments, "delete_path"),
        "system_list_directory": (ListDirectoryArguments, "list_directory"),
        "system_glob": (GlobArguments, "glob"),
        "system_grep": (GrepArguments, "grep"),
        "system_shell": (ShellArguments, "run_shell"),
        "system_task_output": (TaskOutputArguments, "task_output"),
        "system_task_stop": (TaskStopArguments, "task_stop"),
        "system_task_cleanup": (TaskCleanupArguments, "task_cleanup"),
    }

    _TOOL_DEFINITIONS: ClassVar[list[dict[str, Any]]] = [
        _definition(
            "system_read_file",
            "Read a UTF-8 text file in the workspace. Use offset and limit for large files.",
            {
                "file_path": {"type": "string", "description": "Workspace-relative or absolute file path."},
                "offset": {"type": "integer", "minimum": 0, "description": "Zero-based starting line."},
                "limit": {"type": "integer", "exclusiveMinimum": 0, "description": "Maximum number of lines."},
            },
            ["file_path"],
        ),
        _definition(
            "system_write_file",
            "Atomically create or replace a UTF-8 text file. Existing files must have been fully read first.",
            {
                "file_path": {"type": "string", "description": "Workspace-relative or absolute file path."},
                "content": {"type": "string", "description": "Complete new file content."},
            },
            ["file_path", "content"],
        ),
        _definition(
            "system_edit_file",
            "Replace text in a workspace file. The old text must be unique unless replace_all is true.",
            {
                "file_path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
                "replace_all": {"type": "boolean", "default": False},
            },
            ["file_path", "old_string", "new_string"],
        ),
        _definition(
            "system_create_directory",
            "Create a directory inside the workspace.",
            {
                "path": {"type": "string"},
                "parents": {"type": "boolean", "default": True},
            },
            ["path"],
        ),
        _definition(
            "system_delete_path",
            "Delete a workspace file or directory. Recursive deletion must be explicitly requested.",
            {
                "path": {"type": "string"},
                "recursive": {"type": "boolean", "default": False},
            },
            ["path"],
        ),
        _definition(
            "system_list_directory",
            "List entries in a workspace directory, optionally recursively.",
            {
                "path": {"type": "string", "default": "."},
                "recursive": {"type": "boolean", "default": False},
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
            },
            [],
        ),
        _definition(
            "system_glob",
            "Find workspace paths using a relative glob pattern.",
            {
                "pattern": {"type": "string"},
                "path": {"type": "string", "default": "."},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
            },
            ["pattern"],
        ),
        _definition(
            "system_grep",
            "Search UTF-8 text files in the workspace with a regular expression.",
            {
                "pattern": {"type": "string"},
                "path": {"type": "string", "default": "."},
                "glob": {"type": "string", "description": "Optional relative file glob."},
                "ignore_case": {"type": "boolean", "default": False},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
            },
            ["pattern"],
        ),
        _definition(
            "system_shell",
            "Run bash in the shared workspace with Agent-persistent HOME and temp storage. On Linux both /tmp and $TMPDIR persist for this Agent; on macOS use $TMPDIR. For work longer than the foreground wait, set run_in_background=true and follow the returned task_id with system_task_output. Do not use nohup, '&', or sleep polling to emulate task management. Prefer HTTP tools over representable curl loops.",
            {
                "command": {"type": "string"},
                "cwd": {"type": "string", "default": "."},
                "timeout": {"type": "number", "exclusiveMinimum": 0, "maximum": 600, "default": 30},
                "max_output_chars": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 30000},
                "run_in_background": {"type": "boolean", "default": False},
            },
            ["command"],
        ),
        _definition(
            "system_task_output",
            "Read retained output and status for an owned Shell task without consuming it. Use wait_seconds instead of shell sleep loops; repeated reads are idempotent.",
            {
                "task_id": {"type": "string"},
                "wait_seconds": {"type": "number", "minimum": 0, "maximum": 30, "default": 0},
                "tail_chars": {"type": "integer", "minimum": 1, "maximum": 1000000, "default": 30000},
            },
            ["task_id"],
        ),
        _definition(
            "system_task_stop",
            "Stop a running Shell task without deleting its retained output.",
            {"task_id": {"type": "string"}},
            ["task_id"],
        ),
        _definition(
            "system_task_cleanup",
            "Delete retained output for a finished Shell task. Repeated cleanup is safe.",
            {"task_id": {"type": "string"}},
            ["task_id"],
        ),
    ]

    def __init__(
        self,
        root: str | os.PathLike[str] = DEFAULT_WORKSPACE_ROOT,
        *,
        shell: AgentShellClient,
    ) -> None:
        policy = WorkspacePolicy(root)
        self._filesystem = FileSystemService(policy)
        self._shell = shell

    @classmethod
    def from_env(cls, **kwargs: Any) -> "SystemTools":
        root = os.environ.get("SYSTEM_TOOLS_ROOT", str(DEFAULT_WORKSPACE_ROOT))
        return cls(root=root, **kwargs)

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return deepcopy(cls._TOOL_DEFINITIONS)

    async def __aenter__(self) -> "SystemTools":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._shell.close()

    async def read_file(self, file_path: str, offset: int | None = None, limit: int | None = None) -> ToolResult:
        return await self._invoke(ReadFileArguments, {"file_path": file_path, "offset": offset, "limit": limit}, self._filesystem.read_file)

    async def write_file(self, file_path: str, content: str) -> ToolResult:
        return await self._invoke(WriteFileArguments, {"file_path": file_path, "content": content}, self._filesystem.write_file)

    async def edit_file(self, file_path: str, old_string: str, new_string: str, replace_all: bool = False) -> ToolResult:
        return await self._invoke(EditFileArguments, {"file_path": file_path, "old_string": old_string, "new_string": new_string, "replace_all": replace_all}, self._filesystem.edit_file)

    async def create_directory(self, path: str, parents: bool = True) -> ToolResult:
        return await self._invoke(CreateDirectoryArguments, {"path": path, "parents": parents}, self._filesystem.create_directory)

    async def delete_path(self, path: str, recursive: bool = False) -> ToolResult:
        return await self._invoke(DeletePathArguments, {"path": path, "recursive": recursive}, self._filesystem.delete_path)

    async def list_directory(self, path: str = ".", recursive: bool = False, max_entries: int = 1000) -> ToolResult:
        return await self._invoke(ListDirectoryArguments, {"path": path, "recursive": recursive, "max_entries": max_entries}, self._filesystem.list_directory)

    async def glob(self, pattern: str, path: str = ".", max_results: int = 100) -> ToolResult:
        return await self._invoke(GlobArguments, {"pattern": pattern, "path": path, "max_results": max_results}, self._filesystem.glob)

    async def grep(self, pattern: str, path: str = ".", glob: str | None = None, ignore_case: bool = False, max_results: int = 100) -> ToolResult:
        return await self._invoke(GrepArguments, {"pattern": pattern, "path": path, "glob": glob, "ignore_case": ignore_case, "max_results": max_results}, self._filesystem.grep)

    async def shell(self, command: str, cwd: str = ".", timeout: float = 30.0, max_output_chars: int = 30_000, run_in_background: bool = False) -> ToolResult:
        return await self._invoke(ShellArguments, {"command": command, "cwd": cwd, "timeout": timeout, "max_output_chars": max_output_chars, "run_in_background": run_in_background}, self._shell.run_shell)

    async def task_output(self, task_id: str, wait_seconds: float = 0.0, tail_chars: int = 30_000) -> ToolResult:
        return await self._invoke(TaskOutputArguments, {"task_id": task_id, "wait_seconds": wait_seconds, "tail_chars": tail_chars}, self._shell.task_output)

    async def task_stop(self, task_id: str) -> ToolResult:
        return await self._invoke(TaskStopArguments, {"task_id": task_id}, self._shell.task_stop)

    async def task_cleanup(self, task_id: str) -> ToolResult:
        return await self._invoke(
            TaskCleanupArguments,
            {"task_id": task_id},
            self._shell.task_cleanup,
        )

    async def dispatch(self, name: str, arguments: Mapping[str, Any] | None = None) -> ToolResult:
        if not isinstance(name, str):
            return self._validation_error("invalid_tool_name", "Tool name must be a string")
        route = self._ROUTES.get(name)
        if route is None:
            return self._validation_error("unknown_tool", f"Unknown system tool: {name}")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._validation_error("invalid_arguments", "Tool arguments must be a JSON object")
        model, operation_name = route
        return await self._invoke(model, arguments, self._operation_for_name(operation_name))

    def _operation_for_name(self, name: str) -> ToolOperation:
        operations: dict[str, ToolOperation] = {
            "read_file": self._filesystem.read_file,
            "write_file": self._filesystem.write_file,
            "edit_file": self._filesystem.edit_file,
            "create_directory": self._filesystem.create_directory,
            "delete_path": self._filesystem.delete_path,
            "list_directory": self._filesystem.list_directory,
            "glob": self._filesystem.glob,
            "grep": self._filesystem.grep,
            "run_shell": self._shell.run_shell,
            "task_output": self._shell.task_output,
            "task_stop": self._shell.task_stop,
            "task_cleanup": self._shell.task_cleanup,
        }
        return operations[name]

    async def _invoke(
        self,
        model: type[ToolArguments],
        arguments: Mapping[str, Any],
        operation: ToolOperation,
    ) -> ToolResult:
        try:
            validated = model.model_validate(arguments)
            result = await operation(**validated.model_dump())
            return {"ok": True, "data": result}
        except SystemToolError as exc:
            return {
                "ok": False,
                "error": {
                    "type": exc.error_type,
                    "code": exc.code,
                    "message": exc.message,
                    "status_code": None,
                    "detail": exc.detail,
                },
            }
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "invalid_arguments",
                    "message": "Invalid system-tool arguments",
                    "status_code": None,
                    "detail": self._safe_validation_detail(exc.errors()),
                },
            }
        except ValueError:
            return self._validation_error("invalid_arguments", "Invalid system-tool arguments")
        except OSError:
            return {
                "ok": False,
                "error": {
                    "type": "internal",
                    "code": "operation_failed",
                    "message": "The system operation could not be completed",
                    "status_code": None,
                    "detail": {},
                },
            }
        except Exception:
            return {
                "ok": False,
                "error": {
                    "type": "internal",
                    "code": "internal_error",
                    "message": "The system tool failed unexpectedly",
                    "status_code": None,
                    "detail": {},
                },
            }

    @staticmethod
    def _validation_error(code: str, message: str) -> ToolResult:
        return {
            "ok": False,
            "error": {
                "type": "validation",
                "code": code,
                "message": message,
                "status_code": None,
                "detail": {},
            },
        }

    @staticmethod
    def _safe_validation_detail(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {key: item[key] for key in ("loc", "msg", "type") if key in item}
            for item in errors
        ]
