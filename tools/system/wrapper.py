"""Agent-facing Tool Specs for workspace filesystem and Shell operations."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
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
from .policy import DEFAULT_WORKSPACE_ROOT, SystemToolError, WorkspacePolicy
from .shell import AgentShellClient


class SystemTools:
    """Expose system operations through the shared ToolExecutor."""

    def __init__(
        self,
        root: str | os.PathLike[str] = DEFAULT_WORKSPACE_ROOT,
        *,
        shell: AgentShellClient,
        agent_work_root: str | os.PathLike[str] | None = None,
        shared_work_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self._policy = WorkspacePolicy(root)
        self._shell = shell
        self._agent_work_root = self._validate_workspace_root(agent_work_root)
        self._shared_work_root = self._validate_workspace_root(shared_work_root)
        self._filesystem = FileSystemService(
            self._policy,
            blocked_roots=(
                self._policy.root / ".aion",
                self._policy.root / ".system-tools",
            ),
            allowed_roots=tuple(
                path
                for path in (self._agent_work_root, self._shared_work_root)
                if path is not None
            ),
        )

    @classmethod
    def from_env(cls, **kwargs: Any) -> "SystemTools":
        return cls(root=os.environ.get("SYSTEM_TOOLS_ROOT", str(DEFAULT_WORKSPACE_ROOT)), **kwargs)

    def tool_specs(self) -> list[ToolSpec]:
        async def read_file(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ReadFileArguments)
            return await self._filesystem.read_file(
                str(self._path_read_value(arguments.file_path)),
                offset=arguments.offset,
                limit_chars=arguments.limit_chars,
            )

        async def write_file(arguments: BaseModel) -> Any:
            assert isinstance(arguments, WriteFileArguments)
            target, path_class, redirected = await self._prepare_write_path(arguments.file_path)
            await self._ensure_agent_workspace()
            result = await self._filesystem.write_file(str(target), arguments.content)
            result = self._display_path(result, target, path_class)
            if redirected:
                await self._record_workspace_event(path_class)
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
            target, path_class, redirected = await self._prepare_write_path(arguments.file_path)
            await self._ensure_agent_workspace()
            result = await self._filesystem.edit_file(
                str(target),
                arguments.old_string,
                arguments.new_string,
                replace_all=arguments.replace_all,
            )
            result = self._display_path(result, target, path_class)
            if redirected:
                await self._record_workspace_event(path_class)
            return {
                **result,
                "_aion_evidence": {
                    "evidence_type": "file",
                    "content": await self._filesystem.evidence_snapshot(
                        str(target)
                    ),
                    "metadata": {"file_path": result["file_path"]},
                },
            }

        async def create_directory(arguments: BaseModel) -> Any:
            assert isinstance(arguments, CreateDirectoryArguments)
            target, path_class, redirected = await self._prepare_write_path(arguments.path)
            await self._ensure_agent_workspace()
            result = await self._filesystem.create_directory(
                str(target), parents=arguments.parents
            )
            if redirected:
                await self._record_workspace_event(path_class)
            return self._display_path(result, target, path_class)

        async def delete_path(arguments: BaseModel) -> Any:
            assert isinstance(arguments, DeletePathArguments)
            target, path_class, redirected = await self._prepare_write_path(arguments.path)
            await self._ensure_agent_workspace()
            result = await self._filesystem.delete_path(
                str(target), recursive=arguments.recursive
            )
            if redirected:
                await self._record_workspace_event(path_class)
            return self._display_path(result, target, path_class)

        async def list_directory(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ListDirectoryArguments)
            return await self._filesystem.list_directory(
                str(self._path_read_value(arguments.path)),
                recursive=arguments.recursive,
                max_entries=arguments.max_entries,
            )

        async def glob_paths(arguments: BaseModel) -> Any:
            assert isinstance(arguments, GlobArguments)
            return await self._filesystem.glob(
                arguments.pattern,
                path=str(self._path_read_value(arguments.path)),
                max_results=arguments.max_results,
            )

        async def grep_files(arguments: BaseModel) -> Any:
            assert isinstance(arguments, GrepArguments)
            return await self._filesystem.grep(
                arguments.pattern,
                path=str(self._path_read_value(arguments.path)),
                glob=arguments.glob,
                ignore_case=arguments.ignore_case,
                max_results=arguments.max_results,
            )

        async def run_shell(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ShellArguments)
            await self._ensure_agent_workspace()
            if arguments.cwd in {".", ""} or not Path(arguments.cwd).is_absolute():
                await self._record_workspace_event("agent")
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

    async def _ensure_agent_workspace(self) -> None:
        if self._agent_work_root is not None:
            await self._shell.ensure_workspace()

    async def _record_workspace_event(
        self,
        path_class: str,
        *,
        event_type: str = "workspace_write_redirected",
        reason: str | None = None,
    ) -> None:
        if self._agent_work_root is None:
            return
        payload: dict[str, Any] = {"path_class": path_class, "operation": "write"}
        if reason is not None:
            payload["reason"] = reason
        await self._shell.record_workspace_event(
            event_type,
            payload,
        )

    async def _prepare_write_path(self, raw: str) -> tuple[Path, str, bool]:
        try:
            return self._path_write_value(raw)
        except SystemToolError as exc:
            await self._record_workspace_event(
                self._logical_path_class(raw),
                event_type="workspace_write_rejected",
                reason=exc.code,
            )
            raise

    def _path_read_value(self, raw: str) -> Path:
        if self._agent_work_root is None:
            target = self._policy.resolve(raw)
            self._filesystem._ensure_visible(target)
            return target
        target, path_class, _ = self._resolve_namespaced(raw, write=False)
        if path_class == "project":
            self._filesystem._ensure_visible(target)
        return target

    def _path_write_value(self, raw: str) -> tuple[Path, str, bool]:
        if self._agent_work_root is None:
            return self._policy.resolve(raw), "project", False
        target, path_class, explicit_namespace = self._resolve_namespaced(raw, write=True)
        return target, path_class, explicit_namespace or path_class in {"agent", "shared"}

    def _resolve_namespaced(self, raw: str, *, write: bool) -> tuple[Path, str, bool]:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise self._workspace_error("invalid_path", "Path must be a non-empty string")

        path = Path(raw).expanduser()
        parts = path.parts
        namespace = parts[0] if not path.is_absolute() and parts else None
        if namespace in {"agent", "shared", "project"}:
            suffix = Path(*parts[1:]) if len(parts) > 1 else Path()
            if namespace == "project":
                if write:
                    raise self._workspace_error(
                        "project_write_protected",
                        "Project files are read-only to Agent write tools",
                    )
                return self._resolve_under(self._policy.root, suffix, "project"), "project", True
            base = self._agent_work_root if namespace == "agent" else self._shared_work_root
            if base is None:
                raise self._workspace_error(
                    "shared_workspace_unavailable",
                    "The requested Agent workspace is not available",
                )
            return self._resolve_under(base, suffix, namespace), namespace, True

        if write:
            if path.is_absolute():
                resolved = self._policy.resolve(path)
                path_class = self._classify_root(resolved)
                if path_class == "project":
                    raise self._workspace_error(
                        "project_write_protected",
                        "Project files are read-only to Agent write tools",
                    )
                return resolved, path_class, True
            return self._resolve_under(self._agent_work_root, path, "agent"), "agent", False

        if path.is_absolute():
            resolved = self._policy.resolve(path)
            return resolved, self._classify_root(resolved), False
        return self._policy.resolve(path), "project", False

    def _resolve_under(self, base: Path, suffix: Path, path_class: str) -> Path:
        base = base.resolve(strict=False)
        candidate = Path(os.path.abspath(os.path.normpath(base / suffix)))
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise self._workspace_error(
                "workspace_write_rejected",
                "Workspace paths cannot escape their assigned area",
                {"path_class": path_class, "reason": "path_traversal"},
            ) from exc
        resolved = self._policy.resolve(candidate)
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise self._workspace_error(
                "workspace_write_rejected",
                "Workspace paths cannot resolve outside their assigned area",
                {"path_class": path_class, "reason": "symlink_escape"},
            ) from exc
        return resolved

    def _classify_root(self, path: Path) -> str:
        for path_class, base in (
            ("agent", self._agent_work_root),
            ("shared", self._shared_work_root),
        ):
            if base is not None:
                try:
                    path.relative_to(base.resolve(strict=False))
                    return path_class
                except ValueError:
                    pass
        return "project"

    def _validate_workspace_root(
        self, value: str | os.PathLike[str] | None
    ) -> Path | None:
        if value is None:
            return None
        candidate = Path(value).expanduser().resolve(strict=False)
        try:
            candidate.relative_to(self._policy.root)
        except ValueError as exc:
            raise self._workspace_error(
                "workspace_root_invalid",
                "Agent workspace must be inside the project root",
            ) from exc
        if candidate == self._policy.root:
            raise self._workspace_error(
                "workspace_root_invalid",
                "Agent workspace cannot be the project root",
            )
        return candidate

    def _display_path(self, result: dict[str, Any], target: Path, path_class: str) -> dict[str, Any]:
        result = dict(result)
        if "file_path" in result:
            result["file_path"] = self._logical_path(target, path_class)
        if "path" in result:
            result["path"] = self._logical_path(target, path_class)
        return result

    def _logical_path(self, target: Path, path_class: str) -> str:
        base = {
            "agent": self._agent_work_root,
            "shared": self._shared_work_root,
            "project": self._policy.root,
        }[path_class]
        if base is None:
            return self._policy.relative(target)
        relative = target.relative_to(base.resolve(strict=False))
        if path_class == "project":
            return relative.as_posix() if str(relative) != "." else "."
        prefix = path_class
        return f"{prefix}/{relative.as_posix()}" if str(relative) != "." else prefix

    @staticmethod
    def _workspace_error(code: str, message: str, detail: Any = None) -> SystemToolError:
        return SystemToolError(
            error_type="permission" if code != "invalid_path" else "validation",
            code=code,
            message=message,
            detail=detail or {},
        )

    def _path_read(self, field: str) -> Callable[[BaseModel], tuple[AccessClaim, ...]]:
        return lambda arguments: (
            AccessClaim("read", f"workspace:{self._path_read_value(getattr(arguments, field))}"),
        )

    def _path_write(self, field: str) -> Callable[[BaseModel], tuple[AccessClaim, ...]]:
        def claims(arguments: BaseModel) -> tuple[AccessClaim, ...]:
            try:
                target, _, _ = self._path_write_value(getattr(arguments, field))
            except SystemToolError:
                # Let the handler record a safe rejection reason before the
                # ToolExecutor serializes the user-facing error.
                return (AccessClaim("write", "workspace:*"),)
            return (AccessClaim("write", f"workspace:{target}"),)

        return claims

    def _logical_path_class(self, raw: str) -> str:
        if isinstance(raw, str) and (raw == "shared" or raw.startswith("shared/")):
            return "shared"
        if isinstance(raw, str) and (raw == "project" or raw.startswith("project/")):
            return "project"
        return "agent"

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
