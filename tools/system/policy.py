"""Workspace path policy and system-tool error types."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

DEFAULT_WORKSPACE_ROOT = Path("/Users/mr.li/aion")


class SystemToolError(Exception):
    """Safe, serializable error raised by a system tool operation."""

    def __init__(
        self,
        *,
        error_type: str,
        code: str,
        message: str,
        detail: Any = None,
    ) -> None:
        self.error_type = error_type
        self.code = code
        self.message = message
        self.detail = detail if detail is not None else {}
        super().__init__(message)


def _error(
    error_type: str,
    code: str,
    message: str,
    detail: Any = None,
) -> SystemToolError:
    return SystemToolError(
        error_type=error_type,
        code=code,
        message=message,
        detail=detail,
    )


class WorkspacePolicy:
    """Resolve paths and prevent filesystem access outside one workspace."""

    _BLOCKED_DEVICE_PATHS = {
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/full",
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",
        "/dev/tty",
        "/dev/console",
        "/dev/fd/0",
        "/dev/fd/1",
        "/dev/fd/2",
    }

    def __init__(self, root: str | os.PathLike[str] = DEFAULT_WORKSPACE_ROOT) -> None:
        root_path = Path(root).expanduser()
        try:
            root_path = root_path.resolve(strict=True)
        except FileNotFoundError as exc:
            raise _error(
                "not_found",
                "workspace_not_found",
                "The system-tools workspace does not exist",
            ) from exc
        if not root_path.is_dir():
            raise _error(
                "validation",
                "workspace_not_directory",
                "The system-tools workspace must be a directory",
            )
        self.root = root_path

    def resolve(
        self,
        value: str | os.PathLike[str],
        *,
        must_exist: bool = False,
        allow_root: bool = True,
    ) -> Path:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise _error("validation", "invalid_path", "Path must be a non-empty string")

        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.root / candidate
        candidate = Path(os.path.abspath(os.path.normpath(candidate)))

        resolved = self._resolve_with_missing_tail(candidate)
        if not self._is_within(resolved):
            raise _error(
                "permission",
                "path_outside_workspace",
                "Path is outside the system-tools workspace",
            )
        if not allow_root and resolved == self.root:
            raise _error(
                "permission",
                "workspace_root_protected",
                "The workspace root cannot be removed or replaced",
            )
        if self._is_blocked_device(resolved):
            raise _error(
                "permission",
                "blocked_device_path",
                "Device paths are not available to system tools",
            )
        try:
            mode = resolved.stat().st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and (stat.S_ISCHR(mode) or stat.S_ISBLK(mode)):
            raise _error(
                "permission",
                "blocked_device_path",
                "Device paths are not available to system tools",
            )
        if must_exist and not resolved.exists():
            raise _error("not_found", "path_not_found", "Path does not exist")
        return resolved

    def relative(self, path: Path) -> str:
        resolved = self.resolve(path)
        relative = resolved.relative_to(self.root)
        return "." if str(relative) == "." else relative.as_posix()

    def relative_lexical(self, path: Path) -> str:
        """Return a workspace-relative path without following symlinks."""
        lexical = Path(os.path.abspath(os.path.normpath(path)))
        if not self._is_within(lexical):
            raise _error(
                "permission",
                "path_outside_workspace",
                "Path is outside the system-tools workspace",
            )
        relative = lexical.relative_to(self.root)
        return "." if str(relative) == "." else relative.as_posix()

    def _resolve_with_missing_tail(self, candidate: Path) -> Path:
        missing: list[str] = []
        current = candidate
        while not current.exists() and current != current.parent:
            missing.append(current.name)
            current = current.parent

        try:
            existing = current.resolve(strict=True)
        except FileNotFoundError:
            existing = current.resolve(strict=False)
        return existing.joinpath(*reversed(missing))

    def _is_within(self, path: Path) -> bool:
        try:
            path.relative_to(self.root)
            return True
        except ValueError:
            return False

    def _is_blocked_device(self, path: Path) -> bool:
        path_string = str(path)
        return path_string in self._BLOCKED_DEVICE_PATHS or path_string.startswith("/dev/")

    def validate_pattern(self, pattern: str) -> None:
        if not pattern or "\x00" in pattern:
            raise _error("validation", "invalid_pattern", "Pattern must be non-empty")
        if Path(pattern).is_absolute():
            raise _error(
                "permission",
                "absolute_pattern_not_allowed",
                "Search patterns must be relative to the workspace",
            )
        parts = Path(pattern).parts
        if ".." in parts:
            raise _error(
                "permission",
                "pattern_outside_workspace",
                "Search patterns cannot escape the workspace",
            )
