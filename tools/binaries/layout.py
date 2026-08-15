"""Paths and errors for the self-contained AION toolchain.

The competition image is deliberately not allowed to resolve security tools
from the host PATH.  This module keeps the bundle lookup in one place so
wrappers, the shell sandbox, and doctor use the same release layout.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any


class ToolchainError(RuntimeError):
    """The release does not contain a usable bundled tool."""


@dataclass(frozen=True)
class ToolchainLayout:
    root: Path

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    @property
    def bin_dir(self) -> Path:
        target = self._target()
        value = target.get("binary_dir", "bin")
        path = (self.root / str(value)).resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError as exc:
            raise ToolchainError("toolchain binary_dir escapes the bundle") from exc
        return path

    def _manifest(self) -> dict[str, Any]:
        import json

        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolchainError(
                f"tool manifest is unreadable: {self.manifest_path}"
            ) from exc
        if not isinstance(value, dict):
            raise ToolchainError("tool manifest must be a JSON object")
        return value

    def _target(self) -> dict[str, Any]:
        value = self._manifest().get("target", {})
        return value if isinstance(value, dict) else {}

    def system_entry(self, name: str) -> dict[str, Any]:
        value = self._manifest().get("system_binaries", {}).get(name)
        if not isinstance(value, dict):
            raise ToolchainError(f"tool {name!r} is not declared in the manifest")
        return value

    def binary_path(self, name: str) -> Path:
        entry = self.system_entry(name)
        relative = Path(str(entry.get("path", f"bin/{name}")))
        if relative.is_absolute() or ".." in relative.parts:
            raise ToolchainError(f"tool {name!r} has an unsafe manifest path")
        path = (self.root / relative).resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError as exc:
            raise ToolchainError(f"tool {name!r} escapes the bundle") from exc
        return path

    def command(self, name: str) -> str:
        path = self.binary_path(name)
        if not path.is_file():
            raise ToolchainError(
                f"bundled tool {name!r} is missing: {path}"
            )
        if not os.access(path, os.X_OK):
            raise ToolchainError(
                f"bundled tool {name!r} is not executable: {path}"
            )
        return str(path)


def default_toolchain_root() -> Path:
    configured = os.environ.get("AION_TOOLCHAIN_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent


def toolchain_for(root: str | os.PathLike[str] | None = None) -> ToolchainLayout:
    return ToolchainLayout(
        Path(root).expanduser().resolve() if root is not None else default_toolchain_root()
    )

