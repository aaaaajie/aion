"""Shared workspace visibility rules for Agent-facing local tools."""

from __future__ import annotations

import os
from pathlib import Path


RUNTIME_CONTROL_PLANE_DIRS = (".aion", ".system-tools")


def is_runtime_control_plane_path(
    root: str | os.PathLike[str], path: str | os.PathLike[str]
) -> bool:
    """Return whether ``path`` belongs to Runtime-owned project state."""

    workspace = Path(root).expanduser().resolve(strict=False)
    candidate = Path(path).expanduser().resolve(strict=False)
    return any(
        _is_within(candidate, workspace / name)
        for name in RUNTIME_CONTROL_PLANE_DIRS
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
