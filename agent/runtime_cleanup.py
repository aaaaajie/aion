"""Cleanup of artifacts that must not leak into a fresh Runtime run."""

from __future__ import annotations

import shutil
from pathlib import Path


class FreshRunCleanupError(RuntimeError):
    """Raised when a fresh run cannot remove its old runtime artifacts."""


def cleanup_fresh_run_artifacts(
    *,
    workspace_root: Path,
    run_root: Path,
    run_id: str,
) -> None:
    """Remove only the exact runtime-owned paths for a new run.

    The workspace is also the location of user evidence and, in local mode,
    may be the repository itself.  Consequently this function deliberately
    removes the named SystemTools cache only; it never recursively cleans the
    workspace root or its arbitrary children.
    """

    workspace = workspace_root.expanduser().resolve()
    runs = run_root.expanduser().resolve()
    _validate_run_id(run_id)

    for target in (
        workspace / ".system-tools",
        workspace / ".aion" / "runs" / run_id,
        runs / run_id,
    ):
        _remove_exact(target)


def _validate_run_id(run_id: str) -> None:
    if not run_id or run_id in {".", ".."} or Path(run_id).name != run_id:
        raise FreshRunCleanupError(
            "fresh run cleanup requires run_id to be one path component"
        )


def _remove_exact(target: Path) -> None:
    try:
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)
    except OSError as exc:
        raise FreshRunCleanupError(
            f"cannot clean fresh-run artifact {target}: {exc}"
        ) from exc
