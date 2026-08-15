"""Tests for fresh-run artifact cleanup."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.config import AgentSettings
from agent.runtime import AgentRuntime
from agent.runtime_cleanup import (
    FreshRunCleanupError,
    cleanup_fresh_run_artifacts,
)


def test_fresh_cleanup_removes_only_runtime_owned_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    run_root = tmp_path / "runs"
    cache = workspace / ".system-tools"
    cache.mkdir(parents=True)
    (cache / "old-task.json").write_text("stale", encoding="utf-8")
    run_dir = run_root / "fresh-run"
    run_dir.mkdir(parents=True)
    (run_dir / "state.sqlite3").write_text("stale", encoding="utf-8")
    evidence_dir = workspace / ".aion" / "runs" / "fresh-run"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "stale.json").write_text("stale", encoding="utf-8")

    evidence = workspace / "evidence" / "keep.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("archive", encoding="utf-8")
    old_run = run_root / "old-run" / "state.sqlite3"
    old_run.parent.mkdir(parents=True)
    old_run.write_text("archive", encoding="utf-8")

    cleanup_fresh_run_artifacts(
        workspace_root=workspace,
        run_root=run_root,
        run_id="fresh-run",
    )

    assert not cache.exists()
    assert not run_dir.exists()
    assert not evidence_dir.exists()
    assert evidence.read_text(encoding="utf-8") == "archive"
    assert old_run.read_text(encoding="utf-8") == "archive"


def test_fresh_cleanup_accepts_missing_artifacts(tmp_path: Path) -> None:
    cleanup_fresh_run_artifacts(
        workspace_root=tmp_path / "workspace",
        run_root=tmp_path / "runs",
        run_id="missing-run",
    )


def test_fresh_cleanup_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(FreshRunCleanupError, match="one path component"):
        cleanup_fresh_run_artifacts(
            workspace_root=tmp_path / "workspace",
            run_root=tmp_path / "runs",
            run_id="../outside",
        )


@pytest.mark.asyncio
async def test_cleanup_failure_blocks_runtime_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent.runtime as runtime_module

    def fail_cleanup(**_kwargs: Any) -> None:
        raise FreshRunCleanupError("cleanup failed")

    monkeypatch.setattr(runtime_module, "cleanup_fresh_run_artifacts", fail_cleanup)
    runtime = AgentRuntime(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        project_root=tmp_path / "workspace",
        run_root=tmp_path / "workspace" / "runs",
    )

    with pytest.raises(FreshRunCleanupError, match="cleanup failed"):
        await runtime.start("fresh", run_id="blocked")

    assert runtime.state_service is None
    assert not (tmp_path / "workspace" / "runs" / "blocked").exists()
