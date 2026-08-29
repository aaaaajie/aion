"""Tests for the monitor process that outlives the online Runtime."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from scripts import runtime_monitor


def _create_run_database(
    database: Path,
    run_id: str,
    *,
    started_at: str,
    updated_at: str,
) -> None:
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT, started_at TEXT, updated_at TEXT)"
        )
        connection.execute(
            "INSERT INTO runs(run_id, started_at, updated_at) VALUES (?, ?, ?)",
            (run_id, started_at, updated_at),
        )


class _FakeMonitor:
    instances: list["_FakeMonitor"] = []

    def __init__(self, database: Path, run_id: str, *, port: int) -> None:
        self.database = database
        self.run_id = run_id
        self.port = port
        self.frozen = False
        self.closed = False
        self.actions: list[str] = []
        self.instances.append(self)

    def start(self) -> str:
        self.actions.append("start")
        return f"http://127.0.0.1:{self.port}/"

    def freeze(self, result: str, *, message: str | None = None) -> None:
        assert result == "stopped"
        assert message and "read-only" in message
        self.frozen = True
        self.actions.append("freeze")

    def resume(self) -> None:
        self.frozen = False
        self.actions.append("resume")

    def close(self) -> None:
        self.closed = True
        self.actions.append("close")


def test_monitor_controller_freezes_and_resumes_without_runtime_restart(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    _FakeMonitor.instances.clear()
    current_run_file = tmp_path / "current-run-id"
    current_run_file.write_text("online-one\n", encoding="utf-8")
    database = tmp_path / "runs" / "online-one" / "state.sqlite3"
    database.parent.mkdir(parents=True)
    database.touch()
    active = True

    monkeypatch.setattr(runtime_monitor, "RuntimeMonitor", _FakeMonitor)
    monkeypatch.setattr(runtime_monitor, "_runtime_active", lambda _service: active)
    controller = runtime_monitor.MonitorController(
        run_root=tmp_path / "runs",
        current_run_file=current_run_file,
        port=8765,
    )

    controller.sync_once()
    monitor = _FakeMonitor.instances[0]
    assert monitor.actions == ["start"]

    active = False
    controller.sync_once()
    assert monitor.actions == ["start", "freeze"]

    active = True
    controller.sync_once()
    assert monitor.actions == ["start", "freeze", "resume"]

    current_run_file.write_text("online-two\n", encoding="utf-8")
    second_database = tmp_path / "runs" / "online-two" / "state.sqlite3"
    second_database.parent.mkdir(parents=True)
    second_database.touch()
    controller.sync_once()
    assert monitor.closed is True
    assert _FakeMonitor.instances[1].run_id == "online-two"


def test_monitor_controller_auto_mounts_newest_sqlite_without_run_marker(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    _FakeMonitor.instances.clear()
    run_root = tmp_path / "runs"
    run_root.mkdir()
    older = run_root / "older" / "state.sqlite3"
    _create_run_database(
        older,
        "older",
        started_at="2026-08-26 10:00:00",
        updated_at="2026-08-26 10:05:00",
    )
    newer = run_root / "newer" / "state.sqlite3"
    _create_run_database(
        newer,
        "newer",
        started_at="2026-08-26 11:00:00",
        updated_at="2026-08-26 11:05:00",
    )

    monkeypatch.setattr(runtime_monitor, "RuntimeMonitor", _FakeMonitor)
    monkeypatch.setattr(runtime_monitor, "_runtime_active", lambda _service: False)
    controller = runtime_monitor.MonitorController(
        run_root=run_root,
        current_run_file=tmp_path / "missing-current-run-id",
        port=8765,
    )

    controller.sync_once()

    assert _FakeMonitor.instances[0].run_id == "newer"
    assert _FakeMonitor.instances[0].actions == ["start", "freeze"]

    latest = run_root / "latest" / "state.sqlite3"
    _create_run_database(
        latest,
        "latest",
        started_at="2026-08-26 12:00:00",
        updated_at="2026-08-26 12:05:00",
    )
    controller.sync_once()

    assert _FakeMonitor.instances[0].closed is True
    assert _FakeMonitor.instances[1].run_id == "latest"


def test_monitor_controller_marker_wins_over_auto_latest(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    _FakeMonitor.instances.clear()
    run_root = tmp_path / "runs"
    run_root.mkdir()
    marker = tmp_path / "current-run-id"
    marker.write_text("marked\n", encoding="utf-8")
    marked = run_root / "marked" / "state.sqlite3"
    marked.parent.mkdir()
    marked.touch()
    newer = run_root / "newer" / "state.sqlite3"
    newer.parent.mkdir()
    newer.touch()

    monkeypatch.setattr(runtime_monitor, "RuntimeMonitor", _FakeMonitor)
    monkeypatch.setattr(runtime_monitor, "_runtime_active", lambda _service: True)
    controller = runtime_monitor.MonitorController(
        run_root=run_root,
        current_run_file=marker,
        port=8765,
    )

    controller.sync_once()

    assert _FakeMonitor.instances[0].run_id == "marked"
