"""Tests for local/remote VPS operations without contacting the server."""

from __future__ import annotations

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
from pathlib import Path
import sqlite3
import tarfile

import pytest

from scripts import export_run_bundle


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, path: Path):  # type: ignore[no-untyped-def]
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_start_sends_token_only_over_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    operator = _load_script("aion_vps_test", PROJECT_ROOT / "deploy" / "aion-vps")
    captured: dict[str, object] = {}

    def fake_ssh(command, **kwargs):  # type: ignore[no-untyped-def]
        captured["command"] = list(command)
        captured["input"] = kwargs.get("input_data")
        return None

    monkeypatch.setattr(operator, "_ssh", fake_ssh)

    run_id = operator._start_remote("fresh", "benchmark-secret")

    assert run_id.startswith("online-")
    assert "benchmark-secret" not in " ".join(captured["command"])
    assert captured["input"] == b"benchmark-secret"


def test_deployment_source_allowlist_excludes_local_state() -> None:
    operator = _load_script("aion_vps_sources_test", PROJECT_ROOT / "deploy" / "aion-vps")

    relative = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in operator._iter_source_files()
    }

    assert "scripts/online_runtime.py" in relative
    assert "deploy/aionctl" in relative
    assert ".env" not in relative
    assert not any(path.startswith((".aion/", "evidence/", "work/", "recon/")) for path in relative)


def test_vpn_validation_rejects_host_scripts_and_default_route(tmp_path: Path) -> None:
    operator = _load_script("aion_vps_vpn_test", PROJECT_ROOT / "deploy" / "aion-vps")
    profile = tmp_path / "profile.ovpn"
    profile.write_text("client\nremote vpn.test 1194\nup /tmp/hook\n", encoding="utf-8")
    with pytest.raises(operator.OperatorError, match="host-execution"):
        operator._validate_vpn(profile)

    profile.write_text(
        "client\nremote vpn.test 1194\nredirect-gateway def1\n", encoding="utf-8"
    )
    with pytest.raises(operator.OperatorError, match="default route"):
        operator._validate_vpn(profile)


def test_remote_token_reader_accepts_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    control = _load_script("aionctl_test", PROJECT_ROOT / "deploy" / "aionctl")
    monkeypatch.setattr(control.sys, "stdin", io.StringIO("benchmark-secret\n"))
    assert control._read_token_stdin() == "benchmark-secret"

    monkeypatch.setattr(control.sys, "stdin", io.StringIO("first\nsecond\n"))
    with pytest.raises(control.ControlError, match="one non-empty line"):
        control._read_token_stdin()


def test_diagnostic_bundle_contains_consistent_sqlite_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = "online-bundle"
    run_directory = tmp_path / "runs" / run_id
    run_directory.mkdir(parents=True)
    database = run_directory / "state.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE runs (run_id TEXT PRIMARY KEY, status TEXT, "
            "started_at TEXT, deadline_at TEXT, last_sequence INTEGER)"
        )
        connection.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
            (run_id, "active", "2026-08-08 12:00:00", "2026-08-08 18:00:00", 42),
        )
    monkeypatch.setattr(export_run_bundle, "_journal_since", lambda _value: "journal\n")
    monkeypatch.setattr(export_run_bundle, "_run", lambda _command: "ActiveState=active\n")
    output = tmp_path / "bundle.tar.gz"

    export_run_bundle.create_bundle(
        run_root=tmp_path / "runs",
        run_id=run_id,
        output=output,
    )

    assert output.stat().st_mode & 0o777 == 0o600
    with tarfile.open(output, "r:gz") as archive:
        assert {
            "state.sqlite3",
            "metadata.json",
            "journal.log",
            "service-status.txt",
        }.issubset(archive.getnames())
        snapshot_data = archive.extractfile("state.sqlite3")
        assert snapshot_data is not None
        snapshot = tmp_path / "snapshot.sqlite3"
        snapshot.write_bytes(snapshot_data.read())
    with sqlite3.connect(snapshot) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT last_sequence FROM runs").fetchone() == (42,)
    assert hashlib.sha256(output.read_bytes()).hexdigest()
