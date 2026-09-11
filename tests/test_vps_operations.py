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


def test_incremental_rsync_command_uses_content_delta_and_hardlinks() -> None:
    operator = _load_script("aion_vps_incremental_test", PROJECT_ROOT / "deploy" / "aion-vps")

    command = operator._rsync_command(
        "root@example:/opt/aion/releases/.incoming-test/",
        base_release_id="20260906013907-995e9ef8145d",
    )

    assert "--checksum" in command
    assert "--executability" in command
    assert "--link-dest" in command
    assert "/opt/aion/releases/20260906013907-995e9ef8145d" in command
    assert "-a" not in command
    assert "--times" not in command
    assert "--owner" not in command
    assert "--group" not in command


def test_deploy_parser_accepts_repeatable_targeted_test_paths() -> None:
    operator = _load_script("aion_vps_test_paths", PROJECT_ROOT / "deploy" / "aion-vps")

    args = operator._build_parser().parse_args(
        [
            "deploy",
            "--benchmark-token",
            "secret",
            "--test-path",
            "tests/test_vps_operations.py",
            "--test-path",
            "tests/test_runtime_web.py::test_runtime_monitor_starts",
        ]
    )

    assert args.test_paths == [
        "tests/test_vps_operations.py",
        "tests/test_runtime_web.py::test_runtime_monitor_starts",
    ]


def test_targeted_local_verify_runs_only_requested_pytest_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operator = _load_script("aion_vps_targeted_verify", PROJECT_ROOT / "deploy" / "aion-vps")
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        commands.append(list(command))
        return None

    monkeypatch.setattr(operator, "_run", fake_run)
    operator._local_verify(["tests/test_vps_operations.py"])

    assert commands[0][-4:] == [
        "-m",
        "pytest",
        "-q",
        "tests/test_vps_operations.py",
    ]
    assert commands[0][-1] == "tests/test_vps_operations.py"
    assert any(
        command[-1].endswith("scripts/runs_download_server.py")
        for command in commands[1:]
    )


def test_targeted_test_paths_are_scoped_to_tests_directory() -> None:
    operator = _load_script("aion_vps_targeted_scope", PROJECT_ROOT / "deploy" / "aion-vps")

    with pytest.raises(operator.OperatorError, match="below tests"):
        operator._validate_test_paths(["README.md"])
    with pytest.raises(operator.OperatorError, match="relative pytest path"):
        operator._validate_test_paths(["--maxfail=1"])


def test_rsync_preview_suppresses_metadata_only_changes(capsys: pytest.CaptureFixture[str]) -> None:
    operator = _load_script("aion_vps_preview_test", PROJECT_ROOT / "deploy" / "aion-vps")

    operator._print_rsync_preview(
        ".f...p... unchanged.md\n"
        "<fcsT.... agent/prompts/chief_agent.txt\n"
        "*deleting old_prompt.txt\n"
        "Number of regular files transferred: 1\n"
        "Total transferred file size: 42 bytes\n"
    )

    output = capsys.readouterr().out
    assert "chief_agent.txt" in output
    assert "old_prompt.txt" in output
    assert "unchanged.md" not in output
    assert "Total transferred file size: 42 bytes" in output


def test_finalize_permissions_never_mutates_hardlinked_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _load_script(
        "release_manager_permissions_test", PROJECT_ROOT / "deploy" / "release_manager.py"
    )
    base = tmp_path / "base"
    incoming = tmp_path / "incoming"
    (base / "agent").mkdir(parents=True)
    (incoming / "agent").mkdir(parents=True)
    base_file = base / "agent" / "unchanged.txt"
    base_file.write_text("unchanged\n", encoding="utf-8")
    base_file.chmod(0o644)
    linked_file = incoming / "agent" / "unchanged.txt"
    linked_file.hardlink_to(base_file)
    new_file = incoming / "agent" / "new.txt"
    new_file.write_text("new\n", encoding="utf-8")
    new_file.chmod(0o600)
    executable = incoming / "agent" / "run.sh"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(manager, "_is_root_owned", lambda _path: True)

    manager._finalize_permissions(incoming, base)

    assert linked_file.samefile(base_file)
    assert base_file.stat().st_mode & 0o777 == 0o644
    assert new_file.stat().st_mode & 0o777 == 0o644
    assert executable.stat().st_mode & 0o777 == 0o755


def test_finalize_permissions_allows_internal_symlinks_and_rejects_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _load_script(
        "release_manager_symlink_test", PROJECT_ROOT / "deploy" / "release_manager.py"
    )
    base = tmp_path / "base"
    incoming = tmp_path / "incoming"
    (base / "agent").mkdir(parents=True)
    (incoming / "agent" / "bin").mkdir(parents=True)
    target = incoming / "agent" / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    link = incoming / "agent" / "bin" / "target.txt"
    link.symlink_to("../target.txt")
    monkeypatch.setattr(manager, "_is_root_owned", lambda _path: True)

    manager._finalize_permissions(incoming, base)
    assert link.is_symlink()
    assert link.resolve() == target

    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    escape = incoming / "agent" / "escape.txt"
    escape.symlink_to(outside)
    with pytest.raises(manager.ReleaseError, match="escapes or is invalid"):
        manager._finalize_permissions(incoming, base)


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


def test_vps_start_forwards_scope_and_resume_rejects_it(monkeypatch):
    operator = _load_script("vps_scope", PROJECT_ROOT / "deploy/aion-vps")
    captured = {}

    def fake_ssh(command, **kwargs):
        captured["command"] = list(command)
        captured.update(kwargs)

    monkeypatch.setattr(operator, "_ssh", fake_ssh)
    args = operator._build_parser().parse_args([
        "start", "--benchmark-token", "secret", "--challenge-code", "b", "--challenge-code", "a",
    ])
    assert args.selected_challenge_codes == ["b", "a"]
    operator._start_remote("fresh", "secret", "run", args.selected_challenge_codes)
    assert captured["command"][-4:] == ["--challenge-code", "b", "--challenge-code", "a"]
    assert captured["input_data"] == b"secret"
    with pytest.raises(operator.OperatorError, match="Resume cannot replace"):
        operator._start_remote("resume", "secret", "run", ["a"])
    with pytest.raises(SystemExit):
        operator._build_parser().parse_args(["resume", "--benchmark-token", "secret", "--challenge-code", "a"])


def test_aionctl_writes_scoped_launch_config_without_starting_service(tmp_path, monkeypatch):
    import json

    control = _load_script("aionctl_scope", PROJECT_ROOT / "deploy/aionctl")
    app_root = tmp_path / "app"
    for relative in ("current/scripts/online_runtime.py", "current-venv/bin/python"):
        path = app_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    runtime_dir = tmp_path / "runtime"
    monkeypatch.setattr(control, "APP_ROOT", app_root)
    monkeypatch.setattr(control, "RUN_ROOT", tmp_path / "runs")
    monkeypatch.setattr(control, "RUNTIME_DIRECTORY", runtime_dir)
    monkeypatch.setattr(control, "LAUNCH_FILE", runtime_dir / "launch.json")
    monkeypatch.setattr(control, "TOKEN_FILE", runtime_dir / "token")
    monkeypatch.setattr(control, "_is_active", lambda: False)
    monkeypatch.setattr(control, "_read_token_stdin", lambda: "secret")
    monkeypatch.setattr(control, "_wait_for_run_ready", lambda run_id: None)
    monkeypatch.setattr(control, "_restart_monitor", lambda: None)
    launches = []
    monkeypatch.setattr(control, "_run", lambda command: launches.append(json.loads(control.LAUNCH_FILE.read_text())))
    control._start("fresh", "run", [" b ", "a", "b"])
    assert launches == [{"mode": "fresh", "run_id": "run", "selected_challenge_codes": ["b", "a"]}]
    assert not control.TOKEN_FILE.exists() and not control.LAUNCH_FILE.exists()
    with pytest.raises(control.ControlError, match="Resume cannot replace"):
        control._start("resume", "run", ["a"])
