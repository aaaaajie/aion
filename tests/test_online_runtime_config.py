"""Configuration-level tests for the online Runtime launcher."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from scripts import online_runtime as online


def test_online_launcher_uses_unbounded_default_and_monitor() -> None:
    parser = online._build_parser()
    args = parser.parse_args(["--benchmark-token-file", "/run/credentials/token"])

    assert args.wait_seconds == online.DEFAULT_WAIT_SECONDS
    assert args.no_monitor is False
    assert args.monitor_port == online.DEFAULT_MONITOR_PORT
    assert args.workspace_root == online.PROJECT_ROOT


def test_online_launcher_requires_explicit_token_file() -> None:
    parser = online._build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([])


@pytest.mark.asyncio
async def test_resume_requires_an_explicit_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        online.sys,
        "argv",
        [
            "online_runtime.py",
            "--benchmark-token-file",
            "/run/credentials/token",
            "--resume",
        ],
    )

    with pytest.raises(SystemExit):
        await online.async_main()


def test_launch_config_is_strict_and_supports_resume(tmp_path: Path) -> None:
    launch = tmp_path / "launch.json"
    launch.write_text(
        json.dumps({"mode": "resume", "run_id": "online-existing"}),
        encoding="utf-8",
    )

    assert online._read_launch_config(launch) == ("online-existing", True)

    launch.write_text(
        json.dumps({"mode": "resume", "run_id": "../escape"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported"):
        online._read_launch_config(launch)


def test_current_run_marker_is_atomic_and_private(tmp_path: Path) -> None:
    marker = tmp_path / "state" / "current-run-id"

    online._write_current_run(marker, "online-current")

    assert marker.read_text(encoding="utf-8") == "online-current\n"
    assert marker.stat().st_mode & 0o777 == 0o600


def test_benchmark_token_file_requires_exactly_one_line(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("benchmark-secret\n", encoding="utf-8")

    assert online._read_benchmark_token(token_file) == "benchmark-secret"

    token_file.write_text("first\nsecond\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        online._read_benchmark_token(token_file)


def test_explicit_token_overrides_environment_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BENCHMARK_BASE_URL", "https://benchmark.test")
    monkeypatch.setenv("BENCHMARK_TOKEN", "environment-secret")

    tools = online._benchmark_from_token("explicit-secret")

    assert tools._client._token == "explicit-secret"


def test_root_starts_openvpn_without_sudo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(online.os, "geteuid", lambda: 0)
    assert online._openvpn_requires_sudo() is False

    monkeypatch.setattr(online.os, "geteuid", lambda: 501)
    assert online._openvpn_requires_sudo() is True


@pytest.mark.asyncio
async def test_wait_for_operation_handles_completion_stop_and_timeout() -> None:
    stop_event = asyncio.Event()
    phase, result = await online._wait_for_operation(
        asyncio.sleep(0, result="done"),
        stop_event,
    )
    assert (phase, result) == ("completed", "done")

    stop_event.set()
    phase, result = await online._wait_for_operation(
        asyncio.sleep(60),
        stop_event,
    )
    assert (phase, result) == ("stopped", None)

    phase, result = await online._wait_for_operation(
        asyncio.sleep(60),
        asyncio.Event(),
        timeout=0.001,
    )
    assert (phase, result) == ("timeout", None)
