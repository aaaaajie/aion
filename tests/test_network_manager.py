"""Tests for the local-only OpenVPN lifecycle manager."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import signal

import pytest

from scripts.network_manager import (
    VPNManager,
    VPNManagerError,
    discover_vpn_config,
    resolve_openvpn_binary,
)


@pytest.fixture
def fake_openvpn(tmp_path: Path) -> Path:
    executable = tmp_path / "fake-openvpn"
    executable.write_text(
        """#!/usr/bin/env python3
import pathlib
import signal
import sys
import time

config = pathlib.Path(sys.argv[sys.argv.index("--config") + 1])
mode = config.read_text(encoding="utf-8").strip()
if mode == "early-exit":
    print("OpenVPN fixture failed before readiness", flush=True)
    raise SystemExit(3)
if mode == "timeout":
    time.sleep(60)
if mode == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("Initialization Sequence Completed", flush=True)
if mode == "exit-after-ready":
    time.sleep(0.2)
    print("OpenVPN fixture disconnected", flush=True)
    raise SystemExit(7)
if mode == "remote-halt":
    time.sleep(0.2)
    print("Halt command was pushed by server ('')", flush=True)
    raise SystemExit(0)
while True:
    time.sleep(1)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _config(tmp_path: Path, mode: str = "ready") -> Path:
    config = tmp_path / "fixture.ovpn"
    config.write_text(mode, encoding="utf-8")
    return config


def _fake_sudo(tmp_path: Path, *, fail_main: bool = False) -> Path:
    executable = tmp_path / "fake-sudo"
    executable.write_text(
        f"""#!/usr/bin/env python3
import os
import sys

arguments = sys.argv[1:]
if arguments and arguments[0] == "-n":
    arguments = arguments[1:]
if arguments and arguments[-1] == "--version":
    expected_sid = os.environ.get("EXPECTED_SUDO_SID")
    if expected_sid is not None and os.getsid(0) != int(expected_sid):
        print("sudo: a password is required", file=sys.stderr, flush=True)
        raise SystemExit(1)
    raise SystemExit(0)
if {fail_main!r}:
    print("sudo: a password is required", file=sys.stderr, flush=True)
    raise SystemExit(1)
expected_sid = int(os.environ["EXPECTED_SUDO_SID"])
if os.getsid(0) != expected_sid:
    print("sudo: a password is required", file=sys.stderr, flush=True)
    raise SystemExit(1)
os.execv(arguments[0], arguments)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def test_vpn_config_discovery_and_explicit_override(tmp_path: Path) -> None:
    project = tmp_path / "project"
    config_dir = project / "config" / "vpn"
    config_dir.mkdir(parents=True)
    first = config_dir / "first.ovpn"
    first.write_text("ready", encoding="utf-8")

    assert discover_vpn_config(project) == first.resolve()

    external = tmp_path / "external.ovpn"
    external.write_text("ready", encoding="utf-8")
    assert discover_vpn_config(project, external) == external.resolve()


def test_vpn_config_discovery_rejects_missing_and_ambiguous(tmp_path: Path) -> None:
    project = tmp_path / "project"
    config_dir = project / "config" / "vpn"
    config_dir.mkdir(parents=True)
    with pytest.raises(VPNManagerError, match="No .ovpn") as missing:
        discover_vpn_config(project)
    assert missing.value.code == "vpn_config_not_found"

    (config_dir / "one.ovpn").write_text("ready", encoding="utf-8")
    (config_dir / "two.ovpn").write_text("ready", encoding="utf-8")
    with pytest.raises(VPNManagerError, match="Multiple .ovpn") as ambiguous:
        discover_vpn_config(project)
    assert ambiguous.value.code == "ambiguous_vpn_config"


def test_configured_openvpn_binary_must_exist(tmp_path: Path) -> None:
    with pytest.raises(VPNManagerError) as caught:
        resolve_openvpn_binary(tmp_path / "missing-openvpn")
    assert caught.value.code == "openvpn_not_found"


def test_openvpn_binary_resolution_preserves_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "openvpn-real"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    link = tmp_path / "openvpn"
    link.symlink_to(target)

    assert resolve_openvpn_binary(link) == link.absolute()


@pytest.mark.asyncio
async def test_vpn_start_is_idempotent_and_close_is_idempotent(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path),
        openvpn_binary=fake_openvpn,
        use_sudo=False,
    )

    first = await manager.start()
    second = await manager.start()
    assert first.ready is True
    assert first.pid == second.pid
    assert manager.status.state == "connected"

    await manager.close()
    await manager.close()
    assert manager.status.state == "stopped"
    assert manager.status.returncode is not None


@pytest.mark.asyncio
async def test_vpn_process_keeps_session_and_owns_process_group(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path),
        openvpn_binary=fake_openvpn,
        use_sudo=False,
    )

    status = await manager.start()
    assert status.pid is not None
    assert os.getsid(status.pid) == os.getsid(0)
    assert os.getpgid(status.pid) == status.pid
    assert status.pid != os.getpgrp()
    await manager.close()


@pytest.mark.asyncio
async def test_sudo_preflight_and_launch_share_parent_session(
    tmp_path: Path,
    fake_openvpn: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EXPECTED_SUDO_SID", str(os.getsid(0)))
    manager = VPNManager(
        _config(tmp_path),
        openvpn_binary=fake_openvpn,
        sudo_binary=_fake_sudo(tmp_path),
    )

    status = await manager.start()
    assert status.ready is True
    assert status.pid is not None
    assert os.getsid(status.pid) == os.getsid(0)
    assert os.getpgid(status.pid) == status.pid
    await manager.close()


@pytest.mark.asyncio
async def test_runtime_sudo_password_error_is_typed(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path),
        openvpn_binary=fake_openvpn,
        sudo_binary=_fake_sudo(tmp_path, fail_main=True),
    )

    with pytest.raises(VPNManagerError) as caught:
        await manager.start()
    assert caught.value.code == "sudo_auth_required"
    assert "sudo -v" in str(caught.value)
    await manager.close()


@pytest.mark.asyncio
async def test_vpn_close_escalates_inside_its_process_group(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    parent_process_group = os.getpgrp()
    manager = VPNManager(
        _config(tmp_path, "ignore-term"),
        openvpn_binary=fake_openvpn,
        stop_timeout_seconds=0.05,
        use_sudo=False,
    )

    status = await manager.start()
    assert status.pid is not None
    assert os.getpgid(status.pid) == status.pid
    assert status.pid != parent_process_group
    await manager.close()
    assert manager.status.returncode == -signal.SIGKILL
    assert os.getpgrp() == parent_process_group


@pytest.mark.asyncio
async def test_vpn_reports_early_exit(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path, "early-exit"),
        openvpn_binary=fake_openvpn,
        use_sudo=False,
    )
    with pytest.raises(VPNManagerError, match="before readiness") as caught:
        await manager.start()
    assert caught.value.code == "vpn_process_failed"
    await manager.close()


@pytest.mark.asyncio
async def test_vpn_start_timeout_stops_process(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path, "timeout"),
        openvpn_binary=fake_openvpn,
        startup_timeout_seconds=0.05,
        use_sudo=False,
    )
    with pytest.raises(VPNManagerError) as caught:
        await manager.start()
    assert caught.value.code == "vpn_start_timeout"
    assert manager.status.returncode is not None
    await manager.close()


@pytest.mark.asyncio
async def test_vpn_wait_failure_detects_disconnect(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path, "exit-after-ready"),
        openvpn_binary=fake_openvpn,
        use_sudo=False,
    )
    await manager.start()
    with pytest.raises(VPNManagerError, match="status 7"):
        await asyncio.wait_for(manager.wait_failure(), timeout=2)
    await manager.close()


@pytest.mark.asyncio
async def test_vpn_remote_halt_is_typed_and_not_a_process_failure(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    manager = VPNManager(
        _config(tmp_path, "remote-halt"),
        openvpn_binary=fake_openvpn,
        use_sudo=False,
    )
    await manager.start()
    with pytest.raises(VPNManagerError) as caught:
        await asyncio.wait_for(manager.wait_failure(), timeout=2)
    assert caught.value.code == "vpn_remote_halt"
    assert manager.status.returncode == 0
    await manager.close()


@pytest.mark.asyncio
async def test_vpn_requires_cached_sudo_credentials(
    tmp_path: Path,
    fake_openvpn: Path,
) -> None:
    sudo = tmp_path / "fake-sudo"
    sudo.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    sudo.chmod(0o755)
    manager = VPNManager(
        _config(tmp_path),
        openvpn_binary=fake_openvpn,
        sudo_binary=sudo,
    )

    with pytest.raises(VPNManagerError, match="sudo -v") as caught:
        await manager.start()
    assert caught.value.code == "sudo_auth_required"
    assert manager.status.state == "idle"
