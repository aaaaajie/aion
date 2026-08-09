#!/usr/bin/env python3
"""Server-side atomic release manager used by the local AION VPS CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


APP_ROOT = Path("/opt/aion")
RELEASES = APP_ROOT / "releases"
VENVS = APP_ROOT / "venvs"
CURRENT = APP_ROOT / "current"
CURRENT_VENV = APP_ROOT / "current-venv"
HISTORY_FILE = APP_ROOT / "release-history.json"
PENDING_FILE = APP_ROOT / ".release-pending.json"
BACKUP_ROOT = APP_ROOT / "control-backups"
SERVICE = "aion-online.service"
RELEASE_PATTERN = re.compile(r"^[0-9]{14}-[a-f0-9]{12}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
SOURCE_NAMES = (
    "agent",
    "tools",
    "challenges_sdk",
    "third_party",
    "scripts",
    "deploy",
    "pyproject.toml",
    "requirements.lock",
)


class ReleaseError(RuntimeError):
    pass


def _run(
    command: list[str],
    *,
    check: bool = True,
    capture_output: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=capture_output,
        text=True,
        env=env,
    )


def _validate_release_id(value: str) -> str:
    if RELEASE_PATTERN.fullmatch(value) is None:
        raise ReleaseError("invalid release id")
    return value


def _validate_venv_id(value: str) -> str:
    if HASH_PATTERN.fullmatch(value) is None:
        raise ReleaseError("invalid virtual environment id")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _symlink_target(path: Path) -> str | None:
    return os.readlink(path) if path.is_symlink() else None


def _atomic_symlink(target: str, link: Path) -> None:
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        temporary.symlink_to(target)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def _service_active() -> bool:
    return (
        _run(
            ["systemctl", "is-active", "--quiet", SERVICE], check=False
        ).returncode
        == 0
    )


def _legacy_venv_matches(venv_id: str) -> bool:
    lock = APP_ROOT / "requirements.lock"
    python = APP_ROOT / ".venv" / "bin" / "python"
    return lock.is_file() and python.is_file() and _sha256(lock) == venv_id


def _make_read_only(root: Path) -> None:
    for directory, directories, files in os.walk(root):
        path = Path(directory)
        path.chmod(0o755)
        for name in directories:
            (path / name).chmod(0o755)
        for name in files:
            item = path / name
            executable = bool(item.stat().st_mode & 0o111)
            item.chmod(0o755 if executable else 0o644)


def _prepare(release_id: str, incoming: Path, venv_id: str) -> None:
    release_id = _validate_release_id(release_id)
    venv_id = _validate_venv_id(venv_id)
    source = incoming.resolve()
    expected_parent = (RELEASES / f".incoming-{release_id}").resolve()
    if source != expected_parent or not source.is_dir():
        raise ReleaseError("incoming release path is invalid")
    for name in SOURCE_NAMES:
        if not (source / name).exists():
            raise ReleaseError(f"incoming release is missing {name}")
    if _sha256(source / "requirements.lock") != venv_id:
        raise ReleaseError("requirements.lock hash does not match the venv id")
    if sys.version_info[:2] != (3, 11):
        raise ReleaseError("release preparation requires Python 3.11")

    VENVS.mkdir(mode=0o755, parents=True, exist_ok=True)
    venv = VENVS / venv_id
    incoming_venv = VENVS / f".incoming-{venv_id}"
    if (venv / "bin" / "python").is_file():
        validation_python = venv / "bin" / "python"
    elif _legacy_venv_matches(venv_id):
        validation_python = APP_ROOT / ".venv" / "bin" / "python"
    else:
        if incoming_venv.exists():
            shutil.rmtree(incoming_venv)
        _run(["python3", "-m", "venv", str(incoming_venv)])
        _run(
            [
                str(incoming_venv / "bin" / "python"),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "-r",
                str(source / "requirements.lock"),
            ]
        )
        os.replace(incoming_venv, venv)
        validation_python = venv / "bin" / "python"

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source)
    _run(
        [
            str(validation_python),
            "-c",
            "import agent, challenges_sdk, scripts.online_runtime, tools",
        ],
        env=environment,
    )
    _run(
        [
            str(validation_python),
            "-m",
            "compileall",
            "-q",
            str(source / "agent"),
            str(source / "tools"),
            str(source / "challenges_sdk"),
            str(source / "scripts"),
            str(source / "deploy"),
        ]
    )
    for cache in source.rglob("__pycache__"):
        shutil.rmtree(cache)
    (source / ".venv-id").write_text(f"{venv_id}\n", encoding="ascii")
    _make_read_only(source)
    final = RELEASES / release_id
    if final.exists():
        raise ReleaseError("release id already exists")
    os.replace(source, final)
    print(release_id)


def _copy_control_file(source: Path, destination: Path, mode: int) -> None:
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(mode)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _backup_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    missing = destination.with_suffix(destination.suffix + ".missing")
    if source.exists():
        missing.unlink(missing_ok=True)
        shutil.copy2(source, destination)
    else:
        destination.unlink(missing_ok=True)
        missing.touch(mode=0o600)


def _restore_file(backup: Path, destination: Path) -> None:
    missing = backup.with_suffix(backup.suffix + ".missing")
    if missing.exists():
        destination.unlink(missing_ok=True)
    elif backup.exists():
        shutil.copy2(backup, destination)


def _ensure_venv(venv_id: str) -> Path:
    venv = VENVS / venv_id
    if (venv / "bin" / "python").is_file():
        return venv
    if _legacy_venv_matches(venv_id):
        os.replace(APP_ROOT / ".venv", venv)
        return venv
    raise ReleaseError("prepared virtual environment is unavailable")


def _activate(release_id: str) -> None:
    release_id = _validate_release_id(release_id)
    if _service_active():
        raise ReleaseError("service must be inactive before activating a release")
    if PENDING_FILE.exists():
        raise ReleaseError("another release activation is pending")
    release = RELEASES / release_id
    if not release.is_dir():
        raise ReleaseError("release was not found")
    venv_id = _validate_venv_id(
        (release / ".venv-id").read_text(encoding="ascii").strip()
    )
    _ensure_venv(venv_id)

    backup = BACKUP_ROOT / release_id
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    control_files = {
        Path("/usr/local/bin/aionctl"): backup / "aionctl",
        Path("/etc/systemd/system/aion-online.service"): backup / "aion-online.service",
        Path("/etc/nginx/conf.d/aion-monitor.conf"): backup / "aion-monitor.conf",
    }
    for destination, saved in control_files.items():
        _backup_file(destination, saved)

    pending = {
        "release_id": release_id,
        "previous_release_target": _symlink_target(CURRENT),
        "previous_venv_target": _symlink_target(CURRENT_VENV),
        "backup": str(backup),
    }
    _atomic_json(PENDING_FILE, pending)
    try:
        _atomic_symlink(f"releases/{release_id}", CURRENT)
        _atomic_symlink(f"venvs/{venv_id}", CURRENT_VENV)
        _copy_control_file(release / "deploy" / "aionctl", Path("/usr/local/bin/aionctl"), 0o755)
        _copy_control_file(
            release / "deploy" / "aion-online.service",
            Path("/etc/systemd/system/aion-online.service"),
            0o644,
        )
        _copy_control_file(
            release / "deploy" / "aion-monitor.conf",
            Path("/etc/nginx/conf.d/aion-monitor.conf"),
            0o644,
        )
        _run(["systemctl", "daemon-reload"])
        _run(["nginx", "-t"])
        _run(["systemctl", "reload", "nginx"])
    except Exception:
        _rollback_pending()
        raise
    print(release_id)


def _read_pending() -> dict[str, Any]:
    if not PENDING_FILE.is_file():
        raise ReleaseError("no release activation is pending")
    value = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReleaseError("pending release state is invalid")
    return value


def _restore_link(path: Path, target: str | None) -> None:
    if target:
        _atomic_symlink(target, path)
    else:
        path.unlink(missing_ok=True)


def _rollback_pending() -> None:
    pending = _read_pending()
    if _service_active():
        raise ReleaseError("service must be inactive before rolling back links")
    _restore_link(CURRENT, pending.get("previous_release_target"))
    _restore_link(CURRENT_VENV, pending.get("previous_venv_target"))
    backup = Path(str(pending["backup"]))
    _restore_file(backup / "aionctl", Path("/usr/local/bin/aionctl"))
    _restore_file(
        backup / "aion-online.service",
        Path("/etc/systemd/system/aion-online.service"),
    )
    _restore_file(
        backup / "aion-monitor.conf",
        Path("/etc/nginx/conf.d/aion-monitor.conf"),
    )
    _run(["systemctl", "daemon-reload"])
    _run(["nginx", "-t"])
    _run(["systemctl", "reload", "nginx"])
    PENDING_FILE.unlink(missing_ok=True)


def _history() -> list[str]:
    if not HISTORY_FILE.is_file():
        return []
    value = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ReleaseError("release history is invalid")
    return [item for item in value if isinstance(item, str) and RELEASE_PATTERN.fullmatch(item)]


def _migrate_legacy_flat() -> None:
    destination = APP_ROOT / "legacy-flat"
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in SOURCE_NAMES:
        source = APP_ROOT / name
        if source.exists() and not (destination / name).exists():
            os.replace(source, destination / name)


def _prune(history: list[str]) -> None:
    keep = set(history[-3:])
    current_target = _symlink_target(CURRENT)
    if current_target:
        keep.add(Path(current_target).name)
    for release in RELEASES.iterdir():
        if release.is_dir() and RELEASE_PATTERN.fullmatch(release.name) and release.name not in keep:
            shutil.rmtree(release)
    used_venvs = {
        (RELEASES / release_id / ".venv-id").read_text(encoding="ascii").strip()
        for release_id in keep
        if (RELEASES / release_id / ".venv-id").is_file()
    }
    for venv in VENVS.iterdir():
        if venv.is_dir() and HASH_PATTERN.fullmatch(venv.name) and venv.name not in used_venvs:
            shutil.rmtree(venv)


def _commit() -> None:
    pending = _read_pending()
    release_id = _validate_release_id(str(pending["release_id"]))
    history = [item for item in _history() if item != release_id]
    history.append(release_id)
    _atomic_json(HISTORY_FILE, history[-3:])
    PENDING_FILE.unlink(missing_ok=True)
    _migrate_legacy_flat()
    _prune(history[-3:])
    print(release_id)


def _current(as_json: bool) -> None:
    data = {
        "current": Path(_symlink_target(CURRENT) or "").name or None,
        "venv": Path(_symlink_target(CURRENT_VENV) or "").name or None,
        "history": _history(),
        "pending": PENDING_FILE.exists(),
    }
    if as_json:
        print(json.dumps(data, sort_keys=True))
    else:
        print(data["current"] or "legacy-flat")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--release-id", required=True)
    prepare.add_argument("--incoming", type=Path, required=True)
    prepare.add_argument("--venv-id", required=True)
    activate = subparsers.add_parser("activate")
    activate.add_argument("--release-id", required=True)
    subparsers.add_parser("commit")
    subparsers.add_parser("rollback-pending")
    current = subparsers.add_parser("current")
    current.add_argument("--json", action="store_true")
    return parser


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("release manager must run as root")
    args = _build_parser().parse_args()
    try:
        if args.command == "prepare":
            _prepare(args.release_id, args.incoming, args.venv_id)
        elif args.command == "activate":
            _activate(args.release_id)
        elif args.command == "commit":
            _commit()
        elif args.command == "rollback-pending":
            _rollback_pending()
        elif args.command == "current":
            _current(args.json)
    except (OSError, ValueError, ReleaseError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise SystemExit(f"release-manager: {exc}") from None


if __name__ == "__main__":
    main()
