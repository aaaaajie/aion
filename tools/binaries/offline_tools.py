"""Offline tool-chain packaging and installation for the competition image.

The competition VPS has no network access.  All tool-chain Python packages are
shipped as Linux x86_64 wheels in ``wheelhouse/`` and installed with
``pip install --no-index --find-links``.  This module is also the single entry
point for regenerating the wheelhouse on a networked build host.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
from typing import Any


TOOLS_ROOT = Path(__file__).resolve().parent
WHEELHOUSE = TOOLS_ROOT / "wheelhouse"
LOCK_FILE = TOOLS_ROOT / "tools-requirements.lock"
OFFLINE_LOCK_FILE = TOOLS_ROOT / "offline-requirements.lock"
MANIFEST_FILE = TOOLS_ROOT / "manifest.json"

PLATFORMS = ("manylinux2014_x86_64", "manylinux_2_28_x86_64")
PYTHON_TAG = "cp311"
ABI_TAG = "cp311"


def checksums(wheelhouse: Path = WHEELHOUSE) -> dict[str, str]:
    values: dict[str, str] = {}
    if not wheelhouse.is_dir():
        return values
    for path in sorted(wheelhouse.iterdir()):
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            values[path.name] = digest.hexdigest()
    return values


def write_checksums(wheelhouse: Path = WHEELHOUSE) -> Path:
    path = wheelhouse.parent / "wheelhouse.sha256"
    path.write_text(
        "\n".join(
            f"{digest}  {name}"
            for name, digest in sorted(checksums(wheelhouse).items())
        )
        + "\n",
        encoding="ascii",
    )
    return path


def verify_checksums(
    wheelhouse: Path = WHEELHOUSE,
    checksums_file: Path | None = None,
) -> dict[str, Any]:
    checksums_file = checksums_file or wheelhouse.parent / "wheelhouse.sha256"
    if not checksums_file.is_file():
        return {"ok": False, "error": "wheelhouse.sha256 is missing"}
    expected = {}
    try:
        lines = checksums_file.read_text(encoding="ascii").splitlines()
        for line in lines:
            if line.strip():
                digest, name = line.split("  ", 1)
                expected[name] = digest
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"wheelhouse.sha256 is invalid: {exc}"}
    actual = checksums(wheelhouse)
    bad = {
        name: {"expected": expected[name], "actual": actual.get(name)}
        for name in expected
        if expected[name] != actual.get(name)
    }
    unlisted = sorted(set(actual) - set(expected))
    return {
        "ok": not bad and not unlisted,
        "checked": len(expected),
        "bad": bad,
        "unlisted": unlisted,
    }


def _locked_packages(lock: Path) -> list[str]:
    packages: list[str] = []
    for raw in lock.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ValueError(f"offline lock entry is not pinned: {line}")
        packages.append(line)
    return packages


def _missing_wheels(lock: Path, wheelhouse: Path) -> list[str]:
    files = {path.name.lower() for path in wheelhouse.iterdir() if path.is_file()}
    # The wheelhouse is generated with pip, so use its package metadata parser
    # rather than trying to reproduce wheel filename normalization here.
    missing: list[str] = []
    for requirement in _locked_packages(lock):
        package, version = requirement.split("==", 1)
        normalized = package.replace("-", "_").lower()
        if not any(
            name.startswith(f"{normalized}-{version.lower()}-")
            or name.startswith(f"{normalized}_{version.lower()}-")
            or name == f"{normalized}-{version.lower()}.tar.gz"
            for name in files
        ):
            missing.append(requirement)
    return missing


def _assert_linux_x86_64() -> None:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError(
            "the bundled toolchain targets Linux x86_64; install must run on the competition image"
        )


def regenerate_wheelhouse(
    *,
    python: str | None = None,
    include_optional: bool = False,
) -> dict[str, Any]:
    """Download the pinned tool chain as Linux wheels into wheelhouse/.

    Run on a networked build host with the same pip used for the image.  The
    optional symbolic-execution packages (angr) are skipped unless requested
    because some of their dependencies only ship as source distributions.
    """

    python = python or sys.executable
    WHEELHOUSE.mkdir(parents=True, exist_ok=True)
    lock = OFFLINE_LOCK_FILE if OFFLINE_LOCK_FILE.is_file() else LOCK_FILE
    packages = _locked_packages(lock)
    if not include_optional:
        manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
        optional = {
            name.lower().replace("-", "_")
            for name, entry in manifest.get("python_packages", {}).items()
            if isinstance(entry, dict) and not entry.get("required", True)
        }
        packages = [
            item
            for item in packages
            if item.split("==", 1)[0].lower().replace("-", "_") not in optional
        ]
    if not packages:
        return {"ok": False, "error": "no packages selected"}
    remaining = packages
    for platform_tag in PLATFORMS:
        if not remaining:
            break
        command = [
            python,
            "-m",
            "pip",
            "download",
            "--dest",
            str(WHEELHOUSE),
            "--no-deps",
            "--only-binary=:all:",
            "--platform",
            platform_tag,
            "--implementation",
            "cp",
            "--python-version",
            PYTHON_TAG,
            "--abi",
            ABI_TAG,
            *remaining,
        ]
        subprocess.run(command, check=False)
        if OFFLINE_LOCK_FILE.is_file():
            remaining = _missing_wheels(OFFLINE_LOCK_FILE, WHEELHOUSE)
        else:
            remaining = [
                item
                for item in remaining
                if not any(
                    name.startswith(item.split("==", 1)[0].lower().replace("-", "_") + "-")
                    for name in checksums(WHEELHOUSE)
                )
            ]
    if remaining:
        return {"ok": False, "error": "no compatible Linux wheel was found", "missing": remaining}
    write_checksums()
    return {
        "ok": True,
        "wheelhouse": str(WHEELHOUSE),
        "package_count": len(packages),
    }


def install_offline(
    *,
    python: str | None = None,
    wheelhouse: Path = WHEELHOUSE,
    lock: Path = OFFLINE_LOCK_FILE,
) -> dict[str, Any]:
    """Install the pinned tool chain from the local wheelhouse with no network."""

    python = python or sys.executable
    if not wheelhouse.is_dir() or not lock.is_file():
        return {
            "ok": False,
            "error": "offline wheelhouse or runtime lock is missing",
        }
    try:
        _assert_linux_x86_64()
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    missing = _missing_wheels(lock, wheelhouse)
    if missing:
        return {"ok": False, "error": "offline wheelhouse is missing pinned artifacts", "missing": missing}
    verified = verify_checksums(wheelhouse)
    if not verified["ok"]:
        return {"ok": False, "error": f"wheelhouse checksum mismatch: {verified}"}
    command = [
        python,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-index",
        "--no-build-isolation",
        "--find-links",
        str(wheelhouse),
        "-r",
        str(lock),
    ]
    env = os.environ.copy()
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_INDEX_URL"] = ""
    env["PIP_EXTRA_INDEX_URL"] = ""
    result = subprocess.run(command, check=False, env=env)
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "wheelhouse": str(wheelhouse),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: offline_tools.py install|bundle [--optional]",
            file=sys.stderr,
        )
        return 2
    command = argv[1]
    if command == "install":
        result = install_offline()
    elif command == "bundle":
        result = regenerate_wheelhouse(include_optional="--optional" in argv[2:])
    elif command == "checksums":
        result = {
            "ok": True,
            "written": str(write_checksums()),
        }
    else:
        print(f"unknown command: {command}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
