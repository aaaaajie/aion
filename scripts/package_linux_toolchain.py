#!/usr/bin/env python3
"""Package the pinned Linux x86_64 system tools into a release.

Run this on the connected Linux build host after installing/building the exact
versions declared in ``tools/binaries/manifest.json``.  The competition
runtime never executes this script and never downloads or installs tools.

Example::

    python scripts/package_linux_toolchain.py --source /srv/aion-toolchain/bin
    python scripts/package_linux_toolchain.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN_ROOT = PROJECT_ROOT / "tools" / "binaries"
MANIFEST = TOOLCHAIN_ROOT / "manifest.json"
BIN_DIR = TOOLCHAIN_ROOT / "bin"


class PackagingError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackagingError(f"cannot read {MANIFEST}: {exc}") from exc
    if not isinstance(value, dict):
        raise PackagingError("tool manifest must be an object")
    return value


def _require_linux_builder() -> None:
    machine = platform.machine().lower()
    if platform.system().lower() != "linux" or machine not in {"x86_64", "amd64"}:
        raise PackagingError(
            "system tool packaging must run on a Linux x86_64 builder; "
            f"got {platform.system()} {machine}"
        )


def _write_manifest(value: dict[str, Any]) -> None:
    temporary = MANIFEST.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, MANIFEST)


def package(source: Path) -> dict[str, Any]:
    _require_linux_builder()
    manifest = _load_manifest()
    BIN_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    copied: dict[str, str] = {}
    binaries = manifest.get("system_binaries", {})
    if not isinstance(binaries, dict) or not binaries:
        raise PackagingError("manifest does not declare system_binaries")
    for name, raw_entry in binaries.items():
        if not isinstance(raw_entry, dict):
            raise PackagingError(f"invalid manifest entry: {name}")
        source_name = str(raw_entry.get("source_name", name))
        source_path = (source / source_name).resolve()
        try:
            source_path.relative_to(source.resolve())
        except ValueError as exc:
            raise PackagingError(f"source path escapes input directory: {source_name}") from exc
        if not source_path.is_file():
            raise PackagingError(f"missing Linux tool: {source_path}")
        destination = BIN_DIR / Path(str(raw_entry.get("path", f"bin/{name}"))).name
        shutil.copy2(source_path, destination)
        destination.chmod(destination.stat().st_mode | 0o111)
        raw_entry["path"] = destination.relative_to(TOOLCHAIN_ROOT).as_posix()
        raw_entry["sha256"] = _sha256(destination)
        copied[name] = raw_entry["sha256"]
    _write_manifest(manifest)
    return {"ok": True, "destination": str(BIN_DIR), "sha256": copied}


def check() -> dict[str, Any]:
    sys.path.insert(0, str(PROJECT_ROOT))
    from tools.binaries.validation import check_tool_chain

    report = check_tool_chain(TOOLCHAIN_ROOT)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", type=Path)
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        result = check() if args.check else package(args.source.resolve())
    except (OSError, PackagingError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

