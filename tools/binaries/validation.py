"""Doctor-facing validation of the fixed-version tool chain."""

from __future__ import annotations

import json
import hashlib
import os
import platform
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from agent.skills.capability_packs import CAPABILITY_PACKS
from .layout import ToolchainError, toolchain_for
from .offline_tools import _missing_wheels, verify_checksums


def load_tool_manifest(root: Path | None = None) -> dict[str, Any]:
    source = root or Path(__file__).resolve().parent
    path = source / "manifest.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"tool manifest is unreadable: {path}") from exc
    if not isinstance(value, dict) or "system_binaries" not in value:
        raise ValueError("tool manifest must declare system_binaries")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _target_report(manifest: dict[str, Any]) -> dict[str, Any]:
    target = manifest.get("target", {})
    expected_os = str(target.get("os", "linux"))
    expected_arch = str(target.get("arch", "x86_64"))
    expected_python = str(target.get("python", "3.11"))
    actual_os = platform.system().lower()
    actual_arch = platform.machine().lower()
    arch_aliases = {"amd64": "x86_64", "x86-64": "x86_64"}
    actual_arch = arch_aliases.get(actual_arch, actual_arch)
    actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    expected_libc = str(target.get("libc", ""))
    actual_libc_name, actual_libc_version = platform.libc_ver()
    libc_ok = True
    if expected_libc:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)>=(\d+)\.(\d+)", expected_libc)
        if match is None:
            libc_ok = False
        else:
            minimum = (int(match.group(2)), int(match.group(3)))
            try:
                actual = tuple(int(part) for part in actual_libc_version.split(".")[:2])
            except ValueError:
                actual = (0, 0)
            libc_ok = actual_libc_name == match.group(1) and actual >= minimum
    return {
        "ok": (
            actual_os == expected_os
            and actual_arch == expected_arch
            and actual_python == expected_python
            and libc_ok
        ),
        "expected": {
            "os": expected_os,
            "arch": expected_arch,
            "python": expected_python,
            "libc": expected_libc,
        },
        "actual": {
            "os": actual_os,
            "arch": actual_arch,
            "python": actual_python,
            "libc": f"{actual_libc_name} {actual_libc_version}".strip(),
        },
        "libc_ok": libc_ok,
    }


def _check_bundled_binary(layout: Any, name: str, entry: dict[str, Any]) -> dict[str, Any]:
    expected_hash = str(entry.get("sha256", "")).lower()
    expected_version = str(entry.get("version", ""))
    path: Path
    try:
        path = layout.binary_path(name)
    except ToolchainError as exc:
        return {"ok": False, "code": "invalid_manifest_path", "error": str(exc)}
    if not path.is_file():
        return {
            "ok": False,
            "code": "bundled_tool_missing",
            "path": str(path),
            "expected_version": expected_version,
        }
    if not path.stat().st_mode & 0o111:
        return {"ok": False, "code": "bundled_tool_not_executable", "path": str(path)}
    actual_hash = _sha256(path)
    if len(expected_hash) != 64 or actual_hash != expected_hash:
        return {
            "ok": False,
            "code": "bundled_tool_hash_mismatch",
            "path": str(path),
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
        }
    args = entry.get("version_args", ["--version"])
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        return {"ok": False, "code": "invalid_version_args", "path": str(path)}
    try:
        result = subprocess.run(
            [str(path), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={
                "PATH": os.pathsep.join((str(layout.bin_dir), "/usr/local/bin", "/usr/bin", "/bin")),
                "LC_ALL": "C",
                "LANG": "C",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "code": "version_probe_failed", "path": str(path), "error": str(exc)}
    output = (result.stdout + "\n" + result.stderr).strip()
    version_pattern = str(entry.get("version_pattern", expected_version))
    version_ok = bool(version_pattern) and version_pattern in output
    if result.returncode != 0 or not version_ok:
        return {
            "ok": False,
            "code": "bundled_tool_version_mismatch",
            "path": str(path),
            "expected_version": expected_version,
            "version_output": output[:500],
            "returncode": result.returncode,
        }
    return {
        "ok": True,
        "path": str(path),
        "sha256": actual_hash,
        "version": expected_version,
    }


def _check_python_bundle(layout: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    runtime = manifest.get("python_runtime", {})
    if not isinstance(runtime, dict):
        return {"ok": False, "code": "invalid_python_runtime_manifest"}
    wheelhouse = (layout.root / str(runtime.get("wheelhouse", "wheelhouse"))).resolve()
    lock = (layout.root / str(runtime.get("lock", "offline-requirements.lock"))).resolve()
    checksums = (layout.root / str(runtime.get("checksums", "wheelhouse.sha256"))).resolve()
    try:
        wheelhouse.relative_to(layout.root.resolve())
        lock.relative_to(layout.root.resolve())
        checksums.relative_to(layout.root.resolve())
    except ValueError:
        return {"ok": False, "code": "python_runtime_path_escapes_bundle"}
    if not wheelhouse.is_dir() or not lock.is_file() or not checksums.is_file():
        return {
            "ok": False,
            "code": "python_runtime_bundle_missing",
            "wheelhouse": str(wheelhouse),
            "lock": str(lock),
            "checksums": str(checksums),
        }
    checksum_report = verify_checksums(wheelhouse, checksums)
    missing = _missing_wheels(lock, wheelhouse)
    if not checksum_report["ok"] or missing:
        return {
            "ok": False,
            "code": "python_runtime_bundle_invalid",
            "checksum": checksum_report,
            "missing_wheels": missing,
        }
    return {
        "ok": True,
        "wheelhouse": str(wheelhouse),
        "lock": str(lock),
        "checked_wheels": checksum_report["checked"],
    }


_PYTHON_PACKAGE_DISTRIBUTIONS = {
    "pwntools": "pwntools",
    "angr": "angr",
    "capstone": "capstone",
    "ropper": "ropper",
    "unicorn": "unicorn",
}

_TOOL_TO_BINARY = {
    "bin_checksec": "checksec",
    "bin_patch_elf": "patchelf",
    "bin_seccomp": "seccomp-tools",
    "bin_debug": "gdb",
    "pentest_service_probe": "nmap",
    "pentest_auth_brute": "hydra",
    "pentest_sqlmap": "sqlmap",
    "pentest_dir_fuzz": "ffuf",
}


def check_tool_chain(root: Path | None = None) -> dict[str, Any]:
    """Validate the self-contained Linux toolchain and installed Python wheels."""

    manifest = load_tool_manifest(root)
    layout = toolchain_for(root)
    python_bundle = _check_python_bundle(layout, manifest)
    present: dict[str, dict[str, Any]] = {}
    missing: dict[str, dict[str, Any]] = {}
    missing_required = False
    if not python_bundle["ok"]:
        missing["python_runtime"] = python_bundle
        missing_required = True
    for name, entry in manifest.get("system_binaries", {}).items():
        if not isinstance(entry, dict):
            missing[name] = {"code": "invalid_manifest_entry"}
            missing_required = True
            continue
        checked = _check_bundled_binary(layout, name, entry)
        if checked["ok"]:
            present[name] = checked
        else:
            missing[name] = {"kind": "system_binary", **checked, **entry}
            if entry.get("required", True):
                missing_required = True
    python_packages: dict[str, dict[str, Any]] = {}
    for name, entry in manifest.get("python_packages", {}).items():
        distribution = _PYTHON_PACKAGE_DISTRIBUTIONS.get(name)
        installed = distribution is not None and _distribution_installed(distribution)
        required = bool(entry.get("required", True))
        installed_version = (
            _distribution_version(distribution)
            if distribution is not None
            else ""
        )
        python_packages[name] = {
            "installed": installed,
            "installed_version": installed_version,
            "expected_version": str(entry.get("version", "")),
            "required": required,
        }
        version_ok = installed and installed_version == str(entry.get("version", ""))
        python_packages[name]["version_ok"] = version_ok
        if not version_ok:
            missing[name] = {"kind": "python_package", **entry}
            if required:
                missing_required = True
    target = _target_report(manifest)
    if not target["ok"]:
        missing["target_platform"] = {"kind": "platform", **target}
        missing_required = True
    capabilities: dict[str, list[str]] = {}
    for pack in CAPABILITY_PACKS:
        capabilities[pack.direction] = sorted(pack.tools)
    blocked = _blocked_capabilities(missing, capabilities)
    return {
        "ok": not missing_required,
        "target": target,
        "present": present,
        "missing": missing,
        "python_packages": python_packages,
        "python_runtime": python_bundle,
        "capabilities": capabilities,
        "blocked_capabilities": blocked,
    }


def required_capabilities(root: Path | None = None) -> dict[str, str]:
    """Map each missing tool to the capability packs it blocks."""

    result = check_tool_chain(root)
    return result["blocked_capabilities"]


def _blocked_capabilities(
    missing: dict[str, Any], capabilities: dict[str, list[str]]
) -> dict[str, str]:
    binary_to_tools = {
        binary: tool for tool, binary in _TOOL_TO_BINARY.items()
    }
    all_tools = {tool for tools in capabilities.values() for tool in tools}
    blocked: dict[str, str] = {}
    for name in missing:
        tool_names = {name}
        if name in binary_to_tools:
            tool_names.add(binary_to_tools[name])
        relevant = tool_names & all_tools
        blocked[name] = ", ".join(
            direction
            for direction, tools in capabilities.items()
            if relevant & set(tools)
        )
    return blocked


def _distribution_installed(distribution: str) -> bool:
    return bool(_distribution_version(distribution))


def _distribution_version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return ""
    except Exception:
        return ""
