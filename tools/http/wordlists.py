"""Trusted read-only wordlists shipped with the AION release."""

from __future__ import annotations

import json
from pathlib import Path

from tools.system.policy import SystemToolError


PACKAGED_WORDLIST_ROOT = Path(__file__).resolve().parents[2] / "tools" / "wordlists" / "ctf"


def resolve_packaged_wordlist(name: str) -> Path:
    """Resolve one manifest-listed wordlist without consulting Agent workspace paths."""

    if not name or Path(name).name != name:
        raise _error("packaged_wordlist_invalid", "Packaged CTF wordlist name is invalid")
    try:
        manifest = json.loads(
            (PACKAGED_WORDLIST_ROOT / "manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise _error(
            "packaged_wordlist_unavailable",
            "Packaged CTF wordlist manifest is unavailable",
        ) from exc
    allowed = manifest.get("lists")
    if not isinstance(allowed, dict) or name not in allowed:
        raise _error("packaged_wordlist_unknown", f"Unknown packaged CTF wordlist: {name}")
    source = (PACKAGED_WORDLIST_ROOT / name).resolve(strict=False)
    try:
        source.relative_to(PACKAGED_WORDLIST_ROOT.resolve())
    except ValueError as exc:
        raise _error("packaged_wordlist_invalid", "Packaged CTF wordlist path is invalid") from exc
    if not source.is_file():
        raise _error(
            "packaged_wordlist_unavailable",
            f"Packaged CTF wordlist is unavailable: {name}",
        )
    return source


def _error(code: str, message: str) -> SystemToolError:
    return SystemToolError(error_type="validation", code=code, message=message)
