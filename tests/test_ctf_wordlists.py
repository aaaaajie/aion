"""Validation for the packaged CTF Web candidate dictionaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "tools" / "wordlists" / "ctf"


def _entries(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_manifest_counts_hashes_and_sources_are_current() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    for name, metadata in manifest["lists"].items():
        path = ROOT / name
        entries = _entries(path)
        assert len(entries) == metadata["line_count"]
        assert len(entries) == len(set(entries))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == metadata["sha256"]
        assert metadata["sources"]
        assert len(entries) <= metadata["max_candidates"] or name == "web-paths-quick.txt"


def test_linux_lfi_dictionary_contains_runtime_calibration_targets() -> None:
    entries = set(_entries(ROOT / "linux-lfi.txt"))
    assert {
        "/etc/passwd",
        "/proc/self/cmdline",
        "/proc/self/environ",
        "/proc/mounts",
    } <= entries


def test_historical_paths_are_generic_and_inserted_in_the_middle() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    entries = _entries(ROOT / "web-paths-quick.txt")
    lower, upper = manifest["historical_insert_range"]
    for candidate in manifest["historical_entries"]:
        index = entries.index(candidate) + 1
        assert lower <= index <= upper
    joined = "\n".join(entries)
    assert "admin/flag" not in joined
    assert "challenge/flag" not in joined
    assert "latest/flag" not in joined
    assert "online-" not in joined
    assert not any(candidate.startswith("a0") for candidate in entries)


def test_prompt_and_skill_describe_bounded_dictionary_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    skill = (root / "agent/skills/common/ctf-flag-locator/SKILL.md").read_text(encoding="utf-8")
    solver = (root / "agent/prompts/solver_system.txt").read_text(encoding="utf-8")
    worker = (root / "agent/prompts/worker_system.txt").read_text(encoding="utf-8")
    for content in (skill, solver, worker):
        assert (
            "web-paths-quick.txt" in content
            or "tools/wordlists/ctf" in content
            or "packaged_wordlists" in content
        )
        assert "packaged_wordlists" in content or "打包" in content
        assert "linux-lfi.txt" in content
        assert "页面内容" in content
        assert "256" in content
    assert "不要因为一次未命中直接否定思路" in solver
