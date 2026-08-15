from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

import agent.skills.capability_packs as packs
from agent.skills.capability_packs import (
    CAPABILITY_PACKS,
    PACK_BY_DIRECTION,
    build_manifest,
    normalize_direction,
)
from agent.skills.catalog import MAX_LISTING_CHARS, SkillCatalog
from agent.skills.discovery import SkillDiscovery
from agent.tooling import ToolRegistry
from tools.binary import BinaryTools
from tools.binaries.validation import check_tool_chain
from tools.pentest import PentestTools
from tools.binaries.offline_tools import LOCK_FILE, WHEELHOUSE, verify_checksums
from tools.binaries.validation import load_tool_manifest
from importlib import import_module


_probe_module = import_module(
    "agent.skills.common.recognize-challenge-direction.scripts.probe_target"
)


def _skill(root: Path, category: str, name: str) -> Path:
    directory = root / category / name
    directory.mkdir(parents=True)
    description = " ".join(name.replace("-", " ").split())
    (directory / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: Use for {description} analysis and testing.\n"
        f"when_to_use: When the bounded task needs {description}.\n"
        "---\n\n# Instructions\nBounded work.\n",
        encoding="utf-8",
    )
    return directory


def _catalog(tmp_path: Path) -> SkillCatalog:
    root = tmp_path / "skills"
    for category in ("common", "challenge", "execution"):
        (root / category).mkdir(parents=True)
    _skill(root, "common", "recognize-challenge-direction")
    _skill(root, "challenge", "challenge-threat-modeling")
    for pack in CAPABILITY_PACKS:
        for name in pack.skills:
            _skill(root, "execution", name)
    (root / "manifest.json").write_text(
        json.dumps(build_manifest(), ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return SkillCatalog(root)


def test_manifest_matches_generated_single_source() -> None:
    repo = Path(__file__).resolve().parents[1] / "agent" / "skills" / "manifest.json"
    assert json.loads(repo.read_text(encoding="utf-8")) == build_manifest()


def test_every_pack_has_at_most_twelve_skills() -> None:
    for pack in CAPABILITY_PACKS:
        assert 1 <= len(pack.skills) <= 12, pack.direction
        assert pack.direction in packs.DIRECTIONS


def test_normalize_direction_maps_legacy_and_six_dimensions() -> None:
    assert normalize_direction("ai") == "evasion"
    assert normalize_direction("blockchain") == "cloud"
    assert normalize_direction("exploit") == "exploit"
    assert normalize_direction(None) == "unknown"
    assert normalize_direction("PENTEST") == "pentest"


def test_probe_script_normalizes_legacy_directions() -> None:
    normalized = _probe_module._normalize_candidates(["ai", "blockchain", "web", "ai"])
    assert normalized == ["evasion", "cloud", "web"]


def test_catalog_mounts_only_manifest_skills(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    execution_mounted = {
        "execution/sqli-sql-injection",
        "execution/ctf-pwn",
        "execution/cloud-k8s",
        "execution/offensive-waf-bypass",
    }
    available = {skill.skill_id for skill in catalog.available("execution")}
    assert execution_mounted <= available
    assert "execution/malware-analysis" not in available
    challenge_available = {skill.skill_id for skill in catalog.available("challenge")}
    assert {
        "common/recognize-challenge-direction",
        "challenge/challenge-threat-modeling",
    } <= challenge_available


def test_execution_listing_stays_within_context_limit(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    assert len(catalog.listing("execution")) <= MAX_LISTING_CHARS


def test_discovery_routes_each_dimension_to_its_pack(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    cases = {
        "web": "SQL injection in the login parameter",
        "pentest": "nmap weak password brute force across services",
        "binary": "reverse the ELF and recover the algorithm",
        "exploit": "stack overflow rop ret2libc heap exploit",
        "cloud": "aws s3 bucket kubernetes metadata",
        "evasion": "waf bypass payload obfuscation prompt injection",
    }
    for direction, text in cases.items():
        candidates = catalog.discovery_candidates(text, limit=12)
        ids = [item["skill_id"] for item in candidates]
        expected = {
            f"execution/{skill}"
            for skill in PACK_BY_DIRECTION[direction].skills
        }
        assert ids, direction
        assert any(item["skill_id"] in expected for item in candidates), direction


class _EventService:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def append_agent_event(
        self, run_id: str, agent_id: str, event_type: str, payload: dict[str, Any]
    ) -> None:
        self.events.append((agent_id, event_type, payload))


def test_discovery_without_model_returns_local_pack_and_never_raises(
    tmp_path: Path,
) -> None:
    class Settings:
        skill_discovery_model = None

    catalog = _catalog(tmp_path)
    service = _EventService()
    discovery = SkillDiscovery(Settings(), catalog, service, "run", client=None)
    result = asyncio.run(
        discovery.candidates_for(
            "exec-1",
            objective="stack overflow rop exploit development",
            task_stage="exploitation",
            hypothesis="ret2libc",
        )
    )
    assert result.source == "local_capability_pack"
    assert result.candidates
    assert all(item.skill_id.startswith("execution/") for item in result.candidates)
    types = {event[1] for event in service.events}
    assert "skill_discovery_fallback" in types
    assert "skill_discovery_completed" in types


def test_binary_tools_are_strict_and_return_evidence(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(
        bytes.fromhex(
            "7f454c4602010100000000000000000002003e0001000000000000000000000000000000004000000000000000000000004000070003000000000000000000000000004000000000000000"
        )
    )
    provider = BinaryTools(tmp_path)
    registry = ToolRegistry([provider])
    assert registry.has_tool("bin_identify")
    assert registry.has_tool("bin_checksec")
    assert registry.has_tool("pwn_pack")
    spec = registry.get("bin_checksec")
    assert spec is not None
    result = spec.handler(spec.input_model.model_validate({"file_path": "sample.bin"}))
    assert result["data"]["pie"] is False
    assert "_aion_evidence" in result
    pack = registry.get("pwn_pack")
    assert pack is not None
    packed = pack.handler(
        pack.input_model.model_validate({"value": 0x11223344, "bits": 64})
    )
    assert packed["data"]["hex"] == "4433221100000000"
    with pytest.raises(Exception):
        pack.input_model.model_validate({"value": "not-an-int"})


def test_pentest_tools_are_bounded_and_structured(tmp_path: Path) -> None:
    provider = PentestTools()
    registry = ToolRegistry([provider])
    assert registry.has_tool("pentest_service_probe")
    assert registry.has_tool("cloud_enum")
    assert registry.has_tool("evasion_payload_analyze")
    spec = registry.get("evasion_payload_analyze")
    assert spec is not None
    result = spec.handler(
        spec.input_model.model_validate({"payload": "%3Cscript%3Ealert(1)%3C/script%3E"})
    )
    assert result["data"]["encodings"]["url_encoded"] is True
    assert "_aion_evidence" in result


def test_doctor_reports_missing_tool_chain(tmp_path: Path) -> None:
    report = check_tool_chain()
    assert isinstance(report["missing"], dict)
    assert isinstance(report["capabilities"], dict)
    assert set(report["capabilities"]) == set(PACK_BY_DIRECTION)


def test_offline_wheelhouse_covers_tools_lock() -> None:
    assert WHEELHOUSE.is_dir(), "offline wheelhouse must be bundled"
    assert LOCK_FILE.is_file(), "tools-requirements.lock must be bundled"
    wheels = {}
    for path in WHEELHOUSE.iterdir():
        name = path.name
        if name.endswith(".whl"):
            package, version = name.split("-", 2)[:2]
            wheels[(package.replace("_", "-").lower(), version.lower())] = path
        elif name.endswith(".tar.gz"):
            stem = name[: -len(".tar.gz")]
            package, version = stem.rsplit("-", 1)
            wheels[(package.replace("_", "-").lower(), version.lower())] = path
    missing = []
    for line in LOCK_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        package, version = line.split("==")
        key = (package.lower().replace("_", "-"), version.lower())
        if key not in wheels:
            missing.append(line)
    assert missing == []


def test_offline_wheelhouse_checksums_match() -> None:
    result = verify_checksums()
    assert result["ok"] is True, result
    assert result["checked"] >= 30


def test_tool_manifest_declares_offline_requirements() -> None:
    manifest = load_tool_manifest()
    assert "wheelhouse" in manifest.get("note", "")
    assert manifest["python_packages"]["unicorn"]["version"] == "2.1.4"
    assert manifest["python_packages"]["angr"]["required"] is False
