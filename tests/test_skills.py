"""Project-local competition Skill discovery and contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.skills import SkillLoadError, discover_skills, project_skill_registry
from scan.contracts import ScannerContext
from scan.registry import COMPETITION_SCANNER_REGISTRY, SKILL_ID_FOR_DOMAIN


EXPECTED_SKILL_IDS = {
    "web.light_scanner",
    "blockchain.light_scanner",
    "ai.light_scanner",
    "binary.light_scanner",
}


def test_four_competition_skills_are_discoverable_and_complete() -> None:
    registry = project_skill_registry()
    assert set(registry) == EXPECTED_SKILL_IDS
    assert set(SKILL_ID_FOR_DOMAIN.values()) == EXPECTED_SKILL_IDS
    assert set(COMPETITION_SCANNER_REGISTRY) == {
        "web",
        "blockchain",
        "ai",
        "other",
    }

    required_sections = (
        "## Purpose",
        "## When to use",
        "## Strategy",
        "## Classification Signals",
        "## Next-batch Handoff",
        "## Avoid",
        "## Success Criteria",
    )
    for definition in registry.values():
        assert definition.manifest.version == "1.0.0"
        assert definition.manifest.risk_level == "low"
        assert definition.instructions_path.name == "SKILL.md"
        assert definition.planner_path.name == "planner.py"
        instructions = definition.load_instructions()
        assert all(section in instructions for section in required_sections)
        assert "简体中文" in instructions
        assert "exact tool names" in instructions
        assert "debugging-only" in instructions
        assert "题目方向：" in instructions
        assert "timeout_seconds <= 480" in instructions
        assert "terminal report" in instructions
        positions = [instructions.index(f"`{step}`") for step in definition.manifest.workflow]
        assert positions == sorted(positions)


def test_skill_manifests_use_exact_planner_tool_names() -> None:
    registry = project_skill_registry()
    for domain, scanner in COMPETITION_SCANNER_REGISTRY.items():
        definition = registry[SKILL_ID_FOR_DOMAIN[domain]]
        tasks = scanner.build_first_round(
            ScannerContext(unique_code="fixture", target_scope=("TARGET",))
        )
        planner_tools = {
            tool_name
            for task in tasks
            for tool_name in task.tool_names
        }
        assert set(definition.manifest.requires.tools) == planner_tools


def test_skill_loader_rejects_id_path_mismatch(tmp_path: Path) -> None:
    skill_root = tmp_path / "skills" / "web" / "light_scanner"
    skill_root.mkdir(parents=True)
    (skill_root / "skill.yaml").write_text(
        """\
id: ai.light_scanner
name: Wrong Path
version: "1.0.0"
category: [web]
stage: [reconnaissance]
description: fixture
risk_level: low
trigger: {keywords: [web], evidence: []}
requires: {tools: [execution_report], permissions: [execution]}
workflow: [report]
outputs:
  findings: [FIXTURE]
  evidence: [test_result]
  credentials: {optional: false}
tags: [fixture]
""",
        encoding="utf-8",
    )

    with pytest.raises(SkillLoadError, match="id/path mismatch"):
        discover_skills(tmp_path / "skills")
