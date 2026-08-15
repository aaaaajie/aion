from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.skills import SkillCatalog, SkillSessionContext


class SkillState:
    def __init__(self) -> None:
        self.values: list[str] = []

    async def activate_agent_skill(self, run_id: str, agent_id: str, **value: Any) -> dict[str, Any]:
        self.values.append(value["skill_id"])
        active = {
            "skill_id": value["skill_id"],
            "content_sha256": value["content_sha256"],
            "activation_mode": value["activation_mode"],
            "activated_at": "2026-08-14T00:00:00+00:00",
        }
        return {"activated": True, "active_skill": active, "agent": {}}


def skill(root: Path, name: str) -> None:
    directory = root / "execution" / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Use {name}.\n---\n\n# Instructions\nBounded work.\n",
        encoding="utf-8",
    )


def catalog(tmp_path: Path) -> SkillCatalog:
    root = tmp_path / "skills"
    for category in ("common", "challenge", "execution"):
        (root / category).mkdir(parents=True)
    skill(root, "sql-injection")
    skill(root, "java-deserialization")
    return SkillCatalog(root)


@pytest.mark.asyncio
async def test_execution_candidate_requires_model_confirmation(tmp_path: Path) -> None:
    state = SkillState()
    context = SkillSessionContext(
        catalog(tmp_path),
        role="execution",
        service=state,  # type: ignore[arg-type]
        run_id="run",
        agent_id="agent",
        selection_text="Validate SQL injection on the id parameter",
        presented_candidates=[
            {
                "skill_id": "execution/sql-injection",
                "relevance_reason": "The assignment explicitly names SQL injection.",
            }
        ],
    )
    assert state.values == []
    assert "<skill_candidates>" in context.render_system_context()
    assert "The assignment explicitly names SQL injection" in (
        context.render_system_context()
    )
    activated = await context.invoke("execution/sql-injection")
    assert activated["activation_status"] == "activated"
    assert state.values == ["execution/sql-injection"]


@pytest.mark.asyncio
async def test_generic_http_baseline_does_not_activate_unrelated_skill(tmp_path: Path) -> None:
    state = SkillState()
    context = SkillSessionContext(
        catalog(tmp_path),
        role="execution",
        service=state,  # type: ignore[arg-type]
        run_id="run",
        agent_id="agent",
        selection_text="Collect a normal HTTP service baseline and headers",
    )
    assert state.values == []
    assert "<skill_candidates>" not in context.render_system_context()
