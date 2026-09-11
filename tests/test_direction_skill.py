from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.skills import SkillCatalog, SkillSessionContext


class SkillState:
    def __init__(self) -> None:
        self.values: list[str] = []

    async def activate_agent_skill(
        self, run_id: str, agent_id: str, **value: Any
    ) -> dict[str, Any]:
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
    skill(root, "sqli-sql-injection")
    skill(root, "java-deserialization")
    return SkillCatalog(root)


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["solver", "worker"])
async def test_skill_search_is_on_demand_and_explicit_activation_survives_resume(
    tmp_path: Path, role: str
) -> None:
    state = SkillState()
    compiled = catalog(tmp_path)
    context = SkillSessionContext(
        compiled,
        role=role,
        service=state,
        run_id="run",
        agent_id="agent",
    )
    assert state.values == [] and context.render_system_context() == ""
    candidates = context.search("sql injection", limit=5)
    assert any(item["skill_id"] == "execution/sql-injection" for item in candidates)
    assert state.values == [] and context.render_system_context() == ""
    activated = await context.invoke("execution/sql-injection")
    assert activated["activation_status"] == "activated"
    assert state.values == ["execution/sql-injection"]
    assert context.active_skills[0]["activation_mode"] == "model"
    rendered = context.render_system_context()
    assert "<active_skills>" in rendered and "Bounded work." in rendered
    restored = SkillSessionContext(
        compiled,
        role=role,
        service=state,
        run_id="run",
        agent_id="agent",
        active_skills=context.active_skills,
    )
    assert restored.render_system_context() == rendered
    assert state.values == ["execution/sql-injection"]
