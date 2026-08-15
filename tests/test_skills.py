"""Competition-oriented Skill compilation, activation, and resource tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import agent.skills.catalog as catalog_module
import agent.skills.session as session_module
from agent.skills import (
    SkillCatalog,
    SkillCatalogError,
    SkillSessionContext,
    SkillTools,
)
from agent.tooling import ToolExecutor, ToolRegistry


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "skills"
    for category in ("common", "challenge", "execution"):
        (root / category).mkdir(parents=True)
    return root


def _skill(
    root: Path,
    category: str,
    name: str,
    *,
    description: str | None = None,
    when_to_use: str | None = None,
    auto_activate_for: tuple[str, ...] = (),
    body: str = "Use the available evidence.\n",
) -> Path:
    directory = root / category / name
    directory.mkdir(parents=True)
    auto = "[" + ", ".join(auto_activate_for) + "]"
    (directory / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {description or f'Use {name} for a bounded task.'}\n"
        f"when_to_use: {when_to_use or f'When the bounded task needs {name}.'}\n"
        f"auto_activate_for: {auto}\n"
        "---\n\n"
        f"{body}",
        encoding="utf-8",
    )
    return directory


class _SkillStateService:
    def __init__(self) -> None:
        self.active: dict[tuple[str, str], dict[str, Any]] = {}
        self.writes = 0

    async def activate_agent_skill(
        self,
        run_id: str,
        agent_id: str,
        *,
        skill_id: str,
        content_sha256: str,
        activation_mode: str,
    ) -> dict[str, Any]:
        key = (agent_id, skill_id)
        existing = self.active.get(key)
        if existing is not None:
            return {"activated": False, "active_skill": existing, "agent": {}}
        value = {
            "skill_id": skill_id,
            "content_sha256": content_sha256,
            "activation_mode": activation_mode,
            "activated_at": "2026-08-14T00:00:00+00:00",
        }
        self.active[key] = value
        self.writes += 1
        return {"activated": True, "active_skill": value, "agent": {}}


def _context(
    catalog: SkillCatalog,
    role: str,
    *,
    service: _SkillStateService | None = None,
    agent_id: str = "agent-one",
    active_skills: list[dict[str, Any]] | None = None,
) -> SkillSessionContext:
    return SkillSessionContext(
        catalog,
        role=role,  # type: ignore[arg-type]
        service=service or _SkillStateService(),  # type: ignore[arg-type]
        run_id="run-one",
        agent_id=agent_id,
        active_skills=active_skills or [],
    )


def test_catalog_compiles_role_listings_auto_skills_and_invocation_payload(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    common = _skill(
        root,
        "common",
        "collect-evidence",
        description="Collect durable evidence.",
        auto_activate_for=("challenge",),
        body="# Evidence\n\nKeep exact paths.\n",
    )
    (common / "references").mkdir()
    (common / "references" / "notes.md").write_text("reference", encoding="utf-8")
    _skill(root, "challenge", "plan-web", description="Plan a web challenge.")
    execution = _skill(
        root,
        "execution",
        "auth-bypass",
        description="Detect login and authentication bypasses.",
    )
    (execution / "scripts").mkdir()
    (execution / "scripts" / "detect.py").write_text("print('ok')\n", encoding="utf-8")

    catalog = SkillCatalog(root)

    assert [item.skill_id for item in catalog.available("challenge")] == [
        "challenge/plan-web",
        "common/collect-evidence",
    ]
    assert [item.skill_id for item in catalog.auto_skills("challenge")] == [
        "common/collect-evidence"
    ]
    assert "common/collect-evidence" not in catalog.listing("challenge")
    assert "challenge/plan-web" in catalog.listing("challenge")
    assert len(catalog.listing("execution")) <= catalog_module.MAX_LISTING_CHARS

    payload = catalog.invocation_payload(
        "execution", "execution/auth-bypass", activation_status="activated"
    )
    assert payload["instructions"].startswith("Use the available evidence")
    assert "---" not in payload["instructions"]
    script = next(item for item in payload["resources"] if item["kind"] == "script")
    assert script["shell_path"] == (
        "$AION_SKILLS_ROOT/execution/auth-bypass/scripts/detect.py"
    )
    assert len(json.dumps(payload, ensure_ascii=False)) < catalog_module.MAX_INVOKE_RESULT_CHARS


def test_catalog_ignores_only_finder_copy_of_a_canonical_skill(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    canonical = _skill(root, "execution", "probe-service")
    duplicate = root / "execution" / "probe-service copy"
    duplicate.mkdir()
    (duplicate / "SKILL.md").write_text(
        (canonical / "SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    catalog = SkillCatalog(root)
    assert [item.skill_id for item in catalog.available("execution")] == [
        "execution/probe-service"
    ]


def test_catalog_reads_only_supporting_resources_by_lines(tmp_path: Path) -> None:
    root = _root(tmp_path)
    skill = _skill(root, "execution", "probe-service")
    (skill / "references").mkdir()
    (skill / "references" / "notes.md").write_text(
        "alpha\nbeta\ngamma\n", encoding="utf-8"
    )
    catalog = SkillCatalog(root)

    first = catalog.read_resource(
        "execution",
        "execution/probe-service",
        resource="references/notes.md",
        limit=2,
    )
    assert first["content"] == "alpha\nbeta"
    assert first["next_offset"] == 2
    final = catalog.read_resource(
        "execution",
        "execution/probe-service",
        resource="references/notes.md",
        offset=first["next_offset"],
        limit=2,
    )
    assert final["content"] == "gamma"
    assert final["has_more"] is False

    with pytest.raises(SkillCatalogError) as core:
        catalog.read_resource(
            "execution", "execution/probe-service", resource="SKILL.md"
        )
    assert core.value.code == "skill_core_read_not_allowed"
    assert core.value.retry_tool == "skill_invoke"


def test_catalog_bounds_large_resource_and_pages_large_instructions(tmp_path: Path) -> None:
    root = _root(tmp_path)
    skill = _skill(root, "common", "large-reference")
    (skill / "references").mkdir()
    body = "\n".join(f"{index:03d}-" + "x" * 196 for index in range(100))
    (skill / "references" / "large.md").write_text(body, encoding="utf-8")
    result = SkillCatalog(root).read_resource(
        "execution", "common/large-reference", resource="references/large.md"
    )
    assert len(result["content"]) <= catalog_module.MAX_READ_CHARS
    assert result["has_more"] is True

    large_root = _root(tmp_path / "large")
    _skill(
        large_root,
        "common",
        "large-core",
        body="# Guide\n\n" + "\n".join("x" * 1_000 for _ in range(9)),
    )
    large_catalog = SkillCatalog(large_root)
    record = large_catalog.get("execution", "common/large-core")
    assert len(record.activation_view) <= catalog_module.MAX_ACTIVATION_VIEW_CHARS
    assert len(record.activation_view) < len(record.instructions)
    page = large_catalog.read_resource(
        "execution", "common/large-core", resource="instructions", limit=10
    )
    assert page["resource"]["kind"] == "instructions"
    assert page["content"].startswith("# Guide")

    invalid = _root(tmp_path / "invalid")
    _skill(
        invalid,
        "common",
        "large-core",
        body="x" * (catalog_module.MAX_SKILL_BODY_CHARS + 1),
    )
    with pytest.raises(SkillCatalogError) as too_large:
        SkillCatalog(invalid)
    assert too_large.value.code == "skill_core_too_large"
    assert too_large.value.detail["path"].endswith("common/large-core/SKILL.md")


def test_catalog_derives_optional_when_to_use_from_body_then_description(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    directory = root / "execution" / "body-routing"
    directory.mkdir()
    (directory / "SKILL.md").write_text(
        "---\nname: body-routing\ndescription: Fallback description.\n---\n\n"
        "# Guide\n\n## When to use\n\n- Use when SQL login behavior needs validation.\n\n"
        "## When to Use\n\nThis duplicate must not be selected.\n",
        encoding="utf-8",
    )
    fallback = root / "execution" / "description-routing"
    fallback.mkdir()
    (fallback / "SKILL.md").write_text(
        "---\nname: description-routing\ndescription: Use for fallback routing.\n---\n\nBody.\n",
        encoding="utf-8",
    )
    catalog = SkillCatalog(root)
    assert catalog.get("execution", "execution/body-routing").when_to_use == (
        "Use when SQL login behavior needs validation."
    )
    assert catalog.get(
        "execution", "execution/description-routing"
    ).when_to_use == "Use for fallback routing."


@pytest.mark.parametrize("resource", ["../outside.txt", "/etc/passwd", "references/../x"])
def test_catalog_rejects_resource_traversal(tmp_path: Path, resource: str) -> None:
    root = _root(tmp_path)
    _skill(root, "challenge", "plan-safe")
    with pytest.raises(SkillCatalogError) as error:
        SkillCatalog(root).read_resource(
            "challenge", "challenge/plan-safe", resource=resource
        )
    assert error.value.code == "skill_resource_outside_root"


def test_catalog_rejects_symlink_binary_invalid_role_and_invalid_frontmatter(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    skill = _skill(root, "execution", "inspect-input")
    references = skill / "references"
    references.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    os.symlink(outside, references / "escape.txt")
    (references / "binary.dat").write_bytes(b"\xff\xfe")
    catalog = SkillCatalog(root)
    with pytest.raises(SkillCatalogError) as escaped:
        catalog.read_resource(
            "execution", "execution/inspect-input", resource="references/escape.txt"
        )
    assert escaped.value.code == "skill_resource_outside_root"
    with pytest.raises(SkillCatalogError) as binary:
        catalog.read_resource(
            "execution", "execution/inspect-input", resource="references/binary.dat"
        )
    assert binary.value.code == "skill_resource_not_utf8"
    with pytest.raises(SkillCatalogError) as inaccessible:
        catalog.get("challenge", "execution/inspect-input")
    assert inaccessible.value.code == "skill_not_found"

    invalid = _root(tmp_path / "invalid")
    _skill(invalid, "common", "bad-role", auto_activate_for=("chief",))
    with pytest.raises(SkillCatalogError) as bad_role:
        SkillCatalog(invalid)
    assert bad_role.value.code == "skill_auto_activate_for_invalid"


def test_catalog_rejects_name_mismatch_and_duplicate_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mismatch_root = _root(tmp_path / "mismatch")
    directory = mismatch_root / "common" / "folder-name"
    directory.mkdir()
    (directory / "SKILL.md").write_text(
        "---\nname: different-name\ndescription: mismatch\n"
        "when_to_use: during a mismatch test\nauto_activate_for: []\n"
        "---\nbody\n",
        encoding="utf-8",
    )
    with pytest.raises(SkillCatalogError) as mismatch:
        SkillCatalog(mismatch_root)
    assert mismatch.value.code == "skill_name_mismatch"

    duplicate_root = _root(tmp_path / "duplicate")
    _skill(duplicate_root, "common", "same-skill")
    monkeypatch.setattr(catalog_module, "SKILL_CATEGORIES", ("common", "common"))
    with pytest.raises(SkillCatalogError) as duplicate:
        SkillCatalog(duplicate_root)
    assert duplicate.value.code == "duplicate_skill_id"


@pytest.mark.asyncio
async def test_session_auto_activation_invoke_idempotency_and_resource_gate(
    tmp_path: Path,
) -> None:
    root = _root(tmp_path)
    auto = _skill(
        root,
        "common",
        "direction",
        auto_activate_for=("challenge",),
        body="Classify the challenge.\n",
    )
    (auto / "references").mkdir()
    (auto / "references" / "web.md").write_text("web rules", encoding="utf-8")
    _skill(root, "execution", "manual")
    catalog = SkillCatalog(root)
    service = _SkillStateService()

    challenge = _context(catalog, "challenge", service=service)
    await challenge.ensure_auto_activated()
    assert service.writes == 1
    assert "<active_skills>" in challenge.render_system_context()
    assert "Classify the challenge." in challenge.render_system_context()
    assert "common/direction" not in catalog.listing("challenge")

    execution = _context(catalog, "execution", service=service, agent_id="execution")
    with pytest.raises(SkillCatalogError) as inactive:
        execution.read_resource(
            "common/direction", resource="references/web.md", offset=0, limit=10
        )
    assert inactive.value.code == "skill_not_active"
    first = await execution.invoke("common/direction")
    repeated = await execution.invoke("common/direction")
    assert first["activation_status"] == "activated"
    assert first["instructions"] == "Classify the challenge."
    assert repeated["activation_status"] == "already_active"
    assert repeated["instructions"] is None
    assert service.writes == 2
    assert execution.read_resource(
        "common/direction", resource="references/web.md", offset=0, limit=10
    )["content"] == "web rules"


@pytest.mark.asyncio
async def test_skill_tools_are_strict_solo_and_return_safe_errors(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _skill(root, "challenge", "plan-web")
    context = _context(SkillCatalog(root), "challenge")
    tools = SkillTools(context)
    registry = ToolRegistry([tools])
    definitions = registry.definitions()
    assert [item["function"]["name"] for item in definitions] == [
        "skill_search",
        "skill_invoke",
        "skill_resource_read",
    ]
    assert all(
        item["function"]["parameters"]["additionalProperties"] is False
        for item in definitions
    )

    async def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
        prepared = await ToolExecutor(registry).execute(
            [{"id": name, "function": {"name": name, "arguments": json.dumps(arguments)}}]
        )
        assert prepared[0].result is not None
        return prepared[0].result

    searched = await call("skill_search", {"query": "web planning", "limit": 4})
    assert searched["data"]["skills"][0]["skill_id"] == "challenge/plan-web"
    invoked = await call("skill_invoke", {"skill_id": "challenge/plan-web"})
    assert invoked["data"]["activation_status"] == "activated"
    extra = await call("skill_invoke", {"skill_id": "challenge/plan-web", "extra": 1})
    assert extra["error"]["code"] == "invalid_arguments"
    unknown = await call("skill_invoke", {"skill_id": "../escape"})
    assert unknown["error"]["code"] == "skill_not_found"
    searched_again = await call("skill_search", {"query": "web planning", "limit": 4})
    assert searched_again["data"]["skills"] == []

    mixed = await ToolExecutor(registry).execute(
        [
            {
                "id": "invoke",
                "function": {
                    "name": "skill_invoke",
                    "arguments": '{"skill_id":"challenge/plan-web"}',
                },
            },
            {
                "id": "resource",
                "function": {
                    "name": "skill_resource_read",
                    "arguments": '{"skill_id":"challenge/plan-web","resource":"x"}',
                },
            },
        ]
    )
    assert {item.result["error"]["code"] for item in mixed if item.result} == {
        "solo_tool_must_be_only_call",
        "blocked_by_solo_tool",
    }


@pytest.mark.asyncio
async def test_activation_budget_is_checked_before_state_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    _skill(root, "execution", "large", body="x" * 200)
    service = _SkillStateService()
    context = _context(SkillCatalog(root), "execution", service=service)
    monkeypatch.setattr(session_module, "MAX_ACTIVE_CONTEXT_CHARS", 100)
    with pytest.raises(SkillCatalogError) as error:
        await context.invoke("execution/large")
    assert error.value.code == "skill_context_budget_exceeded"
    assert service.writes == 0


def test_session_restore_rejects_changed_skill_content(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _skill(root, "execution", "immutable", body="current instructions")
    catalog = SkillCatalog(root)
    with pytest.raises(SkillCatalogError) as error:
        _context(
            catalog,
            "execution",
            active_skills=[
                {
                    "skill_id": "execution/immutable",
                    "content_sha256": "0" * 64,
                    "activation_mode": "model",
                    "activated_at": "2026-08-14T00:00:00+00:00",
                }
            ],
        )
    assert error.value.code == "skill_content_changed"


def test_challenge_strategy_skill_is_llm_selected_not_auto_activated() -> None:
    catalog = SkillCatalog(Path(__file__).resolve().parents[1] / "agent" / "skills")
    skill = catalog.get("challenge", "challenge/challenge-threat-modeling")

    assert "challenge" not in skill.auto_activate_for
    assert "first technical dispatch" in skill.when_to_use
    listing = catalog.listing(
        "challenge",
        selection_text=(
            "No attack-surface model exists and the direction is uncertain before "
            "the first technical dispatch"
        ),
    )
    assert "challenge/challenge-threat-modeling" in listing
