"""Skill catalog, progressive loading, and role filtering tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import agent.skills.catalog as catalog_module
from agent.skills import SkillCatalog, SkillCatalogError, SkillTools


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
    body: str = "Use the available evidence.\n",
) -> Path:
    directory = root / category / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        f"description: {description or f'Use {name} for a bounded task.'}\n"
        "---\n\n"
        f"{body}",
        encoding="utf-8",
    )
    return directory


def test_catalog_filters_roles_and_searches_compact_metadata(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _skill(root, "common", "collect-evidence", description="Collect durable evidence.")
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

    assert [item["skill_id"] for item in catalog.list("challenge")] == [
        "challenge/plan-web",
        "common/collect-evidence",
    ]
    assert [item["skill_id"] for item in catalog.list("execution")] == [
        "common/collect-evidence",
        "execution/auth-bypass",
    ]
    found = catalog.list("execution", query="authentication bypass")
    assert [item["skill_id"] for item in found] == ["execution/auth-bypass"]
    script = next(
        item for item in found[0]["resources"] if item["path"] == "scripts/detect.py"
    )
    assert script["kind"] == "script"
    assert script["shell_path"] == (
        "$AION_SKILLS_ROOT/execution/auth-bypass/scripts/detect.py"
    )


def test_catalog_reads_instruction_and_resources_by_lines(tmp_path: Path) -> None:
    root = _root(tmp_path)
    skill = _skill(
        root,
        "execution",
        "probe-service",
        body="line one\nline two\nline three\n",
    )
    (skill / "references").mkdir()
    (skill / "references" / "notes.md").write_text(
        "alpha\nbeta\ngamma\n", encoding="utf-8"
    )
    catalog = SkillCatalog(root)

    first = catalog.read(
        "execution",
        "execution/probe-service",
        resource="references/notes.md",
        limit=2,
    )
    assert first["content"] == "alpha\nbeta"
    assert first["line_start"] == 1
    assert first["line_end"] == 2
    assert first["has_more"] is True
    assert first["next_offset"] == 2

    final = catalog.read(
        "execution",
        "execution/probe-service",
        resource="references/notes.md",
        offset=first["next_offset"],
        limit=2,
    )
    assert final["content"] == "gamma"
    assert final["has_more"] is False


def test_catalog_bounds_large_read_results(tmp_path: Path) -> None:
    root = _root(tmp_path)
    body = "\n".join(f"{index:03d}-" + "x" * 196 for index in range(100))
    _skill(root, "common", "large-reference", body=body)

    result = SkillCatalog(root).read(
        "execution", "common/large-reference", limit=400
    )

    assert len(result["content"]) <= catalog_module.MAX_READ_CHARS
    assert result["has_more"] is True
    assert 0 < result["next_offset"] < result["total_lines"]


@pytest.mark.parametrize("resource", ["../outside.txt", "/etc/passwd", "references/../SKILL.md"])
def test_catalog_rejects_resource_traversal(tmp_path: Path, resource: str) -> None:
    root = _root(tmp_path)
    _skill(root, "challenge", "plan-safe")
    catalog = SkillCatalog(root)

    with pytest.raises(SkillCatalogError) as error:
        catalog.read("challenge", "challenge/plan-safe", resource=resource)

    assert error.value.code == "skill_resource_outside_root"


def test_catalog_rejects_symlink_escape_and_non_utf8_resource(tmp_path: Path) -> None:
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
        catalog.read(
            "execution", "execution/inspect-input", resource="references/escape.txt"
        )
    assert escaped.value.code == "skill_resource_outside_root"

    with pytest.raises(SkillCatalogError) as binary:
        catalog.read(
            "execution", "execution/inspect-input", resource="references/binary.dat"
        )
    assert binary.value.code == "skill_resource_not_utf8"


def test_catalog_rejects_inaccessible_and_invalid_skills(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _skill(root, "execution", "execution-only")
    catalog = SkillCatalog(root)
    with pytest.raises(SkillCatalogError) as inaccessible:
        catalog.read("challenge", "execution/execution-only")
    assert inaccessible.value.code == "skill_not_found"

    invalid_root = _root(tmp_path / "invalid")
    invalid = invalid_root / "common" / "broken"
    invalid.mkdir()
    (invalid / "SKILL.md").write_text("# no frontmatter\n", encoding="utf-8")
    with pytest.raises(SkillCatalogError) as malformed:
        SkillCatalog(invalid_root)
    assert malformed.value.code == "skill_frontmatter_missing"


def test_catalog_rejects_name_mismatch_and_duplicate_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mismatch_root = _root(tmp_path / "mismatch")
    directory = mismatch_root / "common" / "folder-name"
    directory.mkdir()
    (directory / "SKILL.md").write_text(
        "---\nname: different-name\ndescription: mismatch\n---\n",
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
async def test_skill_tools_validate_arguments_and_return_safe_errors(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _skill(root, "challenge", "plan-web")
    tools = SkillTools(SkillCatalog(root), role="challenge")

    definitions = SkillTools.tool_definitions()
    assert [item["function"]["name"] for item in definitions] == [
        "skill_list",
        "skill_read",
    ]
    assert all(
        item["function"]["parameters"]["additionalProperties"] is False
        for item in definitions
    )
    listed = await tools.dispatch("skill_list", {"query": "web"})
    assert listed["data"]["skills"][0]["skill_id"] == "challenge/plan-web"
    invalid = await tools.dispatch("skill_read", {"skill_id": "../escape"})
    assert invalid["error"]["code"] == "skill_not_found"
    extra = await tools.dispatch("skill_list", {"unexpected": True})
    assert extra["error"]["code"] == "invalid_arguments"
