"""Discover Skill manifests without loading full SKILL.md instructions eagerly."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import ValidationError

from .models import SkillManifest


class SkillLoadError(RuntimeError):
    """Raised when a project Skill is missing or violates the Router contract."""


@dataclass(frozen=True)
class SkillDefinition:
    manifest: SkillManifest
    root: Path

    @property
    def instructions_path(self) -> Path:
        return self.root / "SKILL.md"

    @property
    def planner_path(self) -> Path:
        return self.root / "scripts" / "planner.py"

    def load_instructions(self) -> str:
        try:
            content = self.instructions_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SkillLoadError(
                f"failed to read SKILL.md for {self.manifest.id}"
            ) from exc
        if not content.strip():
            raise SkillLoadError(f"SKILL.md is empty for {self.manifest.id}")
        return content


def default_skills_root() -> Path:
    return Path(str(files("skills"))).resolve()


def _read_manifest(path: Path) -> SkillManifest:
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SkillLoadError(f"failed to parse Skill manifest: {path}") from exc
    if not isinstance(raw, Mapping):
        raise SkillLoadError(f"Skill manifest must be a mapping: {path}")
    try:
        return SkillManifest.model_validate(dict(raw))
    except ValidationError as exc:
        raise SkillLoadError(f"invalid Skill manifest: {path}: {exc}") from exc


def discover_skills(root: Path | None = None) -> dict[str, SkillDefinition]:
    skills_root = (root or default_skills_root()).resolve()
    if not skills_root.is_dir():
        raise SkillLoadError(f"Skill root does not exist: {skills_root}")

    discovered: dict[str, SkillDefinition] = {}
    for manifest_path in sorted(skills_root.glob("*/*/skill.yaml")):
        relative_parent = manifest_path.parent.relative_to(skills_root)
        domain, skill_name = relative_parent.parts
        expected_id = f"{domain}.{skill_name}"
        manifest = _read_manifest(manifest_path)
        if manifest.id != expected_id:
            raise SkillLoadError(
                f"Skill id/path mismatch: {manifest.id}; expected {expected_id}"
            )
        if manifest.id in discovered:
            raise SkillLoadError(f"duplicate Skill id: {manifest.id}")

        definition = SkillDefinition(manifest=manifest, root=manifest_path.parent)
        if not definition.instructions_path.is_file():
            raise SkillLoadError(f"missing SKILL.md for {manifest.id}")
        if not definition.planner_path.is_file():
            raise SkillLoadError(f"missing scripts/planner.py for {manifest.id}")
        discovered[manifest.id] = definition

    if not discovered:
        raise SkillLoadError(f"no skill.yaml files found under {skills_root}")
    return discovered


@lru_cache(maxsize=1)
def project_skill_registry() -> dict[str, SkillDefinition]:
    return discover_skills()


def skill_definition(skill_id: str) -> SkillDefinition:
    try:
        return project_skill_registry()[skill_id]
    except KeyError as exc:
        raise SkillLoadError(f"unknown Skill id: {skill_id}") from exc
