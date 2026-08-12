"""Discover and read immutable skill resources from the release tree."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml


SkillRole = Literal["challenge", "execution"]
SkillCategory = Literal["common", "challenge", "execution"]

SKILL_CATEGORIES: tuple[SkillCategory, ...] = ("common", "challenge", "execution")
ROLE_CATEGORIES: dict[SkillRole, frozenset[SkillCategory]] = {
    "challenge": frozenset({"common", "challenge"}),
    "execution": frozenset({"common", "execution"}),
}
SKILL_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_SKILL_NAME_CHARS = 64
MAX_DESCRIPTION_CHARS = 4_000
MAX_RESOURCE_COUNT = 1_000
MAX_READ_LINES = 1_000
MAX_READ_CHARS = 8_000
MAX_LINE_CHARS = 8_000


class SkillCatalogError(RuntimeError):
    """Safe skill discovery or resource access failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        error_type: str = "validation",
        detail: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.error_type = error_type
        self.detail = detail or {}
        super().__init__(message)


@dataclass(frozen=True)
class SkillResource:
    path: str
    kind: str
    size_bytes: int

    def public(self, skill_id: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
        }
        if self.kind == "script":
            value["shell_path"] = f"$AION_SKILLS_ROOT/{skill_id}/{self.path}"
        return value


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    name: str
    description: str
    category: SkillCategory
    root: Path
    resources: tuple[SkillResource, ...]

    def public(self, *, include_resources: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "skill_id": self.skill_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
        }
        if include_resources:
            value["resources"] = [
                item.public(self.skill_id) for item in self.resources
            ]
        return value


class SkillCatalog:
    """An immutable in-memory index of skills shipped with one Runtime release."""

    def __init__(self, root: Path | str | None = None) -> None:
        source = Path(root) if root is not None else Path(__file__).resolve().parent
        try:
            self.root = source.expanduser().resolve(strict=True)
        except OSError as exc:
            raise SkillCatalogError(
                "skill_root_not_found",
                "The AION skill root does not exist",
                error_type="not_found",
            ) from exc
        if not self.root.is_dir():
            raise SkillCatalogError(
                "skill_root_not_directory", "The AION skill root must be a directory"
            )
        self._skills = self._scan()

    def list(
        self,
        role: SkillRole,
        *,
        query: str | None = None,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        if max_results < 1:
            raise SkillCatalogError(
                "skill_result_limit_invalid", "Skill result limit must be positive"
            )
        categories = self._categories_for_role(role)
        terms = [term for term in (query or "").casefold().split() if term]
        values: list[tuple[int, SkillRecord]] = []
        for skill in self._skills.values():
            if skill.category not in categories:
                continue
            haystack = " ".join(
                (skill.skill_id, skill.name, skill.description)
            ).casefold()
            if terms and not all(term in haystack for term in terms):
                continue
            score = sum(haystack.count(term) for term in terms)
            values.append((score, skill))
        values.sort(key=lambda item: (-item[0], item[1].skill_id))
        return [skill.public() for _, skill in values[:max_results]]

    def read(
        self,
        role: SkillRole,
        skill_id: str,
        *,
        resource: str = "SKILL.md",
        offset: int = 0,
        limit: int = 400,
    ) -> dict[str, Any]:
        if offset < 0 or limit < 1:
            raise SkillCatalogError(
                "skill_read_range_invalid",
                "Skill read offset and limit must define a positive range",
            )
        if limit > MAX_READ_LINES:
            raise SkillCatalogError(
                "skill_read_limit_exceeded",
                f"Skill reads are limited to {MAX_READ_LINES} lines",
            )
        skill = self._skills.get(skill_id)
        if skill is None or skill.category not in self._categories_for_role(role):
            raise SkillCatalogError(
                "skill_not_found",
                "The requested skill is not available to this Agent",
                error_type="not_found",
            )
        relative = self._resource_path(resource)
        indexed = {item.path: item for item in skill.resources}
        resource_record = indexed.get(relative.as_posix())
        if resource_record is None:
            raise SkillCatalogError(
                "skill_resource_not_found",
                "The requested skill resource does not exist",
                error_type="not_found",
            )
        candidate = skill.root.joinpath(*relative.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(skill.root)
        except (OSError, ValueError) as exc:
            raise SkillCatalogError(
                "skill_resource_outside_root",
                "The requested resource escapes its skill directory",
                error_type="permission",
            ) from exc
        if not resolved.is_file():
            raise SkillCatalogError(
                "skill_resource_not_file", "The requested skill resource is not a file"
            )
        try:
            text = resolved.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise SkillCatalogError(
                "skill_resource_not_utf8",
                "The requested skill resource is not UTF-8 text",
            ) from exc
        except OSError as exc:
            raise SkillCatalogError(
                "skill_resource_unreadable",
                "The requested skill resource could not be read",
                error_type="not_found",
            ) from exc

        lines = text.splitlines()
        selected: list[str] = []
        char_count = 0
        requested_end = min(len(lines), offset + limit)
        for line in lines[offset:requested_end]:
            if len(line) > MAX_LINE_CHARS:
                raise SkillCatalogError(
                    "skill_resource_line_too_long",
                    f"Skill resource lines must not exceed {MAX_LINE_CHARS} characters",
                )
            added = len(line) + (1 if selected else 0)
            if selected and char_count + added > MAX_READ_CHARS:
                break
            selected.append(line)
            char_count += added
        consumed = len(selected)
        next_offset = offset + consumed
        has_more = next_offset < len(lines)
        result = {
            "skill": skill.public(include_resources=False),
            "resource": resource_record.public(skill.skill_id),
            "content": "\n".join(selected),
            "offset": offset,
            "line_start": offset + 1 if selected else None,
            "line_end": next_offset if selected else None,
            "total_lines": len(lines),
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
            "content_limit_chars": MAX_READ_CHARS,
        }
        return result

    def _scan(self) -> dict[str, SkillRecord]:
        skills: dict[str, SkillRecord] = {}
        for category in SKILL_CATEGORIES:
            category_root = self.root / category
            if not category_root.is_dir():
                raise SkillCatalogError(
                    "skill_category_missing",
                    f"The required skill category is missing: {category}",
                )
            for skill_root in sorted(category_root.iterdir(), key=lambda item: item.name):
                if not skill_root.is_dir() or skill_root.name == "__pycache__":
                    continue
                if skill_root.is_symlink():
                    raise SkillCatalogError(
                        "skill_directory_symlink",
                        "Skill directories must not be symbolic links",
                    )
                self._validate_name(skill_root.name, field="folder")
                instructions = skill_root / "SKILL.md"
                if not instructions.is_file():
                    raise SkillCatalogError(
                        "skill_instructions_missing",
                        f"Skill is missing SKILL.md: {category}/{skill_root.name}",
                    )
                name, description = self._frontmatter(instructions)
                if name != skill_root.name:
                    raise SkillCatalogError(
                        "skill_name_mismatch",
                        "Skill frontmatter name must match its folder name",
                        detail={"folder": skill_root.name, "name": name},
                    )
                skill_id = f"{category}/{skill_root.name}"
                if skill_id in skills:
                    raise SkillCatalogError("duplicate_skill_id", "Duplicate skill id")
                resources = self._resources(skill_root)
                skills[skill_id] = SkillRecord(
                    skill_id=skill_id,
                    name=name,
                    description=description,
                    category=category,
                    root=skill_root.resolve(strict=True),
                    resources=resources,
                )
        return skills

    def _frontmatter(self, path: Path) -> tuple[str, str]:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SkillCatalogError(
                "skill_instructions_unreadable", "SKILL.md must be readable UTF-8 text"
            ) from exc
        lines = content.splitlines()
        if not lines or lines[0].strip() != "---":
            raise SkillCatalogError(
                "skill_frontmatter_missing", "SKILL.md must start with YAML frontmatter"
            )
        try:
            end = next(
                index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"
            )
        except StopIteration as exc:
            raise SkillCatalogError(
                "skill_frontmatter_unclosed", "SKILL.md YAML frontmatter is not closed"
            ) from exc
        try:
            metadata = yaml.safe_load("\n".join(lines[1:end]))
        except yaml.YAMLError as exc:
            raise SkillCatalogError(
                "skill_frontmatter_invalid", "SKILL.md YAML frontmatter is invalid"
            ) from exc
        if not isinstance(metadata, dict):
            raise SkillCatalogError(
                "skill_frontmatter_invalid", "SKILL.md frontmatter must be an object"
            )
        name = metadata.get("name")
        description = metadata.get("description")
        if not isinstance(name, str):
            raise SkillCatalogError(
                "skill_name_invalid", "Skill name must be a string"
            )
        self._validate_name(name, field="name")
        if not isinstance(description, str) or not description.strip():
            raise SkillCatalogError(
                "skill_description_invalid", "Skill description must be a non-empty string"
            )
        description = " ".join(description.split())
        if len(description) > MAX_DESCRIPTION_CHARS:
            raise SkillCatalogError(
                "skill_description_too_long",
                f"Skill descriptions must not exceed {MAX_DESCRIPTION_CHARS} characters",
            )
        return name, description

    def _resources(self, skill_root: Path) -> tuple[SkillResource, ...]:
        values: list[SkillResource] = []
        for path in sorted(skill_root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = path.relative_to(skill_root).as_posix()
            first = PurePosixPath(relative).parts[0]
            kind = {
                "SKILL.md": "instructions",
                "scripts": "script",
                "references": "reference",
                "assets": "asset",
            }.get(first, "resource")
            values.append(
                SkillResource(path=relative, kind=kind, size_bytes=path.stat().st_size)
            )
            if len(values) > MAX_RESOURCE_COUNT:
                raise SkillCatalogError(
                    "too_many_skill_resources",
                    f"A skill may contain at most {MAX_RESOURCE_COUNT} files",
                )
        return tuple(values)

    @staticmethod
    def _resource_path(value: str) -> PurePosixPath:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise SkillCatalogError(
                "skill_resource_invalid", "Skill resource path must be non-empty"
            )
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise SkillCatalogError(
                "skill_resource_outside_root",
                "Skill resource paths must stay inside one skill",
                error_type="permission",
            )
        return path

    @staticmethod
    def _validate_name(value: str, *, field: str) -> None:
        if (
            len(value) > MAX_SKILL_NAME_CHARS
            or SKILL_NAME_PATTERN.fullmatch(value) is None
        ):
            raise SkillCatalogError(
                "skill_name_invalid",
                f"Skill {field} must use lowercase letters, digits, and hyphens",
            )

    @staticmethod
    def _categories_for_role(role: SkillRole) -> frozenset[SkillCategory]:
        categories = ROLE_CATEGORIES.get(role)
        if categories is None:
            raise SkillCatalogError(
                "skill_role_not_allowed",
                "This Agent role cannot access skills",
                error_type="permission",
            )
        return categories
