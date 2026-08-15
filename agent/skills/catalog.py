"""Compile immutable, role-scoped skills from the AION release tree."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import Any, Literal, Mapping, Sequence

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
MAX_LISTING_DESCRIPTION_CHARS = 250
MIN_LISTING_DESCRIPTION_CHARS = 20
MAX_LISTING_CHARS = 2_560
MAX_LISTING_SKILLS = 12
MAX_DISCOVERY_CANDIDATES = 20
MAX_SKILL_BODY_CHARS = 64_000
MAX_INLINE_INSTRUCTIONS_CHARS = 6_000
MAX_ACTIVATION_VIEW_CHARS = 6_000
MAX_INVOKE_RESULT_CHARS = 10_000
MAX_ACTIVE_CONTEXT_CHARS = 16_000
MAX_SEARCH_RESULTS = 8
MAX_INLINE_RESOURCES = 12
MAX_RESOURCE_COUNT = 1_000
MAX_READ_LINES = 1_000
MAX_READ_CHARS = 8_000
MAX_LINE_CHARS = 8_000
ROUTING_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "agent",
        "analysis",
        "api",
        "are",
        "as",
        "audit",
        "available",
        "be",
        "by",
        "challenge",
        "common",
        "do",
        "evidence",
        "execution",
        "for",
        "from",
        "in",
        "into",
        "is",
        "it",
        "of",
        "on",
        "only",
        "or",
        "security",
        "target",
        "task",
        "technique",
        "test",
        "testing",
        "that",
        "the",
        "this",
        "to",
        "tool",
        "use",
        "when",
        "with",
    }
)


def _truncate(value: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    if limit == 1:
        return "…"
    return value[: limit - 1].rstrip() + "…"


class SkillCatalogError(RuntimeError):
    """Safe skill compilation or resource access failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        error_type: str = "validation",
        detail: dict[str, Any] | None = None,
        retry_allowed: bool = False,
        retry_action: str = "none",
        retry_tool: str | None = None,
        same_arguments: bool = False,
    ) -> None:
        self.code = code
        self.message = message
        self.error_type = error_type
        self.detail = detail or {}
        self.retry_allowed = retry_allowed
        self.retry_action = retry_action
        self.retry_tool = retry_tool
        self.same_arguments = same_arguments
        super().__init__(message)


@dataclass(frozen=True)
class SkillResource:
    path: str
    kind: str
    size_bytes: int
    content_sha256: str

    def public(self, skill_id: str) -> dict[str, Any]:
        value: dict[str, Any] = {
            "path": self.path,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
        }
        if self.kind == "script":
            value["shell_path"] = f"$AION_SKILLS_ROOT/{skill_id}/{self.path}"
        return value


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    name: str
    description: str
    when_to_use: str
    auto_activate_for: frozenset[SkillRole]
    category: SkillCategory
    root: Path
    instructions: str
    activation_view: str
    content_sha256: str
    resources: tuple[SkillResource, ...]

    def public(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "name": self.name,
            "description": self.description,
            "when_to_use": self.when_to_use,
            "category": self.category,
            "content_sha256": self.content_sha256,
        }

    def invocation_payload(self, *, activation_status: str) -> dict[str, Any]:
        already_active = activation_status == "already_active"
        payload: dict[str, Any] = {
            "skill": self.public(),
            "activation_status": activation_status,
            "instructions_in_context": already_active,
            "instructions": None if already_active else self.activation_view,
            "instructions_complete": len(self.instructions)
            <= MAX_INLINE_INSTRUCTIONS_CHARS,
            "instruction_resource": (
                None
                if len(self.instructions) <= MAX_INLINE_INSTRUCTIONS_CHARS
                else "instructions"
            ),
            "resource_root": f"$AION_SKILLS_ROOT/{self.skill_id}",
            "resource_count": sum(item.path != "SKILL.md" for item in self.resources),
            "resource_manifest": "manifest",
            "resources": [],
        }
        if already_active:
            return payload
        resources = [item for item in self.resources if item.path != "SKILL.md"]
        for item in resources[:MAX_INLINE_RESOURCES]:
            candidate = {**payload, "resources": [*payload["resources"], item.public(self.skill_id)]}
            if len(self._encoded(candidate)) > MAX_INVOKE_RESULT_CHARS:
                break
            payload = candidate
        if len(self._encoded(payload)) > MAX_INVOKE_RESULT_CHARS:
            instructions = str(payload.get("instructions") or "")
            overflow = len(self._encoded(payload)) - MAX_INVOKE_RESULT_CHARS + 32
            payload["instructions"] = _truncate(instructions, max(0, len(instructions) - overflow))
        return payload

    @staticmethod
    def _encoded(payload: Mapping[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class SkillCatalog:
    """An immutable in-memory index of skills shipped with one Runtime release."""

    def __init__(self, root: Path | str | None = None) -> None:
        started = monotonic()
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
        self._mounted: frozenset[str] | None = None
        manifest = self.root / "manifest.json"
        if manifest.is_file():
            self._mounted = self._load_manifest(manifest)
        self._skills = self._scan()
        self.content_sha256 = sha256(
            "\n".join(
                f"{skill_id}:{skill.content_sha256}"
                for skill_id, skill in sorted(self._skills.items())
            ).encode("utf-8")
        ).hexdigest()
        self.initialization_latency_ms = int((monotonic() - started) * 1_000)

    @property
    def metrics(self) -> dict[str, int | str]:
        return {
            "initialization_latency_ms": self.initialization_latency_ms,
            "skill_count": len(self._skills),
            "content_sha256": self.content_sha256,
        }

    def _load_manifest(self, path: Path) -> frozenset[str]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SkillCatalogError(
                "skill_manifest_unreadable",
                "The skill manifest is not valid JSON",
                detail={"path": str(path)},
            ) from exc
        skills = value.get("skills") if isinstance(value, dict) else None
        if not isinstance(skills, list) or not skills:
            raise SkillCatalogError(
                "skill_manifest_invalid",
                "The skill manifest must list mounted skills",
                detail={"path": str(path)},
            )
        if any(not isinstance(item, str) or not item for item in skills):
            raise SkillCatalogError(
                "skill_manifest_invalid",
                "The skill manifest entries must be non-empty skill ids",
            )
        return frozenset(skills)

    def _is_mounted(self, skill_id: str) -> bool:
        if self._mounted is None:
            return True
        return skill_id in self._mounted

    def available(self, role: SkillRole) -> tuple[SkillRecord, ...]:
        categories = self._categories_for_role(role)
        return tuple(
            sorted(
                (
                    skill
                    for skill in self._skills.values()
                    if skill.category in categories
                ),
                key=lambda skill: skill.skill_id,
            )
        )

    def get(self, role: SkillRole, skill_id: str) -> SkillRecord:
        skill = self._skills.get(skill_id)
        if skill is None or skill.category not in self._categories_for_role(role):
            raise SkillCatalogError(
                "skill_not_found",
                "The requested skill is not available to this Agent",
                error_type="not_found",
            )
        return skill

    def auto_skills(self, role: SkillRole) -> tuple[SkillRecord, ...]:
        return tuple(
            skill for skill in self.available(role) if role in skill.auto_activate_for
        )

    def listing(
        self,
        role: SkillRole,
        *,
        selection_text: str = "",
        excluded_ids: Sequence[str] = (),
    ) -> str:
        excluded = set(excluded_ids)
        skills = [
            skill
            for skill in self.available(role)
            if role not in skill.auto_activate_for and skill.skill_id not in excluded
        ]
        ranked = self._rank(skills, selection_text, include_unmatched=True)
        return self._build_listing([skill for _, skill in ranked[:MAX_LISTING_SKILLS]])

    def discovery_candidates(
        self,
        selection_text: str,
        *,
        limit: int = MAX_DISCOVERY_CANDIDATES,
        excluded_ids: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        """Return bounded Execution candidates without activating a Skill."""

        if limit < 1 or limit > MAX_DISCOVERY_CANDIDATES:
            raise SkillCatalogError(
                "skill_discovery_limit_invalid",
                f"Skill discovery limit must be between 1 and {MAX_DISCOVERY_CANDIDATES}",
            )
        excluded = set(excluded_ids)
        skills = [
            skill
            for skill in self.available("execution")
            if "execution" not in skill.auto_activate_for
            and skill.skill_id not in excluded
            and not self._violates_routing_boundary(skill, selection_text)
        ]
        ranked = self._rank(skills, selection_text, include_unmatched=False)
        return [skill.public() for _, skill in ranked[:limit]]

    def search(
        self,
        role: SkillRole,
        query: str,
        *,
        limit: int = MAX_SEARCH_RESULTS,
        excluded_ids: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        normalized_query = " ".join(query.split())
        if not normalized_query:
            raise SkillCatalogError(
                "skill_search_query_invalid", "Skill search query must not be empty"
            )
        if len(normalized_query) > 500:
            raise SkillCatalogError(
                "skill_search_query_invalid", "Skill search query must not exceed 500 characters"
            )
        if limit < 1 or limit > MAX_SEARCH_RESULTS:
            raise SkillCatalogError(
                "skill_search_limit_invalid",
                f"Skill search limit must be between 1 and {MAX_SEARCH_RESULTS}",
            )
        excluded = set(excluded_ids)
        skills = [
            skill
            for skill in self.available(role)
            if role not in skill.auto_activate_for and skill.skill_id not in excluded
        ]
        ranked = self._rank(skills, normalized_query, include_unmatched=False)
        return [skill.public() for _, skill in ranked[:limit]]

    def invocation_payload(
        self, role: SkillRole, skill_id: str, *, activation_status: str
    ) -> dict[str, Any]:
        return self.get(role, skill_id).invocation_payload(
            activation_status=activation_status
        )

    def read_resource(
        self,
        role: SkillRole,
        skill_id: str,
        *,
        resource: str,
        offset: int = 0,
        limit: int = 400,
    ) -> dict[str, Any]:
        if resource == "SKILL.md":
            raise SkillCatalogError(
                "skill_core_read_not_allowed",
                "Use skill_invoke to activate and read core Skill instructions",
                retry_allowed=True,
                retry_action="rewrite_arguments",
                retry_tool="skill_invoke",
            )
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
        skill = self.get(role, skill_id)
        if resource == "instructions":
            text = skill.instructions
            resource_value = {
                "path": "instructions",
                "kind": "instructions",
                "size_bytes": len(text.encode("utf-8")),
                "content_sha256": sha256(text.encode("utf-8")).hexdigest(),
            }
        elif resource == "manifest":
            text = "\n".join(
                f"{item.path}\t{item.kind}\t{item.size_bytes}\t{item.content_sha256}"
                for item in skill.resources
                if item.path != "SKILL.md"
            )
            resource_value = {
                "path": "manifest",
                "kind": "manifest",
                "size_bytes": len(text.encode("utf-8")),
                "content_sha256": sha256(text.encode("utf-8")).hexdigest(),
            }
        else:
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
            resource_value = resource_record.public(skill.skill_id)

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
        return {
            "skill": skill.public(),
            "resource": resource_value,
            "content": "\n".join(selected),
            "offset": offset,
            "line_start": offset + 1 if selected else None,
            "line_end": next_offset if selected else None,
            "total_lines": len(lines),
            "has_more": has_more,
            "next_offset": next_offset if has_more else None,
            "content_limit_chars": MAX_READ_CHARS,
        }

    def validate_active(
        self, role: SkillRole, active_skills: Sequence[Mapping[str, Any]]
    ) -> tuple[SkillRecord, ...]:
        records: list[SkillRecord] = []
        seen: set[str] = set()
        for value in active_skills:
            skill_id = str(value.get("skill_id") or "")
            if not skill_id or skill_id in seen:
                raise SkillCatalogError(
                    "skill_content_changed",
                    "Persisted Skill activation state is invalid",
                )
            skill = self.get(role, skill_id)
            if value.get("content_sha256") != skill.content_sha256:
                raise SkillCatalogError(
                    "skill_content_changed",
                    "An activated Skill changed after the Agent session started",
                    detail={"skill_id": skill_id},
                )
            records.append(skill)
            seen.add(skill_id)
        if sum(len(item.activation_view) for item in records) > MAX_ACTIVE_CONTEXT_CHARS:
            raise SkillCatalogError(
                "skill_context_budget_exceeded",
                "Activated Skill instructions exceed the Agent context budget",
                detail={"max_chars": MAX_ACTIVE_CONTEXT_CHARS},
            )
        return tuple(records)

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
                # Finder-style duplicate directories are workspace artifacts,
                # not published Skill IDs. Ignore them only when the canonical
                # sibling is present; every other invalid folder remains a
                # startup error.
                if skill_root.name.endswith(" copy") and (
                    category_root / skill_root.name.removesuffix(" copy")
                ).is_dir():
                    continue
                if skill_root.is_symlink():
                    raise SkillCatalogError(
                        "skill_directory_symlink",
                        "Skill directories must not be symbolic links",
                    )
                self._validate_name(skill_root.name, field="folder")
                instructions_path = skill_root / "SKILL.md"
                if not instructions_path.is_file():
                    raise SkillCatalogError(
                        "skill_instructions_missing",
                        f"Skill is missing SKILL.md: {category}/{skill_root.name}",
                    )
                try:
                    name, description, when_to_use, auto_activate_for, instructions = (
                        self._skill_file(instructions_path)
                    )
                except SkillCatalogError as exc:
                    exc.detail.setdefault("path", str(instructions_path))
                    raise
                if name != skill_root.name:
                    raise SkillCatalogError(
                        "skill_name_mismatch",
                        "Skill frontmatter name must match its folder name",
                        detail={"folder": skill_root.name, "name": name},
                    )
                skill_id = f"{category}/{skill_root.name}"
                if skill_id in skills:
                    raise SkillCatalogError("duplicate_skill_id", "Duplicate skill id")
                if not self._is_mounted(skill_id):
                    continue
                resources = self._resources(skill_root)
                activation_view = self._activation_view(
                    description, when_to_use, instructions
                )
                hash_payload = {
                    "name": name,
                    "description": description,
                    "when_to_use": when_to_use,
                    "auto_activate_for": sorted(auto_activate_for),
                    "instructions": instructions,
                    "resources": [
                        {
                            "path": item.path,
                            "kind": item.kind,
                            "size_bytes": item.size_bytes,
                            "content_sha256": item.content_sha256,
                        }
                        for item in resources
                    ],
                }
                record = SkillRecord(
                    skill_id=skill_id,
                    name=name,
                    description=description,
                    when_to_use=when_to_use,
                    auto_activate_for=auto_activate_for,
                    category=category,
                    root=skill_root.resolve(strict=True),
                    instructions=instructions,
                    activation_view=activation_view,
                    content_sha256=sha256(
                        json.dumps(
                            hash_payload,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                    resources=resources,
                )
                payload = record.invocation_payload(activation_status="activated")
                payload["active_skill"] = {
                    "skill_id": skill_id,
                    "content_sha256": record.content_sha256,
                    "activation_mode": "model",
                    "activated_at": "9999-12-31T23:59:59.999999+00:00",
                }
                encoded = json.dumps(
                    {"ok": True, "data": payload},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                if len(encoded) > MAX_INVOKE_RESULT_CHARS:
                    raise SkillCatalogError(
                        "skill_invoke_result_too_large",
                        f"Skill activation results must not exceed {MAX_INVOKE_RESULT_CHARS} characters",
                        detail={"skill_id": skill_id, "result_chars": len(encoded)},
                    )
                skills[skill_id] = record
        return skills

    def _skill_file(
        self, path: Path
    ) -> tuple[str, str, str, frozenset[SkillRole], str]:
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
        when_to_use_raw = metadata.get("when_to_use")
        if not isinstance(name, str):
            raise SkillCatalogError("skill_name_invalid", "Skill name must be a string")
        self._validate_name(name, field="name")
        description = self._normalized_text(
            description, "skill_description_invalid", "Skill description"
        )
        if when_to_use_raw is None:
            when_to_use = self._when_to_use_from_body(instructions="\n".join(lines[end + 1 :]))
            if not when_to_use:
                when_to_use = description
        else:
            when_to_use = self._normalized_text(
                when_to_use_raw, "skill_when_to_use_invalid", "Skill when_to_use"
            )
        auto_raw = metadata.get("auto_activate_for", [])
        if not isinstance(auto_raw, list) or any(
            not isinstance(item, str) or item not in ROLE_CATEGORIES for item in auto_raw
        ):
            raise SkillCatalogError(
                "skill_auto_activate_for_invalid",
                "Skill auto_activate_for must contain only challenge or execution",
            )
        if len(set(auto_raw)) != len(auto_raw):
            raise SkillCatalogError(
                "skill_auto_activate_for_invalid",
                "Skill auto_activate_for must not contain duplicates",
            )
        instructions = "\n".join(lines[end + 1 :]).strip()
        if not instructions:
            raise SkillCatalogError(
                "skill_instructions_empty", "SKILL.md must contain instructions"
            )
        if len(instructions) > MAX_SKILL_BODY_CHARS:
            raise SkillCatalogError(
                "skill_core_too_large",
                f"Skill instructions must not exceed {MAX_SKILL_BODY_CHARS} characters",
            )
        return (
            name,
            description,
            when_to_use,
            frozenset(auto_raw),
            instructions,
        )

    @staticmethod
    def _normalized_text(value: Any, code: str, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SkillCatalogError(code, f"{label} must be a non-empty string")
        normalized = " ".join(value.split())
        if len(normalized) > MAX_DESCRIPTION_CHARS:
            raise SkillCatalogError(
                code, f"{label} must not exceed {MAX_DESCRIPTION_CHARS} characters"
            )
        return normalized

    def _build_listing(self, skills: Sequence[SkillRecord]) -> str:
        if not skills:
            return ""
        for description_limit in range(
            MAX_LISTING_DESCRIPTION_CHARS,
            MIN_LISTING_DESCRIPTION_CHARS - 1,
            -10,
        ):
            lines = [self._listing_line(skill, description_limit) for skill in skills]
            listing = "\n".join(lines)
            if len(listing) <= MAX_LISTING_CHARS:
                return listing
        names: list[str] = []
        for skill in skills:
            candidate = "\n".join([*names, f"- {skill.skill_id}"])
            if len(candidate) > MAX_LISTING_CHARS:
                break
            names.append(f"- {skill.skill_id}")
        return "\n".join(names)

    @staticmethod
    def _listing_line(skill: SkillRecord, description_limit: int) -> str:
        description = f"{skill.description} When to use: {skill.when_to_use}"
        if len(description) > description_limit:
            description = description[: max(1, description_limit - 1)].rstrip() + "…"
        return f"- {skill.skill_id}: {description}"

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
                SkillResource(
                    path=relative,
                    kind=kind,
                    size_bytes=path.stat().st_size,
                    content_sha256=sha256(path.read_bytes()).hexdigest(),
                )
            )
            if len(values) > MAX_RESOURCE_COUNT:
                raise SkillCatalogError(
                    "too_many_skill_resources",
                    f"A skill may contain at most {MAX_RESOURCE_COUNT} files",
                )
        return tuple(values)

    @staticmethod
    def _when_to_use_from_body(*, instructions: str) -> str | None:
        match = re.search(
            r"(?mi)^##\s+when\s+to\s+use(?:\s+this\s+skill)?\s*$",
            instructions,
        )
        if match is None:
            return None
        tail = instructions[match.end() :]
        boundary = re.search(r"(?m)^#{1,2}\s+", tail)
        section = tail[: boundary.start()] if boundary is not None else tail
        section = re.sub(r"(?m)^\s*[-*+]\s*", "", section)
        normalized = " ".join(section.split())
        return normalized or None

    @staticmethod
    def _activation_view(
        description: str, when_to_use: str, instructions: str
    ) -> str:
        if len(instructions) <= MAX_INLINE_INSTRUCTIONS_CHARS:
            return instructions
        headings: list[str] = []
        for line_number, line in enumerate(instructions.splitlines(), start=1):
            match = re.match(r"^(#{1,3})\s+(.+?)\s*$", line)
            if match is not None:
                headings.append(
                    f"- line {line_number}: {match.group(1)} {match.group(2)}"
                )
        preview = _truncate(instructions, 2_500)
        view = (
            f"Description: {description}\n"
            f"When to use: {when_to_use}\n\n"
            "Instructions preview:\n"
            f"{preview}\n\n"
            "Section index (read resource=instructions from the listed line offset for details):\n"
            + "\n".join(headings)
        )
        return _truncate(view, MAX_ACTIVATION_VIEW_CHARS)

    @classmethod
    def _rank(
        cls,
        skills: Sequence[SkillRecord],
        query: str,
        *,
        include_unmatched: bool,
    ) -> list[tuple[int, SkillRecord]]:
        normalized_query = " ".join(query.casefold().split())
        query_terms = cls._search_terms(normalized_query)
        query_bigrams = cls._cjk_bigrams(normalized_query)
        ranked: list[tuple[int, SkillRecord]] = []
        for skill in skills:
            name = skill.name.casefold()
            skill_id = skill.skill_id.casefold()
            haystack = " ".join(
                (
                    skill_id,
                    name,
                    cls._positive_routing_text(skill.description),
                    cls._positive_routing_text(skill.when_to_use),
                )
            ).casefold()
            score = 0
            if normalized_query:
                if normalized_query in {name, skill_id}:
                    score += 100_000
                if name.startswith(normalized_query) or skill_id.startswith(normalized_query):
                    score += 50_000
                if normalized_query in haystack:
                    score += 20_000
                score += 200 * len(query_terms & cls._search_terms(haystack))
                score += 20 * len(query_bigrams & cls._cjk_bigrams(haystack))
            if score or include_unmatched:
                ranked.append((score, skill))
        ranked.sort(key=lambda item: (-item[0], item[1].skill_id))
        return ranked

    @staticmethod
    def _positive_routing_text(value: str) -> str:
        """Keep exclusions model-visible without rewarding them during lexical rank."""

        return re.split(
            r"(?i)(?:\bnot\s+for\b|\bdo\s+not\s+use\b|\bis\s+not\s+a\s+match\b)",
            value,
            maxsplit=1,
        )[0]

    @classmethod
    def _violates_routing_boundary(cls, skill: SkillRecord, query: str) -> bool:
        """Honor explicit ``Not for`` metadata in the local fail-soft router."""

        negative_parts: list[str] = []
        for value in (skill.description, skill.when_to_use):
            parts = re.split(r"(?i)\bnot\s+for\b", value, maxsplit=1)
            if len(parts) == 2:
                negative_parts.append(parts[1])
        if not negative_parts:
            return False
        query_terms = cls._search_terms(query.casefold())
        negative_terms = cls._search_terms(" ".join(negative_parts).casefold())
        negative_overlap = len(query_terms & negative_terms)
        if not negative_overlap:
            return False
        positive_terms = cls._search_terms(
            " ".join(
                (
                    skill.skill_id,
                    skill.name,
                    cls._positive_routing_text(skill.description),
                    cls._positive_routing_text(skill.when_to_use),
                )
            ).casefold()
        )
        return negative_overlap >= len(query_terms & positive_terms)

    @staticmethod
    def _search_terms(value: str) -> set[str]:
        return {
            term
            for term in re.findall(r"[^\W_]+", value, flags=re.UNICODE)
            if len(term) > 1 and term not in ROUTING_STOP_WORDS
        }

    @staticmethod
    def _cjk_bigrams(value: str) -> set[str]:
        chars = re.findall(r"[\u3400-\u9fff]", value)
        return {"".join(chars[index : index + 2]) for index in range(len(chars) - 1)}

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
