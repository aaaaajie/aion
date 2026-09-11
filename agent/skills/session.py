"""Per-Agent activation state and bounded Skill context rendering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TYPE_CHECKING

from .catalog import (
    MAX_ACTIVE_CONTEXT_CHARS,
    SkillCatalog,
    SkillCatalogError,
    SkillRecord,
    SkillRole,
)

if TYPE_CHECKING:
    from agent.state.service import StateService


class SkillSessionContext:
    """Share immutable Skill context between tools and one Agent runner."""

    def __init__(
        self,
        catalog: SkillCatalog,
        *,
        role: SkillRole,
        service: StateService,
        run_id: str,
        agent_id: str,
        active_skills: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        self.catalog = catalog
        self.role = role
        self.service = service
        self.run_id = run_id
        self.agent_id = agent_id
        self._active = {
            str(item.get("skill_id")): dict(item)
            for item in active_skills
            if item.get("skill_id")
        }
        self.catalog.validate_active(self.role, self.active_skills)

    @property
    def active_skills(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._active.values())

    async def invoke(self, skill_id: str) -> dict[str, Any]:
        skill = self.catalog.get(self.role, skill_id)
        return await self._activate(skill, activation_mode="model")

    async def activate_capability(self, source_review_sequence: int) -> dict[str, Any]:
        """Load the generic post-access locator from a validated Solver review."""

        if self.role != "solver":
            raise SkillCatalogError(
                "capability_activation_role_invalid",
                "Only Solver can activate capability-derived Skills",
            )
        if source_review_sequence <= 0:
            raise SkillCatalogError(
                "capability_activation_source_invalid",
                "A capability activation requires a positive review sequence",
            )
        skill = self.catalog.get(self.role, "common/ctf-flag-locator")
        return await self._activate(
            skill,
            activation_mode="capability",
            source_review_sequence=source_review_sequence,
        )

    def search(self, query: str, *, limit: int) -> list[dict[str, Any]]:
        return self.catalog.search(
            self.role,
            query,
            limit=limit,
            excluded_ids=tuple(self._active),
        )

    def read_resource(
        self,
        skill_id: str,
        *,
        resource: str,
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        skill = self.catalog.get(self.role, skill_id)
        active = self._active.get(skill_id)
        if active is None:
            raise SkillCatalogError(
                "skill_not_active",
                "Activate the Skill before reading its resources",
                retry_allowed=True,
                retry_action="rewrite_arguments",
                retry_tool="skill_invoke",
                detail={"skill_id": skill_id},
            )
        self._validate_hash(skill, active)
        return self.catalog.read_resource(
            self.role,
            skill_id,
            resource=resource,
            offset=offset,
            limit=limit,
        )

    def render_system_context(self) -> str:
        records = self.catalog.validate_active(self.role, self.active_skills)
        sections: list[str] = []
        if records:
            active = ["<active_skills>"]
            for skill in records:
                active.extend(
                    [
                        f'<skill id="{skill.skill_id}" sha256="{skill.content_sha256}">',
                        skill.activation_view,
                        "</skill>",
                    ]
                )
            active.append("</active_skills>")
            sections.append("\n".join(active))
        return "\n\n".join(sections)

    async def _activate(
        self,
        skill: SkillRecord,
        *,
        activation_mode: str,
        source_review_sequence: int | None = None,
    ) -> dict[str, Any]:
        existing = self._active.get(skill.skill_id)
        if existing is not None:
            self._validate_hash(skill, existing)
            payload = skill.invocation_payload(activation_status="already_active")
            payload["active_skill"] = dict(existing)
            return payload
        candidate = [
            *self.catalog.validate_active(self.role, self.active_skills),
            skill,
        ]
        if (
            sum(len(item.activation_view) for item in candidate)
            > MAX_ACTIVE_CONTEXT_CHARS
        ):
            raise SkillCatalogError(
                "skill_context_budget_exceeded",
                "Activating this Skill would exceed the Agent Skill context budget",
                detail={
                    "skill_id": skill.skill_id,
                    "max_chars": MAX_ACTIVE_CONTEXT_CHARS,
                    "active_skill_ids": list(self._active),
                },
            )
        activation_args = {
            "skill_id": skill.skill_id,
            "content_sha256": skill.content_sha256,
            "activation_mode": activation_mode,
        }
        if source_review_sequence is not None:
            activation_args["source_review_sequence"] = source_review_sequence
        result = await self.service.activate_agent_skill(
            self.run_id, self.agent_id, **activation_args
        )
        active = dict(result["active_skill"])
        self._validate_hash(skill, active)
        self._active[skill.skill_id] = active
        status = "activated" if result["activated"] else "already_active"
        payload = skill.invocation_payload(activation_status=status)
        payload["active_skill"] = active
        return payload

    @staticmethod
    def _validate_hash(skill: SkillRecord, active: Mapping[str, Any]) -> None:
        if active.get("content_sha256") != skill.content_sha256:
            raise SkillCatalogError(
                "skill_content_changed",
                "An activated Skill changed after the Agent session started",
                detail={"skill_id": skill.skill_id},
            )
