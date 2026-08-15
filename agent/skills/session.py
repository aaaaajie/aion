"""Per-Agent activation state and bounded Skill context rendering."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from time import monotonic
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
        selection_text: str = "",
        presented_candidates: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        self.catalog = catalog
        self.role = role
        self.service = service
        self.run_id = run_id
        self.agent_id = agent_id
        self.selection_text = " ".join(selection_text.split())
        self._presented_candidates = tuple(
            dict(item) for item in presented_candidates[:5]
        )
        self._active = {
            str(item.get("skill_id")): dict(item)
            for item in active_skills
            if item.get("skill_id")
        }
        self.catalog.validate_active(self.role, self.active_skills)
        self._available_listing = ""
        self._candidate_count = 0
        self._selection_latency_ms = 0
        self._refresh_listing()

    @property
    def active_skills(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._active.values())

    async def ensure_auto_activated(self) -> None:
        for skill in self.catalog.auto_skills(self.role):
            await self._activate(skill, activation_mode="auto")

    async def invoke(self, skill_id: str) -> dict[str, Any]:
        skill = self.catalog.get(self.role, skill_id)
        return await self._activate(skill, activation_mode="model")

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
        listing = self._available_listing
        if listing:
            if self.role == "execution":
                sections.append(
                    "<skill_candidates>\n"
                    "These are discovery suggestions, not active instructions. Inspect "
                    "their boundaries. If one is genuinely relevant, call skill_invoke "
                    "as the only tool call in that response. If none applies, start the "
                    "technical tools immediately.\n"
                    f"{listing}\n"
                    "</skill_candidates>"
                )
            else:
                sections.append(
                    "<available_skills>\n"
                    "Invoke a matching Skill with skill_invoke as the only tool call in that "
                    "model response. Do not invoke an already active Skill.\n"
                    f"{listing}\n"
                    "</available_skills>"
                )
        return "\n\n".join(sections)

    @property
    def listing_metrics(self) -> dict[str, int]:
        return {
            "latency_ms": self._selection_latency_ms,
            "listing_chars": len(self._available_listing),
            "candidate_count": self._candidate_count,
        }

    def _refresh_listing(self) -> None:
        started = monotonic()
        if self.role == "execution":
            lines: list[str] = []
            for candidate in self._presented_candidates:
                skill_id = str(candidate.get("skill_id") or "")
                if not skill_id or skill_id in self._active:
                    continue
                skill = self.catalog.get("execution", skill_id)
                reason = " ".join(
                    str(candidate.get("relevance_reason") or "").split()
                )[:160]
                lines.append(
                    json.dumps(
                        {
                            "skill_id": skill.skill_id,
                            "description": skill.description[:240],
                            "when_to_use": skill.when_to_use[:240],
                            "relevance_reason": reason,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                )
            self._available_listing = "\n".join(lines)
            self._candidate_count = len(lines)
        else:
            self._available_listing = self.catalog.listing(
                self.role,
                selection_text=self.selection_text,
                excluded_ids=tuple(self._active),
            )
            self._candidate_count = len(self._available_listing.splitlines())
        self._selection_latency_ms = int((monotonic() - started) * 1_000)

    async def _activate(
        self, skill: SkillRecord, *, activation_mode: str
    ) -> dict[str, Any]:
        existing = self._active.get(skill.skill_id)
        if existing is not None:
            self._validate_hash(skill, existing)
            payload = skill.invocation_payload(activation_status="already_active")
            payload["active_skill"] = dict(existing)
            return payload
        candidate = [*self.catalog.validate_active(self.role, self.active_skills), skill]
        if sum(len(item.activation_view) for item in candidate) > MAX_ACTIVE_CONTEXT_CHARS:
            raise SkillCatalogError(
                "skill_context_budget_exceeded",
                "Activating this Skill would exceed the Agent Skill context budget",
                detail={
                    "skill_id": skill.skill_id,
                    "max_chars": MAX_ACTIVE_CONTEXT_CHARS,
                    "active_skill_ids": list(self._active),
                },
            )
        result = await self.service.activate_agent_skill(
            self.run_id,
            self.agent_id,
            skill_id=skill.skill_id,
            content_sha256=skill.content_sha256,
            activation_mode=activation_mode,
        )
        active = dict(result["active_skill"])
        self._validate_hash(skill, active)
        self._active[skill.skill_id] = active
        self._refresh_listing()
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
