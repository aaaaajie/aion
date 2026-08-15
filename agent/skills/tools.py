"""Tool Specs for activating Skills and reading active Skill resources."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tooling import AccessClaim, ToolSpec

from .catalog import MAX_READ_LINES, MAX_SEARCH_RESULTS
from .session import SkillSessionContext


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SkillInvokeArguments(_Arguments):
    skill_id: str = Field(min_length=1, max_length=160)


class SkillSearchArguments(_Arguments):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=MAX_SEARCH_RESULTS, ge=1, le=MAX_SEARCH_RESULTS)


class SkillResourceReadArguments(_Arguments):
    skill_id: str = Field(min_length=1, max_length=160)
    resource: str = Field(min_length=1, max_length=1_000)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=400, ge=1, le=MAX_READ_LINES)


class SkillTools:
    """Expose one Agent-owned view of the immutable Skill catalog."""

    def __init__(self, context: SkillSessionContext) -> None:
        self.context = context

    def tool_specs(self) -> list[ToolSpec]:
        async def invoke_skill(arguments: BaseModel) -> dict[str, Any]:
            assert isinstance(arguments, SkillInvokeArguments)
            return await self.context.invoke(arguments.skill_id)

        async def search_skills(arguments: BaseModel) -> dict[str, Any]:
            assert isinstance(arguments, SkillSearchArguments)
            results = self.context.search(arguments.query, limit=arguments.limit)
            return {
                "query": arguments.query,
                "count": len(results),
                "skills": results,
            }

        async def read_resource(arguments: BaseModel) -> dict[str, Any]:
            assert isinstance(arguments, SkillResourceReadArguments)
            return self.context.read_resource(
                arguments.skill_id,
                resource=arguments.resource,
                offset=arguments.offset,
                limit=arguments.limit,
            )

        return [
            ToolSpec(
                "skill_search",
                "Search role-visible long-tail Skills by a specific task description. "
                "This does not activate a Skill.",
                SkillSearchArguments,
                search_skills,
                access_claims=lambda _arguments: (
                    AccessClaim("read", f"agent:{self.context.agent_id}:skills"),
                    AccessClaim("read", "skill:catalog"),
                ),
            ),
            ToolSpec(
                "skill_invoke",
                "Activate one available Skill and load its bounded activation instructions. "
                "This must be the only tool call in the model response.",
                SkillInvokeArguments,
                invoke_skill,
                access_claims=lambda _arguments: (
                    AccessClaim("write", f"agent:{self.context.agent_id}:skills"),
                ),
                requires_solo=True,
            ),
            ToolSpec(
                "skill_resource_read",
                "Read one UTF-8 supporting or virtual instructions/manifest resource "
                "from an already active Skill.",
                SkillResourceReadArguments,
                read_resource,
                access_claims=lambda arguments: (
                    AccessClaim("read", f"agent:{self.context.agent_id}:skills"),
                    AccessClaim(
                        "read", f"skill:{arguments.skill_id}:{arguments.resource}"
                    ),
                ),
            ),
        ]

    async def close(self) -> None:
        return None
