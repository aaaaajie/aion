"""Agent-facing tools for progressive skill discovery and reading."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .catalog import MAX_READ_LINES, SkillCatalog, SkillCatalogError, SkillRole


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SkillListArguments(_Arguments):
    query: str | None = Field(default=None, max_length=1_000)
    max_results: int = Field(default=50, ge=1, le=50)


class SkillReadArguments(_Arguments):
    skill_id: str = Field(min_length=1, max_length=160)
    resource: str = Field(default="SKILL.md", min_length=1, max_length=1_000)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=400, ge=1, le=MAX_READ_LINES)


def _definition(name: str, description: str, model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema()
    schema.setdefault("additionalProperties", False)
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": schema},
    }


class SkillTools:
    """Expose one role-filtered view of the immutable skill catalog."""

    _ROUTES: ClassVar[dict[str, tuple[type[_Arguments], str]]] = {
        "skill_list": (SkillListArguments, "list_skills"),
        "skill_read": (SkillReadArguments, "read_skill"),
    }
    _DEFINITIONS: ClassVar[list[dict[str, Any]]] = [
        _definition(
            "skill_list",
            "Search the skills available to this Agent role. Returns only compact metadata and resource names. Use a concise task, vulnerability, or technology query; then call skill_read only for relevant skills.",
            SkillListArguments,
        ),
        _definition(
            "skill_read",
            "Read SKILL.md or one named text resource from an available skill. Read the instructions before using bundled scripts. Use offset and limit to continue large resources; scripts execute through system_shell, not this tool.",
            SkillReadArguments,
        ),
    ]

    def __init__(self, catalog: SkillCatalog, *, role: SkillRole) -> None:
        if role not in {"challenge", "execution"}:
            raise ValueError("only Challenge and Execution Agents can use skills")
        self.catalog = catalog
        self.role = role

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return deepcopy(cls._DEFINITIONS)

    async def dispatch(
        self, name: str, arguments: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        route = self._ROUTES.get(name)
        if route is None:
            return self._error("unknown_tool", "Unknown skill tool")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._error("invalid_arguments", "Tool arguments must be an object")
        model, operation_name = route
        try:
            validated = model.model_validate(arguments)
            operation = getattr(self, operation_name)
            return await operation(**validated.model_dump())
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "invalid_arguments",
                    "message": "Invalid skill-tool arguments",
                    "status_code": None,
                    "detail": [
                        {key: item[key] for key in ("loc", "msg", "type") if key in item}
                        for item in exc.errors()
                    ],
                },
            }
        except SkillCatalogError as exc:
            return {
                "ok": False,
                "error": {
                    "type": exc.error_type,
                    "code": exc.code,
                    "message": exc.message,
                    "status_code": None,
                    "detail": exc.detail,
                },
            }

    async def list_skills(
        self, query: str | None = None, max_results: int = 50
    ) -> dict[str, Any]:
        skills = self.catalog.list(self.role, query=query, max_results=max_results)
        return {
            "ok": True,
            "data": {
                "skills": skills,
                "count": len(skills),
                "query": query,
                "role": self.role,
            },
        }

    async def read_skill(
        self,
        skill_id: str,
        resource: str = "SKILL.md",
        offset: int = 0,
        limit: int = 400,
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "data": self.catalog.read(
                self.role,
                skill_id,
                resource=resource,
                offset=offset,
                limit=limit,
            ),
        }

    async def close(self) -> None:
        return None

    @staticmethod
    def _error(code: str, message: str) -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": "validation",
                "code": code,
                "message": message,
                "status_code": None,
                "detail": {},
            },
        }
