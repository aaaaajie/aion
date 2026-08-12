"""Strict schemas for project-local competition Skill manifests."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SkillTrigger(_StrictModel):
    keywords: list[str] = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)


class SkillRequirements(_StrictModel):
    tools: list[str] = Field(min_length=1)
    permissions: list[str] = Field(min_length=1)


class SkillCredentialsOutput(_StrictModel):
    optional: bool = False


class SkillOutputs(_StrictModel):
    findings: list[str] = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)
    credentials: SkillCredentialsOutput


class SkillManifest(_StrictModel):
    id: str = Field(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")
    name: str = Field(min_length=1)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    category: list[str] = Field(min_length=1)
    stage: list[str] = Field(min_length=1)
    description: str = Field(min_length=1)
    risk_level: Literal["low", "medium", "high", "critical"]
    trigger: SkillTrigger
    requires: SkillRequirements
    workflow: list[str] = Field(min_length=1)
    outputs: SkillOutputs
    tags: list[str] = Field(default_factory=list)

    @field_validator(
        "category",
        "stage",
        "workflow",
        "tags",
    )
    @classmethod
    def validate_string_lists(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("Skill manifest list items must not be blank")
        if len(set(values)) != len(values):
            raise ValueError("Skill manifest list items must be unique")
        return values
