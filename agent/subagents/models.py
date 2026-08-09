"""Validated payloads exchanged between role-scoped Agents."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AgentRole = Literal["chief", "challenge", "execution"]
AgentStatus = Literal[
    "pending",
    "running",
    "waiting",
    "completed",
    "failed",
    "stopped",
    "interrupted",
    "indeterminate",
]


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EmptyArguments(_Arguments):
    pass


class UniqueCodeArguments(_Arguments):
    unique_code: str = Field(min_length=1, max_length=256)

    @field_validator("unique_code")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("unique_code must not be blank")
        return value


class HintArguments(UniqueCodeArguments):
    reason: str = Field(min_length=1, max_length=1_000)


class CreateExecutionArguments(_Arguments):
    mission: str = Field(min_length=1, max_length=4_000)
    cycle_id: str | None = Field(default=None, min_length=1, max_length=128)
    kind: Literal["general", "recon", "web", "exploit", "credential", "privilege", "verification", "exploration"] = "general"
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(default_factory=list, max_length=20)
    context_refs: list[str] = Field(default_factory=list, max_length=50)
    timeout_seconds: int = Field(default=1_800, ge=1, le=3_600)

    @field_validator("mission")
    @classmethod
    def mission_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("mission must not be blank")
        return value


class PollArguments(_Arguments):
    wait_seconds: float = Field(default=0.0, ge=0.0, le=30.0)
    max_reports: int = Field(default=20, ge=1, le=50)


class ExecutionReportPollArguments(_Arguments):
    """Long-poll execution reports unless the caller explicitly opts out."""

    wait_seconds: float = Field(default=30.0, ge=0.0, le=30.0)
    max_reports: int = Field(default=20, ge=1, le=50)


class CycleArguments(_Arguments):
    expected_challenge_version: int = Field(ge=1)


class CycleVersionArguments(_Arguments):
    cycle_id: str = Field(min_length=1, max_length=128)
    expected_version: int = Field(ge=1)
    payload: dict[str, Any] = Field(default_factory=dict)


class ProgressArguments(_Arguments):
    status: Literal["working", "blocked", "completed", "failed", "cancelled"]
    phase: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    expected_result_seconds: int | None = Field(default=None, ge=1, le=300)


ChallengeReportStatus = Literal[
    "analyzing",
    "blocked",
    "ready_for_hint",
    "flag_candidate",
    "completed",
    "failed",
]


class ChallengeStatusArguments(_Arguments):
    status: ChallengeReportStatus
    summary: str = Field(min_length=1, max_length=4_000)
    hint_recommended: bool = False
    blocker: str | None = Field(default=None, max_length=1_000)
    next_steps: list[str] = Field(default_factory=list, max_length=20)


class StagnationExtensionArguments(_Arguments):
    unique_code: str = Field(min_length=1, max_length=256)
    reason: Literal["high_probability_path", "waiting_remote", "imminent_result"]
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    note: str | None = Field(default=None, max_length=1_000)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence_refs must not be blank")
        return values


class SubmitFlagArguments(_Arguments):
    flag: str = Field(min_length=1, max_length=4_096)


ExecutionReportStatus = Literal["working", "completed", "blocked", "failed", "cancelled"]


class ExecutionReport(_Arguments):
    status: ExecutionReportStatus
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[str | dict[str, Any]] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class AgentReport(_Arguments):
    agent_id: str = Field(min_length=1)
    role: AgentRole
    unique_code: str | None = None
    status: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[str | dict[str, Any]] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    sequence: int = Field(default=0, ge=0)


class AgentStatusReport(_Arguments):
    agent_id: str = Field(min_length=1)
    unique_code: str = Field(min_length=1)
    status: ChallengeReportStatus
    summary: str = Field(min_length=1, max_length=4_000)
    hint_recommended: bool = False
    blocker: str | None = Field(default=None, max_length=1_000)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    sequence: int = Field(default=0, ge=0)
