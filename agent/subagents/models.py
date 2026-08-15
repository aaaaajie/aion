"""Validated payloads exchanged between role-scoped Agents."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SkipValidation, field_validator

from agent.state.schemas import (
    ChallengeDirection,
    ExecutionTaskInput,
    HypothesisOutcome,
    ReportFindingInput,
)

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


class ReportQueryArguments(_Arguments):
    max_reports: int = Field(
        default=20,
        ge=1,
        le=50,
        description="Maximum new reports to consume in this snapshot (1-50).",
    )


class LaunchChallengesArguments(_Arguments):
    unique_codes: list[str] = Field(min_length=1, max_length=16)

    @field_validator("unique_codes")
    @classmethod
    def unique_non_blank_codes(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("challenge codes must not be blank")
        if len(set(values)) != len(values):
            raise ValueError("challenge codes must be unique")
        return values


class ControllerWaitArguments(_Arguments):
    reason: str | None = Field(default=None, max_length=1_000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class SimpleHintArguments(UniqueCodeArguments):
    reason: str = Field(min_length=1, max_length=1_000)


class ChallengeDispatchArguments(_Arguments):
    summary: str = Field(
        min_length=1,
        max_length=8_000,
        description="Decision summary at the top level; do not wrap arguments in another object.",
    )
    outcome: Literal["continue", "blocked", "completed", "failed"] = "continue"
    direction: ChallengeDirection | None = None
    tasks: SkipValidation[list[ExecutionTaskInput]] = Field(
        default_factory=list,
        description=(
            "Independent tasks. Each task requires only objective; optional malformed "
            "metadata is dropped or defaulted with warnings."
        ),
    )
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    next_steps: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_evidence_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence references must not be blank")
        return values


class SubmitFlagArguments(_Arguments):
    flag: str = Field(min_length=1, max_length=4_096)


class EvidenceReadArguments(_Arguments):
    evidence_ref: str = Field(
        pattern=r"^evidence:evidence_[0-9a-f]{32}$",
        description="Complete evidence:evidence_<32 hex> reference.",
    )
    offset: int = Field(default=0, ge=0)
    limit_chars: int = Field(default=8_000, ge=1, le=8_000)


ExecutionReportStatus = Literal["completed", "blocked", "failed", "cancelled"]


class ExecutionReport(_Arguments):
    status: ExecutionReportStatus
    summary: str = Field(min_length=1, max_length=4_000)
    hypothesis_outcome: SkipValidation[HypothesisOutcome] = Field(
        default="inconclusive",
        description="Use exactly supported, rejected, or inconclusive.",
    )
    findings: SkipValidation[list[ReportFindingInput]] = Field(
        default_factory=list,
        description=(
            "Optional best-effort findings. Each item uses summary, optional object detail, "
            "category, confidence, verification_status, finding_ref, and evidence_refs. "
            "Malformed items are warnings and never invalidate the terminal report."
        ),
    )
    evidence_refs: SkipValidation[list[str]] = Field(
        default_factory=list,
        description="Optional Evidence refs; malformed refs are dropped with warnings.",
    )
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(
        default=None,
        min_length=1,
        max_length=4_096,
        description=(
            "An exact flag token ready for challenge_submit_flag. Omit it for task names, "
            "credentials, URLs, vulnerability descriptions, or unverified guesses."
        ),
    )
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class AgentReport(_Arguments):
    agent_id: str = Field(min_length=1)
    role: AgentRole
    unique_code: str | None = None
    status: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    evidence_refs: list[Any] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    sequence: int = Field(default=0, ge=0)
