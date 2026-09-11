"""Validated state-service and FastAPI payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SkipValidation, field_validator

FindingCategory = Literal[
    "service",
    "vulnerability",
    "credential",
    "privilege",
    "attack_path",
    "flag",
    "other",
]
VerificationStatus = Literal["candidate", "verified", "rejected"]
ChallengeDirection = Literal[
    "unknown",
    "web",
    "pentest",
    "binary",
    "exploit",
    "cloud",
    "evasion",
]
CHALLENGE_DIRECTION_VALUES = frozenset(
    {"unknown", "web", "pentest", "binary", "exploit", "cloud", "evasion"}
)
ChallengeWorkStatus = Literal[
    "unassigned",
    "active",
    "paused",
    "completed",
    "closed",
]
CHALLENGE_WORK_STATUS_VALUES = frozenset(
    {"unassigned", "active", "paused", "completed", "closed"}
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ChallengeSyncResult(StrictModel):
    challenges: list[dict[str, Any]]
    changed_codes: list[str] = Field(default_factory=list)
    capacity_changed: bool = False
    event_sequence: int | None = None


class FindingInput(StrictModel):
    category: FindingCategory
    summary: str = Field(min_length=1, max_length=2_000)
    detail: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0, le=1)
    verification_status: VerificationStatus = "candidate"
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)


class ReportFindingInput(StrictModel):
    """Best-effort finding attached to a terminal Execution report."""

    finding_ref: str | None = Field(default=None, max_length=256)
    category: FindingCategory = "other"
    summary: str = Field(min_length=1, max_length=2_000)
    detail: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.5, ge=0, le=1)
    verification_status: VerificationStatus = "candidate"
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_report_evidence(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence references must not be blank")
        return values


class WorkerTaskInput(StrictModel):
    objective: str = Field(min_length=1, max_length=4_000)
    task_key: str = Field(min_length=1, max_length=128)
    mode: Literal["execute", "review"] = "execute"
    success_criteria: list[str] = Field(default_factory=list, max_length=20)
    context_refs: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Exact evidence_ref/report_ref values supplied by the parent. Required when a review targets a specific artifact; never invent references.",
    )
    timeout_seconds: int | None = Field(default=None, ge=1)

    @field_validator("objective", "task_key")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be blank")
        return value.strip()


class WorkerUpdateInput(StrictModel):
    summary: str = Field(min_length=1, max_length=4_000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    tested: list[str] = Field(default_factory=list, max_length=50)
    untested: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)


class AgentReportInput(WorkerUpdateInput):
    status: Literal["completed", "blocked", "failed", "cancelled", "interrupted"]
    findings: list[ReportFindingInput] = Field(default_factory=list, max_length=50)
    confidence: float | None = Field(default=None, ge=0, le=1)


class ReviewAgentReportInput(WorkerUpdateInput):
    """Terminal report contract for read-only review Workers."""

    status: Literal["completed", "blocked", "failed", "cancelled", "interrupted"]
    confidence: float | None = Field(default=None, ge=0, le=1)


class ChallengeStateUpdate(StrictModel):
    work_status: ChallengeWorkStatus | None = None
    platform_status: str | None = Field(default=None, max_length=32)
    container_status: str | None = Field(default=None, max_length=32)
    container_addr: list[str] | None = None


class CapabilityContext(StrictModel):
    run_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    role: Literal["chief", "solver", "worker"]
    unique_code: str | None = None


class ChallengeImport(StrictModel):
    unique_code: str = Field(min_length=1, max_length=256)
    description: str | None = None
    difficulty: str = "unknown"
    level: int = 0
    total_score: int = 0
    flag_count: int = 0
    correct_flag_count: int = 0
    is_completed: bool = False
    container_status: str = "stopped"
    container_addr: list[str] = Field(default_factory=list)

    @field_validator("unique_code")
    @classmethod
    def code_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("unique_code must not be blank")
        return value
