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
ExecutionKind = Literal[
    "general",
    "recon",
    "web",
    "pentest",
    "exploit",
    "cloud",
    "evasion",
    "credential",
    "privilege",
    "verification",
    "exploration",
]
TaskStage = Literal["discovery", "validation", "exploitation", "post_exploitation"]
HypothesisOutcome = Literal["supported", "rejected", "inconclusive"]
ChallengeWorkStatus = Literal[
    "unassigned",
    "active",
    "warning",
    "extended",
    "paused",
    "completed",
    "closed",
]
CHALLENGE_WORK_STATUS_VALUES = frozenset(
    {"unassigned", "active", "warning", "extended", "paused", "completed", "closed"}
)
ChallengeControlState = Literal[
    "ok",
    "blocked",
    "degraded",
    "waiting_external_change",
]
CHALLENGE_CONTROL_STATE_VALUES = frozenset(
    {"ok", "blocked", "degraded", "waiting_external_change"}
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



class ExecutionTaskInput(StrictModel):
    objective: str = Field(min_length=1, max_length=4_000)
    task_key: str | None = Field(default=None, min_length=1, max_length=128)
    hypothesis_key: str | None = Field(default=None, min_length=1, max_length=128)
    branch_key: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Stable capability branch key; defaults to hypothesis:kind when omitted.",
    )
    kind: ExecutionKind = "general"
    task_stage: TaskStage = "discovery"
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(default_factory=list, max_length=20)
    context_refs: list[str] = Field(default_factory=list, max_length=50)
    timeout_seconds: int = Field(default=1_800, ge=1, le=3_600)


class HypothesisInput(StrictModel):
    key: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=4_000)
    confidence: float = Field(default=0.5, ge=0, le=1)
    based_on_observations: list[str] = Field(default_factory=list, max_length=50)



class ChallengeDispatchInput(StrictModel):
    summary: str = Field(min_length=1, max_length=8_000)
    outcome: Literal["continue", "blocked", "completed", "failed"] = "continue"
    direction: ChallengeDirection | None = None
    tasks: list[ExecutionTaskInput] = Field(default_factory=list, max_length=50)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    next_steps: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_evidence_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence references must not be blank")
        return values



class AgentReportInput(StrictModel):
    status: Literal["completed", "blocked", "failed", "cancelled"]
    summary: str = Field(min_length=1, max_length=4_000)
    hypothesis_outcome: SkipValidation[HypothesisOutcome] = "inconclusive"
    findings: SkipValidation[list[ReportFindingInput]] = Field(
        default_factory=list,
        description=(
            "Optional best-effort findings. Use summary (not title), an object detail, "
            "and complete finding:/evidence: references. Malformed items produce warnings "
            "without losing the terminal report."
        ),
    )
    evidence_refs: SkipValidation[list[str]] = Field(
        default_factory=list,
        description="Optional Evidence refs; malformed refs are dropped with warnings.",
    )
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0, le=1)



class ChallengeStateUpdate(StrictModel):
    work_status: ChallengeWorkStatus | None = None
    platform_status: str | None = Field(default=None, max_length=32)
    container_status: str | None = Field(default=None, max_length=32)
    container_addr: list[str] | None = None



class CapabilityContext(StrictModel):
    run_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    role: Literal["chief", "challenge", "execution"]
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
