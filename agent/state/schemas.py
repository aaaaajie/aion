"""Validated state-service and FastAPI payloads."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
ChallengeDirection = Literal["unknown", "web", "binary", "ai", "blockchain"]
CHALLENGE_DIRECTION_VALUES = frozenset(
    {"unknown", "web", "binary", "ai", "blockchain"}
)
ExecutionKind = Literal[
    "general",
    "recon",
    "web",
    "exploit",
    "credential",
    "privilege",
    "verification",
    "exploration",
]
TaskStage = Literal["discovery", "validation", "exploitation"]
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


class CredentialInput(StrictModel):
    kind: str = Field(min_length=1, max_length=32)
    principal: str | None = Field(default=None, max_length=1_000)
    secret_value: str = Field(min_length=1, max_length=8_192)
    scope: str | None = Field(default=None, max_length=2_000)
    verified: bool = False


class ExecutionTaskInput(StrictModel):
    task_key: str = Field(min_length=1, max_length=128)
    hypothesis_key: str = Field(min_length=1, max_length=128)
    branch_key: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Stable capability branch key; defaults to hypothesis:kind when omitted.",
    )
    kind: ExecutionKind = "general"
    task_stage: TaskStage
    objective: str = Field(min_length=1, max_length=4_000)
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(default_factory=list, max_length=20)
    context_refs: list[str] = Field(default_factory=list, max_length=50)
    timeout_seconds: int = Field(default=1_800, ge=1, le=3_600)


class HypothesisInput(StrictModel):
    key: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=4_000)
    confidence: float = Field(default=0.5, ge=0, le=1)
    based_on_observations: list[str] = Field(default_factory=list, max_length=50)


class AnalysisPlanInput(StrictModel):
    expected_version: int = Field(ge=1)
    analysis_summary: str = Field(min_length=1, max_length=8_000)
    direction: ChallengeDirection = "unknown"
    hypotheses: list[HypothesisInput] = Field(default_factory=list, max_length=50)
    information_gaps: list[str] = Field(default_factory=list, max_length=50)
    avoid_repeating: list[str] = Field(default_factory=list, max_length=50)
    tasks: list[ExecutionTaskInput] = Field(default_factory=list, max_length=50)


class AttackPathInput(StrictModel):
    summary: str = Field(min_length=1, max_length=2_000)
    verification_steps: list[str] = Field(min_length=1, max_length=20)
    evidence_paths: list[str] = Field(min_length=1, max_length=50)
    confidence: float = Field(default=0.5, ge=0, le=1)

    @field_validator("verification_steps", "evidence_paths")
    @classmethod
    def non_blank_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("attack path references must not be blank")
        return values


class VerificationUpdateInput(StrictModel):
    expected_version: int = Field(ge=1)
    summary: str = Field(min_length=1, max_length=8_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=100)
    credentials: list[CredentialInput] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=50)
    new_attack_paths: list[AttackPathInput] = Field(default_factory=list, max_length=20)
    outcome: Literal["progress", "no_progress", "completed", "blocked", "failed"]


class AgentProgressInput(StrictModel):
    status: Literal["working", "blocked", "completed", "failed", "cancelled"]
    phase: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    expected_result_seconds: int | None = Field(default=None, ge=1, le=300)


class FindingResolutionInput(StrictModel):
    finding_ref: str = Field(min_length=1, max_length=256)
    outcome: Literal["verified", "rejected"]
    evidence_paths: list[str] = Field(min_length=1, max_length=50)

    @field_validator("finding_ref", "evidence_paths")
    @classmethod
    def non_blank_references(cls, value: Any) -> Any:
        values = [value] if isinstance(value, str) else value
        if any(not item.strip() for item in values):
            raise ValueError("finding resolution references must not be blank")
        return value


class AgentReportInput(StrictModel):
    status: Literal["working", "completed", "blocked", "failed", "cancelled"]
    summary: str = Field(min_length=1, max_length=4_000)
    failure_code: str | None = Field(default=None, min_length=1, max_length=64)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0, le=1)
    hypothesis_outcome: HypothesisOutcome | None = None
    finding_resolutions: list[FindingResolutionInput] = Field(
        default_factory=list, max_length=50
    )

    @model_validator(mode="after")
    def validate_terminal_outcome(self) -> "AgentReportInput":
        if self.status != "working" and self.hypothesis_outcome is None:
            raise ValueError("hypothesis_outcome is required for terminal reports")
        if self.hypothesis_outcome in {"supported", "rejected"}:
            has_evidence = bool(self.evidence_paths) or any(
                finding.evidence_paths for finding in self.findings
            ) or any(item.evidence_paths for item in self.finding_resolutions)
            if not has_evidence:
                raise ValueError(
                    "supported or rejected outcomes require structured evidence"
                )
        return self


class CreateCycleInput(StrictModel):
    expected_challenge_version: int = Field(ge=1)


class ChallengeStateUpdate(StrictModel):
    work_status: ChallengeWorkStatus | None = None
    platform_status: str | None = Field(default=None, max_length=32)
    container_status: str | None = Field(default=None, max_length=32)
    container_addr: list[str] | None = None


class StagnationExtensionInput(StrictModel):
    reason: Literal["high_probability_path", "waiting_remote", "imminent_result"]
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    note: str | None = Field(default=None, max_length=1_000)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence_refs must not be blank")
        return values


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
