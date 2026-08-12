"""Validated state-service and FastAPI payloads."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scan.contracts import (
    CostClass,
    DomainName,
    ScannerProfileName,
    TaskPhase,
    dependency_batches,
    validate_domain_profile,
    validate_profile_tools,
    validate_task_budgets,
)

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
ExecutionKind = Literal[
    "general",
    "recon",
    "web",
    "exploit",
    "credential",
    "privilege",
    "verification",
    "exploration",
    "domain_recognition",
]
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
    task_phase: TaskPhase
    entry_point: str = Field(min_length=1, max_length=2_000)
    capability_class: str = Field(min_length=1, max_length=128)
    verification_question: str = Field(min_length=1, max_length=2_000)
    objective: str = Field(min_length=1, max_length=4_000)
    target_scope: list[str] = Field(min_length=1, max_length=20)
    tool_names: list[str] = Field(min_length=1, max_length=20)
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(min_length=1, max_length=20)
    failure_criteria: list[str] = Field(min_length=1, max_length=20)
    evidence_requirements: list[str] = Field(min_length=1, max_length=20)
    stop_conditions: list[str] = Field(min_length=1, max_length=20)
    depends_on: list[str] = Field(default_factory=list, max_length=20)
    scanner_profile: ScannerProfileName
    cost_class: CostClass = "low"
    context_refs: list[str] = Field(default_factory=list, max_length=50)
    max_http_requests: int = Field(ge=0, le=1_000)
    max_shell_tasks: int = Field(ge=0, le=100)
    max_network_tasks: int = Field(ge=0, le=20)
    timeout_seconds: int = Field(default=1_800, ge=1, le=3_600)

    @field_validator(
        "entry_point",
        "capability_class",
        "verification_question",
        "objective",
    )
    @classmethod
    def non_blank_atomic_fields(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("atomic task fields must not be blank")
        return value

    @field_validator(
        "target_scope",
        "tool_names",
        "success_criteria",
        "failure_criteria",
        "evidence_requirements",
        "stop_conditions",
        "depends_on",
        "context_refs",
    )
    @classmethod
    def non_blank_task_items(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("task contract items must not be blank")
        if len(set(values)) != len(values):
            raise ValueError("task contract items must be unique")
        return values

    @model_validator(mode="after")
    def validate_atomic_contract(self) -> "ExecutionTaskInput":
        if self.task_key in self.depends_on:
            raise ValueError("a task must not depend on itself")
        validate_profile_tools(self.scanner_profile, self.tool_names)
        validate_task_budgets(
            self.tool_names,
            max_http_requests=self.max_http_requests,
            max_shell_tasks=self.max_shell_tasks,
            max_network_tasks=self.max_network_tasks,
        )
        if self.kind == "domain_recognition":
            if self.scanner_profile != "domain_recognition":
                raise ValueError(
                    "domain recognition tasks require the domain_recognition profile"
                )
            if self.task_phase != "domain_recognition":
                raise ValueError(
                    "domain recognition tasks require the domain_recognition phase"
                )
            if (
                self.max_http_requests > 1
                or self.max_shell_tasks != 0
                or self.max_network_tasks != 0
            ):
                raise ValueError("domain recognition task budgets must remain bounded")
        elif self.scanner_profile == "domain_recognition":
            raise ValueError(
                "the domain_recognition profile is reserved for domain probes"
            )
        elif self.task_phase == "domain_recognition":
            raise ValueError(
                "the domain_recognition phase is reserved for domain probes"
            )
        return self


class HypothesisInput(StrictModel):
    key: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=4_000)
    confidence: float = Field(default=0.5, ge=0, le=1)
    based_on_observations: list[str] = Field(default_factory=list, max_length=50)


class AnalysisPlanInput(StrictModel):
    expected_version: int = Field(ge=1)
    domain: DomainName
    domain_confidence: float = Field(ge=0, le=1)
    domain_evidence_refs: list[str] = Field(min_length=1, max_length=20)
    scanner_profile: ScannerProfileName
    analysis_summary: str = Field(min_length=1, max_length=8_000)
    hypotheses: list[HypothesisInput] = Field(default_factory=list, max_length=50)
    information_gaps: list[str] = Field(default_factory=list, max_length=50)
    avoid_repeating: list[str] = Field(default_factory=list, max_length=50)
    tasks: list[ExecutionTaskInput] = Field(default_factory=list, max_length=50)

    @field_validator("domain_evidence_refs")
    @classmethod
    def non_blank_domain_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("domain evidence references must not be blank")
        if len(set(values)) != len(values):
            raise ValueError("domain evidence references must be unique")
        return values

    @model_validator(mode="after")
    def validate_domain_and_task_graph(self) -> "AnalysisPlanInput":
        validate_domain_profile(self.domain, self.scanner_profile)
        task_keys = [task.task_key for task in self.tasks]
        if len(set(task_keys)) != len(task_keys):
            raise ValueError("a plan contains duplicate task keys")
        hypothesis_keys = [task.hypothesis_key for task in self.tasks]
        if len(set(hypothesis_keys)) != len(hypothesis_keys):
            raise ValueError("a plan may start only one task per hypothesis")
        for task in self.tasks:
            if task.kind == "domain_recognition":
                raise ValueError(
                    "domain recognition tasks must be created before an analysis plan"
                )
            if task.scanner_profile != self.scanner_profile:
                raise ValueError(
                    "every task scanner profile must match the identified domain"
                )
        known = set(task_keys)
        dependency_batches(
            [
                {
                    "task_key": task.task_key,
                    "depends_on": [
                        value for value in task.depends_on if value in known
                    ],
                }
                for task in self.tasks
            ]
        )
        return self


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
    rejected_finding_ids: list[str] = Field(default_factory=list, max_length=100)
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


class AgentReportInput(StrictModel):
    status: Literal["working", "completed", "blocked", "failed", "cancelled"]
    summary: str = Field(min_length=1, max_length=4_000)
    failure_code: str | None = Field(default=None, min_length=1, max_length=64)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0, le=1)


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
