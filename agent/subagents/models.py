"""Validated payloads exchanged between role-scoped Agents."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent.state.schemas import (
    AttackPathInput,
    ChallengeDirection,
    CredentialInput,
    ExecutionKind,
    ExecutionTaskInput,
    FindingInput,
    FindingResolutionInput,
    HypothesisOutcome,
    HypothesisInput,
    TaskStage,
)

AgentRole = Literal["chief", "challenge", "execution"]
HintBasis = Literal[
    "high_probability_path",
    "second_pass_convergence",
    "near_deadline",
]
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
    basis: HintBasis
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("evidence_refs")
    @classmethod
    def non_blank_evidence_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence_refs must not be blank")
        return values


class CreateExecutionArguments(_Arguments):
    mission: str = Field(min_length=1, max_length=4_000)
    hypothesis_key: str = Field(min_length=1, max_length=128)
    task_key: str = Field(min_length=1, max_length=128)
    cycle_id: str | None = Field(default=None, min_length=1, max_length=128)
    kind: Literal["general", "recon", "web", "exploit", "credential", "privilege", "verification", "exploration"] = "general"
    task_stage: TaskStage
    priority: int = Field(default=50, ge=0, le=100)
    target_scope: list[str] = Field(min_length=1, max_length=20)
    tool_names: list[str] = Field(min_length=1, max_length=20)
    success_criteria: list[str] = Field(min_length=1, max_length=20)
    failure_criteria: list[str] = Field(min_length=1, max_length=20)
    evidence_requirements: list[str] = Field(min_length=1, max_length=20)
    stop_conditions: list[str] = Field(min_length=1, max_length=20)
    depends_on: list[str] = Field(default_factory=list, max_length=20)
    scanner_profile: ScannerProfileName
    cost_class: CostClass = "low"
    context_refs: list[str] = Field(default_factory=list, max_length=50)
    branch_key: str | None = Field(default=None, min_length=1, max_length=256)
    timeout_seconds: int = Field(default=1_800, ge=1, le=3_600)

    @field_validator(
        "mission",
        "entry_point",
        "capability_class",
        "verification_question",
    )
    @classmethod
    def atomic_fields_non_blank(cls, value: str) -> str:
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
    def validate_atomic_contract(self) -> "CreateExecutionArguments":
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


class ReportQueryArguments(_Arguments):
    max_reports: int = Field(default=20, ge=1, le=50)


class CycleArguments(_Arguments):
    expected_challenge_version: int = Field(ge=1)


class AnalysisPlanArguments(_Arguments):
    cycle_id: str = Field(min_length=1, max_length=128)
    expected_version: int = Field(ge=1)
    analysis_summary: str = Field(min_length=1, max_length=8_000)
    direction: ChallengeDirection = "unknown"
    hypotheses: list[HypothesisInput] = Field(default_factory=list, max_length=50)
    information_gaps: list[str] = Field(default_factory=list, max_length=50)
    avoid_repeating: list[str] = Field(default_factory=list, max_length=50)
    tasks: list[ExecutionTaskInput] = Field(default_factory=list, max_length=50)


class CommitCycleArguments(_Arguments):
    cycle_id: str = Field(min_length=1, max_length=128)
    expected_version: int = Field(ge=1)
    summary: str = Field(min_length=1, max_length=8_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=100)
    credentials: list[CredentialInput] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=50)
    new_attack_paths: list[AttackPathInput] = Field(default_factory=list, max_length=20)
    outcome: Literal["progress", "no_progress", "completed", "blocked", "failed"]


class ProgressArguments(_Arguments):
    status: Literal["working", "blocked", "completed", "failed", "cancelled"]
    phase: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
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
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_hint_recommendation(self) -> "ChallengeStatusArguments":
        if any(not value.strip() for value in self.evidence_refs):
            raise ValueError("evidence_refs must not be blank")
        if self.status == "ready_for_hint" and self.hint_recommended:
            if not self.blocker or not self.blocker.strip():
                raise ValueError(
                    "blocker is required when hint_recommended is true"
                )
            if not self.evidence_refs:
                raise ValueError(
                    "evidence_refs are required when hint_recommended is true"
                )
        return self


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


ExecutionReportStatus = Literal["completed", "blocked", "failed", "cancelled"]


class ExecutionReport(_Arguments):
    status: ExecutionReportStatus
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
    evidence_paths: list[str] = Field(default_factory=list, max_length=50)
    next_steps: list[str] = Field(default_factory=list, max_length=20)
    candidate_flag: str | None = Field(default=None, min_length=1, max_length=4_096)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    hypothesis_outcome: HypothesisOutcome
    finding_resolutions: list[FindingResolutionInput] = Field(
        default_factory=list, max_length=50
    )

    @model_validator(mode="after")
    def validate_terminal_outcome(self) -> "ExecutionReport":
        if self.hypothesis_outcome in {"supported", "rejected"}:
            has_evidence = bool(self.evidence_paths) or any(
                finding.evidence_paths for finding in self.findings
            ) or any(item.evidence_paths for item in self.finding_resolutions)
            if not has_evidence:
                raise ValueError(
                    "supported or rejected outcomes require structured evidence"
                )
        return self


class AgentReport(_Arguments):
    agent_id: str = Field(min_length=1)
    role: AgentRole
    unique_code: str | None = None
    status: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=4_000)
    findings: list[FindingInput] = Field(default_factory=list, max_length=50)
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
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    sequence: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_hint_recommendation(self) -> "AgentStatusReport":
        if any(not value.strip() for value in self.evidence_refs):
            raise ValueError("evidence_refs must not be blank")
        if self.status == "ready_for_hint" and self.hint_recommended:
            if not self.blocker or not self.blocker.strip():
                raise ValueError(
                    "blocker is required when hint_recommended is true"
                )
            if not self.evidence_refs:
                raise ValueError(
                    "evidence_refs are required when hint_recommended is true"
                )
        return self
