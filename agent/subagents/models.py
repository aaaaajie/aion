"""Current model-facing Agent control contracts."""

from typing import Literal
from pydantic import Field, model_validator
from agent.state.schemas import (
    StrictModel,
    WorkerTaskInput,
    WorkerUpdateInput,
    AgentReportInput,
)

AgentRole = Literal["chief", "solver", "worker"]


class EmptyArguments(StrictModel):
    pass


class ReportQueryArguments(StrictModel):
    max_reports: int = Field(default=20, ge=1, le=100)


class LaunchChallengesArguments(StrictModel):
    unique_codes: list[str] = Field(min_length=1, max_length=50)


class ControllerWaitArguments(StrictModel):
    reason: str | None = Field(default=None, max_length=1000)


class SimpleHintArguments(StrictModel):
    unique_code: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2000)


class PauseChallengesArguments(LaunchChallengesArguments):
    reason: str = Field(min_length=1, max_length=2000)
    release_container: bool = True


class CloseChallengesArguments(LaunchChallengesArguments):
    reason: str = Field(min_length=1, max_length=2000)


class DelegateArguments(StrictModel):
    tasks: list[WorkerTaskInput] = Field(
        min_length=1,
        max_length=50,
        description="Independent tasks. For artifact-specific review, include exact evidence/report refs in each task's context_refs.",
    )


class CancelWorkerArguments(StrictModel):
    worker_id: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2000)


class ReviewValidation(StrictModel):
    conclusion_sequences: list[int] = Field(min_length=1, max_length=20)
    control_evidence_refs: list[str] = Field(min_length=1, max_length=20)
    calibration_basis: str | None = Field(default=None, min_length=1, max_length=1000)
    calibration_sequences: list[int] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def evidence_contract(self):
        if not (self.calibration_basis or "").strip() and not self.calibration_sequences:
            raise ValueError("Validation requires an implementation calibration basis or calibration sequences")
        if any(not ref.startswith("evidence:") for ref in self.control_evidence_refs):
            raise ValueError("Controls must use evidence references")
        if any(seq <= 0 for seq in self.conclusion_sequences + self.calibration_sequences):
            raise ValueError("Source sequences must be positive")
        return self


class AcquiredCapability(StrictModel):
    """A Solver's evidence-backed statement about a target-side capability."""

    kind: Literal[
        "file_read",
        "command_execution",
        "database_read",
        "admin_session",
        "ssrf",
    ]
    target_environment: str = Field(min_length=1, max_length=1_000)
    scope: str = Field(
        min_length=1,
        max_length=2_000,
        description="What was actually demonstrated in the target environment.",
    )
    limitations: str = Field(
        min_length=1,
        max_length=2_000,
        description="What remains unverified or unavailable.",
    )

    @model_validator(mode="after")
    def non_blank_details(self):
        if any(
            not value.strip()
            for value in (self.target_environment, self.scope, self.limitations)
        ):
            raise ValueError("Capability environment, scope and limitations must not be blank")
        return self


class SolverReviewArguments(StrictModel):
    hypothesis_id: str = Field(min_length=1, max_length=128)
    strategy_revision: int = Field(default=1, ge=1)
    covered_sequences: list[int] = Field(max_length=100)
    assessment: Literal["inconclusive", "no_new_information", "new_information"]
    direction_status: Literal["open", "weakly_rejected", "dead"] = "open"
    summary: str = Field(min_length=1, max_length=2000)
    next_test: str = Field(min_length=1, max_length=1000)
    validation: ReviewValidation | None = Field(default=None, description="Evidence for a verified conclusion or ruled-out hypothesis. Ordinary progress observations may omit it.")
    acquired_capabilities: list[AcquiredCapability] = Field(
        default_factory=list,
        max_length=5,
        description="Only evidence-validated target-side capabilities. Local command success or a keyword is not sufficient.",
    )
    revoked_sequences: list[int] = Field(default_factory=list, max_length=50)
    environment_dependent: bool = True
    observation_revision: int | None = Field(default=None, gt=0,
        description="Optional existing observer snapshot event sequence. Omit both observation fields when no observer snapshot was delivered.")
    observation_assessment: Literal["corrected", "dismissed", "uncertain"] | None = Field(default=None,
        description="Feedback about the observer snapshot named by observation_revision, NOT the uncertainty of this review. Omit unless observation_revision is supplied.")

    @model_validator(mode="after")
    def evidence_contract(self):
        if any(not value.strip() for value in (self.hypothesis_id, self.summary, self.next_test)):
            raise ValueError("Hypothesis, summary and next test must not be blank")
        if (self.observation_revision is None) != (self.observation_assessment is None):
            raise ValueError("Observation assessment and revision must be supplied together")
        if any(seq <= 0 for seq in self.covered_sequences + self.revoked_sequences):
            raise ValueError("Source sequences must be positive")
        if self.acquired_capabilities and (
            self.assessment != "new_information" or self.validation is None
        ):
            raise ValueError(
                "Acquired capabilities require a new-information review with validation"
            )
        if self.direction_status == "dead" and (
            self.assessment != "new_information" or self.validation is None
        ):
            raise ValueError("dead directions require validated new information")
        return self


class SolverProgressArguments(WorkerUpdateInput):
    status: Literal["working", "blocked"] = "working"


class SubmitFlagArguments(StrictModel):
    flag: str = Field(min_length=1, max_length=4096)


class EvidenceReadArguments(StrictModel):
    evidence_ref: str = Field(
        min_length=1,
        description=(
            "Copy the exact returned evidence_ref: "
            "evidence:evidence_<32 lowercase hex characters>. "
            "Do not pass a bare evidence ID."
        ),
    )
    offset: int = Field(default=0, ge=0, description="Character offset returned by the prior page.")
    limit_chars: int = Field(default=8000, ge=1, le=30000, description="Maximum characters to return per page.")


class ReportReadArguments(StrictModel):
    report_ref: str = Field(min_length=1, description="Exact report_ref returned by a control or Worker report; never synthesize a reference.")
    offset: int = Field(default=0, ge=0, description="Character offset returned by the prior read.")
    limit_chars: int = Field(default=8000, ge=1, le=30000, description="Maximum characters to return per page.")


class EvidenceSearchArguments(StrictModel):
    query: str = Field(default="", max_length=1000, description="Search source, evidence type, or an exact/partial system task_id.")
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


class SolverObserveArguments(ReportQueryArguments):
    task_offset: int = Field(default=0, ge=0)
    task_limit: int = Field(default=20, ge=1, le=100)
