"""SQLAlchemy models for one run's authoritative state database."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


DEFAULT_SESSION_MEMORY = """# Current State

# Task Specification

# Targets

# Important Observations

# Workflow

# Errors & Corrections

# Next Steps

# Worklog
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SchemaMetaRecord(Base):
    __tablename__ = "schema_meta"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class RunRecord(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    model: Mapped[str | None] = mapped_column(String(256))
    prompt: Mapped[str | None] = mapped_column(Text)
    context_window_tokens: Mapped[int] = mapped_column(Integer, default=1_000_000, nullable=False)
    phase: Mapped[str] = mapped_column(String(16), default="early", nullable=False)
    pass_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=360, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_challenge_code: Mapped[str | None] = mapped_column(String(256))
    score_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    last_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_projected_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stagnation_epoch: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pause_reason: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)


class ChallengeRecord(Base):
    __tablename__ = "challenges"

    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True)
    unique_code: Mapped[str] = mapped_column(String(256), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    difficulty: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    flag_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    correct_flag_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    platform_status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    container_status: Mapped[str] = mapped_column(String(32), default="stopped", nullable=False)
    container_addr: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    work_status: Mapped[str] = mapped_column(String(32), default="unassigned", nullable=False)
    control_state: Mapped[str] = mapped_column(
        String(32), default="ok", nullable=False
    )
    control_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pause_reason: Mapped[str | None] = mapped_column(String(128))
    pass_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    resume_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    evidence_root: Mapped[str | None] = mapped_column(Text)
    stagnation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hint_eligible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    hint_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_progress_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exploration_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    l2_explorer_created: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    extension_cycle_pending: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_challenges_run_work", "run_id", "work_status"),
        Index("ix_challenges_run_progress", "run_id", "last_progress_at"),
    )


class AgentRecord(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    parent_id: Mapped[str | None] = mapped_column(String(128))
    unique_code: Mapped[str | None] = mapped_column(String(256))
    cycle_id: Mapped[str | None] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), default="general", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    mission: Mapped[str] = mapped_column(Text, default="", nullable=False)
    initial_prompt: Mapped[str] = mapped_column(Text, default="", nullable=False)
    session_memory: Mapped[str] = mapped_column(Text, default=DEFAULT_SESSION_MEMORY, nullable=False)
    final_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    last_summarized_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    report_cursor: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    report_cursors: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    success_criteria: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    context_refs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    hypothesis_key: Mapped[str | None] = mapped_column(String(128))
    task_key: Mapped[str | None] = mapped_column(String(128))
    branch_key: Mapped[str | None] = mapped_column(String(256))
    terminal_report_id: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    timeout_seconds: Mapped[int | None] = mapped_column(Integer)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_report_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    controller_cursor: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stop_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_agents_run_status", "run_id", "status"),
        Index("ix_agents_challenge_status", "run_id", "unique_code", "status"),
        UniqueConstraint(
            "run_id", "unique_code", "task_key", name="uq_execution_task_key"
        ),
        Index(
            "ix_agents_challenge_hypothesis",
            "run_id",
            "unique_code",
            "hypothesis_key",
        ),
        Index(
            "ix_agents_challenge_branch",
            "run_id",
            "unique_code",
            "branch_key",
        ),
    )


class ObservationRecord(Base):
    __tablename__ = "observation_records"

    observation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    target_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(128))
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "unique_code",
            "target_fingerprint",
            "category",
            "fingerprint",
            name="uq_observation_fingerprint",
        ),
        Index(
            "ix_observations_challenge",
            "run_id",
            "unique_code",
            "target_fingerprint",
        ),
    )


class HypothesisRecord(Base):
    __tablename__ = "hypothesis_records"

    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    hypothesis_key: Mapped[str] = mapped_column(String(128), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    based_on_observations: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default="proposed", nullable=False
    )
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint(
            "run_id", "unique_code", "hypothesis_key", name="pk_hypothesis"
        ),
        Index(
            "ix_hypotheses_challenge",
            "run_id",
            "unique_code",
            "status",
        ),
    )


class ExecutionBranchRecord(Base):
    __tablename__ = "execution_branches"

    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    branch_key: Mapped[str] = mapped_column(String(256), nullable=False)
    target_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    hypothesis_key: Mapped[str | None] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default="proposed", nullable=False
    )
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    mission: Mapped[str | None] = mapped_column(Text)
    agent_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    outcome: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint(
            "run_id", "unique_code", "branch_key", name="pk_execution_branch"
        ),
        Index(
            "ix_execution_branches_challenge_status",
            "run_id",
            "unique_code",
            "status",
        ),
    )


class ShellTaskRecord(Base):
    __tablename__ = "shell_tasks"

    task_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    process_started_at: Mapped[float] = mapped_column(Float, nullable=False)
    cwd: Mapped[str] = mapped_column(Text, nullable=False)
    temp_dir: Mapped[str] = mapped_column(Text, nullable=False)
    output_path: Mapped[str] = mapped_column(Text, nullable=False)
    capture_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    output_chars: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    timed_out: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    output_cleaned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cleanup_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index("ix_shell_tasks_owner_status", "run_id", "agent_id", "status"),
        Index("ix_shell_tasks_expiry", "run_id", "expires_at"),
    )


class NetworkTaskRecord(Base):
    __tablename__ = "network_tasks"

    task_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    resource_status: Mapped[str] = mapped_column(
        String(32), default="queued", nullable=False
    )
    scan_intent: Mapped[str] = mapped_column(
        String(128), default="network_discovery", nullable=False
    )
    result_path: Mapped[str] = mapped_column(Text, nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer)
    process_started_at: Mapped[float | None] = mapped_column(Float)
    scanner_version: Mapped[str | None] = mapped_column(String(128))
    bridge_protocol_version: Mapped[str | None] = mapped_column(String(32))
    estimated_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    estimated_ports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    estimated_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requested_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    tasks_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tasks_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hosts_alive: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    open_ports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    services: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    web_ports: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(128))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    output_cleaned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cleanup_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index("ix_network_tasks_owner_status", "run_id", "agent_id", "status"),
        Index("ix_network_tasks_resource_status", "run_id", "resource_status"),
    )


class HttpInteractionRecord(Base):
    __tablename__ = "http_interactions"

    interaction_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    execution_status: Mapped[str] = mapped_column(
        String(32), default="queued", nullable=False
    )
    analysis_status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False
    )
    resource_status: Mapped[str] = mapped_column(
        String(32), default="queued", nullable=False
    )
    result_path: Mapped[str] = mapped_column(Text, nullable=False)
    estimated_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    requested_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_disk_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_memory_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_analysis_work: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    started_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    response_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    analyzed_responses: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    analysis_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    output_cleaned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cleanup_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index(
            "ix_http_interactions_owner_status",
            "run_id",
            "agent_id",
            "status",
        ),
    )


class CycleRecord(Base):
    __tablename__ = "cycles"

    cycle_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    cycle_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="state", nullable=False)
    state_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    analysis: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    state_update: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    analysis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    plan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execute_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verify_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    update_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("run_id", "unique_code", "cycle_number", name="uq_cycle_number"),
        Index("ix_cycles_challenge", "run_id", "unique_code", "cycle_number"),
    )


class FindingRecord(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(16), default="candidate", nullable=False)
    evidence_paths: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        UniqueConstraint("run_id", "unique_code", "category", "fingerprint", name="uq_finding_fingerprint"),
        Index("ix_findings_challenge_verification", "run_id", "unique_code", "verification_status"),
    )


class CredentialRecord(Base):
    __tablename__ = "credentials"

    credential_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    unique_code: Mapped[str] = mapped_column(String(256), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    principal: Mapped[str | None] = mapped_column(Text)
    secret_value: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str | None] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (Index("ix_credentials_challenge", "run_id", "unique_code"),)


class ReportRecord(Base):
    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    parent_id: Mapped[str | None] = mapped_column(String(128))
    unique_code: Mapped[str | None] = mapped_column(String(256))
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    consumed_by: Mapped[str | None] = mapped_column(String(128))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_report_sequence"),
        Index("ix_reports_parent_sequence", "run_id", "parent_id", "sequence"),
    )


class OperationRecord(Base):
    __tablename__ = "operations"

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128))
    unique_code: Mapped[str | None] = mapped_column(String(256))
    operation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="started", nullable=False)
    arguments_fingerprint: Mapped[str | None] = mapped_column(String(64))
    request_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_code: Mapped[str | None] = mapped_column(String(128))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(String(512))
    started_sequence: Mapped[int | None] = mapped_column(Integer)
    completed_sequence: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_operations_state", "run_id", "status"),)


class AdmissionRecord(Base):
    __tablename__ = "admission_queue"

    admission_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    unique_code: Mapped[str | None] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(128))
    retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reserved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("run_id", "agent_id", name="uq_admission_agent"),
        Index("ix_admission_status_priority", "run_id", "status", "priority"),
    )


class ResourceWorkRecord(Base):
    __tablename__ = "resource_work_queue"

    work_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False
    )
    owner_type: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    requested_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_disk_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_memory_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(128))
    retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reserved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("owner_id", "phase", name="uq_resource_work_owner_phase"),
        Index(
            "ix_resource_work_status_priority",
            "run_id",
            "status",
            "priority",
        ),
    )


class ResourceSampleRecord(Base):
    __tablename__ = "resource_samples"

    sample_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (Index("ix_resource_sample_time", "run_id", "sampled_at"),)


class StateEventRecord(Base):
    __tablename__ = "state_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128))
    cycle_id: Mapped[str | None] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_state_event_sequence"),
        Index("ix_state_events_run_sequence", "run_id", "sequence"),
        Index("ix_state_events_agent_sequence", "run_id", "agent_id", "sequence"),
    )


class AuditOutboxRecord(Base):
    __tablename__ = "audit_outbox"

    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), primary_key=True
    )
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_outbox_pending", "run_id", "sequence"),
    )
