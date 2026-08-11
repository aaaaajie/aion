"""Serializable models for a single Agent run."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


TargetStatus = Literal[
    "pending",
    "started",
    "in_progress",
    "flag_found",
    "submitted",
    "closed",
    "failed",
    "indeterminate",
]

AgentRole = Literal["chief", "challenge", "execution"]
RunStatus = Literal["active", "paused", "completed", "failed", "interrupted"]
AgentLifecycleStatus = Literal[
    "pending",
    "running",
    "waiting",
    "completed",
    "failed",
    "stopped",
    "interrupted",
    "indeterminate",
]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunManifest(_Model):
    schema_version: int = 1
    run_id: str = Field(min_length=1)
    model: str = Field(min_length=1)
    context_window_tokens: int = Field(gt=0)
    prompt: str = ""
    role: AgentRole | None = None
    parent_id: str | None = None
    unique_code: str | None = None
    status: RunStatus = "active"
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class TargetState(_Model):
    unique_code: str = Field(min_length=1)
    status: TargetStatus = "pending"
    is_completed: bool = False
    work_status: str = "unassigned"
    container_status: str = "stopped"
    slot_occupied: bool = False
    container_addr: list[str] = Field(default_factory=list)
    score_snapshot: dict[str, Any] = Field(default_factory=dict)
    last_error_code: str | None = None
    last_event_sequence: int = 0


class OperationState(_Model):
    operation_id: str = Field(default_factory=lambda: uuid4().hex)
    tool_name: str = Field(min_length=1)
    unique_code: str | None = None
    status: Literal["started", "completed", "indeterminate"] = "started"
    arguments_fingerprint: str | None = None
    started_sequence: int = 0
    completed_sequence: int | None = None
    result_code: str | None = None


class AgentNode(_Model):
    """Durable metadata for one Agent in the current run's Agent graph."""

    agent_id: str = Field(min_length=1)
    role: AgentRole
    parent_id: str | None = None
    unique_code: str | None = None
    status: AgentLifecycleStatus = "pending"
    sidecar_path: str = Field(min_length=1)
    task_id: str | None = None
    mission: str = ""
    timeout_seconds: int | None = Field(default=None, ge=1)
    report_count: int = Field(default=0, ge=0)
    last_report_sequence: int = Field(default=0, ge=0)
    started_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Checkpoint(_Model):
    schema_version: int = 1
    run_id: str = Field(min_length=1)
    status: RunStatus = "active"
    phase: str = "initializing"
    targets: list[TargetState] = Field(default_factory=list)
    container_capacity: dict[str, Any] = Field(default_factory=dict)
    current_target: str | None = None
    score_snapshot: dict[str, Any] = Field(default_factory=dict)
    last_event_sequence: int = 0
    last_summarized_event_sequence: int = 0
    active_tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    last_completed_operation: OperationState | None = None
    indeterminate_operations: list[OperationState] = Field(default_factory=list)
    agents: list[AgentNode] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)


class RunEvent(_Model):
    schema_version: int = 1
    run_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
