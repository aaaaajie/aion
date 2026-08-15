"""Authoritative per-run state storage and scheduling services."""

from .database import SCHEMA_VERSION, StateDatabase
from .agent_store import AgentStateStore
from .capabilities import Capability, CapabilityRegistry
from .service import StateService, derive_phase
from .wakeup import StateSignalBus
from .scheduling import ChallengeScheduler, ResourceController, StagnationManager
from .resources import (
    ACTIVE_CHALLENGE_WORK_STATUSES,
    MAX_CHALLENGE_SLOTS,
    RELEASED_CONTAINER_STATUSES,
    challenge_work_active,
    challenge_start_gate,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .schemas import (
    AgentReportInput,
    CHALLENGE_DIRECTION_VALUES,
    CapabilityContext,
    ChallengeDispatchInput,
    ChallengeImport,
    ChallengeSyncResult,
    ExecutionTaskInput,
    FindingInput,
    HypothesisOutcome,
    HypothesisInput,
    TaskStage,
)

__all__ = [
    "SCHEMA_VERSION",
    "AgentStateStore",
    "Capability",
    "CapabilityRegistry",
    "AgentReportInput",
    "CHALLENGE_DIRECTION_VALUES",
    "CapabilityContext",
    "ChallengeDispatchInput",
    "ChallengeImport",
    "ChallengeSyncResult",
    "ExecutionTaskInput",
    "FindingInput",
    "HypothesisOutcome",
    "HypothesisInput",
    "TaskStage",
    "StateDatabase",
    "StateService",
    "StateSignalBus",
    "derive_phase",
    "ResourceController",
    "StagnationManager",
    "ChallengeScheduler",
    "ACTIVE_CHALLENGE_WORK_STATUSES",
    "MAX_CHALLENGE_SLOTS",
    "RELEASED_CONTAINER_STATUSES",
    "challenge_start_gate",
    "challenge_work_active",
    "checkpoint_target_status",
    "container_capacity_summary",
    "container_slot_occupied",
]
