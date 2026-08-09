"""Authoritative per-run state storage and scheduling services."""

from .database import SCHEMA_VERSION, StateDatabase
from .agent_store import AgentStateStore
from .capabilities import Capability, CapabilityRegistry
from .service import StateService, derive_phase
from .wakeup import StateSignalBus
from .scheduling import ChallengeLoopController, ChallengeScheduler, ResourceController, StagnationManager
from .resources import (
    RELEASED_CONTAINER_STATUSES,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .schemas import (
    AgentProgressInput,
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    ChallengeImport,
    ChallengeSyncResult,
    ExecutionTaskInput,
    FindingInput,
    VerificationUpdateInput,
)

__all__ = [
    "SCHEMA_VERSION",
    "AgentStateStore",
    "Capability",
    "CapabilityRegistry",
    "AgentProgressInput",
    "AgentReportInput",
    "AnalysisPlanInput",
    "CapabilityContext",
    "ChallengeImport",
    "ChallengeSyncResult",
    "ExecutionTaskInput",
    "FindingInput",
    "StateDatabase",
    "StateService",
    "StateSignalBus",
    "derive_phase",
    "ResourceController",
    "StagnationManager",
    "ChallengeScheduler",
    "ChallengeLoopController",
    "RELEASED_CONTAINER_STATUSES",
    "checkpoint_target_status",
    "container_capacity_summary",
    "container_slot_occupied",
    "VerificationUpdateInput",
]
