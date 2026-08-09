"""Agent-facing tool wrappers for the project."""

from .benchmark import BenchmarkTools
from .http import HttpInteractionEngine, HttpProbeManager, HttpTools
from .system import SystemTools

__all__ = [
    "BenchmarkTools",
    "SystemTools",
    "HttpInteractionEngine",
    "HttpProbeManager",
    "HttpTools",
    "AgentControlTools",
    "ChiefAgentTools",
    "ChallengeAgentTools",
    "ExecutionAgentTools",
]


def __getattr__(name: str):
    """Load Agent orchestration tools lazily to avoid runner import cycles."""

    if name in {
        "AgentControlTools",
        "ChiefAgentTools",
        "ChallengeAgentTools",
        "ExecutionAgentTools",
    }:
        from .agents import (
            AgentControlTools,
            ChallengeAgentTools,
            ChiefAgentTools,
            ExecutionAgentTools,
        )

        return {
            "AgentControlTools": AgentControlTools,
            "ChiefAgentTools": ChiefAgentTools,
            "ChallengeAgentTools": ChallengeAgentTools,
            "ExecutionAgentTools": ExecutionAgentTools,
        }[name]
    raise AttributeError(name)
