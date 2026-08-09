"""Compatibility import surface for role-scoped Agent tools."""

from agent.subagents.tools import (
    AgentControlTools,
    ChallengeAgentTools,
    ChiefAgentTools,
    ExecutionAgentTools,
)

__all__ = [
    "AgentControlTools",
    "ChiefAgentTools",
    "ChallengeAgentTools",
    "ExecutionAgentTools",
]
