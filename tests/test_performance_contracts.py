from __future__ import annotations

from pathlib import Path
from types import MethodType
from typing import Any

import pytest

from agent.config import ContextBudget, ROLE_CONTEXT_PROFILES
from agent.prompts import system_prompt
from agent.runtime import AgentRuntime
from agent.state import StateService
from agent.state.database import SCHEMA_VERSION
from agent.subagents.policy import AgentPolicy
from scripts.analyze_run_performance import analyze_run


def test_competition_context_and_schema_contract() -> None:
    assert SCHEMA_VERSION == 15
    assert ContextBudget().absolute_prompt_tokens("chief") == 959_040
    assert ContextBudget().absolute_prompt_tokens("execution") == 975_424
    assert {
        role: profile.soft_prompt_tokens
        for role, profile in ROLE_CONTEXT_PROFILES.items()
    } == {"chief": 128_000, "challenge": 96_000, "execution": 64_000}


def test_role_prompts_are_small() -> None:
    limits = {"chief": 3_000, "challenge": 5_000, "execution": 4_000}
    for role, limit in limits.items():
        assert len(system_prompt(role)) <= limit


def test_execution_surface_is_bounded_and_has_no_cleanup_tools() -> None:
    tools = AgentPolicy("execution").allowed_tools
    assert len(tools) <= 50
    assert not any(name.endswith("cleanup") for name in tools)
    assert "system_create_directory" not in tools
    assert "system_delete_path" not in tools
    assert {"execution_report", "evidence_read"} <= tools


def test_control_prompts_only_name_current_tools() -> None:
    root = Path(__file__).resolve().parents[1] / "agent" / "prompts"
    text = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.txt"))
    assert "challenge_dispatch" in text
    assert "challenge_observe" in text
    assert "execution_report" in text


@pytest.mark.asyncio
async def test_admission_drain_interleaves_explicit_resource_and_agent_batches() -> None:
    class Controller:
        def __init__(self) -> None:
            self.resources = [f"work-{index}" for index in range(50)]
            self.agents = [f"agent-{index}" for index in range(12)]

        async def sample(self) -> dict[str, float]:
            return {"cpu_percent": 0.0, "memory_percent": 0.0}

        async def next_queued_resource_work_item(self) -> dict[str, Any] | None:
            if not self.resources:
                return None
            return {
                "kind": "resource",
                "id": self.resources[0],
                "owner_type": "http_interaction",
                "owner_id": self.resources[0],
                "phase": "execution",
            }

        async def next_queued_agent_id(self) -> str | None:
            return self.agents[0] if self.agents else None

    controller = Controller()
    runtime = object.__new__(AgentRuntime)
    runtime.resource_controller = controller
    admitted: list[tuple[str, str]] = []

    async def admit_item(
        _self: AgentRuntime,
        item: dict[str, Any],
        *,
        sample: dict[str, float],
    ) -> dict[str, Any]:
        assert sample == {"cpu_percent": 0.0, "memory_percent": 0.0}
        admitted.append((item["kind"], item["id"]))
        if item["kind"] == "resource":
            assert controller.resources.pop(0) == item["id"]
        else:
            assert controller.agents.pop(0) == item["id"]
        return {"ok": True, "status": "running"}

    runtime._admit_item = MethodType(admit_item, runtime)
    results = await runtime.admission_drain()

    assert len(results) == 62
    assert [kind for kind, _ in admitted[:12]] == ["resource"] * 8 + ["agent"] * 4
    assert [kind for kind, _ in admitted[12:24]] == ["resource"] * 8 + ["agent"] * 4
    assert [kind for kind, _ in admitted[24:36]] == ["resource"] * 8 + ["agent"] * 4
    assert not controller.resources
    assert not controller.agents


@pytest.mark.asyncio
async def test_performance_analysis_exposes_competition_failures(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    service = StateService(database)
    await service.create_run("analysis-run")
    chief = await service.register_agent(
        "analysis-run", role="chief", initial_prompt="coordinate"
    )
    agent_id = chief["agent_id"]
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "agent_report",
        {
            "findings_received": 3,
            "findings_normalized": 2,
            "findings_persisted": 2,
            "findings_dropped": 1,
            "candidate_flag_present": True,
        },
    )
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "memory_update_failed",
        {"code": "summary_unavailable"},
    )
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "context_micro_compacted",
        {"reason": "summary_failed"},
    )
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "tool_result",
        {
            "tool_name": "challenge_dispatch",
            "round": 1,
            "result": {"ok": True, "data": {}},
            "execution_latency_ms": 20,
        },
    )
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "tool_result",
        {
            "tool_name": "execution_report",
            "round": 2,
            "result": {
                "ok": False,
                "error": {"stage": "schema", "code": "invalid_arguments"},
            },
            "error_stage": "schema",
            "error_code": "invalid_arguments",
        },
    )
    await service.append_agent_event(
        "analysis-run",
        agent_id,
        "agent_resource_cleanup_failed",
        {
            "failures": [
                {"manager": "shell", "error_type": "FileNotFoundError"},
                {"manager": "network", "error_type": "OSError"},
            ]
        },
    )

    result = analyze_run(database, "analysis-run")
    assert result["findings"] == {
        "received": 3,
        "normalized": 2,
        "persisted": 2,
        "dropped": 1,
        "persistence_rate": 0.6667,
    }
    assert result["flags"]["candidate_count"] == 1
    assert result["competition_flow"]["first_dispatch_success_rate"] == 1.0
    assert result["critical_tools"]["challenge_dispatch"]["successes"] == 1
    assert result["critical_tools"]["execution_report"]["failures"] == {
        "schema:invalid_arguments": 1
    }
    assert result["context_compaction"]["by_role"]["chief"] == {
        "successes": 0,
        "failures": 1,
        "micro_compactions": 1,
        "failure_rate": 1.0,
    }
    assert result["agent_resource_cleanup_failures"] == {
        "event_count": 1,
        "by_manager": {"network": 1, "shell": 1},
        "failure_count": 2,
    }
    await service.close()
