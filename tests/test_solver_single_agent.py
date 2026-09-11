"""Solver-first lifecycle tests.

These tests assert the architectural contract that replaced the legacy
Bootstrap + initial-recon workgroup: launching a challenge creates exactly one
Solver Agent, that Solver carries the full technical tool surface, and Runtime
does not create any Execution, Observer, Bootstrap, or Admission row for it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from agent.config import AgentSettings
from agent.state import CapabilityContext
from agent.state.database import StateDatabase
from agent.state.models import (
    AdmissionRecord,
    AgentRecord,
)
from agent.state.schemas import ChallengeImport
from agent.state.service import StateService
from agent.subagents.supervisor import AgentSupervisor
from agent.subagents.policy import AgentPolicy


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="test-key",
    )


async def _service_for(tmp_path: Path) -> StateService:
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
    )
    await service.initialize()
    await service.create_run(
        "run",
        challenges=[
            ChallengeImport(
                unique_code="challenge-a",
                description="a direct-solve challenge",
                container_status="running",
                container_addr=["http://127.0.0.1:18000"],
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    return service


@pytest.mark.asyncio
async def test_register_solver_creates_one_agent_and_no_legacy_work(
    tmp_path: Path,
) -> None:
    service = await _service_for(tmp_path)
    created = await service.register_solver_for_challenge(
        "run",
        solver_agent_id="solver_a",
        parent_id="chief",
        unique_code="challenge-a",
        solver_prompt="solve it",
        mission="direct solve",
    )
    assert created["agent_id"] == "solver_a"
    assert created["role"] == "solver"

    overview = await service.get_overview("run")
    agents = overview["agents"]
    assert len([item for item in agents if item["role"] == "solver"]) == 1
    assert not [item for item in agents if item["role"] == "worker"]

    duplicate = await service.register_solver_for_challenge(
        "run",
        solver_agent_id="solver_b",
        parent_id="chief",
        unique_code="challenge-a",
        solver_prompt="solve it again",
    )
    assert duplicate["agent_id"] == "solver_a"
    assert duplicate["idempotent"] is True

    async with service.db.sessions() as session:
        admission_count = await session.scalar(
            select(func.count(AdmissionRecord.admission_id)).where(
                AdmissionRecord.run_id == "run"
            )
        )
        solver_count = await session.scalar(
            select(func.count(AgentRecord.agent_id)).where(
                AgentRecord.run_id == "run",
                AgentRecord.role == "solver",
                AgentRecord.unique_code == "challenge-a",
            )
        )
    assert admission_count == 0
    assert solver_count == 1
    await service.close()


def test_solver_policy_allows_the_full_technical_surface() -> None:
    policy = AgentPolicy("solver")
    for tool in (
        "system_shell",
        "system_http_request",
        "system_network_discovery",
        "bin_disassemble",
        "pentest_sqlmap",
        "artifact_static_review",
        "solver_submit_flag",
        "evidence_read",
    ):
        assert policy.allows(tool), tool
    for tool in (
        "worker_report",
        "bootstrap_checkpoint",
        "bootstrap_cycle_yield",
    ):
        assert not policy.allows(tool), tool


@pytest.mark.asyncio
async def test_create_challenge_agent_launches_one_solver_with_technical_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = await _service_for(tmp_path)
    supervisor = AgentSupervisor(
        _settings(),
        run_root=tmp_path / "runs",
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    supervisor.run_id = "run"
    supervisor.chief_agent_id = "chief"
    await supervisor._sync_nodes()
    supervisor._issue_capabilities()
    launched: list[str] = []

    async def fake_refresh(caller_id: str) -> dict[str, Any]:
        supervisor._catalog = {
            "challenge-a": {
                "unique_code": "challenge-a",
                "name": "Challenge A",
                "description": "direct solve",
                "difficulty": "easy",
                "level": 1,
                "container_addr": ["http://127.0.0.1:18000"],
            }
        }
        return {"ok": True}

    async def fake_container(caller_id: str, unique_code: str) -> dict[str, Any]:
        return {
            "ok": True,
            "data": {
                "container_addr": ["http://127.0.0.1:18000"],
            },
        }

    async def fake_launch(agent_id: str, *, resume: bool = False) -> Any:
        launched.append(agent_id)

    monkeypatch.setattr(supervisor, "refresh_challenges", fake_refresh)
    monkeypatch.setattr(supervisor, "_ensure_challenge_container", fake_container)
    monkeypatch.setattr(supervisor, "_launch_agent", fake_launch)

    result = await supervisor.create_solver("chief", "challenge-a")
    assert result["ok"] is True
    solver_id = result["data"]["agent_id"]
    assert solver_id.startswith("solver_")
    assert launched == [solver_id]

    runtime = await service.get_agent_runtime("run", solver_id)
    agent = runtime["agent"]
    assert agent["role"] == "solver"
    assert agent["unique_code"] == "challenge-a"

    overview = await service.get_overview("run")
    agents = overview["agents"]
    assert not [item for item in agents if item["role"] == "worker"]

    # A second launch is idempotent and reuses the same Solver.
    result2 = await supervisor.create_solver("chief", "challenge-a")
    assert result2["ok"] is True
    assert result2["data"]["agent_id"] == solver_id
    assert result2["data"]["idempotent"] is True
    assert launched == [solver_id, solver_id]
    await service.close()


@pytest.mark.asyncio
async def test_solver_capability_can_persist_and_read_same_challenge_evidence(
    tmp_path: Path,
) -> None:
    service = await _service_for(tmp_path)
    await service.register_solver_for_challenge(
        "run",
        solver_agent_id="solver_a",
        parent_id="chief",
        unique_code="challenge-a",
        solver_prompt="solve it",
    )
    context = CapabilityContext(
        run_id="run",
        agent_id="solver_a",
        role="solver",
        unique_code="challenge-a",
    )
    saved = await service.persist_evidence(
        "run",
        context,
        evidence_type="observation",
        source="fixture",
        content="probe result",
    )
    evidence_ref = saved["evidence_ref"]
    read = await service.read_evidence("run", context, evidence_ref)
    assert read["content"] == "probe result"
    await service.close()
