"""Offline tests for role-scoped Agent orchestration."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from agent.config import AgentSettings
from agent.runner import ToolRegistry
from agent.skills import SkillTools
from agent.state import StateService
from agent.state.models import ChallengeRecord, StateEventRecord
from agent.subagents import (
    AgentSupervisor,
    ChallengeAgentTools,
    ChiefAgentTools,
    ExecutionAgentTools,
    ExecutionReport,
    SubagentError,
)
from agent.subagents.policy import AgentPolicy


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="llm-secret",
    )


def test_execution_report_contract_is_strict_and_outcome_is_terminal() -> None:
    with pytest.raises(ValidationError):
        ExecutionReport.model_validate(
            {"status": "completed", "summary": "missing outcome"}
        )
    with pytest.raises(ValidationError):
        ExecutionReport.model_validate(
            {
                "status": "working",
                "summary": "legacy finding",
                "findings": ["free-form finding"],
            }
        )
    with pytest.raises(ValidationError):
        ExecutionReport.model_validate(
            {
                "status": "completed",
                "summary": "unsupported claim",
                "hypothesis_outcome": "supported",
            }
        )
    accepted = ExecutionReport.model_validate(
        {
            "status": "completed",
            "summary": "evidence-backed rejection",
            "hypothesis_outcome": "rejected",
            "evidence_paths": ["evidence/rejection.json"],
        }
    )
    assert accepted.hypothesis_outcome == "rejected"


def _challenge(code: str) -> dict[str, Any]:
    return {
        "unique_code": code,
        "description": "A bounded test challenge",
        "difficulty": "easy",
        "level": 1,
        "total_score": 10,
        "flag_count": 1,
        "correct_flag_count": 0,
        "is_completed": False,
        "container_status": "stopped",
        "container_addr": [],
    }


def _atomic_task_arguments(
    *, mission: str, hypothesis_key: str, task_key: str
) -> dict[str, Any]:
    return {
        "mission": mission,
        "hypothesis_key": hypothesis_key,
        "task_key": task_key,
        "task_phase": "reconnaissance",
        "entry_point": "task-1",
        "capability_class": "fixture_inspection",
        "verification_question": "Does the fixture answer the assigned hypothesis?",
        "target_scope": ["task-1"],
        "tool_names": ["execution_get_assignment", "execution_report"],
        "success_criteria": ["the one assigned question is answered"],
        "failure_criteria": ["the assigned evidence is insufficient"],
        "evidence_requirements": ["cite the inspected metadata or response"],
        "stop_conditions": ["a success or failure criterion is met"],
        "scanner_profile": "other_light",
        "cost_class": "low",
        "max_http_requests": 0,
        "max_shell_tasks": 0,
        "max_network_tasks": 0,
    }


class _FakeBenchmark:
    def __init__(self) -> None:
        self.challenges = [_challenge(f"task-{index}") for index in range(1, 6)]
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, dict(arguments)))
        code = arguments.get("unique_code")
        if name == "benchmark_list_challenges":
            return {"ok": True, "data": self.challenges}
        if name == "benchmark_start_challenge":
            challenge = next(item for item in self.challenges if item["unique_code"] == code)
            challenge["container_status"] = "running"
            return {"ok": True, "data": {"unique_code": code, "container_addr": ["10.0.0.1"]}}
        if name == "benchmark_get_hint":
            return {"ok": True, "data": {"unique_code": code, "hint": "try the test path"}}
        if name == "benchmark_submit_flag":
            return {
                "ok": True,
                "data": {
                    "correct": True,
                    "awarded": 10,
                    "cumulative_score": 10,
                    "correct_flag_count": 1,
                    "total_flag_count": 1,
                },
            }
        if name == "benchmark_close_challenge":
            challenge = next(item for item in self.challenges if item["unique_code"] == code)
            challenge["container_status"] = "stopped"
            return {"ok": True, "data": {"unique_code": code, "closed": True}}
        raise AssertionError(name)

    async def close(self) -> None:
        return None


class _TwoFlagBenchmark(_FakeBenchmark):
    def __init__(self) -> None:
        super().__init__()
        self.challenges = [_challenge("multi-flag")]
        self.challenges[0]["flag_count"] = 2
        self.accepted = 0

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "benchmark_submit_flag":
            self.accepted += 1
            self.challenges[0]["correct_flag_count"] = self.accepted
            self.challenges[0]["is_completed"] = self.accepted >= 2
            return {
                "ok": True,
                "data": {
                    "correct": True,
                    "awarded": 10,
                    "cumulative_score": self.accepted * 10,
                    "correct_flag_count": self.accepted,
                    "total_flag_count": 2,
                    "matched_flag_index": self.accepted - 1,
                },
            }
        return await super().dispatch(name, arguments)


class _IncidentBenchmark(_FakeBenchmark):
    def __init__(self, *, reject_close: bool = False) -> None:
        super().__init__()
        self.reject_close = reject_close
        self.challenges = [
            {
                **_challenge("a-02"),
                "correct_flag_count": 1,
                "is_completed": True,
                "container_status": "available",
            },
            {**_challenge("a-03"), "container_status": "running"},
            {
                **_challenge("a-15"),
                "correct_flag_count": 1,
                "is_completed": True,
                "container_status": "available",
            },
            _challenge("a-16"),
        ]

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "benchmark_close_challenge" and self.reject_close:
            self.calls.append((name, dict(arguments)))
            return {
                "ok": False,
                "error": {
                    "type": "api",
                    "code": "invalid_state",
                    "message": "container close rejected",
                },
            }
        return await super().dispatch(name, arguments)


class _FakeRunner:
    """Keep spawned Agents alive until Supervisor cleanup cancels them."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.started = asyncio.Event()

    async def run_session(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.started.set()
        await asyncio.Event().wait()
        return {"status": "completed"}

    async def close(self) -> None:
        return None


class _YieldingControllerRunner:
    """Yield Challenge sessions immediately so signal consumption is observable."""

    calls: dict[str, int] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.role = kwargs["role"]
        self.agent_id = kwargs["agent_id"]

    async def run_session(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if self.role == "chief":
            await asyncio.Event().wait()
        self.calls[self.agent_id] = self.calls.get(self.agent_id, 0) + 1
        return {"final": "session yielded"}

    async def close(self) -> None:
        return None


class _YieldingChiefRunner:
    calls = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.role = kwargs["role"]

    async def run_session(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        assert self.role == "chief"
        type(self).calls += 1
        return {"final": "ordinary coordinator reply"}

    async def close(self) -> None:
        return None


class _MissingReportRunner:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.role = kwargs["role"]

    async def run_session(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if self.role != "execution":
            await asyncio.Event().wait()
        return {"final": "execution returned without reporting"}

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_role_tools_are_fixed_and_do_not_cross_permissions() -> None:
    chief_names = {item["function"]["name"] for item in ChiefAgentTools.tool_definitions()}
    challenge_names = {item["function"]["name"] for item in ChallengeAgentTools.tool_definitions()}
    execution_names = {item["function"]["name"] for item in ExecutionAgentTools.tool_definitions()}

    assert "chief_create_challenge_agent" in chief_names
    assert "challenge_create_domain_probes" in challenge_names
    assert "challenge_create_execution_agent" in challenge_names
    assert "system_shell" not in chief_names | challenge_names
    assert "benchmark_submit_flag" not in execution_names
    assert all(
        item["function"]["parameters"]["additionalProperties"] is False
        for definitions in (ChiefAgentTools.tool_definitions(), ChallengeAgentTools.tool_definitions(), ExecutionAgentTools.tool_definitions())
        for item in definitions
    )
    execution_snapshot = next(
        item
        for item in ChallengeAgentTools.tool_definitions()
        if item["function"]["name"] == "challenge_get_execution_reports"
    )
    assert "wait_seconds" not in execution_snapshot["function"]["parameters"]["properties"]
    assert "chief_wait_for_state" in chief_names
    assert "challenge_wait_for_state" in challenge_names
    skill_names = {item["function"]["name"] for item in SkillTools.tool_definitions()}
    assert skill_names <= AgentPolicy("challenge").allowed_tools
    assert skill_names <= AgentPolicy("execution").allowed_tools
    assert skill_names.isdisjoint(AgentPolicy("chief").allowed_tools)

    recognition_policy = AgentPolicy(
        "execution", execution_kind="domain_recognition"
    )
    assert recognition_policy.allows("system_http_request")
    assert recognition_policy.allows("system_read_file")
    assert not recognition_policy.allows("system_shell")
    assert not recognition_policy.allows("system_http_probe")
    assert not recognition_policy.allows("system_network_discovery")

    mixed_registry = ToolRegistry(
        [ChiefAgentTools.__new__(ChiefAgentTools), ExecutionAgentTools.__new__(ExecutionAgentTools)],
        allowed_tools={"chief_refresh_challenges"},
    )
    # The registry-level filter remains effective even if a caller accidentally
    # assembles wrappers from multiple roles.
    assert [item["function"]["name"] for item in mixed_registry.definitions()] == [
        "chief_refresh_challenges"
    ]


@pytest.mark.asyncio
async def test_agent_control_tool_schemas_match_state_payloads(tmp_path: Path) -> None:
    challenge_definition = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in ChallengeAgentTools.tool_definitions()
    }
    execution_definition = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in ExecutionAgentTools.tool_definitions()
    }

    plan_schema = challenge_definition["challenge_submit_analysis_plan"]
    assert "payload" not in plan_schema["properties"]
    assert {
        "cycle_id",
        "expected_version",
        "analysis_summary",
        "direction",
        "hypotheses",
        "information_gaps",
        "avoid_repeating",
        "tasks",
    } <= set(plan_schema["properties"])
    assert "payload" not in challenge_definition["challenge_commit_cycle"]["properties"]
    assert challenge_definition["challenge_create_execution_agent"]["properties"]["branch_key"]["type"] == "string"
    assert "task_stage" in challenge_definition["challenge_create_execution_agent"]["required"]
    assert "hypothesis_outcome" in execution_definition["execution_report"]["required"]
    assert "working" not in execution_definition["execution_report"]["properties"]["status"]["enum"]
    finding_schema = execution_definition["execution_update_progress"]["properties"]["findings"]["items"]
    assert {"category", "summary", "detail", "confidence", "verification_status", "evidence_paths"} <= set(finding_schema["properties"])
    assert finding_schema["additionalProperties"] is False

    service = StateService(
        tmp_path / "runs" / "tool-contract" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="tool-contract")
    created = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = created["data"]["agent_id"]
    challenge = ChallengeAgentTools(
        supervisor,
        agent_id=challenge_id,
        unique_code="task-1",
    )
    state = await challenge.dispatch("challenge_get_state", {})
    cycle = await challenge.dispatch(
        "challenge_begin_cycle",
        {"expected_challenge_version": state["data"]["challenge"]["version"]},
    )
    cycle_data = cycle["data"]
    plan = await challenge.dispatch(
        "challenge_submit_analysis_plan",
        {
            "cycle_id": cycle_data["cycle_id"],
            "expected_version": cycle_data["version"],
            "analysis_summary": "test the explicit plan contract",
            "direction": "web",
            "hypotheses": [
                {
                    "key": "contract-hypothesis",
                    "statement": "the explicit tool contract can create one bounded task",
                }
            ],
            "information_gaps": ["contract result"],
            "avoid_repeating": [],
            "tasks": [
                {
                    "task_key": "contract-task-1",
                    "hypothesis_key": "contract-hypothesis",
                    "kind": "verification",
                    "task_stage": "discovery",
                    "objective": "verify the tool contract",
                    "branch_key": "contract:tool:schema",
                    "success_criteria": ["the task is persisted"],
                    "context_refs": ["test:tool-contract"],
                    "timeout_seconds": 30,
                }
            ],
        },
    )
    assert plan["ok"] is True
    committed = await challenge.dispatch(
        "challenge_commit_cycle",
        {
            "cycle_id": cycle_data["cycle_id"],
            "expected_version": plan["data"]["version"],
            "summary": "the explicit cycle contract was accepted",
            "findings": [],
            "credentials": [],
            "next_steps": [],
            "new_attack_paths": [],
            "outcome": "no_progress",
        },
    )
    assert committed["ok"] is True
    created_execution = await challenge.dispatch(
        "challenge_create_execution_agent",
        {
            "mission": "verify the progress contract",
            "hypothesis_key": "challenge-direction",
            "task_key": "direction-probe-1",
            "kind": "verification",
            "task_stage": "discovery",
            "branch_key": "challenge:direction:probe",
        },
    )
    assert created_execution["ok"] is True
    execution_id = created_execution["data"]["agent_id"]

    execution = ExecutionAgentTools(
        supervisor,
        agent_id=execution_id,
        unique_code="task-1",
    )
    progress = await execution.dispatch(
        "execution_update_progress",
        {
            "status": "working",
            "phase": "contract-check",
            "summary": "persisting a canonical finding",
            "findings": [
                {
                    "category": "service",
                    "summary": "contract finding",
                    "detail": {"source": "test"},
                    "confidence": 0.9,
                    "verification_status": "candidate",
                    "evidence_paths": ["contract.json"],
                }
            ],
            "evidence_paths": ["contract.json"],
            "expected_result_seconds": 30,
        },
    )
    assert progress["ok"] is True

    before = await service.get_overview("tool-contract")
    rejected_plan = await challenge.dispatch(
        "challenge_submit_analysis_plan",
        {
            "cycle_id": cycle_data["cycle_id"],
            "expected_version": 1,
            "payload": {"analysis_summary": "obsolete payload"},
        },
    )
    after = await service.get_overview("tool-contract")
    assert rejected_plan["ok"] is False
    assert rejected_plan["error"]["code"] == "invalid_arguments"
    assert len(after["agents"]) == len(before["agents"])

    rejected_progress = await execution.dispatch(
        "execution_update_progress",
        {
            "status": "working",
            "phase": "contract-check",
            "summary": "reject legacy finding shape",
            "findings": [{"title": "legacy finding"}],
        },
    )
    assert rejected_progress["ok"] is False
    assert rejected_progress["error"]["code"] == "invalid_arguments"

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_challenge_conflict_requires_authoritative_refresh(
    tmp_path: Path,
) -> None:
    service = StateService(
        tmp_path / "runs" / "refresh-gate" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="refresh-gate")
    first_created = await supervisor.create_challenge_agent(chief_id, "task-1")
    second_created = await supervisor.create_challenge_agent(chief_id, "task-2")
    first = ChallengeAgentTools(
        supervisor,
        agent_id=first_created["data"]["agent_id"],
        unique_code="task-1",
    )
    second = ChallengeAgentTools(
        supervisor,
        agent_id=second_created["data"]["agent_id"],
        unique_code="task-2",
    )

    first_state = await first.dispatch("challenge_get_state", {})
    first_cycle = await first.dispatch(
        "challenge_begin_cycle",
        {
            "expected_challenge_version": first_state["data"]["challenge"]["version"]
        },
    )
    planned = await first.dispatch(
        "challenge_submit_analysis_plan",
        {
            "cycle_id": first_cycle["data"]["cycle_id"],
            "expected_version": first_cycle["data"]["version"],
            "analysis_summary": "persist the first cycle",
        },
    )
    assert planned["ok"] is True

    async with service.db.sessions() as session:
        before_events = len(
            (
                await session.scalars(
                    select(StateEventRecord).where(
                        StateEventRecord.run_id == "refresh-gate"
                    )
                )
            ).all()
        )
    stale_arguments = {
        "cycle_id": first_cycle["data"]["cycle_id"],
        "expected_version": first_cycle["data"]["version"],
        "analysis_summary": "retry stale cycle state",
    }
    stale = await first.dispatch("challenge_submit_analysis_plan", stale_arguments)
    assert stale["ok"] is False
    assert stale["error"]["code"] == "state_conflict"
    assert stale["error"]["status_code"] == 409
    assert stale["error"]["detail"]["required_tool"] == "challenge_get_state"
    assert stale["error"]["detail"]["retry_same_arguments"] is False
    assert stale["error"]["detail"]["cycle_id"] == first_cycle["data"]["cycle_id"]
    assert stale["error"]["detail"]["current_status"] == "execute"
    assert stale["error"]["detail"]["current_version"] == planned["data"]["version"]

    # A newly constructed wrapper must observe the Supervisor-level gate.
    rebuilt = ChallengeAgentTools(
        supervisor,
        agent_id=first_created["data"]["agent_id"],
        unique_code="task-1",
    )
    repeated = await rebuilt.dispatch(
        "challenge_submit_analysis_plan", stale_arguments
    )
    assert repeated["ok"] is False
    assert repeated["error"]["code"] == "state_refresh_required"
    assert repeated["error"]["detail"]["original_conflict_code"] == "state_conflict"
    assert repeated["error"]["detail"]["required_tool"] == "challenge_get_state"
    waiting = await rebuilt.dispatch("challenge_wait_for_state", {})
    assert waiting["ok"] is False
    assert waiting["error"]["code"] == "state_refresh_required"

    async with service.db.sessions() as session:
        after_events = len(
            (
                await session.scalars(
                    select(StateEventRecord).where(
                        StateEventRecord.run_id == "refresh-gate"
                    )
                )
            ).all()
        )
    assert after_events == before_events

    # The gate is scoped to one Challenge Agent.
    second_state = await second.dispatch("challenge_get_state", {})
    second_cycle = await second.dispatch(
        "challenge_begin_cycle",
        {
            "expected_challenge_version": second_state["data"]["challenge"]["version"]
        },
    )
    assert second_cycle["ok"] is True

    refreshed = await rebuilt.dispatch("challenge_get_state", {})
    assert refreshed["ok"] is True
    current_cycle = refreshed["data"]["recent_cycles"][0]
    wrong_phase = await rebuilt.dispatch(
        "challenge_submit_analysis_plan",
        {
            "cycle_id": current_cycle["cycle_id"],
            "expected_version": current_cycle["version"],
            "analysis_summary": "plan after the cycle already entered execute",
        },
    )
    assert wrong_phase["ok"] is False
    assert wrong_phase["error"]["code"] == "invalid_cycle_phase"
    assert wrong_phase["error"]["detail"]["current_status"] == "execute"
    assert "challenge_commit_cycle" in wrong_phase["error"]["detail"]["allowed_tools"]

    await rebuilt.dispatch("challenge_get_state", {})
    committed = await rebuilt.dispatch(
        "challenge_commit_cycle",
        {
            "cycle_id": current_cycle["cycle_id"],
            "expected_version": current_cycle["version"],
            "summary": "finish the empty test cycle",
            "outcome": "no_progress",
        },
    )
    assert committed["ok"] is True
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_completed_available_containers_are_released_before_chief_starts(
    tmp_path: Path,
) -> None:
    benchmark = _IncidentBenchmark()
    service = StateService(
        tmp_path / "runs" / "incident" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )

    chief_id = await supervisor.prepare_chief("coordinate", run_id="incident")
    overview = await service.get_overview("incident")
    states = {item["unique_code"]: item for item in overview["challenges"]}
    assert states["a-02"]["is_completed"] is True
    assert states["a-02"]["container_status"] == "stopped"
    assert states["a-02"]["slot_occupied"] is False
    assert states["a-15"]["container_status"] == "stopped"
    assert overview["container_capacity"] == {
        "limit": 3,
        "occupied_count": 1,
        "free_count": 2,
        "occupied_codes": ["a-03"],
        "completed_pending_release_codes": [],
    }
    close_calls = [
        arguments["unique_code"]
        for name, arguments in benchmark.calls
        if name == "benchmark_close_challenge"
    ]
    assert close_calls == ["a-02", "a-15"]
    events = await service.list_agent_events("incident", chief_id, limit=500)
    event_types = [item["event_type"] for item in events]
    assert event_types.count("completed_container_release_started") == 2
    assert event_types.count("completed_container_release_succeeded") == 2
    assert "container_capacity_reconciled" in event_types

    created = await supervisor.create_challenge_agent(chief_id, "a-16")
    assert created["ok"] is True
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_concurrent_refresh_closes_each_completed_container_once(
    tmp_path: Path,
) -> None:
    benchmark = _IncidentBenchmark()
    service = StateService(
        tmp_path / "runs" / "concurrent" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="concurrent")
    benchmark.calls.clear()
    target = next(
        item for item in benchmark.challenges if item["unique_code"] == "a-16"
    )
    target.update(
        is_completed=True,
        correct_flag_count=1,
        container_status="available",
    )

    await asyncio.gather(
        supervisor.refresh_challenges(chief_id),
        supervisor.refresh_challenges(chief_id),
    )
    assert [
        arguments["unique_code"]
        for name, arguments in benchmark.calls
        if name == "benchmark_close_challenge"
    ] == ["a-16"]
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_unconfirmed_release_remains_occupied_and_blocks_new_start(
    tmp_path: Path,
) -> None:
    benchmark = _IncidentBenchmark(reject_close=True)
    service = StateService(
        tmp_path / "runs" / "blocked" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="blocked")
    overview = await service.get_overview("blocked")
    assert overview["container_capacity"]["occupied_codes"] == [
        "a-02",
        "a-03",
        "a-15",
    ]
    denied = await supervisor.create_challenge_agent(chief_id, "a-16")
    assert denied["ok"] is False
    assert denied["error"]["code"] == "challenge_slots_exhausted"
    assert not any(
        name == "benchmark_start_challenge" and arguments.get("unique_code") == "a-16"
        for name, arguments in benchmark.calls
    )
    events = await service.list_agent_events("blocked", chief_id, limit=500)
    assert any(
        item["event_type"] == "completed_container_release_failed"
        for item in events
    )
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_stagnant_pause_releases_before_next_challenge_start(tmp_path: Path) -> None:
    benchmark = _FakeBenchmark()
    service = StateService(
        tmp_path / "runs" / "pause" / "state.sqlite3", run_root=tmp_path / "runs"
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="pause")
    created = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = created["data"]["agent_id"]
    async with service.db.sessions.begin() as session:
        row = await session.get(ChallengeRecord, ("pause", "task-1"))
        assert row is not None
        row.last_progress_at = row.started_at - timedelta(seconds=901)
        row.active_since = row.last_progress_at
        row.stagnation_level = 2
        row.work_status = "paused"

    paused = await supervisor.pause_stagnant_challenge(chief_id, "task-1")
    assert paused["ok"] is True
    assert paused["data"]["paused"] is True
    state = next(item for item in await service.list_challenges("pause") if item["unique_code"] == "task-1")
    assert state["work_status"] == "paused"
    assert state["container_status"] == "stopped"
    assert state["slot_occupied"] is False
    parent = next(item for item in (await service.get_overview("pause"))["agents"] if item["agent_id"] == challenge_id)
    assert parent["status"] == "stopped"
    operations = await service.list_operations("pause")
    assert [item["operation_type"] for item in operations] == ["benchmark_start_challenge", "benchmark_close_challenge"]
    events = await service.list_agent_events("pause", chief_id, limit=500)
    assert any(item["event_type"] == "stagnation_pause_started" for item in events)
    assert any(item["event_type"] == "stagnation_pause_succeeded" for item in events)

    next_challenge = await supervisor.create_challenge_agent(chief_id, "task-2")
    assert next_challenge["ok"] is True
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_stagnant_pause_failure_keeps_slot_and_rejects_switch(tmp_path: Path) -> None:
    benchmark = _IncidentBenchmark(reject_close=True)
    service = StateService(
        tmp_path / "runs" / "pause-failed" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="pause-failed")
    paused = await supervisor.pause_stagnant_challenge(chief_id, "a-03")
    assert paused["ok"] is True
    assert paused["data"]["paused"] is False
    state = next(item for item in await service.list_challenges("pause-failed") if item["unique_code"] == "a-03")
    assert state["work_status"] == "paused"
    assert state["slot_occupied"] is True
    denied = await supervisor.create_challenge_agent(chief_id, "a-16")
    assert denied["ok"] is False
    assert denied["error"]["code"] == "challenge_slots_exhausted"
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_warning_allows_parallel_validation_and_one_discovery_pivot(tmp_path: Path) -> None:
    service = StateService(
        tmp_path / "runs" / "explorer" / "state.sqlite3", run_root=tmp_path / "runs"
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="explorer")
    created = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = created["data"]["agent_id"]
    async with service.db.sessions.begin() as session:
        row = await session.get(ChallengeRecord, ("explorer", "task-1"))
        assert row is not None
        row.stagnation_level = 1
        row.work_status = "warning"
        row.hint_eligible = True

    observation = await service.record_observation(
        "explorer",
        "task-1",
        category="service",
        summary="HTTP entry point found",
        source="test",
        mark_progress=False,
    )
    evidence_ref = f"observation:{observation['observation_id']}"

    first_validation = await supervisor.create_execution_agent(
        challenge_id,
        "validate authorization behavior",
        hypothesis_key="authorization-validation",
        task_key="authorization-validation-1",
        task_stage="validation",
        context_refs=[evidence_ref],
    )
    assert first_validation["ok"] is True
    second_validation = await supervisor.create_execution_agent(
        challenge_id,
        "validate input behavior",
        hypothesis_key="input-validation",
        task_key="input-validation-1",
        task_stage="validation",
        context_refs=[evidence_ref],
    )
    assert second_validation["ok"] is True
    challenge_state = next(
        item for item in await service.list_challenges("explorer")
        if item["unique_code"] == "task-1"
    )
    assert challenge_state["warning_pivot_used"] is False

    missing_gap = await supervisor.create_execution_agent(
        challenge_id,
        "explore",
        hypothesis_key="missing-gap",
        task_key="missing-gap-1",
        task_stage="discovery",
        kind="exploration",
    )
    assert missing_gap["ok"] is False
    assert missing_gap["error"]["code"] == "warning_discovery_reference_required"
    failed_after_reservation = await supervisor.create_execution_agent(
        challenge_id,
        "pivot through an already active branch",
        hypothesis_key="failed-pivot",
        task_key="failed-pivot-1",
        task_stage="discovery",
        branch_key="authorization-validation:general",
        context_refs=["gap:failed-pivot"],
    )
    assert failed_after_reservation["ok"] is False
    assert failed_after_reservation["error"]["code"] == "branch_already_active"
    challenge_state = next(
        item for item in await service.list_challenges("explorer")
        if item["unique_code"] == "task-1"
    )
    assert challenge_state["warning_pivot_used"] is False
    first = await supervisor.create_execution_agent(
        challenge_id,
        "verify the unauthenticated document endpoint",
        hypothesis_key="authorization-boundary",
        task_key="authorization-boundary-1",
        task_stage="discovery",
        kind="exploration",
        context_refs=["gap:authorization-boundary"],
    )
    assert first["ok"] is True
    second = await supervisor.create_execution_agent(
        challenge_id,
        "verify a second direction",
        hypothesis_key="second-direction",
        task_key="second-direction-1",
        task_stage="discovery",
        kind="exploration",
        context_refs=["gap:second-direction"],
    )
    assert second["ok"] is False
    assert second["error"]["code"] == "warning_discovery_limit"
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_supervisor_enforces_slots_reports_and_plaintext_flag(tmp_path: Path) -> None:
    benchmark = _FakeBenchmark()
    service = StateService(
        tmp_path / "runs" / "run-one" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate the test run", run_id="run-one")
    chief = ChiefAgentTools(supervisor, agent_id=chief_id)

    first = await chief.dispatch("chief_create_challenge_agent", {"unique_code": "task-1"})
    assert first["ok"] is True
    challenge_id = first["data"]["agent_id"]
    challenge = ChallengeAgentTools(supervisor, agent_id=challenge_id, unique_code="task-1")
    await service.record_observation(
        "run-one",
        "task-1",
        category="domain_triage",
        summary="Challenge domain classified as other",
        detail={
            "domain": "other",
            "confidence": 0.9,
            "scanner_profile": "other_light",
        },
        source="test_domain_triage",
        confidence=0.9,
        mark_progress=False,
        route_branches=False,
    )

    execution = await challenge.dispatch(
        "challenge_create_execution_agent",
        {
            "mission": "inspect the service",
            "hypothesis_key": "service-inspection",
            "task_key": "service-inspection-1",
            "task_stage": "discovery",
            "timeout_seconds": 20,
        },
    )
    assert execution["ok"] is True
    execution_id = execution["data"]["agent_id"]
    execution_tools = ExecutionAgentTools(supervisor, agent_id=execution_id, unique_code="task-1")
    candidate = "flag{do-not-persist}"
    report = await execution_tools.dispatch(
        "execution_report",
        {
            "status": "completed",
            "summary": "found a candidate",
            "candidate_flag": candidate,
            "hypothesis_outcome": "inconclusive",
            "findings": [
                {
                    "category": "flag",
                    "summary": "candidate Flag extracted",
                    "detail": {"source": "test"},
                    "confidence": 1.0,
                    "verification_status": "candidate",
                    "evidence_paths": ["evidence/flag-candidate.txt"],
                }
            ],
        },
    )
    assert report["ok"] is True
    reports = await challenge.dispatch("challenge_get_execution_reports", {})
    assert reports["ok"] is True
    assert reports["data"]["reports"][0]["candidate_flag"] == candidate

    stored_report = (tmp_path / "runs" / "run-one" / "agents" / execution_id / "report.json").read_text()
    assert candidate in stored_report

    submitted = await challenge.dispatch("challenge_submit_flag", {"flag": candidate})
    assert submitted["ok"] is True
    root_events = (tmp_path / "runs" / "run-one" / "events.jsonl").read_text()
    assert candidate not in root_events
    assert supervisor.state_service is not None
    operations = await supervisor.state_service.list_operations("run-one")
    assert operations
    assert all(item["status"] == "completed" for item in operations)
    submitted_operation = next(
        item
        for item in operations
        if item["operation_type"] == "benchmark_submit_flag"
    )
    assert submitted_operation["request_payload"]["flag"] == candidate
    assert submitted_operation["result_payload"]["data"]["correct"] is True
    assert submitted_operation["started_sequence"] < submitted_operation["completed_sequence"]

    for code in ("task-2", "task-3"):
        result = await chief.dispatch("chief_create_challenge_agent", {"unique_code": code})
        assert result["ok"] is True
    denied = await chief.dispatch("chief_create_challenge_agent", {"unique_code": "task-4"})
    assert denied["ok"] is False
    assert denied["error"]["code"] == "challenge_slots_exhausted"

    invalid = await challenge.dispatch(
        "challenge_create_execution_agent",
        {"mission": "x", "unexpected": True},
    )
    assert invalid["ok"] is False
    assert invalid["error"]["type"] == "validation"

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_multiple_flag_submission_requires_remote_completion(
    tmp_path: Path,
) -> None:
    benchmark = _TwoFlagBenchmark()
    service = StateService(
        tmp_path / "runs" / "multi-flag" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="multi-flag")
    created = await supervisor.create_challenge_agent(chief_id, "multi-flag")
    challenge_id = created["data"]["agent_id"]
    challenge = ChallengeAgentTools(
        supervisor,
        agent_id=challenge_id,
        unique_code="multi-flag",
    )

    first_status = await challenge.dispatch(
        "challenge_report_status",
        {"status": "completed", "summary": "one Flag was accepted"},
    )
    assert first_status["ok"] is False
    assert first_status["error"]["code"] == "challenge_not_completed"

    first = await challenge.dispatch(
        "challenge_submit_flag", {"flag": "candidate-one"}
    )
    assert first["ok"] is True
    overview = await service.get_overview("multi-flag")
    state = overview["challenges"][0]
    assert state["correct_flag_count"] == 1
    assert state["is_completed"] is False
    assert state["work_status"] == "active"

    second = await challenge.dispatch(
        "challenge_submit_flag", {"flag": "candidate-two"}
    )
    assert second["ok"] is True
    overview = await service.get_overview("multi-flag")
    state = overview["challenges"][0]
    assert state["correct_flag_count"] == 2
    assert state["is_completed"] is True
    assert state["work_status"] == "completed"
    assert state["container_status"] == "stopped"
    assert state["slot_occupied"] is False
    assert second["data"]["container_release"]["released"] is True
    operations = await service.list_operations("multi-flag")
    assert [item["operation_type"] for item in operations].count(
        "benchmark_submit_flag"
    ) == 2
    assert [item["operation_type"] for item in operations].count(
        "benchmark_close_challenge"
    ) == 1

    final_status = await challenge.dispatch(
        "challenge_report_status",
        {"status": "completed", "summary": "all Flags were accepted"},
    )
    assert final_status["ok"] is True
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_failed_execution_report_contains_safe_reason_and_advances_parent_cursor(
    tmp_path: Path,
) -> None:
    service = StateService(
        tmp_path / "runs" / "run-failure" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="run-failure")
    challenge_result = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = challenge_result["data"]["agent_id"]
    execution_result = await supervisor.create_execution_agent(
        challenge_id,
        "inspect the service",
        hypothesis_key="service-inspection-failure",
        task_key="service-inspection-failure-1",
        task_stage="discovery",
    )
    execution_id = execution_result["data"]["agent_id"]

    await supervisor._finalize_missing_report(
        execution_id,
        failure_code="llm_request_failed",
        failure_message="LLM request failed",
    )

    challenge = ChallengeAgentTools(
        supervisor,
        agent_id=challenge_id,
        unique_code="task-1",
    )
    reports = await challenge.dispatch("challenge_get_execution_reports", {})
    assert reports["ok"] is True
    assert reports["data"]["reports"][0]["failure_code"] == "llm_request_failed"
    overview = await service.get_overview("run-failure")
    parent = next(item for item in overview["agents"] if item["agent_id"] == challenge_id)
    assert parent["report_cursors"]["execution"] == reports["data"]["next_sequence"]
    failure_events = await service.list_agent_events("run-failure", execution_id)
    assert any(
        event["event_type"] == "agent_report" for event in failure_events
    )

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_challenge_controller_waits_and_consumes_each_sequence_once(
    tmp_path: Path,
) -> None:
    _YieldingControllerRunner.calls.clear()
    service = StateService(
        tmp_path / "runs" / "run-controller" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_YieldingControllerRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="run-controller")
    challenge_result = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = challenge_result["data"]["agent_id"]

    for _ in range(100):
        overview = await service.get_overview("run-controller")
        parent = next(
            item for item in overview["agents"] if item["agent_id"] == challenge_id
        )
        if parent["status"] == "waiting":
            break
        await asyncio.sleep(0.001)
    assert parent["status"] == "waiting"
    assert _YieldingControllerRunner.calls[challenge_id] == 1
    await asyncio.sleep(0.01)
    assert _YieldingControllerRunner.calls[challenge_id] == 1

    execution = await service.register_agent(
        "run-controller",
        role="execution",
        parent_id=challenge_id,
        unique_code="task-1",
        hypothesis_key="controller-report",
        task_key="controller-report-1",
        task_stage="discovery",
        mission="report fixture",
    )
    report = await service.publish_control_report(
        "run-controller",
        sender_id=execution["agent_id"],
        recipient_id=challenge_id,
        unique_code="task-1",
        report_type="execution",
        status="completed",
        payload={"summary": "one durable report"},
    )

    for _ in range(100):
        overview = await service.get_overview("run-controller")
        parent = next(
            item for item in overview["agents"] if item["agent_id"] == challenge_id
        )
        if (
            parent["status"] == "waiting"
            and parent["controller_cursor"] == report["sequence"]
            and _YieldingControllerRunner.calls.get(challenge_id) == 2
        ):
            break
        await asyncio.sleep(0.001)
    assert parent["controller_cursor"] == report["sequence"]
    assert _YieldingControllerRunner.calls[challenge_id] == 2

    await service.notifier.notify(
        service.agent_signal_key("run-controller", challenge_id),
        report["sequence"],
    )
    await asyncio.sleep(0.01)
    assert _YieldingControllerRunner.calls[challenge_id] == 2

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_remote_completion_finishes_waiting_challenge_without_restart(
    tmp_path: Path,
) -> None:
    _YieldingControllerRunner.calls.clear()
    service = StateService(
        tmp_path / "runs" / "run-remote-complete" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    benchmark = _FakeBenchmark()
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_YieldingControllerRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief(
        "coordinate", run_id="run-remote-complete"
    )
    created = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = created["data"]["agent_id"]
    for _ in range(100):
        overview = await service.get_overview("run-remote-complete")
        controller = next(
            item for item in overview["agents"] if item["agent_id"] == challenge_id
        )
        if controller["status"] == "waiting":
            break
        await asyncio.sleep(0.001)
    assert controller["status"] == "waiting"
    assert _YieldingControllerRunner.calls[challenge_id] == 1

    remote = dict(benchmark.challenges[0])
    remote.update(
        {
            "is_completed": True,
            "correct_flag_count": 1,
            "container_status": "running",
        }
    )
    await service.import_challenges("run-remote-complete", [remote])
    for _ in range(100):
        overview = await service.get_overview("run-remote-complete")
        controller = next(
            item for item in overview["agents"] if item["agent_id"] == challenge_id
        )
        if controller["status"] == "completed":
            break
        await asyncio.sleep(0.001)
    assert controller["status"] == "completed"
    assert _YieldingControllerRunner.calls[challenge_id] == 1

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_chief_natural_reply_waits_without_finishing_run(tmp_path: Path) -> None:
    _YieldingChiefRunner.calls = 0
    service = StateService(
        tmp_path / "runs" / "run-chief-wait" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_YieldingChiefRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief(
        "coordinate", run_id="run-chief-wait"
    )

    for _ in range(100):
        overview = await service.get_overview("run-chief-wait")
        chief = next(
            item for item in overview["agents"] if item["agent_id"] == chief_id
        )
        if chief["status"] == "waiting":
            break
        await asyncio.sleep(0.001)
    assert chief["status"] == "waiting"
    assert overview["run"]["status"] == "active"
    assert _YieldingChiefRunner.calls == 1
    await asyncio.sleep(0.01)
    assert _YieldingChiefRunner.calls == 1

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_execution_without_structured_report_has_one_failed_terminal_state(
    tmp_path: Path,
) -> None:
    service = StateService(
        tmp_path / "runs" / "run-missing-report" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=_FakeBenchmark(),
        run_root=tmp_path / "runs",
        runner_factory=_MissingReportRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief(
        "coordinate", run_id="run-missing-report"
    )
    challenge = await supervisor.create_challenge_agent(chief_id, "task-1")
    challenge_id = challenge["data"]["agent_id"]
    execution = await supervisor.create_execution_agent(
        challenge_id,
        "return without a report",
        hypothesis_key="missing-report",
        task_key="missing-report-1",
        task_stage="discovery",
    )
    execution_id = execution["data"]["agent_id"]
    await supervisor.launch_execution_agent(execution_id)
    await supervisor.wait_agent(execution_id)

    overview = await service.get_overview("run-missing-report")
    worker = next(
        item for item in overview["agents"] if item["agent_id"] == execution_id
    )
    assert worker["status"] == "failed"
    reports = await supervisor.get_execution_reports(challenge_id)
    assert reports["data"]["reports"][0]["failure_code"] == (
        "missing_structured_report"
    )
    events = await service.list_agent_events(
        "run-missing-report", execution_id, limit=100
    )
    assert [item["event_type"] for item in events].count(
        "agent_execution_failed"
    ) == 1
    assert [item["event_type"] for item in events].count("agent_report") == 1

    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_resume_rejects_legacy_recovery_state(
    tmp_path: Path,
) -> None:
    benchmark = _FakeBenchmark()
    service = StateService(
        tmp_path / "runs" / "run-recovery" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="run-recovery")
    created = await supervisor.create_challenge_agent(chief_id, "task-1")
    assert created["ok"] is True
    async with service.db.sessions.begin() as session:
        challenge = await session.scalar(
            select(ChallengeRecord).where(
                ChallengeRecord.run_id == "run-recovery",
                ChallengeRecord.unique_code == "task-1",
            )
        )
        assert challenge is not None
        challenge.work_status = "recovery"
    await supervisor.close()
    await service.close()

    resumed_service = StateService(
        tmp_path / "runs" / "run-recovery" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    resumed = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=resumed_service,
    )
    with pytest.raises(SubagentError, match="legacy recovery state"):
        await resumed.prepare_chief("", run_id="run-recovery", resume=True)
    await resumed.close()
    await resumed_service.close()


@pytest.mark.asyncio
async def test_hint_is_chief_only_and_status_mailbox_is_structured(tmp_path: Path) -> None:
    benchmark = _FakeBenchmark()
    service = StateService(
        tmp_path / "runs" / "run-hint" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    supervisor = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        state_service=service,
    )
    chief_id = await supervisor.prepare_chief("coordinate", run_id="run-hint")
    chief = ChiefAgentTools(supervisor, agent_id=chief_id)
    created = await chief.dispatch("chief_create_challenge_agent", {"unique_code": "task-1"})
    challenge_id = created["data"]["agent_id"]
    challenge = ChallengeAgentTools(supervisor, agent_id=challenge_id, unique_code="task-1")

    status = await challenge.dispatch(
        "challenge_report_status",
        {
            "status": "analyzing",
            "summary": "Collected a concrete blocker reference",
        },
    )
    assert status["ok"] is True
    prior_report = await service.latest_control_report(
        "run-hint", recipient_id=chief_id, report_type="challenge_status"
    )
    assert prior_report is not None
    async with service.db.sessions.begin() as session:
        row = await session.get(ChallengeRecord, ("run-hint", "task-1"))
        assert row is not None
        row.work_status = "warning"
        row.stagnation_level = 1
        row.hint_eligible = True
        row.control_since = row.active_since
    chief_reports = await chief.dispatch("chief_get_challenge_reports", {})
    assert chief_reports["data"]["reports"][0]["status"] == "analyzing"

    status = await challenge.dispatch(
        "challenge_report_status",
        {
            "status": "ready_for_hint",
            "summary": "Need more direction",
            "hint_recommended": True,
            "blocker": "The final path remains unverified",
            "evidence_refs": [f"report:{prior_report['report_id']}"],
        },
    )
    assert status["ok"] is True

    hint = await chief.dispatch(
        "chief_request_hint",
        {
            "unique_code": "task-1",
            "basis": "high_probability_path",
            "evidence_refs": [f"report:{prior_report['report_id']}"],
            "reason": "execution agents are blocked",
        },
    )
    assert hint["ok"] is True
    reused = await chief.dispatch(
        "chief_request_hint",
        {
            "unique_code": "task-1",
            "basis": "high_probability_path",
            "evidence_refs": [f"report:{prior_report['report_id']}"],
            "reason": "check the same persisted hint",
        },
    )
    assert reused["ok"] is True
    assert reused["data"]["reused"] is True
    assert [name for name, _ in benchmark.calls].count("benchmark_get_hint") == 1
    challenge_updates = await challenge.dispatch("challenge_get_updates", {})
    assert challenge_updates["data"]["count"] == 1
    assert challenge_updates["data"]["updates"][0]["type"] == "hint_received"

    forbidden = await challenge.dispatch("chief_request_hint", {"unique_code": "task-1", "reason": "no"})
    assert forbidden["ok"] is False
    assert forbidden["error"]["code"] == "unknown_tool"
    assert json.dumps(hint)
    await supervisor.close()
    await service.close()


@pytest.mark.asyncio
async def test_resume_marks_unfinished_state_operation_without_retrying(tmp_path: Path) -> None:
    benchmark = _FakeBenchmark()
    first_service = StateService(
        tmp_path / "runs" / "run-resume" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    first = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=first_service,
    )
    chief_id = await first.prepare_chief("coordinate", run_id="run-resume")
    assert first.state_service is not None
    actual_operation_id = await first.state_service.mark_operation_started(
        "run-resume",
        "benchmark_start_challenge",
        agent_id=chief_id,
        unique_code="task-1",
        arguments={"unique_code": "task-1"},
    )
    await first.close()
    assert chief_id
    await first_service.close()

    benchmark.calls.clear()
    second_service = StateService(
        tmp_path / "runs" / "run-resume" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    second = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=second_service,
    )
    recovered = await second.resume("run-resume")
    assert recovered["ok"] is True
    assert any(
        item["operation_id"] == actual_operation_id
        for item in recovered["data"]["indeterminate_operations"]
    )
    assert [name for name, _ in benchmark.calls] == ["benchmark_list_challenges"]
    await second.close()
    await second_service.close()


@pytest.mark.asyncio
async def test_resume_restarts_stopped_challenge_agent_for_unfinished_challenge(
    tmp_path: Path,
) -> None:
    benchmark = _FakeBenchmark()
    first_service = StateService(
        tmp_path / "runs" / "run-challenge-resume" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    first = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=first_service,
    )
    chief_id = await first.prepare_chief("coordinate", run_id="run-challenge-resume")
    created = await first.create_challenge_agent(chief_id, "task-1")
    challenge_id = created["data"]["agent_id"]
    await first.close()

    stopped = await first_service.get_overview("run-challenge-resume")
    stopped_agent = next(
        item for item in stopped["agents"] if item["agent_id"] == challenge_id
    )
    assert stopped_agent["status"] == "stopped"
    challenge = next(
        item for item in stopped["challenges"] if item["unique_code"] == "task-1"
    )
    assert challenge["is_completed"] is False
    assert challenge["container_status"] == "running"

    await first_service.close()
    benchmark.calls.clear()
    second_service = StateService(
        tmp_path / "runs" / "run-challenge-resume" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    second = AgentSupervisor(
        _settings(),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        runner_factory=_FakeRunner,
        catalog_reconcile_interval_seconds=0,
        state_service=second_service,
    )
    await second.prepare_chief("", run_id="run-challenge-resume", resume=True)

    resumed = await second_service.get_overview("run-challenge-resume")
    resumed_agent = next(
        item for item in resumed["agents"] if item["agent_id"] == challenge_id
    )
    assert resumed_agent["status"] == "running"
    assert [name for name, _ in benchmark.calls] == ["benchmark_list_challenges"]
    events = await second_service.list_agent_events(
        "run-challenge-resume", challenge_id
    )
    assert any(event["event_type"] == "challenge_agent_restarted" for event in events)

    await second.close()
    await second_service.close()
