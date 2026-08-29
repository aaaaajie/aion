from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent.config import AgentSettings
from agent.runner import ToolRegistry
from agent.memory.context import request_token_count, rough_token_count
from agent.state.database import StateDatabase
from agent.state.models import ChallengeRecord
from agent.state.schemas import ChallengeImport
from agent.state.service import StateService
from agent.prompts import system_prompt
from agent.subagents.supervisor import AgentSupervisor
from agent.subagents.policy import AgentPolicy
from agent.subagents.tools import ChallengeAgentTools, ChiefAgentTools, ExecutionAgentTools
from agent.tooling import ToolDispatchOutcome
from tests.benchmark_tools import benchmark_tool_specs


def test_supervisor_resolves_toolchain_independently_of_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    configured_toolchain = tmp_path / "image" / "tools" / "binaries"
    configured_toolchain.mkdir(parents=True)
    monkeypatch.setenv("AION_TOOLCHAIN_ROOT", str(configured_toolchain))
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
    )

    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        project_root=workspace,
        run_root=tmp_path / "runs",
        state_service=service,
    )

    assert supervisor.project_root == workspace.resolve()
    assert supervisor.toolchain_root == configured_toolchain.resolve()


class SupervisorStub:
    async def observe_chief(self, agent_id: str, *, max_reports: int) -> dict[str, Any]:
        return {"ok": True, "data": {"agent_id": agent_id, "max_reports": max_reports}}

    async def launch_challenges(self, agent_id: str, values: list[str]) -> dict[str, Any]:
        return {"ok": True, "data": {"values": values}}

    async def wait_chief(self, agent_id: str, *, reason: str | None) -> ToolDispatchOutcome:
        return ToolDispatchOutcome({"ok": True, "data": {"reason": reason}}, True)

    async def request_hint_light(self, agent_id: str, code: str, reason: str) -> dict[str, Any]:
        return {"ok": True, "data": {"unique_code": code, "reason": reason}}

    async def observe_challenge(self, agent_id: str, *, max_reports: int) -> dict[str, Any]:
        return {"ok": True, "data": {"max_reports": max_reports}}

    async def dispatch_challenge(self, agent_id: str, payload: Any) -> dict[str, Any]:
        return {"ok": True, "data": payload.model_dump(mode="json"), "warnings": []}

    async def wait_for_state(self, agent_id: str, reason: str | None) -> ToolDispatchOutcome:
        return ToolDispatchOutcome({"ok": True, "data": {"reason": reason}}, True)

    async def submit_flag(self, agent_id: str, flag: str) -> dict[str, Any]:
        return {"ok": True, "data": {"accepted": bool(flag)}}

    async def close_challenge(self, agent_id: str) -> dict[str, Any]:
        return {"ok": True, "data": {"closed": True}}

    async def report_execution_payload(self, agent_id: str, payload: Any) -> dict[str, Any]:
        return {"ok": True, "data": {"terminal": True}, "warnings": []}

    async def read_evidence(self, agent_id: str, evidence_ref: str, **_: Any) -> dict[str, Any]:
        return {"ok": True, "data": {"evidence_ref": evidence_ref}}


def names(provider: Any, role: str) -> set[str]:
    return {
        item["function"]["name"]
        for item in ToolRegistry(
            [provider], allowed_tools=AgentPolicy(role).allowed_tools
        ).definitions()
    }


def test_lightweight_role_surfaces_are_fixed() -> None:
    supervisor = SupervisorStub()
    assert names(ChiefAgentTools(supervisor, agent_id="chief"), "chief") == {
        "chief_observe",
        "chief_launch_challenges",
        "chief_wait",
        "chief_request_hint",
    }
    assert names(
        ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c"),
        "challenge",
    ) == {
        "challenge_observe",
        "challenge_dispatch",
        "challenge_request_secondary_bootstrap",
        "challenge_wait",
        "challenge_submit_flag",
        "challenge_close",
        "evidence_read",
    }
    assert names(
        ExecutionAgentTools(supervisor, agent_id="execution", unique_code="c"),
        "execution",
    ) == {"execution_report", "execution_checkpoint", "evidence_read"}
    assert names(
        ExecutionAgentTools(
            supervisor,
            agent_id="bootstrap",
            unique_code="c",
            bootstrap_mode=True,
        ),
        "execution",
    ) == {
        "execution_report",
        "bootstrap_checkpoint",
        "bootstrap_cycle_yield",
        "evidence_read",
    }
    assert len(AgentPolicy("execution").allowed_tools) <= 64


@pytest.mark.asyncio
async def test_dispatch_requires_only_summary_and_task_objective() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c")],
        allowed_tools=AgentPolicy("challenge").allowed_tools,
    )
    spec = registry.get("challenge_dispatch")
    assert spec is not None
    arguments = spec.input_model.model_validate(
        {"summary": "decide now", "tasks": [{"objective": "probe one surface"}]}
    )
    outcome = await spec.handler(arguments)
    assert isinstance(outcome, ToolDispatchOutcome)
    assert outcome.yield_session is True
    result = outcome.result
    assert result["ok"] is True
    assert result["data"]["tasks"][0]["task_stage"] == "discovery"


@pytest.mark.asyncio
async def test_empty_dispatch_object_is_valid_for_runtime_followups() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c")],
        allowed_tools=AgentPolicy("challenge").allowed_tools,
    )
    spec = registry.get("challenge_dispatch")
    assert spec is not None
    arguments = spec.input_model.model_validate({})
    assert arguments.summary == "runtime state update"
    assert spec.input_model.model_validate({"tasks": None}).tasks is None


@pytest.mark.asyncio
async def test_dispatch_normalizes_optional_task_metadata_without_rejecting_decision() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c")],
        allowed_tools=AgentPolicy("challenge").allowed_tools,
    )
    spec = registry.get("challenge_dispatch")
    assert spec is not None
    arguments = spec.input_model.model_validate(
        {
            "summary": "act on the report",
            "tasks": [
                {
                    "objective": "probe one surface",
                    "kind": "http",
                    "task_stage": "initial",
                    "priority": "urgent",
                    "hypothesis_key2": "ignored",
                },
                {"kind": "web"},
            ],
        }
    )
    outcome = await spec.handler(arguments)
    assert isinstance(outcome, ToolDispatchOutcome)
    assert outcome.yield_session is True
    assert outcome.result["data"]["tasks"] == [
        {
            "objective": "probe one surface",
            "task_key": None,
            "hypothesis_key": None,
            "branch_key": None,
            "kind": "general",
            "task_stage": "discovery",
            "priority": 50,
            "success_criteria": [],
            "context_refs": [],
            "timeout_seconds": 1800,
        }
    ]
    assert {item["code"] for item in outcome.result["warnings"]} == {
        "task_fields_normalized",
        "invalid_task_dropped",
    }


@pytest.mark.asyncio
async def test_dispatch_with_only_invalid_tasks_keeps_session_for_correction() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c")],
        allowed_tools=AgentPolicy("challenge").allowed_tools,
    )
    spec = registry.get("challenge_dispatch")
    assert spec is not None
    arguments = spec.input_model.model_validate(
        {"summary": "invalid task", "tasks": [{"kind": "web"}]}
    )
    outcome = await spec.handler(arguments)
    assert isinstance(outcome, ToolDispatchOutcome)
    assert outcome.yield_session is False
    assert outcome.result["ok"] is True


@pytest.mark.asyncio
async def test_dispatch_enforces_stage_timeout_floors() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ChallengeAgentTools(supervisor, agent_id="challenge", unique_code="c")],
        allowed_tools=AgentPolicy("challenge").allowed_tools,
    )
    spec = registry.get("challenge_dispatch")
    assert spec is not None
    arguments = spec.input_model.model_validate(
        {
            "summary": "use deterministic stage budgets",
            "tasks": [
                {
                    "objective": "collect a bounded baseline",
                    "task_stage": "discovery",
                    "timeout_seconds": 1,
                },
                {
                    "objective": "validate the observed result",
                    "task_stage": "validation",
                    "timeout_seconds": 1,
                },
            ],
        }
    )
    outcome = await spec.handler(arguments)
    assert outcome.result["ok"] is True
    assert [
        item["timeout_seconds"] for item in outcome.result["data"]["tasks"]
    ] == [900, 1800]


class _FlagLifecycleBenchmark:
    def __init__(self) -> None:
        self.close_calls = 0

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "benchmark_submit_flag":
            return {
                "ok": True,
                "data": {
                    "correct": True,
                    "correct_flag_count": 2,
                    "total_flag_count": 2,
                    "awarded": 50,
                },
            }
        if name == "benchmark_close_challenge":
            self.close_calls += 1
            return {"ok": True, "data": {"closed": True}}
        if name == "benchmark_list_challenges":
            return {
                "ok": True,
                "data": [
                    {
                        "unique_code": "challenge-a",
                        "description": "test challenge",
                        "difficulty": "unknown",
                        "level": 0,
                        "total_score": 100,
                        "flag_count": 2,
                        "correct_flag_count": 2,
                        "is_completed": True,
                        "container_status": "stopped",
                        "container_addr": [],
                    }
                ],
            }
        raise AssertionError(name)

    def tool_specs(self):
        return benchmark_tool_specs(self.dispatch)


class _TransientReleaseBenchmark:
    def __init__(self) -> None:
        self.close_calls = 0

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "benchmark_close_challenge":
            self.close_calls += 1
            if self.close_calls == 1:
                return {
                    "ok": False,
                    "error": {
                        "stage": "execution",
                        "code": "service_unavailable",
                        "message": "temporary service response",
                        "details": {"status_code": 503},
                        "retry": {
                            "allowed": True,
                            "action": "retry",
                            "tool": "benchmark_close_challenge",
                            "same_arguments": False,
                        },
                    },
                }
            return {"ok": True, "data": {"closed": True}}
        if name == "benchmark_list_challenges":
            return {
                "ok": True,
                "data": [
                    {
                        "unique_code": "challenge-a",
                        "description": "test challenge",
                        "difficulty": "unknown",
                        "level": 0,
                        "total_score": 100,
                        "flag_count": 1,
                        "correct_flag_count": 1,
                        "is_completed": True,
                        "container_status": (
                            "stopped" if self.close_calls >= 2 else "running"
                        ),
                        "container_addr": [],
                    }
                ],
            }
        raise AssertionError(name)

    def tool_specs(self):
        return benchmark_tool_specs(self.dispatch)


class _PausedReleaseBenchmark:
    def __init__(self, *, transient_failures: int) -> None:
        self.transient_failures = transient_failures
        self.close_calls = 0

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "benchmark_close_challenge":
            self.close_calls += 1
            if self.close_calls <= self.transient_failures:
                return {
                    "ok": False,
                    "error": {
                        "stage": "execution",
                        "code": "service_unavailable",
                        "message": "temporary service response",
                        "details": {"status_code": 503},
                        "retry": {
                            "allowed": True,
                            "action": "retry",
                            "tool": "benchmark_close_challenge",
                            "same_arguments": False,
                        },
                    },
                }
            return {"ok": True, "data": {"closed": True}}
        if name == "benchmark_list_challenges":
            released = self.close_calls > self.transient_failures
            return {
                "ok": True,
                "data": [
                    {
                        "unique_code": "challenge-a",
                        "description": "test challenge",
                        "difficulty": "unknown",
                        "level": 0,
                        "total_score": 100,
                        "flag_count": 1,
                        "correct_flag_count": 0,
                        "is_completed": False,
                        "container_status": "stopped" if released else "running",
                        "container_addr": [],
                    }
                ],
            }
        raise AssertionError(name)

    def tool_specs(self):
        return benchmark_tool_specs(self.dispatch)


@pytest.mark.asyncio
async def test_final_flag_returns_before_submitter_is_stopped_and_releases_container(
    tmp_path: Any,
) -> None:
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
                description="test challenge",
                flag_count=2,
                correct_flag_count=1,
                container_status="running",
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    await service.register_agent(
        "run",
        agent_id="challenge",
        role="challenge",
        parent_id="chief",
        unique_code="challenge-a",
        initial_prompt="challenge",
    )
    await service.register_agent(
        "run",
        agent_id="execution-child",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="child",
    )
    benchmark = _FlagLifecycleBenchmark()
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    supervisor.run_id = "run"
    supervisor.chief_agent_id = "chief"
    await supervisor._sync_nodes()
    supervisor._issue_capabilities()

    result = await supervisor.submit_flag("challenge", "flag{final}")
    assert result["ok"] is True
    assert result["data"]["challenge_completed"] is True
    assert result["data"]["container_release_status"] == "pending"

    challenge_runtime = await service.get_agent_runtime("run", "challenge")
    assert challenge_runtime["agent"]["status"] not in supervisor.TERMINAL_AGENT_STATES

    completion = supervisor._challenge_completion_tasks["challenge-a"]
    await completion
    overview = await service.get_overview("run")
    challenge = next(
        item for item in overview["challenges"] if item["unique_code"] == "challenge-a"
    )
    child = next(item for item in overview["agents"] if item["agent_id"] == "execution-child")
    assert challenge["is_completed"] is True
    assert challenge["slot_occupied"] is False
    assert child["status"] in supervisor.TERMINAL_AGENT_STATES
    assert benchmark.close_calls == 1
    await service.close()


@pytest.mark.asyncio
async def test_completed_container_release_retries_transient_close_failure(
    tmp_path: Any,
) -> None:
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
                description="test challenge",
                flag_count=1,
                correct_flag_count=1,
                is_completed=True,
                container_status="running",
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    benchmark = _TransientReleaseBenchmark()
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    supervisor.run_id = "run"
    supervisor.chief_agent_id = "chief"

    result = await supervisor._release_completed_container(
        "chief", "challenge-a", reason="test_retry"
    )
    assert result["released"] is True
    assert result["attempts"] == 2
    assert benchmark.close_calls == 2
    challenge = next(
        item
        for item in await service.list_challenges("run")
        if item["unique_code"] == "challenge-a"
    )
    assert challenge["slot_occupied"] is False
    await service.close()


@pytest.mark.parametrize(
    ("transient_failures", "released", "expected_attempts", "expected_delays"),
    [
        (1, True, 2, [0.5]),
        (3, False, 3, [0.5, 1.0]),
    ],
)
@pytest.mark.asyncio
async def test_paused_container_release_converges_with_bounded_retries(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    transient_failures: int,
    released: bool,
    expected_attempts: int,
    expected_delays: list[float],
) -> None:
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
                description="test challenge",
                container_status="running",
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run", "challenge-a"))
        assert challenge is not None
        challenge.work_status = "paused"
        challenge.pause_reason = "stagnation_timeout"

    benchmark = _PausedReleaseBenchmark(transient_failures=transient_failures)
    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        benchmark=benchmark,
        run_root=tmp_path / "runs",
        catalog_reconcile_interval_seconds=0,
        state_service=service,
    )
    supervisor.run_id = "run"
    supervisor.chief_agent_id = "chief"
    delays: list[float] = []

    async def record_delay(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr("agent.subagents.supervisor.asyncio.sleep", record_delay)
    result = await supervisor.release_paused_container(
        "challenge-a", caller_id="chief"
    )

    assert result["released"] is released
    assert result["attempts"] == expected_attempts
    assert result["retry_exhausted"] is (not released)
    assert benchmark.close_calls == expected_attempts
    assert delays == expected_delays
    challenge = next(
        item
        for item in await service.list_challenges("run")
        if item["unique_code"] == "challenge-a"
    )
    assert challenge["work_status"] == "paused"
    assert challenge["slot_occupied"] is (not released)
    await service.close()


@pytest.mark.asyncio
async def test_paused_challenge_stops_controller_bootstrap_and_execution(
    tmp_path: Any,
) -> None:
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
                description="test challenge",
                container_status="running",
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    await service.start_challenge("run", "challenge-a")
    created = await service.register_challenge_workgroup(
        "run",
        challenge_agent_id="challenge",
        bootstrap_agent_id="bootstrap",
        parent_id="chief",
        unique_code="challenge-a",
        challenge_prompt="challenge",
        bootstrap_prompt="bootstrap",
    )
    await service.register_agent(
        "run",
        agent_id="execution-child",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="bounded work",
    )
    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run", "challenge-a"))
        assert challenge is not None
        challenge.work_status = "paused"
        challenge.pause_reason = "stagnation_timeout"

    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://llm.test",
            llm_model="test-model",
            llm_api_key="test-key",
        ),
        run_root=tmp_path / "runs",
        state_service=service,
    )
    supervisor.run_id = "run"
    supervisor.chief_agent_id = "chief"
    await supervisor.stop_challenge_work(
        "challenge-a", reason="stagnation_timeout"
    )

    overview = await service.get_overview("run")
    owned = [
        item
        for item in overview["agents"]
        if item.get("unique_code") == "challenge-a"
    ]
    bootstrap_ids = {
        item["agent_id"] for item in created["bootstraps"]
    }
    initial_ids = {
        item["agent_id"] for item in created["initial_executions"]
    }
    assert {item["agent_id"] for item in owned} == {
        "challenge",
        "execution-child",
        *bootstrap_ids,
        *initial_ids,
    }
    assert all(item["status"] in supervisor.TERMINAL_AGENT_STATES for item in owned)
    assert created["bootstrap"]["agent_id"] == "bootstrap"
    ensured = await service.ensure_bootstrap_for_challenge(
        "run",
        "challenge-a",
        parent_id="challenge",
        bootstrap_prompt="must-not-start",
    )
    assert ensured["enabled"] is False
    assert ensured["reason"] == "challenge_stopped"
    await service.close()


@pytest.mark.asyncio
async def test_interrupt_execution_agents_builds_strict_terminal_report(
    tmp_path: Any,
) -> None:
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
                description="test challenge",
                container_status="running",
            )
        ],
    )
    await service.register_agent(
        "run", agent_id="chief", role="chief", initial_prompt="chief"
    )
    await service.register_agent(
        "run",
        agent_id="challenge",
        role="challenge",
        parent_id="chief",
        unique_code="challenge-a",
        initial_prompt="challenge",
    )
    await service.register_agent(
        "run",
        agent_id="execution-child",
        role="execution",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="child",
    )

    interrupted = await service.interrupt_execution_agents("run")

    assert interrupted == ["execution-child"]
    runtime = await service.get_agent_runtime("run", "execution-child")
    assert runtime["agent"]["status"] == "interrupted"
    assert runtime["agent"]["final_report"]["status"] == "cancelled"
    await service.close()


def test_terminal_report_schema_keeps_optional_items_best_effort() -> None:
    supervisor = SupervisorStub()
    registry = ToolRegistry(
        [ExecutionAgentTools(supervisor, agent_id="execution", unique_code="c")],
        allowed_tools=AgentPolicy("execution").allowed_tools,
    )
    spec = registry.get("execution_report")
    assert spec is not None
    parsed = spec.input_model.model_validate(
        {
            "status": "completed",
            "summary": "done",
            "hypothesis_outcome": "provider-specific-value",
            "findings": [{"malformed": True}],
            "evidence_refs": [1, "bad"],
        }
    )
    assert parsed.status == "completed"


def test_chief_catalog_projection_is_compact_at_cloud_scale() -> None:
    projected = [
        AgentSupervisor._compact_challenge_for_chief(
            {
                "unique_code": f"c-{index:02d}",
                "name": f"Challenge {index}",
                "description": "d" * 4_000,
                "difficulty": "hard",
                "total_score": 500,
                "flag_count": 1,
                "correct_flag_count": 0,
                "is_completed": False,
                "work_status": "unassigned",
                "container_status": "stopped",
                "direction": None,
                "internal_field": "must not be exposed",
            }
        )
        for index in range(63)
    ]
    assert all(len(item["description"]) == 500 for item in projected)
    assert all("internal_field" not in item for item in projected)
    assert rough_token_count(projected) < 20_000
    tools = ToolRegistry(
        [ChiefAgentTools(SupervisorStub(), agent_id="chief")],
        allowed_tools=AgentPolicy("chief").allowed_tools,
    ).definitions()
    assert request_token_count(
        [
            {"role": "system", "content": system_prompt("chief")},
            {
                "role": "user",
                "content": str(
                    {
                        "run": {"status": "active", "phase": "middle"},
                        "capacity": {"limit": 3, "free_count": 3},
                        "challenges": projected,
                        "active_agents": [],
                        "reports": [],
                    }
                ),
            },
        ],
        tools,
    ) < 40_000
