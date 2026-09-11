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
from agent.subagents.tools import AgentControlTools
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

    async def launch_challenges(
        self, agent_id: str, values: list[str]
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"values": values}}

    async def wait_chief(
        self, agent_id: str, *, reason: str | None
    ) -> ToolDispatchOutcome:
        return ToolDispatchOutcome({"ok": True, "data": {"reason": reason}}, True)

    async def request_hint_light(
        self, agent_id: str, code: str, reason: str
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"unique_code": code, "reason": reason}}

    async def observe_challenge(
        self, agent_id: str, *, max_reports: int
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"max_reports": max_reports}}

    async def dispatch_challenge(self, agent_id: str, payload: Any) -> dict[str, Any]:
        return {"ok": True, "data": payload.model_dump(mode="json"), "warnings": []}

    async def wait_for_state(
        self, agent_id: str, reason: str | None
    ) -> ToolDispatchOutcome:
        return ToolDispatchOutcome({"ok": True, "data": {"reason": reason}}, True)

    async def submit_flag(self, agent_id: str, flag: str) -> dict[str, Any]:
        return {"ok": True, "data": {"correct": bool(flag)}}

    async def close_challenge(self, agent_id: str) -> dict[str, Any]:
        return {"ok": True, "data": {"closed": True}}

    async def report_execution_payload(
        self, agent_id: str, payload: Any
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"terminal": True}, "warnings": []}

    async def report_observer_payload(
        self, agent_id: str, payload: Any
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"terminal": True}, "warnings": []}

    async def read_evidence(
        self, agent_id: str, evidence_ref: str, **_: Any
    ) -> dict[str, Any]:
        return {"ok": True, "data": {"evidence_ref": evidence_ref}}


def names(provider: Any, role: str) -> set[str]:
    return {
        item["function"]["name"]
        for item in ToolRegistry(
            [provider], allowed_tools=AgentPolicy(role).allowed_tools
        ).definitions()
    }


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
                        "container_status": "stopped"
                        if self.close_calls
                        else "running",
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
        role="solver",
        parent_id="chief",
        unique_code="challenge-a",
        initial_prompt="challenge",
    )
    await service.register_agent(
        "run",
        agent_id="execution-child",
        role="worker",
        parent_id="challenge",
        unique_code="challenge-a",
        mission="child",
        task_key="execution-child",
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

    outcome = await supervisor.submit_flag("challenge", "flag{final}")
    assert outcome.yield_session is True
    result = outcome.result
    assert result["ok"] is True
    assert result["data"]["challenge_completed"] is True
    assert result["data"]["container_release_status"] == "pending"

    challenge_runtime = await service.get_agent_runtime("run", "challenge")
    assert challenge_runtime["agent"]["status"] == "completed"

    completion = supervisor._challenge_completion_tasks["challenge-a"]
    await completion
    overview = await service.get_overview("run")
    challenge = next(
        item for item in overview["challenges"] if item["unique_code"] == "challenge-a"
    )
    child = next(
        item for item in overview["agents"] if item["agent_id"] == "execution-child"
    )
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
    result = await supervisor.release_paused_container("challenge-a", caller_id="chief")

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
        [AgentControlTools(SupervisorStub(), agent_id="chief", role="chief")],
        allowed_tools=AgentPolicy("chief").allowed_tools,
    ).definitions()
    assert (
        request_token_count(
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
        )
        < 40_000
    )
