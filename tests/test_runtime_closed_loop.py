"""Offline acceptance tests for the SQLite-only Agent Runtime."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent.config import AgentSettings
from agent.runtime import AgentRuntime
from agent.subagents import AgentSupervisor


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="test-key",
        agent_start_interval_seconds=0,
    )


class _Resources:
    @staticmethod
    def cpu_percent(interval: Any = None) -> float:
        return 10.0

    @staticmethod
    def virtual_memory() -> Any:
        return SimpleNamespace(percent=20.0)


class _QuiescenceState:
    def __init__(self) -> None:
        self.calls = 0
        self.notifier = self

    @staticmethod
    def run_signal_key(run_id: str) -> str:
        return f"run:{run_id}"

    async def current(self, _key: str) -> int:
        return 0

    async def wait(self, _key: str, after_sequence: int, _timeout: float) -> int:
        return after_sequence + 1

    async def get_overview(self, _run_id: str) -> dict[str, Any]:
        self.calls += 1
        status = "running" if self.calls == 1 else "completed"
        return {"agents": [{"agent_id": "chief", "status": status}]}


class _Benchmark:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, dict(arguments)))
        if name == "benchmark_list_challenges":
            return {
                "ok": True,
                "data": [
                    {
                        "unique_code": "offline-1",
                        "description": "offline lifecycle fixture",
                        "difficulty": "easy",
                        "level": 1,
                        "total_score": 10,
                        "flag_count": 1,
                        "correct_flag_count": 0,
                        "is_completed": False,
                        "container_status": "stopped",
                        "container_addr": [],
                    }
                ],
            }
        if name == "benchmark_start_challenge":
            return {
                "ok": True,
                "data": {
                    "unique_code": arguments["unique_code"],
                    "container_addr": ["local-fixture"],
                },
            }
        raise AssertionError(name)

    async def close(self) -> None:
        return None


class _LifecycleRunner:
    """Block coordinators; execute one safe local tool round for workers."""

    def __init__(self, settings: Any, registry: Any, **kwargs: Any) -> None:
        self.registry = registry
        self.names = {item["function"]["name"] for item in registry.definitions()}

    async def run_session(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        if "execution_report" not in self.names:
            await asyncio.Event().wait()
        written = await self.registry.dispatch(
            "system_write_file",
            {"file_path": "runtime-fixture.txt", "content": "sqlite closed loop"},
        )
        assert written["ok"] is True
        read = await self.registry.dispatch(
            "system_read_file", {"file_path": "runtime-fixture.txt"}
        )
        assert read["ok"] is True
        report = await self.registry.dispatch(
            "execution_report",
            {
                "status": "completed",
                "summary": "local tool round completed",
                "findings": [
                    {
                        "category": "service",
                        "summary": "local file round-trip verified",
                        "verification_status": "candidate",
                    }
                ],
                "hypothesis_outcome": "inconclusive",
            },
        )
        assert report["ok"] is True
        return {"status": "completed"}

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_runtime_sqlite_only_three_layer_closed_loop(tmp_path: Path) -> None:
    project_root = tmp_path / "workspace"
    project_root.mkdir()
    run_root = project_root / "runs"
    runtime = AgentRuntime(
        _settings(),
        benchmark=_Benchmark(),
        project_root=project_root,
        run_root=run_root,
        runner_factory=_LifecycleRunner,
        psutil_module=_Resources,
        admission_interval_seconds=60,
        stagnation_interval_seconds=60,
        projection_interval_seconds=60,
        catalog_reconcile_interval_seconds=0,
    )
    stale_cache = project_root / ".system-tools"
    stale_cache.mkdir()
    (stale_cache / "stale-task-output").write_text("stale", encoding="utf-8")
    chief_id = await runtime.start("coordinate offline fixture", run_id="closed-loop")
    assert not (stale_cache / "stale-task-output").exists()
    assert runtime.supervisor is not None
    supervisor = runtime.supervisor

    created = await supervisor.create_challenge_agent(chief_id, "offline-1")
    assert created["ok"] is True
    challenge_id = created["data"]["agent_id"]
    domain_observation = await supervisor.state_service.record_observation(
        "closed-loop",
        "offline-1",
        category="domain_triage",
        summary="Challenge domain classified as other",
        detail={
            "domain": "other",
            "confidence": 0.95,
            "scanner_profile": "other_light",
        },
        source="test_domain_triage",
        confidence=0.95,
        mark_progress=False,
        route_branches=False,
    )
    domain_ref = f"observation:{domain_observation['observation_id']}"
    state = await supervisor.get_challenge_state(challenge_id)
    challenge_version = state["data"]["challenge"]["version"]
    cycle = await supervisor.begin_cycle(challenge_id, challenge_version)
    plan = await supervisor.submit_analysis_plan(
        challenge_id,
        cycle["data"]["cycle_id"],
        cycle["data"]["version"],
        analysis_summary="exercise the local report path",
        hypotheses=[],
        information_gaps=[],
        avoid_repeating=[],
        tasks=[
            {
                "hypothesis_key": "local-file-roundtrip",
                "task_key": "local-file-roundtrip-1",
                "kind": "verification",
                "task_stage": "discovery",
                "objective": "round-trip one local file and report it",
                "priority": 80,
                "success_criteria": ["read content matches"],
                "context_refs": [],
                "timeout_seconds": 30,
            }
        ],
    )
    execution_id = plan["data"]["admissions"][0]["agent_id"]
    admitted = await runtime.admission_once()
    assert admitted is not None and admitted["status"] == "running"
    await supervisor.wait_agent(execution_id)

    reports = await supervisor.get_execution_reports(challenge_id)
    assert reports["data"]["reports"][0]["summary"] == "local tool round completed"
    committed = await supervisor.commit_cycle(
        challenge_id,
        cycle["data"]["cycle_id"],
        plan["data"]["version"],
        summary="worker evidence accepted",
        findings=[],
        credentials=[],
        next_steps=[],
        outcome="no_progress",
    )
    # The discovery report is intentionally non-progress; cycle commit only
    # stores the Challenge summary and does not copy report Findings.
    assert committed["data"]["valid_progress"] is False
    assert (project_root / "runtime-fixture.txt").read_text() == "sqlite closed loop"
    await runtime.project_once()
    assert (run_root / "closed-loop" / "state.sqlite3").is_file()

    cursor = reports["data"]["next_sequence"]
    await runtime.close()

    for name in ("events.jsonl", "checkpoint.json", "session_memory.md"):
        (run_root / "closed-loop" / name).unlink(missing_ok=True)

    resumed = AgentRuntime(
        _settings(),
        benchmark=_Benchmark(),
        project_root=project_root,
        run_root=run_root,
        runner_factory=_LifecycleRunner,
        psutil_module=_Resources,
        admission_interval_seconds=60,
        stagnation_interval_seconds=60,
        projection_interval_seconds=60,
        catalog_reconcile_interval_seconds=0,
    )
    resumed_cache = project_root / ".system-tools"
    resumed_cache.mkdir(exist_ok=True)
    (resumed_cache / "keep-on-resume").write_text("keep", encoding="utf-8")
    await resumed.start("", run_id="closed-loop", resume=True)
    assert (resumed_cache / "keep-on-resume").read_text(encoding="utf-8") == "keep"
    assert resumed.supervisor is not None
    no_replay = await resumed.supervisor.get_execution_reports(challenge_id)
    assert no_replay["data"]["reports"] == []
    assert no_replay["data"]["next_sequence"] == cursor
    overview = await resumed.state_service.get_overview("closed-loop")  # type: ignore[union-attr]
    execution = next(item for item in overview["agents"] if item["agent_id"] == execution_id)
    assert execution["status"] == "completed"
    await resumed.close()


@pytest.mark.asyncio
async def test_supervisor_waits_for_persisted_tree_quiescence() -> None:
    state = _QuiescenceState()
    supervisor = object.__new__(AgentSupervisor)
    supervisor.state_service = state
    supervisor.run_id = "quiescence"
    supervisor._tasks = {}

    await supervisor.wait_for_quiescence()

    assert state.calls >= 2
