"""Runtime ordering and failure tests for an injected network lifecycle."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest
from sqlalchemy import func, select

from agent.config import AgentSettings
from agent.runtime import AgentRuntime, RuntimePausedError
from agent.state import StateService
from agent.state.models import StateEventRecord


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="test-key",
    )


class _Network:
    def __init__(
        self,
        events: list[str],
        *,
        start_error: Exception | None = None,
        failure_error: Exception | None = None,
    ) -> None:
        self.events = events
        self.start_error = start_error
        self.failure_error = failure_error or RuntimeError("vpn disconnected")
        self.failure = asyncio.Event()
        self.closed = False

    async def start(self) -> None:
        self.events.append("vpn-ready")
        if self.start_error is not None:
            raise self.start_error

    async def wait_failure(self) -> None:
        await self.failure.wait()
        raise self.failure_error

    async def close(self) -> None:
        self.closed = True
        self.events.append("vpn-close")


class _Benchmark:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.closed = False

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.events.append(f"benchmark:{name}")
        assert name == "benchmark_list_challenges"
        return {"ok": True, "data": []}

    async def close(self) -> None:
        self.closed = True
        self.events.append("benchmark-close")


class _BlockingRunner:
    events: list[str] = []

    def __init__(self, *_args: Any, **kwargs: Any) -> None:
        self.role = kwargs.get("role")
        self.events.append(f"runner:{self.role}")

    async def run_session(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        await asyncio.Event().wait()
        return {"status": "stopped"}

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_runtime_loop_diagnostics_are_visible_and_rate_limited(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run("diagnostic")
    runtime = AgentRuntime(_settings(), project_root=tmp_path, run_root=tmp_path / "runs")
    runtime.state_service = service
    runtime.run_id = "diagnostic"

    await runtime._record_loop_diagnostic("stagnation", ValueError("bad state"))
    await runtime._record_loop_diagnostic("stagnation", ValueError("bad state"))
    async with service.db.sessions() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(StateEventRecord)
            .where(
                StateEventRecord.run_id == "diagnostic",
                StateEventRecord.event_type == "runtime_loop_failed",
            )
        )
    assert count == 1
    await service.close()


@pytest.mark.asyncio
async def test_runtime_waits_for_network_before_benchmark_and_chief(tmp_path: Path) -> None:
    events: list[str] = []
    _BlockingRunner.events = events
    network = _Network(events)
    benchmark = _Benchmark(events)
    runtime = AgentRuntime(
        _settings(),
        benchmark=benchmark,
        network_manager=network,
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        runner_factory=_BlockingRunner,
        catalog_reconcile_interval_seconds=0,
    )

    await runtime.start("test", run_id="network-order")
    assert events.index("vpn-ready") < events.index("benchmark:benchmark_list_challenges")
    assert events.index("benchmark:benchmark_list_challenges") < events.index("runner:chief")

    await runtime.close()
    assert events.index("benchmark-close") < events.index("vpn-close")


@pytest.mark.asyncio
async def test_runtime_pause_preserves_chief_for_resume(tmp_path: Path) -> None:
    events: list[str] = []
    _BlockingRunner.events = events
    run_root = tmp_path / "runs"
    runtime = AgentRuntime(
        _settings(),
        benchmark=_Benchmark(events),
        network_manager=_Network(events),
        project_root=tmp_path,
        run_root=run_root,
        runner_factory=_BlockingRunner,
        catalog_reconcile_interval_seconds=0,
    )
    await runtime.start("test", run_id="pause-resume")

    await runtime.pause()

    with sqlite3.connect(run_root / "pause-resume" / "state.sqlite3") as connection:
        chief_status = connection.execute(
            "SELECT status FROM agents WHERE role = 'chief'"
        ).fetchone()
        run_status = connection.execute(
            "SELECT status, pause_reason FROM runs WHERE run_id = 'pause-resume'"
        ).fetchone()
        outbox_count = connection.execute(
            "SELECT COUNT(*) FROM audit_outbox"
        ).fetchone()[0]
    assert chief_status == ("running",)
    assert run_status == ("paused", "runtime_pause")
    assert outbox_count == 0
    assert json.loads(
        (run_root / "pause-resume" / "checkpoint.json").read_text(encoding="utf-8")
    )["status"] == "paused"

    resumed_events: list[str] = []
    _BlockingRunner.events = resumed_events
    resumed = AgentRuntime(
        _settings(),
        benchmark=_Benchmark(resumed_events),
        network_manager=_Network(resumed_events),
        project_root=tmp_path,
        run_root=run_root,
        runner_factory=_BlockingRunner,
        catalog_reconcile_interval_seconds=0,
    )
    await resumed.start("", run_id="pause-resume", resume=True)
    assert "runner:chief" in resumed_events
    assert resumed.state_service is not None
    assert (await resumed.state_service.get_overview("pause-resume"))["run"]["status"] == "active"
    await resumed.close()


@pytest.mark.asyncio
async def test_network_start_failure_prevents_benchmark_and_chief(tmp_path: Path) -> None:
    events: list[str] = []
    _BlockingRunner.events = events
    network = _Network(events, start_error=RuntimeError("vpn unavailable"))
    benchmark = _Benchmark(events)
    runtime = AgentRuntime(
        _settings(),
        benchmark=benchmark,
        network_manager=network,
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        runner_factory=_BlockingRunner,
    )

    with pytest.raises(RuntimeError, match="vpn unavailable"):
        await runtime.start("test", run_id="network-start-failed")

    assert not any(item.startswith("benchmark:") for item in events)
    assert not any(item.startswith("runner:") for item in events)
    assert benchmark.closed is True
    assert network.closed is True


@pytest.mark.asyncio
async def test_network_disconnect_fails_running_runtime(tmp_path: Path) -> None:
    events: list[str] = []
    _BlockingRunner.events = events
    network = _Network(events)
    benchmark = _Benchmark(events)
    runtime = AgentRuntime(
        _settings(),
        benchmark=benchmark,
        network_manager=network,
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        runner_factory=_BlockingRunner,
        catalog_reconcile_interval_seconds=0,
    )

    await runtime.start("test", run_id="network-disconnected")
    network.failure.set()
    assert runtime._network_failure_event is not None
    await asyncio.wait_for(runtime._network_failure_event.wait(), timeout=1)
    with pytest.raises(RuntimeError, match="vpn disconnected"):
        await runtime.ensure_healthy()

    assert runtime.state_service is not None
    overview = await runtime.state_service.get_overview("network-disconnected")
    assert overview["run"]["status"] == "failed"
    for _ in range(100):
        if all(
            item["status"] in {"completed", "failed", "stopped", "interrupted"}
            for item in overview["agents"]
        ):
            break
        await asyncio.sleep(0.01)
        overview = await runtime.state_service.get_overview("network-disconnected")
    assert all(
        item["status"] in {"completed", "failed", "stopped", "interrupted"}
        for item in overview["agents"]
    )
    await runtime.close()
    assert benchmark.closed is True
    assert network.closed is True


class _RemoteHalt(RuntimeError):
    code = "vpn_remote_halt"


@pytest.mark.asyncio
async def test_remote_vpn_halt_pauses_without_reconnect_or_run_failure(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _BlockingRunner.events = events
    run_root = tmp_path / "runs"
    network = _Network(events, failure_error=_RemoteHalt("server halt"))
    runtime = AgentRuntime(
        _settings(),
        benchmark=_Benchmark(events),
        network_manager=network,
        project_root=tmp_path,
        run_root=run_root,
        runner_factory=_BlockingRunner,
        catalog_reconcile_interval_seconds=0,
    )

    await runtime.start("test", run_id="remote-halt")
    network.failure.set()
    assert runtime._network_failure_event is not None
    await asyncio.wait_for(runtime._network_failure_event.wait(), timeout=1)
    with pytest.raises(RuntimePausedError) as paused:
        await runtime.ensure_healthy()
    assert paused.value.reason == "vpn_remote_halt"
    assert events.count("vpn-ready") == 1
    with sqlite3.connect(run_root / "remote-halt" / "state.sqlite3") as connection:
        run_state = connection.execute(
            "SELECT status, pause_reason FROM runs WHERE run_id = 'remote-halt'"
        ).fetchone()
    assert run_state == ("paused", "vpn_remote_halt")
    assert network.closed is True
    await runtime.close()
