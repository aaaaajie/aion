"""Runtime ordering and failure tests for an injected network lifecycle."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from agent.config import AgentSettings
from agent.runtime import AgentRuntime


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="test-key",
    )


class _Network:
    def __init__(self, events: list[str], *, start_error: Exception | None = None) -> None:
        self.events = events
        self.start_error = start_error
        self.failure = asyncio.Event()
        self.closed = False

    async def start(self) -> None:
        self.events.append("vpn-ready")
        if self.start_error is not None:
            raise self.start_error

    async def wait_failure(self) -> None:
        await self.failure.wait()
        raise RuntimeError("vpn disconnected")

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
    assert chief_status == ("running",)

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
