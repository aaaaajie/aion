"""Unified SQLite-first lifecycle for one AION run."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
import logging
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import psutil

from agent.config import AgentSettings, PROJECT_ROOT
from agent.runtime_cleanup import cleanup_fresh_run_artifacts
from agent.state import (
    AgentReportInput,
    CapabilityContext,
    CapabilityRegistry,
    ChallengeScheduler,
    ResourceController,
    StateService,
    StagnationManager,
    challenge_work_active,
)
from agent.state.clock import utc_now
from agent.subagents import AgentSupervisor, SubagentError
from tools.benchmark import BenchmarkTools


LOGGER = logging.getLogger(__name__)


class NetworkLifecycle(Protocol):
    """Optional network dependency owned by the Runtime process."""

    async def start(self) -> Any: ...

    async def wait_failure(self) -> None: ...

    async def close(self) -> None: ...


class RuntimePausedError(RuntimeError):
    """Raised after Runtime has safely persisted a resumable pause."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Runtime paused: {reason}")
        self.reason = reason


class AgentRuntime:
    """Build and supervise the complete run from one authoritative database."""

    def __init__(
        self,
        settings: AgentSettings,
        *,
        benchmark: Any | None = None,
        network_manager: NetworkLifecycle | None = None,
        project_root: Path = PROJECT_ROOT,
        run_root: Path | None = None,
        runner_factory: Callable[..., Any] | None = None,
        capability_registry: CapabilityRegistry | None = None,
        psutil_module: Any = psutil,
        clock: Callable[[], datetime] = utc_now,
        stagnation_interval_seconds: float = 30.0,
        projection_interval_seconds: float = 1.0,
        catalog_reconcile_interval_seconds: float = 120.0,
    ) -> None:
        self.settings = settings
        self.benchmark = benchmark
        self.network_manager = network_manager
        self.project_root = project_root.resolve()
        self.run_root = (run_root or settings.run_root).resolve()
        self.runner_factory = runner_factory
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.psutil_module = psutil_module
        self.clock = clock
        self.stagnation_interval_seconds = stagnation_interval_seconds
        self.projection_interval_seconds = projection_interval_seconds
        self.catalog_reconcile_interval_seconds = catalog_reconcile_interval_seconds
        self.run_id: str | None = None
        self.chief_agent_id: str | None = None
        self.state_service: StateService | None = None
        self.supervisor: AgentSupervisor | None = None
        self.resource_controller: ResourceController | None = None
        self.stagnation_manager: StagnationManager | None = None
        self._background_tasks: list[asyncio.Task[None]] = []
        self._execution_watchers: dict[str, asyncio.Task[None]] = {}
        self._network_watch_task: asyncio.Task[None] | None = None
        self._network_failure_event: asyncio.Event | None = None
        self._network_failure: Exception | None = None
        self._network_pause_reason: str | None = None
        self._network_failure_recorded = False
        self._network_failure_record_lock = asyncio.Lock()
        self._loop_diagnostics: dict[str, float] = {}
        self._shutdown_event = asyncio.Event()
        self._closed = False

    @classmethod
    def from_env(cls, **kwargs: Any) -> "AgentRuntime":
        settings = kwargs.pop("settings", None) or AgentSettings()
        benchmark = kwargs.pop("benchmark", None)
        if benchmark is None:
            benchmark = BenchmarkTools.from_env()
        return cls(settings, benchmark=benchmark, **kwargs)

    async def start(
        self,
        prompt: str,
        *,
        run_id: str | None = None,
        resume: bool = False,
    ) -> str:
        if self.state_service is not None:
            raise RuntimeError("AgentRuntime is already started")
        run_id = run_id or uuid4().hex
        run_dir = self.run_root / run_id
        database_path = run_dir / "state.sqlite3"
        if resume and not database_path.exists():
            raise SubagentError("run state database was not found")
        if not resume:
            cleanup_fresh_run_artifacts(
                workspace_root=self.project_root,
                run_root=self.run_root,
                run_id=run_id,
            )

        service = StateService(
            database_path,
            run_root=self.run_root,
            workspace_root=self.project_root,
            clock=self.clock,
        )
        await service.initialize()
        self.state_service = service
        self.run_id = run_id
        try:
            if self.network_manager is not None:
                await self.network_manager.start()
                self._network_failure_event = asyncio.Event()
                self._network_watch_task = asyncio.create_task(
                    self._network_watch_loop(),
                    name=f"aion-network-watch-{run_id}",
                )

            supervisor_kwargs: dict[str, Any] = {
                "benchmark": self.benchmark,
                "project_root": self.project_root,
                "run_root": self.run_root,
                "state_service": service,
                "capability_registry": self.capability_registry,
                "catalog_reconcile_interval_seconds": self.catalog_reconcile_interval_seconds,
                "duration_minutes": self.settings.run_duration_minutes,
            }
            if self.runner_factory is not None:
                supervisor_kwargs["runner_factory"] = self.runner_factory
            self.resource_controller = ResourceController(
                service,
                run_id,
                cpu_limit_percent=self.settings.cpu_limit_percent,
                memory_limit_percent=self.settings.memory_limit_percent,
                storage_root=self.project_root,
                disk_reserve_bytes=self.settings.disk_reserve_bytes,
                disk_reserve_percent=self.settings.disk_reserve_percent,
                psutil_module=self.psutil_module,
                clock=self.clock,
            )
            supervisor_kwargs["resource_controller"] = self.resource_controller
            self.supervisor = AgentSupervisor(self.settings, **supervisor_kwargs)
            self.stagnation_manager = StagnationManager(service, clock=self.clock)
            self.chief_agent_id = await self.supervisor.prepare_chief(
                prompt, run_id=run_id, resume=resume
            )
            await self.ensure_healthy()
        except Exception:
            await self.close()
            raise
        self._background_tasks = [
            asyncio.create_task(
                self._admission_loop(), name=f"aion-admission-{run_id}"
            ),
            asyncio.create_task(
                self._stagnation_loop(), name=f"aion-stagnation-{run_id}"
            ),
            asyncio.create_task(
                self._projection_loop(), name=f"aion-outbox-{run_id}"
            ),
        ]
        return self.chief_agent_id

    async def run(
        self,
        prompt: str,
        *,
        run_id: str | None = None,
        resume: bool = False,
    ) -> dict[str, Any]:
        chief_id = await self.start(prompt, run_id=run_id, resume=resume)
        try:
            return await self.wait(chief_id)
        finally:
            await self.close()

    async def wait(self, chief_id: str | None = None) -> dict[str, Any]:
        """Wait for a started run without owning Runtime shutdown."""

        if self.supervisor is None:
            raise RuntimeError("AgentRuntime is not started")
        chief_id = chief_id or self.chief_agent_id
        if chief_id is None:
            raise RuntimeError("Chief Agent is not started")
        assert self.supervisor is not None
        agents_task = asyncio.create_task(
            self._wait_for_agents(chief_id),
            name=f"aion-run-agents-{self._run_id()}",
        )
        network_waiter: asyncio.Task[bool] | None = None
        if self._network_failure_event is not None:
            network_waiter = asyncio.create_task(
                self._network_failure_event.wait(),
                name=f"aion-run-network-{self._run_id()}",
            )
        try:
            if network_waiter is None:
                return await agents_task
            await asyncio.wait(
                {agents_task, network_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
            await self.ensure_healthy()
            return await agents_task
        finally:
            if not agents_task.done():
                agents_task.cancel()
                await asyncio.gather(agents_task, return_exceptions=True)
            if network_waiter is not None:
                network_waiter.cancel()
                await asyncio.gather(network_waiter, return_exceptions=True)

    async def ensure_healthy(self) -> None:
        """Raise after recording an unexpected managed-network failure."""

        if self._network_pause_reason is not None:
            reason = self._network_pause_reason
            await self.pause(reason=reason)
            raise RuntimePausedError(reason)
        if self._network_failure is None:
            return
        await self._record_network_failure()
        if self.supervisor is not None:
            await self.supervisor.close()
        raise self._network_failure

    async def admission_once(
        self,
        *,
        sample: dict[str, float] | None = None,
    ) -> dict[str, Any] | None:
        controller = self._resource()
        sample = sample or await controller.sample()
        item = await controller.next_queued_work_item()
        if item is None:
            return None
        return await self._admit_item(item, sample=sample)

    async def _admit_item(
        self,
        item: dict[str, Any],
        *,
        sample: dict[str, float],
    ) -> dict[str, Any]:
        """Admit the already selected queue item without re-reading another queue."""

        controller = self._resource()
        if item["kind"] == "resource":
            decision = await controller.admit_resource_work(item["id"], sample=sample)
            if not decision.get("ok") or decision.get("status") != "reserved":
                return decision
            claim = await controller.claim_resource_work(item["id"])
            if not claim.get("claimed"):
                return {"ok": True, **claim}
            try:
                assert self.supervisor is not None
                if item["owner_type"] == "http_interaction":
                    await self.supervisor.launch_http_work(
                        item["owner_id"], item["phase"], work_id=item["id"]
                    )
                elif item["owner_type"] == "network_task":
                    await self.supervisor.launch_network_work(
                        item["owner_id"], work_id=item["id"]
                    )
                else:
                    raise RuntimeError("unsupported resource work owner")
                return await controller.mark_resource_started(item["id"])
            except Exception:
                return await controller.finish_resource_work(
                    item["id"],
                    status="failed",
                    reason="resource_work_start_failed",
                )
        agent_id = item["id"]
        decision = await controller.admit(agent_id, sample=sample)
        if not decision.get("ok") or decision.get("status") != "starting":
            return decision
        if not decision.get("claimed"):
            return decision
        try:
            assert self.supervisor is not None
            await self.supervisor.launch_execution_agent(agent_id)
            started = await controller.mark_started(agent_id)
            self._execution_watchers[agent_id] = asyncio.create_task(
                self._watch_execution(agent_id),
                name=f"aion-execution-watch-{agent_id}",
            )
            return started
        except Exception:
            await controller.mark_failed(agent_id, reason="agent_start_failed")
            assert self.state_service is not None
            runtime = await self.state_service.get_agent_runtime(
                self._run_id(), agent_id
            )
            if runtime["agent"].get("terminal_report_id") is None:
                await self.state_service.finalize_execution_agent(
                    self._run_id(),
                    agent_id,
                    CapabilityContext(
                        run_id=self._run_id(),
                        agent_id=agent_id,
                        role="execution",
                        unique_code=runtime["agent"]["unique_code"],
                    ),
                    AgentReportInput(
                        status="failed",
                        summary="Execution Agent could not be started",
                        hypothesis_outcome="inconclusive",
                    ),
                    allow_inactive=True,
                )
            return {"ok": False, "status": "failed", "agent_id": agent_id}

    async def admission_drain(self) -> list[dict[str, Any]]:
        """Fairly drain explicit resource and Agent batches for one wakeup."""

        controller = self._resource()
        sample = await controller.sample()
        results: list[dict[str, Any]] = []
        resource_blocked = False
        agent_blocked = False
        while not (resource_blocked and agent_blocked):
            made_progress = False
            if not resource_blocked:
                for _ in range(8):
                    item = await controller.next_queued_resource_work_item()
                    if item is None:
                        resource_blocked = True
                        break
                    result = await self._admit_item(item, sample=sample)
                    results.append(result)
                    if not result.get("ok") or result.get("status") not in {
                        "reserved",
                        "starting",
                        "running",
                    }:
                        resource_blocked = True
                        break
                    made_progress = True
                    sample = await controller.sample()

            if not agent_blocked:
                for _ in range(4):
                    agent_id = await controller.next_queued_agent_id()
                    if agent_id is None:
                        agent_blocked = True
                        break
                    result = await self._admit_item(
                        {"kind": "agent", "id": agent_id}, sample=sample
                    )
                    results.append(result)
                    if not result.get("ok") or result.get("status") not in {
                        "starting",
                        "running",
                    }:
                        agent_blocked = True
                        break
                    made_progress = True
                    sample = await controller.sample()

            if not made_progress:
                break
        return results

    async def stagnation_once(self) -> list[dict[str, Any]]:
        if self.stagnation_manager is None or self.state_service is None:
            raise RuntimeError("AgentRuntime is not started")
        challenges = await self.state_service.list_challenges(self._run_id())
        results: list[dict[str, Any]] = []
        for challenge in challenges:
            if not challenge_work_active(challenge):
                continue
            result = await self.stagnation_manager.evaluate(
                self._run_id(), challenge["unique_code"]
            )
            results.append(result)
            if result.get("action") == "pause_stagnation" and self.supervisor is not None:
                await self.supervisor.stop_challenge_work(
                    challenge["unique_code"],
                    reason=str(result.get("pause_reason") or "stagnation_timeout"),
                )
            if result.get("event_sequence") is not None:
                await self.state_service.signal_challenge_changes(
                    self._run_id(),
                    [challenge["unique_code"]],
                    int(result["event_sequence"]),
                )
        await self._restart_exhausted_challenges()
        return results

    async def _restart_exhausted_challenges(self) -> None:
        """Start the next solving round when every unfinished challenge is paused."""

        if self.supervisor is None or self.state_service is None or self.chief_agent_id is None:
            return
        scheduled = await ChallengeScheduler(self.state_service, clock=self.clock).select(
            self._run_id()
        )
        restart_codes = [
            str(item["unique_code"])
            for item in scheduled
            if item.get("restart_required") is True
        ]
        if not restart_codes:
            return
        await self.supervisor.launch_challenges(
            self.chief_agent_id,
            restart_codes,
        )

    async def project_once(self) -> int:
        if self.state_service is None:
            raise RuntimeError("AgentRuntime is not started")
        return await self.state_service.project_pending_events(
            self._run_id(), run_dir=self.run_root / self._run_id(), limit=500
        )

    async def close(self) -> None:
        await self._shutdown(preserve_run=False)

    async def pause(self, *, reason: str = "runtime_pause") -> None:
        """Release external resources while keeping the run resumable."""

        self._shutdown_event.set()
        if self.state_service is not None and self.run_id is not None:
            await self.state_service.pause_run(self.run_id, reason=reason)
        await self._shutdown(preserve_run=True)

    async def _shutdown(self, *, preserve_run: bool) -> None:
        if self._closed:
            return
        self._closed = True
        self._shutdown_event.set()
        if self._network_watch_task is not None:
            self._network_watch_task.cancel()
            await asyncio.gather(self._network_watch_task, return_exceptions=True)
            self._network_watch_task = None
        for task in self._background_tasks:
            task.cancel()
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        self._background_tasks.clear()
        for task in self._execution_watchers.values():
            task.cancel()
        if self._execution_watchers:
            await asyncio.gather(
                *self._execution_watchers.values(), return_exceptions=True
            )
        self._execution_watchers.clear()
        supervisor_error: Exception | None = None
        if self.supervisor is not None:
            try:
                if preserve_run:
                    await self.supervisor.pause()
                else:
                    await self.supervisor.close()
            except Exception as exc:
                supervisor_error = exc
                LOGGER.exception(
                    "supervisor_shutdown_failed run_id=%s preserve_run=%s",
                    self.run_id,
                    preserve_run,
                )
            self.supervisor = None
        if self.benchmark is not None:
            try:
                await self.benchmark.close()
            except Exception:
                pass
        if self.state_service is not None:
            try:
                while await self.state_service.project_pending_events(
                    self._run_id(), run_dir=self.run_root / self._run_id(), limit=500
                ):
                    pass
                await self.state_service.project_pending_events(
                    self._run_id(),
                    run_dir=self.run_root / self._run_id(),
                    limit=500,
                    force_checkpoint=True,
                )
            except Exception:
                pass
            try:
                await self.state_service.close()
            except Exception:
                pass
            self.state_service = None
        if self.network_manager is not None:
            try:
                await self.network_manager.close()
            except Exception:
                pass
        if supervisor_error is not None:
            raise supervisor_error

    async def _admission_loop(self) -> None:
        assert self.state_service is not None
        signal_key = self.state_service.run_signal_key(self._run_id())
        signal_sequence = await self.state_service.notifier.current(signal_key)
        while True:
            try:
                await self.admission_drain()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._record_loop_diagnostic("admission", exc)
            signal_wait = asyncio.create_task(
                self.state_service.notifier.wait(
                    signal_key,
                    signal_sequence,
                    0.5,
                )
            )
            shutdown_wait = asyncio.create_task(self._shutdown_event.wait())
            done, pending = await asyncio.wait(
                {signal_wait, shutdown_wait},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if shutdown_wait in done:
                return
            signal_sequence = signal_wait.result()

    async def _stagnation_loop(self) -> None:
        while True:
            try:
                await self.stagnation_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._record_loop_diagnostic("stagnation", exc)
            await asyncio.sleep(self.stagnation_interval_seconds)

    async def _record_loop_diagnostic(self, loop_name: str, exc: Exception) -> None:
        fingerprint = f"{loop_name}:{type(exc).__name__}:{str(exc)[:200]}"
        now = asyncio.get_running_loop().time()
        if now - self._loop_diagnostics.get(fingerprint, -600.0) < 300.0:
            return
        self._loop_diagnostics[fingerprint] = now
        LOGGER.warning(
            "runtime_loop_failed run_id=%s loop=%s error_type=%s",
            self.run_id,
            loop_name,
            type(exc).__name__,
        )
        if self.state_service is not None and self.run_id is not None:
            try:
                await self.state_service.append_run_event(
                    self.run_id,
                    "runtime_loop_failed",
                    {
                        "loop": loop_name,
                        "error_type": type(exc).__name__,
                        "message": str(exc)[:500],
                    },
                )
            except Exception:
                LOGGER.exception(
                    "runtime_loop_failure_event_failed run_id=%s loop=%s",
                    self.run_id,
                    loop_name,
                )

    async def _projection_loop(self) -> None:
        while True:
            try:
                await self.project_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(self.projection_interval_seconds)

    async def _network_watch_loop(self) -> None:
        assert self.network_manager is not None
        try:
            await self.network_manager.wait_failure()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if getattr(exc, "code", None) == "vpn_remote_halt":
                self._network_pause_reason = "vpn_remote_halt"
            else:
                self._network_failure = exc
        else:
            self._network_failure = RuntimeError(
                "Managed network connection stopped unexpectedly"
            )
        if self._network_failure_event is not None:
            self._network_failure_event.set()
        if self._network_pause_reason is not None:
            return
        await self._record_network_failure()

    async def _record_network_failure(self) -> None:
        async with self._network_failure_record_lock:
            if (
                self._network_failure_recorded
                or self.state_service is None
                or self.run_id is None
            ):
                return
            if not await self.state_service.run_exists(self.run_id):
                return
            await self.state_service.finish_run(
                self.run_id,
                "failed",
                report={
                    "type": "network_failure",
                    "summary": "The managed VPN connection exited unexpectedly",
                },
            )
            self._network_failure_recorded = True

    async def _wait_for_agents(self, chief_id: str) -> dict[str, Any]:
        assert self.supervisor is not None
        result = await self.supervisor.wait_agent(chief_id)
        await self.supervisor.wait_for_quiescence()
        return result

    async def _watch_execution(self, agent_id: str) -> None:
        try:
            assert self.supervisor is not None
            await self.supervisor.wait_agent(agent_id)
            runtime = await self.state_service.get_agent_runtime(  # type: ignore[union-attr]
                self._run_id(), agent_id
            )
            status = runtime["agent"]["status"]
            await self._resource().finish(
                agent_id,
                status="completed" if status == "completed" else status,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            try:
                await self._resource().finish(agent_id, status="failed")
            except Exception:
                pass
        finally:
            self._execution_watchers.pop(agent_id, None)

    def _resource(self) -> ResourceController:
        if self.resource_controller is None:
            raise RuntimeError("AgentRuntime is not started")
        return self.resource_controller

    def _run_id(self) -> str:
        if self.run_id is None:
            raise RuntimeError("AgentRuntime is not started")
        return self.run_id


__all__ = ["AgentRuntime", "NetworkLifecycle"]
