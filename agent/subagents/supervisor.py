"""SQLite-authoritative parent/child Agent orchestration."""

from __future__ import annotations

from agent.subagents.receipts import submission_report

import asyncio
import json
import logging
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from agent.config import AgentSettings, PROJECT_ROOT
from agent.memory.models import AgentNode
from agent.memory.redaction import redact_value
from agent.prompts import load_prompt, render_prompt, system_prompt
from agent.runner import AgentRunner, AgentRunnerError, AgentSessionResult, ToolRegistry
from agent.skills import (
    SkillCatalog,
    SkillCatalogError,
    SkillDiscovery,
    SkillSessionContext,
    SkillTools,
)
from agent.state import (
    AgentStateStore,
    CapabilityRegistry,
    MAX_CHALLENGE_SLOTS as DEFAULT_MAX_CHALLENGE_SLOTS,
    ResourceController,
    StateService,
    container_capacity_summary,
    container_slot_occupied,
)
from agent.state.errors import StateError, StateConflict
from agent.state.clock import aware, utc_now
from agent.state.schemas import (
    AgentReportInput,
    CapabilityContext,
)
from agent.tooling import (
    ToolDispatchOutcome,
    ToolExecutor,
    ToolResultStore,
    ToolResultTools,
    tool_error,
)
from tools.http import HttpProbeManager, HttpTools
from tools.network import NetworkDiscoveryManager, NetworkTools
from tools.binary import BinaryTools
from tools.artifact import ArtifactTools
from tools.binaries import default_toolchain_root, toolchain_for
from tools.pentest import PentestTools
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy

from .models import AgentRole
from .policy import AgentPolicy
from .lifecycle import AgentLifecycle
from agent.run_ownership import RunOwnership
from agent.model_usage import current_model_event_writer

LOGGER = logging.getLogger("aion.supervisor")
if not LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


class SubagentError(RuntimeError):
    """Safe orchestration failure without exposing credentials or stack traces."""


class AgentSupervisor(AgentLifecycle):
    """Own live tasks while SQLite owns all recoverable Agent state."""

    async def solver_progress(self, caller_id: str, payload: Any) -> dict[str, Any]:
        node = self._require_role(caller_id, "solver")
        async with self._service().db.sessions() as session:
            await self._service()._validate_context_refs(
                session, self._run_id(), node.unique_code, payload.evidence_refs
            )
        result = await self._service().publish_control_report(
            self._run_id(), sender_id=caller_id, recipient_id=self.chief_agent_id,
            unique_code=node.unique_code, report_type="solver", status=payload.status,
            payload=payload.model_dump(exclude={"candidate_flag"}),
        )
        return self._ok(result)

    async def solver_review(self, caller_id: str, payload: Any) -> dict[str, Any]:
        self._require_role(caller_id, "solver")
        sequence = await self._service().record_solver_review(
            self._run_id(), self._state_context(caller_id), payload
        )
        return self._ok({"review_sequence": sequence})


    MAX_CHALLENGE_SLOTS = DEFAULT_MAX_CHALLENGE_SLOTS
    HEARTBEAT_INTERVAL_SECONDS = 30.0
    HEARTBEAT_EVENT_INTERVAL_SECONDS = 300.0
    TERMINAL_AGENT_STATES = {
        "completed",
        "failed",
        "stopped",
        "cancelled",
        "interrupted",
        "blocked",
    }

    def __init__(
        self,
        settings: AgentSettings,
        *,
        benchmark: Any | None = None,
        project_root: Path = PROJECT_ROOT,
        run_root: Path | None = None,
        runner_factory: Callable[..., AgentRunner] = AgentRunner,
        max_challenge_slots: int = DEFAULT_MAX_CHALLENGE_SLOTS,
        catalog_reconcile_interval_seconds: float = 120.0,
        duration_minutes: int | None = None,
        state_service: StateService,
        capability_registry: CapabilityRegistry | None = None,
        resource_controller: ResourceController | None = None,
        skill_catalog: SkillCatalog | None = None,
        poc_index_root: Path | None = None,
    ) -> None:
        if max_challenge_slots != DEFAULT_MAX_CHALLENGE_SLOTS:
            raise ValueError(
                f"the benchmark challenge slot limit is fixed at {DEFAULT_MAX_CHALLENGE_SLOTS}"
            )
        if catalog_reconcile_interval_seconds < 0:
            raise ValueError("catalog_reconcile_interval_seconds must not be negative")
        self.settings = settings
        self.benchmark = benchmark
        self.project_root = project_root.resolve()
        self.poc_index_root = (poc_index_root or self.project_root / "output" / "poc-index").resolve()
        self.toolchain_root = default_toolchain_root()
        self.run_root = (run_root or self.project_root / ".aion" / "runs").resolve()
        self.runner_factory = runner_factory
        self.max_challenge_slots = max_challenge_slots
        self.catalog_reconcile_interval_seconds = catalog_reconcile_interval_seconds
        self.duration_minutes = duration_minutes or getattr(
            settings, "run_duration_minutes", 360
        )
        self.state_service = state_service
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.resource_controller = resource_controller
        self.skill_catalog = skill_catalog or SkillCatalog()
        self._state_capabilities: dict[str, CapabilityContext] = {}
        self._run_ownership = None
        self._ownership_conflict = False
        self.run_id: str | None = None
        self.store: AgentStateStore | None = None
        self.chief_agent_id: str | None = None
        # These are live process views only. SQLite remains authoritative.
        self.nodes: dict[str, AgentNode] = {}
        self._runners: dict[str, AgentRunner] = {}
        self._runner_metrics: dict[str, dict[str, Any]] = {}
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._heartbeat_tasks: dict[str, asyncio.Task[None]] = {}
        self._catalog: dict[str, dict[str, Any]] = {}
        self._poll_task: asyncio.Task[None] | None = None
        self._stagnation_task: asyncio.Task[None] | None = None
        self._challenge_completion_tasks: dict[str, asyncio.Task[Any]] = {}
        self._container_operation_lock = asyncio.Lock()
        self._container_locks: dict[str, asyncio.Lock] = {}
        self._closing = False
        self._hint_locks: dict[str, asyncio.Lock] = {}
        self._benchmark_unavailable: set[str] = set()
        # Keep this in the Supervisor so the requirement survives Runner and
        # Tool wrapper reconstruction while a controller is waiting.
        self._pausing = False
        self._shell_tasks: ShellTaskManager | None = None
        self._http_interactions: HttpProbeManager | None = None
        self._network_discovery: NetworkDiscoveryManager | None = None
        self._model_http_client: httpx.AsyncClient | None = None
        self._registries: dict[str, ToolRegistry] = {}
        self._skill_contexts: dict[str, SkillSessionContext] = {}
        self._solver_observers: dict[str, Any] = {}
        self._resources_closed: set[str] = set()
        self._cleanup_tasks: dict[str, asyncio.Task] = {}
        self._manager_cleanup_tasks: dict[tuple[str, str], asyncio.Task] = {}
        self._cleanup_operations: dict[str, dict[str, asyncio.Task]] = {}
        self._cleanup_deadlines: dict[str, float] = {}
        self._stopping_agents: set[str] = set()
        self._launch_locks: dict[str, asyncio.Lock] = {}
        self._challenge_locks: dict[str, asyncio.Lock] = {}

    async def run_chief(
        self,
        prompt: str,
        *,
        run_id: str | None = None,
        resume: bool = False,
    ) -> dict[str, Any]:
        chief_id = await self.prepare_chief(prompt, run_id=run_id, resume=resume)
        try:
            result = await self._tasks[chief_id]
            return (
                result if isinstance(result, dict) else self._ok({"agent_id": chief_id})
            )
        finally:
            await self.close()

    async def prepare_chief(
        self,
        prompt: str,
        *,
        run_id: str | None = None,
        resume: bool = False,
    ) -> str:
        if resume and self.settings.selected_challenge_codes is not None:
            raise ValueError("Resume cannot replace selected_challenge_codes")
        if not prompt.strip() and not resume:
            raise SubagentError("Chief prompt must not be empty")
        run_id = run_id or uuid4().hex
        await self._ensure_service(run_id)
        service = self._service()
        self.run_id = run_id
        self._claim_run_ownership()

        if resume:
            await self._prepare_resume(run_id)
            overview = await service.get_overview(run_id)
            if overview["run"]["status"] == "completed":
                raise SubagentError("completed runs cannot be resumed")
            chief = next(
                (item for item in overview["agents"] if item["role"] == "chief"), None
            )
            if chief is None:
                raise SubagentError("run does not contain a Chief Agent")
            self.chief_agent_id = chief["agent_id"]
            prompt = (await service.get_agent_runtime(run_id, self.chief_agent_id))[
                "agent"
            ]["initial_prompt"]
        else:
            if await service.run_exists(run_id):
                raise SubagentError("run_id already exists")
            await service.create_run(
                run_id,
                duration_minutes=self.duration_minutes,
                model=self.settings.llm_model,
                prompt=prompt,
                context_window_tokens=self.settings.context_budget.context_window_tokens,
                selected_challenge_codes=self.settings.selected_challenge_codes,
            )
            self.chief_agent_id = f"chief_{uuid4().hex}"
            await service.register_agent(
                run_id,
                agent_id=self.chief_agent_id,
                role="chief",
                initial_prompt=prompt,
            )
            await service.append_run_event(
                run_id,
                "llm_policy_configured",
                {
                    "model": self.settings.llm_model,
                    "thinking_enabled": True,
                    "reasoning_effort": "max",
                    "stream": False,
                    "completion_budgets": {
                        "chief": self.settings.context_budget.max_output_tokens(
                            "chief"
                        ),
                        "solver": self.settings.context_budget.max_output_tokens(
                            "solver"
                        ),
                        "worker": self.settings.context_budget.max_output_tokens(
                            "worker"
                        ),
                    },
                    "auxiliary_thinking_enabled": False,
                },
            )
        await service.append_run_event(
            run_id, "skill_catalog_ready", self.skill_catalog.metrics
        )
        await service.append_run_event(
            run_id,
            "solver_context_policy_configured",
            {
                "compact_tools": self.settings.compact_tools,
                "solver_observation": self.settings.solver_observation,
            },
        )

        runtime_prefix = Path(sys.prefix).resolve()
        runtime_python = runtime_prefix / "bin" / Path(sys.executable).name
        if not runtime_python.is_file():
            runtime_python = Path(sys.executable).resolve()
        toolchain = toolchain_for(self.toolchain_root)
        self._shell_tasks = ShellTaskManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            clock=service.clock,
            read_only_paths=(
                self.skill_catalog.root,
                Path(__file__).resolve().parents[2] / "tools" / "source",
                runtime_prefix,
                self.toolchain_root,
            ),
            environment={
                "AION_SKILLS_ROOT": str(self.skill_catalog.root),
                "AION_PYTHON": str(runtime_python),
                "AION_VENV_BIN": str(runtime_python.parent),
                "AION_TOOLCHAIN_ROOT": str(toolchain.root),
                "AION_TOOLCHAIN_BIN": str(toolchain.bin_dir),
            },
        )
        await self._shell_tasks.initialize(resume=resume)
        self._http_interactions = HttpProbeManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            resource_guard=(
                self.resource_controller.check_resource_work
                if self.resource_controller is not None
                else None
            ),
            disk_reserve_bytes=self.settings.disk_reserve_bytes,
            disk_reserve_percent=self.settings.disk_reserve_percent,
        )
        await self._http_interactions.initialize(resume=resume)
        self._network_discovery = NetworkDiscoveryManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            resource_guard=(
                self.resource_controller.check_resource_work
                if self.resource_controller is not None
                else None
            ),
        )
        await self._network_discovery.initialize(resume=resume)

        await self._sync_nodes()
        self._issue_capabilities()
        assert self.chief_agent_id is not None
        self.store = await AgentStateStore.open(
            service,
            run_id=run_id,
            agent_id=self.chief_agent_id,
            run_dir=self._run_dir(),
        )
        refreshed = await self.refresh_challenges(self.chief_agent_id)
        run = (await service.get_overview(run_id))["run"]
        if run["selected_challenge_codes"] is not None:
            if not refreshed.get("ok"):
                raise SubagentError("Selected challenges require a successful catalog refresh")
            await service.validate_selected_challenges(run_id)
        await self._launch_agent(self.chief_agent_id, resume=resume)
        if resume:
            await self._restart_challenge_agents()
        self._start_poller(self.chief_agent_id)
        self._start_stagnation_monitor()
        return self.chief_agent_id

    async def refresh_challenges(self, caller_id: str) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        synced = await self._sync_challenge_catalog()
        if not synced.get("ok"):
            return synced
        overview = await self._service().get_overview(self._run_id())
        live_challenge_agents = {
            item["unique_code"]: item["agent_id"]
            for item in overview["agents"]
            if item["role"] == "solver"
            and item.get("unique_code")
            and item["status"] not in self.TERMINAL_AGENT_STATES
        }
        pending_releases = []
        for challenge in synced["data"]["challenges"]:
            if (
                challenge["slot_occupied"]
                and (
                    challenge["is_completed"]
                    or challenge["work_status"] == "closed"
                    or (
                        challenge["work_status"] == "paused"
                        and (
                            challenge["container_status"] == "release_pending"
                            or challenge["platform_status"] == "close_requested"
                        )
                    )
                )
            ):
                self._schedule_challenge_completion(
                    challenge["unique_code"],
                    reason=(
                        "catalog_release_pending"
                        if challenge["work_status"] == "paused"
                        else "catalog_completed"
                    ),
                    exclude_agent_id=live_challenge_agents.get(
                        challenge["unique_code"]
                    ),
                    release_caller_id=caller_id,
                )
                pending_releases.append(challenge["unique_code"])

        # Recovery must settle stale release_pending records before the caller
        # can admit another challenge and consume a slot.
        pending_tasks = [
            task
            for code, task in self._challenge_completion_tasks.items()
            if code in pending_releases and not task.done()
        ]
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        values = await self._service().list_challenges(self._run_id())
        self._catalog = {item["unique_code"]: item for item in values}
        capacity = container_capacity_summary(values, limit=self.max_challenge_slots)
        sync = synced["data"]["sync"]
        if sync["capacity_changed"]:
            await self._service().append_agent_event(
                self._run_id(),
                caller_id,
                "container_capacity_reconciled",
                capacity,
            )
            LOGGER.info(
                "container_capacity_reconciled run_id=%s occupied_count=%s limit=%s occupied_codes=%s completed_pending_release_codes=%s",
                self._run_id(),
                capacity["occupied_count"],
                capacity["limit"],
                ",".join(capacity["occupied_codes"]),
                ",".join(capacity["completed_pending_release_codes"]),
            )
        return self._ok(
            {
                "challenges": values,
                "count": len(values),
                "container_capacity": capacity,
            }
        )

    async def _sync_challenge_catalog(self) -> dict[str, Any]:
        result = await self._benchmark_call("benchmark_list_challenges", {})
        if not result.get("ok"):
            return result
        data = result.get("data")
        if not isinstance(data, list):
            return self._error(
                "invalid_response",
                "Benchmark status was invalid",
                error_type="internal",
            )
        values = [dict(item) for item in data if isinstance(item, Mapping)]
        synced = await self._service().import_challenges(self._run_id(), values)
        persisted = synced.challenges
        self._catalog = {item["unique_code"]: item for item in persisted}
        return self._ok(
            {
                "challenges": persisted,
                "count": len(persisted),
                "sync": synced.model_dump(mode="json"),
            }
        )

    async def _ensure_challenge_container(
        self, caller_id: str, unique_code: str
    ) -> dict[str, Any]:
        async with self._container_operation_lock, self._container_locks.setdefault(unique_code, asyncio.Lock()):
            if self._closing:
                return self._error("runtime_stopping", "New containers are disabled during shutdown", error_type="conflict")
            gate = await self._service().challenge_start_gate(
                self._run_id(),
                unique_code,
                context=self._state_context(caller_id),
            )
            challenge = gate["challenge"]
            if challenge["is_completed"] or challenge["work_status"] == "closed":
                return self._error(
                    "challenge_completed",
                    "The challenge is already completed or closed",
                    error_type="conflict",
                )
            capacity = gate["container_capacity"]
            if not gate["allowed"]:
                LOGGER.warning(
                    "challenge_start_blocked run_id=%s unique_code=%s occupied_count=%s limit=%s occupied_codes=%s",
                    self._run_id(),
                    unique_code,
                    capacity["occupied_count"],
                    capacity["limit"],
                    ",".join(capacity["occupied_codes"]),
                )
                return self._error(
                    "challenge_slots_exhausted",
                    "No challenge slot is currently available",
                    error_type="resource",
                    detail={
                        "active_count": capacity["occupied_count"],
                        **capacity,
                    },
                )
            if challenge["slot_occupied"]:
                return self._ok({"container_status": challenge["container_status"]})
            result = await self._execute_operation(
                caller_id=caller_id,
                tool_name="benchmark_start_challenge",
                arguments={"unique_code": unique_code},
                unique_code=unique_code,
            )
            if result.get("ok"):
                await self._sync_challenge_catalog()
            return result

    async def _release_container_with_confirmation(
        self,
        *,
        owner: str,
        unique_code: str,
        reason: str,
        observed_status: str,
        event_prefix: str,
        failure_report: bool = False,
    ) -> dict[str, Any]:
        """Close one container and free its slot only after a fresh catalog read."""
        started = asyncio.get_running_loop().time()
        await self._service().append_agent_event(
            self._run_id(),
            owner,
            f"{event_prefix}_started",
            {
                "unique_code": unique_code,
                "observed_container_status": observed_status,
                "reason": reason,
            },
        )
        close_result: dict[str, Any] = self._error(
            "container_release_unconfirmed",
            "Container release was not confirmed",
            error_type="internal",
        )
        synced: dict[str, Any] = self._error(
            "catalog_sync_failed",
            "Container release could not be confirmed",
            error_type="internal",
        )
        attempts = 0
        for attempt in range(1, 4):
            attempts = attempt
            try:
                close_result = await self._execute_operation(
                    caller_id=owner,
                    tool_name="benchmark_close_challenge",
                    arguments={"unique_code": unique_code},
                    unique_code=unique_code,
                )
                # A 409/invalid_state can mean the platform already stopped
                # the container; always refresh before deciding whether to retry.
                synced = await self._sync_challenge_catalog()
            except Exception:
                LOGGER.warning(
                    "%s_operation_failed run_id=%s unique_code=%s attempt=%s",
                    event_prefix,
                    self._run_id(),
                    unique_code,
                    attempt,
                    exc_info=True,
                )
                close_result = self._error(
                    "benchmark_error",
                    "Container release failed",
                    error_type="internal",
                )
                synced = self._error(
                    "catalog_sync_failed",
                    "Container release could not be confirmed",
                    error_type="internal",
                )
            current = await self._challenge_record(unique_code)
            if synced.get("ok") is True and not current["slot_occupied"]:
                break
            if attempt < 3 and (
                self._is_transient_release_failure(close_result, synced)
                # The close may be accepted asynchronously. Keep the release
                # pending and retry until the catalog confirms a free slot.
                or (synced.get("ok") is True and current["slot_occupied"])
            ):
                await asyncio.sleep(0.5 if attempt == 1 else 1.0)
                continue
            break

        current = await self._challenge_record(unique_code)
        released = synced.get("ok") is True and not current["slot_occupied"]
        if not released:
            # Keep the durable state pending when the platform could not
            # confirm release.  Recovery will reconcile this record later.
            await self._service().mark_completed_container_release_pending(
                self._run_id(),
                unique_code,
                agent_id=owner or None,
            )
            current = await self._challenge_record(unique_code)
        error_code = None
        if not released:
            error_code = self._error_code(close_result)
            if error_code is None and not synced.get("ok"):
                error_code = self._error_code(synced) or "catalog_sync_failed"
            error_code = error_code or "container_release_unconfirmed"
        event_type = f"{event_prefix}_succeeded" if released else f"{event_prefix}_failed"
        payload: dict[str, Any] = {
            "unique_code": unique_code,
            "observed_container_status": observed_status,
            "container_status": current["container_status"],
            "reason": reason,
            "attempts": attempts,
            "duration_ms": int(
                (asyncio.get_running_loop().time() - started) * 1_000
            ),
        }
        if error_code is not None:
            payload["error_code"] = error_code
        await self._service().append_agent_event(
            self._run_id(), owner, event_type, payload
        )
        log = LOGGER.info if released else LOGGER.warning
        log(
            "%s run_id=%s unique_code=%s observed_container_status=%s container_status=%s reason=%s duration_ms=%s error_code=%s",
            event_type,
            self._run_id(),
            unique_code,
            observed_status,
            current["container_status"],
            reason,
            payload["duration_ms"],
            error_code or "",
        )
        if not released and failure_report:
            await self._service().publish_challenge_report(
                self._run_id(),
                sender_id=owner,
                unique_code=unique_code,
                report_type="challenge_status",
                status="paused_container_release_failed",
                payload={
                    "type": "paused_container_release_failed",
                    "unique_code": unique_code,
                    "attempts": attempts,
                    "error_code": error_code,
                    "slot_occupied": current["slot_occupied"],
                },
            )
        result = {
            "released": released,
            "attempts": attempts,
            "container_status": current["container_status"],
            "error_code": error_code,
        }
        if failure_report:
            result["retry_exhausted"] = attempts >= 3 and not released
        return result

    async def _release_completed_container(
        self,
        caller_id: str,
        unique_code: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._container_locks.setdefault(unique_code, asyncio.Lock()):
            challenge = await self._challenge_record(unique_code)
            if not challenge["is_completed"] and challenge["work_status"] != "closed":
                return {
                    "released": False,
                    "skipped": True,
                    "reason": "challenge_not_completed",
                }
            if not challenge["slot_occupied"]:
                return {
                    "released": True,
                    "skipped": True,
                    "container_status": challenge["container_status"],
                }

            await self._service().mark_completed_container_release_pending(
                self._run_id(),
                unique_code,
                agent_id=caller_id or None,
            )
            challenge = await self._challenge_record(unique_code)
            return await self._release_container_with_confirmation(
                owner=caller_id,
                unique_code=unique_code,
                reason=reason,
                observed_status=challenge["container_status"],
                event_prefix="completed_container_release",
            )

    async def release_paused_container(
        self,
        unique_code: str,
        *,
        reason: str = "chief_pause",
        caller_id: str | None = None,
    ) -> dict[str, Any]:
        """Close a paused target and count a slot free only after confirmation."""

        async with self._container_locks.setdefault(unique_code, asyncio.Lock()):
            challenge = await self._challenge_record(unique_code)
            if challenge["work_status"] != "paused" or challenge["is_completed"]:
                return {
                    "released": False,
                    "skipped": True,
                    "reason": "challenge_not_paused",
                }
            if not challenge["slot_occupied"]:
                return {
                    "released": True,
                    "skipped": True,
                    "container_status": challenge["container_status"],
                }
            owner = caller_id or self.chief_agent_id or ""
            await self._service().mark_completed_container_release_pending(
                self._run_id(),
                unique_code,
                agent_id=owner or None,
            )
            challenge = await self._challenge_record(unique_code)
            return await self._release_container_with_confirmation(
                owner=owner,
                unique_code=unique_code,
                reason=reason,
                observed_status=challenge["container_status"],
                event_prefix="paused_container_release",
                failure_report=True,
            )

    def _schedule_challenge_completion(
        self,
        unique_code: str,
        *,
        reason: str,
        exclude_agent_id: str | None,
        release_caller_id: str | None,
    ) -> None:
        existing = self._challenge_completion_tasks.get(unique_code)
        if existing is not None and not existing.done():
            return

        caller_id = release_caller_id or self.chief_agent_id or exclude_agent_id or ""

        async def converge() -> None:
            run = (await self._service().get_overview(self._run_id()))["run"]
            selected = run["selected_challenge_codes"]
            if selected is not None and unique_code not in selected:
                return
            await self.stop_challenge_work(
                unique_code,
                reason=reason,
                exclude_agent_id=exclude_agent_id,
            )
            challenge = await self._challenge_record(unique_code)
            if challenge["work_status"] == "paused" and not challenge["is_completed"]:
                await self.release_paused_container(
                    unique_code,
                    caller_id=caller_id,
                    reason=reason,
                )
            else:
                await self._release_completed_container(
                    caller_id,
                    unique_code,
                    reason=reason,
                )

        task = asyncio.create_task(converge(), name=f"aion-complete-{unique_code}")
        self._challenge_completion_tasks[unique_code] = task

        def completed(done: asyncio.Task[Any]) -> None:
            current = self._challenge_completion_tasks.get(unique_code)
            if current is done:
                self._challenge_completion_tasks.pop(unique_code, None)
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception:
                LOGGER.warning(
                    "challenge_completion_convergence_failed run_id=%s unique_code=%s",
                    self._run_id(),
                    unique_code,
                    exc_info=True,
                )

        task.add_done_callback(completed)

    async def launch_challenges(
        self,
        caller_id: str,
        unique_codes: list[str],
    ) -> dict[str, Any]:
        """Refresh once, then launch an ordered batch independently."""

        self._require_role(caller_id, "chief")
        refreshed = await self.refresh_challenges(caller_id)
        if not refreshed.get("ok"):
            return refreshed
        results: list[dict[str, Any]] = []
        for unique_code in unique_codes:
            result = await self.create_solver(caller_id, unique_code, refresh=False)
            results.append(
                {
                    "unique_code": unique_code,
                    **result,
                }
            )
        return self._ok(
            {
                "results": results,
                "started_count": sum(1 for item in results if item.get("ok") is True),
            }
        )

    async def _resume_with_hint(self, caller_id: str, unique_code: str, solver_id: str) -> None:
        claim = await self._service().claim_resume_hint(self._run_id(), unique_code, solver_id)
        if claim is None:
            return
        status = claim["decision"]
        error_code = None
        if status == "request":
            try:
                result = await self.request_hint_light(caller_id, unique_code, "stagnation_resume")
                error_code = self._error_code(result)
                if result.get("ok"):
                    status = "succeeded"
                elif error_code in {"hint_response_unavailable", "operation_indeterminate"}:
                    status = "uncertain"
                elif error_code == "hint_already_requested":
                    status = "reused"
                else:
                    status = "failed"
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status, error_code = "uncertain", type(exc).__name__
        await self._service().append_agent_event(
            self._run_id(), solver_id, "solver_resume_hint_result",
            {**claim, "status": status, "error_code": error_code},
        )

    async def request_hint_light(
        self,
        caller_id: str,
        unique_code: str,
        reason: str,
    ) -> dict[str, Any]:
        """Request a Hint using only remote hard rules and idempotency."""

        self._require_role(caller_id, "chief")
        if "get_hint" in self._benchmark_unavailable:
            return self._error(
                "hint_unavailable",
                "The benchmark does not expose a usable Hint operation",
                error_type="conflict",
            )
        challenge = await self._challenge_record(unique_code)
        if challenge["is_completed"] or challenge["work_status"] == "closed":
            return self._error(
                "challenge_inactive",
                "Hint cannot be requested for an inactive challenge",
                error_type="permission",
            )
        if challenge["hint_requested"]:
            return self._error(
                "hint_already_requested",
                "Only one hint may be requested for a challenge",
                error_type="conflict",
            )
        lock = self._hint_locks.setdefault(unique_code, asyncio.Lock())
        async with lock:
            challenge = await self._challenge_record(unique_code)
            if challenge["hint_requested"]:
                return self._error(
                    "hint_already_requested",
                    "Only one hint may be requested for a challenge",
                    error_type="conflict",
                )
            operations = await self._service().list_operations(self._run_id(), unique_code=unique_code)
            if any(op["operation_type"] == "benchmark_get_hint" and
                   (op["status"] in {"started", "indeterminate"} or
                    op.get("result_code") == "hint_response_unavailable") for op in operations):
                return self._error("hint_response_unavailable", "Previous Hint outcome is uncertain; do not retry",
                                   error_type="conflict")
            result = await self._execute_operation(
                caller_id=caller_id,
                tool_name="benchmark_get_hint",
                arguments={"unique_code": unique_code},
                unique_code=unique_code,
            )
        if result.get("ok"):
            hint_payload = {
                "type": "hint_received",
                "unique_code": unique_code,
                "reason": reason,
                "hint": (result.get("data") or {}).get("hint"),
            }
            await self._service().publish_challenge_report(
                self._run_id(),
                sender_id=caller_id,
                unique_code=unique_code,
                report_type="hint",
                status="received",
                payload=hint_payload,
            )
            challenge_agent = await self._find_agent("solver", unique_code=unique_code)
            if challenge_agent is not None:
                await self._service().publish_control_report(
                    self._run_id(),
                    sender_id=caller_id,
                    recipient_id=challenge_agent["agent_id"],
                    unique_code=unique_code,
                    report_type="hint",
                    status="received",
                    payload=hint_payload,
                )

        return result

    async def wait_agent(self, agent_id: str) -> dict[str, Any]:
        task = self._tasks.get(agent_id)
        if task is None:
            raise SubagentError("Agent task is not running")
        result = await task
        return result if isinstance(result, dict) else {"agent_id": agent_id}

    async def wait_for_agents(self) -> None:
        """Wait on durable lifecycle signals until the complete Agent tree stops."""

        signal_key = self._service().run_signal_key(self._run_id())
        cursor = await self._service().notifier.current(signal_key)
        while True:
            overview = await self._service().get_overview(self._run_id())
            agents_terminal = all(
                item["status"] in self.TERMINAL_AGENT_STATES
                for item in overview["agents"]
            )
            tasks_done = all(task.done() for task in self._tasks.values()) and all(
                task.done() for task in self._challenge_completion_tasks.values()
            )
            if agents_terminal and tasks_done:
                return
            cursor = await self._service().notifier.wait(
                signal_key, cursor, self.CONTROLLER_SAFETY_WAKE_SECONDS
            )

    async def submit_flag(
        self, caller_id: str, flag: str
    ) -> dict[str, Any] | ToolDispatchOutcome:
        node = self._require_role(caller_id, "solver")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Solver is not bound to a challenge",
            )
        result = await self._execute_operation(
            caller_id=caller_id,
            tool_name="benchmark_submit_flag",
            arguments={"unique_code": node.unique_code, "flag": flag},
            unique_code=node.unique_code,
        )
        if not result.get("ok") and self._error_code(result) == "duplicate":
            # A duplicate is not a reason to submit again.  One catalog
            # read is enough to learn whether another Agent already
            # completed the Challenge.
            await self._sync_challenge_catalog()
        if result.get("ok"):
            await self._sync_challenge_catalog()
        current = await self._challenge_record(node.unique_code)
        completed = bool(current["is_completed"])
        if result.get("ok") and isinstance(result.get("data"), Mapping):
            result = {
                **result,
                "data": {
                    **dict(result["data"]),
                    "challenge_completed": completed,
                },
            }
        elif (
            not result.get("ok")
            and self._error_code(result) == "duplicate"
            and completed
        ):
            result = self._ok(
                {
                    "correct": None,
                    "duplicate": True,
                    "challenge_completed": True,
                }
            )
        if result.get("ok") and completed:
            release_status = "pending" if current["slot_occupied"] else "released"
            result = {
                **result,
                "data": {
                    **dict(result.get("data") or {}),
                    "challenge_completed": True,
                    "container_release_status": release_status,
                },
            }
            await self._service().finish_agent(
                self._run_id(), caller_id, status="completed",
                final_report=submission_report(node.unique_code, result, completed),
            )
            self._close_agent_admission(caller_id)
            self._schedule_challenge_completion(
                node.unique_code,
                reason="all_flags_submitted",
                exclude_agent_id=caller_id,
                release_caller_id=self.chief_agent_id or caller_id,
            )
        if self.chief_agent_id is not None:
            await self._service().publish_control_report(
                self._run_id(),
                sender_id=caller_id,
                recipient_id=self.chief_agent_id,
                unique_code=node.unique_code,
                report_type="challenge_status",
                status="flag_submitted",
                payload=submission_report(node.unique_code, result, completed),
            )
        if result.get("ok") and completed:
            return ToolDispatchOutcome(result, yield_session=True)
        return result

    async def read_evidence(
        self,
        caller_id: str,
        evidence_ref: str,
        *,
        offset: int = 0,
        limit_chars: int = 8_000,
    ) -> dict[str, Any]:
        node = self.nodes.get(caller_id)
        if node is None or node.role not in {"solver", "worker"}:
            raise SubagentError("Agent role is not authorized for this operation")
        return self._ok(
            await self._service().read_evidence(
                self._run_id(),
                self._state_context(caller_id),
                evidence_ref,
                offset=offset,
                limit_chars=limit_chars,
            )
        )

    async def resume(self, run_id: str) -> dict[str, Any]:
        await self._ensure_service(run_id)
        self.run_id = run_id
        self._claim_run_ownership()
        await self._prepare_resume(run_id)
        if self.chief_agent_id:
            await self.refresh_challenges(self.chief_agent_id)
        return self._ok(
            {
                "run_id": run_id,
                "agents": (await self._service().get_overview(run_id))["agents"],
            }
        )

    def _claim_run_ownership(self) -> None:
        if self._run_ownership is None:
            try:
                self._run_ownership = RunOwnership(self._service().db.path)
            except StateConflict:
                self._ownership_conflict = True
                raise
            self._ownership_conflict = False

    def _release_run_ownership(self) -> None:
        if self._run_ownership is not None:
            self._run_ownership.close()
            self._run_ownership = None

    async def close(self, *, deadline: float | None = None) -> None:
        from .shutdown import shutdown_supervisor
        await shutdown_supervisor(self, preserve_run=False,
                                  deadline=deadline or asyncio.get_running_loop().time() + 30)

    async def _finish_run_managers(self, operation: str, *, deadline: float | None = None) -> None:
        from .lifecycle import AGENT_CLEANUP_SECONDS

        tasks = {}
        for attribute in ("_http_interactions", "_network_discovery", "_shell_tasks"):
            manager = getattr(self, attribute)
            if manager is None:
                continue
            key = (attribute, operation)
            task = self._manager_cleanup_tasks.get(key)
            if task is None or task.done():
                task = asyncio.create_task(
                    getattr(manager, operation)(), name=f"aion-{attribute}-{operation}"
                )
                self._manager_cleanup_tasks[key] = task
            tasks[attribute] = task
        if tasks:
            await asyncio.wait(list(tasks.values()), timeout=max(0, deadline - asyncio.get_running_loop().time()) if deadline is not None else AGENT_CLEANUP_SECONDS)
        failures = []
        for attribute, task in tasks.items():
            if not task.done():
                task.cancel()
                error, message = (
                    "TimeoutError",
                    "Run resource cleanup exceeded its deadline",
                )
            elif task.cancelled():
                error, message = "CancelledError", "Run resource cleanup was cancelled"
            elif task.exception() is not None:
                error, message = (
                    type(task.exception()).__name__,
                    str(task.exception())[:500],
                )
            else:
                setattr(self, attribute, None)
                self._manager_cleanup_tasks.pop((attribute, operation), None)
                continue
            failures.append({"resource": attribute, "error": error, "message": message})
        if failures:
            await self._service().append_agent_event(
                self._run_id(),
                self.chief_agent_id,
                "agent_resource_cleanup_failed",
                {"failures": failures},
            )

    async def pause(self, *, deadline: float | None = None) -> None:
        """Cancel live work while preserving resumable orchestration state."""

        from .shutdown import shutdown_supervisor
        await shutdown_supervisor(self, preserve_run=True,
                                  deadline=deadline or asyncio.get_running_loop().time() + 30)

    def _shared_model_http_client(self) -> httpx.AsyncClient:
        client = self._model_http_client
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(90.0, connect=20.0),
                limits=httpx.Limits(
                    max_connections=32,
                    max_keepalive_connections=16,
                ),
            )
            self._model_http_client = client
        return client

    async def _close_model_http_client(self) -> None:
        client = self._model_http_client
        self._model_http_client = None
        if client is not None and not client.is_closed:
            await client.aclose()

    async def _settle_controller(
        self,
        agent_id: str,
        role: AgentRole,
        result: AgentSessionResult | Any,
    ) -> bool:
        overview = await self._service().get_overview(self._run_id())
        agent = next(
            item for item in overview["agents"] if item["agent_id"] == agent_id
        )
        if agent["status"] in self.TERMINAL_AGENT_STATES:
            return True
        if overview["run"]["status"] != "active":
            return True
        report = self._session_report(result)
        if role == "solver":
            challenge = next(
                item
                for item in overview["challenges"]
                if item["unique_code"] == agent["unique_code"]
            )
            if challenge["is_completed"] or challenge["work_status"] == "closed":
                await self._service().finish_agent(
                    self._run_id(), agent_id,
                    status="completed" if challenge["is_completed"] else "stopped",
                    final_report=report,
                )
                return True
            return agent["status"] in {"paused", "stopping"}

        if agent["status"] in {"paused", "stopping"}:
            return True
        run = overview["run"]
        deadline_reached = aware(self._service().clock()) >= aware(
            datetime.fromisoformat(run["deadline_at"])
        )
        selected = run["selected_challenge_codes"]
        challenges = [
            item for item in overview["challenges"]
            if selected is None or item["unique_code"] in selected
        ]
        scope_present = selected is None or set(selected) == {
            item["unique_code"] for item in challenges
        }
        challenges_terminal = scope_present and bool(challenges) and all(
            item["is_completed"] or (selected is None and item["work_status"] == "closed")
            for item in challenges
        )
        descendants_terminal = all(
            item["agent_id"] == agent_id or item["status"] in self.TERMINAL_AGENT_STATES
            for item in overview["agents"]
        )
        if not deadline_reached and not (challenges_terminal and descendants_terminal):
            return False
        if not deadline_reached:
            # Terminal state is committed before the task's receipt and cleanup finish.
            pending = [
                task for child_id, task in self._tasks.items()
                if child_id != agent_id and not task.done()
            ] + list(self._challenge_completion_tasks.values())
            if pending:
                await asyncio.gather(*(asyncio.shield(task) for task in pending), return_exceptions=True)
            overview = await self._service().get_overview(self._run_id())
            if overview["run"]["status"] != "active":
                return True
            if selected is not None and any(
                not item["is_completed"] for item in overview["challenges"]
                if item["unique_code"] in selected
            ):
                return False
            if any(
                item["slot_occupied"] for item in overview["challenges"]
                if selected is None or item["unique_code"] in selected
            ) or any(
                child_id != agent_id and child_id not in self._resources_closed
                for child_id in self._tasks
            ):
                return False
        if deadline_reached:
            await self._stop_descendants(agent_id)
            await self.release_targets(reason="deadline", permanent=True)
        report = {
            **report,
            "completion_reason": (
                "deadline" if deadline_reached else
                "selected_challenges_completed" if selected is not None else
                "catalog_terminal"
            ),
        }
        await self._service().finish_agent(
            self._run_id(), agent_id, status="completed", final_report=report
        )
        await self._service().finish_run(self._run_id(), "completed", report=report)
        return True

    async def _remaining_run_seconds(self) -> float:
        overview = await self._service().get_overview(self._run_id())
        deadline = aware(datetime.fromisoformat(overview["run"]["deadline_at"]))
        return max(0.0, (deadline - aware(self._service().clock())).total_seconds())

    async def _stop_descendants(self, root_id: str) -> None:
        overview = await self._service().get_overview(self._run_id())
        descendants = [
            item for item in overview["agents"] if item["agent_id"] != root_id
        ]
        for role in ("worker", "solver"):
            await asyncio.gather(
                *(
                    self._stop_agent(item["agent_id"])
                    for item in descendants
                    if item["role"] == role
                    and item["status"] not in self.TERMINAL_AGENT_STATES
                ),
            )

    @staticmethod
    def _session_report(result: AgentSessionResult | Any) -> dict[str, Any]:
        if isinstance(result, AgentSessionResult):
            return {
                "final": result.final,
                "last_event_sequence": result.last_event_sequence,
                "yield_reason": result.yield_reason,
            }
        if isinstance(result, Mapping):
            return dict(result)
        return {"final": str(result)}

    async def _heartbeat_loop(self, agent_id: str) -> None:
        samples = 0
        event_every = max(
            1,
            round(
                self.HEARTBEAT_EVENT_INTERVAL_SECONDS / self.HEARTBEAT_INTERVAL_SECONDS
            ),
        )
        while True:
            await asyncio.sleep(self.HEARTBEAT_INTERVAL_SECONDS)
            samples += 1
            await self._service().heartbeat(
                self._run_id(),
                agent_id,
                self._state_context(agent_id),
                sample_event=samples % event_every == 0,
            )

    async def _execute_operation(
        self,
        *,
        caller_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        unique_code: str,
    ) -> dict[str, Any]:
        before = None
        if tool_name in {
            "benchmark_start_challenge",
            "benchmark_get_hint",
            "benchmark_submit_flag",
            "benchmark_close_challenge",
        }:
            try:
                before = await self._challenge_record(unique_code)
            except StateError:
                before = None
        operations = await self._service().list_operations(self._run_id())
        if any(
            item["status"] == "indeterminate"
            and item["operation_type"] == tool_name
            and item["unique_code"] == unique_code
            for item in operations
        ):
            return self._error(
                "operation_indeterminate",
                "Read-only synchronization is required before this operation can be retried",
                error_type="conflict",
            )
        try:
            operation_id = await self._service().mark_operation_started(
                self._run_id(),
                tool_name,
                agent_id=caller_id,
                unique_code=unique_code,
                arguments=arguments,
            )
        except StateConflict as exc:
            return self._error(exc.code, exc.message, error_type="conflict")
        try:
            if self.benchmark is None:
                raise RuntimeError("benchmark unavailable")
            result = await self._benchmark_execute(
                tool_name, arguments, caller_id=caller_id
            )
        except Exception:
            if tool_name in {"benchmark_submit_flag", "benchmark_get_hint"}:
                await self._service().mark_operation_indeterminate(
                    self._run_id(),
                    operation_id,
                    result_payload={"error": "benchmark_transport_error"},
                )
                return self._error(
                    "operation_indeterminate",
                    "Remote operation outcome is unknown; synchronize before further action",
                    error_type="conflict",
                )
            await self._service().fail_operation(
                self._run_id(),
                operation_id,
                error_code="benchmark_error",
                error_message="Benchmark operation failed",
            )
            return self._error(
                "benchmark_error",
                "Benchmark operation failed",
                error_type="internal",
            )
        await self._record_benchmark_events(result)
        transport_uncertain = (
            tool_name in {"benchmark_submit_flag", "benchmark_get_hint"}
            and not result.get("ok")
            and (
                self._error_code(result)
                in {
                    "timeout",
                    "http_error",
                    "transport_error",
                    "invalid_tool_result",
                    "network_error",
                    "benchmark_error",
                    "execution_error",
                }
                or (
                    isinstance(result.get("error"), Mapping)
                    and isinstance(result["error"].get("details"), Mapping)
                    and isinstance(result["error"]["details"].get("status_code"), int)
                    and result["error"]["details"]["status_code"] >= 500
                )
            )
        )
        if not result.get("ok") and (
            self._is_ambiguous_benchmark_response(result) or transport_uncertain
        ):
            if tool_name == "benchmark_get_hint":
                # A successful Hint request may already have consumed score even
                # when its response cannot be decoded. Never request it again.
                await self._service().complete_operation(
                    self._run_id(),
                    operation_id,
                    result_code="hint_response_unavailable",
                    result_payload=result,
                    challenge_updates={
                        "hint_requested": True,
                    },
                )
                return self._error(
                    "hint_response_unavailable",
                    "The Hint request may have succeeded but its response could not be decoded",
                    error_type="execution",
                    detail={"retry_allowed": False},
                )
            reconciled = await self._reconcile_ambiguous_operation(
                tool_name,
                unique_code,
                before,
            )
            if reconciled is not None:
                result = reconciled
            else:
                await self._service().mark_operation_indeterminate(
                    self._run_id(),
                    operation_id,
                    result_payload=result,
                )
                await self._append_benchmark_event(
                    "benchmark_operation_indeterminate",
                    unique_code=unique_code,
                    operation=tool_name,
                )
                return self._error(
                    "operation_indeterminate",
                    "The remote operation may have executed but could not be confirmed",
                    error_type="conflict",
                    detail={"retry_allowed": False},
                )
        if not result.get("ok"):
            if self._is_benchmark_capability_unavailable(result):
                await self._mark_benchmark_capability_unavailable(tool_name)
            code = self._error_code(result) or "benchmark_rejected"
            message = self._error_message(result) or "Benchmark operation was rejected"
            operation_secrets = (
                (str(arguments["flag"]),)
                if isinstance(arguments.get("flag"), str)
                else ()
            )
            await self._service().fail_operation(
                self._run_id(),
                operation_id,
                error_code=code,
                error_message=str(redact_value(message, secrets=operation_secrets)),
                result_payload=redact_value(result, secrets=operation_secrets),
            )
            return result
        operation_secrets = (
            (str(arguments["flag"]),) if isinstance(arguments.get("flag"), str) else ()
        )
        await self._service().complete_operation(
            self._run_id(),
            operation_id,
            result_code=self._error_code(result),
            result_payload=redact_value(result, secrets=operation_secrets),
            challenge_updates=await self._operation_challenge_updates(
                tool_name, unique_code, result
            ),
        )
        return result

    @staticmethod
    def _is_ambiguous_benchmark_response(result: Mapping[str, Any]) -> bool:
        if result.get("ok") is not False:
            return False
        error = result.get("error")
        if not isinstance(error, Mapping) or error.get("code") != "invalid_response":
            return False
        details = error.get("details")
        if not isinstance(details, Mapping):
            return False
        status_code = details.get("status_code")
        return isinstance(status_code, int) and 200 <= status_code < 300

    @staticmethod
    def _is_benchmark_capability_unavailable(result: Mapping[str, Any]) -> bool:
        if result.get("ok") is not False:
            return False
        error = result.get("error")
        if not isinstance(error, Mapping):
            return False
        details = error.get("details")
        status_code = (
            details.get("status_code") if isinstance(details, Mapping) else None
        )
        return status_code in {404, 405, 501}

    async def _mark_benchmark_capability_unavailable(self, tool_name: str) -> None:
        operation = tool_name.removeprefix("benchmark_")
        self._benchmark_unavailable.add(operation)

    def benchmark_capability_available(self, operation: str) -> bool:
        return operation not in self._benchmark_unavailable

    async def _reconcile_ambiguous_operation(
        self,
        tool_name: str,
        unique_code: str,
        before: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Use bounded read-only catalog sync to confirm a malformed 2xx write."""

        for attempt in range(3):
            synced = await self._sync_challenge_catalog()
            if synced.get("ok"):
                after = await self._challenge_record(unique_code)
                if (
                    tool_name == "benchmark_start_challenge"
                    and container_slot_occupied(after.get("container_status"))
                ):
                    return self._ok(
                        {
                            "unique_code": unique_code,
                            "container_addr": list(after.get("container_addr") or []),
                            "reconciled": True,
                        }
                    )
                if (
                    tool_name == "benchmark_close_challenge"
                    and not container_slot_occupied(after.get("container_status"))
                ):
                    return self._ok(
                        {
                            "unique_code": unique_code,
                            "closed": True,
                            "reconciled": True,
                        }
                    )
                if tool_name == "benchmark_submit_flag" and before is not None:
                    before_count = int(before.get("correct_flag_count") or 0)
                    after_count = int(after.get("correct_flag_count") or 0)
                    if after_count > before_count or (
                        bool(after.get("is_completed"))
                        and not bool(before.get("is_completed"))
                    ):
                        return self._ok(
                            {
                                "correct": None,
                                "awarded": None,
                                "correct_flag_count": after_count,
                                "total_flag_count": int(after.get("flag_count") or 0),
                                "challenge_completed": bool(after.get("is_completed")),
                                "reconciled": True,
                            }
                        )
            if attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
        return None

    async def _append_benchmark_event(self, event_type: str, **payload: Any) -> None:
        """Expose adapter recovery metadata without making it authoritative."""

        if self.run_id is None or self.chief_agent_id is None:
            return
        await self._service().append_agent_event(
            self._run_id(), self.chief_agent_id, event_type, payload
        )

    async def _record_benchmark_events(self, result: Mapping[str, Any]) -> None:
        """Persist adapter metadata without persisting untrusted response bodies."""

        warnings = result.get("warnings")
        if not isinstance(warnings, list):
            error = result.get("error")
            details = error.get("details") if isinstance(error, Mapping) else None
            warnings = (
                details.get("benchmark_events")
                if isinstance(details, Mapping)
                else None
            )
        if not isinstance(warnings, list):
            return
        for warning in warnings:
            if not isinstance(warning, Mapping):
                continue
            event_type = warning.get("code")
            details = warning.get("details")
            if not isinstance(event_type, str) or not event_type.startswith(
                "benchmark_"
            ):
                continue
            payload = dict(details) if isinstance(details, Mapping) else {}
            await self._append_benchmark_event(event_type, **payload)

    async def _operation_challenge_updates(
        self,
        tool_name: str,
        unique_code: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
        if tool_name == "benchmark_start_challenge":
            return {
                "platform_status": "started",
                "container_status": "running",
                "work_status": "active",
                "container_addr": list(data.get("container_addr") or []),
            }
        if tool_name == "benchmark_get_hint":
            return {"hint_requested": True}
        if tool_name == "benchmark_close_challenge":
            current = await self._challenge_record(unique_code)
            return {
                "platform_status": "close_requested",
                "container_status": "release_pending",
                "work_status": (
                    "completed"
                    if current["is_completed"]
                    else "closed" if current["work_status"] != "paused" else "paused"
                ),
            }
        if tool_name == "benchmark_submit_flag":
            current = await self._challenge_record(unique_code)
            total_value = data.get("total_flag_count", current["flag_count"])
            try:
                total_count = int(total_value)
            except (TypeError, ValueError):
                total_count = int(current["flag_count"] or 0)
            correct_value = data.get(
                "correct_flag_count", current["correct_flag_count"]
            )
            try:
                correct_count = int(correct_value)
            except (TypeError, ValueError):
                correct_count = int(current["correct_flag_count"] or 0)
            updates: dict[str, Any] = {
                "flag_count": total_count,
                "correct_flag_count": correct_count,
            }
            if (
                bool(data.get("correct"))
                and correct_count > current["correct_flag_count"]
            ):
                updates["progress_kind"] = "flag_accepted"
            return updates
        return {}

    async def _benchmark_call(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if self.benchmark is None:
            return self._error(
                "benchmark_unavailable",
                "Benchmark tools are not configured",
                error_type="internal",
            )
        try:
            result = await self._benchmark_execute(name, arguments)
        except Exception:
            return self._error(
                "benchmark_error", "Benchmark operation failed", error_type="internal"
            )
        if isinstance(result, Mapping):
            normalized = dict(result)
            await self._record_benchmark_events(normalized)
            return normalized
        return self._error(
            "invalid_response",
            "Benchmark operation returned invalid data",
            error_type="internal",
        )

    async def _benchmark_execute(
        self, name: str, arguments: Mapping[str, Any], *, caller_id: str | None = None
    ) -> dict[str, Any]:
        if self.benchmark is None:
            raise RuntimeError("benchmark unavailable")

        async def record_model_call(event_type, payload):
            await self._service().append_agent_event(
                self._run_id(), caller_id or self.chief_agent_id, event_type, payload
            )

        token = current_model_event_writer.set(record_model_call)
        try:
            calls = await ToolExecutor(ToolRegistry([self.benchmark])).execute(
                [
                    {
                        "id": f"internal-{name}",
                        "function": {
                            "name": name,
                            "arguments": json.dumps(arguments, ensure_ascii=False),
                        },
                    }
                ]
            )
        finally:
            current_model_event_writer.reset(token)
        result = calls[0].result
        if not isinstance(result, Mapping):
            raise RuntimeError("invalid benchmark response")
        return dict(result)

    async def _restart_challenge_agents(self) -> None:
        overview = await self._service().get_overview(self._run_id())
        challenges = {
            challenge["unique_code"]: challenge
            for challenge in overview.get("challenges", [])
        }
        for agent in overview["agents"]:
            if agent["role"] != "solver":
                continue

            unique_code = agent.get("unique_code")
            challenge = challenges.get(unique_code)
            if not challenge:
                LOGGER.warning(
                    "Skipping challenge agent restart without challenge state "
                    "run_id=%s agent_id=%s unique_code=%s",
                    self._run_id(),
                    agent["agent_id"],
                    unique_code,
                )
                continue

            # A service pause stops the Solver model session, but must not
            # turn an unfinished challenge into a terminal controller. Resume
            # every unfinished challenge, including one whose persisted agent
            # status is stopped, while completed/closed challenges stay done.
            if challenge.get("is_completed") or challenge.get("work_status") == "closed":
                await self._settle_controller(
                    agent["agent_id"], "solver", {"reason": "challenge_ended_before_resume"}
                )
                await self._finish_agent_resources(agent["agent_id"])
                continue
            if challenge.get("work_status") == "paused":
                continue

            previous_status = agent.get("status")
            caller_id = self.chief_agent_id or agent.get("parent_id")
            if not caller_id:
                LOGGER.warning(
                    "Challenge agent restart deferred without Chief "
                    "run_id=%s agent_id=%s unique_code=%s",
                    self._run_id(),
                    agent["agent_id"],
                    unique_code,
                )
                continue
            ensured = await self._ensure_challenge_container(caller_id, unique_code)
            if not ensured.get("ok"):
                LOGGER.warning(
                    "Challenge agent restart deferred because container is unavailable "
                    "run_id=%s agent_id=%s unique_code=%s reason=%s",
                    self._run_id(),
                    agent["agent_id"],
                    unique_code,
                    ensured.get("error_code"),
                )
                continue

            await self._service().reset_strategy_for_resume(
                self._run_id(), unique_code, agent["agent_id"], recovery=True
            )
            await self._resume_with_hint(caller_id, unique_code, agent["agent_id"])
            await self._launch_agent(agent["agent_id"], resume=True)
            await self._service().append_agent_event(
                self._run_id(),
                agent["agent_id"],
                "challenge_agent_restarted",
                {
                    "unique_code": unique_code,
                    "reason": "resume_active_challenge",
                    "previous_status": previous_status,
                },
            )
            LOGGER.info(
                "Challenge agent restarted for unfinished challenge "
                "run_id=%s agent_id=%s unique_code=%s previous_status=%s",
                self._run_id(),
                agent["agent_id"],
                unique_code,
                previous_status,
            )

    def _start_poller(self, chief_id: str) -> None:
        if self.catalog_reconcile_interval_seconds <= 0 or self._poll_task is not None:
            return

        async def poll() -> None:
            while True:
                await asyncio.sleep(self.catalog_reconcile_interval_seconds)
                try:
                    await self.refresh_challenges(chief_id)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOGGER.warning(
                        "challenge_catalog_poll_failed run_id=%s error_type=%s",
                        self._run_id(),
                        type(exc).__name__,
                    )

        self._poll_task = asyncio.create_task(poll(), name="aion-chief-poller")

    def _start_stagnation_monitor(self) -> None:
        if self._stagnation_task is not None:
            return
        policy = self.settings.stagnation_policy

        async def monitor() -> None:
            while True:
                await asyncio.sleep(policy.poll_interval_seconds)
                try:
                    actions = await self._service().scan_stagnation(
                        self._run_id(), policy
                    )
                    for action in sorted(actions, key=lambda item: item["kind"] != "rotate"):
                        code = action["unique_code"]
                        if action["kind"] == "strategy_reset":
                            runner = self._runners.get(action["solver_id"])
                            if runner is not None:
                                runner.request_strategy_reset()
                            continue
                        if action["kind"] == "alternate_worker":
                            worker = await self._service().create_stagnation_worker(
                                self._run_id(),
                                unique_code=code,
                                solver_id=action["solver_id"],
                                timeout_seconds=policy.worker_timeout_seconds,
                            )
                            if worker is None:
                                continue
                            await self._sync_nodes()
                            self._issue_capabilities()
                            try:
                                await self._launch_agent(worker["agent_id"])
                            except Exception as exc:
                                cleanup = await self._finish_agent_resources(worker["agent_id"])
                                await self._service().append_agent_event(self._run_id(), worker["agent_id"], "worker_resource_cleanup", {
                                    "resource_cleanup_status": "closed" if cleanup["ok"] else "release_pending", "failures": cleanup.get("failures", [])})
                                await self._service().finalize_worker_runtime(
                                    self._run_id(),
                                    worker["agent_id"],
                                    self._state_context(worker["agent_id"]),
                                    status="failed", summary="Worker 启动失败", error_code="worker_start_failed", error_stage="launch",
                                    termination_reason="worker_start_failed", owned_resources_closed=cleanup["ok"],
                                    resource_cleanup_status="closed" if cleanup["ok"] else "release_pending",
                                    allow_inactive=True,
                                )
                            continue
                        if action["kind"] == "rotate":
                            current = await self._challenge_record(code)
                            if (
                                current["version"] != action["challenge_version"]
                                or current["stagnation_stage"] != "rotation_due"
                            ):
                                continue
                            result = await self.pause_challenges(
                                self.chief_agent_id,
                                [code],
                                reason="stagnation_timeout",
                                release_container=True,
                                reason_code="stagnation_timeout",
                            )
                            await self._service().append_agent_event(
                                self._run_id(),
                                self.chief_agent_id,
                                "stagnation_rotation_completed",
                                {
                                    "unique_code": code,
                                    "result": result,
                                    "strategy_revision": action["strategy_revision"],
                                },
                            )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOGGER.warning(
                        "stagnation_monitor_failed run_id=%s error_type=%s",
                        self._run_id(),
                        type(exc).__name__,
                    )

        self._stagnation_task = asyncio.create_task(
            monitor(), name="aion-stagnation-monitor"
        )

    async def _stop_all(self) -> None:
        overview = await self._service().get_overview(self._run_id())
        await asyncio.gather(
            *(self._stop_agent(item["agent_id"]) for item in overview["agents"]),
        )

    async def _pause_all(self) -> None:
        overview = await self._service().get_overview(self._run_id())
        await asyncio.gather(
            *(
                self._stop_agent(
                    a["agent_id"], reason="runtime paused", pause=a["role"] != "worker"
                )
                for a in overview["agents"]
            )
        )

    async def launch_http_work(
        self, interaction_id: str, phase: str, *, work_id: str
    ) -> None:
        if self._http_interactions is None:
            raise SubagentError("HTTP interaction manager is not initialized")
        await self._http_interactions.launch_work(
            interaction_id, phase, work_id=work_id
        )

    async def launch_network_work(self, task_id: str, *, work_id: str) -> None:
        if self._network_discovery is None:
            raise SubagentError("Network discovery manager is not initialized")
        await self._network_discovery.launch_queued(task_id, work_id=work_id)

    async def _ensure_service(self, run_id: str) -> None:
        expected_database = (self.run_root / run_id / "state.sqlite3").resolve()
        if self.state_service.db.path != expected_database:
            raise SubagentError("StateService is not bound to the requested run")
        await self.state_service.initialize()

    def _service(self) -> StateService:
        return self.state_service

    def _run_id(self) -> str:
        if self.run_id is None:
            raise SubagentError("Agent run is not initialized")
        return self.run_id

    def _run_dir(self) -> Path:
        return self.run_root / self._run_id()

    async def _sync_nodes(self) -> None:
        if self.run_id is None:
            return
        overview = await self._service().get_overview(self._run_id())
        self.nodes = {
            a["agent_id"]: AgentNode(
                agent_id=a["agent_id"],
                role=a["role"],
                mode=a["mode"],
                parent_id=a["parent_id"],
                unique_code=a["unique_code"],
                status=a["status"],
                sidecar_path=str(self._run_dir() / "agents" / a["agent_id"]),
                mission=a["mission"],
                timeout_seconds=a["timeout_seconds"],
                last_report_sequence=a["last_report_sequence"],
                last_heartbeat_at=a.get("last_heartbeat_at"),
                last_model_activity_at=a.get("last_model_activity_at"),
                last_tool_activity_at=a.get("last_tool_activity_at"),
                waiting_sources=a.get("waiting_sources", []),
            )
            for a in overview["agents"]
        }

    def _issue_capabilities(self, agents: list[dict[str, Any]] | None = None) -> None:
        values = agents
        if values is None:
            values = [
                {
                    "agent_id": node.agent_id,
                    "role": node.role,
                    "unique_code": node.unique_code,
                }
                for node in self.nodes.values()
            ]
        for item in values:
            self._state_capabilities[item["agent_id"]] = self.capability_registry.issue(
                self._run_id(),
                item["agent_id"],
                item["role"],
                item.get("unique_code"),
            ).context

    def _state_context(self, agent_id: str) -> CapabilityContext:
        context = self._state_capabilities.get(agent_id)
        if context is None:
            raise SubagentError("state capability is not available")
        return context

    def _require_role(self, agent_id: str, role: AgentRole) -> AgentNode:
        node = self.nodes.get(agent_id)
        if node is None or node.role != role:
            raise SubagentError("Agent role is not authorized for this operation")
        return node

    async def _find_agent(
        self, role: AgentRole, *, unique_code: str | None = None
    ) -> dict[str, Any] | None:
        overview = await self._service().get_overview(self._run_id())
        return next(
            (
                item
                for item in overview["agents"]
                if item["role"] == role
                and (unique_code is None or item["unique_code"] == unique_code)
            ),
            None,
        )

    async def _challenge_record(self, unique_code: str | None) -> dict[str, Any]:
        if not unique_code:
            raise SubagentError("Agent is not bound to a challenge")
        values = await self._service().list_challenges(self._run_id())
        challenge = next(
            (item for item in values if item["unique_code"] == unique_code), None
        )
        if challenge is None:
            raise SubagentError("Challenge was not found")
        return challenge

    async def _project(self) -> None:
        if self.run_id is None:
            return
        try:
            while await self._service().project_pending_events(
                self._run_id(), run_dir=self._run_dir(), limit=500
            ):
                pass
        except Exception:
            # Projection is retryable and never rolls back domain state.
            pass

    @staticmethod
    def _compact_challenge_for_chief(item: Mapping[str, Any]) -> dict[str, Any]:
        """Project only fields needed for score-first Chief scheduling."""

        return {
            "unique_code": item.get("unique_code"),
            "name": item.get("name"),
            "description": str(item.get("description") or "")[:500],
            "difficulty": item.get("difficulty"),
            "total_score": item.get("total_score"),
            "flag_count": item.get("flag_count"),
            "correct_flag_count": item.get("correct_flag_count"),
            "is_completed": item.get("is_completed"),
            "work_status": item.get("work_status"),
            "container_status": item.get("container_status"),
            "direction": item.get("direction"),
        }

    @staticmethod
    async def _ignore_cancel(task: asyncio.Task[Any]) -> None:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    def _solver_prompt(
        self,
        challenge: Mapping[str, Any],
        start_result: Mapping[str, Any],
        *,
        hints: Any = (),
    ) -> str:
        start_data = (
            start_result.get("data")
            if isinstance(start_result.get("data"), Mapping)
            else {}
        )
        data = {
            "unique_code": challenge.get("unique_code"),
            "name": challenge.get("name"),
            "description": str(challenge.get("description") or "")[:4_000],
            "difficulty": challenge.get("difficulty"),
            "level": challenge.get("level"),
            "container_addr": start_data.get("container_addr")
            or challenge.get("container_addr")
            or [],
            "hints": list(hints or [])[:4],
        }
        return render_prompt(
            "solver_agent.txt",
            challenge_data=json.dumps(data, ensure_ascii=False),
        )

    @staticmethod
    def _system_prompt(role: str) -> str:
        return system_prompt(role)

    @staticmethod
    def _error(
        code: str,
        message: str,
        *,
        error_type: str = "validation",
        status_code: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stage = (
            "permission"
            if error_type == "permission"
            else (
                "conflict"
                if error_type == "conflict" or status_code == 409
                else (
                    "internal"
                    if error_type == "internal"
                    else (
                        "execution"
                        if error_type in {"transport", "api"}
                        else "semantic"
                    )
                )
            )
        )
        return tool_error(
            stage,
            code,
            message,
            retry_allowed=False,
            retry_action="none",
            details=detail or {},
        )

    @staticmethod
    def _ok(data: Any) -> dict[str, Any]:
        return {"ok": True, "data": data}

    @staticmethod
    def _error_code(result: Any) -> str | None:
        if isinstance(result, Mapping) and isinstance(result.get("error"), Mapping):
            code = result["error"].get("code")
            return code if isinstance(code, str) else None
        return None

    @classmethod
    def _is_transient_release_failure(
        cls,
        close_result: Mapping[str, Any],
        sync_result: Mapping[str, Any],
    ) -> bool:
        """Bound retries to transport/service failures for an idempotent close."""

        transient_codes = {
            "transport_error",
            "benchmark_error",
            "catalog_sync_failed",
            "invalid_state",
        }
        for result in (close_result, sync_result):
            code = cls._error_code(result)
            error = result.get("error") if isinstance(result, Mapping) else None
            details = error.get("details") if isinstance(error, Mapping) else None
            status_code = (
                details.get("status_code") if isinstance(details, Mapping) else None
            )
            if code in transient_codes or status_code in {
                409,
                408,
                429,
                500,
                502,
                503,
                504,
            }:
                return True
        return False

    @staticmethod
    def _error_message(result: Any) -> str | None:
        if isinstance(result, Mapping) and isinstance(result.get("error"), Mapping):
            message = result["error"].get("message")
            return message if isinstance(message, str) else None
        return None
