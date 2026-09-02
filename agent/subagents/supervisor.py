"""SQLite-authoritative parent/child Agent orchestration."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from agent.config import AgentSettings, PROJECT_ROOT
from agent.memory.models import AgentNode
from agent.memory.blackboard import BlackboardCompactionError, BlackboardCompactor
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
    BOOTSTRAP_CYCLE_TIMEOUT_SECONDS,
    BOOTSTRAP_MAX_ROUNDS,
    BOOTSTRAP_MISSION,
    BOOTSTRAP_REPORT_ONLY_GRACE_SECONDS,
    BOOTSTRAP_SUCCESS_CRITERIA,
    CapabilityRegistry,
    BOOTSTRAP_SCALE_INTERVAL_SECONDS as STATE_BOOTSTRAP_SCALE_INTERVAL_SECONDS,
    MAX_BOOTSTRAP_AGENTS_PER_CHALLENGE,
    MAX_CHALLENGE_SLOTS as DEFAULT_MAX_CHALLENGE_SLOTS,
    ResourceController,
    StateService,
    container_capacity_summary,
    container_slot_occupied,
)
from agent.state.errors import StateError
from agent.state.clock import aware, utc_now
from agent.state.blackboard import blackboard_content_digest
from agent.state.schemas import (
    AgentReportInput,
    CapabilityContext,
    ChallengeDispatchInput,
    ExecutionTaskInput,
)
from agent.state.scheduling import ChallengeScheduler
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
from tools.browser import BrowserManager, BrowserTools
from tools.binaries import default_toolchain_root, toolchain_for
from tools.pentest import PentestTools
from tools.proxy import CaidoProxyManager, ProxyTools
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy

from .models import AgentRole
from .policy import AgentPolicy
from .tools import ChallengeAgentTools, ChiefAgentTools, ExecutionAgentTools


LOGGER = logging.getLogger("aion.supervisor")
if not LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


def _browser_proxy_environment() -> dict[str, str]:
    """Pass only explicit proxy/browser settings into the sandboxed browser."""

    proxy = (
        os.environ.get("AION_CAIDO_PROXY_URL", "").strip()
        or os.environ.get("AGENT_BROWSER_PROXY", "").strip()
    )
    environment: dict[str, str] = {}
    if proxy:
        no_proxy = os.environ.get(
            "AION_CAIDO_NO_PROXY",
            os.environ.get("AGENT_BROWSER_PROXY_BYPASS", "localhost,127.0.0.1"),
        ).strip()
        environment.update(
            {
                "AGENT_BROWSER_PROXY": proxy,
                "AGENT_BROWSER_PROXY_BYPASS": no_proxy,
                "HTTP_PROXY": proxy,
                "HTTPS_PROXY": proxy,
                "ALL_PROXY": proxy,
                "http_proxy": proxy,
                "https_proxy": proxy,
                "all_proxy": proxy,
                "NO_PROXY": no_proxy,
                "no_proxy": no_proxy,
            }
        )
    # Shell rebuilds its environment instead of inheriting the controller's
    # process environment; forward only fixed browser launch knobs explicitly.
    for name in (
        "AGENT_BROWSER_EXECUTABLE_PATH",
        "AGENT_BROWSER_ARGS",
        "AGENT_BROWSER_CA_CERT",
        "AGENT_BROWSER_ALLOWED_DOMAINS",
        "AGENT_BROWSER_USER_AGENT",
        "AGENT_BROWSER_IGNORE_HTTPS_ERRORS",
        "AGENT_BROWSER_IDLE_TIMEOUT_MS",
        "AGENT_BROWSER_DEFAULT_TIMEOUT",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


class SubagentError(RuntimeError):
    """Safe orchestration failure without exposing credentials or stack traces."""


class AgentSupervisor:
    """Own live tasks while SQLite owns all recoverable Agent state."""

    MAX_CHALLENGE_SLOTS = DEFAULT_MAX_CHALLENGE_SLOTS
    CONTROLLER_SAFETY_WAKE_SECONDS = 300.0
    HEARTBEAT_INTERVAL_SECONDS = 30.0
    HEARTBEAT_EVENT_INTERVAL_SECONDS = 300.0
    BOOTSTRAP_SCALE_INTERVAL_SECONDS = STATE_BOOTSTRAP_SCALE_INTERVAL_SECONDS
    EXECUTION_TIMEOUT_FLOORS = {
        "discovery": 900,
        "validation": 1_800,
        "exploitation": 1_800,
        "post_exploitation": 1_800,
    }
    TERMINAL_AGENT_STATES = {
        "completed",
        "failed",
        "stopped",
        "cancelled",
        "interrupted",
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
        self.toolchain_root = default_toolchain_root()
        self.run_root = (
            run_root or self.project_root / ".aion" / "runs"
        ).resolve()
        self.runner_factory = runner_factory
        self.max_challenge_slots = max_challenge_slots
        self.catalog_reconcile_interval_seconds = catalog_reconcile_interval_seconds
        self.duration_minutes = duration_minutes or getattr(settings, "run_duration_minutes", 360)
        self.state_service = state_service
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.resource_controller = resource_controller
        self.skill_catalog = skill_catalog or SkillCatalog()
        self._state_capabilities: dict[str, CapabilityContext] = {}
        self.run_id: str | None = None
        self.store: AgentStateStore | None = None
        self.chief_agent_id: str | None = None
        # These are live process views only. SQLite remains authoritative.
        self.nodes: dict[str, AgentNode] = {}
        self._runners: dict[str, AgentRunner] = {}
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._heartbeat_tasks: dict[str, asyncio.Task[None]] = {}
        self._catalog: dict[str, dict[str, Any]] = {}
        self._poll_task: asyncio.Task[None] | None = None
        self._challenge_completion_tasks: dict[str, asyncio.Task[Any]] = {}
        self._container_operation_lock = asyncio.Lock()
        self._bootstrap_scale_lock = asyncio.Lock()
        self._hint_locks: dict[str, asyncio.Lock] = {}
        self._benchmark_unavailable: set[str] = set()
        # Keep this in the Supervisor so the requirement survives Runner and
        # Tool wrapper reconstruction while a controller is waiting.
        self._pausing = False
        self._shell_tasks: ShellTaskManager | None = None
        self._browser: BrowserManager | None = None
        self._proxy: CaidoProxyManager | None = None
        self._http_interactions: HttpProbeManager | None = None
        self._network_discovery: NetworkDiscoveryManager | None = None
        self._model_http_client: httpx.AsyncClient | None = None
        self._skill_discovery: SkillDiscovery | None = None
        self._skill_discovery_bootstrap_tasks: set[asyncio.Task[None]] = set()
        self._blackboard_compaction_cache: dict[str, Mapping[str, Any]] = {}

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
            return result if isinstance(result, dict) else self._ok({"agent_id": chief_id})
        finally:
            await self.close()

    async def prepare_chief(
        self,
        prompt: str,
        *,
        run_id: str | None = None,
        resume: bool = False,
    ) -> str:
        if not prompt.strip() and not resume:
            raise SubagentError("Chief prompt must not be empty")
        run_id = run_id or uuid4().hex
        await self._ensure_service(run_id)
        service = self._service()
        self.run_id = run_id

        if resume:
            await self._prepare_resume(run_id)
            overview = await service.get_overview(run_id)
            if overview["run"]["status"] == "completed":
                raise SubagentError("completed runs cannot be resumed")
            chief = next((item for item in overview["agents"] if item["role"] == "chief"), None)
            if chief is None:
                raise SubagentError("run does not contain a Chief Agent")
            self.chief_agent_id = chief["agent_id"]
            prompt = (await service.get_agent_runtime(run_id, self.chief_agent_id))["agent"]["initial_prompt"]
        else:
            if await service.run_exists(run_id):
                raise SubagentError("run_id already exists")
            await service.create_run(
                run_id,
                duration_minutes=self.duration_minutes,
                model=self.settings.llm_model,
                prompt=prompt,
                context_window_tokens=self.settings.context_budget.context_window_tokens,
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
                        "challenge": self.settings.context_budget.max_output_tokens(
                            "challenge"
                        ),
                        "bootstrap": self.settings.context_budget.max_output_tokens(
                            "execution", bootstrap=True
                        ),
                        "execution": self.settings.context_budget.max_output_tokens(
                            "execution"
                        ),
                    },
                    "auxiliary_thinking_enabled": False,
                },
            )
        await service.append_run_event(
            run_id, "skill_catalog_ready", self.skill_catalog.metrics
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
                runtime_prefix,
                self.toolchain_root,
            ),
            environment={
                "AION_SKILLS_ROOT": str(self.skill_catalog.root),
                "AION_PYTHON": str(runtime_python),
                "AION_VENV_BIN": str(runtime_python.parent),
                "AION_TOOLCHAIN_ROOT": str(toolchain.root),
                "AION_TOOLCHAIN_BIN": str(toolchain.bin_dir),
                **_browser_proxy_environment(),
            },
        )
        await self._shell_tasks.initialize(resume=resume)
        self._browser = BrowserManager(run_id)
        self._proxy = CaidoProxyManager(project_name=f"aion-{run_id}")
        if os.environ.get("AION_CAIDO_URL", "").strip() or os.environ.get(
            "STRIX_CAIDO_URL", ""
        ).strip():
            try:
                await self._proxy.initialize()
            except Exception as exc:
                # Caido remains optional outside the hosted image; ProxyTools
                # retries lazily when the Agent actually requests it.
                LOGGER.warning(
                    "caido initialization deferred error_type=%s", type(exc).__name__
                )
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
        await self.refresh_challenges(self.chief_agent_id)
        await self._launch_agent(self.chief_agent_id, resume=resume)
        if resume:
            await self._restart_challenge_agents()
        self._start_poller(self.chief_agent_id)
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
            if item["role"] == "challenge"
            and item.get("unique_code")
            and item["status"] not in self.TERMINAL_AGENT_STATES
        }
        for challenge in synced["data"]["challenges"]:
            if challenge["is_completed"]:
                self._schedule_challenge_completion(
                    challenge["unique_code"],
                    reason="catalog_completed",
                    exclude_agent_id=live_challenge_agents.get(
                        challenge["unique_code"]
                    ),
                    release_caller_id=caller_id,
                )

        values = await self._service().list_challenges(self._run_id())
        self._catalog = {item["unique_code"]: item for item in values}
        capacity = container_capacity_summary(
            values, limit=self.max_challenge_slots
        )
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
        async with self._container_operation_lock:
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

    async def _release_completed_container(
        self,
        caller_id: str,
        unique_code: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._container_operation_lock:
            challenge = await self._challenge_record(unique_code)
            if not challenge["is_completed"]:
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
            started = asyncio.get_running_loop().time()
            observed_status = challenge["container_status"]
            await self._service().append_agent_event(
                self._run_id(),
                caller_id,
                "completed_container_release_started",
                {
                    "unique_code": unique_code,
                    "observed_container_status": observed_status,
                    "reason": reason,
                },
            )
            LOGGER.info(
                "completed_container_release_started run_id=%s unique_code=%s observed_container_status=%s reason=%s",
                self._run_id(),
                unique_code,
                observed_status,
                reason,
            )
            close_result: dict[str, Any] = self._error(
                "container_release_unconfirmed",
                "Completed challenge container release was not confirmed",
                error_type="internal",
            )
            synced: dict[str, Any] = self._error(
                "catalog_sync_failed",
                "Completed challenge container release could not be confirmed",
                error_type="internal",
            )
            attempts = 0
            for attempt in range(1, 4):
                attempts = attempt
                try:
                    close_result = await self._execute_operation(
                        caller_id=caller_id,
                        tool_name="benchmark_close_challenge",
                        arguments={"unique_code": unique_code},
                        unique_code=unique_code,
                    )
                    synced = await self._sync_challenge_catalog()
                except Exception:
                    LOGGER.warning(
                        "completed_container_release_operation_failed run_id=%s unique_code=%s attempt=%s",
                        self._run_id(),
                        unique_code,
                        attempt,
                        exc_info=True,
                    )
                    close_result = self._error(
                        "benchmark_error",
                        "Completed challenge container release failed",
                        error_type="internal",
                    )
                    synced = self._error(
                        "catalog_sync_failed",
                        "Completed challenge container release could not be confirmed",
                        error_type="internal",
                    )
                current = await self._challenge_record(unique_code)
                if synced.get("ok") is True and not current["slot_occupied"]:
                    break
                if attempt < 3 and self._is_transient_release_failure(
                    close_result, synced
                ):
                    await asyncio.sleep(0.5 if attempt == 1 else 1.0)
                    continue
                break
            current = await self._challenge_record(unique_code)
            released = synced.get("ok") is True and not current["slot_occupied"]
            duration_ms = int(
                (asyncio.get_running_loop().time() - started) * 1_000
            )
            event_type = (
                "completed_container_release_succeeded"
                if released
                else "completed_container_release_failed"
            )
            error_code = None
            if not released:
                error_code = self._error_code(close_result)
                if error_code is None and not synced.get("ok"):
                    error_code = self._error_code(synced) or "catalog_sync_failed"
                error_code = error_code or "container_release_unconfirmed"
            payload = {
                "unique_code": unique_code,
                "observed_container_status": observed_status,
                "container_status": current["container_status"],
                "reason": reason,
                "attempts": attempts,
                "duration_ms": duration_ms,
            }
            if error_code is not None:
                payload["error_code"] = error_code
            await self._service().append_agent_event(
                self._run_id(), caller_id, event_type, payload
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
                duration_ms,
                error_code or "",
            )
            return {
                "released": released,
                "container_status": current["container_status"],
                "error_code": error_code,
                "attempts": attempts,
            }

    async def release_paused_container(
        self,
        unique_code: str,
        *,
        reason: str = "stagnation_timeout",
        caller_id: str | None = None,
    ) -> dict[str, Any]:
        """Close a paused target and count a slot free only after confirmation."""

        async with self._container_operation_lock:
            challenge = await self._challenge_record(unique_code)
            if challenge["work_status"] != "paused" or challenge["is_completed"]:
                return {"released": False, "skipped": True, "reason": "challenge_not_paused"}
            if not challenge["slot_occupied"]:
                return {
                    "released": True,
                    "skipped": True,
                    "container_status": challenge["container_status"],
                }
            owner = caller_id or self.chief_agent_id or ""
            started = asyncio.get_running_loop().time()
            await self._service().append_agent_event(
                self._run_id(),
                owner,
                "paused_container_release_started",
                {
                    "unique_code": unique_code,
                    "reason": reason,
                    "observed_container_status": challenge["container_status"],
                },
            )
            close_result: dict[str, Any] = self._error(
                "container_release_unconfirmed",
                "Paused challenge container release was not confirmed",
                error_type="internal",
            )
            synced: dict[str, Any] = self._error(
                "catalog_sync_failed",
                "Paused challenge container release could not be confirmed",
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
                    synced = await self._sync_challenge_catalog()
                except Exception:
                    LOGGER.warning(
                        "paused_container_release_operation_failed run_id=%s unique_code=%s attempt=%s",
                        self._run_id(),
                        unique_code,
                        attempt,
                        exc_info=True,
                    )
                    close_result = self._error(
                        "benchmark_error",
                        "Paused challenge container release failed",
                        error_type="internal",
                    )
                    synced = self._error(
                        "catalog_sync_failed",
                        "Paused challenge container release could not be confirmed",
                        error_type="internal",
                    )
                current = await self._challenge_record(unique_code)
                if synced.get("ok") is True and not current["slot_occupied"]:
                    break
                if attempt < 3 and self._is_transient_release_failure(
                    close_result, synced
                ):
                    await asyncio.sleep(0.5 if attempt == 1 else 1.0)
                    continue
                break
            current = await self._challenge_record(unique_code)
            released = synced.get("ok") is True and not current["slot_occupied"]
            error_code = None
            if not released:
                error_code = self._error_code(close_result)
                if error_code is None and not synced.get("ok"):
                    error_code = self._error_code(synced) or "catalog_sync_failed"
                error_code = error_code or "container_release_unconfirmed"
            event_type = (
                "paused_container_release_succeeded"
                if released
                else "paused_container_release_failed"
            )
            payload: dict[str, Any] = {
                "unique_code": unique_code,
                "attempts": attempts,
                "reason": reason,
                "container_status": current["container_status"],
                "duration_ms": int((asyncio.get_running_loop().time() - started) * 1_000),
            }
            if error_code is not None:
                payload["error_code"] = error_code
            await self._service().append_agent_event(
                self._run_id(), owner, event_type, payload
            )
            if not released:
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
            return {
                "released": released,
                "retry_exhausted": attempts >= 3 and not released,
                "attempts": attempts,
                "container_status": current["container_status"],
                "error_code": error_code,
            }

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
            await self.stop_challenge_work(
                unique_code,
                reason=reason,
                exclude_agent_id=exclude_agent_id,
            )
            await self._release_completed_container(
                caller_id,
                unique_code,
                reason=reason,
            )

        task = asyncio.create_task(
            converge(), name=f"aion-complete-{unique_code}"
        )
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

    async def create_challenge_agent(
        self,
        caller_id: str,
        unique_code: str,
        *,
        refresh: bool = True,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        if refresh:
            refreshed = await self.refresh_challenges(caller_id)
            if not refreshed.get("ok"):
                return refreshed
        challenge = self._catalog.get(unique_code)
        if challenge is None:
            return self._error(
                "task_not_found",
                "Challenge was not found",
                error_type="api",
                status_code=404,
            )
        overview = await self._service().get_overview(self._run_id())
        existing = next(
            (
                item
                for item in overview["agents"]
                if item["role"] == "challenge"
                and item["unique_code"] == unique_code
                and item["status"] not in self.TERMINAL_AGENT_STATES
            ),
            None,
        )
        if existing is not None:
            bootstrap_result = await self._ensure_bootstrap_agent(
                unique_code,
                existing["agent_id"],
                reason="challenge_start_existing",
            )
            initial_executions = [
                item
                for item in overview["agents"]
                if item.get("role") == "execution"
                and item.get("unique_code") == unique_code
                and item.get("task_key") == "initial-recon"
            ]
            return self._ok(
                {
                    "agent_id": existing["agent_id"],
                    "role": "challenge",
                    "unique_code": unique_code,
                    "status": existing["status"],
                    "idempotent": True,
                    "bootstrap": bootstrap_result,
                    "initial_executions": initial_executions,
                }
            )
        challenge_state = next(
            item for item in overview["challenges"] if item["unique_code"] == unique_code
        )
        if challenge_state["is_completed"] or challenge_state["work_status"] == "closed":
            return self._error(
                "challenge_completed",
                "The challenge is already completed or closed",
                error_type="conflict",
            )
        if challenge_state["work_status"] == "paused" and challenge_state["slot_occupied"]:
            try:
                await self._service().start_challenge(
                    self._run_id(),
                    unique_code,
                    context=self._state_context(caller_id),
                )
            except Exception:
                return self._error(
                    "challenge_resume_failed",
                    "The paused challenge could not be resumed",
                    error_type="conflict",
                )
        start_result = await self._ensure_challenge_container(
            caller_id, unique_code
        )
        if not start_result.get("ok"):
            return start_result

        agent_id = f"challenge_{uuid4().hex}"
        bootstrap_agent_id = f"execution_{uuid4().hex}"
        bootstrap_agent_ids: list[str] = []
        initial_execution_ids: list[str] = []
        prior_context = await self._service().get_challenge_context(
            self._run_id(), unique_code, compact=True
        )
        prior_hints = prior_context.get("hints") if isinstance(prior_context, Mapping) else []
        prompt = self._challenge_prompt(
            challenge,
            start_result,
            hints=prior_hints,
        )
        bootstrap_prompt = self._bootstrap_prompt(
            challenge,
            start_result,
            hints=prior_hints,
        )
        initial_execution = self._initial_execution_task(challenge)
        try:
            record = await self._service().register_challenge_workgroup(
                self._run_id(),
                challenge_agent_id=agent_id,
                bootstrap_agent_id=bootstrap_agent_id,
                parent_id=caller_id,
                unique_code=unique_code,
                challenge_prompt=prompt,
                bootstrap_prompt=bootstrap_prompt,
                initial_execution=initial_execution,
                bootstrap_enabled=bool(
                    getattr(self.settings, "bootstrap_enabled", True)
                ),
            )
            bootstrap_entries = (
                record.get("bootstraps")
                if isinstance(record, Mapping)
                else None
            )
            if not isinstance(bootstrap_entries, list):
                bootstrap_entries = [
                    record.get("bootstrap") if isinstance(record, Mapping) else None
                ]
            bootstrap_agent_ids = [
                str(item["agent_id"])
                for item in bootstrap_entries
                if isinstance(item, Mapping) and item.get("agent_id")
            ]
            self._state_capabilities[agent_id] = self.capability_registry.issue(
                self._run_id(), agent_id, "challenge", unique_code
            ).context
            for bootstrap_id in bootstrap_agent_ids:
                self._state_capabilities[bootstrap_id] = self.capability_registry.issue(
                    self._run_id(), bootstrap_id, "execution", unique_code
                ).context
            initial_entries = (
                record.get("initial_executions")
                if isinstance(record, Mapping)
                else None
            )
            if not isinstance(initial_entries, list):
                initial_entries = []
            initial_execution_ids = [
                str(item["agent_id"])
                for item in initial_entries
                if isinstance(item, Mapping) and item.get("agent_id")
            ]
            for initial_id in initial_execution_ids:
                self._state_capabilities[initial_id] = self.capability_registry.issue(
                    self._run_id(), initial_id, "execution", unique_code
                ).context
            await self._sync_nodes()
            for initial_id in initial_execution_ids:
                task = asyncio.create_task(
                    self._prefetch_execution_skill(initial_id),
                    name=f"skill-discovery-initial-{initial_id}",
                )
                self._skill_discovery_bootstrap_tasks.add(task)
                task.add_done_callback(self._skill_discovery_bootstrap_tasks.discard)
            await self._launch_agent(agent_id)
        except Exception:
            try:
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="failed"
                )
            except Exception:
                pass
            try:
                for execution_id in bootstrap_agent_ids + initial_execution_ids or [bootstrap_agent_id]:
                    bootstrap_record = await self._service().get_agent_runtime(
                        self._run_id(), execution_id
                    )
                    if bootstrap_record["agent"]["status"] in self.TERMINAL_AGENT_STATES:
                        continue
                    live_execution = self._tasks.get(execution_id)
                    if live_execution is not None and not live_execution.done():
                        await self._stop_agent(execution_id)
                    else:
                        await self._service().finalize_execution_agent(
                            self._run_id(),
                            execution_id,
                            CapabilityContext(
                                run_id=self._run_id(),
                                agent_id=execution_id,
                                role="execution",
                                unique_code=unique_code,
                            ),
                            AgentReportInput(
                                status="failed",
                                summary="Challenge workgroup Execution could not be started",
                                hypothesis_outcome="inconclusive",
                            ),
                            terminal_status="failed",
                            allow_inactive=True,
                        )
            except Exception:
                pass
            return self._error(
                "agent_start_failed",
                "Challenge Agent could not be started",
                error_type="execution",
            )
        return self._ok(
            {
                "agent_id": agent_id,
                "role": record["role"],
                "unique_code": unique_code,
                "status": "running",
                "bootstrap": record.get("bootstrap", {"enabled": False}),
                "bootstraps": record.get("bootstraps", []),
                "initial_executions": record.get("initial_executions", []),
                "start": start_result.get("data", {}),
            }
        )

    async def observe_chief(
        self,
        caller_id: str,
        *,
        max_reports: int = 20,
    ) -> dict[str, Any]:
        """Return one compact authoritative Chief snapshot."""

        self._require_role(caller_id, "chief")
        reports = await self._service().consume_reports(
            self._run_id(),
            self._state_context(caller_id),
            report_type="challenge_status",
            wait_seconds=0.0,
            max_reports=max_reports,
        )
        snapshot_replayed = False
        if not reports.get("reports"):
            replay = await self._service().replay_unacknowledged_controller_reports(
                self._run_id(),
                self._state_context(caller_id),
                report_type="challenge_status",
                max_reports=max_reports,
            )
            if replay is not None:
                reports = replay
                snapshot_replayed = True
        overview = await self._service().get_overview(self._run_id())
        scheduled = await ChallengeScheduler(self._service()).select(self._run_id())
        evidence = await self._service().list_evidence_metadata(
            self._run_id(), self._state_context(caller_id), limit=max_reports
        )
        compact_reports = [
            self._flatten_report(item, "challenge_status")
            for item in reports["reports"]
        ]
        run = overview.get("run") or {}
        return self._ok(
            {
                "run": {
                    key: run.get(key)
                    for key in (
                        "run_id",
                        "status",
                        "phase",
                        "deadline_at",
                        "current_challenge_code",
                        "score_snapshot",
                    )
                },
                "capacity": overview.get("container_capacity"),
                "challenges": [
                    self._compact_challenge_for_chief(item)
                    for item in overview.get("challenges", [])
                ],
                "active_agents": [
                    {
                        key: item.get(key)
                        for key in (
                            "agent_id",
                            "role",
                            "unique_code",
                            "status",
                            "task_stage",
                            "priority",
                            "mission",
                            "started_at",
                            "last_report_sequence",
                        )
                    }
                    for item in overview.get("agents", [])
                    if item.get("status") not in self.TERMINAL_AGENT_STATES
                ],
                "schedule": scheduled,
                "evidence": evidence,
                "reports": compact_reports,
                "report_count": len(compact_reports),
                "next_sequence": reports["next_sequence"],
                "has_more": len(compact_reports) >= max_reports,
                "snapshot_replayed": snapshot_replayed,
            }
        )

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
            result = await self.create_challenge_agent(
                caller_id, unique_code, refresh=False
            )
            results.append(
                {
                    "unique_code": unique_code,
                    **result,
                }
            )
        return self._ok(
            {
                "results": results,
                "started_count": sum(
                    1 for item in results if item.get("ok") is True
                ),
            }
        )

    async def wait_chief(
        self,
        caller_id: str,
        *,
        reason: str | None = None,
    ) -> ToolDispatchOutcome:
        self._require_role(caller_id, "chief")
        return ToolDispatchOutcome(
            self._ok({"status": "waiting", "reason": reason}),
            yield_session=True,
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
        if not challenge["hint_eligible"]:
            return self._error(
                "hint_not_eligible",
                "The runtime has not granted a hint signal for this challenge",
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
            if not challenge["hint_eligible"]:
                return self._error(
                    "hint_not_eligible",
                    "The runtime has not granted a hint signal for this challenge",
                    error_type="conflict",
                )
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
            challenge_agent = await self._find_agent(
                "challenge", unique_code=unique_code
            )
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
            bootstrap_agents = [
                item
                for item in (await self._service().get_overview(self._run_id()))["agents"]
                if item.get("role") == "execution"
                and item.get("unique_code") == unique_code
            ]
            for bootstrap in bootstrap_agents:
                if bootstrap.get("kind") != "bootstrap" or bootstrap.get("status") in self.TERMINAL_AGENT_STATES:
                    continue
                await self._service().publish_control_report(
                    self._run_id(),
                    sender_id=caller_id,
                    recipient_id=bootstrap["agent_id"],
                    unique_code=unique_code,
                    report_type="hint",
                    status="received",
                    payload=hint_payload,
                )
        return result

    async def launch_execution_agent(self, agent_id: str) -> None:
        """Launch a previously admitted Execution Agent."""

        record = await self._agent_record(agent_id, "execution")
        if record["status"] not in {"queued", "starting", "pending"}:
            raise SubagentError("Execution Agent is not awaiting admission")
        if agent_id not in self._state_capabilities:
            self._state_capabilities[agent_id] = self.capability_registry.issue(
                self._run_id(), agent_id, "execution", record["unique_code"]
            ).context
        await self._sync_nodes()
        await self._launch_agent(agent_id)

    async def stop_execution_agents(self, unique_code: str) -> None:
        """Stop live execution tasks after a persisted pause decision."""

        overview = await self._service().get_overview(self._run_id())
        await asyncio.gather(
            *(
                self._stop_agent(item["agent_id"])
                for item in overview["agents"]
                if item["role"] == "execution"
                and item["unique_code"] == unique_code
                and item["status"] not in self.TERMINAL_AGENT_STATES
            ),
        )

    async def stop_challenge_work(
        self,
        unique_code: str,
        *,
        reason: str = "challenge_completed",
        exclude_agent_id: str | None = None,
    ) -> None:
        """Immediately stop live work owned by one challenge.

        A submitting Challenge Agent can be excluded so its synchronous tool
        result can reach the controller before the controller settles.
        """

        try:
            await self._service().cancel_challenge_branches(
                self._run_id(), unique_code, reason=reason
            )
        except Exception:
            LOGGER.warning(
                "challenge_branch_cancel_failed run_id=%s unique_code=%s",
                self._run_id(),
                unique_code,
            )
        overview = await self._service().get_overview(self._run_id())
        live_agents = [
            item
            for item in overview["agents"]
            if item["role"] in {"challenge", "execution"}
            and item["unique_code"] == unique_code
            and item["agent_id"] != exclude_agent_id
            and item["status"] not in self.TERMINAL_AGENT_STATES
        ]
        if not live_agents:
            return
        await asyncio.gather(
            *(self._stop_agent(item["agent_id"]) for item in live_agents)
        )
        await self._service().append_agent_event(
            self._run_id(),
            self.chief_agent_id or "",
            "challenge_completed_agents_stopped",
            {
                "unique_code": unique_code,
                "reason": reason,
                "excluded_agent_id": exclude_agent_id,
            },
        )
        await self._sync_nodes()

    async def wait_agent(self, agent_id: str) -> dict[str, Any]:
        task = self._tasks.get(agent_id)
        if task is None:
            raise SubagentError("Agent task is not running")
        result = await task
        return result if isinstance(result, dict) else {"agent_id": agent_id}

    async def wait_for_quiescence(self) -> None:
        """Wait on durable lifecycle signals until the complete Agent tree stops."""

        signal_key = self._service().run_signal_key(self._run_id())
        cursor = await self._service().notifier.current(signal_key)
        while True:
            overview = await self._service().get_overview(self._run_id())
            agents_terminal = all(
                item["status"] in self.TERMINAL_AGENT_STATES
                for item in overview["agents"]
            )
            tasks_done = all(task.done() for task in self._tasks.values())
            if agents_terminal and tasks_done:
                return
            cursor = await self._service().notifier.wait(
                signal_key, cursor, self.CONTROLLER_SAFETY_WAKE_SECONDS
            )

    async def observe_challenge(
        self,
        caller_id: str,
        *,
        max_reports: int = 8,
    ) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Challenge Agent is not bound to a challenge",
            )
        observed = await self._service().observe_challenge(
            self._run_id(),
            node.unique_code,
            self._state_context(caller_id),
            max_reports=max_reports,
        )
        observed = await self._maybe_compact_challenge_observation(
            caller_id, observed
        )
        return self._ok(observed)

    async def _maybe_compact_challenge_observation(
        self, caller_id: str, observed: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Shorten large safe report projections without touching authority."""

        encoded_length = len(
            json.dumps(dict(observed), ensure_ascii=False, default=str)
        )
        reports = list(observed.get("reports") or [])
        if encoded_length < 6_000 or not reports:
            return dict(observed)
        digest = blackboard_content_digest(observed)
        cached = self._blackboard_compaction_cache.get(digest)
        if cached is not None:
            return dict(cached)
        compactor = BlackboardCompactor(
            self.settings,
            client=self._shared_model_http_client(),
        )
        try:
            compacted = await compactor.compact(observed)
        except BlackboardCompactionError as exc:
            await self._service().append_agent_event(
                self._run_id(),
                caller_id,
                "blackboard_compaction_fallback",
                {
                    "content_digest": digest,
                    "error_type": type(exc).__name__,
                },
            )
            return dict(observed)
        await self._service().append_agent_event(
            self._run_id(),
            caller_id,
            "blackboard_compacted",
            {
                "content_digest": digest,
                "report_count": len(reports),
                "input_chars": encoded_length,
                "output_chars": len(
                    json.dumps(dict(compacted), ensure_ascii=False, default=str)
                ),
                "latency_ms": compactor.last_metrics.get("latency_ms"),
            },
        )
        compacted.pop("compacted", None)
        self._blackboard_compaction_cache[digest] = compacted
        if len(self._blackboard_compaction_cache) > 8:
            oldest = next(iter(self._blackboard_compaction_cache))
            self._blackboard_compaction_cache.pop(oldest, None)
        return compacted

    async def request_secondary_bootstrap(
        self,
        caller_id: str,
        route_a: str,
        route_b: str,
        reason: str,
    ) -> dict[str, Any]:
        """Temporarily open one extra Bootstrap lane for two distinct routes."""

        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Challenge Agent is not bound to a challenge",
            )
        route_a = route_a.strip()
        route_b = route_b.strip()
        reason = reason.strip()
        if not route_a or not route_b or not reason:
            return self._error(
                "invalid_secondary_bootstrap_request",
                "Two non-empty independent routes and a reason are required",
            )
        if route_a.casefold() == route_b.casefold():
            return self._error(
                "duplicate_secondary_bootstrap_route",
                "The two Bootstrap routes must be materially different",
            )
        challenge = await self._challenge_record(node.unique_code)
        capacity = await self._service().set_bootstrap_capacity(
            self._run_id(),
            node.unique_code,
            parent_id=node.agent_id,
            target_count=2,
            reason="secondary_independent_routes",
        )
        target_count = int(capacity.get("target_count") or 0)
        if target_count < 1:
            return self._error(
                "challenge_stopped",
                "The Challenge is no longer active",
                error_type="conflict",
            )
        result = await self._ensure_bootstrap_agent(
            node.unique_code,
            node.agent_id,
            reason="secondary_independent_routes",
            bootstrap_count=target_count,
            route_scope=(
                f"Do not repeat route A: {route_a[:800]}. "
                f"Explore route B only: {route_b[:800]}."
            ),
        )
        await self._service().append_agent_event(
            self._run_id(),
            caller_id,
            "bootstrap_secondary_requested",
            {
                "unique_code": node.unique_code,
                "route_a": route_a[:800],
                "route_b": route_b[:800],
                "reason": reason[:1_000],
                "bootstrap_count": target_count,
            },
        )
        await self._project()
        return self._ok(
            {
                "unique_code": node.unique_code,
                "challenge_status": challenge.get("work_status"),
                "bootstrap_count": len(result.get("bootstraps") or []),
                "bootstraps": result.get("bootstraps") or [],
            }
        )

    async def dispatch_challenge(
        self,
        caller_id: str,
        payload: ChallengeDispatchInput,
    ) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Challenge Agent is not bound to a challenge",
            )
        if payload.outcome == "blocked" and not payload.tasks:
            overview = await self._service().get_overview(self._run_id())
            active_children = [
                item["agent_id"]
                for item in overview["agents"]
                if item["role"] == "execution"
                and item.get("unique_code") == node.unique_code
                and item["status"] not in self.TERMINAL_AGENT_STATES
            ]
            if active_children:
                return self._error(
                    "active_work_requires_wait",
                    "Active Execution work is still running; use challenge_wait instead of recording a blocked decision",
                    error_type="conflict",
                    detail={"active_agent_ids": active_children},
                )
        result = await self._service().dispatch_challenge(
            self._run_id(),
            node.unique_code,
            self._state_context(caller_id),
            payload,
        )
        if not result.get("no_action"):
            await self._register_dispatch_admissions(
                node.unique_code, result.get("admissions", [])
            )
        if self.chief_agent_id is not None and not result.get("no_action"):
            await self._service().publish_control_report(
                self._run_id(),
                sender_id=caller_id,
                recipient_id=self.chief_agent_id,
                unique_code=node.unique_code,
                report_type="challenge_status",
                status=payload.outcome,
                payload={
                    "type": "challenge_dispatch",
                    "summary": payload.summary,
                    "outcome": payload.outcome,
                    "task_count": len(payload.tasks),
                    "next_steps": payload.next_steps,
                    "evidence_refs": payload.evidence_refs,
                },
            )
        warnings = list(result.pop("warnings", []))
        await self._project()
        return {"ok": True, "data": result, "warnings": warnings}

    async def submit_flag(self, caller_id: str, flag: str) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Challenge Agent is not bound to a challenge",
            )
        try:
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
                synced = await self._sync_challenge_catalog()
                if not synced.get("ok"):
                    return result
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
                        "accepted": False,
                        "duplicate": True,
                        "challenge_completed": True,
                    }
                )
            if result.get("ok") and completed:
                release_status = (
                    "pending" if current["slot_occupied"] else "released"
                )
                result = {
                    **result,
                    "data": {
                        **dict(result.get("data") or {}),
                        "challenge_completed": True,
                        "container_release_status": release_status,
                    },
                }
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
                    payload={
                        "type": "challenge_flag",
                        "unique_code": node.unique_code,
                        "accepted": bool(
                            isinstance(result.get("data"), Mapping)
                            and result["data"].get("accepted")
                        ),
                    },
                )
            return result
        finally:
            self._service().forget_ephemeral_secret(flag)

    async def close_challenge(self, caller_id: str) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error(
                "missing_challenge",
                "Challenge Agent is not bound to a challenge",
            )
        result = await self._execute_operation(
            caller_id=caller_id,
            tool_name="benchmark_close_challenge",
            arguments={"unique_code": node.unique_code},
            unique_code=node.unique_code,
        )
        await self._sync_challenge_catalog()
        if result.get("ok"):
            await self._stop_children(caller_id)
            await self._service().finish_agent(
                self._run_id(), caller_id, status="completed"
            )
            await self._sync_nodes()
        return result

    async def report_execution_payload(
        self,
        caller_id: str,
        payload: AgentReportInput,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        saved = await self._service().submit_report(
            self._run_id(), caller_id, self._state_context(caller_id), payload
        )
        if (
            saved.get("terminal", True)
            and self._report_has_high_value_progress(saved)
        ):
            node = self.nodes[caller_id]
            await self._stop_competing_executions(
                unique_code=node.unique_code or "",
                exclude_agent_id=caller_id,
                discovery_only=True,
            )
        await self._project()
        await self._sync_nodes()
        return {
            "ok": True,
            "data": {
                "agent_id": caller_id,
                "sequence": saved["sequence"],
                "status": payload.status,
                "hypothesis_outcome": saved.get(
                    "hypothesis_outcome", "inconclusive"
                ),
                "terminal": bool(saved.get("terminal", True)),
                "cycle_yield": bool(saved.get("cycle_yield", False)),
                "report_id": saved.get("report_id"),
                "idempotent": saved.get("idempotent", False),
            },
            "warnings": saved.get("warnings", []),
        }

    @staticmethod
    def _report_has_high_value_progress(saved: Mapping[str, Any]) -> bool:
        """Recognize only evidence-backed progress suitable for lane pruning."""

        if saved.get("candidate_flag_present"):
            return True
        findings = saved.get("findings")
        if not isinstance(findings, list):
            return False
        categories = {"vulnerability", "credential", "privilege", "attack_path", "flag"}
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            if finding.get("category") not in categories:
                continue
            if finding.get("verification_status") == "rejected":
                continue
            refs = finding.get("evidence_refs")
            if not isinstance(refs, list) or not any(
                isinstance(ref, str) and ref.startswith("evidence:") for ref in refs
            ):
                continue
            if finding.get("verification_status") == "verified":
                return True
            try:
                confidence = float(finding.get("confidence"))
            except (TypeError, ValueError):
                confidence = 0.0
            if confidence >= 0.8:
                return True
        return False

    async def report_bootstrap_checkpoint(
        self,
        caller_id: str,
        *,
        route_key: str,
        summary: str,
        next_step: str,
        task_stage: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        saved = await self._service().submit_bootstrap_checkpoint(
            self._run_id(),
            caller_id,
            self._state_context(caller_id),
            route_key=route_key,
            summary=summary,
            next_step=next_step,
            task_stage=task_stage,
            evidence_refs=evidence_refs,
        )
        if not saved.get("idempotent"):
            # A Bootstrap checkpoint is already a verified route handoff. Stop
            # stale discovery lanes so the Challenge-created follow-up is the
            # next piece of work instead of competing with old reconnaissance.
            await self._stop_competing_executions(
                unique_code=self.nodes[caller_id].unique_code or "",
                exclude_agent_id=caller_id,
                discovery_only=True,
            )
        await self._project()
        await self._sync_nodes()
        return {
            "ok": True,
            "data": {
                "agent_id": caller_id,
                "sequence": saved["sequence"],
                "status": saved["status"],
                "terminal": False,
                "report_id": saved["report_id"],
                "route_key": saved["route_key"],
                "idempotent": saved.get("idempotent", False),
            },
            "warnings": saved.get("warnings", []),
        }

    async def yield_bootstrap_cycle(
        self,
        caller_id: str,
        *,
        summary: str,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        saved = await self._service().yield_bootstrap_cycle(
            self._run_id(),
            caller_id,
            self._state_context(caller_id),
            summary=summary,
        )
        await self._project()
        await self._sync_nodes()
        return {
            "ok": True,
            "data": {
                **saved,
                "terminal": False,
                "cycle_yield": True,
            },
            "warnings": [],
        }

    async def report_execution_checkpoint(
        self,
        caller_id: str,
        *,
        summary: str,
        next_step: str,
        task_stage: str,
        urgency: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        saved = await self._service().submit_execution_checkpoint(
            self._run_id(),
            caller_id,
            self._state_context(caller_id),
            summary=summary,
            next_step=next_step,
            task_stage=task_stage,
            urgency=urgency,
            evidence_refs=evidence_refs,
        )
        # An interrupt checkpoint is an explicit verified handoff: preserve the
        # checkpointing lane and the persistent Bootstrap lane, but stop only
        # discovery Executions that would otherwise continue stale exploration.
        # Informational checkpoints only wake consumers.
        if not saved.get("idempotent") and urgency == "interrupt":
            await self._stop_competing_executions(
                unique_code=self.nodes[caller_id].unique_code or "",
                exclude_agent_id=caller_id,
                discovery_only=True,
            )
        handoff = False
        # A discovery interrupt is a verified handoff to the deterministic
        # validation follow-up.  End this broad lane after the checkpoint is
        # durable so it cannot continue probing while the follow-up runs.
        if (
            not saved.get("idempotent")
            and urgency == "interrupt"
            and task_stage == "discovery"
        ):
            handoff_result = await self._service().finalize_execution_handoff(
                self._run_id(),
                caller_id,
                self._state_context(caller_id),
                checkpoint_report_id=saved["report_id"],
            )
            handoff = bool(handoff_result.get("handoff"))
        await self._project()
        await self._sync_nodes()
        return {
            "ok": True,
            "data": {
                "agent_id": caller_id,
                "sequence": saved["sequence"],
                "status": saved["status"],
                "terminal": False,
                "report_id": saved["report_id"],
                "urgency": saved["urgency"],
                "idempotent": saved.get("idempotent", False),
                "handoff": handoff,
                "handoff_terminal": handoff,
            },
            "warnings": saved.get("warnings", []),
        }

    async def _stop_competing_executions(
        self,
        *,
        unique_code: str,
        exclude_agent_id: str,
        discovery_only: bool = True,
    ) -> None:
        """Stop stale sibling discovery Executions after a verified handoff."""

        if not unique_code:
            return
        overview = await self._service().get_overview(self._run_id())
        candidates = [
            item
            for item in overview.get("agents", [])
            if item.get("role") == "execution"
            and item.get("kind") != "bootstrap"
            and item.get("unique_code") == unique_code
            and item.get("agent_id") != exclude_agent_id
            and item.get("status") not in self.TERMINAL_AGENT_STATES
            and (
                not discovery_only
                or (item.get("task_stage") or "discovery") == "discovery"
            )
        ]
        if not candidates:
            return
        await asyncio.gather(
            *(self._stop_agent(item["agent_id"]) for item in candidates)
        )
        await self._service().append_agent_event(
            self._run_id(),
            exclude_agent_id,
            "execution_checkpoint_siblings_stopped",
            {
                "unique_code": unique_code,
                "stopped_count": len(candidates),
                "discovery_only": discovery_only,
                "stopped_task_stages": sorted(
                    {item.get("task_stage") or "discovery" for item in candidates}
                ),
            },
        )

    async def read_evidence(
        self,
        caller_id: str,
        evidence_ref: str,
        *,
        offset: int = 0,
        limit_chars: int = 8_000,
    ) -> dict[str, Any]:
        node = self.nodes.get(caller_id)
        if node is None or node.role not in {"challenge", "execution"}:
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

    async def _prepare_bootstrap_shared_context(
        self, agent_id: str
    ) -> Mapping[str, Any] | None:
        """Return a replayable sibling-report update before a Bootstrap request."""

        return await self._service().prepare_bootstrap_shared_update(
            self._run_id(),
            self._state_context(agent_id),
            max_reports=20,
            max_chars=8_000,
        )

    async def _ack_bootstrap_shared_context(
        self, agent_id: str, update: Mapping[str, Any]
    ) -> None:
        through = update.get("through_sequence")
        if isinstance(through, int):
            await self._service().acknowledge_bootstrap_shared_update(
                self._run_id(), self._state_context(agent_id), through
            )

    async def wait_for_state(
        self,
        caller_id: str,
        reason: str | None,
    ) -> ToolDispatchOutcome:
        self._require_role(caller_id, "challenge")
        result = await self._service().record_controller_wait(
            self._run_id(), caller_id, reason
        )
        await self._sync_nodes()
        return ToolDispatchOutcome(
            self._ok(result),
            yield_session=result.get("status") == "waiting",
        )

    async def _register_dispatch_admissions(
        self, unique_code: str, admissions: Any
    ) -> None:
        if not isinstance(admissions, list) or not admissions:
            return
        self._issue_capabilities(
            [
                {
                    "agent_id": item["agent_id"],
                    "role": "execution",
                    "unique_code": unique_code,
                }
                for item in admissions
                if isinstance(item, Mapping)
                and isinstance(item.get("agent_id"), str)
            ]
        )
        await self._sync_nodes()
        for item in admissions:
            if not isinstance(item, Mapping) or not isinstance(
                item.get("agent_id"), str
            ):
                continue
            task = asyncio.create_task(
                self._prefetch_execution_skill(str(item["agent_id"])),
                name=f"skill-discovery-bootstrap-{item['agent_id']}",
            )
            self._skill_discovery_bootstrap_tasks.add(task)
            task.add_done_callback(self._skill_discovery_bootstrap_tasks.discard)

    async def resume(self, run_id: str) -> dict[str, Any]:
        await self._ensure_service(run_id)
        self.run_id = run_id
        await self._prepare_resume(run_id)
        if self.chief_agent_id:
            await self.refresh_challenges(self.chief_agent_id)
        return self._ok(
            {
                "run_id": run_id,
                "agents": (await self._service().get_overview(run_id))["agents"],
            }
        )

    async def close(self) -> None:
        self._pausing = False
        if self._poll_task is not None:
            self._poll_task.cancel()
            await self._ignore_cancel(self._poll_task)
            self._poll_task = None
        await self._close_skill_discovery()
        completion_tasks = list(self._challenge_completion_tasks.values())
        self._challenge_completion_tasks.clear()
        if completion_tasks:
            await asyncio.gather(*completion_tasks, return_exceptions=True)
        await self._stop_all()
        managers = (
            ("_browser", self._browser),
            ("_proxy", self._proxy),
            ("_http_interactions", self._http_interactions),
            ("_network_discovery", self._network_discovery),
            ("_shell_tasks", self._shell_tasks),
        )
        for attribute, manager in managers:
            if manager is None:
                continue
            try:
                await manager.finish_run()
            except Exception:
                LOGGER.exception("resource manager close failed: %s", attribute)
            setattr(self, attribute, None)
        for runner in list(self._runners.values()):
            try:
                await runner.close()
            except Exception:
                pass
        self._runners.clear()
        await self._close_model_http_client()
        await self._project()

    async def pause(self) -> None:
        """Cancel live work while preserving resumable orchestration state."""

        self._pausing = True
        if self._poll_task is not None:
            self._poll_task.cancel()
            await self._ignore_cancel(self._poll_task)
            self._poll_task = None
        await self._close_skill_discovery()
        if self._browser is not None:
            try:
                await self._browser.pause_run()
            finally:
                self._browser = None
        if self._proxy is not None:
            try:
                await self._proxy.pause_run()
            finally:
                self._proxy = None
        if self._shell_tasks is not None:
            try:
                await self._shell_tasks.pause_run()
            finally:
                self._shell_tasks = None
        if self._http_interactions is not None:
            try:
                await self._http_interactions.pause_run()
            finally:
                self._http_interactions = None
        if self._network_discovery is not None:
            try:
                await self._network_discovery.pause_run()
            finally:
                self._network_discovery = None
        await self._pause_all()
        await self._service().interrupt_execution_agents(self._run_id())
        for runner in list(self._runners.values()):
            try:
                await runner.close()
            except Exception:
                pass
        self._runners.clear()
        await self._close_model_http_client()
        await self._sync_nodes()
        await self._project()

    async def _launch_agent(self, agent_id: str, *, resume: bool = False) -> None:
        existing = self._tasks.get(agent_id)
        if existing is not None and not existing.done():
            return
        if existing is not None and existing.done():
            await self._ignore_cancel(existing)
        runtime = await self._service().get_agent_runtime(self._run_id(), agent_id)
        agent = runtime["agent"]
        role: AgentRole = agent["role"]
        initial_wake_sequence = max(
            int(agent.get("controller_cursor") or 0),
            await self._service().notifier.current(
                self._service().agent_signal_key(self._run_id(), agent_id)
            ),
        )
        if role in {"chief", "challenge"}:
            await self._service().transition_controller(
                self._run_id(),
                agent_id,
                "running",
                controller_cursor=initial_wake_sequence,
            )
        else:
            await self._service().transition_agent(
                self._run_id(), agent_id, "running"
            )
            await self._service().mark_execution_branch_running(
                self._run_id(), agent_id
            )
            if agent.get("kind") == "bootstrap":
                await self._service().append_agent_event(
                    self._run_id(),
                    agent_id,
                    "bootstrap_started",
                    {
                        "priority": agent.get("priority", 100),
                        "lifecycle": "challenge_bound",
                    },
                )
        await self._sync_nodes()

        first_session_started = asyncio.Event()

        async def execute() -> Any:
            failure_code: str | None = None
            failure_message: str | None = None
            session_resume = resume
            wake_sequence = initial_wake_sequence
            controller_recovery_attempt = 0
            controller_recovery_started: float | None = None
            self._heartbeat_tasks[agent_id] = asyncio.create_task(
                self._heartbeat_loop(agent_id), name=f"aion-heartbeat-{agent_id}"
            )
            try:
                while True:
                    if role == "chief" and await self._remaining_run_seconds() <= 0:
                        result = {"final": "Run deadline reached"}
                        await self._settle_controller(agent_id, role, result)
                        return result
                    if role in {"chief", "challenge"}:
                        await self._service().transition_controller(
                            self._run_id(),
                            agent_id,
                            "running",
                            controller_cursor=wake_sequence,
                        )
                    else:
                        await self._service().transition_agent(
                            self._run_id(), agent_id, "running"
                        )
                    await self._sync_nodes()
                    session = self._run_agent_session(
                        agent_id,
                        role,
                        resume=session_resume,
                        started_event=(
                            first_session_started
                            if not first_session_started.is_set()
                            else None
                        ),
                    )
                    try:
                        if role == "chief":
                            result = await asyncio.wait_for(
                                session, timeout=await self._remaining_run_seconds()
                            )
                        else:
                            result = await session
                    except asyncio.TimeoutError:
                        if role != "chief":
                            raise
                        result = {"final": "Run deadline reached"}
                        await self._settle_controller(agent_id, role, result)
                        return result
                    except AgentRunnerError as exc:
                        if role not in {"chief", "challenge"} or not exc.recoverable:
                            raise
                        controller_recovery_attempt += 1
                        if controller_recovery_started is None:
                            controller_recovery_started = asyncio.get_running_loop().time()
                        delay = (1.0, 2.0, 5.0, 10.0)[
                            min(controller_recovery_attempt - 1, 3)
                        ]
                        await self._service().append_agent_event(
                            self._run_id(),
                            agent_id,
                            "controller_session_recovery_scheduled",
                            {
                                "role": role,
                                "code": exc.code,
                                "recovery_attempt": controller_recovery_attempt,
                                "recovery_delay_ms": int(delay * 1_000),
                            },
                        )
                        waiting = await self._service().transition_controller(
                            self._run_id(),
                            agent_id,
                            "waiting",
                            controller_cursor=wake_sequence,
                        )
                        await self._sync_nodes()
                        cursor = max(
                            wake_sequence,
                            int(waiting.get("controller_cursor") or 0),
                            await self._service().notifier.current(
                                self._service().agent_signal_key(
                                    self._run_id(), agent_id
                                )
                            ),
                        )
                        signal = await self._service().notifier.wait(
                            self._service().agent_signal_key(
                                self._run_id(), agent_id
                            ),
                            cursor,
                            min(delay, await self._remaining_run_seconds()),
                        )
                        wake_sequence = max(cursor, signal)
                        session_resume = True
                        continue
                    if controller_recovery_attempt:
                        assert controller_recovery_started is not None
                        await self._service().append_agent_event(
                            self._run_id(),
                            agent_id,
                            "controller_session_recovered",
                            {
                                "role": role,
                                "recovery_attempt": controller_recovery_attempt,
                                "controller_recovery_latency_ms": int(
                                    (
                                        asyncio.get_running_loop().time()
                                        - controller_recovery_started
                                    )
                                    * 1_000
                                ),
                            },
                        )
                        controller_recovery_attempt = 0
                        controller_recovery_started = None
                    if role == "execution":
                        if (
                            agent.get("kind") == "bootstrap"
                            and isinstance(result, AgentSessionResult)
                            and result.yield_reason == "bootstrap_cycle_yield"
                        ):
                            # A cycle boundary is not a terminal report. Keep
                            # the same logical lane and resume with durable
                            # memory/context instead of creating a replacement
                            # Agent or entering missing-report recovery.
                            session_resume = True
                            wake_sequence = max(
                                wake_sequence,
                                await self._service().notifier.current(
                                    self._service().agent_signal_key(
                                        self._run_id(), agent_id
                                    )
                                ),
                            )
                            continue
                        if (
                            agent.get("kind") == "bootstrap"
                            and isinstance(result, AgentSessionResult)
                            and not result.structured_report_seen
                        ):
                            await self._service().yield_bootstrap_cycle(
                                self._run_id(),
                                agent_id,
                                self._state_context(agent_id),
                                summary="Bootstrap session ended without a terminal candidate; resume the same lane.",
                            )
                            session_resume = True
                            continue
                        return result
                    terminal = await self._settle_controller(agent_id, role, result)
                    if terminal:
                        return result
                    waiting = await self._service().transition_controller(
                        self._run_id(), agent_id, "waiting"
                    )
                    await self._sync_nodes()
                    cursor = max(
                        int(waiting.get("controller_cursor") or 0), wake_sequence
                    )
                    wait_seconds = self.CONTROLLER_SAFETY_WAKE_SECONDS
                    if role == "chief":
                        wait_seconds = min(
                            wait_seconds, await self._remaining_run_seconds()
                        )
                    agent_signal_key = self._service().agent_signal_key(
                        self._run_id(), agent_id
                    )
                    signal = await self._service().notifier.wait(
                        agent_signal_key, cursor, wait_seconds
                    )
                    if await self._settle_controller(agent_id, role, result):
                        return result
                    if signal <= cursor:
                        signal = await self._service().append_agent_event(
                            self._run_id(),
                            agent_id,
                            "controller_safety_wakeup",
                            {"role": role},
                        )
                        await self._service().notifier.notify(
                            agent_signal_key, signal
                        )
                    wake_sequence = signal
                    session_resume = True
            except asyncio.TimeoutError as exc:
                failure_code = "timeout"
                failure_message = "Execution Agent timed out"
                raise SubagentError("Agent execution timed out") from exc
            except asyncio.CancelledError:
                failure_code = "cancelled"
                failure_message = "Execution Agent was cancelled before reporting"
                raise
            except Exception as exc:
                failure_code, failure_message = self._execution_failure(exc)
                current = await self._service().get_agent_runtime(
                    self._run_id(), agent_id
                )
                if (
                    role != "execution"
                    and current["agent"]["status"] not in self.TERMINAL_AGENT_STATES
                ):
                    await self._service().finish_agent(
                        self._run_id(), agent_id, status="failed"
                    )
                raise
            finally:
                heartbeat = self._heartbeat_tasks.pop(agent_id, None)
                if heartbeat is not None:
                    heartbeat.cancel()
                if role == "execution" and not self._pausing:
                    current = await self._service().get_agent_runtime(
                        self._run_id(), agent_id
                    )
                    if current["agent"].get("terminal_report_id") is None:
                        await self._record_execution_failure(
                            agent_id,
                            failure_code or "missing_structured_report",
                            failure_message or "Execution Agent ended without a structured report",
                        )
                        await self._finalize_missing_report(
                            agent_id,
                            failure_code=failure_code or "missing_structured_report",
                            failure_message=failure_message,
                        )
                if role == "execution":
                    current = await self._service().get_agent_runtime(
                        self._run_id(), agent_id
                    )
                    if (
                        current["agent"]["status"] in self.TERMINAL_AGENT_STATES
                        and not self._pausing
                    ):
                        await self._finish_agent_resources(agent_id)
                    if (
                        current["agent"].get("kind") == "bootstrap"
                        and current["agent"].get("status")
                        in self.TERMINAL_AGENT_STATES
                        and current["agent"].get("unique_code")
                        and current["agent"].get("parent_id")
                        and not self._pausing
                        and failure_code != "cancelled"
                    ):
                        try:
                            await self._ensure_bootstrap_agent(
                                str(current["agent"]["unique_code"]),
                                str(current["agent"]["parent_id"]),
                                reason=(
                                    "bootstrap_report_cycle"
                                    if failure_code is None
                                    else "bootstrap_recovery"
                                ),
                            )
                        except Exception:
                            LOGGER.warning(
                                "bootstrap_reactivation_failed run_id=%s agent_id=%s",
                                self._run_id(),
                                agent_id,
                                exc_info=True,
                            )
                await self._sync_nodes()

        task = asyncio.create_task(execute(), name=f"aion-{agent_id}")
        self._tasks[agent_id] = task
        started_wait = asyncio.create_task(first_session_started.wait())
        done, _ = await asyncio.wait(
            {task, started_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done and not first_session_started.is_set():
            started_wait.cancel()
            await task
        if not started_wait.done():
            started_wait.cancel()
        await self._ignore_cancel(started_wait)

    async def _run_agent_session(
        self,
        agent_id: str,
        role: AgentRole,
        *,
        resume: bool,
        started_event: asyncio.Event | None = None,
    ) -> AgentSessionResult | Any:
        runtime = await self._service().get_agent_runtime(self._run_id(), agent_id)
        agent = runtime["agent"]
        prompt = agent["initial_prompt"]
        if not prompt:
            raise SubagentError("Agent does not have an initial prompt")
        bootstrap_mode = role == "execution" and agent.get("kind") == "bootstrap"
        if role == "execution" and not bootstrap_mode:
            assignment = await self._service().get_assignment(
                self._run_id(), agent_id, self._state_context(agent_id)
            )
            prompt = self._execution_prompt(assignment)
            if started_event is not None:
                started_event.set()
        elif bootstrap_mode:
            # Bootstrap has a standalone mission prompt.  It intentionally
            # does not call execution_get_assignment or expose a controller
            # management turn before its first technical action.
            if started_event is not None:
                started_event.set()
        elif role == "challenge":
            snapshot = await self._service().observe_challenge(
                self._run_id(),
                str(agent["unique_code"]),
                self._state_context(agent_id),
                max_reports=8,
                replay_pending_snapshot=True,
            )
            prompt = (
                f"{prompt}\n\n# Authoritative controller snapshot\n"
                f"{json.dumps(snapshot, ensure_ascii=False, default=str)}"
            )
        else:
            snapshot_result = await self.observe_chief(agent_id, max_reports=20)
            prompt = (
                f"{prompt}\n\n# Authoritative controller snapshot\n"
                f"{json.dumps(snapshot_result.get('data', {}), ensure_ascii=False, default=str)}"
            )
        previous_runner = self._runners.pop(agent_id, None)
        if previous_runner is not None:
            try:
                await previous_runner.close()
            except Exception:
                pass
        skill_context: SkillSessionContext | None = None
        if role in {"challenge", "execution"}:
            try:
                selection_text = await self._skill_selection_text(role, agent)
                presented_candidates: list[dict[str, Any]] = []
                discovery_result = None
                execution_direction: str | None = None
                if role == "execution":
                    execution_direction = str(
                        agent.get("direction")
                        or (await self._challenge_record(agent.get("unique_code"))).get(
                            "direction"
                        )
                        or "unknown"
                    )
                    selection_text = " ".join(
                        (
                            selection_text,
                            f"direction: {execution_direction}",
                            f"task_key: {agent.get('task_key') or ''}",
                            f"branch_key: {agent.get('branch_key') or ''}",
                        )
                    )
                    discovery_result = await self._skill_discovery_service().candidates_for(
                        agent_id,
                        objective=str(agent.get("mission") or ""),
                        direction=execution_direction,
                        task_stage=(
                            str(agent["task_stage"])
                            if agent.get("task_stage") is not None
                            else None
                        ),
                        hypothesis=(
                            str(agent["hypothesis_key"])
                            if agent.get("hypothesis_key") is not None
                            else None
                        ),
                        excluded_ids=tuple(
                            str(item.get("skill_id"))
                            for item in agent.get("active_skills", [])
                            if isinstance(item, Mapping) and item.get("skill_id")
                        ),
                    )
                    presented_candidates = [
                        candidate.public()
                        for candidate in discovery_result.candidates
                    ]
                skill_context = SkillSessionContext(
                    self.skill_catalog,
                    role=role,
                    service=self._service(),
                    run_id=self._run_id(),
                    agent_id=agent_id,
                    active_skills=agent.get("active_skills", []),
                    selection_text=selection_text,
                    presented_candidates=presented_candidates,
                )
                await skill_context.ensure_auto_activated()
                if role == "execution":
                    assert discovery_result is not None
                    await self._service().append_agent_event(
                        self._run_id(),
                        agent_id,
                        "skill_candidate_presented",
                        {
                            **skill_context.listing_metrics,
                            "candidate_ids": [
                                item["skill_id"] for item in presented_candidates
                            ],
                            "strong_match_ids": [
                                item["skill_id"]
                                for item in presented_candidates
                                if item.get("match_strength") == "strong"
                            ],
                            "recommended_ids": [
                                item["skill_id"]
                                for item in presented_candidates
                                if item.get("recommended") is True
                            ],
                            "source": discovery_result.source,
                            "discovery_latency_ms": discovery_result.latency_ms,
                            "cache_hit": discovery_result.cache_hit,
                            "discovery_call_id": discovery_result.discovery_call_id,
                        },
                    )
                else:
                    await self._service().append_agent_event(
                        self._run_id(),
                        agent_id,
                        "skill_top_k_selected",
                        skill_context.listing_metrics,
                    )
            except SkillCatalogError as exc:
                await self._service().append_agent_event(
                    self._run_id(),
                    agent_id,
                    "skill_context_restore_failed",
                    {
                        "code": exc.code,
                        "details": exc.detail,
                    },
                )
                raise
        store = await AgentStateStore.open(
            self._service(),
            run_id=self._run_id(),
            agent_id=agent_id,
            run_dir=self._run_dir(),
        )
        result_tools = ToolResultTools(ToolResultStore(store.run_dir, agent_id))
        if role == "chief":
            wrappers: list[Any] = [result_tools, ChiefAgentTools(self, agent_id=agent_id)]
        elif role == "challenge":
            assert skill_context is not None
            wrappers = [
                result_tools,
                SkillTools(skill_context),
                ChallengeAgentTools(
                    self, agent_id=agent_id, unique_code=agent["unique_code"]
                )
            ]
        else:
            assert skill_context is not None
            if (
                self._shell_tasks is None
                or self._http_interactions is None
                or self._network_discovery is None
                or self._browser is None
                or self._proxy is None
            ):
                raise SubagentError("Execution task managers are not initialized")
            shell_client = self._shell_tasks.bind(
                agent_id,
                shared_root=self._shell_tasks.shared_workspace_root(
                    str(agent["unique_code"])
                ),
            )
            wrappers = [
                result_tools,
                SkillTools(skill_context),
                SystemTools(
                    root=self.project_root,
                    shell=shell_client,
                    agent_work_root=shell_client.agent_work_root,
                    shared_work_root=shell_client.shared_work_root,
                ),
                HttpTools(self._http_interactions.bind(agent_id)),
                NetworkTools(self._network_discovery.bind(agent_id)),
                BrowserTools(self._browser.bind(agent_id, shell_client)),
                ProxyTools(self._proxy),
                BinaryTools(self.project_root, toolchain_root=self.toolchain_root),
                ArtifactTools(self.project_root),
                PentestTools(root=self.project_root, toolchain_root=self.toolchain_root),
                ExecutionAgentTools(
                    self,
                    agent_id=agent_id,
                    unique_code=agent["unique_code"],
                    bootstrap_mode=bootstrap_mode,
                ),
            ]
        live_context_provider = None
        live_context_ack = None
        if bootstrap_mode:
            live_context_provider = lambda: self._prepare_bootstrap_shared_context(
                agent_id
            )
            live_context_ack = lambda update: self._ack_bootstrap_shared_context(
                agent_id, update
            )
        runner_options: dict[str, Any] = {}
        if bootstrap_mode:
            runner_options = {
                "live_context_provider": live_context_provider,
                "live_context_ack": live_context_ack,
                "bootstrap_mode": True,
                "session_timeout_seconds": float(
                    self._effective_execution_timeout(agent)
                ),
            }
        elif role == "execution":
            runner_options = {
                "session_timeout_seconds": float(
                    self._effective_execution_timeout(agent)
                ),
            }
        runner = self.runner_factory(
            self.settings,
            ToolRegistry(wrappers, allowed_tools=AgentPolicy(role).allowed_tools),
            max_rounds=(
                BOOTSTRAP_MAX_ROUNDS
                if bootstrap_mode
                else (200 if role == "execution" else 1_000)
            ),
            run_root=self.run_root,
            role=role,
            agent_id=agent_id,
            parent_id=agent["parent_id"],
            base_system_prompt=self._system_prompt(
                "bootstrap" if bootstrap_mode else role
            ),
            system_context_provider=(
                skill_context.render_system_context if skill_context is not None else None
            ),
                require_structured_report=role == "execution" and not bootstrap_mode,
            state_service=self._service(),
            http_client=self._shared_model_http_client(),
            **runner_options,
        )
        self._runners[agent_id] = runner
        if started_event is not None and not started_event.is_set():
            started_event.set()
        await self._service().append_agent_event(
            self._run_id(), agent_id, "agent_runner_started", {"role": role}
        )
        try:
            operation = runner.run_session(prompt, store=store, resume=resume)
            timeout = (
                self._effective_execution_timeout(agent)
                if role == "execution"
                else None
            )
            try:
                return (
                    await asyncio.wait_for(operation, timeout=timeout)
                    if timeout
                    else await operation
                )
            except asyncio.TimeoutError:
                if not bootstrap_mode:
                    raise
                await self._service().yield_bootstrap_cycle(
                    self._run_id(),
                    agent_id,
                    self._state_context(agent_id),
                    summary="Bootstrap cycle reached its time budget; resume the same lane with persisted context.",
                )
                return AgentSessionResult(
                    run_id=self._run_id(),
                    final="",
                    last_event_sequence=int(store.checkpoint.last_event_sequence),
                    structured_report_seen=False,
                    yield_reason="bootstrap_cycle_yield",
                )
        finally:
            self._runners.pop(agent_id, None)
            try:
                await runner.close()
            except Exception:
                pass

    @classmethod
    def _effective_execution_timeout(cls, agent: Mapping[str, Any]) -> int:
        """Apply the competition timeout floor to persisted and new tasks."""

        if agent.get("kind") == "bootstrap":
            value = agent.get("timeout_seconds")
            if not isinstance(value, int) or isinstance(value, bool):
                value = BOOTSTRAP_CYCLE_TIMEOUT_SECONDS
            return min(BOOTSTRAP_CYCLE_TIMEOUT_SECONDS, max(60, value))
        stage = str(agent.get("task_stage") or "discovery")
        floor = cls.EXECUTION_TIMEOUT_FLOORS.get(stage, 1_800)
        value = agent.get("timeout_seconds")
        if not isinstance(value, int) or isinstance(value, bool):
            value = 1_800
        return min(3_600, max(floor, value))

    async def _skill_selection_text(
        self, role: AgentRole, agent: Mapping[str, Any]
    ) -> str:
        """Build bounded Top-K routing text from current authoritative state."""

        values: list[Any] = [
            agent.get("mission"),
            agent.get("task_stage"),
            agent.get("hypothesis_key"),
        ]
        if role != "execution":
            unique_code = str(agent.get("unique_code") or "")
            state = await self._service().get_challenge_context(
                self._run_id(),
                unique_code,
                self._state_context(str(agent["agent_id"])),
                compact=True,
            )
            challenge = state.get("challenge")
            if isinstance(challenge, Mapping):
                values.extend(
                    [
                        challenge.get("description"),
                        challenge.get("direction"),
                    ]
                )
            values.extend(
                [
                    [
                        {
                            "category": item.get("category"),
                            "summary": item.get("summary"),
                            "verification_status": item.get(
                                "verification_status"
                            ),
                        }
                        for item in list(state.get("findings") or [])[-10:]
                        if isinstance(item, Mapping)
                    ],
                ]
            )
        return " ".join(
            json.dumps(value, ensure_ascii=False, default=str)
            if isinstance(value, (Mapping, list))
            else str(value or "")
            for value in values
        )[:8_000]

    async def _prefetch_execution_skill(self, agent_id: str) -> None:
        try:
            runtime = await self._service().get_agent_runtime(
                self._run_id(), agent_id
            )
            agent = runtime["agent"]
            self._skill_discovery_service().prefetch(
                agent_id,
                objective=str(agent.get("mission") or ""),
                direction=str(
                    agent.get("direction")
                    or (await self._challenge_record(agent.get("unique_code"))).get("direction")
                    or "unknown"
                ),
                task_stage=(
                    str(agent["task_stage"])
                    if agent.get("task_stage") is not None
                    else None
                ),
                hypothesis=(
                    str(agent["hypothesis_key"])
                    if agent.get("hypothesis_key") is not None
                    else None
                ),
                excluded_ids=tuple(
                    str(item.get("skill_id"))
                    for item in agent.get("active_skills", [])
                    if isinstance(item, Mapping) and item.get("skill_id")
                ),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.warning(
                "skill_discovery_prefetch_failed run_id=%s agent_id=%s",
                self.run_id,
                agent_id,
            )

    def _skill_discovery_service(self) -> SkillDiscovery:
        service = self._skill_discovery
        if service is None:
            service = SkillDiscovery(
                self.settings,
                self.skill_catalog,
                self._service(),
                self._run_id(),
            )
            self._skill_discovery = service
        return service

    async def _close_skill_discovery(self) -> None:
        bootstrap = list(self._skill_discovery_bootstrap_tasks)
        for task in bootstrap:
            task.cancel()
        if bootstrap:
            await asyncio.gather(*bootstrap, return_exceptions=True)
        self._skill_discovery_bootstrap_tasks.clear()
        service = self._skill_discovery
        self._skill_discovery = None
        if service is not None:
            await service.close()

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
        agent = next(item for item in overview["agents"] if item["agent_id"] == agent_id)
        if agent["status"] in self.TERMINAL_AGENT_STATES:
            return True
        report = self._session_report(result)
        if role == "challenge":
            challenge = next(
                item
                for item in overview["challenges"]
                if item["unique_code"] == agent["unique_code"]
            )
            if challenge["is_completed"] or challenge["work_status"] == "closed":
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="completed", final_report=report
                )
                return True
            return False

        run = overview["run"]
        deadline_reached = aware(self._service().clock()) >= aware(
            datetime.fromisoformat(run["deadline_at"])
        )
        challenges = overview["challenges"]
        challenges_terminal = bool(challenges) and all(
            item["is_completed"] or item["work_status"] == "closed"
            for item in challenges
        )
        descendants_terminal = all(
            item["agent_id"] == agent_id
            or item["status"] in self.TERMINAL_AGENT_STATES
            for item in overview["agents"]
        )
        if not deadline_reached and not (
            challenges_terminal and descendants_terminal
        ):
            return False
        if deadline_reached:
            await self._stop_descendants(agent_id)
        await self._service().finish_agent(
            self._run_id(), agent_id, status="completed", final_report=report
        )
        await self._service().finish_run(
            self._run_id(), "completed", report=report
        )
        return True

    async def _remaining_run_seconds(self) -> float:
        overview = await self._service().get_overview(self._run_id())
        deadline = aware(datetime.fromisoformat(overview["run"]["deadline_at"]))
        return max(
            0.0, (deadline - aware(self._service().clock())).total_seconds()
        )

    async def _stop_descendants(self, root_id: str) -> None:
        overview = await self._service().get_overview(self._run_id())
        descendants = [
            item for item in overview["agents"] if item["agent_id"] != root_id
        ]
        for role in ("execution", "challenge"):
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
                self.HEARTBEAT_EVENT_INTERVAL_SECONDS
                / self.HEARTBEAT_INTERVAL_SECONDS
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
        operation_id = await self._service().mark_operation_started(
            self._run_id(),
            tool_name,
            agent_id=caller_id,
            unique_code=unique_code,
            arguments=arguments,
        )
        try:
            if self.benchmark is None:
                raise RuntimeError("benchmark unavailable")
            result = await self._benchmark_execute(tool_name, arguments)
        except Exception:
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
        if not result.get("ok") and self._is_ambiguous_benchmark_response(result):
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
                        "hint_eligible": False,
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
                error_message=str(
                    redact_value(message, secrets=operation_secrets)
                ),
                result_payload=redact_value(result, secrets=operation_secrets),
            )
            return result
        operation_secrets = (
            (str(arguments["flag"]),)
            if isinstance(arguments.get("flag"), str)
            else ()
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
            details.get("status_code")
            if isinstance(details, Mapping)
            else None
        )
        return status_code in {404, 405, 501}

    async def _mark_benchmark_capability_unavailable(self, tool_name: str) -> None:
        operation = tool_name.removeprefix("benchmark_")
        self._benchmark_unavailable.add(operation)
        if operation == "get_hint":
            await self._service().disable_hint_eligibility(
                self._run_id(), reason="benchmark_endpoint_unavailable"
            )

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
                if tool_name == "benchmark_start_challenge" and container_slot_occupied(
                    after.get("container_status")
                ):
                    return self._ok(
                        {
                            "unique_code": unique_code,
                            "container_addr": list(after.get("container_addr") or []),
                            "reconciled": True,
                        }
                    )
                if tool_name == "benchmark_close_challenge" and not container_slot_occupied(
                    after.get("container_status")
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
                                "accepted": True,
                                "correct": True,
                                "awarded": 0,
                                "cumulative_score": 0,
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
            return {"hint_requested": True, "hint_eligible": False}
        if tool_name == "benchmark_close_challenge":
            current = await self._challenge_record(unique_code)
            return {
                "platform_status": "close_requested",
                "container_status": "release_pending",
                "work_status": (
                    "completed" if current["is_completed"] else "closed"
                    if current["work_status"] != "paused"
                    else "paused"
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
            completed = total_count > 0 and correct_count >= total_count
            updates: dict[str, Any] = {
                "flag_count": total_count,
                "correct_flag_count": correct_count,
                "is_completed": completed,
            }
            if completed:
                updates.update(
                    {
                        "platform_status": "completed",
                        "work_status": "completed",
                    }
                )
            if bool(data.get("correct")) and correct_count > current["correct_flag_count"]:
                updates["progress_kind"] = "flag_accepted"
            return updates
        return {}

    async def _benchmark_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
        self, name: str, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        if self.benchmark is None:
            raise RuntimeError("benchmark unavailable")
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
        result = calls[0].result
        if not isinstance(result, Mapping):
            raise RuntimeError("invalid benchmark response")
        return dict(result)

    async def _prepare_resume(self, run_id: str) -> None:
        service = self._service()
        if not await service.run_exists(run_id):
            raise SubagentError("run state database was not found")
        await service.restore_run(run_id)
        overview = await service.get_overview(run_id)
        await service.resume_run(run_id)
        overview = await service.get_overview(run_id)
        chief = next((item for item in overview["agents"] if item["role"] == "chief"), None)
        self.chief_agent_id = chief["agent_id"] if chief else None
        self._issue_capabilities(overview["agents"])
        # Bootstrap is resumable from its persisted conversation.  Other
        # Executions retain the existing no-replay recovery semantics.
        await service.interrupt_execution_agents(run_id, exclude_kinds=("bootstrap",))
        await self._sync_nodes()

    async def _restart_challenge_agents(self) -> None:
        overview = await self._service().get_overview(self._run_id())
        challenges = {
            challenge["unique_code"]: challenge
            for challenge in overview.get("challenges", [])
        }
        for agent in overview["agents"]:
            if agent["role"] != "challenge":
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

            # A service pause stops the Challenge Agent process, but must not
            # turn an unfinished challenge into a terminal controller. Resume
            # every unfinished challenge, including one whose persisted agent
            # status is stopped, while completed/closed challenges stay done.
            if challenge.get("is_completed") or challenge.get("work_status") in {"closed", "paused"}:
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
            await self._ensure_bootstrap_agent(
                str(unique_code),
                str(agent["agent_id"]),
                reason="resume_active_challenge",
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

    async def _finalize_missing_report(
        self,
        agent_id: str,
        *,
        failure_code: str = "missing_structured_report",
        failure_message: str | None = None,
    ) -> None:
        cancelled = failure_code == "cancelled"
        evidence_refs: list[str] = []
        try:
            evidence_refs = [
                str(item["evidence_ref"])
                for item in await self._service().list_evidence_metadata(
                    self._run_id(), self._state_context(agent_id), limit=20
                )
                if isinstance(item, Mapping) and item.get("evidence_ref")
            ][:20]
        except Exception:
            # A missing evidence snapshot must not mask the original Agent
            # failure or prevent the terminal state from being persisted.
            evidence_refs = []
        payload = AgentReportInput(
            status="cancelled" if cancelled else "failed",
            summary=(
                failure_message
                or "Execution Agent ended without a structured report"
            )[:4_000],
            findings=[],
            evidence_refs=evidence_refs,
            next_steps=[],
            hypothesis_outcome="inconclusive",
        )
        await self._service().finalize_execution_agent(
            self._run_id(),
            agent_id,
            self._state_context(agent_id),
            payload,
        )

    async def _record_execution_failure(
        self,
        agent_id: str,
        failure_code: str,
        failure_message: str,
    ) -> None:
        try:
            await self._service().append_agent_event(
                self._run_id(),
                agent_id,
                "agent_execution_failed",
                {
                    "code": failure_code,
                    "message": failure_message[:1_000],
                },
            )
        except Exception:
            pass

    def _execution_failure(self, exc: Exception) -> tuple[str, str]:
        if isinstance(exc, AgentRunnerError):
            message = str(exc)
            if exc.code != "agent_runner_failed":
                return exc.code, message
            if "without a structured report" in message:
                return "missing_structured_report", message
            if "LLM request failed" in message:
                return "llm_request_failed", message
            if "LLM response" in message:
                return "invalid_llm_response", message
            return "agent_runner_failed", message
        try:
            safe_detail = str(
                redact_value(
                    str(exc),
                    secrets=(
                        self.settings.llm_api_key.get_secret_value(),
                        *self._service().ephemeral_secrets(),
                    ),
                )
            )
        except Exception:
            safe_detail = ""
        safe_detail = safe_detail.strip()[:800]
        detail = f"{type(exc).__name__}: {safe_detail}" if safe_detail else type(exc).__name__
        return "agent_execution_failed", f"Execution Agent failed before reporting ({detail})"

    async def _stop_children(self, parent_id: str) -> None:
        overview = await self._service().get_overview(self._run_id())
        await asyncio.gather(
            *(
                self._stop_agent(item["agent_id"])
                for item in overview["agents"]
                if item["parent_id"] == parent_id
                and item["status"] not in self.TERMINAL_AGENT_STATES
            ),
        )

    async def _stop_all(self) -> None:
        overview = await self._service().get_overview(self._run_id())
        await asyncio.gather(
            *(
                self._stop_agent(item["agent_id"])
                for item in overview["agents"]
                if item["status"] not in self.TERMINAL_AGENT_STATES
            ),
        )

    async def _pause_all(self) -> None:
        tasks = list(self._tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for heartbeat in list(self._heartbeat_tasks.values()):
            heartbeat.cancel()
        if self._heartbeat_tasks:
            await asyncio.gather(
                *self._heartbeat_tasks.values(), return_exceptions=True
            )
        self._heartbeat_tasks.clear()

    async def _stop_agent(self, agent_id: str) -> None:
        if self.run_id is None:
            return
        try:
            runtime = await self._service().get_agent_runtime(self._run_id(), agent_id)
        except StateError:
            return
        if runtime["agent"]["status"] not in self.TERMINAL_AGENT_STATES:
            await self._service().transition_agent(self._run_id(), agent_id, "stopping")
        task = self._tasks.get(agent_id)
        if task is not None and not task.done():
            # There is no cooperative stop channel in the model API, so cancel
            # after persisting intent. Ten seconds remains the outer lifecycle cap.
            await asyncio.sleep(0)
            task.cancel()
            await self._ignore_cancel(task)
        heartbeat = self._heartbeat_tasks.pop(agent_id, None)
        if heartbeat is not None:
            heartbeat.cancel()
            await self._ignore_cancel(heartbeat)
        current = await self._service().get_agent_runtime(self._run_id(), agent_id)
        if current["agent"]["status"] not in self.TERMINAL_AGENT_STATES:
            if current["agent"]["role"] == "execution":
                await self._service().finalize_execution_agent(
                    self._run_id(),
                    agent_id,
                    CapabilityContext(
                        run_id=self._run_id(),
                        agent_id=agent_id,
                        role="execution",
                        unique_code=current["agent"]["unique_code"],
                    ),
                    AgentReportInput(
                        status="cancelled",
                        summary="Execution Agent was stopped by its owner",
                        hypothesis_outcome="inconclusive",
                    ),
                    terminal_status="stopped",
                    allow_inactive=True,
                )
            else:
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="stopped"
                )
        await self._finish_agent_resources(agent_id)
        await self._sync_nodes()

    async def _finish_agent_resources(self, agent_id: str) -> None:
        """Best-effort idempotent cleanup for every Execution-owned manager."""

        failures: list[dict[str, str]] = []
        # Browser commands run through the Shell client, so close the browser
        # before Shell removes the Agent workspace.
        if self._browser is not None:
            try:
                await self._browser.finish_agent(agent_id)
            except Exception as exc:
                failures.append({"manager": "browser", "error_type": type(exc).__name__})

        operations: list[tuple[str, Any]] = []
        if self._http_interactions is not None:
            operations.append(("http", self._http_interactions.finish_agent(agent_id)))
        if self._network_discovery is not None:
            operations.append(("network", self._network_discovery.finish_agent(agent_id)))
        if self._shell_tasks is not None:
            operations.append(("shell", self._shell_tasks.finish_agent(agent_id)))
        if operations:
            results = await asyncio.gather(
                *(operation for _, operation in operations), return_exceptions=True
            )
            failures.extend(
                {
                    "manager": name,
                    "error_type": type(result).__name__,
                }
                for (name, _), result in zip(operations, results, strict=True)
                if isinstance(result, BaseException)
            )
        if not failures:
            return
        await self._service().append_agent_event(
            self._run_id(),
            agent_id,
            "agent_resource_cleanup_failed",
            {"failures": failures},
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
        nodes: dict[str, AgentNode] = {}
        status_map = {
            "queued": "pending",
            "starting": "pending",
            "working": "running",
            "blocked": "running",
            "stopping": "running",
            "cancelled": "stopped",
        }
        for item in overview["agents"]:
            status = status_map.get(item["status"], item["status"])
            nodes[item["agent_id"]] = AgentNode(
                agent_id=item["agent_id"],
                role=item["role"],
                parent_id=item["parent_id"],
                unique_code=item["unique_code"],
                status=status,
                sidecar_path=str(self._run_dir() / "agents" / item["agent_id"]),
                task_id=item["agent_id"] if item["agent_id"] in self._tasks else None,
                mission=item["mission"],
                timeout_seconds=item["timeout_seconds"],
                report_count=1 if item["last_report_sequence"] else 0,
                last_report_sequence=item["last_report_sequence"],
            )
        self.nodes = nodes

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

    async def _agent_record(self, agent_id: str, role: AgentRole) -> dict[str, Any]:
        runtime = await self._service().get_agent_runtime(self._run_id(), agent_id)
        if runtime["agent"]["role"] != role:
            raise SubagentError("Agent role is not authorized for this operation")
        return runtime["agent"]

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
        challenge = next((item for item in values if item["unique_code"] == unique_code), None)
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
    def _flatten_report(item: Mapping[str, Any], fallback_type: str) -> dict[str, Any]:
        payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
        return {
            "type": payload.get("type", fallback_type),
            **dict(payload),
            "report_id": item.get("report_id"),
            "report_ref": item.get("report_ref"),
            "agent_id": item.get("agent_id"),
            "unique_code": item.get("unique_code"),
            "sequence": item.get("sequence"),
        }

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

    async def _ensure_bootstrap_agent(
        self,
        unique_code: str,
        parent_id: str,
        *,
        reason: str,
        bootstrap_count: int | None = None,
        route_scope: str | None = None,
    ) -> dict[str, Any]:
        """Ensure the durable Bootstrap capacity without shrinking existing lanes."""

        if bootstrap_count is not None and not 1 <= bootstrap_count <= MAX_BOOTSTRAP_AGENTS_PER_CHALLENGE:
            raise ValueError(
                f"bootstrap_count must be between 1 and {MAX_BOOTSTRAP_AGENTS_PER_CHALLENGE}"
            )

        if not bool(getattr(self.settings, "bootstrap_enabled", True)):
            return {"enabled": False, "agent_id": None, "status": None}
        challenge = await self._challenge_record(unique_code)
        result = await self._service().ensure_bootstrap_for_challenge(
            self._run_id(),
            unique_code,
            parent_id=parent_id,
            bootstrap_prompt=self._bootstrap_prompt(
                challenge,
                {
                    "data": {
                        "container_addr": challenge.get("container_addr") or [],
                    }
                },
                restart_reason=reason,
                route_scope=route_scope,
            ),
            bootstrap_priority=100,
            bootstrap_count=bootstrap_count,
        )
        bootstrap_entries = result.get("bootstraps")
        if not isinstance(bootstrap_entries, list):
            bootstrap_entries = [result]
        await self._sync_nodes()
        for bootstrap in bootstrap_entries:
            if not isinstance(bootstrap, Mapping):
                continue
            bootstrap_id = bootstrap.get("agent_id")
            if not isinstance(bootstrap_id, str) or not bootstrap_id:
                continue
            self._state_capabilities[bootstrap_id] = self.capability_registry.issue(
                self._run_id(), bootstrap_id, "execution", unique_code
            ).context
            existing_task = self._tasks.get(bootstrap_id)
            # Newly created Bootstraps are already queued in the authoritative
            # Admission table. Let Runtime's admission loop reserve resources
            # and start them; launching here would race that loop.
            should_resume = bootstrap.get("status") not in {
                "queued",
                "pending",
                "starting",
            }
            if should_resume and (existing_task is None or existing_task.done()):
                await self._launch_agent(bootstrap_id, resume=True)
                await self._service().append_agent_event(
                    self._run_id(),
                    bootstrap_id,
                    "bootstrap_activated",
                    {
                        "reason": reason,
                        "idempotent": bool(bootstrap.get("idempotent")),
                    },
                )
        return result

    async def scale_bootstraps(self) -> list[dict[str, Any]]:
        """Add at most one Bootstrap lane per productive 15-minute window."""

        if self.run_id is None:
            return []
        async with self._bootstrap_scale_lock:
            overview = await self._service().get_overview(self._run_id())
            results: list[dict[str, Any]] = []
            for challenge_agent in overview.get("agents", []):
                if challenge_agent.get("role") != "challenge":
                    continue
                unique_code = challenge_agent.get("unique_code")
                parent_id = challenge_agent.get("agent_id")
                if not isinstance(unique_code, str) or not isinstance(parent_id, str):
                    continue
                decision = await self._service().maybe_scale_bootstrap_capacity(
                    self._run_id(), unique_code, parent_id=parent_id
                )
                target_count = decision.get("target_count")
                if (
                    not decision.get("should_ensure")
                    or not isinstance(target_count, int)
                    or target_count < 1
                ):
                    continue
                ensured = await self._ensure_bootstrap_agent(
                    unique_code,
                    parent_id,
                    reason=str(decision.get("reason") or "bootstrap_capacity_sync"),
                    bootstrap_count=target_count,
                )
                results.append(
                    {
                        "unique_code": unique_code,
                        "reason": decision.get("reason"),
                        "target_count": target_count,
                        "bootstraps": ensured.get("bootstraps") or [],
                    }
                )
            return results

    @staticmethod
    async def _ignore_cancel(task: asyncio.Task[Any]) -> None:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    def _challenge_prompt(
        self,
        challenge: Mapping[str, Any],
        start_result: Mapping[str, Any],
        *,
        hints: Any = (),
    ) -> str:
        start_data = start_result.get("data") if isinstance(start_result.get("data"), Mapping) else {}
        data = {
            "unique_code": challenge.get("unique_code"),
            "name": challenge.get("name"),
            "description": str(challenge.get("description") or "")[:4_000],
            "difficulty": challenge.get("difficulty"),
            "level": challenge.get("level"),
            "container_addr": start_data.get("container_addr") or challenge.get("container_addr") or [],
            "hints": list(hints or [])[:4],
        }
        return render_prompt(
            "challenge_agent.txt",
            challenge_data=json.dumps(data, ensure_ascii=False),
        )

    @staticmethod
    def _initial_execution_task(challenge: Mapping[str, Any]) -> ExecutionTaskInput:
        direction = str(challenge.get("direction") or "unknown")
        objective = (
            "Perform one bounded independent reconnaissance pass for this Challenge. "
            f"Focus on the {direction} surface when known; identify one verified, "
            "high-value fact that can shorten the path to the final result. "
            "Start with a discriminating technical action, avoid repeating the "
            "Bootstrap's full route, and submit an execution_checkpoint immediately "
            "when a credential, vulnerability, access primitive, or concrete result "
            "path is verified. Finish with a concise execution_report."
        )
        return ExecutionTaskInput(
            objective=objective,
            task_key="initial-recon",
            hypothesis_key="initial-surface-recon",
            branch_key="initial-recon:discovery",
            kind="recon",
            task_stage="discovery",
            priority=90,
            success_criteria=[
                "Produce one verified high-value fact or a concrete negative result.",
                "Use Evidence references for any checkpoint or final finding.",
                "Do not repeat the Bootstrap route or perform unbounded reconnaissance.",
            ],
            timeout_seconds=900,
        )

    @staticmethod
    def _execution_prompt(assignment: Mapping[str, Any]) -> str:
        return render_prompt(
            "execution_agent.txt",
            assignment=json.dumps(
                assignment,
                ensure_ascii=False,
                default=str,
            )[:16_000],
        )

    def _bootstrap_prompt(
        self,
        challenge: Mapping[str, Any],
        start_result: Mapping[str, Any],
        *,
        hints: Any = (),
        restart_reason: str | None = None,
        route_scope: str | None = None,
    ) -> str:
        start_data = (
            start_result.get("data")
            if isinstance(start_result.get("data"), Mapping)
            else {}
        )
        try:
            flag_count = int(challenge.get("flag_count") or 0)
        except (TypeError, ValueError):
            flag_count = 0
        try:
            correct_flag_count = int(challenge.get("correct_flag_count") or 0)
        except (TypeError, ValueError):
            correct_flag_count = 0
        data = {
            "run_id": self._run_id(),
            "unique_code": challenge.get("unique_code"),
            "name": challenge.get("name"),
            "description": str(challenge.get("description") or "")[:4_000],
            "difficulty": challenge.get("difficulty"),
            "level": challenge.get("level"),
            "target": start_data.get("container_addr")
            or challenge.get("container_addr")
            or [],
            "flag_count": flag_count,
            "correct_flag_count": correct_flag_count,
            "remaining_flags": max(0, flag_count - correct_flag_count),
            "direction": challenge.get("direction", "unknown"),
            "evidence_root": challenge.get("evidence_root"),
            "hints": list(hints or [])[:4],
            "restart_reason": restart_reason,
            "route_scope": route_scope,
            "bootstrap_contract": {
                "mission": BOOTSTRAP_MISSION,
                "success_criteria": list(BOOTSTRAP_SUCCESS_CRITERIA),
                "cycle_timeout_seconds": BOOTSTRAP_CYCLE_TIMEOUT_SECONDS,
                "report_only_grace_seconds": BOOTSTRAP_REPORT_ONLY_GRACE_SECONDS,
            },
        }
        return render_prompt(
            "bootstrap_agent.txt",
            challenge_data=json.dumps(data, ensure_ascii=False, default=str),
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
            else "conflict"
            if error_type == "conflict" or status_code == 409
            else "internal"
            if error_type == "internal"
            else "execution"
            if error_type in {"transport", "api"}
            else "semantic"
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
        }
        for result in (close_result, sync_result):
            code = cls._error_code(result)
            error = result.get("error") if isinstance(result, Mapping) else None
            details = error.get("details") if isinstance(error, Mapping) else None
            status_code = (
                details.get("status_code")
                if isinstance(details, Mapping)
                else None
            )
            if code in transient_codes or status_code in {
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
