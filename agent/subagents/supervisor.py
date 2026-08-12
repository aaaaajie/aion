"""SQLite-authoritative parent/child Agent orchestration."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent.config import AgentSettings, PROJECT_ROOT
from agent.memory.models import AgentNode
from agent.memory.redaction import redact_value
from agent.prompts import render_prompt, system_prompt
from agent.runner import AgentRunner, AgentRunnerError, AgentSessionResult, ToolRegistry
from agent.skills import SkillCatalog, SkillTools
from agent.state import (
    AgentStateStore,
    CapabilityRegistry,
    ResourceController,
    StateService,
    container_capacity_summary,
    container_slot_occupied,
)
from agent.state.errors import StateError
from agent.state.clock import aware
from agent.state.schemas import (
    AgentProgressInput,
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    CreateCycleInput,
    FindingInput,
    ExecutionTaskInput,
    StagnationExtensionInput,
    VerificationUpdateInput,
)
from agent.state.scheduling import ChallengeScheduler
from tools.http import HttpProbeManager, HttpTools
from tools.network import NetworkDiscoveryManager, NetworkTools
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy
from scan.contracts import (
    SCANNER_PROFILES,
    extract_task_contract,
    task_contract_json,
    validate_profile_tools,
    validate_task_budgets,
)
from scan.domain import COMPETITION_DOMAINS, assess_probe_reports, classify_challenge
from scan.registry import (
    build_first_round_tasks,
    skill_for_domain,
    skill_instructions_for_domain,
)

from .models import AgentRole, AgentStatusReport, ExecutionReport
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

DOMAIN_RECOGNITION_SIGNALS = {
    "web": (
        "Positive discriminators: traditional login, register, upload, download, "
        "CRUD, CMS, admin, route, cookie, session, framework, or middleware evidence. "
        "Treat messages/prompt/model request fields with choices/assistant/usage or "
        "SSE responses as cross-domain AI evidence."
    ),
    "blockchain": (
        "Positive discriminators: Solidity, ABI, contract address, bytecode, JSON-RPC, "
        "wallet, nonce, gas, transaction, event, Foundry, or Hardhat evidence."
    ),
    "ai": (
        "Positive discriminators: /chat, /completions, /generate, /v1/models, or /ask; "
        "messages, prompt, input, system, model, temperature, max_tokens, or top_p request "
        "fields; choices, role=assistant, content, usage, or SSE data: response shapes."
    ),
    "other": (
        "Positive discriminators: ELF, PE, APK, firmware, pcap, memory dump, ciphertext, "
        "binary, pwn, reverse, forensics, or cryptography artifact evidence."
    ),
}


class SubagentError(RuntimeError):
    """Safe orchestration failure without exposing credentials or stack traces."""


class AgentSupervisor:
    """Own live tasks while SQLite owns all recoverable Agent state."""

    MAX_CHALLENGE_SLOTS = 3
    DEFAULT_EXECUTION_TIMEOUT = 1_800
    CONTROLLER_SAFETY_WAKE_SECONDS = 300.0
    HEARTBEAT_INTERVAL_SECONDS = 30.0
    HEARTBEAT_EVENT_INTERVAL_SECONDS = 300.0
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
        max_challenge_slots: int = MAX_CHALLENGE_SLOTS,
        default_execution_timeout: int = DEFAULT_EXECUTION_TIMEOUT,
        catalog_reconcile_interval_seconds: float = 120.0,
        duration_minutes: int | None = None,
        second_pass_min_remaining_seconds: int = 30 * 60,
        state_service: StateService,
        capability_registry: CapabilityRegistry | None = None,
        resource_controller: ResourceController | None = None,
        skill_catalog: SkillCatalog | None = None,
    ) -> None:
        if max_challenge_slots != self.MAX_CHALLENGE_SLOTS:
            raise ValueError("the benchmark challenge slot limit is fixed at 3")
        if catalog_reconcile_interval_seconds < 0:
            raise ValueError("catalog_reconcile_interval_seconds must not be negative")
        self.settings = settings
        self.benchmark = benchmark
        self.project_root = project_root.resolve()
        self.run_root = (run_root or settings.run_root).resolve()
        self.runner_factory = runner_factory
        self.max_challenge_slots = max_challenge_slots
        self.default_execution_timeout = default_execution_timeout
        self.catalog_reconcile_interval_seconds = catalog_reconcile_interval_seconds
        self.duration_minutes = duration_minutes or getattr(settings, "run_duration_minutes", 360)
        self.second_pass_min_remaining_seconds = second_pass_min_remaining_seconds
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
        self._container_operation_lock = asyncio.Lock()
        self._hint_locks: dict[str, asyncio.Lock] = {}
        self._pausing = False
        self._shell_tasks: ShellTaskManager | None = None
        self._http_interactions: HttpProbeManager | None = None
        self._network_discovery: NetworkDiscoveryManager | None = None

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

        runtime_prefix = Path(sys.prefix).resolve()
        runtime_python = runtime_prefix / "bin" / Path(sys.executable).name
        if not runtime_python.is_file():
            runtime_python = Path(sys.executable).resolve()
        self._shell_tasks = ShellTaskManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            clock=service.clock,
            read_only_paths=(self.skill_catalog.root, runtime_prefix),
            environment={
                "AION_SKILLS_ROOT": str(self.skill_catalog.root),
                "AION_PYTHON": str(runtime_python),
            },
        )
        await self._shell_tasks.initialize(resume=resume)
        self._http_interactions = HttpProbeManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            admission_callback=(
                self.resource_controller.admit_resource_work
                if self.resource_controller is not None
                else None
            ),
            resource_guard=(
                self.resource_controller.check_resource_work
                if self.resource_controller is not None
                else None
            ),
        )
        await self._http_interactions.initialize(resume=resume)
        self._network_discovery = NetworkDiscoveryManager(
            WorkspacePolicy(self.project_root),
            service,
            run_id,
            admission_callback=(
                self.resource_controller.admit_resource_work
                if self.resource_controller is not None
                else None
            ),
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
        for challenge in synced["data"]["challenges"]:
            if challenge["is_completed"]:
                await self.stop_challenge_work(
                    challenge["unique_code"], reason="catalog_completed"
                )
                if challenge["slot_occupied"]:
                    await self._release_completed_container(
                        caller_id,
                        challenge["unique_code"],
                        reason="catalog_refresh",
                    )
            elif challenge["work_status"] == "paused" and challenge["slot_occupied"]:
                await self._pause_stagnant_challenge(
                    caller_id,
                    challenge["unique_code"],
                    reason="refresh_retry",
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
        result = await self._benchmark_dispatch("benchmark_list_challenges", {})
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
            overview = await self._service().get_overview(self._run_id())
            challenge = next(
                item
                for item in overview["challenges"]
                if item["unique_code"] == unique_code
            )
            if challenge["is_completed"] or challenge["work_status"] == "closed":
                return self._error(
                    "challenge_completed",
                    "The challenge is already completed or closed",
                    error_type="conflict",
                )
            capacity = overview["container_capacity"]
            if (
                not challenge["slot_occupied"]
                and capacity["occupied_count"] >= capacity["limit"]
            ):
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
            close_result = await self._execute_operation(
                caller_id=caller_id,
                tool_name="benchmark_close_challenge",
                arguments={"unique_code": unique_code},
                unique_code=unique_code,
            )
            synced = await self._sync_challenge_catalog()
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
            }

    async def pause_stagnant_challenge(
        self, caller_id: str, unique_code: str
    ) -> dict[str, Any]:
        """Pause one stagnant challenge and confirm its remote slot release."""

        self._require_role(caller_id, "chief")
        return await self._pause_stagnant_challenge(
            caller_id, unique_code, reason="stagnation_threshold"
        )

    async def _pause_stagnant_challenge(
        self,
        caller_id: str,
        unique_code: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._container_operation_lock:
            await self._sync_challenge_catalog()
            challenge = await self._challenge_record(unique_code)
            close_operations = [
                item
                for item in await self._service().list_operations(self._run_id())
                if item["unique_code"] == unique_code
                and item["operation_type"] == "benchmark_close_challenge"
                and item["status"] == "indeterminate"
            ]
            for operation in close_operations:
                await self._service().reconcile_indeterminate_operation(
                    self._run_id(),
                    operation["operation_id"],
                    resolved=not challenge["slot_occupied"],
                    result_code=(
                        "remote_release_confirmed"
                        if not challenge["slot_occupied"]
                        else "container_release_unconfirmed"
                    ),
                )
            if challenge["is_completed"]:
                return self._ok(
                    {
                        "unique_code": unique_code,
                        "paused": False,
                        "released": False,
                        "reason": "completed_during_pause",
                    }
                )
            if not challenge["slot_occupied"]:
                await self._service().mark_challenge_paused(
                    self._run_id(), unique_code
                )
                released = True
                current = await self._challenge_record(unique_code)
                close_result: dict[str, Any] = {}
            else:
                started = asyncio.get_running_loop().time()
                observed_status = challenge["container_status"]
                await self._service().append_agent_event(
                    self._run_id(),
                    caller_id,
                    "stagnation_pause_started",
                    {
                        "unique_code": unique_code,
                        "observed_container_status": observed_status,
                        "reason": reason,
                    },
                )
                close_result = await self._execute_operation(
                    caller_id=caller_id,
                    tool_name="benchmark_close_challenge",
                    arguments={"unique_code": unique_code},
                    unique_code=unique_code,
                )
                synced = await self._sync_challenge_catalog()
                current = await self._challenge_record(unique_code)
                released = synced.get("ok") is True and not current["slot_occupied"]
                if released:
                    await self._service().mark_challenge_paused(
                        self._run_id(), unique_code
                    )
                    current = await self._challenge_record(unique_code)
                else:
                    await self._service().mark_challenge_pause_pending(
                        self._run_id(),
                        unique_code,
                        platform_status="close_requested",
                    )
                    current = await self._challenge_record(unique_code)
                duration_ms = int(
                    (asyncio.get_running_loop().time() - started) * 1_000
                )
                event_type = (
                    "stagnation_pause_succeeded"
                    if released
                    else "stagnation_pause_failed"
                )
                payload = {
                    "unique_code": unique_code,
                    "observed_container_status": observed_status,
                    "container_status": current["container_status"],
                    "slot_occupied": current["slot_occupied"],
                    "reason": reason,
                    "duration_ms": duration_ms,
                }
                if not released:
                    payload["error_code"] = (
                        self._error_code(close_result)
                        or "container_release_unconfirmed"
                    )
                await self._service().append_agent_event(
                    self._run_id(), caller_id, event_type, payload
                )
                LOGGER.log(
                    logging.INFO if released else logging.WARNING,
                    "%s run_id=%s unique_code=%s observed_container_status=%s container_status=%s slot_occupied=%s duration_ms=%s error_code=%s",
                    event_type,
                    self._run_id(),
                    unique_code,
                    observed_status,
                    current["container_status"],
                    current["slot_occupied"],
                    duration_ms,
                    payload.get("error_code", ""),
                )

            if released:
                await self.stop_execution_agents(unique_code)
                overview = await self._service().get_overview(self._run_id())
                challenge_agents = [
                    item
                    for item in overview["agents"]
                    if item["role"] == "challenge"
                    and item["unique_code"] == unique_code
                ]
                await asyncio.gather(
                    *(
                        self._stop_agent(item["agent_id"])
                        for item in challenge_agents
                        if item["status"] not in self.TERMINAL_AGENT_STATES
                    ),
                )
                await self._sync_nodes()
            return self._ok(
                {
                    "unique_code": unique_code,
                    "paused": released,
                    "released": released,
                    "container_status": current["container_status"],
                    "slot_occupied": current["slot_occupied"],
                    "error_code": None if released else self._error_code(close_result) or "container_release_unconfirmed",
                }
            )

    async def create_challenge_agent(self, caller_id: str, unique_code: str) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
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
            return self._error(
                "challenge_agent_exists",
                "A Challenge Agent already exists for this challenge",
                error_type="conflict",
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
        start_result = await self._ensure_challenge_container(
            caller_id, unique_code
        )
        if not start_result.get("ok"):
            return start_result

        agent_id = f"challenge_{uuid4().hex}"
        prompt = self._challenge_prompt(challenge, start_result)
        try:
            record = await self._service().register_agent(
                self._run_id(),
                agent_id=agent_id,
                role="challenge",
                parent_id=caller_id,
                unique_code=unique_code,
                initial_prompt=prompt,
            )
            self._state_capabilities[agent_id] = self.capability_registry.issue(
                self._run_id(), agent_id, "challenge", unique_code
            ).context
            await self._sync_nodes()
            await self._launch_agent(agent_id)
        except Exception:
            try:
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="failed"
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
                "start": start_result.get("data", {}),
            }
        )

    async def get_challenge_reports(
        self,
        caller_id: str,
        wait_seconds: float = 0.0,
        max_reports: int = 20,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        result = await self._service().consume_reports(
            self._run_id(),
            self._state_context(caller_id),
            report_type="challenge_status",
            wait_seconds=wait_seconds,
            max_reports=max_reports,
        )
        reports = [self._flatten_report(item, "challenge_status") for item in result["reports"]]
        return self._ok({"reports": reports, "count": len(reports), "next_sequence": result["next_sequence"]})

    async def request_hint(
        self,
        caller_id: str,
        unique_code: str,
        basis: str,
        evidence_refs: list[str],
        reason: str,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        lock = self._hint_locks.setdefault(unique_code, asyncio.Lock())
        async with lock:
            return await self._request_hint_locked(
                caller_id, unique_code, basis, evidence_refs, reason
            )

    async def _request_hint_locked(
        self,
        caller_id: str,
        unique_code: str,
        basis: str,
        evidence_refs: list[str],
        reason: str,
    ) -> dict[str, Any]:
        challenge_agent = await self._find_agent("challenge", unique_code=unique_code)
        if challenge_agent is None or challenge_agent["status"] in self.TERMINAL_AGENT_STATES:
            return self._error(
                "challenge_agent_not_found",
                "No Challenge Agent is registered for this challenge",
            )
        challenge = await self._challenge_record(unique_code)
        if challenge.get("hint_requested"):
            operation = await self._service().latest_completed_operation(
                self._run_id(),
                operation_type="benchmark_get_hint",
                unique_code=unique_code,
            )
            if operation is None:
                return self._error(
                    "hint_result_missing",
                    "The persisted Hint marker has no completed operation",
                    error_type="internal",
                )
            result = dict(operation.get("result_payload") or {})
            data = (
                dict(result.get("data") or {})
                if isinstance(result.get("data"), Mapping)
                else {}
            )
            existing_report = await self._service().latest_control_report(
                self._run_id(),
                recipient_id=challenge_agent["agent_id"],
                report_type="hint",
            )
            if existing_report is None:
                await self._service().publish_control_report(
                    self._run_id(),
                    sender_id=caller_id,
                    recipient_id=challenge_agent["agent_id"],
                    unique_code=unique_code,
                    report_type="hint",
                    status="received",
                    payload={
                        "type": "hint_received",
                        "unique_code": unique_code,
                        "reason": reason,
                        "hint": data.get("hint"),
                    },
                )
            data["reused"] = True
            return {**result, "ok": bool(result.get("ok", True)), "data": data}
        admission = await self._service().evaluate_hint_admission(
            self._run_id(),
            unique_code,
            self._state_context(caller_id),
            basis=basis,
            evidence_refs=evidence_refs,
        )
        if not admission["eligible"]:
            return self._error(
                "hint_not_admitted",
                "Hint admission requirements are not satisfied",
                error_type="conflict",
                status_code=409,
                detail=admission,
            )
        result = await self._execute_operation(
            caller_id=caller_id,
            tool_name="benchmark_get_hint",
            arguments={"unique_code": unique_code},
            unique_code=unique_code,
        )
        if result.get("ok"):
            await self._service().publish_control_report(
                self._run_id(),
                sender_id=caller_id,
                recipient_id=challenge_agent["agent_id"],
                unique_code=unique_code,
                report_type="hint",
                status="received",
                payload={
                    "type": "hint_received",
                    "unique_code": unique_code,
                    "reason": reason,
                    "hint": (result.get("data") or {}).get("hint"),
                },
            )
        if isinstance(result, Mapping) and result.get("ok"):
            result_data = result.get("data")
            data = dict(result_data) if isinstance(result_data, Mapping) else {}
            return {**result, "data": {**data, "admission": admission}}
        return result

    async def extend_stagnation(
        self,
        caller_id: str,
        unique_code: str,
        reason: str,
        evidence_refs: list[str],
        note: str | None = None,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        result = await self._service().grant_stagnation_extension(
            self._run_id(),
            unique_code,
            self._state_context(caller_id),
            StagnationExtensionInput(
                reason=reason,
                evidence_refs=evidence_refs,
                note=note,
            ),
        )
        LOGGER.info(
            "stagnation_extension_granted run_id=%s unique_code=%s reason=%s evidence_ref_count=%s",
            self._run_id(),
            unique_code,
            reason,
            len(evidence_refs),
        )
        return self._ok(result)

    async def create_domain_probes(self, caller_id: str) -> dict[str, Any]:
        """Select one scanner profile or launch only low-cost domain probes."""

        parent = await self._agent_record(caller_id, "challenge")
        if parent["status"] in self.TERMINAL_AGENT_STATES:
            return self._error(
                "parent_not_running",
                "The Challenge Agent is no longer active",
                error_type="conflict",
            )
        unique_code = parent["unique_code"]
        context = await self._service().get_challenge_context(
            self._run_id(), unique_code, self._state_context(caller_id)
        )
        challenge = context["challenge"]
        report_snapshot = await self._service().list_reports(
            self._run_id(),
            self._state_context(caller_id),
            after_sequence=0,
            wait_seconds=0,
            max_reports=100,
        )
        hints = [
            str(item.get("payload", {}).get("hint"))
            for item in report_snapshot.get("reports") or []
            if item.get("report_type") == "hint"
            and isinstance(item.get("payload"), Mapping)
            and item.get("payload", {}).get("hint")
        ]
        overview = await self._service().get_overview(self._run_id())
        probe_agents = [
            item
            for item in overview["agents"]
            if item["parent_id"] == caller_id
            and item["kind"] == "domain_recognition"
        ]
        if probe_agents:
            probe_reports: list[dict[str, Any]] = []
            for item in probe_agents:
                runtime = await self._service().get_agent_runtime(
                    self._run_id(), item["agent_id"]
                )
                probe_reports.append(
                    self._domain_probe_result(runtime["agent"])
                )
            combined = assess_probe_reports(probe_reports)
            result = combined.as_dict()
            result["source"] = "domain_probe_reports"
            result["probes"] = [
                {
                    "agent_id": item["agent_id"],
                    "task_key": item["task_key"],
                    "status": item["status"],
                }
                for item in probe_agents
            ]
            if combined.decision == "direct" and combined.domain is not None:
                selected_skill = skill_for_domain(combined.domain)
                observation = await self._service().record_observation(
                    self._run_id(),
                    unique_code,
                    category="domain_triage",
                    summary=f"Challenge domain classified as {combined.domain}",
                    detail={
                        "domain": combined.domain,
                        "subdomain": combined.subdomain,
                        "confidence": combined.confidence,
                        "scanner_profile": combined.scanner_profile,
                        "skill_id": selected_skill.manifest.id,
                        "source": "domain_probe_reports",
                        "evidence_refs": list(combined.evidence_refs),
                    },
                    source="challenge_domain_triage",
                    source_ref=caller_id,
                    confidence=combined.confidence,
                    mark_progress=False,
                    route_branches=False,
                )
                result["evidence_refs"] = [
                    f"observation:{observation['observation_id']}",
                    *combined.evidence_refs,
                ]
                result["skill_id"] = selected_skill.manifest.id
                result["skill_instructions"] = skill_instructions_for_domain(
                    combined.domain
                )
                result["first_round_tasks"] = build_first_round_tasks(
                    combined.domain,
                    unique_code=unique_code,
                    target_scope=list(challenge.get("container_addr") or [])
                    or [f"challenge-metadata:{unique_code}"],
                    description=str(challenge.get("description") or ""),
                    evidence_refs=result["evidence_refs"],
                    observations=context.get("observations") or [],
                )
            return self._ok(result)

        assessment = classify_challenge(
            challenge,
            hints=hints,
            observations=context.get("observations") or [],
        )
        if assessment.decision == "direct" and assessment.domain is not None:
            selected_skill = skill_for_domain(assessment.domain)
            observation = await self._service().record_observation(
                self._run_id(),
                unique_code,
                category="domain_triage",
                summary=f"Challenge domain classified as {assessment.domain}",
                detail={
                    "domain": assessment.domain,
                    "subdomain": assessment.subdomain,
                    "confidence": assessment.confidence,
                    "scanner_profile": assessment.scanner_profile,
                    "skill_id": selected_skill.manifest.id,
                    "scores": assessment.scores,
                    "signals": list(assessment.evidence),
                    "source": "challenge_metadata",
                },
                source="challenge_domain_triage",
                source_ref=caller_id,
                confidence=assessment.confidence,
                mark_progress=False,
                route_branches=False,
            )
            result = assessment.as_dict()
            result.update(
                {
                    "source": "challenge_metadata",
                    "evidence_refs": [
                        f"observation:{observation['observation_id']}"
                    ],
                }
            )
            result["skill_id"] = selected_skill.manifest.id
            result["skill_instructions"] = skill_instructions_for_domain(
                assessment.domain
            )
            result["first_round_tasks"] = build_first_round_tasks(
                assessment.domain,
                unique_code=unique_code,
                target_scope=list(challenge.get("container_addr") or [])
                or [f"challenge-metadata:{unique_code}"],
                description=str(challenge.get("description") or ""),
                evidence_refs=result["evidence_refs"],
                observations=context.get("observations") or [],
            )
            return self._ok(result)

        metadata = {
            "unique_code": challenge.get("unique_code"),
            "description": challenge.get("description"),
            "difficulty": challenge.get("difficulty"),
            "level": challenge.get("level"),
            "target_addresses": challenge.get("container_addr") or [],
            "initial_scores": assessment.scores,
            "initial_signals": list(assessment.evidence),
            "hints": hints,
        }
        target_scope = list(challenge.get("container_addr") or []) or [
            f"challenge-metadata:{unique_code}"
        ]
        probe_tools = [
            "execution_get_assignment",
            "system_http_request",
            "system_http_analyze",
            "system_http_output",
            "system_http_response",
            "execution_report",
        ]
        probes: list[dict[str, Any]] = []
        for domain in COMPETITION_DOMAINS:
            mission = (
                f"Answer only whether this challenge belongs to the {domain} domain. "
                f"{DOMAIN_RECOGNITION_SIGNALS[domain]} "
                "Use the supplied metadata first. If an HTTP target is available, make at "
                "most one low-cost request only when metadata is insufficient. Do not run "
                "path discovery, network discovery, bulk probing, exploitation, or Flag work. "
                "Report one candidate finding whose detail is exactly structured with domain, "
                "is_match, confidence, and signals. For the other domain, also return subdomain "
                "as binary, pwn, reverse, forensics, cryptography, or null. Challenge metadata: "
                f"{json.dumps(metadata, ensure_ascii=False)}"
            )
            created = await self.create_execution_agent(
                caller_id,
                mission,
                120,
                hypothesis_key=f"domain-recognition:{domain}",
                task_key=f"domain-recognition:{domain}:1",
                kind="domain_recognition",
                task_phase="domain_recognition",
                entry_point=target_scope[0],
                capability_class="domain_recognition",
                verification_question=f"该题是否属于 {domain} 方向？",
                priority=100,
                target_scope=target_scope,
                tool_names=probe_tools,
                success_criteria=[
                    f"return a yes or no decision for only the {domain} domain",
                    "return confidence between 0 and 1 with concrete matched signals",
                ],
                failure_criteria=[
                    "available metadata and one optional request contain no discriminating signal"
                ],
                evidence_requirements=[
                    "cite the exact title, description, target, header, or response clue used"
                ],
                stop_conditions=[
                    "the domain decision and confidence are ready",
                    "one HTTP interaction has completed",
                    "120 seconds have elapsed",
                ],
                depends_on=[],
                scanner_profile="domain_recognition",
                cost_class="low",
                context_refs=[],
                branch_key=f"domain:recognition:{domain}",
                max_http_requests=1,
                max_shell_tasks=0,
                max_network_tasks=0,
            )
            probes.append(
                {
                    "domain": domain,
                    "ok": created.get("ok") is True,
                    **(
                        dict(created.get("data") or {})
                        if isinstance(created.get("data"), Mapping)
                        else {"error": created.get("error")}
                    ),
                }
            )
        return self._ok(
            {
                **assessment.as_dict(),
                "decision": "probe",
                "source": "challenge_metadata",
                "cost_class": "low",
                "probes": probes,
            }
        )

    async def _execution_dependency_error(
        self, unique_code: str, depends_on: list[str]
    ) -> dict[str, Any] | None:
        if not depends_on:
            return None
        challenge = await self._service().get_challenge_context(
            self._run_id(), unique_code
        )
        ledger = {
            item.get("task_key"): item
            for item in challenge.get("task_ledger") or []
            if item.get("task_key")
        }
        missing = sorted(key for key in depends_on if key not in ledger)
        if missing:
            return self._error(
                "task_dependency_unknown",
                "The execution task references an unknown dependency",
                detail={"task_keys": missing},
            )
        pending = sorted(
            key
            for key in depends_on
            if not ledger[key].get("terminal_report_id")
        )
        if pending:
            return self._error(
                "task_dependency_not_ready",
                "The previous atomic task batch has not reported yet",
                error_type="conflict",
                detail={"task_keys": pending},
            )
        return None

    async def _scanner_profile_selection_error(
        self, unique_code: str, scanner_profile: str
    ) -> dict[str, Any] | None:
        context = await self._service().get_challenge_context(
            self._run_id(), unique_code
        )
        selected_profile: str | None = None
        for cycle in context.get("recent_cycles") or []:
            analysis = cycle.get("analysis")
            if isinstance(analysis, Mapping) and analysis.get("scanner_profile"):
                selected_profile = str(analysis["scanner_profile"])
                break
        if selected_profile is None:
            for observation in context.get("observations") or []:
                if observation.get("category") != "domain_triage":
                    continue
                detail = observation.get("detail")
                if isinstance(detail, Mapping) and detail.get("scanner_profile"):
                    selected_profile = str(detail["scanner_profile"])
                    break
        if selected_profile is None:
            return self._error(
                "domain_triage_required",
                "Identify the challenge domain before creating a normal execution task",
                error_type="conflict",
            )
        if scanner_profile != selected_profile:
            return self._error(
                "scanner_profile_mismatch",
                "The execution task scanner profile does not match the identified domain",
                error_type="conflict",
                detail={"expected_scanner_profile": selected_profile},
            )
        return None

    async def create_execution_agent(
        self,
        caller_id: str,
        mission: str,
        timeout_seconds: int | None = None,
        *,
        hypothesis_key: str,
        task_key: str,
        cycle_id: str | None = None,
        kind: str = "general",
        task_phase: str | None = None,
        entry_point: str | None = None,
        capability_class: str | None = None,
        verification_question: str | None = None,
        priority: int = 50,
        target_scope: list[str] | None = None,
        tool_names: list[str] | None = None,
        success_criteria: list[str] | None = None,
        failure_criteria: list[str] | None = None,
        evidence_requirements: list[str] | None = None,
        stop_conditions: list[str] | None = None,
        depends_on: list[str] | None = None,
        scanner_profile: str | None = None,
        cost_class: str = "low",
        context_refs: list[str] | None = None,
        branch_key: str | None = None,
        max_http_requests: int | None = None,
        max_shell_tasks: int | None = None,
        max_network_tasks: int | None = None,
        require_domain_selection: bool = False,
    ) -> dict[str, Any]:
        parent = await self._agent_record(caller_id, "challenge")
        if parent["status"] in self.TERMINAL_AGENT_STATES:
            return self._error(
                "parent_not_running",
                "The Challenge Agent is no longer active",
                error_type="conflict",
            )
        timeout = timeout_seconds or self.default_execution_timeout
        agent_id = f"execution_{uuid4().hex}"
        challenge = await self._challenge_record(parent["unique_code"])
        addresses = list(challenge.get("container_addr") or [])
        resolved_profile = scanner_profile or (
            "web_light" if kind == "web" else "other_light"
        )
        if resolved_profile not in SCANNER_PROFILES:
            return self._error(
                "invalid_scanner_profile",
                "The execution task scanner profile is unknown",
            )
        if require_domain_selection and kind != "domain_recognition":
            selection_error = await self._scanner_profile_selection_error(
                parent["unique_code"], resolved_profile
            )
            if selection_error is not None:
                return selection_error
        resolved_scope = list(target_scope or addresses or [parent["unique_code"]])
        resolved_tools = list(
            tool_names
            or (
                "execution_get_assignment",
                "execution_update_progress",
                "execution_report",
            )
        )
        resolved_phase = task_phase or {
            "domain_recognition": "domain_recognition",
            "recon": "reconnaissance",
            "web": "reconnaissance",
            "verification": "validation",
            "exploit": "exploitation",
        }.get(kind, "reconnaissance")
        resolved_entry_point = entry_point or resolved_scope[0]
        resolved_capability = capability_class or kind
        resolved_question = verification_question or (
            f"Does {resolved_entry_point} satisfy hypothesis {hypothesis_key}?"
        )
        resolved_http_budget = (
            max_http_requests
            if max_http_requests is not None
            else (1 if resolved_tools and any(name.startswith("system_http_") or name.startswith("system_web_") for name in resolved_tools) else 0)
        )
        resolved_shell_budget = (
            max_shell_tasks
            if max_shell_tasks is not None
            else (1 if "system_shell" in resolved_tools else 0)
        )
        resolved_network_budget = (
            max_network_tasks
            if max_network_tasks is not None
            else (1 if "system_network_discovery" in resolved_tools else 0)
        )
        try:
            validate_profile_tools(resolved_profile, resolved_tools)
            validate_task_budgets(
                resolved_tools,
                max_http_requests=resolved_http_budget,
                max_shell_tasks=resolved_shell_budget,
                max_network_tasks=resolved_network_budget,
            )
        except ValueError as exc:
            return self._error("invalid_task_tools", str(exc))
        resolved_success = list(
            success_criteria or ["the single assigned hypothesis is answered"]
        )
        resolved_failure = list(
            failure_criteria or ["the hypothesis cannot be answered with the assigned tools"]
        )
        resolved_evidence = list(
            evidence_requirements or ["report the concrete output that supports the conclusion"]
        )
        resolved_stop = list(
            stop_conditions
            or [
                "a success criterion is met",
                "a failure criterion is met",
                "the task timeout is reached",
            ]
        )
        resolved_dependencies = list(depends_on or [])
        resolved_branch_key = branch_key or f"{hypothesis_key}:{kind}"
        dependency_error = await self._execution_dependency_error(
            parent["unique_code"], resolved_dependencies
        )
        if dependency_error is not None:
            return dependency_error
        if challenge["stagnation_level"] >= 2 or challenge.get("work_status") in {"paused", "extended"}:
            return self._error(
                "challenge_paused",
                "Runtime has paused this challenge; execution work is stopped",
                error_type="conflict",
            )
        if challenge["stagnation_level"] >= 1 and kind != "exploration":
            return self._error(
                "exploration_only",
                "Warning state permits only one explicit exploration task for a named knowledge gap",
                error_type="conflict",
            )
        if challenge["stagnation_level"] >= 1 and not context_refs:
            return self._error(
                "information_gap_required",
                "The warning exploration must cite at least one concrete information gap",
                error_type="validation",
            )
        if challenge["stagnation_level"] >= 1:
            if challenge.get("l2_explorer_created"):
                return self._error(
                    "stagnation_explorer_limit",
                    "This warning episode already used its exploration Agent",
                    error_type="conflict",
                )
            overview = await self._service().get_overview(self._run_id())
            if any(
                item["role"] == "execution"
                and item["unique_code"] == parent["unique_code"]
                and item["kind"] == "exploration"
                and item["status"] not in self.TERMINAL_AGENT_STATES
                for item in overview["agents"]
            ):
                return self._error(
                    "exploration_exists",
                    "The warning challenge already has an exploration task",
                    error_type="conflict",
                )
            try:
                await self._service().reserve_stagnation_explorer(
                    self._run_id(), parent["unique_code"]
                )
            except StateError as exc:
                return self._error(
                    exc.code,
                    exc.message,
                    error_type="conflict",
                )
        task_contract = {
            "task_key": task_key,
            "hypothesis_key": hypothesis_key,
            "branch_key": resolved_branch_key,
            "kind": kind,
            "task_phase": resolved_phase,
            "entry_point": resolved_entry_point,
            "capability_class": resolved_capability,
            "verification_question": resolved_question,
            "objective": mission,
            "target_scope": resolved_scope,
            "tool_names": resolved_tools,
            "priority": priority,
            "success_criteria": resolved_success,
            "failure_criteria": resolved_failure,
            "evidence_requirements": resolved_evidence,
            "stop_conditions": resolved_stop,
            "depends_on": resolved_dependencies,
            "scanner_profile": resolved_profile,
            "cost_class": cost_class,
            "context_refs": list(context_refs or []),
            "max_http_requests": resolved_http_budget,
            "max_shell_tasks": resolved_shell_budget,
            "max_network_tasks": resolved_network_budget,
            "timeout_seconds": timeout,
        }
        try:
            ExecutionTaskInput.model_validate(task_contract)
        except ValueError as exc:
            return self._error("invalid_atomic_task", str(exc))
        prompt = self._execution_prompt(task_contract, addresses)
        record = await self._service().register_agent(
            self._run_id(),
            agent_id=agent_id,
            role="execution",
            parent_id=caller_id,
            unique_code=parent["unique_code"],
            cycle_id=cycle_id,
            kind=kind,
            priority=priority,
            mission=mission,
            initial_prompt=prompt,
            success_criteria=resolved_success,
            context_refs=context_refs or [],
            hypothesis_key=hypothesis_key,
            task_key=task_key,
            branch_key=resolved_branch_key,
            timeout_seconds=timeout,
        )
        if record.get("duplicate"):
            return self._ok(
                {
                    "agent_id": record["agent_id"],
                    "role": record["role"],
                    "unique_code": record["unique_code"],
                    "status": record["status"],
                    "hypothesis_key": record["hypothesis_key"],
                    "task_key": record["task_key"],
                    "duplicate": True,
                    "terminal_report_id": record.get("terminal_report_id"),
                    "final_report": record.get("final_report"),
                }
            )
        admission = await self._service().enqueue_agent(self._run_id(), agent_id)
        self._state_capabilities[agent_id] = self.capability_registry.issue(
            self._run_id(), agent_id, "execution", parent["unique_code"]
        ).context
        await self._sync_nodes()
        return self._ok(
            {
                "agent_id": agent_id,
                "role": record["role"],
                "unique_code": record["unique_code"],
                "status": admission["status"],
                "hypothesis_key": hypothesis_key,
                "task_key": task_key,
                "timeout_seconds": timeout,
            }
        )

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
        self, unique_code: str, *, reason: str = "challenge_completed"
    ) -> None:
        """Immediately stop every Agent and live task owned by one challenge."""

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
            {"unique_code": unique_code, "reason": reason},
        )
        await self._sync_nodes()

    async def start_second_pass(self, caller_id: str) -> dict[str, Any]:
        """Begin the single automatic second pass over paused challenges."""

        self._require_role(caller_id, "chief")
        ready = await self._service().second_pass_ready(
            self._run_id(),
            min_remaining_seconds=self.second_pass_min_remaining_seconds,
        )
        if not ready["ready"]:
            return self._ok({"started": False, **ready})
        began = await self._service().begin_second_pass(self._run_id())
        started_codes: list[str] = []
        for code in began["unique_codes"]:
            result = await self.create_challenge_agent(caller_id, code)
            if result.get("ok"):
                started_codes.append(code)
            else:
                LOGGER.warning(
                    "second_pass_challenge_start_failed run_id=%s unique_code=%s error_code=%s",
                    self._run_id(),
                    code,
                    result.get("error_code"),
                )
        return self._ok(
            {
                "started": True,
                "unique_codes": began["unique_codes"],
                "started_codes": started_codes,
            }
        )

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

    async def get_execution_reports(
        self,
        caller_id: str,
        wait_seconds: float = 0.0,
        max_reports: int = 20,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "challenge")
        result = await self._service().consume_reports(
            self._run_id(),
            self._state_context(caller_id),
            report_type="execution",
            wait_seconds=wait_seconds,
            max_reports=max_reports,
        )
        reports = [self._flatten_report(item, "execution_report") for item in result["reports"]]
        return self._ok({"reports": reports, "count": len(reports), "next_sequence": result["next_sequence"]})

    async def get_challenge_updates(
        self,
        caller_id: str,
        wait_seconds: float = 0.0,
        max_reports: int = 20,
    ) -> dict[str, Any]:
        self._require_role(caller_id, "challenge")
        result = await self._service().consume_reports(
            self._run_id(),
            self._state_context(caller_id),
            report_type="hint",
            wait_seconds=wait_seconds,
            max_reports=max_reports,
        )
        updates = [self._flatten_report(item, "hint_received") for item in result["reports"]]
        return self._ok({"updates": updates, "count": len(updates), "next_sequence": result["next_sequence"]})

    async def report_challenge_status(
        self,
        caller_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if payload.get("status") == "completed":
            challenge = await self._challenge_record(node.unique_code)
            if not challenge["is_completed"] and challenge["work_status"] != "closed":
                return self._error(
                    "challenge_not_completed",
                    "Challenge can be reported completed only after the remote platform confirms is_completed",
                    error_type="conflict",
                )
        report = AgentStatusReport(
            agent_id=caller_id,
            unique_code=node.unique_code or "unknown",
            **dict(payload),
        )
        if self.chief_agent_id is None:
            raise SubagentError("Chief Agent is unavailable")
        saved = await self._service().publish_control_report(
            self._run_id(),
            sender_id=caller_id,
            recipient_id=self.chief_agent_id,
            unique_code=node.unique_code,
            report_type="challenge_status",
            status=report.status,
            payload=report.model_dump(mode="json", exclude={"sequence"}),
        )
        return self._ok(
            {"agent_id": caller_id, "sequence": saved["sequence"], "status": report.status}
        )

    async def submit_flag(self, caller_id: str, flag: str) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error("missing_challenge", "Challenge Agent is not bound to a challenge")
        try:
            result = await self._execute_operation(
                caller_id=caller_id,
                tool_name="benchmark_submit_flag",
                arguments={"unique_code": node.unique_code, "flag": flag},
                unique_code=node.unique_code,
            )
            if result.get("ok"):
                await self._sync_challenge_catalog()
                challenge = await self._challenge_record(node.unique_code)
                if challenge["is_completed"] and challenge["slot_occupied"]:
                    release = await self._release_completed_container(
                        caller_id,
                        node.unique_code,
                        reason="remote_completion_confirmed",
                    )
                    data = (
                        dict(result["data"])
                        if isinstance(result.get("data"), Mapping)
                        else {}
                    )
                    data["container_release"] = release
                    result = {**result, "data": data}
        finally:
            self._service().forget_ephemeral_secret(flag)
        return result

    async def close_challenge(self, caller_id: str) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error("missing_challenge", "Challenge Agent is not bound to a challenge")
        async with self._container_operation_lock:
            result = await self._execute_operation(
                caller_id=caller_id,
                tool_name="benchmark_close_challenge",
                arguments={"unique_code": node.unique_code},
                unique_code=node.unique_code,
            )
            synced = await self._sync_challenge_catalog()
            challenge = await self._challenge_record(node.unique_code)
            released = synced.get("ok") is True and not challenge["slot_occupied"]
        if released:
            await self._stop_children(caller_id)
            await self._service().finish_agent(
                self._run_id(), caller_id, status="completed"
            )
            await self._sync_nodes()
            if result.get("ok"):
                return result
            return self._ok(
                {
                    "unique_code": node.unique_code,
                    "closed": True,
                    "reconciled": True,
                }
            )
        if result.get("ok"):
            return self._error(
                "container_release_unconfirmed",
                "Challenge close was accepted but release could not be confirmed",
                error_type="conflict",
            )
        return result

    async def report_execution(self, caller_id: str, report: ExecutionReport) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        payload = AgentReportInput(
            status=report.status,
            summary=report.summary,
            findings=[self._finding_input(item, report.confidence) for item in report.findings],
            evidence_paths=report.evidence_paths,
            next_steps=report.next_steps,
            candidate_flag=report.candidate_flag,
            confidence=report.confidence,
        )
        saved = await self._service().submit_report(
            self._run_id(), caller_id, self._state_context(caller_id), payload
        )
        cancelled_branches = saved.get("cancelled_branches") or []
        if cancelled_branches:
            overview = await self._service().get_overview(self._run_id())
            stale_agents = [
                item["agent_id"]
                for item in overview["agents"]
                if item["role"] == "execution"
                and item.get("branch_key") in cancelled_branches
                and item["status"] not in self.TERMINAL_AGENT_STATES
            ]
            await asyncio.gather(
                *(self._stop_agent(agent_id) for agent_id in stale_agents)
            )
        await self._project()
        await self._sync_nodes()
        return self._ok(
            {
                "agent_id": caller_id,
                "sequence": saved["sequence"],
                "status": report.status,
                "terminal": report.status != "working",
                "report_id": saved.get("report_id"),
                "idempotent": saved.get("idempotent", False),
            }
        )

    async def get_core_state(self, caller_id: str) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        return self._ok(await self._service().get_overview(self._run_id()))

    async def get_schedule(self, caller_id: str) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        selected = await ChallengeScheduler(self._service()).select(self._run_id())
        return self._ok({"challenges": selected})

    async def get_challenge_state(self, caller_id: str) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error("missing_challenge", "Challenge Agent is not bound to a challenge")
        return self._ok(
            await self._service().get_challenge_context(
                self._run_id(), node.unique_code, self._state_context(caller_id)
            )
        )

    async def begin_cycle(self, caller_id: str, expected_challenge_version: int) -> dict[str, Any]:
        node = self._require_role(caller_id, "challenge")
        if not node.unique_code:
            return self._error("missing_challenge", "Challenge Agent is not bound to a challenge")
        return self._ok(
            await self._service().begin_cycle(
                self._run_id(),
                node.unique_code,
                self._state_context(caller_id),
                CreateCycleInput(expected_challenge_version=expected_challenge_version),
            )
        )

    async def submit_analysis_plan(
        self,
        caller_id: str,
        expected_version: int,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._require_role(caller_id, "challenge")
        cycle_id = str(payload.get("cycle_id", ""))
        if not cycle_id:
            return self._error("cycle_required", "cycle_id is required in the structured plan payload")
        data = dict(payload)
        data.pop("cycle_id", None)
        data["expected_version"] = expected_version
        return self._ok(
            await self._service().submit_analysis_plan(
                self._run_id(),
                cycle_id,
                self._state_context(caller_id),
                AnalysisPlanInput.model_validate(data),
            )
        )

    async def commit_cycle(
        self,
        caller_id: str,
        expected_version: int,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._require_role(caller_id, "challenge")
        cycle_id = str(payload.get("cycle_id", ""))
        if not cycle_id:
            return self._error("cycle_required", "cycle_id is required in the structured update payload")
        data = dict(payload)
        data.pop("cycle_id", None)
        data["expected_version"] = expected_version
        return self._ok(
            await self._service().commit_cycle(
                self._run_id(),
                cycle_id,
                self._state_context(caller_id),
                VerificationUpdateInput.model_validate(data),
            )
        )

    async def get_execution_assignment(self, caller_id: str) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        return self._ok(
            await self._service().get_assignment(
                self._run_id(), caller_id, self._state_context(caller_id)
            )
        )

    async def update_execution_progress(
        self,
        caller_id: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._require_role(caller_id, "execution")
        return self._ok(
            await self._service().update_progress(
                self._run_id(),
                caller_id,
                self._state_context(caller_id),
                AgentProgressInput.model_validate(payload),
            )
        )

    async def resume(self, run_id: str) -> dict[str, Any]:
        await self._ensure_service(run_id)
        self.run_id = run_id
        await self._prepare_resume(run_id)
        if self.chief_agent_id:
            await self.refresh_challenges(self.chief_agent_id)
        operations = await self._service().list_operations(run_id)
        indeterminate = [item for item in operations if item["status"] == "indeterminate"]
        if self.store is not None:
            indeterminate.extend(
                item.model_dump(mode="json")
                for item in self.store.checkpoint.indeterminate_operations
                if not any(
                    existing.get("operation_id") == item.operation_id
                    for existing in indeterminate
                )
            )
        return self._ok(
            {
                "run_id": run_id,
                "indeterminate_operations": indeterminate,
                "agents": (await self._service().get_overview(run_id))["agents"],
            }
        )

    async def close(self) -> None:
        self._pausing = False
        if self._poll_task is not None:
            self._poll_task.cancel()
            await self._ignore_cancel(self._poll_task)
            self._poll_task = None
        await self._stop_all()
        try:
            if self._http_interactions is not None:
                try:
                    await self._http_interactions.finish_run()
                finally:
                    self._http_interactions = None
        finally:
            try:
                if self._network_discovery is not None:
                    try:
                        await self._network_discovery.finish_run()
                    finally:
                        self._network_discovery = None
            finally:
                if self._shell_tasks is not None:
                    try:
                        await self._shell_tasks.finish_run()
                    finally:
                        self._shell_tasks = None
        for runner in list(self._runners.values()):
            try:
                await runner.close()
            except Exception:
                pass
        self._runners.clear()
        await self._project()

    async def pause(self) -> None:
        """Cancel live work while preserving resumable orchestration state."""

        self._pausing = True
        if self._poll_task is not None:
            self._poll_task.cancel()
            await self._ignore_cancel(self._poll_task)
            self._poll_task = None
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
        await self._service().interrupt_execution_agents(
            self._run_id(), failure_code="runtime_paused"
        )
        for runner in list(self._runners.values()):
            try:
                await runner.close()
            except Exception:
                pass
        self._runners.clear()
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
        await self._sync_nodes()

        first_session_started = asyncio.Event()

        async def execute() -> Any:
            failure_code: str | None = None
            failure_message: str | None = None
            session_resume = resume
            wake_sequence = initial_wake_sequence
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
                    if role == "chief":
                        try:
                            result = await asyncio.wait_for(
                                session, timeout=await self._remaining_run_seconds()
                            )
                        except asyncio.TimeoutError:
                            result = {"final": "Run deadline reached"}
                            await self._settle_controller(agent_id, role, result)
                            return result
                    else:
                        result = await session
                    if role == "execution":
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
                if role == "execution" and self._shell_tasks is not None:
                    current = await self._service().get_agent_runtime(
                        self._run_id(), agent_id
                    )
                    if (
                        current["agent"]["status"] in self.TERMINAL_AGENT_STATES
                        and not self._pausing
                    ):
                        try:
                            if self._http_interactions is not None:
                                await self._http_interactions.finish_agent(agent_id)
                        finally:
                            await self._shell_tasks.finish_agent(agent_id)
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
        previous_runner = self._runners.pop(agent_id, None)
        if previous_runner is not None:
            try:
                await previous_runner.close()
            except Exception:
                pass
        store = await AgentStateStore.open(
            self._service(),
            run_id=self._run_id(),
            agent_id=agent_id,
            run_dir=self._run_dir(),
        )
        if role == "chief":
            wrappers: list[Any] = [ChiefAgentTools(self, agent_id=agent_id)]
        elif role == "challenge":
            wrappers = [
                SkillTools(self.skill_catalog, role="challenge"),
                ChallengeAgentTools(
                    self, agent_id=agent_id, unique_code=agent["unique_code"]
                )
            ]
        else:
            if (
                self._shell_tasks is None
                or self._http_interactions is None
                or self._network_discovery is None
            ):
                raise SubagentError("Execution task managers are not initialized")
            wrappers = [
                SkillTools(self.skill_catalog, role="execution"),
                SystemTools(
                    root=self.project_root,
                    shell=self._shell_tasks.bind(agent_id),
                ),
                HttpTools(self._http_interactions.bind(agent_id)),
                NetworkTools(self._network_discovery.bind(agent_id)),
                ExecutionAgentTools(
                    self, agent_id=agent_id, unique_code=agent["unique_code"]
                ),
            ]
        task_contract = extract_task_contract(prompt) if role == "execution" else None
        policy = AgentPolicy(
            role,
            execution_kind=agent.get("kind"),
            requested_tools=(
                task_contract.get("tool_names")
                if isinstance(task_contract, Mapping)
                and isinstance(task_contract.get("tool_names"), list)
                else None
            ),
            scanner_profile=(
                str(task_contract.get("scanner_profile"))
                if isinstance(task_contract, Mapping)
                and task_contract.get("scanner_profile")
                else None
            ),
        )
        runner = self.runner_factory(
            self.settings,
            ToolRegistry(wrappers, allowed_tools=policy.allowed_tools),
            max_rounds=200 if role == "execution" else 1_000,
            run_root=self.run_root,
            role=role,
            agent_id=agent_id,
            parent_id=agent["parent_id"],
            base_system_prompt=self._system_prompt(role),
            require_structured_report=role == "execution",
            state_service=self._service(),
        )
        self._runners[agent_id] = runner
        if started_event is not None:
            started_event.set()
        await self._service().append_agent_event(
            self._run_id(), agent_id, "agent_runner_started", {"role": role}
        )
        try:
            operation = runner.run_session(prompt, store=store, resume=resume)
            timeout = agent["timeout_seconds"] if role == "execution" else None
            return await asyncio.wait_for(operation, timeout=timeout) if timeout else await operation
        finally:
            self._runners.pop(agent_id, None)
            try:
                await runner.close()
            except Exception:
                pass

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
            if challenge["work_status"] == "paused":
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="stopped", final_report=report
                )
                return True
            return False

        run = overview["run"]
        deadline_reached = aware(self._service().clock()) >= aware(
            datetime.fromisoformat(run["deadline_at"])
        )
        challenges = overview["challenges"]
        challenges_terminal = bool(challenges) and all(
            item["is_completed"] or item["work_status"] in {"closed", "paused"}
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
        if not deadline_reached and run["pass_number"] == 1:
            second_pass = await self.start_second_pass(agent_id)
            if second_pass.get("ok") and second_pass["data"].get("started"):
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
            raw = await self.benchmark.dispatch(tool_name, arguments)
            if not isinstance(raw, Mapping):
                raise RuntimeError("invalid benchmark response")
            result = dict(raw)
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
        if not result.get("ok"):
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
        if tool_name in {"benchmark_submit_flag", "benchmark_close_challenge"}:
            current = await self._challenge_record(unique_code)
            if current["is_completed"]:
                await self.stop_challenge_work(
                    unique_code, reason="challenge_completed"
                )
        return result

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
                    "completed" if current["is_completed"] else "closed"
                ),
            }
        if tool_name == "benchmark_submit_flag":
            current = await self._challenge_record(unique_code)
            correct_count = int(
                data.get("correct_flag_count", current["correct_flag_count"])
                or current["correct_flag_count"]
            )
            updates: dict[str, Any] = {
                "correct_flag_count": correct_count,
            }
            if bool(data.get("correct")) and correct_count > current["correct_flag_count"]:
                updates["progress_kind"] = "flag_accepted"
            return updates
        return {}

    async def _benchmark_dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self.benchmark is None:
            return self._error(
                "benchmark_unavailable",
                "Benchmark tools are not configured",
                error_type="internal",
            )
        try:
            result = await self.benchmark.dispatch(name, arguments)
        except Exception:
            return self._error(
                "benchmark_error", "Benchmark operation failed", error_type="internal"
            )
        if isinstance(result, Mapping):
            return dict(result)
        return self._error(
            "invalid_response",
            "Benchmark operation returned invalid data",
            error_type="internal",
        )

    async def _prepare_resume(self, run_id: str) -> None:
        service = self._service()
        if not await service.run_exists(run_id):
            raise SubagentError("run state database was not found")
        await service.restore_run(run_id)
        overview = await service.get_overview(run_id)
        if any(
            item.get("work_status") == "recovery"
            for item in overview.get("challenges", [])
        ):
            raise SubagentError(
                "legacy recovery state is read-only and cannot be resumed"
            )
        await service.resume_run(run_id)
        overview = await service.get_overview(run_id)
        chief = next((item for item in overview["agents"] if item["role"] == "chief"), None)
        self.chief_agent_id = chief["agent_id"] if chief else None
        self._issue_capabilities(overview["agents"])
        await service.interrupt_execution_agents(run_id)
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
        payload = AgentReportInput(
            status="cancelled" if cancelled else "failed",
            summary=(
                failure_message
                or "Execution Agent ended without a structured report"
            )[:4_000],
            failure_code=failure_code,
            findings=[],
            evidence_paths=[],
            next_steps=[],
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
                        failure_code="owner_stopped",
                    ),
                    terminal_status="stopped",
                    allow_inactive=True,
                )
            else:
                await self._service().finish_agent(
                    self._run_id(), agent_id, status="stopped"
                )
        try:
            if self._http_interactions is not None:
                await self._http_interactions.finish_agent(agent_id)
        finally:
            try:
                if self._network_discovery is not None:
                    await self._network_discovery.finish_agent(agent_id)
            finally:
                if self._shell_tasks is not None:
                    await self._shell_tasks.finish_agent(agent_id)
        await self._sync_nodes()

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
            "agent_id": item.get("agent_id"),
            "unique_code": item.get("unique_code"),
            "sequence": item.get("sequence"),
        }

    @staticmethod
    def _domain_probe_result(agent: Mapping[str, Any]) -> dict[str, Any]:
        hypothesis = str(agent.get("hypothesis_key") or "")
        domain = hypothesis.rsplit(":", 1)[-1].lower()
        if domain not in {"web", "blockchain", "ai", "binary", "other"}:
            domain = "other"
        final_report = (
            agent.get("final_report")
            if isinstance(agent.get("final_report"), Mapping)
            else {}
        )
        is_match: bool | None = None
        confidence: Any = final_report.get("confidence", 0.0)
        signals: list[str] = []
        for finding in final_report.get("findings") or []:
            if not isinstance(finding, Mapping):
                continue
            detail = finding.get("detail")
            if not isinstance(detail, Mapping):
                continue
            finding_domain = str(detail.get("domain") or domain).lower()
            if finding_domain != domain:
                continue
            raw_match = detail.get("is_match", detail.get("matches"))
            if isinstance(raw_match, bool):
                is_match = raw_match
            confidence = detail.get(
                "confidence", finding.get("confidence", confidence)
            )
            signals = [str(value) for value in detail.get("signals") or []]
            break
        if is_match is None:
            summary = str(final_report.get("summary") or "").lower()
            positive_markers = (
                "domain_match=true",
                "is_match=true",
                "is_match: true",
                f"{domain}: yes",
            )
            negative_markers = (
                "domain_match=false",
                "is_match=false",
                "is_match: false",
                f"{domain}: no",
            )
            if any(marker in summary for marker in positive_markers):
                is_match = True
            elif any(marker in summary for marker in negative_markers):
                is_match = False
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            confidence_value = 0.0
        report_id = final_report.get("report_id") or agent.get(
            "terminal_report_id"
        )
        return {
            "domain": domain,
            "is_match": is_match,
            "confidence": max(0.0, min(1.0, confidence_value)),
            "signals": signals,
            "status": agent.get("status") or "pending",
            "evidence_ref": f"report:{report_id}" if report_id else None,
        }

    @staticmethod
    def _finding_input(value: str | dict[str, Any], confidence: float | None) -> FindingInput:
        if isinstance(value, str):
            return FindingInput(
                category="other",
                summary=value[:2_000],
                detail={},
                confidence=confidence if confidence is not None else 0.5,
            )
        category = value.get("category", "other")
        if category not in {
            "service", "vulnerability", "credential", "privilege",
            "attack_path", "flag", "other",
        }:
            category = "other"
        summary = str(value.get("summary") or value.get("title") or value.get("detail") or "finding")
        detail = value.get("detail")
        if not isinstance(detail, Mapping):
            detail = {"value": detail} if detail is not None else dict(value)
        return FindingInput(
            category=category,
            summary=summary[:2_000],
            detail=dict(detail),
            confidence=float(value.get("confidence", confidence if confidence is not None else 0.5)),
            verification_status=value.get("verification_status", "candidate"),
            evidence_paths=list(value.get("evidence_paths") or []),
        )

    @staticmethod
    async def _ignore_cancel(task: asyncio.Task[Any]) -> None:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    def _challenge_prompt(
        self, challenge: Mapping[str, Any], start_result: Mapping[str, Any]
    ) -> str:
        start_data = start_result.get("data") if isinstance(start_result.get("data"), Mapping) else {}
        data = {
            "unique_code": challenge.get("unique_code"),
            "name": challenge.get("name") or challenge.get("unique_code"),
            "description": str(challenge.get("description") or "")[:4_000],
            "difficulty": challenge.get("difficulty"),
            "level": challenge.get("level"),
            "container_addr": start_data.get("container_addr") or challenge.get("container_addr") or [],
        }
        return render_prompt(
            "challenge_agent.txt",
            challenge_data=json.dumps(data, ensure_ascii=False),
        )

    @staticmethod
    def _execution_prompt(
        task_contract: Mapping[str, Any], addresses: list[str]
    ) -> str:
        return render_prompt(
            "execution_agent.txt",
            mission=str(task_contract.get("objective") or "")[:4_000],
            task_contract=task_contract_json(task_contract),
            target_addresses=json.dumps(addresses),
        )

    @staticmethod
    def _system_prompt(role: AgentRole) -> str:
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
        return {
            "ok": False,
            "error": {
                "type": error_type,
                "code": code,
                "message": message,
                "status_code": status_code,
                "detail": detail or {},
            },
        }

    @staticmethod
    def _ok(data: Any) -> dict[str, Any]:
        return {"ok": True, "data": data}

    @staticmethod
    def _error_code(result: Any) -> str | None:
        if isinstance(result, Mapping) and isinstance(result.get("error"), Mapping):
            code = result["error"].get("code")
            return code if isinstance(code, str) else None
        return None

    @staticmethod
    def _error_message(result: Any) -> str | None:
        if isinstance(result, Mapping) and isinstance(result.get("error"), Mapping):
            message = result["error"].get("message")
            return message if isinstance(message, str) else None
        return None
