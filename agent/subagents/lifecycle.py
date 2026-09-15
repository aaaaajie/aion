"""Supervisor-owned Agent tasks and technical resources."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from agent.memory.models import AgentNode
from agent.runner import AgentRunnerError
from agent.skills import SkillSessionContext, SkillTools
from agent.state import AgentStateStore, CapabilityContext
from agent.state.agents import TERMINAL
from agent.state.clock import aware
from agent.state.errors import StateConflict
from agent.state.models import AgentRecord, ChallengeRecord, EvidenceRecord
from agent.state.schemas import AgentReportInput, WorkerTaskInput
from agent.tooling import (
    current_tool_call_id,
    ToolRegistry,
    ToolResultStore,
    ToolResultTools,
    ToolDispatchOutcome,
)
from tools.system import SystemTools
from tools.browser import BrowserTools
from tools.source import SourceTools
from tools.cyberchef import CyberChefTools
from tools.http import HttpTools
from tools.poc_runtime.tools import PocTools
from tools.fastcgi import FastCGITools
from tools.network import NetworkTools
from tools.binary import BinaryTools
from tools.binary.session import BinarySessionManager
from tools.artifact import ArtifactTools
from tools.pentest import PentestTools
from .policy import AgentPolicy
from .tools import AgentControlTools


WORKER_BLOCKING_ERRORS = frozenset(
    {
        "worker_round_budget_exhausted",
        "missing_structured_report",
        "llm_completion_truncated",
        "context_capacity_deferred",
        "capability_verifier_foreign_handle",
        "worker_foreign_handle",
        "context_not_accessible",
        "evidence_not_accessible",
        "evidence_content_unavailable",
        "capability_verifier_scope",
        "capability_verifier_budget",
        "invalid_json",
        "invalid_arguments",
        "capability_verifier_contract",
        "stagnation_worker_contract",
        "review_read_only",
        "tool_not_allowed_for_role",
        "tool_not_exposed",
        "permission_denied",
    }
)

AGENT_CLEANUP_SECONDS = 10.0
WORKER_PROFILE_LIMITS = {
    "capability_verifier": {"max_rounds": 8, "timeout_seconds": 90},
    "stagnation": {"max_rounds": 24, "timeout_seconds": 480},
    "review": {"max_rounds": 16, "timeout_seconds": 480},
    "normal": {"max_rounds": 32, "timeout_seconds": 480},
}
_WORKER_RESOURCE_KEYS = {
    "interaction_id",
    "request_id",
    "task_id",
    "session_id",
}


def worker_profile(agent: Mapping[str, Any]) -> str:
    task_key = str(agent.get("task_key") or "")
    if task_key.startswith("capability-verifier:"):
        return "capability_verifier"
    if task_key.startswith("stagnation:"):
        return "stagnation"
    if agent.get("mode") == "review":
        return "review"
    return "normal"


def _portable_worker_value(value: Any, *, depth: int = 0) -> Any:
    """Keep evidence useful while removing Agent-owned resource handles."""
    if depth > 3:
        return str(value)[:500]
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.casefold() in _WORKER_RESOURCE_KEYS:
                continue
            output[key_text] = _portable_worker_value(item, depth=depth + 1)
        return output
    if isinstance(value, list):
        return [_portable_worker_value(item, depth=depth + 1) for item in value[:8]]
    if isinstance(value, str):
        value = re.sub(
            r'(?i)("?(?:interaction_id|request_id|task_id|session_id)"?\s*[:=]\s*["\']?)[^,\s"\'}]+',
            r"\1<source-owned-handle>",
            value,
        )
        return value[:1200]
    return value


class AgentLifecycle:
    """Live handles remain here; identities and task outcomes live in SQLite."""

    async def create_solver(
        self, caller_id: str, unique_code: str, *, refresh: bool = True
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        async with self._challenge_locks.setdefault(unique_code, asyncio.Lock()):
            run = (await self._service().get_overview(self._run_id()))["run"]
            selected = run["selected_challenge_codes"]
            if selected is not None and unique_code not in selected:
                return self._error("challenge_out_of_scope", "Challenge is outside the selected run scope")
            if run["status"] != "active" or await self._remaining_run_seconds() <= 0:
                return self._error(
                    "run_inactive", "The absolute Run deadline has passed"
                )
            if refresh:
                refreshed = await self.refresh_challenges(caller_id)
                if not refreshed.get("ok"):
                    return refreshed
            challenge = self._catalog.get(unique_code)
            if challenge is None:
                return self._error("task_not_found", "Challenge was not found")
            state = await self._challenge_record(unique_code)
            if state["is_completed"] or state["work_status"] == "closed":
                return self._error("challenge_completed", "Challenge has ended")
            existing = await self._find_agent("solver", unique_code=unique_code)
            if existing and existing["agent_id"] in self._stopping_agents:
                previous_id = existing["agent_id"]
                task = self._tasks.get(previous_id)
                if task and not task.done():
                    return self._error(
                        "agent_cleanup_pending",
                        "Previous Solver execution has not stopped",
                    )
                cleanup = await self._finish_agent_resources(previous_id)
                if not cleanup["ok"]:
                    return self._error(
                        "agent_cleanup_pending",
                        "Previous Solver resources remain",
                        detail=cleanup,
                    )
            if existing and state["work_status"] == "active" and existing["status"] not in {
                "paused", "stopped", "failed", "cancelled", "interrupted", "completed"
            }:
                return self._ok(
                    {
                        "agent_id": existing["agent_id"],
                        "role": "solver",
                        "unique_code": unique_code,
                        "idempotent": True,
                        "solver": existing,
                    }
                )
            start = await self._ensure_challenge_container(caller_id, unique_code)
            if not start.get("ok"):
                return start
            await self._service().start_challenge(
                self._run_id(), unique_code, self._state_context(caller_id)
            )
            if existing:
                record = await self._service().reset_strategy_for_resume(
                    self._run_id(), unique_code, existing["agent_id"]
                )
                self._state_capabilities[existing["agent_id"]] = self.capability_registry.issue(
                    self._run_id(), existing["agent_id"], "solver", unique_code
                ).context
                await self._sync_nodes()
                await self._resume_with_hint(caller_id, unique_code, existing["agent_id"])
                await self._launch_agent(existing["agent_id"], resume=True)
                actual = (
                    await self._service().get_agent_runtime(
                        self._run_id(), existing["agent_id"]
                    )
                )["agent"]
                return self._ok(
                    {
                        "agent_id": existing["agent_id"],
                        "role": "solver",
                        "unique_code": unique_code,
                        "idempotent": True,
                        "solver": actual,
                        "strategy_revision": record["strategy_revision"],
                    }
                )
            record = await self._service().register_solver_for_challenge(
                self._run_id(),
                solver_agent_id=f"solver_{uuid4().hex}",
                parent_id=caller_id,
                unique_code=unique_code,
                solver_prompt=self._solver_prompt(challenge, start),
                mission=str(challenge.get("description") or "")[:2000],
            )
            agent_id = record["agent_id"]
            self._state_capabilities[agent_id] = self.capability_registry.issue(
                self._run_id(), agent_id, "solver", unique_code
            ).context
            await self._sync_nodes()
            await self._launch_agent(agent_id, resume=bool(record.get("idempotent")))
            actual = (
                await self._service().get_agent_runtime(self._run_id(), agent_id)
            )["agent"]
            if actual["status"] in {"failed", "stopped", "paused"}:
                return self._error(
                    "solver_start_failed", f"Solver {agent_id} is {actual['status']}"
                )
            return self._ok(
                {
                    "agent_id": agent_id,
                    "role": "solver",
                    "unique_code": unique_code,
                    "idempotent": record.get("idempotent", False),
                    "solver": record,
                }
            )

    async def observe_chief(
        self, caller_id: str, *, max_reports: int = 20
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        return self._ok(
            await self._service().observe_chief(
                self._run_id(), self._state_context(caller_id), max_reports=max_reports
            )
        )

    async def observe_solver(
        self,
        caller_id: str,
        *,
        max_reports: int = 20,
        task_offset: int = 0,
        task_limit: int = 20,
    ) -> dict[str, Any]:
        node = self._require_role(caller_id, "solver")
        return self._ok(
            await self._service().observe_solver(
                self._run_id(),
                node.unique_code,
                self._state_context(caller_id),
                max_reports=max_reports,
                task_offset=task_offset,
                task_limit=task_limit,
            )
        )

    async def delegate_workers(self, caller_id: str, tasks: list) -> dict[str, Any]:
        self._require_role(caller_id, "solver")
        result = await self._service().delegate_workers(
            self._run_id(), self._state_context(caller_id), tasks
        )
        await self._sync_nodes()
        self._issue_capabilities()
        return self._ok(result)

    async def cancel_worker(
        self, caller_id: str, worker_id: str, *, reason: str
    ) -> dict[str, Any]:
        self._require_role(caller_id, "solver")
        worker = (await self._service().get_agent_runtime(self._run_id(), worker_id))[
            "agent"
        ]
        if worker["parent_id"] != caller_id or worker["role"] != "worker":
            return self._error(
                "worker_not_owned",
                "Worker is not owned by this Solver",
                error_type="permission",
            )
        await self._stop_agent(worker_id, reason=reason)
        return self._ok(
            {
                "agent_id": worker_id,
                "status": (
                    await self._service().get_agent_runtime(self._run_id(), worker_id)
                )["agent"]["status"],
            }
        )

    async def report_worker(
        self, caller_id: str, payload: Any, *, terminal: bool
    ) -> dict[str, Any]:
        self._require_role(caller_id, "worker")
        result = await self._service().report_worker(
            self._run_id(),
            caller_id,
            self._state_context(caller_id),
            payload,
            terminal=terminal,
            call_id=current_tool_call_id.get(),
        )
        await self._sync_nodes()
        return self._ok(result)

    async def wait_for_state(
        self, caller_id: str, reason: str | None
    ) -> ToolDispatchOutcome:
        result = await self._service().record_controller_wait(
            self._run_id(), caller_id, reason
        )
        return ToolDispatchOutcome(
            self._ok(result),
            # A Chief state-change wake must return to the lifecycle loop so
            # it can settle terminal work before issuing another model turn.
            # Report-ready waits still stay in the model session for handling.
            yield_session=(
                result["status"] != "ready"
                or result.get("code") == "state_changed"
            ),
        )

    async def pause_challenges(
        self,
        caller_id: str,
        codes: list[str],
        *,
        reason: str,
        release_container: bool = True,
        reason_code: str = "manual",
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        results = []
        for code in dict.fromkeys(codes):
            async with self._challenge_locks.setdefault(code, asyncio.Lock()):
                try:
                    service = self._service()
                    async with service._lock:
                        async with service.db.sessions.begin() as session:
                            challenge = await service._require_challenge(
                                session, self._run_id(), code
                            )
                            if (
                                challenge.is_completed
                                or challenge.work_status == "closed"
                            ):
                                results.append(
                                    {
                                        "unique_code": code,
                                        "ok": True,
                                        "status": (
                                            "completed"
                                            if challenge.is_completed
                                            else "closed"
                                        ),
                                    }
                                )
                                continue
                            challenge.work_status = "paused"
                            challenge.pause_reason = reason
                            await service._event(
                                session,
                                self._run_id(),
                                "challenge_paused",
                                {
                                    "unique_code": code,
                                    "reason": reason,
                                    "reason_code": reason_code,
                                    "release_container": release_container,
                                },
                                agent_id=caller_id,
                            )
                    if release_container:
                        # Persist the intent before stopping live work.  If
                        # the Runtime exits between these steps, recovery can
                        # still find and reconcile the occupied paused target.
                        await service.mark_completed_container_release_pending(
                            self._run_id(), code, agent_id=caller_id
                        )
                    cleanup = await self.stop_challenge_work(
                        code, reason=reason, pause_solver=True
                    )
                    release = (
                        await self.release_paused_container(
                            code, caller_id=caller_id, reason=reason
                        )
                        if release_container
                        else {"released": False, "retained": True}
                    )
                    results.append(
                        {
                            "unique_code": code,
                            "status": "paused",
                            "cleanup": cleanup,
                            "release": release,
                            "ok": cleanup["ok"]
                            and (
                                not release_container or release.get("released", False)
                            ),
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "unique_code": code,
                            **self._error("pause_failed", type(exc).__name__),
                        }
                    )
        return self._ok({"results": results})

    async def close_challenges(
        self, caller_id: str, codes: list[str], *, reason: str
    ) -> dict[str, Any]:
        self._require_role(caller_id, "chief")
        results = []
        for code in dict.fromkeys(codes):
            async with self._challenge_locks.setdefault(code, asyncio.Lock()):
                try:
                    challenge = await self._service().close_challenge(
                        self._run_id(), code, self._state_context(caller_id)
                    )
                    cleanup = await self.stop_challenge_work(code, reason=reason)
                    release = await self._release_completed_container(
                        caller_id, code, reason=reason
                    )
                    results.append(
                        {
                            "unique_code": code,
                            "status": "completed" if challenge["is_completed"] else "closed",
                            "cleanup": cleanup,
                            "release": release,
                            "ok": cleanup["ok"] and release.get("released", False),
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "unique_code": code,
                            **self._error("close_failed", type(exc).__name__),
                        }
                    )
        return self._ok({"results": results})

    async def stop_challenge_work(
        self,
        unique_code: str,
        *,
        reason: str = "challenge_completed",
        exclude_agent_id: str | None = None,
        pause_solver: bool = False,
    ) -> dict[str, Any]:
        overview = await self._service().get_overview(
            self._run_id(), unique_code=unique_code
        )
        results = await asyncio.gather(
            *(
                self._stop_agent(
                    a["agent_id"],
                    reason=reason,
                    pause=pause_solver and a["role"] == "solver",
                )
                for a in overview["agents"]
                if a["agent_id"] != exclude_agent_id
                and self._tasks.get(a["agent_id"]) is not asyncio.current_task()
            ),
            return_exceptions=True,
        )

        items = [
            (
                r
                if isinstance(r, dict)
                else {
                    "ok": False,
                    "failures": [{"error": type(r).__name__, "message": str(r)[:500]}],
                }
            )
            for r in results
        ]
        return {"ok": all(r["ok"] for r in items), "agents": items}

    async def launch_worker(self, agent_id: str) -> None:
        await self._sync_nodes()
        self._issue_capabilities()
        self._require_role(agent_id, "worker")
        await self._launch_agent(agent_id)

    async def _launch_agent(self, agent_id: str, *, resume: bool = False) -> None:
        if self._closing:
            raise StateConflict("runtime_stopping", "New Agent work is disabled during shutdown")
        self._claim_run_ownership()
        async with self._launch_locks.setdefault(agent_id, asyncio.Lock()):
            task = self._tasks.get(agent_id)
            if task is not None and not task.done():
                if agent_id in self._stopping_agents:
                    raise RuntimeError("Previous Agent execution has not stopped")
                return
            if agent_id in self._registries:
                await self._finish_agent_resources(agent_id)
                if agent_id in self._registries:
                    raise RuntimeError(
                        "Previous technical resources could not be closed"
                    )
            service = self._service()
            agent = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
            if agent["role"] == "worker" and agent["terminal_report_id"]:
                return
            self._resources_closed.discard(agent_id)
            self._runner_metrics.pop(agent_id, None)
            self._stopping_agents.discard(agent_id)
            self._cleanup_tasks.pop(agent_id, None)
            if self._shell_tasks:
                self._shell_tasks.open_admission(agent_id)
            role = agent["role"]
            started = asyncio.Event()

            async def execute():
                nonlocal resume
                reason = "completed"
                pending_worker_outcome: dict[str, Any] | None = None
                try:
                    await service.transition_agent(self._run_id(), agent_id, "running")
                    if role == "worker":
                        profile = worker_profile(agent)
                        limits = WORKER_PROFILE_LIMITS[profile]
                        await service.append_agent_event(
                            self._run_id(),
                            agent_id,
                            "worker_started",
                            {
                                "worker_profile": profile,
                                "task_key": agent.get("task_key"),
                                "timeout_seconds": agent.get("timeout_seconds")
                                or limits["timeout_seconds"],
                                "max_rounds": limits["max_rounds"],
                            },
                        )
                    self._heartbeat_tasks[agent_id] = asyncio.create_task(
                        self._heartbeat_loop(agent_id)
                    )
                    worker_deadline = None
                    if role == "worker":
                        profile = worker_profile(agent)
                        profile_timeout = WORKER_PROFILE_LIMITS[profile]["timeout_seconds"]
                        worker_deadline = (
                            asyncio.get_running_loop().time()
                            + (agent.get("timeout_seconds") or profile_timeout)
                        )
                    recovery = 0
                    while True:
                        if role != "worker" and await self._settle_controller(
                            agent_id, role, {"reason": "scope_completed"}
                        ):
                            return {"agent_id": agent_id}
                        remaining = await self._remaining_run_seconds()
                        if worker_deadline is not None:
                            remaining = min(
                                remaining,
                                worker_deadline - asyncio.get_running_loop().time(),
                            )
                        if remaining <= 0:
                            raise asyncio.TimeoutError()
                        try:
                            result = await asyncio.wait_for(
                                self._run_agent_session(
                                    agent_id, role, resume=resume, started_event=started
                                ),
                                timeout=remaining,
                            )
                        except AgentRunnerError as exc:
                            # Workers have a single bounded retry for transient
                            # provider failures. Deterministic contract, budget,
                            # context and report errors must become a terminal
                            # structured report instead of a blind restart.
                            worker_retryable = (
                                role == "worker"
                                and exc.code == "llm_temporarily_unavailable"
                                and recovery == 0
                            )
                            if role == "worker" and not worker_retryable:
                                raise
                            if role != "worker" and not exc.recoverable:
                                raise
                            recovery += 1
                            await service.append_agent_event(
                                self._run_id(),
                                agent_id,
                                "agent_model_recovery",
                                {"code": exc.code, "attempt": recovery},
                            )
                            remaining = await self._remaining_run_seconds()
                            if worker_deadline is not None:
                                remaining = min(
                                    remaining,
                                    worker_deadline - asyncio.get_running_loop().time(),
                                )
                            await asyncio.sleep(
                                min(10, 2 ** min(recovery - 1, 3), max(0, remaining))
                            )
                            resume = True
                            continue
                        recovery = 0
                        if role == "worker":
                            current = (
                                await service.get_agent_runtime(
                                    self._run_id(), agent_id
                                )
                            )["agent"]
                            if current["terminal_report_id"] is None:
                                pending_worker_outcome = {
                                    "status": "blocked",
                                    "summary": "验证未完整完成",
                                    "verification_status": (
                                        "uncertain"
                                        if worker_profile(agent) == "capability_verifier"
                                        else None
                                    ),
                                    "error_code": "worker_missing_terminal_report",
                                    "error_stage": "report",
                                    "blocked_by": "missing_terminal_report",
                                    "termination_reason": "missing_terminal_report",
                                }
                            return result
                        if await self._settle_controller(agent_id, role, result):
                            return result
                        waiting = await service.record_controller_wait(
                            self._run_id(), agent_id, "waiting for state"
                        )
                        if waiting["status"] not in {"waiting", "ready"}:
                            return result
                        if waiting["status"] == "waiting":
                            cursor = waiting["sequence"]
                            while True:
                                remaining = await self._remaining_run_seconds()
                                if remaining <= 0:
                                    raise asyncio.TimeoutError()
                                signal = await service.notifier.wait(
                                    service.agent_signal_key(self._run_id(), agent_id),
                                    cursor,
                                    min(60, remaining),
                                )
                                if await self._settle_controller(
                                    agent_id, role, result
                                ):
                                    return result
                                # Recheck durable facts even when a post-commit signal was lost.
                                pending = await service.record_controller_wait(
                                    self._run_id(), agent_id, "waiting for state"
                                )
                                if pending["status"] not in {"ready", "waiting"}:
                                    return result
                                if pending["status"] == "ready" or signal > cursor:
                                    break
                                cursor = pending["sequence"]
                                # Health checks without a meaningful event do not run the model.
                        await service.transition_agent(
                            self._run_id(), agent_id, "running"
                        )
                        resume = True
                except asyncio.CancelledError:
                    reason = "cancelled"
                    if role == "worker":
                        pending_worker_outcome = {
                            "status": "cancelled",
                            "summary": "Worker 已停止",
                            "termination_reason": "cancelled",
                        }
                    raise
                except Exception as exc:
                    reason = "deadline" if isinstance(exc, asyncio.TimeoutError) else type(exc).__name__
                    if role == "worker":
                        metrics = self._runner_metrics.get(agent_id, {})
                        error_code = (
                            exc.code
                            if isinstance(exc, AgentRunnerError)
                            else "worker_timeout"
                            if isinstance(exc, asyncio.TimeoutError)
                            else "worker_runtime_error"
                        )
                        if isinstance(exc, asyncio.TimeoutError):
                            status = "interrupted"
                            blocked_by = "timeout"
                            summary = "Worker 超时"
                            verification_status = None
                        elif (
                            error_code in WORKER_BLOCKING_ERRORS
                            or (
                                worker_profile(agent) == "capability_verifier"
                                and error_code == "invalid_llm_response"
                            )
                            or metrics.get("report_recovery_reason")
                            or metrics.get("report_protocol_failure")
                        ):
                            status = "blocked"
                            blocked_by = "worker_report_recovery"
                            summary = (
                                "验证未完整完成"
                                if worker_profile(agent) == "capability_verifier"
                                else "Worker 未完整提交报告"
                            )
                            verification_status = (
                                "uncertain"
                                if worker_profile(agent) == "capability_verifier"
                                else None
                            )
                        else:
                            status = "failed"
                            blocked_by = error_code
                            summary = (
                                "模型服务不可用"
                                if error_code == "llm_temporarily_unavailable"
                                else "Worker 运行失败"
                            )
                            verification_status = None
                        pending_worker_outcome = {
                            "status": status,
                            "summary": summary,
                            "verification_status": verification_status,
                            "error_code": error_code,
                            "error_stage": (
                                exc.details.get("stage")
                                if isinstance(exc, AgentRunnerError)
                                else "lifecycle"
                            ),
                            "blocked_by": blocked_by,
                            "termination_reason": (
                                "timeout"
                                if isinstance(exc, asyncio.TimeoutError)
                                else error_code
                            ),
                        }
                    else:
                        if role == "solver":
                            # create_solver holds the challenge lock until startup
                            # returns. Publish failure before cleanup reacquires it.
                            await service.finish_agent(
                                self._run_id(), agent_id,
                                status="completed" if reason == "deadline" else "failed",
                            )
                            started.set()
                            await self.pause_challenges(
                                self.chief_agent_id,
                                [agent["unique_code"]],
                                reason=reason,
                            )
                        if role == "chief":
                            await self._stop_descendants(agent_id)
                            await self.release_targets(
                                reason=reason, permanent=reason == "deadline"
                            )
                            if reason == "deadline":
                                await service.finish_run(
                                    self._run_id(),
                                    "completed",
                                    report={"reason": reason, "completion_reason": "deadline"},
                                )
                        await service.finish_agent(
                            self._run_id(),
                            agent_id,
                            status="completed" if reason == "deadline" else "failed",
                        )
                    await service.append_agent_event(
                        self._run_id(),
                        agent_id,
                        "agent_execution_ended",
                        {
                            "reason": (
                                pending_worker_outcome.get("termination_reason")
                                if role == "worker" and pending_worker_outcome
                                else reason
                            ),
                            "message": (
                                "Worker execution ended"
                                if role == "worker"
                                else str(exc)[:500]
                            ),
                            **(
                                {
                                    "error_code": pending_worker_outcome.get("error_code"),
                                    "exception_type": type(exc).__name__,
                                }
                                if role == "worker" and pending_worker_outcome
                                else {}
                            ),
                        },
                    )
                finally:
                    started.set()
                    if role == "worker":
                        pending_worker_outcome = await self._record_worker_outcome(
                            agent_id, pending_worker_outcome, reason="completed_report")
                    heartbeat = self._heartbeat_tasks.pop(agent_id, None)
                    if heartbeat:
                        from agent.deadline import cancel_before
                        cleanup_deadline = self._cleanup_deadlines.setdefault(agent_id, asyncio.get_running_loop().time() + AGENT_CLEANUP_SECONDS)
                        await cancel_before([heartbeat], cleanup_deadline)
                    cleanup = await self._finish_agent_resources(agent_id)
                    if role == "worker":
                        await service.append_agent_event(
                            self._run_id(),
                            agent_id,
                            "worker_resource_cleanup",
                            {
                                "worker_profile": worker_profile(agent),
                                "resource_cleanup_status": (
                                    "closed" if cleanup["ok"] else "release_pending"
                                ),
                                "failures": cleanup.get("failures", []),
                            },
                        )
                        outcome = pending_worker_outcome
                        summary = str(outcome.get("summary") or "Worker 运行失败")
                        if "AgentRunnerError" in summary:
                            summary = (
                                "验证未完整完成"
                                if worker_profile(agent) == "capability_verifier"
                                else "Worker 运行失败"
                            )
                        await service.finalize_worker_runtime(
                            self._run_id(),
                            agent_id,
                            self._state_context(agent_id),
                            status=str(outcome.get("status") or "failed"),
                            summary=summary,
                            verification_status=outcome.get("verification_status"),
                            error_code=outcome.get("error_code"),
                            error_stage=outcome.get("error_stage"),
                            blocked_by=outcome.get("blocked_by"),
                            owned_resources_closed=bool(cleanup.get("ok")),
                            resource_cleanup_status=(
                                "closed" if cleanup.get("ok") else "release_pending"
                            ),
                            termination_reason=str(
                                outcome.get("termination_reason") or "worker_finished"
                            ),
                            allow_inactive=True,
                        )
                    await self._sync_nodes()

            self._tasks[agent_id] = asyncio.create_task(
                execute(), name=f"aion-{agent_id}"
            )
            await started.wait()

    async def _portable_worker_context(
        self, solver_id: str, refs: list[str]
    ) -> list[dict[str, Any]]:
        """Materialize a bounded, handle-free evidence snapshot for a Worker."""
        service = self._service()
        context = self._state_context(solver_id)
        bundle: list[dict[str, Any]] = []
        for ref in refs:
            if not ref.startswith("evidence:"):
                bundle.append({"ref": ref, "content": "Read this reference from the shared report state."})
                continue
            try:
                item = await service.read_evidence(
                    self._run_id(),
                    context,
                    ref,
                    offset=0,
                    limit_chars=4_000,
                    portable=True,
                )
                if item.get("evidence_type") != "experiment":
                    from agent.experiment_records import observation, digest
                    try:
                        raw = json.loads(item.get("content") or "{}")
                    except ValueError:
                        raw = {}
                    item["content"] = json.dumps({
                        "output": raw.get("output", observation(raw)),
                        "raw_artifact_sha256": digest(item.get("content", "")),
                        "input_availability": "Read the corresponding experiment record; no request inferred from a summary.",
                    }, ensure_ascii=False)
                bundle.append(
                    {
                        "ref": ref,
                        "evidence_type": item.get("evidence_type"),
                        "source": item.get("source"),
                        "content": _portable_worker_value(item.get("content", "")),
                    }
                )
            except Exception as exc:
                bundle.append(
                    {
                        "ref": ref,
                        "unavailable": type(exc).__name__,
                        "content": "Evidence must be read from the shared reference before testing.",
                    }
                )
        return bundle

    @staticmethod
    def _capability_evidence_gate(payload: Mapping[str, Any]) -> bool:
        basis = {
            str(item).casefold().replace("-", "_")
            for item in payload.get("evidence_basis", [])
            if isinstance(item, str)
        }
        return bool(
            basis
            & {
                "input_difference",
                "state_change",
                "redirect",
                "cookie_change",
                "auth_state_change",
                "protected_response",
                "database_error",
            }
        )

    async def _dispatch_capability_verifier(
        self, solver_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Dispatch one evidence-scoped verifier for a missed decision."""
        self._require_role(solver_id, "solver")
        refs = [
            ref for ref in payload.get("evidence_refs", [])
            if isinstance(ref, str)
            and ref.startswith(("evidence:", "report:"))
        ][:4]
        if not refs:
            return {"status": "skipped", "reason": "no_persisted_evidence"}
        if not self._capability_evidence_gate(payload):
            return {"status": "skipped", "reason": "insufficient_evidence_gate"}
        solver_runtime = (await self._service().get_agent_runtime(
            self._run_id(), solver_id
        ))["agent"]
        unique_code = solver_runtime.get("unique_code")
        if not isinstance(unique_code, str) or not unique_code:
            return {"status": "skipped", "reason": "solver_not_bound"}
        challenge = await self._challenge_record(unique_code)
        if challenge.get("is_completed") or challenge.get("work_status") != "active":
            return {"status": "skipped", "reason": "challenge_not_active"}
        target = str(payload.get("target") or "")
        decision_key = str(payload.get("decision_key") or "")
        revision = int(challenge.get("strategy_revision") or 1)
        basis = sorted({
            item for item in payload.get("evidence_basis", [])
            if isinstance(item, str)
        })
        candidate_ids = [
            item for item in payload.get("candidate_skill_ids", [])
            if isinstance(item, str)
        ][:3]
        evidence_bundle = await self._portable_worker_context(solver_id, refs)
        evidence_digest = hashlib.sha256(
            json.dumps(evidence_bundle, ensure_ascii=False, sort_keys=True, default=str).encode()
        ).hexdigest()
        digest = hashlib.sha256(
            f"{unique_code}:{revision}:{decision_key}:{target}:{evidence_digest}".encode()
        ).hexdigest()
        task_key = f"capability-verifier:{digest[:56]}"
        context_packet = {
            "evidence_refs": refs,
            "evidence_basis": basis,
            "candidate_skill_ids": candidate_ids,
            "decision_key": decision_key,
            "target": target,
            "evidence_digest": evidence_digest,
            "evidence_snapshot": evidence_bundle,
        }
        context_json = json.dumps(
            context_packet, ensure_ascii=False, separators=(",", ":")
        )
        if len(context_json) > 2_800:
            context_packet["evidence_snapshot"] = [
                {
                    **entry,
                    "content": str(entry.get("content") or "")[:350],
                }
                for entry in evidence_bundle
            ]
            context_json = json.dumps(
                context_packet, ensure_ascii=False, separators=(",", ":")
            )
        if len(context_json) > 2_800:
            context_packet["evidence_snapshot"] = [
                {"ref": entry.get("ref"), "content": "Read the cited evidence before testing."}
                for entry in evidence_bundle
            ]
            context_json = json.dumps(
                context_packet, ensure_ascii=False, separators=(",", ":")
            )
        objective = (
            "Verify one current Web capability decision using only the supplied same-Run evidence. "
            "Read the evidence refs first. Keep one target and one session. Do not perform path discovery, "
            "network discovery, SQLMap, credential spraying, or cross-target exploration. "
            "For input-difference evidence, compare one baseline with one controlled variation. "
            "For state-change evidence, validate one existing or protected control after the observed state change. "
            "Return one worker_report with terminal status=completed and verification_status set to "
            "confirmed, uncertain or rejected; include only tested, evidence_refs, untested and next_steps.\n\n"
            + "\n<worker_context>\n"
            + context_json
            + "\n</worker_context>"
        )
        task = WorkerTaskInput(
            objective=objective,
            task_key=task_key,
            success_criteria=[
                "Read the supplied evidence refs before testing",
                "Use one target and no more than eight HTTP requests",
                "Return tested, evidence_refs, untested, next_steps and status",
            ],
            context_refs=refs,
            timeout_seconds=90,
        )
        result = await self._service().delegate_workers(
            self._run_id(), self._state_context(solver_id), [task]
        )
        await self._sync_nodes()
        self._issue_capabilities()
        admissions = result.get("admissions") if isinstance(result, Mapping) else None
        admission = admissions[0] if isinstance(admissions, list) and admissions else {}
        idempotent = admission.get("idempotent") if isinstance(admission, Mapping) else None
        return {
            "status": "existing" if idempotent else "dispatched",
            "worker_id": admission.get("agent_id") if isinstance(admission, Mapping) else None,
            "task_key": task_key,
            "idempotent": idempotent,
            "worker_profile": "capability_verifier",
            "decision_key": decision_key,
            "evidence_digest": evidence_digest,
        }

    async def _run_agent_session(
        self,
        agent_id: str,
        role: str,
        *,
        resume: bool,
        started_event: asyncio.Event | None = None,
    ):
        service = self._service()
        agent = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
        profile_name = worker_profile(agent) if role == "worker" else None
        store = await AgentStateStore.open(
            service, run_id=self._run_id(), agent_id=agent_id, run_dir=self._run_dir()
        )
        registry = self._registries.get(agent_id)
        skill = self._skill_contexts.get(agent_id)
        if registry is None:
            providers = [
                AgentControlTools(
                    self,
                    agent_id=agent_id,
                    role=role,
                    mode=agent["mode"],
                    worker_profile=profile_name,
                )
            ]
            review = role == "worker" and agent["mode"] == "review"
            if not review:
                providers.append(
                    ToolResultTools(ToolResultStore(store.run_dir, agent_id))
                )
            if role in {"solver", "worker"} and not review:
                skill = SkillSessionContext(
                    self.skill_catalog,
                    role=role,
                    service=service,
                    run_id=self._run_id(),
                    agent_id=agent_id,
                    active_skills=agent.get("active_skills", []),
                )
                self._skill_contexts[agent_id] = skill
                shell = self._shell_tasks.bind(
                    agent_id,
                    shared_root=self._shell_tasks.shared_workspace_root(
                        agent["unique_code"]
                    ),
                )
                await shell.ensure_workspace()
                providers.extend(
                    [
                        SkillTools(skill),
                        SystemTools(
                            root=self.project_root,
                            shell=shell,
                            agent_work_root=shell.agent_work_root,
                            shared_work_root=shell.shared_work_root,
                        ),
                        HttpTools(
                            self._http_interactions.bind(
                                agent_id, workspace_root=shell.agent_work_root
                            )
                        ),
                        PocTools(
                            self.poc_index_root,
                            self._http_interactions,
                            agent_id,
                        ),
                        NetworkTools(self._network_discovery.bind(agent_id)),
                        FastCGITools(),
                        BinaryTools(
                            shell.agent_work_root,
                            shell=shell,
                            toolchain_root=self.toolchain_root,
                            session_manager=BinarySessionManager(
                                shell.agent_work_root,
                                on_process_started=lambda pid: (
                                    service.track_agent_process(
                                        self._run_id(), agent_id, pid
                                    )
                                ),
                            ),
                        ),
                        ArtifactTools(shell.agent_work_root),
                        SourceTools(shell),
                        CyberChefTools(shell, toolchain_root=self.toolchain_root),
                        BrowserTools(shell.agent_work_root, toolchain_root=self.toolchain_root,
                            on_process_started=lambda pid: service.track_agent_process(self._run_id(), agent_id, pid)),
                        PentestTools(
                            root=shell.agent_work_root,
                            toolchain_root=self.toolchain_root,
                        ),
                    ]
                )
            registry = ToolRegistry(
                providers,
                allowed_tools=AgentPolicy(role, agent["mode"]).allowed_tools,
                compact=self.settings.compact_tools
                and role in {"solver", "worker"}
                and not review,
            )
            self._registries[agent_id] = registry
        prompt = agent["initial_prompt"]
        if role == "solver":
            prompt = "Solve this authorized challenge using the factual experiments and official hints in your authoritative checkpoint. Derive your own hypotheses."
        delivery_ids = []
        if role in {"chief", "solver"}:
            snapshot = await (
                self.observe_chief(agent_id)
                if role == "chief"
                else self.observe_solver(agent_id)
            )
            data = snapshot["data"]
            if role == "chief" and isinstance(data.get("observation_revision"), int):
                await service.append_agent_event(
                    self._run_id(),
                    agent_id,
                    "chief_observation_delivered",
                    {
                        "observation_revision": data["observation_revision"],
                        "observation_digest": data.get("observation_digest"),
                        "delivery": "initial_prompt",
                    },
                )
            initial_state = data if role == "chief" else {k: v for k, v in data.items() if k not in {"context", "challenge_context", "experiments", "challenge", "run"}}
            prompt += "\n\nAuthoritative state:\n" + json.dumps(initial_state, ensure_ascii=False, default=str)
            if data.get("delivery_id"):
                delivery_ids.append(data["delivery_id"])
        else:
            prompt = ("Independently investigate the supplied factual experiments for this authorized challenge. "
                "Do not infer that a prior Agent conclusion is correct. Respect your profile and authorization. "
                "Review mode is read-only; capability_verifier uses one evidenced target, one baseline and one variation, "
                "with no discovery or credential spraying. Finish with worker_report within your budget.\n"
                + "Task scope (not evidence; independently verify any technical assertion):\n"
                + (agent["mission"] if profile_name == "normal" else "Independently inspect the factual inputs and response differences; prior conclusions are unavailable.") + "\n\nAssignment:\n"
                + json.dumps({"profile": profile_name, "context_refs": agent.get("context_refs", []),
                              "facts_source": "authoritative checkpoint"}, ensure_ascii=False))
        if resume and agent["resource_generation"]:
            prompt += f"\nTechnical session generation: {agent['resource_generation']}. Handles from a closed generation or previous Runtime process are invalid; reopen those connections. Handles opened in this generation remain usable across waits and compression. Do not replay uncertain operations."
        observation = self._solver_observers.get(agent_id)
        if (
            role == "solver"
            and self.settings.solver_observation
            and observation is None
        ):
            from agent.observation import SolverObserver

            observation = SolverObserver(
                self.settings,
                service,
                self._state_context(agent_id),
                self._shared_model_http_client(),
            )
            self._solver_observers[agent_id] = observation
            observation.start()
        profile_name = profile_name or "normal"
        profile_limits = WORKER_PROFILE_LIMITS[profile_name]
        execution_profile = profile_name if role == "worker" else "normal"
        worker_timeout = (
            agent.get("timeout_seconds")
            if role == "worker"
            else None
        ) or profile_limits["timeout_seconds"]
        runner = self.runner_factory(
            self.settings,
            registry,
            role=role,
            agent_id=agent_id,
            parent_id=agent["parent_id"],
            max_rounds=(
                profile_limits["max_rounds"]
                if role == "worker"
                else 1000
            ),
            run_root=self.run_root,
            base_system_prompt=self._system_prompt(
                "review" if role == "worker" and agent["mode"] == "review" else role
            ),
            system_context_provider=skill.render_system_context if skill else None,
            required_report_tool="worker_report" if role == "worker" else None,
            session_timeout_seconds=worker_timeout if role == "worker" else None,
            state_service=service,
            http_client=self._shared_model_http_client(),
            delivery_ids=delivery_ids,
            observation=observation,
            capability_awareness=role in {"solver"},
            execution_profile=execution_profile,
            on_capability_decision_missed=(
                (lambda payload, owner=agent_id: self._dispatch_capability_verifier(owner, payload))
                if role == "solver"
                else None
            ),
        )
        if role == "solver" and resume:
            current_challenge = await self._challenge_record(agent["unique_code"])
            if current_challenge.get("strategy_revision", 1) > 1:
                runner.request_strategy_reset()
        self._runners[agent_id] = runner
        if started_event:
            started_event.set()
        try:
            return await runner.run_session(prompt, store=store, resume=resume)
        finally:
            self._runner_metrics[agent_id] = {
                "rounds_used": max(0, int(getattr(runner, "_current_round_number", 0))),
                "tool_calls": max(0, int(getattr(runner, "_tool_call_count", 0))),
                "report_recovery_reason": getattr(runner, "report_recovery_reason", None),
                "report_protocol_failure": getattr(runner, "report_protocol_failure", None),
            }
            self._runners.pop(agent_id, None)
            await runner.close()

    def _close_agent_admission(self, agent_id: str) -> None:
        self._stopping_agents.add(agent_id)
        registry = self._registries.get(agent_id)
        if registry:
            registry.admission_closed = True
        if self._shell_tasks:
            self._shell_tasks.close_admission(agent_id)

    async def _finish_agent_resources(self, agent_id: str) -> dict[str, Any]:
        if agent_id in self._resources_closed:
            return {"ok": True, "failures": []}
        self._close_agent_admission(agent_id)
        active = self._cleanup_tasks.get(agent_id)
        if active is None or active.done():
            active = asyncio.create_task(
                self._cleanup_agent_resources(agent_id), name=f"aion-cleanup-{agent_id}"
            )
            self._cleanup_tasks[agent_id] = active
        # Shared cleanup is never cancelled by a Runner's finally block. All
        # callers observe the same pass, and a timed-out provider stays owned.
        return await asyncio.shield(active)

    @staticmethod
    def _is_idempotent_cleanup_error(exc: BaseException) -> bool:
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
            return True
        message = str(exc).casefold()
        return any(
            marker in message
            for marker in (
                "path does not exist",
                "no such file or directory",
                "connection closed while reading from driver",
                "target page, context or browser has been closed",
                "browser has been closed",
            )
        )

    async def _cleanup_agent_resources(self, agent_id: str) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        deadline = self._cleanup_deadlines.get(
            agent_id, loop.time() + AGENT_CLEANUP_SECONDS
        )
        registry = self._registries.get(agent_id)
        factories = {
            f"{type(provider).__name__}:{index}": (
                type(provider).__name__,
                provider.close,
            )
            for index, provider in enumerate(registry.providers if registry else [])
            if hasattr(provider, "close")
        }
        observation = self._solver_observers.get(agent_id)
        if observation is not None:
            factories["solver_observation"] = ("solver_observation", observation.close)
        for name, manager in (
            ("http", self._http_interactions),
            ("network", self._network_discovery),
            ("shell", self._shell_tasks),
        ):
            if manager:
                factories[name] = (
                    name,
                    lambda manager=manager: manager.finish_agent(agent_id),
                )
        factories["recorded_processes"] = (
            "recorded_processes",
            lambda: self._service().reap_agent_processes(self._run_id(), agent_id),
        )
        operations = self._cleanup_operations.setdefault(agent_id, {})
        for key, (_, factory) in factories.items():
            previous = operations.get(key)
            if previous is None or (
                previous.done()
                and (previous.cancelled() or previous.exception() is not None)
            ):

                async def invoke(factory=factory):
                    try:
                        return await factory()
                    except Exception as exc:
                        if self._is_idempotent_cleanup_error(exc):
                            return {"idempotent_cleanup": type(exc).__name__}
                        raise

                operations[key] = asyncio.create_task(
                    invoke(), name=f"aion-close-{agent_id}-{key}"
                )
        if operations:
            await asyncio.wait(
                list(operations.values()), timeout=max(0, deadline - loop.time())
            )
        failures = []
        idempotent = []
        for key, operation in operations.items():
            if not operation.done():
                operation.cancel()
                error = "TimeoutError"
                message = "Resource cleanup exceeded the Agent shutdown deadline"
            elif operation.cancelled():
                error, message = "CancelledError", "Resource cleanup was cancelled"
            else:
                exc = operation.exception()
                if exc is None:
                    result = operation.result()
                    if isinstance(result, Mapping) and result.get("idempotent_cleanup"):
                        idempotent.append(
                            {
                                "resource": factories.get(key, (key, None))[0],
                                "error": result["idempotent_cleanup"],
                            }
                        )
                    continue
                error, message = type(exc).__name__, str(exc)[:500]
            failures.append(
                {
                    "resource": factories.get(key, (key, None))[0],
                    "error": error,
                    "message": message,
                }
            )
        if failures:
            await self._service().append_agent_event(
                self._run_id(),
                agent_id,
                "agent_resource_cleanup_failed",
                {"failures": failures},
            )
        if idempotent:
            await self._service().append_agent_event(
                self._run_id(),
                agent_id,
                "agent_resource_cleanup_idempotent",
                {"resources": idempotent},
            )
        # Idempotent "already gone/closed" outcomes are successful cleanup.
        # Only genuine failures keep the Agent's resources retained for retry.
        if not failures:
            self._resources_closed.add(agent_id)
            self._registries.pop(agent_id, None)
            self._skill_contexts.pop(agent_id, None)
            self._solver_observers.pop(agent_id, None)
            self._cleanup_operations.pop(agent_id, None)
        await self._service().invalidate_agent_resources(
            self._run_id(),
            agent_id,
            reason="cleanup_incomplete" if failures else "resources_closed",
        )
        return {"ok": not failures, "failures": failures}

    async def _record_worker_outcome(self, agent_id, pending=None, *, reason):
        service = self._service()
        agent = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
        report = agent.get("final_report") or {}
        metrics = self._runner_metrics.get(agent_id, {})
        runner = self._runners.get(agent_id)
        recovery = (metrics.get("report_recovery_reason") or metrics.get("report_protocol_failure")
                    or getattr(runner, "report_recovery_reason", None)
                    or getattr(runner, "report_protocol_failure", None))
        if recovery:
            verifier = worker_profile(agent) == "capability_verifier"
            outcome = {"status": "blocked", "summary": "验证未完整完成" if verifier else "Worker 未完整提交报告",
                       "verification_status": "uncertain" if verifier else None,
                       "error_code": recovery.get("error_code") if isinstance(recovery, Mapping) else "worker_report_contract",
                       "error_stage": "report", "blocked_by": "worker_report_recovery", "termination_reason": "report_recovery"}
        else:
            default_summary = "Worker 未完整提交报告" if reason == "completed_report" else "Worker 已停止"
            outcome = pending or {
                "status": report.get("status") if report.get("status") in TERMINAL else
                          "blocked" if reason == "completed_report" else "cancelled",
                "summary": report.get("summary") or default_summary,
                "verification_status": report.get("verification_status"),
                "termination_reason": "completed_report" if report.get("status") in TERMINAL else reason,
            }
        return await service.record_worker_termination(self._run_id(), agent_id, self._state_context(agent_id), outcome)

    async def _stop_agent(
        self, agent_id: str, *, reason: str = "cancelled by owner", pause: bool = False
    ) -> dict[str, Any]:
        self._close_agent_admission(agent_id)
        deadline = self._cleanup_deadlines.setdefault(
            agent_id, asyncio.get_running_loop().time() + AGENT_CLEANUP_SECONDS
        )
        service = self._service()
        agent = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
        if agent["status"] not in TERMINAL:
            if agent["role"] == "worker":
                # Worker terminal state is written after technical cleanup.
                # This keeps cancellation, timeout and normal completion on
                # the same lifecycle path and prevents false cleanup flags.
                pass
            elif pause:
                await service.transition_agent(self._run_id(), agent_id, "paused")
            else:
                await service.finish_agent(self._run_id(), agent_id, status="stopped")
        task = self._tasks.get(agent_id)
        if task and task is not asyncio.current_task() and not task.done():
            # Serialize cancellation with finish_agent: a submission may have
            # completed while the stop transition was awaiting its transaction.
            async with service._lock:
                async with service.db.sessions() as session:
                    current = await session.get(AgentRecord, agent_id)
                    completed = current.status == "completed" or (current.role == "worker" and current.terminal_report_id is not None)
                    if not completed:
                        task.cancel()
            if completed:
                await asyncio.wait(
                    [task], timeout=max(0, deadline - asyncio.get_running_loop().time())
                )
                if not task.done() and agent["role"] != "worker":
                    self._cleanup_deadlines.pop(agent_id, None)
                    return {
                        "agent_id": agent_id, "ok": False,
                        "failures": [{
                            "resource": "agent_execution", "error": "TimeoutError",
                            "message": "Completed Agent is still finishing its receipt and cleanup",
                        }],
                    }
        if agent["role"] == "worker":
            await self._record_worker_outcome(agent_id, reason=reason)
        cleanup = await self._finish_agent_resources(agent_id)
        if task and task is not asyncio.current_task() and not task.done():
            await asyncio.wait(
                [task], timeout=max(0, deadline - asyncio.get_running_loop().time())
            )
            if not task.done():
                failure = {
                    "resource": "agent_execution",
                    "error": "TimeoutError",
                    "message": "Agent execution did not stop",
                }
                cleanup = {"ok": False, "failures": [*cleanup["failures"], failure]}
                await service.append_agent_event(
                    self._run_id(),
                    agent_id,
                    "agent_resource_cleanup_failed",
                    {"failures": [failure]},
                )
        if agent["role"] == "worker":
            metrics = self._runner_metrics.get(agent_id, {})
            current = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
            report = current.get("final_report") or {}
            summary = str(report.get("summary") or "Worker 已停止")
            if "AgentRunnerError" in summary:
                summary = "Worker 已停止"
            await service.finalize_worker_runtime(
                self._run_id(),
                agent_id,
                self._state_context(agent_id),
                status=(
                    current.get("status")
                    if current.get("status") in TERMINAL
                    else "cancelled"
                ),
                summary=summary,
                verification_status=report.get("verification_status"),
                error_code=report.get("error_code"),
                error_stage=report.get("error_stage"),
                blocked_by=report.get("blocked_by"),
                owned_resources_closed=bool(cleanup.get("ok")),
                resource_cleanup_status=(
                    "closed" if cleanup.get("ok") else "release_pending"
                ),
                termination_reason=reason,
                allow_inactive=True,
            )
        if pause and agent["role"] == "solver" and agent["status"] not in TERMINAL:
            if task is None or task.done():
                # A controller may have begun its running transition before the
                # pause request. Once it has stopped, pause owns the final state.
                current = (await service.get_agent_runtime(self._run_id(), agent_id))["agent"]
                if current["status"] not in TERMINAL | {"paused"}:
                    await service.transition_agent(self._run_id(), agent_id, "paused")
        self._cleanup_deadlines.pop(agent_id, None)
        await self._sync_nodes()
        return {"agent_id": agent_id, **cleanup}

    async def _prepare_resume(self, run_id: str) -> None:
        service = self._service()
        await service.restore_run(run_id)
        await service.resume_run(run_id)
        await service.interrupt_workers(run_id)
        async with service.db.sessions.begin() as session:
            rows = (
                await session.scalars(
                    select(ChallengeRecord).where(
                        ChallengeRecord.run_id == run_id,
                        ChallengeRecord.work_status == "paused",
                        ChallengeRecord.pause_reason == "runtime_pause",
                    )
                )
            ).all()
            for row in rows:
                row.work_status = "active"
                row.pause_reason = None
        overview = await service.get_overview(run_id)
        for agent in overview["agents"]:
            await service.reap_agent_processes(run_id, agent["agent_id"])
            await service.invalidate_agent_resources(
                run_id, agent["agent_id"], reason="process_restarted"
            )
        self._issue_capabilities(overview["agents"])
        await self._sync_nodes()

    async def read_report(self, caller_id: str, **arguments) -> dict[str, Any]:
        return self._ok(
            await self._service().read_report(
                self._run_id(), self._state_context(caller_id), **arguments
            )
        )

    async def search_evidence(
        self, caller_id: str, *, query: str = "", offset: int = 0, limit: int = 20,
        experiment_type: str | None = None, target: str | None = None,
        input_digest: str | None = None, resource_generation: int | None = None,
        batch_digest: str | None = None,
    ) -> dict[str, Any]:
        context = self._state_context(caller_id)
        service = self._service()
        async with service.db.sessions() as session:
            agent = await service._authorize(
                session,
                context,
                roles={"solver", "worker"},
                agent_id=caller_id,
                run_id=self._run_id(),
            )
            statement = select(EvidenceRecord).where(
                EvidenceRecord.run_id == self._run_id(),
                EvidenceRecord.unique_code == agent.unique_code,
            )
            for key, value in (("tool", experiment_type), ("target", target), ("input_digest", input_digest), ("resource_generation", resource_generation), ("batch_digest", batch_digest)):
                if value is not None:
                    field = EvidenceRecord.metadata_json[key]
                    statement = statement.where((field.as_integer() if isinstance(value, int) else field.as_string()) == value)
            rows = (
                await session.scalars(
                    statement.order_by(
                        EvidenceRecord.created_at, EvidenceRecord.evidence_id
                    )
                )
            ).all()
            if query:
                needle = query.casefold()
                rows = [
                    e
                    for e in rows
                    if needle in e.source.casefold()
                    or needle in e.evidence_type.casefold()
                    or needle in str((e.metadata_json or {}).get("task_id", "")).casefold()
                ]
            rows = rows[offset : offset + limit + 1]
            return self._ok(
                {
                    "evidence": [
                        {
                            "evidence_ref": f"evidence:{e.evidence_id}",
                            "source": e.source,
                            "type": e.evidence_type,
                            "size_chars": e.size_chars,
                            "created_at": aware(e.created_at).isoformat(),
                            "experiment": e.metadata_json if e.evidence_type == "experiment" else None,
                        }
                        for e in rows[:limit]
                    ],
                    "next_offset": offset + limit if len(rows) > limit else None,
                }
            )

    async def release_targets(self, *, reason: str, permanent: bool = False) -> dict[str, Any]:
        if not self.run_id or not self.chief_agent_id:
            return {"results": [], "unreleased": []}
        overview = await self._service().get_overview(self._run_id())
        selected = overview["run"]["selected_challenge_codes"]
        results: list[dict[str, Any]] = []
        for challenge in overview["challenges"]:
            if selected is not None and challenge["unique_code"] not in selected:
                continue
            if not challenge["slot_occupied"]:
                continue
            code = challenge["unique_code"]
            try:
                if (
                    permanent
                    or challenge["is_completed"]
                    or challenge["work_status"] == "closed"
                ):
                    result = await self.close_challenges(
                        self.chief_agent_id, [code], reason=reason
                    )
                else:
                    result = await self.pause_challenges(
                        self.chief_agent_id, [code], reason=reason
                    )
            except Exception as exc:
                result = {
                    "ok": False,
                    "data": {"results": [{
                        "unique_code": code,
                        "ok": False,
                        "error": type(exc).__name__,
                    }]},
                }
            entries = result.get("data", {}).get("results", [])
            if not isinstance(entries, list) or not entries:
                # Preserve one durable row when a batch operation failed
                # before it could construct its normal per-target result.
                entries = [{
                    "unique_code": code,
                    "ok": False,
                    "error": result.get("error") or "release_failed",
                }]
            results.extend(entries)
        unreleased = []
        for result in results:
            release = result.get("release") or {}
            if (
                not release.get("released", False)
                and not release.get("retained")
            ):
                unreleased.append(
                    {
                        "unique_code": result.get("unique_code"),
                        "container_status": release.get("container_status"),
                        "error_code": release.get("error_code") or result.get("error"),
                    }
                )
        summary = {
            "reason": reason,
            "permanent": permanent,
            "results": results,
            "unreleased": unreleased,
        }
        await self._service().append_agent_event(
            self._run_id(), self.chief_agent_id, "container_release_summary", summary
        )
        return summary
