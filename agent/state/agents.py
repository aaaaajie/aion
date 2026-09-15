"""Transactional Agent identities, explicit tasks, and durable report delivery.

The state service composes this with its evidence, platform and resource stores.
No method in this module chooses a solving strategy or creates implicit work.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from sqlalchemy import or_, select, text

from agent.memory.redaction import redact_value
from .completion_delivery import pending_completions
from .clock import aware
from .errors import StateConflict, StateError, StateNotFound, StatePermission
from .models import (
    AgentRecord,
    AdmissionRecord,
    EvidenceRecord,
    FindingRecord,
    ReportRecord,
    ShellTaskRecord,
    NetworkTaskRecord,
    HttpInteractionRecord,
    StateEventRecord,
)
from .resources import container_capacity_summary
from .schemas import (
    AgentReportInput,
    CapabilityContext,
    WorkerTaskInput,
    WorkerUpdateInput,
)

TERMINAL = frozenset(
    {"completed", "blocked", "failed", "stopped", "cancelled", "interrupted"}
)


def payload_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()


def chief_schedule_snapshot(
    challenges: list[Mapping[str, Any]], agents: list[Mapping[str, Any]]
) -> dict[str, Any]:
    """Return only the durable scheduling facts that can wake Chief."""

    return {
        "capacity": container_capacity_summary(challenges),
        "challenges": [
            {
                "unique_code": item.get("unique_code"),
                "is_completed": bool(item.get("is_completed")),
                "work_status": item.get("work_status"),
                "container_status": item.get("container_status"),
                "slot_occupied": bool(item.get("slot_occupied")),
                "correct_flag_count": item.get("correct_flag_count"),
            }
            for item in challenges
        ],
        "solvers": [
            {
                "agent_id": item.get("agent_id"),
                "unique_code": item.get("unique_code"),
                "status": item.get("status"),
            }
            for item in agents
            if item.get("role") == "solver"
        ],
    }


class AgentStateMixin:
    """Agent operations sharing StateService's database transaction boundary."""

    async def register_agent(
        self,
        run_id: str,
        *,
        role: str,
        agent_id: str | None = None,
        parent_id: str | None = None,
        unique_code: str | None = None,
        mission: str = "",
        initial_prompt: str | None = None,
        mode: str = "execute",
        task_key: str | None = None,
        success_criteria: list[str] | None = None,
        context_refs: list[str] | None = None,
        timeout_seconds: int | None = None,
        priority: int = 50,
        enqueue: bool = False,
    ) -> dict[str, Any]:
        if (
            role not in {"chief", "solver", "worker"}
            or mode not in {"execute", "review"}
            or (role != "worker" and mode != "execute")
        ):
            raise StateError(
                "invalid_role", "Unknown Agent role or mode", status_code=422
            )
        agent_id = agent_id or f"{role}_{uuid4().hex}"
        async with self._lock:
            async with self.db.sessions.begin() as session:
                # Serialize identity creation across independent service instances.
                await session.execute(text("BEGIN IMMEDIATE"))
                run = await self._require_run(session, run_id)
                if (
                    aware(self.clock()) >= aware(run.deadline_at)
                    or run.status == "completed"
                ):
                    raise StateConflict("run_inactive", "Run has ended")
                if role == "chief":
                    if parent_id or unique_code:
                        raise StatePermission(
                            "invalid_parent", "Chief has no parent or challenge"
                        )
                    existing = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id, AgentRecord.role == "chief"
                        )
                    )
                else:
                    parent = await session.get(AgentRecord, parent_id)
                    expected = "chief" if role == "solver" else "solver"
                    if (
                        parent is None
                        or parent.run_id != run_id
                        or parent.role != expected
                    ):
                        raise StatePermission("invalid_parent", "Invalid Agent parent")
                    challenge = await self._require_challenge(
                        session, run_id, unique_code
                    )
                    if challenge.is_completed or challenge.work_status in {
                        "closed",
                        "paused",
                    }:
                        raise StateConflict(
                            "challenge_not_active", "Challenge is not active"
                        )
                    if role == "worker" and (
                        parent.unique_code != unique_code
                        or parent.status in TERMINAL | {"paused"}
                    ):
                        raise StatePermission(
                            "invalid_parent", "Worker requires its active Solver"
                        )
                    clauses = [
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == role,
                    ]
                    if role == "worker":
                        if not task_key:
                            raise StateError(
                                "task_key_required",
                                "Explicit Worker task key is required",
                                status_code=422,
                            )
                        clauses.append(AgentRecord.task_key == task_key)
                    existing = await session.scalar(select(AgentRecord).where(*clauses))
                task = {
                    "objective": mission,
                    "mode": mode,
                    "success_criteria": success_criteria or [],
                    "context_refs": context_refs or [],
                    "timeout_seconds": timeout_seconds,
                }
                digest = payload_digest(task)
                if existing is not None:
                    if role == "worker" and existing.task_digest != digest:
                        raise StateConflict(
                            "task_key_conflict",
                            "Task key already describes different work",
                        )
                    return {**self._agent_dict(existing), "idempotent": True}
                if await session.get(AgentRecord, agent_id) is not None:
                    raise StateConflict("agent_exists", "Agent id already exists")
                record = AgentRecord(
                    agent_id=agent_id,
                    run_id=run_id,
                    role=role,
                    parent_id=parent_id,
                    unique_code=unique_code,
                    mode=mode,
                    task_key=task_key,
                    task_digest=digest if role == "worker" else None,
                    priority=priority,
                    mission=mission,
                    initial_prompt=(
                        initial_prompt if initial_prompt is not None else mission
                    ),
                    success_criteria=success_criteria or [],
                    context_refs=context_refs or [],
                    timeout_seconds=timeout_seconds,
                    status="queued" if enqueue else "pending",
                )
                session.add(record)
                if enqueue:
                    session.add(
                        AdmissionRecord(
                            admission_id=f"admission_{uuid4().hex}",
                            run_id=run_id,
                            agent_id=agent_id,
                            unique_code=unique_code,
                            role=role,
                            priority=priority,
                            status="queued",
                        )
                    )
                sequence = await self._event(
                    session,
                    run_id,
                    "agent_created",
                    {
                        "agent_id": agent_id,
                        "role": role,
                        "mode": mode,
                        "parent_id": parent_id,
                        "unique_code": unique_code,
                    },
                    agent_id=agent_id,
                )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        if role == "solver" and unique_code is not None:
            await self.signal_challenge_changes(run_id, [unique_code], sequence)
        return {**self._agent_dict(record), "idempotent": False}

    async def register_solver_for_challenge(
        self,
        run_id: str,
        *,
        solver_agent_id: str,
        parent_id: str,
        unique_code: str,
        solver_prompt: str,
        mission: str = "",
        priority: int = 50,
    ) -> dict[str, Any]:
        return await self.register_agent(
            run_id,
            agent_id=solver_agent_id,
            role="solver",
            parent_id=parent_id,
            unique_code=unique_code,
            initial_prompt=solver_prompt,
            mission=mission,
            priority=priority,
        )

    async def delegate_workers(
        self, run_id: str, context: CapabilityContext, tasks: list[WorkerTaskInput]
    ) -> dict[str, Any]:
        # Validate the whole batch before creating any work. Each explicit task
        # then uses the same idempotent transaction as recovery and retries.
        async with self.db.sessions() as session:
            solver = await self._authorize(
                session,
                context,
                roles={"solver"},
                agent_id=context.agent_id,
                run_id=run_id,
            )
            seen = {}
            for task in tasks:
                body = task.model_dump(exclude={"task_key"})
                digest = payload_digest(body)
                if task.task_key in seen and seen[task.task_key] != digest:
                    raise StateConflict(
                        "task_key_conflict", "Batch reuses a key for different work"
                    )
                seen[task.task_key] = digest
                await self._validate_context_refs(
                    session, run_id, solver.unique_code, task.context_refs
                )
                existing = await session.scalar(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == solver.unique_code,
                        AgentRecord.task_key == task.task_key,
                    )
                )
                if existing and existing.task_digest != digest:
                    raise StateConflict(
                        "task_key_conflict", "Task key already describes different work"
                    )
        admissions = []
        for task in tasks:
            admissions.append(
                await self.register_agent(
                    run_id,
                    role="worker",
                    parent_id=context.agent_id,
                    unique_code=context.unique_code,
                    mission=task.objective,
                    mode=task.mode,
                    task_key=task.task_key,
                    success_criteria=task.success_criteria,
                    context_refs=task.context_refs,
                    timeout_seconds=task.timeout_seconds,
                    enqueue=True,
                )
            )
        return {"admissions": admissions}

    async def _validate_context_refs(
        self, session: Any, run_id: str, code: str, refs: list[str]
    ) -> None:
        from .references import parse_reference
        for ref in refs:
            prefix, ident = parse_reference(ref)
            model = {
                "evidence": EvidenceRecord,
                "report": ReportRecord,
            }[prefix]
            row = await session.get(model, ident)
            if row is None:
                raise StateError(f"{prefix}_not_found", "The referenced record does not exist", status_code=404)
            if row.run_id != run_id or row.unique_code != code:
                raise StatePermission(
                    "context_not_accessible",
                    "Reference is outside this challenge and Run",
                )

    async def get_challenge_context(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext | None = None,
        *,
        compact: bool = False,
        task_offset: int = 0,
        task_limit: int = 20,
    ) -> dict[str, Any]:
        from agent.experiment_records import challenge_facts
        facts = await self.experiment_context(run_id, unique_code)
        async with self.db.sessions() as session:
            if context:
                await self._authorize(
                    session,
                    context,
                    roles={"chief", "solver", "worker"},
                    unique_code=unique_code,
                    run_id=run_id,
                )
            run = await self._require_run(session, run_id)
            challenge = await self._require_challenge(session, run_id, unique_code)
            agents = (
                await session.scalars(
                    select(AgentRecord)
                    .where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "worker",
                    )
                    .order_by(AgentRecord.created_at, AgentRecord.agent_id)
                    .offset(task_offset)
                    .limit(task_limit + 1)
                )
            ).all()
            return {
                "run": self._run_dict(run),
                "challenge": challenge_facts(self._challenge_dict(challenge)),
                "tasks": [{**{k: getattr(a, k) for k in ("agent_id", "role", "mode", "status")},
                           "report_ref": f"report:{a.terminal_report_id}" if a.terminal_report_id and (a.final_report or {}).get("system_finalized") else None} for a in agents[:task_limit]],
                "next_task_offset": (
                    task_offset + task_limit if len(agents) > task_limit else None
                ),
                "experiments": facts,
                "hints": [
                    {**r.payload, "report_ref": f"report:{r.report_id}", "sequence": r.sequence}
                    for r in (
                        await session.scalars(
                            select(ReportRecord)
                            .where(
                                ReportRecord.run_id == run_id,
                                ReportRecord.unique_code == unique_code,
                                ReportRecord.report_type == "hint",
                                ReportRecord.parent_id.is_(None),
                            )
                            .order_by(ReportRecord.sequence.desc())
                            .limit(5)
                        )
                    ).all()
                ],
            }

    async def get_assignment(
        self, run_id: str, agent_id: str, context: CapabilityContext
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            agent = await self._authorize(
                session, context, roles={"worker"}, agent_id=agent_id, run_id=run_id
            )
            assignment = {k: getattr(agent, k) for k in ("agent_id", "role", "mode", "task_key", "context_refs", "status", "timeout_seconds")}
            if agent.mode != "review" and not (agent.task_key or "").startswith(("stagnation:", "capability-verifier:")):
                assignment["task_scope"] = agent.mission
        return {
            "assignment": assignment,
            "challenge": await self.get_challenge_context(
                run_id, context.unique_code, context, compact=True
            ),
        }

    async def observe_solver(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext,
        *,
        max_reports: int = 20,
        task_offset: int = 0,
        task_limit: int = 20,
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            await self._authorize(
                session,
                context,
                roles={"solver"},
                unique_code=unique_code,
                run_id=run_id,
            )
        snapshot = await self.get_challenge_context(
            run_id,
            unique_code,
            context,
            compact=True,
            task_offset=task_offset,
            task_limit=task_limit,
        )
        reports = await self.consume_reports(run_id, context, max_reports=max_reports)
        from agent.experiment_records import report_receipt
        reports["reports"] = [report_receipt(r) for r in reports["reports"]]
        snapshot.update(reports)
        return snapshot

    async def observe_chief(
        self, run_id: str, context: CapabilityContext, *, max_reports: int = 20
    ) -> dict[str, Any]:
        """Consume Chief's inbox and record one atomic scheduling snapshot."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._authorize(
                    session,
                    context,
                    roles={"chief"},
                    agent_id=context.agent_id,
                    run_id=run_id,
                )
                reports = await self._consume_reports_locked(
                    session, run_id, context.agent_id, max_reports=max_reports
                )
                overview = await self._overview_locked(session, run_id)
                schedule = chief_schedule_snapshot(
                    overview["challenges"], overview["agents"]
                )
                digest = payload_digest(schedule)
                revision = await self._event(
                    session,
                    run_id,
                    "chief_observation_snapshot",
                    {"snapshot": schedule, "snapshot_digest": digest},
                    agent_id=context.agent_id,
                )
                return {
                    **overview,
                    **reports,
                    "capacity": overview["container_capacity"],
                    "observation_revision": revision,
                    "observation_digest": digest,
                }

    async def consume_reports(
        self, run_id: str, context: CapabilityContext, *, max_reports: int = 20
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session,
                    context,
                    roles={"chief", "solver"},
                    agent_id=context.agent_id,
                    run_id=run_id,
                )
                return await self._consume_reports_locked(
                    session, run_id, agent.agent_id, max_reports=max_reports
                )

    async def _consume_reports_locked(
        self, session: Any, run_id: str, agent_id: str, *, max_reports: int
    ) -> dict[str, Any]:
        agent = await session.get(AgentRecord, agent_id)
        if agent is None or agent.run_id != run_id:
            raise StateNotFound("agent_not_found", "Agent was not found")
        # One ordered inbox per owner. Pending delivery is never replaced by
        # newer reports or acknowledged by an unrelated response.
        delivery = dict(agent.pending_delivery or {})
        if delivery:
            rows = (
                await session.scalars(
                    select(ReportRecord)
                    .where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.report_id.in_(delivery["report_ids"]),
                    )
                    .order_by(ReportRecord.sequence)
                )
            ).all()
        else:
            rows = (
                await session.scalars(
                    select(ReportRecord)
                    .where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.parent_id == agent_id,
                        ReportRecord.sequence > agent.report_cursor,
                        or_(ReportRecord.report_type != "worker", ReportRecord.status == "working",
                            ReportRecord.payload["system_finalized"].as_boolean().is_(True)),
                    )
                    .order_by(ReportRecord.sequence)
                    .limit(max(1, min(max_reports, 100)))
                )
            ).all()
            if rows:
                delivery = {
                    "delivery_id": f"delivery_{uuid4().hex}",
                    "through_sequence": rows[-1].sequence,
                    "report_ids": [r.report_id for r in rows],
                }
                agent.pending_delivery = delivery
                await self._event(
                    session,
                    run_id,
                    "report_delivery_prepared",
                    delivery,
                    agent_id=agent_id,
                )
        reports = [self._report_dict(r) for r in rows]
        return {
            "reports": reports,
            "count": len(reports),
            "delivery_id": delivery.get("delivery_id"),
            "next_sequence": delivery.get("through_sequence", agent.report_cursor),
        }

    async def acknowledge_report_delivery(
        self, run_id: str, agent_id: str, delivery_id: str, response_sequence: int
    ) -> None:
        from .models import StateEventRecord

        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                delivery = agent.pending_delivery or {}
                if delivery.get("delivery_id") != delivery_id:
                    return
                response = await session.scalar(
                    select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent_id,
                        StateEventRecord.sequence == response_sequence,
                        StateEventRecord.event_type == "assistant_response",
                    )
                )
                if response is None or delivery_id not in (response.payload or {}).get(
                    "delivery_ids", []
                ):
                    raise StateConflict(
                        "delivery_response_required",
                        "A persisted response for this delivery is required",
                    )
                agent.report_cursor = max(
                    agent.report_cursor, int(delivery["through_sequence"])
                )
                agent.pending_delivery = {}
                await self._event(
                    session,
                    run_id,
                    "report_delivery_acknowledged",
                    {
                        "delivery_id": delivery_id,
                        "response_sequence": response_sequence,
                    },
                    agent_id=agent_id,
                )

    async def record_controller_wait(
        self, run_id: str, agent_id: str, reason: str | None
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if (
                    agent is None
                    or agent.run_id != run_id
                    or agent.role not in {"chief", "solver"}
                ):
                    raise StatePermission(
                        "controller_required", "Only Chief or Solver can wait"
                    )
                if agent.status in TERMINAL | {"paused", "stopping"}:
                    return {"status": agent.status, "reports_available": False}
                unread = await session.scalar(
                    select(ReportRecord.sequence)
                    .where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.parent_id == agent_id,
                        ReportRecord.sequence > agent.report_cursor,
                        or_(ReportRecord.report_type != "worker", ReportRecord.status == "working",
                            ReportRecord.payload["system_finalized"].as_boolean().is_(True)),
                    )
                    .limit(1)
                )
                if unread is not None or agent.pending_delivery:
                    return {"status": "ready", "reports_available": True}
                if agent.role == "solver" and await pending_completions(session, run_id, agent_id, limit=1):
                    return {"status": "ready", "reports_available": False, "completions_available": True}
                if agent.role == "chief":
                    changed, digest = await self._chief_schedule_changed_locked(
                        session, run_id, agent_id
                    )
                    if changed:
                        return {
                            "status": "ready",
                            "reports_available": False,
                            "code": "state_changed",
                            "observation_digest": digest,
                        }
                sources = await self._waiting_sources(session, run_id, agent_id)
                if agent.role == "solver":
                    # Check durable producers under the same lock as completion
                    # writers, before recording the wait cursor. An arbitrary
                    # reason string is not a subscription or a retry timer.
                    if not sources:
                        return {"status": "ready", "wait_entered": False,
                                "code": "no_wait_source", "reports_available": False,
                                "message": "No active task or Worker can wake this wait. solver_wait is not a timer and does not monitor application readiness. Continue bounded verification, or report the concrete blocker to Chief with solver_progress. For a short delayed retry, use a bounded foreground command; HTTP 500 alone does not establish initialization."}
                agent.status = "waiting"
                run = await self._require_run(session, run_id)
                # Solver uses this as a notification cursor. Chief's durable
                # scheduling baseline is the delivered observation digest
                # above; never overwrite it with the global event sequence.
                if agent.role == "solver":
                    agent.controller_cursor = run.last_sequence
                return {
                    "status": "waiting",
                    "sequence": run.last_sequence,
                    "reason": reason,
                    "waiting_sources": sources,
                }

    async def _chief_schedule_changed_locked(
        self, session: Any, run_id: str, agent_id: str
    ) -> tuple[bool, str]:
        overview = await self._overview_locked(session, run_id)
        schedule = chief_schedule_snapshot(
            overview["challenges"], overview["agents"]
        )
        digest = payload_digest(schedule)
        delivered = await session.scalar(
            select(StateEventRecord)
            .where(
                StateEventRecord.run_id == run_id,
                StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type == "chief_observation_delivered",
            )
            .order_by(StateEventRecord.sequence.desc())
            .limit(1)
        )
        if delivered is None:
            # A controller that has not observed yet may still enter a real
            # wait. The next durable check will compare the current state
            # against the delivered baseline once chief_observe has run.
            return False, digest
        observed = (delivered.payload or {}).get("observation_digest")
        return observed != digest, digest

    async def report_worker(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        payload: WorkerUpdateInput | AgentReportInput,
        *,
        terminal: bool,
        terminal_status: str | None = None,
        allow_inactive: bool = False,
        call_id: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                agent = await self._authorize(
                    session, context, roles={"worker"}, agent_id=agent_id, run_id=run_id
                )
                value = payload.model_dump(mode="python")
                if (agent.task_key or "").startswith("capability-verifier:"):
                    value["task_key"] = agent.task_key
                digest = payload_digest(value)
                if agent.terminal_report_id:
                    existing = await session.get(ReportRecord, agent.terminal_report_id)
                    if existing.content_digest != digest:
                        await self._event(
                            session,
                            run_id,
                            "worker_late_result",
                            {
                                "terminal_report_id": existing.report_id,
                                "content_digest": digest,
                                "payload": redact_value(
                                    {
                                        k: v
                                        for k, v in value.items()
                                        if k != "candidate_flag"
                                    }
                                ),
                            },
                            agent_id=agent_id,
                        )
                    return {
                        **self._report_dict(existing),
                        "idempotent": True,
                        "terminal": True,
                        "warnings": [],
                    }
                if call_id:
                    prior = await session.scalar(
                        select(ReportRecord).where(
                            ReportRecord.run_id == run_id,
                            ReportRecord.agent_id == agent_id,
                            ReportRecord.call_id == call_id,
                        )
                    )
                    if prior and prior.content_digest != digest:
                        raise StateConflict(
                            "report_call_conflict",
                            "Tool call id already identifies a different report",
                        )
                duplicate = await session.scalar(
                    select(ReportRecord).where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.agent_id == agent_id,
                        ReportRecord.content_digest == digest,
                    )
                )
                if duplicate:
                    return {
                        **self._report_dict(duplicate),
                        "idempotent": True,
                        "terminal": terminal,
                        "warnings": [],
                    }
                challenge = await self._require_challenge(
                    session, run_id, agent.unique_code
                )
                if not allow_inactive and (
                    challenge.is_completed
                    or challenge.work_status in {"paused", "closed"}
                ):
                    raise StateConflict(
                        "challenge_not_active", "Challenge no longer accepts updates"
                    )
                refs = value.get("evidence_refs") or []
                await self._validate_context_refs(
                    session, run_id, agent.unique_code, refs
                )
                warnings = []
                if agent.mode == "review" and value.get("findings"):
                    raise StatePermission(
                        "review_read_only",
                        "Review reports cannot modify shared findings",
                    )
                if (agent.task_key or "").startswith("stagnation:") and (
                    value.get("findings") or value.get("candidate_flag") is not None
                ):
                    raise StatePermission(
                        "stagnation_worker_contract",
                        "Automatic stagnation Workers return tested, evidence_refs, untested and next_steps only",
                    )
                if (agent.task_key or "").startswith("capability-verifier:") and (
                    value.get("findings") or value.get("candidate_flag") is not None
                ):
                    raise StatePermission(
                        "capability_verifier_contract",
                        "Capability verifier Workers return tested, evidence_refs, untested, next_steps and status only",
                    )
                if value.get("findings"):
                    findings = await self.record_worker_findings(
                        session, run_id, agent, value["findings"]
                    )
                    value["findings"] = findings
                candidate = value.get("candidate_flag")
                status = (
                    (terminal_status or value.get("status", "completed"))
                    if terminal
                    else "working"
                )
                sequence = await self._next_sequence(session, run_id)
                report = ReportRecord(
                    report_id=f"report_{uuid4().hex}",
                    run_id=run_id,
                    agent_id=agent_id,
                    parent_id=agent.parent_id,
                    unique_code=agent.unique_code,
                    sequence=sequence,
                    report_type="worker",
                    status=status,
                    content_digest=digest,
                    call_id=call_id,
                    payload=redact_value(
                        {
                            **value,
                            "type": "worker_report" if terminal else "worker_update",
                            "terminal": terminal,
                            "candidate_flag_present": candidate is not None,
                        }
                    ),
                )
                session.add(report)
                if not terminal:
                    agent.last_report_sequence = sequence
                if terminal:
                    agent.terminal_report_id = report.report_id
                    agent.final_report = report.payload
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "worker_report_submitted" if terminal else "worker_updated",
                    {
                        "report_id": report.report_id,
                        "status": status,
                        "terminal": terminal,
                        "summary": report.payload.get("summary"),
                        "verification_status": value.get("verification_status"),
                        "error_code": value.get("error_code"),
                        "error_stage": value.get("error_stage"),
                        "rounds_used": value.get("rounds_used"),
                        "tool_calls": value.get("tool_calls"),
                        "blocked_by": value.get("blocked_by"),
                        "new_evidence": value.get("new_evidence"),
                        "owned_resources_closed": value.get("owned_resources_closed"),
                        "candidate_flag_present": candidate is not None,
                        "findings_received": len(value.get("findings", [])),
                        "findings_persisted": len(value.get("findings", [])),
                    },
                    agent_id=agent_id,
                )
        if not terminal:
            await self.notifier.notify(self.agent_signal_key(run_id, agent.parent_id), sequence)
            await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return {
            **self._report_dict(report),
            "idempotent": False,
            "terminal": terminal,
            "warnings": warnings,
        }

    async def finalize_worker(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        payload: AgentReportInput,
        *,
        terminal_status: str | None = None,
        allow_inactive: bool = False,
    ) -> dict[str, Any]:
        return await self.report_worker(
            run_id,
            agent_id,
            context,
            payload,
            terminal=True,
            terminal_status=terminal_status,
            allow_inactive=allow_inactive,
        )

    async def record_worker_termination(
        self, run_id: str, agent_id: str, context: CapabilityContext, outcome: dict[str, Any]
    ) -> dict[str, Any]:
        """Persist the first system stop cause before cleanup can time out."""
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._authorize(session, context, roles={"worker"}, agent_id=agent_id, run_id=run_id)
                existing = await session.scalar(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.agent_id == agent_id,
                    StateEventRecord.event_type == "worker_termination_requested",
                ).order_by(StateEventRecord.sequence).limit(1))
                if existing is not None:
                    return existing.payload
                safe = redact_value(outcome)
                await self._event(session, run_id, "worker_termination_requested", safe, agent_id=agent_id)
                return safe

    async def finalize_worker_runtime(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        *,
        status: str,
        summary: str,
        owned_resources_closed: bool,
        resource_cleanup_status: str,
        termination_reason: str,
        error_code: str | None = None,
        error_stage: str | None = None,
        blocked_by: str | None = None,
        verification_status: str | None = None,
        allow_inactive: bool = True,
    ) -> dict[str, Any]:
        """Finalize or enrich exactly one Worker report with system facts.

        Model supplied counters and cleanup flags are deliberately ignored.
        The lifecycle calls this only after technical resources have reached a
        terminal cleanup result, so the report and the cleanup event agree.
        """

        if status == "stopped":
            status = "cancelled"
        if status not in TERMINAL:
            raise StateError("invalid_terminal_status", "Invalid Worker terminal status")
        if "AgentRunnerError" in summary:
            summary = (
                "验证未完整完成"
                if verification_status == "uncertain"
                else "Worker 运行失败"
            )
        outcome = await self.record_worker_termination(run_id, agent_id, context, {
            "status": status, "summary": summary, "termination_reason": termination_reason,
            "verification_status": verification_status, "error_code": error_code,
            "error_stage": error_stage, "blocked_by": blocked_by,
        })
        status = outcome["status"]
        if termination_reason != outcome["termination_reason"]:
            summary = outcome["summary"]
        termination_reason = outcome["termination_reason"]
        verification_status, error_code = outcome.get("verification_status"), outcome.get("error_code")
        error_stage, blocked_by = outcome.get("error_stage"), outcome.get("blocked_by")
        if "AgentRunnerError" in summary:
            summary = "验证未完整完成" if verification_status == "uncertain" else "Worker 运行失败"
        # Only the event journal is authoritative, including the zero-call case.
        async with self.db.sessions() as metrics_session:
            metric_rows = (
                await metrics_session.scalars(
                    select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent_id,
                        StateEventRecord.event_type.in_({
                            "model_call_started",
                            "tool_call",
                        }),
                    )
                )
            ).all()
        event_rounds = sum(
            1
            for row in metric_rows
            if row.event_type == "model_call_started"
        )
        event_tool_calls = sum(
            1 for row in metric_rows if row.event_type == "tool_call"
        )
        runtime = {
            "rounds_used": event_rounds,
            "tool_calls": event_tool_calls,
            "owned_resources_closed": bool(owned_resources_closed),
            "resource_cleanup_status": resource_cleanup_status,
            "termination_reason": termination_reason,
        }
        base = AgentReportInput(
            status=status,
            summary=summary,
            verification_status=verification_status,
            error_code=error_code,
            error_stage=error_stage,
            blocked_by=blocked_by,
            rounds_used=runtime["rounds_used"],
            tool_calls=runtime["tool_calls"],
            owned_resources_closed=runtime["owned_resources_closed"],
        )
        sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                agent = await self._authorize(
                    session, context, roles={"worker"}, agent_id=agent_id, run_id=run_id
                )
                report = (
                    await session.get(ReportRecord, agent.terminal_report_id)
                    if agent.terminal_report_id
                    else None
                )
                if report is None:
                    # Preserve the latest non-terminal Worker update when the
                    # lifecycle has to synthesize the terminal report.
                    latest = await session.scalar(
                        select(ReportRecord)
                        .where(
                            ReportRecord.run_id == run_id,
                            ReportRecord.agent_id == agent_id,
                            ReportRecord.report_type == "worker",
                            ReportRecord.status == "working",
                        )
                        .order_by(ReportRecord.sequence.desc())
                        .limit(1)
                    )
                    if latest is not None:
                        payload = latest.payload or {}
                        base = AgentReportInput(
                            status=status,
                            summary=str(payload.get("summary") or summary),
                            evidence_refs=list(payload.get("evidence_refs") or []),
                            tested=list(payload.get("tested") or []),
                            untested=list(payload.get("untested") or []),
                            next_steps=list(payload.get("next_steps") or []),
                            candidate_flag=payload.get("candidate_flag"),
                            verification_status=verification_status,
                            error_code=error_code,
                            error_stage=error_stage,
                            rounds_used=runtime["rounds_used"],
                            tool_calls=runtime["tool_calls"],
                            blocked_by=blocked_by,
                            owned_resources_closed=runtime["owned_resources_closed"],
                        )
                    # Leave creation to the normal report path after this
                    # transaction. This branch is used for crashes before the
                    # model could submit a terminal report.
                    report_id = None
                else:
                    value = dict(report.payload or {})
                    if bool(value.get("system_finalized")):
                        report_id = report.report_id
                        continue_update = False
                        if (
                            value.get("owned_resources_closed") is not True
                            and runtime["owned_resources_closed"] is True
                        ):
                            value.update(
                                {
                                    "owned_resources_closed": True,
                                    "resource_cleanup_status": runtime[
                                        "resource_cleanup_status"
                                    ],
                                }
                            )
                            report.payload = redact_value(value)
                            report.content_digest = payload_digest(report.payload)
                            agent.final_report = report.payload
                            sequence = await self._event(
                                session,
                                run_id,
                                "worker_cleanup_reconciled",
                                {
                                    "report_id": report.report_id,
                                    "owned_resources_closed": True,
                                    "resource_cleanup_status": runtime[
                                        "resource_cleanup_status"
                                    ],
                                },
                                agent_id=agent_id,
                            )
                    else:
                        continue_update = True
                    if continue_update:
                        value.update(
                            {
                                "status": status,
                                "summary": summary,
                                **runtime,
                                **{
                                    key: item
                                    for key, item in {
                                        "verification_status": verification_status,
                                        "error_code": error_code,
                                        "error_stage": error_stage,
                                        "blocked_by": blocked_by,
                                    }.items()
                                    if item is not None
                                },
                            },
                        )
                        value.update(
                            {
                                "type": "worker_report",
                                "terminal": True,
                                "system_finalized": True,
                            }
                        )
                        safe_value = redact_value(value)
                        report.payload = safe_value
                        report.status = status
                        report.content_digest = payload_digest(safe_value)
                        agent.status = status
                        agent.final_report = safe_value
                        agent.ended_at = agent.ended_at or self.clock()
                        sequence = await self._event(
                            session,
                            run_id,
                            "worker_terminal_finalized",
                            {
                                "report_id": report.report_id,
                                "status": status,
                                "summary": summary,
                                "error_code": error_code,
                                "error_stage": error_stage,
                                "blocked_by": blocked_by,
                                "verification_status": verification_status,
                                **runtime,
                            },
                            agent_id=agent_id,
                        )
                        report.sequence = sequence
                        agent.last_report_sequence = sequence
                        terminal_event = {
                            **safe_value, "report_id": report.report_id,
                            "report_ref": f"report:{report.report_id}",
                            "worker_id": agent_id, "solver_id": agent.parent_id,
                            "unique_code": agent.unique_code, "task_key": agent.task_key,
                            "status": status, **runtime,
                        }
                        terminal_event.pop("candidate_flag", None)
                        await self._event(session, run_id, "worker_reported", terminal_event, agent_id=agent_id)
                        if (agent.task_key or "").startswith("capability-verifier:"):
                            await self._event(session, run_id, "capability_verifier_finished", terminal_event, agent_id=agent.parent_id)
                        elif (agent.task_key or "").startswith("stagnation:"):
                            terminal_event["strategy_revision"] = int(agent.task_key.rsplit(":", 1)[-1])
                            await self._event(session, run_id, "solver_stagnation_worker_finished", terminal_event, agent_id=agent_id)
                        admission = await session.scalar(
                            select(AdmissionRecord).where(
                                AdmissionRecord.run_id == run_id,
                                AdmissionRecord.agent_id == agent_id,
                            )
                        )
                        if admission:
                            admission.status = (
                                "completed"
                                if status == "completed"
                                else "cancelled"
                                if status in {"cancelled", "stopped", "interrupted"}
                                else "failed"
                            )
                        report_id = report.report_id
        if report_id is None:
            await self.finalize_worker(
                run_id,
                agent_id,
                context,
                base,
                allow_inactive=allow_inactive,
            )
            # A report created after cleanup still needs the system-only
            # fields. Use the same path once more; the existing report branch
            # is idempotent and updates it without creating a second report.
            return await self.finalize_worker_runtime(
                run_id,
                agent_id,
                context,
                status=status,
                summary=base.summary,
                owned_resources_closed=runtime["owned_resources_closed"],
                resource_cleanup_status=resource_cleanup_status,
                termination_reason=termination_reason,
                error_code=error_code,
                error_stage=error_stage,
                blocked_by=blocked_by,
                verification_status=verification_status,
                allow_inactive=allow_inactive,
            )
        if sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), sequence)
            await self.notifier.notify(self.agent_signal_key(run_id, agent.parent_id), sequence)
        return {
            "report_id": report_id,
            "report_ref": f"report:{report_id}",
            "status": report.status,
            "runtime": {key: report.payload[key] for key in runtime},
        }

    async def interrupt_workers(
        self, run_id: str, *, reason: str = "Runtime process interrupted"
    ) -> int:
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.role == "worker",
                        AgentRecord.terminal_report_id.is_(None),
                    )
                )
            ).all()
        for a in rows:
            await self.finalize_worker_runtime(
                run_id,
                a.agent_id,
                CapabilityContext(
                    run_id=run_id,
                    agent_id=a.agent_id,
                    role="worker",
                    unique_code=a.unique_code,
                ),
                status="interrupted",
                summary="Worker 超时" if "timeout" in reason.casefold() else "Worker 已停止",
                owned_resources_closed=False,
                resource_cleanup_status="release_pending",
                termination_reason="runtime_interrupted",
                error_code="runtime_interrupted",
                error_stage="lifecycle",
                allow_inactive=True,
            )
        return len(rows)

    async def invalidate_agent_resources(
        self, run_id: str, agent_id: str, *, reason: str
    ) -> int:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                agent.resource_generation += 1
                await self._event(
                    session,
                    run_id,
                    "agent_resources_invalidated",
                    {
                        "generation": agent.resource_generation,
                        "reason": reason,
                        "resources": [
                            "shell",
                            "http",
                            "network",
                            "binary",
                            "tcp",
                            "ssh",
                        ],
                    },
                    agent_id=agent_id,
                )
                return agent.resource_generation

    async def read_report(
        self,
        run_id: str,
        context: CapabilityContext,
        report_ref: str,
        *,
        offset: int = 0,
        limit_chars: int = 8000,
    ) -> dict[str, Any]:
        from .references import parse_reference
        _, report_id = parse_reference(report_ref, "report")
        async with self.db.sessions() as session:
            agent = await self._authorize(
                session,
                context,
                roles={"solver", "worker"},
                agent_id=context.agent_id,
                run_id=run_id,
            )
            await self._validate_context_refs(
                session, run_id, agent.unique_code, [report_ref]
            )
            row = await session.get(ReportRecord, report_id)
            if row.report_type == "worker" and row.status != "working" and not row.payload.get("system_finalized"):
                raise StateError("report_pending", "Worker report is awaiting resource cleanup and system finalization", status_code=409)
            report = self._report_dict(row)
            from agent.experiment_records import report_receipt
            report = report_receipt(report)
            portable = context.role == "worker" and row.agent_id != context.agent_id
            if portable:
                # A report is shared evidence too.  Do not let a Worker turn
                # another Agent's report payload into a handle transport.
                from .service import portable_evidence_projection

                content = portable_evidence_projection(
                    json.dumps(report, ensure_ascii=False, default=str),
                    max_preview=max(8_000, limit_chars),
                )
            else:
                content = json.dumps(report, ensure_ascii=False, default=str)
        end = min(len(content), offset + limit_chars)
        return {
            "report_ref": report_ref,
            "portable": portable,
            "offset": offset,
            "content": content[offset:end],
            "next_offset": end if end < len(content) else None,
            "eof": end >= len(content),
        }

    async def track_agent_process(self, run_id: str, agent_id: str, pid: int) -> None:
        import psutil

        created_at = psutil.Process(pid).create_time()
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id or agent.mode == "review":
                    raise StatePermission(
                        "process_owner_invalid", "Agent cannot own this process"
                    )
                agent.resource_processes = [
                    *(agent.resource_processes or []),
                    {
                        "pid": pid,
                        "created_at": created_at,
                        "generation": agent.resource_generation,
                    },
                ]
                await self._event(
                    session,
                    run_id,
                    "agent_process_owned",
                    {
                        "pid": pid,
                        "created_at": created_at,
                        "generation": agent.resource_generation,
                    },
                    agent_id=agent_id,
                )

    async def reap_agent_processes(self, run_id: str, agent_id: str) -> None:
        from agent.process_resources import terminate_recorded_process

        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise StateNotFound("agent_not_found", "Agent was not found")
            records = list(agent.resource_processes or [])
        results = await __import__("asyncio").gather(
            *(terminate_recorded_process(r) for r in records),
            return_exceptions=True,
        )
        failures = [
            {**r, "error": type(result).__name__}
            for r, result in zip(records, results)
            if isinstance(result, BaseException)
        ]
        released = [
            r
            for r, result in zip(records, results)
            if not isinstance(result, BaseException)
        ]
        # OS waits must not hold the global StateService lock or block unrelated
        # Agents from reporting, submitting, or finishing their own cleanup.
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                agent.resource_processes = [
                    r for r in (agent.resource_processes or []) if r not in released
                ]
                if records:
                    await self._event(
                        session,
                        run_id,
                        "agent_process_cleanup",
                        {"attempted": len(records), "failures": failures},
                        agent_id=agent_id,
                    )
        if failures:
            raise StateConflict(
                "process_cleanup_failed", "Recorded processes could not be released"
            )

    async def record_worker_findings(self, session, run_id, agent, findings):
        from .schemas import ReportFindingInput

        if agent.mode == "review":
            raise StatePermission(
                "review_read_only", "Review Workers cannot modify findings"
            )
        saved = []
        for raw in findings:
            item = ReportFindingInput.model_validate(raw)
            await self._validate_context_refs(
                session, run_id, agent.unique_code, item.evidence_refs
            )
            record = None
            if item.finding_ref:
                import re
                if not re.fullmatch(r"finding:finding_[0-9a-f]{32}", item.finding_ref):
                    raise StateError("invalid_reference", "Expected an exact Finding business-record reference", status_code=422)
                record = await session.get(
                    FindingRecord, item.finding_ref.removeprefix("finding:")
                )
                if record is None:
                    raise StateError("finding_not_found", "Finding does not exist", status_code=404)
                if record.run_id != run_id or record.unique_code != agent.unique_code:
                    raise StatePermission("context_not_accessible", "Finding is outside this challenge and Run")
            fingerprint = payload_digest(
                {
                    "category": item.category,
                    "summary": " ".join(item.summary.lower().split()),
                    "detail": item.detail,
                }
            )
            if record is None:
                record = await session.scalar(
                    select(FindingRecord).where(
                        FindingRecord.run_id == run_id,
                        FindingRecord.unique_code == agent.unique_code,
                        FindingRecord.category == item.category,
                        FindingRecord.fingerprint == fingerprint,
                    )
                )
            refs = list(
                dict.fromkeys(
                    [
                        *(
                            (record.detail or {}).get("evidence_refs", [])
                            if record
                            else []
                        ),
                        *item.evidence_refs,
                    ]
                )
            )
            if item.verification_status in {"verified", "rejected"} and not refs:
                raise StateError(
                    "finding_evidence_required",
                    "Verified and rejected findings require Evidence",
                    status_code=422,
                )
            now = self.clock()
            detail = {**item.detail, "evidence_refs": refs}
            if record is None:
                record = FindingRecord(
                    finding_id="finding_" + uuid4().hex,
                    run_id=run_id,
                    unique_code=agent.unique_code,
                    agent_id=agent.agent_id,
                    category=item.category,
                    fingerprint=fingerprint,
                    summary=item.summary,
                    detail=detail,
                    confidence=item.confidence,
                    verification_status=item.verification_status,
                    evidence_paths=[],
                    first_seen_at=now,
                    last_seen_at=now,
                    verified_at=now if item.verification_status == "verified" else None,
                )
                session.add(record)
                await session.flush()
            else:
                record.summary = item.summary
                record.detail = detail
                record.confidence = item.confidence
                record.verification_status = item.verification_status
                record.last_seen_at = now
                record.verified_at = (
                    now if item.verification_status == "verified" else None
                )
                record.version += 1
            saved.append(self._finding_dict(record))
        return saved
