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

from sqlalchemy import select, text

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
        for ref in refs:
            prefix, _, ident = ref.partition(":")
            model = {
                "evidence": EvidenceRecord,
                "report": ReportRecord,
                "finding": FindingRecord,
            }.get(prefix)
            row = await session.get(model, ident) if model else None
            if row is None or row.run_id != run_id or row.unique_code != code:
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
            findings = (
                await session.scalars(
                    select(FindingRecord)
                    .where(
                        FindingRecord.run_id == run_id,
                        FindingRecord.unique_code == unique_code,
                    )
                    .order_by(FindingRecord.first_seen_at.desc())
                    .limit(24 if compact else 100)
                )
            ).all()
            return {
                "run": self._run_dict(run),
                "challenge": self._challenge_dict(challenge),
                "tasks": [self._agent_dict(a) for a in agents[:task_limit]],
                "next_task_offset": (
                    task_offset + task_limit if len(agents) > task_limit else None
                ),
                "findings": [self._controller_finding_dict(f) for f in findings],
                "hints": [
                    {**r.payload, "report_id": r.report_id, "sequence": r.sequence}
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
            assignment = self._agent_dict(agent, include_runtime=True)
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
                agent.last_report_sequence = sequence
                if terminal:
                    agent.status = status
                    agent.terminal_report_id = report.report_id
                    agent.ended_at = self.clock()
                    agent.final_report = report.payload
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
                            else (
                                "cancelled"
                                if status in {"cancelled", "stopped", "interrupted"}
                                else "failed"
                            )
                        )
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "worker_reported" if terminal else "worker_updated",
                    {
                        "report_id": report.report_id,
                        "status": status,
                        "terminal": terminal,
                        "summary": report.payload.get("summary"),
                        "candidate_flag_present": candidate is not None,
                        "findings_received": len(value.get("findings", [])),
                        "findings_persisted": len(value.get("findings", [])),
                    },
                    agent_id=agent_id,
                )
                if terminal and (agent.task_key or "").startswith("stagnation:"):
                    await self._event(
                        session,
                        run_id,
                        "solver_stagnation_worker_finished",
                        {
                            "unique_code": agent.unique_code,
                            "worker_id": agent_id,
                            "solver_id": agent.parent_id,
                            "strategy_revision": (
                                (agent.task_key or "").rsplit(":", 1)[-1]
                            ),
                            "status": status,
                            "report_id": report.report_id,
                            "evidence_refs": value.get("evidence_refs", []),
                            "tested": value.get("tested", []),
                            "untested": value.get("untested", []),
                            "next_steps": value.get("next_steps", []),
                        },
                        agent_id=agent_id,
                    )
        await self.notifier.notify(
            self.agent_signal_key(run_id, agent.parent_id), sequence
        )
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
            await self.finalize_worker(
                run_id,
                a.agent_id,
                CapabilityContext(
                    run_id=run_id,
                    agent_id=a.agent_id,
                    role="worker",
                    unique_code=a.unique_code,
                ),
                AgentReportInput(status="interrupted", summary=reason),
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
            if not report_ref.startswith("report:"):
                raise StatePermission("report_required", "Expected a report reference")
            row = await session.get(ReportRecord, report_ref.removeprefix("report:"))
            content = json.dumps(
                self._report_dict(row), ensure_ascii=False, default=str
            )
        end = min(len(content), offset + limit_chars)
        return {
            "report_ref": report_ref,
            "content": content[offset:end],
            "next_offset": end if end < len(content) else None,
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
                await self._validate_context_refs(
                    session, run_id, agent.unique_code, [item.finding_ref]
                )
                if not item.finding_ref.startswith("finding:"):
                    raise StatePermission(
                        "finding_required", "Expected a Finding reference"
                    )
                record = await session.get(
                    FindingRecord, item.finding_ref.removeprefix("finding:")
                )
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
