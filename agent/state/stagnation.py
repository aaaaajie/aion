"""Durable, idempotent challenge stagnation state transitions."""

from __future__ import annotations

import json
import hashlib
from typing import Any
from uuid import uuid4

from sqlalchemy import select, text

from agent.config import StagnationPolicy

from .agents import payload_digest
from .clock import aware
from .errors import StateConflict, StatePermission
from .models import AdmissionRecord, AgentRecord, ChallengeRecord, ReportRecord, StateEventRecord, OperationRecord
from .resources import container_slot_occupied
from .schemas import WorkerTaskInput


class StagnationState:
    """State-service mixin for threshold transitions and auto Workers."""

    async def scan_stagnation(
        self, run_id: str, policy: StagnationPolicy
    ) -> list[dict[str, Any]]:
        now = self.clock()
        actions: list[dict[str, Any]] = []
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                run = await self._require_run(session, run_id)
                if run.status != "active":
                    return []
                challenges = (
                    await session.scalars(
                        select(ChallengeRecord).where(
                            ChallengeRecord.run_id == run_id,
                            ChallengeRecord.is_completed.is_(False),
                            ChallengeRecord.work_status == "active",
                        )
                    )
                ).all()
                for challenge in challenges:
                    if (
                        not container_slot_occupied(challenge.container_status)
                        or challenge.last_progress_at is None
                    ):
                        continue
                    solver = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == challenge.unique_code,
                            AgentRecord.role == "solver",
                            AgentRecord.status.not_in(
                                [
                                    "completed",
                                    "failed",
                                    "stopped",
                                    "cancelled",
                                    "interrupted",
                                    "paused",
                                ]
                            ),
                        )
                    )
                    if solver is None:
                        continue
                    elapsed = max(
                        0.0,
                        (
                            aware(now) - aware(challenge.last_progress_at)
                        ).total_seconds(),
                    )
                    common = {
                        "unique_code": challenge.unique_code,
                        "solver_id": solver.agent_id,
                        "strategy_revision": challenge.strategy_revision,
                        "challenge_version": challenge.version,
                        "stalled_seconds": int(elapsed),
                    }
                    if elapsed >= policy.rotate_after_seconds or challenge.stagnation_stage == "rotation_due":
                        if challenge.stagnation_stage != "rotation_due":
                            challenge.stagnation_stage = "rotation_due"
                            challenge.last_intervention_at = now
                            challenge.intervention_count += 1
                            challenge.version += 1
                            await self._event(
                                session, run_id, "solver_stagnation_rotation_requested",
                                {**common, "threshold_seconds": policy.rotate_after_seconds},
                                agent_id=solver.agent_id,
                            )
                        actions.append({"kind": "rotate", **common, "challenge_version": challenge.version})
                        continue
                    if (
                        challenge.stagnation_stage == "normal"
                        and elapsed >= policy.review_after_seconds
                    ):
                        challenge.stagnation_stage = "review_due"
                        challenge.strategy_revision += 1
                        challenge.alternate_worker_id = None
                        challenge.last_intervention_at = now
                        challenge.intervention_count += 1
                        challenge.version += 1
                        sequence = await self._event(
                            session,
                            run_id,
                            "solver_stagnation_review_due",
                            {**common, "threshold_seconds": policy.review_after_seconds},
                            agent_id=solver.agent_id,
                        )
                        await self._event(
                            session,
                            run_id,
                            "solver_strategy_reset",
                            {
                                **common,
                                "strategy_revision": challenge.strategy_revision,
                                "previous_strategy_revision": challenge.strategy_revision - 1,
                                "trigger": "stagnation_review_due",
                            },
                            agent_id=solver.agent_id,
                        )
                        actions.append(
                            {
                                "kind": "strategy_reset",
                                **common,
                                "strategy_revision": challenge.strategy_revision,
                                "challenge_version": challenge.version,
                                "event_sequence": sequence,
                            }
                        )
                        if elapsed >= policy.alternate_after_seconds:
                            actions.append({"kind": "alternate_worker", **common,
                                            "strategy_revision": challenge.strategy_revision,
                                            "challenge_version": challenge.version,
                                            "threshold_seconds": policy.alternate_after_seconds})
                    elif (
                        challenge.stagnation_stage == "review_due"
                        and elapsed >= policy.alternate_after_seconds
                    ):
                        actions.append(
                            {
                                "kind": "alternate_worker",
                                **common,
                                "threshold_seconds": policy.alternate_after_seconds,
                            }
                        )
        if actions:
            run_snapshot = await self.get_overview(run_id)
            await self.signal_challenge_changes(
                run_id,
                list(dict.fromkeys(a["unique_code"] for a in actions)),
                int(run_snapshot["run"]["last_sequence"]),
            )
        return actions

    async def get_stagnation_packet(
        self, run_id: str, unique_code: str
    ) -> dict[str, Any]:
        """Return compact, evidence-oriented context for a fresh Solver/Worker."""

        challenge = (await self.get_overview(run_id, unique_code=unique_code))["challenges"][0]
        async with self.db.sessions() as session:
            hint_reports = (await session.scalars(select(ReportRecord).where(
                ReportRecord.run_id == run_id, ReportRecord.unique_code == unique_code,
                ReportRecord.report_type == "hint",
            ).order_by(ReportRecord.sequence))).all()
            hints = [{"report_ref": f"report:{row.report_id}", "sequence": row.sequence,
                      "hint": row.payload.get("hint")} for row in hint_reports]
            # A crash after the remote operation commits may precede report delivery.
            if not hints:
                operations = (await session.scalars(select(OperationRecord).where(
                    OperationRecord.run_id == run_id, OperationRecord.unique_code == unique_code,
                    OperationRecord.operation_type == "benchmark_get_hint",
                    OperationRecord.status == "completed",
                ))).all()
                hints = [{"operation_id": row.operation_id, "hint": row.result_payload["data"]["hint"]}
                         for row in operations if isinstance(row.result_payload, dict)
                         and isinstance(row.result_payload.get("data"), dict)
                         and row.result_payload["data"].get("hint") is not None]
        from agent.experiment_records import challenge_facts
        facts = await self.experiment_context(run_id, unique_code)
        return {
            "challenge": challenge_facts(challenge),
            "strategy_revision": challenge["strategy_revision"],
            "hints": hints,
            **facts,
        }

    async def reset_strategy_for_resume(
        self, run_id: str, unique_code: str, solver_id: str, *, recovery: bool = False
    ) -> dict[str, Any]:
        """Create one fresh strategy per pause while retaining the Solver identity."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                challenge = await self._require_challenge(session, run_id, unique_code)
                solver = await session.get(AgentRecord, solver_id)
                if (
                    solver is None
                    or solver.role != "solver"
                    or solver.unique_code != unique_code
                ):
                    raise StatePermission("solver_required", "Challenge Solver was not found")
                pause = await session.scalar(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.event_type == "challenge_paused",
                    StateEventRecord.payload["unique_code"].as_string() == unique_code,
                ).order_by(StateEventRecord.sequence.desc()).limit(1))
                reset = await session.scalar(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == solver_id,
                    StateEventRecord.event_type == "solver_strategy_reset",
                    StateEventRecord.payload["trigger"].as_string() == "challenge_resumed",
                ).order_by(StateEventRecord.sequence.desc()).limit(1))
                pause_reason_code = (
                    pause.payload.get("reason_code")
                    if pause
                    else None
                )
                is_stagnation_pause = pause_reason_code in {
                    "stagnation_manual",
                    "stagnation_timeout",
                } or (pause and pause.payload.get("reason") == "stagnation_timeout")
                if recovery and (not pause or not is_stagnation_pause):
                    return self._challenge_dict(challenge)
                if pause and reset and reset.payload.get("pause_sequence") == pause.sequence:
                    return self._challenge_dict(challenge)
                challenge.strategy_revision += 1
                # Container start may already have populated active_since before
                # start_challenge runs. Grant the resumed strategy a fresh clock once.
                challenge.last_progress_at = self.clock()
                challenge.stagnation_stage = "normal"
                challenge.alternate_worker_id = None
                challenge.last_intervention_at = self.clock()
                challenge.intervention_count += 1
                challenge.version += 1
                sequence = await self._event(
                    session,
                    run_id,
                    "solver_strategy_reset",
                    {
                        "unique_code": unique_code,
                        "solver_id": solver_id,
                        "strategy_revision": challenge.strategy_revision,
                        "trigger": "challenge_resumed",
                        "pause_sequence": pause.sequence if pause else None,
                        "pause_reason": pause.payload.get("reason") if pause else None,
                        "pause_reason_code": pause_reason_code,
                    },
                    agent_id=solver_id,
                )
        await self.signal_challenge_changes(run_id, [unique_code], sequence)
        return self._challenge_dict(challenge)

    async def claim_resume_hint(self, run_id: str, unique_code: str, solver_id: str) -> dict[str, Any] | None:
        """Persist the attempt before crossing the remote Hint boundary."""
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.is_completed or challenge.work_status != "active":
                    return None
                reset = await session.scalar(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == solver_id,
                    StateEventRecord.event_type == "solver_strategy_reset",
                    StateEventRecord.payload["trigger"].as_string() == "challenge_resumed",
                ).order_by(StateEventRecord.sequence.desc()).limit(1))
                if not reset or (
                    reset.payload.get("pause_reason_code") not in {
                        "stagnation_manual",
                        "stagnation_timeout",
                    }
                    and reset.payload.get("pause_reason") != "stagnation_timeout"
                ):
                    return None
                revision = challenge.strategy_revision
                if reset.payload.get("strategy_revision") != revision:
                    return None
                events = (await session.scalars(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == solver_id,
                    StateEventRecord.event_type.in_(["solver_resume_hint_decision", "solver_resume_hint_result"]),
                    StateEventRecord.payload["strategy_revision"].as_integer() == revision,
                ))).all()
                if any(row.event_type == "solver_resume_hint_result" for row in events):
                    return None
                operations = (await session.scalars(select(OperationRecord).where(
                    OperationRecord.run_id == run_id, OperationRecord.unique_code == unique_code,
                    OperationRecord.operation_type == "benchmark_get_hint",
                ))).all()
                prior_hint_events = (await session.scalars(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == solver_id,
                    StateEventRecord.event_type.in_(["solver_resume_hint_decision", "solver_resume_hint_result"]),
                ))).all()
                resolved = {row.payload["strategy_revision"] for row in prior_hint_events
                            if row.event_type == "solver_resume_hint_result"
                            and row.payload.get("status") in {"failed", "succeeded", "reused"}}
                pending = any(row.payload.get("decision") == "request"
                              and row.payload["strategy_revision"] not in resolved for row in prior_hint_events)
                uncertain = any(row.status in {"started", "indeterminate"} or
                                row.result_code == "hint_response_unavailable" for row in operations)
                failed_attempt = bool(events) and any(
                    row.status == "failed" and row.started_sequence > min(event.sequence for event in events)
                    for row in operations
                )
                if uncertain:
                    decision = "uncertain"
                elif challenge.hint_requested:
                    decision = "reused"
                elif failed_attempt:
                    decision = "failed"
                elif pending or events:
                    decision = "uncertain"
                else:
                    decision = "request"
                payload = {"unique_code": unique_code, "strategy_revision": revision,
                           "reason": reset.payload.get("pause_reason") or "stagnation_timeout",
                           "reason_code": reset.payload.get("pause_reason_code") or "stagnation_timeout",
                           "decision": decision}
                if not events:
                    await self._event(session, run_id, "solver_resume_hint_decision", payload, agent_id=solver_id)
                return payload

    async def _find_solver_for_challenge(
        self, run_id: str, unique_code: str
    ) -> dict[str, Any] | None:
        async with self.db.sessions() as session:
            row = await session.scalar(
                select(AgentRecord).where(
                    AgentRecord.run_id == run_id,
                    AgentRecord.unique_code == unique_code,
                    AgentRecord.role == "solver",
                )
            )
            return self._agent_dict(row) if row is not None else None

    async def create_stagnation_worker(
        self,
        run_id: str,
        *,
        unique_code: str,
        solver_id: str,
        timeout_seconds: int,
    ) -> dict[str, Any] | None:
        packet = await self.get_stagnation_packet(run_id, unique_code)
        task_key = f"stagnation:{unique_code}:{packet['strategy_revision']}"
        if len(task_key) > 128:
            task_key = (
                f"stagnation:{hashlib.sha256(unique_code.encode()).hexdigest()[:32]}:"
                f"{packet['strategy_revision']}"
            )
        worker_packet = {
            **packet,
            "challenge": {
                key: packet["challenge"].get(key)
                for key in (
                    "unique_code",
                    "description",
                    "difficulty",
                    "container_addr",
                    "strategy_revision",
                )
            },
            "evidence_refs": packet["evidence_refs"][:20],
        }
        worker_packet["challenge"]["description"] = str(
            worker_packet["challenge"].get("description") or ""
        )[:1200]
        objective = (
            "Independently re-evaluate this challenge from a different direction. "
            "Do not assume the Solver's conclusions are correct and do not repeat "
            "listed requests. Prefer a different entry point, parameter source, or "
            "trust boundary. Do not reuse handles copied from another Agent; read "
            "the cited evidence and create only Worker-owned sessions. Return tested, "
            "evidence_refs, untested and next_steps "
            "within the time limit, even when nothing can be verified.\n\n"
            + json.dumps({"evidence_refs": worker_packet["evidence_refs"]}, ensure_ascii=False)
        )
        objective = objective[:3950]
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                challenge = await self._require_challenge(session, run_id, unique_code)
                solver = await session.get(AgentRecord, solver_id)
                if challenge.alternate_worker_id:
                    row = await session.get(AgentRecord, challenge.alternate_worker_id)
                    return self._agent_dict(row) if row is not None else None
                if (
                    solver is None
                    or solver.role != "solver"
                    or solver.unique_code != unique_code
                    or solver.status in {"completed", "failed", "stopped", "cancelled", "interrupted", "paused"}
                    or challenge.is_completed
                    or challenge.work_status != "active"
                    or challenge.stagnation_stage != "review_due"
                ):
                    return None
                worker_id = f"worker_{uuid4().hex}"
                worker_task = WorkerTaskInput(
                    objective=objective,
                    task_key=task_key,
                    success_criteria=[
                        "Return tested, evidence_refs, untested and next_steps",
                        "Use a materially different direction from the listed tests",
                    ],
                    context_refs=packet["evidence_refs"][:20],
                    timeout_seconds=timeout_seconds,
                )
                task = worker_task.model_dump(mode="python", exclude={"task_key"})
                record = AgentRecord(
                    agent_id=worker_id,
                    run_id=run_id,
                    role="worker",
                    parent_id=solver_id,
                    unique_code=unique_code,
                    task_key=task_key,
                    task_digest=payload_digest(task),
                    mission=objective,
                    initial_prompt=objective,
                    success_criteria=task["success_criteria"],
                    context_refs=task["context_refs"],
                    timeout_seconds=timeout_seconds,
                    status="queued",
                )
                session.add(record)
                session.add(
                    AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}",
                        run_id=run_id,
                        agent_id=worker_id,
                        unique_code=unique_code,
                        role="worker",
                        priority=40,
                        status="queued",
                    )
                )
                challenge.alternate_worker_id = worker_id
                challenge.stagnation_stage = "alternate_worker"
                challenge.last_intervention_at = self.clock()
                challenge.intervention_count += 1
                challenge.version += 1
                await self._event(
                    session,
                    run_id,
                    "agent_created",
                    {
                        "agent_id": worker_id,
                        "role": "worker",
                        "mode": "execute",
                        "parent_id": solver_id,
                        "unique_code": unique_code,
                        "task_key": task_key,
                    },
                    agent_id=worker_id,
                )
                worker_sequence = await self._event(
                    session,
                    run_id,
                    "solver_stagnation_worker_started",
                    {
                        "unique_code": unique_code,
                        "solver_id": solver_id,
                        "worker_id": worker_id,
                        "strategy_revision": challenge.strategy_revision,
                        "task_key": task_key,
                        "timeout_seconds": timeout_seconds,
                    },
                    agent_id=solver_id,
                )
        await self.signal_challenge_changes(run_id, [unique_code], worker_sequence)
        return self._agent_dict(record)
