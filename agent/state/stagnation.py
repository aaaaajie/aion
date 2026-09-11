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
from .models import AdmissionRecord, AgentRecord, ChallengeRecord, EvidenceRecord
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
                await self._require_run(session, run_id)
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
                    elif (
                        challenge.stagnation_stage == "alternate_worker"
                        and elapsed >= policy.rotate_after_seconds
                    ):
                        challenge.stagnation_stage = "rotation_due"
                        challenge.last_intervention_at = now
                        challenge.intervention_count += 1
                        challenge.version += 1
                        await self._event(
                            session,
                            run_id,
                            "solver_stagnation_rotation_requested",
                            {**common, "threshold_seconds": policy.rotate_after_seconds},
                            agent_id=solver.agent_id,
                        )
                        actions.append(
                            {
                                "kind": "rotate",
                                **common,
                                "challenge_version": challenge.version,
                            }
                        )
                    elif (
                        challenge.stagnation_stage == "review_due"
                        and elapsed >= policy.rotate_after_seconds
                    ):
                        challenge.stagnation_stage = "rotation_due"
                        challenge.last_intervention_at = now
                        challenge.intervention_count += 1
                        challenge.version += 1
                        await self._event(
                            session,
                            run_id,
                            "solver_stagnation_rotation_requested",
                            {**common, "threshold_seconds": policy.rotate_after_seconds},
                            agent_id=solver.agent_id,
                        )
                        actions.append(
                            {
                                "kind": "rotate",
                                **common,
                                "challenge_version": challenge.version,
                            }
                        )
                    elif challenge.stagnation_stage == "rotation_due":
                        # The durable marker is intentionally retryable: a
                        # process may stop after recording the request and
                        # before cleanup/release completes.
                        actions.append(
                            {
                                "kind": "rotate",
                                **common,
                                "challenge_version": challenge.version,
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
            rows = (
                await session.scalars(
                    select(EvidenceRecord)
                    .where(
                        EvidenceRecord.run_id == run_id,
                        EvidenceRecord.unique_code == unique_code,
                    )
                    .order_by(EvidenceRecord.created_at.desc())
                    .limit(30)
                )
            ).all()
        solver = await self._find_solver_for_challenge(run_id, unique_code)
        review_state = (
            await self.solver_review_state(run_id, solver["agent_id"])
            if solver
            else {"hypotheses": {}, "revoked_sequences": []}
        )
        directions = []
        for hypothesis_id, value in review_state.get("hypotheses", {}).items():
            review = value.get("review", {})
            directions.append(
                {
                    "hypothesis_id": hypothesis_id,
                    "status": review.get("direction_status", "open"),
                    "assessment": review.get("assessment"),
                    "summary": str(review.get("summary") or "")[:600],
                    "next_test": str(review.get("next_test") or "")[:400],
                    "strategy_revision": review.get("strategy_revision", 1),
                    "revoked": value.get("revoked", False),
                }
            )
        return {
            "challenge": challenge,
            "strategy_revision": challenge["strategy_revision"],
            "evidence_refs": [f"evidence:{row.evidence_id}" for row in rows],
            "directions": directions[-12:],
            "weakly_rejected": [
                item["hypothesis_id"] for item in directions
                if item["status"] == "weakly_rejected" and not item["revoked"]
            ],
            "dead": [
                item["hypothesis_id"] for item in directions
                if item["status"] == "dead" and not item["revoked"]
            ],
            "facts": [
                "Only cited evidence and completed task results are authoritative.",
                "A weakly rejected direction may be rechecked with a changed assumption.",
                "A dead direction requires new evidence before it may be reopened.",
            ],
        }

    async def reset_strategy_for_resume(
        self, run_id: str, unique_code: str, solver_id: str
    ) -> dict[str, Any]:
        """Resume a paused challenge with the same Solver identity and revision."""

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
                challenge.strategy_revision += 1
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
                    },
                    agent_id=solver_id,
                )
        await self.signal_challenge_changes(run_id, [unique_code], sequence)
        return self._challenge_dict(challenge)

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
            "directions": packet["directions"][-4:],
            "evidence_refs": packet["evidence_refs"][:20],
        }
        worker_packet["challenge"]["description"] = str(
            worker_packet["challenge"].get("description") or ""
        )[:1200]
        objective = (
            "Independently re-evaluate this challenge from a different direction. "
            "Do not assume the Solver's conclusions are correct and do not repeat "
            "listed requests. Prefer a different entry point, parameter source, or "
            "trust boundary. Return tested, evidence_refs, untested and next_steps "
            "within the time limit, even when nothing can be verified.\n\n"
            + json.dumps(worker_packet, ensure_ascii=False, default=str)
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
