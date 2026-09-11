"""Persist an isolated Solver observation map in the existing event journal."""

from __future__ import annotations

from sqlalchemy import select, text, func

from agent.observation_models import ObservationMap, without_revoked
from .clock import aware
from .errors import StateConflict, StatePermission
from .models import StateEventRecord
from .observer_corrections import ObserverCorrectionState, latest_correction

TRACE_EVENTS = frozenset({"assistant_response", "tool_call", "tool_result", "solver_review_record", "shell_task_started", "shell_task_finished", "agent_resources_invalidated"})
TRACE_PAGE_SIZE = 80


class SolverObservationState(ObserverCorrectionState):
    async def solver_observation_state(self, run_id, context):
        async with self.db.sessions() as session:
            agent = await self._authorize(
                session, context, run_id=run_id, roles={"solver"}
            )
            run = await self._require_run(session, run_id)
            snapshot = await self._observation_event(
                session, run_id, agent.agent_id, "solver_observation_snapshot"
            )
            attempt = await self._observation_event(
                session, run_id, agent.agent_id, "solver_observation_started"
            )
            review = await self.solver_review_state(run_id, agent.agent_id)
            correction = await latest_correction(session, run_id, agent.agent_id)
            if correction and (correction['status'] != 'open'
                or correction['generation'] != agent.resource_generation
                or set(correction['original_sources'] + correction['sources']) & set(review['revoked_sequences'])):
                correction = None
            current_generation = snapshot is not None and snapshot.payload['generation'] == agent.resource_generation
            cursor = snapshot.payload["through_sequence"] if snapshot else 0
            backlog = await session.scalar(select(func.count()).select_from(StateEventRecord).where(
                StateEventRecord.run_id == run_id,
                StateEventRecord.agent_id == agent.agent_id,
                StateEventRecord.sequence > cursor,
                StateEventRecord.event_type.in_(TRACE_EVENTS),
            ))
            return {
                "map_coverage": snapshot.payload.get("map_coverage") if current_generation else None,
                "coverage": snapshot.payload.get("coverage") if snapshot else None,
                "backlog_events": backlog,
                "correction": correction,
                "revision": snapshot.sequence if snapshot else 0,
                "cursor": snapshot.payload["through_sequence"] if snapshot else 0,
                "map": (
                    without_revoked(snapshot.payload["map"], review["revoked_sequences"])
                    if current_generation
                    else ObservationMap().model_dump()
                ),
                "last_attempt_at": (
                    aware(attempt.created_at).isoformat() if attempt else None
                ),
                "generation": agent.resource_generation,
                "active": run.status == "active"
                and agent.status in {"running", "waiting"}
                and aware(self.clock()) < aware(run.deadline_at),
                "deadline_at": aware(run.deadline_at).isoformat(),
            }

    async def solver_observation_evidence(self, run_id, context, snapshot):
        """Original premises and latest feedback, separate from fresh coverage."""
        async with self.db.sessions() as session:
            await self._authorize(session, context, run_id=run_id, roles={'solver'})
            invalidation = await self._observation_event(session, run_id, context.agent_id, 'agent_resources_invalidated')
            generation_start = invalidation.sequence if invalidation else 0
            refs = ObservationMap.model_validate(snapshot['map']).source_ids()
            correction = snapshot.get('correction')
            if correction:
                refs.update(correction['sources'] + correction['original_sources'])
            recent = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.agent_id == context.agent_id,
                StateEventRecord.event_type == 'solver_review_record', StateEventRecord.sequence > generation_start,
            ).order_by(StateEventRecord.sequence.desc()).limit(3))).all()
            refs.update(row.sequence for row in recent)
            rows = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.agent_id == context.agent_id,
                StateEventRecord.sequence.in_(refs), StateEventRecord.event_type.in_(TRACE_EVENTS),
                StateEventRecord.sequence > generation_start,
            ).order_by(StateEventRecord.sequence))).all()
            return [{'sequence': r.sequence, 'event_type': r.event_type, 'payload': r.payload} for r in rows]

    async def solver_observation_trace(self, run_id, context, *, after_sequence):
        async with self.db.sessions() as session:
            agent = await self._authorize(
                session, context, run_id=run_id, roles={"solver"}
            )
            rows = (
                await session.scalars(
                    select(StateEventRecord)
                    .where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.sequence > after_sequence,
                        StateEventRecord.event_type.in_(TRACE_EVENTS),
                    )
                    .order_by(StateEventRecord.sequence.desc())
                    .limit(TRACE_PAGE_SIZE)
                )
            ).all()
            return [
                {
                    "sequence": row.sequence,
                    "event_type": row.event_type,
                    "payload": row.payload,
                }
                for row in reversed(rows)
            ]

    async def save_solver_observation(
        self,
        run_id,
        context,
        *,
        generation,
        expected_revision,
        through_sequence,
        observation,
        error=None,
        diagnostics=None,
        observed_sequences=None,
        evidence_sequences=(),
    ):
        candidate = (
            ObservationMap.model_validate({k: v for k, v in observation.items() if k != 'correction'})
            if observation is not None
            else None
        )
        async with self._lock:
            # Recheck revocations while holding the write lock: a review may
            # have arrived during the non-blocking model call.
            review = await self.solver_review_state(run_id, context.agent_id)
            if candidate is not None:
                candidate = ObservationMap.model_validate(
                    without_revoked(candidate.model_dump(), review["revoked_sequences"])
                )
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                agent = await self._authorize(
                    session, context, run_id=run_id, roles={"solver"}
                )
                run = await self._require_run(session, run_id)
                if (
                    agent.resource_generation != generation
                    or agent.status not in {"running", "waiting"}
                    or run.status != "active"
                    or aware(self.clock()) >= aware(run.deadline_at)
                ):
                    raise StateConflict(
                        "observation_session_expired",
                        "Solver observation belongs to an inactive session",
                    )
                previous = await self._observation_event(
                    session, run_id, agent.agent_id, "solver_observation_snapshot"
                )
                if (previous.sequence if previous else 0) != expected_revision:
                    raise StateConflict(
                        "observation_revision_conflict",
                        "A newer observation is already durable",
                    )
                cursor = previous.payload["through_sequence"] if previous else 0
                old_map = (
                    ObservationMap.model_validate(without_revoked(previous.payload["map"], review["revoked_sequences"]))
                    if previous and previous.payload['generation'] == agent.resource_generation
                    else ObservationMap()
                )
                if through_sequence <= cursor:
                    raise StateConflict(
                        "observation_cursor_conflict",
                        "Observation must consume new trace",
                    )
                sources = set(
                    (
                        await session.scalars(
                            select(StateEventRecord.sequence).where(
                                StateEventRecord.run_id == run_id,
                                StateEventRecord.agent_id == agent.agent_id,
                                StateEventRecord.sequence > cursor,
                                StateEventRecord.sequence <= through_sequence,
                                StateEventRecord.event_type.in_(TRACE_EVENTS),
                            )
                        )
                    ).all()
                )
                if through_sequence not in sources:
                    raise StatePermission(
                        "observation_source_invalid",
                        "Observation cursor must reference this Solver's trace",
                    )
                observed = sources if observed_sequences is None else set(observed_sequences)
                evidence = set((await session.scalars(select(StateEventRecord.sequence).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                    StateEventRecord.sequence.in_(evidence_sequences), StateEventRecord.event_type.in_(TRACE_EVENTS),
                ))).all())
                if evidence != set(evidence_sequences) or len(evidence) > 40:
                    raise StatePermission('observation_source_invalid', 'Invalid supporting evidence')
                if not observed <= sources:
                    raise StatePermission("observation_source_invalid", "Observed window must reference this Solver's trace")
                if observed and observed != {s for s in sources if s >= min(observed)}:
                    raise StatePermission("observation_source_invalid", "Observed window must be a continuous suffix")
                if candidate and not candidate.source_ids() <= observed | evidence | old_map.source_ids():
                    raise StatePermission("observation_source_invalid", "Map sources must belong to the actual observed window")
                proposal = observation.get('correction') if observation else None
                invalidation = await self._observation_event(session, run_id, agent.agent_id, 'agent_resources_invalidated')
                if proposal and invalidation and min(proposal['sources']) <= invalidation.sequence:
                    raise StatePermission('correction_source_stale', 'Correction cannot reuse a previous resource generation')
                if proposal and not set(proposal['sources']) <= observed | evidence | old_map.source_ids():
                    raise StatePermission('observation_source_invalid', 'Correction must cite observed evidence')
                skipped = sources - observed
                skipped_only = (diagnostics or {}).get("outcome") == "skipped"
                previous_coverage = previous.payload.get("coverage") if previous else {}
                previous_failure_streak = int(
                    previous_coverage.get("failure_streak") or 0
                ) if isinstance(previous_coverage, dict) else 0
                failure_streak = (
                    0
                    if candidate is not None or skipped_only
                    else previous_failure_streak + 1
                )
                map_coverage = previous.payload.get("map_coverage") if previous else None
                if candidate is not None:
                    through_event = await session.scalar(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.sequence == through_sequence,
                    ))
                    map_coverage = {
                        "from_sequence": min(observed) if observed else None,
                        "through_sequence": through_sequence,
                        "through_at": aware(through_event.created_at).isoformat(),
                    }
                    diagnostics = {
                        **(diagnostics or {}),
                        "outcome": "empty" if not any(candidate.model_dump().values())
                        else "unchanged" if candidate == old_map else "updated",
                    }
                sequence = await self._event(
                    session,
                    run_id,
                    "solver_observation_snapshot",
                    {
                        "through_sequence": through_sequence,
                        "generation": generation,
                        "map_coverage": map_coverage,
                        "map": (
                            candidate if candidate is not None else old_map
                        ).model_dump(),
                        "status": (
                            ("unchanged" if candidate == old_map else "updated")
                            if candidate is not None
                            else "skipped" if skipped_only else "failed"
                        ),
                        "error": error,
                        "correction": proposal,
                        "evidence_sequences": sorted(evidence),
                        "diagnostics": diagnostics,
                        "coverage": {
                            "after_sequence": cursor,
                            "through_sequence": through_sequence,
                            "status": "skipped" if skipped_only else "failed" if candidate is None else "processed",
                            "failure_streak": failure_streak,
                            "observed_from_sequence": min(observed) if observed else None,
                            "observed_count": len(observed),
                            "skipped": {"after_sequence": cursor, "through_sequence": max(skipped), "count": len(skipped)} if skipped else None,
                        },
                    },
                    agent_id=agent.agent_id,
                )

                if candidate is not None:
                    await self._save_observer_correction(session, run_id, agent, proposal, sequence, review)
                return sequence

    @staticmethod
    async def _observation_event(session, run_id, agent_id, event_type):
        return await session.scalar(
            select(StateEventRecord)
            .where(
                StateEventRecord.run_id == run_id,
                StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type == event_type,
            )
            .order_by(StateEventRecord.sequence.desc())
            .limit(1)
        )
