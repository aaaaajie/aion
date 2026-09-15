"""Independent observation snapshots scoped to a strategy and resource generation."""

from sqlalchemy import select

from .clock import aware
from .errors import StateConflict, StatePermission
from .models import StateEventRecord, EvidenceRecord


class SolverObservationState:
    @staticmethod
    def observation_references(packet):
        # Only structured reference fields are sources, never quoted body text.
        refs = set(packet["evidence_refs"])
        for item in packet.get("experiments", []):
            refs.update(item[k] for k in ("evidence_ref", "same_input_previous_ref") if item.get(k))
        for batch in packet.get("batch_coverage", []):
            if batch.get("manifest_ref"):
                refs.add(batch["manifest_ref"])
            refs.update(batch.get("expansion_refs", []))
        return refs

    async def observation_input(self, run_id, unique_code):
        packet = await self.get_stagnation_packet(run_id, unique_code)
        refs = self.observation_references(packet)
        async with self.db.sessions() as session:
            await self._validate_context_refs(session, run_id, unique_code, sorted(refs))
            facts = set(await session.scalars(select(EvidenceRecord.evidence_id).where(
                EvidenceRecord.run_id == run_id, EvidenceRecord.unique_code == unique_code,
                EvidenceRecord.evidence_type == "experiment",
                EvidenceRecord.evidence_id.in_([r.removeprefix("evidence:") for r in refs]))))
        if facts != {r.removeprefix("evidence:") for r in refs}:
            raise StatePermission("observation_source_invalid", "Observer sources must be factual experiments")
        return {**packet, "evidence_refs": sorted(refs)}

    async def solver_observation_state(self, run_id, context):
        async with self.db.sessions() as session:
            agent = await self._authorize(session, context, run_id=run_id, roles={"solver"})
            run = await self._require_run(session, run_id)
            challenge = await self._require_challenge(session, run_id, agent.unique_code)
            previous = await self._observation_event(session, run_id, agent.agent_id, "solver_observation_snapshot")
            latest_fact = await session.scalar(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.event_type == "experiment_recorded",
                StateEventRecord.payload["unique_code"].as_string() == agent.unique_code,
            ).order_by(StateEventRecord.sequence.desc()).limit(1))
            same = previous is not None and previous.payload.get("strategy_revision") == challenge.strategy_revision and previous.payload.get("generation") == agent.resource_generation
            return {"revision": previous.sequence if same else 0,
                "cursor": previous.payload["through_sequence"] if same else 0,
                "through_sequence": latest_fact.sequence if latest_fact else 0,
                "strategy_revision": challenge.strategy_revision, "generation": agent.resource_generation,
                "unique_code": agent.unique_code,
                "advice": previous.payload.get("advice") if same else None,
                "updated_at": aware(previous.created_at).isoformat() if same else None,
                "active": run.status == "active" and agent.status in {"running", "waiting"} and not challenge.is_completed and aware(self.clock()) < aware(run.deadline_at),
                "deadline_at": aware(run.deadline_at).isoformat()}

    async def save_solver_observation(self, run_id, context, *, generation, strategy_revision,
                                      expected_revision, through_sequence, advice, evidence_refs, error=None):
        from agent.observation_models import validate_observation_output
        import json
        if advice is not None:
            advice = validate_observation_output(json.dumps(advice), evidence_refs)
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(session, context, run_id=run_id, roles={"solver"})
                challenge = await self._require_challenge(session, run_id, agent.unique_code)
                run = await self._require_run(session, run_id)
                if (agent.resource_generation != generation or challenge.strategy_revision != strategy_revision
                    or agent.status not in {"running", "waiting"} or challenge.is_completed or run.status != "active"
                    or aware(self.clock()) >= aware(run.deadline_at)):
                    raise StatePermission("observation_stale", "Observation belongs to an expired execution scope")
                previous = await self._observation_event(session, run_id, agent.agent_id, "solver_observation_snapshot")
                same = previous and previous.payload.get("strategy_revision") == strategy_revision and previous.payload.get("generation") == generation
                if (previous.sequence if same else 0) != expected_revision:
                    raise StateConflict("observation_revision_conflict", "A newer observation exists")
                await self._validate_context_refs(session, run_id, agent.unique_code, evidence_refs)
                ids = {ref.removeprefix("evidence:") for ref in evidence_refs}
                facts = (await session.scalars(select(EvidenceRecord.evidence_id).where(
                    EvidenceRecord.run_id == run_id, EvidenceRecord.unique_code == agent.unique_code,
                    EvidenceRecord.evidence_type == "experiment", EvidenceRecord.evidence_id.in_(ids)))).all()
                if set(facts) != ids:
                    raise StatePermission("observation_source_invalid", "Observer can cite only factual experiments")
                return await self._event(session, run_id, "solver_observation_snapshot", {
                    "strategy_revision": strategy_revision, "generation": generation,
                    "through_sequence": through_sequence, "advice": advice,
                    "evidence_refs": evidence_refs, "error": error,
                }, agent_id=agent.agent_id)

    @staticmethod
    async def _observation_event(session, run_id, agent_id, event_type):
        return await session.scalar(select(StateEventRecord).where(
            StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent_id,
            StateEventRecord.event_type == event_type,
        ).order_by(StateEventRecord.sequence.desc()).limit(1))
