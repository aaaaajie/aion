"""Event-backed bounded progress checks; execution activity is not progress."""

from sqlalchemy import select

from agent.experiment_records import digest, observation
from agent.execution_facts import execution_fact, EXECUTION_TOOLS, TASK_TOOLS, HTTP_TASK_TOOLS
from .clock import aware
from .errors import StateError
from .models import StateEventRecord
from .solver_review import _review_receipt_is_valid


class ProgressAdoptionState:
    async def recover_progress_checks(self, run_id, agent_id):
        async with self.db.sessions() as session:
            rows = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type.in_({"solver_progress_check_started", "solver_progress_check_finished"}),
            ).order_by(StateEventRecord.sequence))).all()
        pending = {}
        for row in rows:
            key = row.payload["check_key"]
            if row.event_type == "solver_progress_check_started":
                pending[key] = row.payload
            else:
                pending.pop(key, None)
        for p in pending.values():
            await self.append_agent_event(run_id, agent_id, "solver_progress_check_finished", {
                "check_key": p["check_key"], "scope": p["scope"], "status": "interrupted",
                "reason": "session_restarted", "requests": 0})

    async def begin_progress_check(self, run_id, context, *, interval_seconds, rotate_after_seconds):
        state = await self.solver_review_state(run_id, context.agent_id)
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(session, context, run_id=run_id, roles={"solver"})
                run = await self._require_run(session, run_id)
                challenge = await self._require_challenge(session, run_id, agent.unique_code)
                now = aware(self.clock())
                if run.status != "active" or agent.status != "running" or challenge.is_completed or challenge.work_status != "active" or not challenge.last_progress_at:
                    return None
                stalled = (now - aware(challenge.last_progress_at)).total_seconds()
                if not interval_seconds <= stalled < rotate_after_seconds or challenge.stagnation_stage == "rotation_due":
                    return None
                scope = {"generation": agent.resource_generation, "strategy_revision": challenge.strategy_revision}
                rows = (await session.scalars(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                    StateEventRecord.event_type.in_({"tool_result", "tool_result_delivery_confirmed", "solver_progress_check_started", "solver_review_record"}),
                ).order_by(StateEventRecord.sequence))).all()
                checks = [r for r in rows if r.event_type == "solver_progress_check_started"]
                if checks and (now - aware(checks[-1].created_at)).total_seconds() < interval_seconds:
                    return None
                attempted = {s for r in checks if r.payload["scope"] == scope for s in r.payload["result_sequences"]}
                handled = set(state["revoked_sequences"])
                for row in rows:
                    if row.event_type == "solver_review_record":
                        review = row.payload["review"]
                        handled.update(review["covered_sequences"])
                        handled.update((review.get("validation") or {}).get("conclusion_sequences", []))
                delivered = {s for r in rows if r.event_type == "tool_result_delivery_confirmed" and r.payload.get("scope") == scope
                             for s in r.payload["result_sequences"]}
                previous_windows = [r.payload for r in checks if r.payload["scope"] == scope]
                if previous_windows and max(delivered, default=0) <= max(p["through_sequence"] for p in previous_windows):
                    return None
                receipts = []
                for row in rows:
                    if row.event_type != "tool_result" or row.sequence not in delivered - attempted - handled:
                        continue
                    p = row.payload
                    fact = p.get("execution_fact") or execution_fact(p.get("tool_name"), p.get("result"))
                    if p.get("tool_name") not in EXECUTION_TOOLS | TASK_TOOLS | HTTP_TASK_TOOLS or not fact or p.get("replayed") or (p.get("result") or {}).get("ok") is False:
                        continue
                    try:
                        _review_receipt_is_valid(row, state["execution"])
                    except StateError:
                        continue
                    data = (p.get("result") or {}).get("data") or {}
                    receipts.append({"sequence": row.sequence, "tool": p.get("tool_name"),
                        "result": observation(p.get("result")),
                        "evidence_refs": data.get("evidence_refs", []) if isinstance(data, dict) else []})
                if not receipts:
                    return None
                receipts = receipts[-20:]
                sequences = [r["sequence"] for r in receipts]
                payload = {"check_key": digest([run_id, agent.agent_id, scope, sequences]), "scope": scope,
                    "result_sequences": sequences, "receipts": receipts,
                    "through_sequence": max(delivered),
                    "max_requests": 2, "timeout_seconds": min(20, rotate_after_seconds - stalled,
                                                                (aware(run.deadline_at) - now).total_seconds())}
                if payload["timeout_seconds"] <= 0:
                    return None
                await self._event(session, run_id, "solver_progress_check_started", payload, agent_id=agent.agent_id)
                return payload
