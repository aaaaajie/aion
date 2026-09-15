"""Evidence-scoped reviews projected from the event journal."""

from typing import Any

from sqlalchemy import select, text

from agent.execution_facts import (
    project_execution,
    execution_fact,
    TASK_TOOLS,
)
from agent.state.errors import StatePermission
from agent.state.models import ChallengeRecord, StateEventRecord, EvidenceRecord


REVIEW_EXECUTION_EVENTS = frozenset(
    {
        "tool_result",
        "shell_task_finished",
        "network_task_status_changed",
        "http_interaction_status_changed",
    }
)


def _native_receipt_is_valid(
    row: StateEventRecord, execution: dict[str, Any]
) -> bool:
    """Validate a durable task completion without inventing model output."""

    payload = row.payload or {}
    status = payload.get("status") or payload.get("execution_status")
    if status != "completed" or payload.get("timed_out") or payload.get("truncated"):
        return False
    if payload.get("output_incomplete") or payload.get("outcome_unknown"):
        return False
    execution_tasks = execution.get("completed_tasks") or execution.get("tasks", [])
    task_id = payload.get("task_id")
    interaction_id = payload.get("interaction_id")
    if task_id is not None:
        task = next(
            (item for item in execution_tasks if item.get("task_id") == task_id),
            None,
        )
        if task is None or task.get("output_read") is not True:
            return False
    elif interaction_id is not None:
        task = next(
            (
                item
                for item in execution_tasks
                if item.get("interaction_id") == interaction_id
            ),
            None,
        )
        if task is None or task.get("output_read") is not True:
            return False
    else:
        return False
    if row.event_type == "shell_task_finished":
        return payload.get("exit_code") in (None, 0)
    if row.event_type == "network_task_status_changed":
        return payload.get("error_code") in (None, "")
    if row.event_type == "http_interaction_status_changed":
        return payload.get("analysis_status") not in {"failed", "timeout"}
    return False


def _review_receipt_is_valid(row: StateEventRecord, execution: dict[str, Any]) -> None:
    if row.event_type == "tool_result":
        if row.payload.get("replayed"):
            raise StatePermission(
                "review_result_invalid",
                "Validated conclusions need fresh, current tool-result sequences",
            )
        validate_execution(row, execution)
        return
    if not _native_receipt_is_valid(row, execution):
        raise StatePermission(
            "review_execution_inconclusive",
            "Incomplete execution cannot be validated",
        )


def project_reviews(rows, *, revoked_sequences=()):
    revoked = set(revoked_sequences)
    for row in rows:
        revoked.update(row["payload"]["review"]["revoked_sequences"])
    # Revoked sources invalidate dependent reviews and their conclusions transitively.
    changed = True
    while changed:
        expanded = set(revoked)
        for row in rows:
            validation = row["payload"]["review"]["validation"] or {}
            conclusions = validation.get("conclusion_sequences", [])
            dependencies = conclusions + validation.get("calibration_sequences", []) + row["payload"].get("control_sequences", [])
            if row["sequence"] in revoked or set(dependencies) & revoked:
                expanded.add(row["sequence"])
                expanded.update(conclusions)
        changed = expanded != revoked
        revoked = expanded
    hypotheses, seen_results = {}, {}
    for row in rows:
        record = row["payload"]["review"]
        key = record["hypothesis_id"]
        previous = hypotheses.get(key, {})
        count, pending = previous.get("stagnation_count", 0), previous.get("pending_since")
        validation = record["validation"]
        sources = set(validation["conclusion_sequences"] if validation else record["covered_sequences"]) - revoked
        seen = seen_results.setdefault(key, set())
        is_revoked = row["sequence"] in revoked
        if is_revoked:
            count, pending = 0, None
        elif sources - seen:
            if record["assessment"] == "new_information":
                count, pending = 0, None
            else:
                # Uncertain attempts can stall without proving a negative conclusion.
                count += 1
                if count >= 2 and pending is None:
                    pending = row["sequence"]
        if not is_revoked:
            seen.update(sources)
        hypotheses[key] = {
            "sequence": row["sequence"], "review": record, "revoked": is_revoked,
            "stagnation_count": count, "pending_since": pending,
        }
    acquired_capabilities: list[dict] = []
    seen_capabilities: set[tuple[str, str, str]] = set()
    for row in rows:
        if row["sequence"] in revoked:
            continue
        record = row["payload"]["review"]
        if record.get("assessment") != "new_information" or not record.get("validation"):
            continue
        validation = record["validation"] or {}
        for capability in record.get("acquired_capabilities", []):
            if not isinstance(capability, dict):
                continue
            key = (
                str(capability.get("kind") or ""),
                str(capability.get("target_environment") or ""),
                str(capability.get("scope") or ""),
            )
            if not all(key) or key in seen_capabilities:
                continue
            seen_capabilities.add(key)
            acquired_capabilities.append({
                **capability,
                "review_sequence": row["sequence"],
                "validation_sequences": list(validation.get("conclusion_sequences", [])),
            })
    return {
        "hypotheses": hypotheses,
        "revoked_sequences": sorted(revoked),
        "acquired_capabilities": acquired_capabilities,
    }


def validate_execution(result, execution):
    output = result.payload.get("result")
    if (isinstance(output, dict) and output.get("ok") is False
        and (output.get("error") or {}).get("stage") in {
            "parse", "schema", "semantic", "permission", "conflict",
        }):
        raise StatePermission("review_result_invalid", "Rejected tool calls cannot validate conclusions or calibration")
    fact = result.payload.get("execution_fact") or execution_fact(
        result.payload.get("tool_name"), output)
    if not fact:
        return
    incomplete = {"running", "queued", "failed", "timeout", "stopped", "interrupted", "cancelled"}
    invalid = (fact.get("outcome_unknown") or fact.get("complete") is False
               or fact.get("timed_out") or fact.get("output_incomplete") or fact.get("truncated")
               or fact.get("status") in incomplete or fact.get("execution_status") in incomplete)
    delivery = fact.get("delivery")
    if delivery:
        invalid |= delivery["result_ref"] in execution["unread_result_refs"]
    if fact.get("interaction_id"):
        interaction = fact["interaction_id"]
        if fact.get("body_read"):
            body = fact["body_read"]
            read = any(item["interaction_id"] == interaction
                       and item["request_id"] == body["request_id"]
                       and item["body_sha256"] == body["body_sha256"] and item["complete"]
                       for item in execution["body_reads"])
        else:
            read = any(item["interaction_id"] == interaction and item["output_read"]
                       for item in execution["http_reads"])
        invalid |= not read
        invalid |= any(item.get("interaction_id") == interaction and item.get("status") in incomplete
                       for item in execution["tasks"])
    elif result.payload.get("tool_name") in TASK_TOOLS:
        if fact.get("network_read"):
            invalid |= not any(item.get("task_id") == fact.get("task_id") and item.get("output_read") for item in execution.get("completed_tasks", []))
        else:
            invalid |= not fact.get("output_read")
        invalid |= any(fact.get("task_id") and item.get("task_id") == fact.get("task_id") and not item.get("output_read")
                       for item in execution["tasks"])
    if invalid:
        raise StatePermission("review_execution_inconclusive", "Incomplete execution cannot be validated")


class SolverReviewState:
    async def activity_reminder(self, run_id, agent_id):
        from .activity import activity_reminder
        from .models import AgentRecord
        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise StatePermission("agent_not_found", "Agent was not found")
            rows = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type.in_({"solver_review_record", "solver_flag_accepted", "assistant_response",
                    "tool_result", "shell_task_finished", "network_task_status_changed", "http_interaction_status_changed"})
            ).order_by(StateEventRecord.sequence))).all()
            return activity_reminder([{"sequence": row.sequence, "event_type": row.event_type,
                "payload": row.payload, "created_at": row.created_at} for row in rows], agent.created_at, self.clock())

    async def pending_execution_completions(self, run_id, agent_id):
        from .completion_delivery import pending_completions

        async with self.db.sessions() as session:
            return await pending_completions(session, run_id, agent_id)

    async def solver_review_state(self, run_id, agent_id):
        async with self.db.sessions() as session:
            rows = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id,
                StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type.in_({"solver_review_record", "tool_result", "report_context", "shell_task_started", "shell_task_finished", "agent_resources_invalidated", "http_interaction_status_changed", "network_task_status_changed"}),
            ).order_by(StateEventRecord.sequence))).all()
            events = [{"sequence": row.sequence, "event_type": row.event_type, "payload": row.payload} for row in rows]
            reviews = [row for row in events if row["event_type"] == "solver_review_record"]
            invalidations = [row["sequence"] for row in events if row["event_type"] == "agent_resources_invalidated"]
            state = project_reviews(reviews)
            if invalidations:
                stale = [row["sequence"] for row in reviews if row["sequence"] < max(invalidations)
                         and row["payload"]["review"]["environment_dependent"]]
                state = project_reviews(reviews, revoked_sequences=stale)
                state["revalidation_required"] = stale
            covered = {seq for row in reviews for seq in row["payload"]["review"]["covered_sequences"]}
            covered.update(seq for row in reviews
                           for seq in (row["payload"]["review"]["validation"] or {}).get("conclusion_sequences", []))
            state["execution"] = project_execution(events, covered)
            state["execution"]["invalidated_at_sequence"] = max(invalidations, default=0)
            return state

    async def record_solver_review(self, run_id, context, review):
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                agent = await self._authorize(session, context, run_id=run_id, roles={"solver"})
                challenge = await session.get(
                    ChallengeRecord, (run_id, agent.unique_code)
                )
                if challenge is None:
                    raise StatePermission("challenge_not_found", "Solver challenge was not found")
                if review.strategy_revision != challenge.strategy_revision:
                    raise StatePermission(
                        "stale_strategy_revision",
                        "Review belongs to an expired Solver strategy revision",
                    )
                validation = review.validation
                conclusions = validation.conclusion_sequences if validation else []
                calibration_sequences = validation.calibration_sequences if validation else []
                refs = set(conclusions + review.revoked_sequences + review.covered_sequences + calibration_sequences)
                if refs:
                    available = set((await session.scalars(select(StateEventRecord.sequence).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.sequence.in_(refs),
                        StateEventRecord.event_type.in_({"tool_result", "assistant_response", "solver_review_record", "report_context", "shell_task_finished", "agent_resources_invalidated", "http_interaction_status_changed", "network_task_status_changed"}),
                    ))).all())
                    if refs != available:
                        raise StatePermission("review_source_invalid", "Review sources must belong to this Solver")
                control_sequences = []
                if validation:
                    await self._validate_context_refs(session, run_id, agent.unique_code, validation.control_evidence_refs)
                    state = await self.solver_review_state(run_id, agent.agent_id)
                    # Include this review's withdrawals when checking its own dependencies.
                    prior = (await session.scalars(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.event_type == "solver_review_record",
                    ).order_by(StateEventRecord.sequence))).all()
                    revoked = set(project_reviews([
                        {"sequence": row.sequence, "payload": row.payload} for row in prior
                    ], revoked_sequences=state["revoked_sequences"] + review.revoked_sequences)["revoked_sequences"])
                    if set(calibration_sequences) & revoked:
                        raise StatePermission("review_calibration_invalid", "Calibration must be validated, current and owned by this Solver")
                    calibrations = {row.sequence: row.payload["review"] for row in prior}
                    if any(seq not in calibrations or calibrations[seq]["assessment"] == "inconclusive"
                           or not calibrations[seq]["validation"] for seq in calibration_sequences):
                        raise StatePermission("review_calibration_invalid", "Calibration must be validated, current and owned by this Solver")
                    results = (await session.scalars(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.sequence.in_(conclusions),
                        StateEventRecord.event_type.in_(REVIEW_EXECUTION_EVENTS),
                    ))).all()
                    if (len(results) != len(set(conclusions)) or set(conclusions) & revoked
                        or (review.environment_dependent and any(row.sequence < state["execution"]["invalidated_at_sequence"] for row in results))):
                        raise StatePermission("review_result_invalid", "Validated conclusions need fresh, current execution sequences")
                    for result in results:
                        _review_receipt_is_valid(result, state["execution"])
                    receipts = (await session.scalars(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.event_type == "tool_result",
                    ).order_by(StateEventRecord.sequence))).all()
                    for ref in validation.control_evidence_refs:
                        from agent.experiment_records import execution_keys
                        evidence_row = await session.get(EvidenceRecord, ref.removeprefix("evidence:"))
                        execution_key = None
                        if (evidence_row is not None and evidence_row.agent_id == agent.agent_id
                            and evidence_row.evidence_type == "experiment"
                            and evidence_row.metadata_json.get("resource_generation") == agent.resource_generation):
                            execution_key = evidence_row.metadata_json.get("execution_key")
                        matches = []
                        for receipt in receipts:
                            output = receipt.payload.get("result")
                            if not isinstance(output, dict):
                                continue
                            data = output.get("data")
                            evidence_refs = output.get("evidence_refs", [])
                            if isinstance(data, dict):
                                evidence_refs = evidence_refs + data.get("evidence_refs", [])
                            if ref in evidence_refs or (execution_key and execution_key in execution_keys(agent.agent_id, output)):
                                matches.append(receipt)
                        if not matches:
                            raise StatePermission("review_control_invalid", "Control needs an owned execution receipt")
                        receipt = matches[-1] if execution_key else matches[0]
                        fact = receipt.payload.get("execution_fact") or execution_fact(
                            receipt.payload.get("tool_name"), receipt.payload.get("result"))
                        if (receipt.sequence in revoked or receipt.payload.get("replayed")
                            or receipt.sequence < state["execution"]["invalidated_at_sequence"]
                            or not fact or fact.get("status") == "failed"
                            or fact.get("exit_code") not in (None, 0)
                            or receipt.payload.get("result", {}).get("ok") is False
                            or not (fact.get("execution") or fact.get("task_id") or fact.get("interaction_id"))):
                            raise StatePermission("review_control_invalid", "Control must be current, executed and not revoked")
                        validate_execution(receipt, state["execution"])
                        control_sequences.append(receipt.sequence)
                if review.observation_revision is not None:
                    snapshot = await session.scalar(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.sequence == review.observation_revision,
                        StateEventRecord.event_type == "solver_observation_snapshot"))
                    if snapshot is None:
                        raise StatePermission("review_observation_invalid", "Assessment must reference an owned observation snapshot")
                    if (snapshot.payload.get("generation") != agent.resource_generation
                        or snapshot.payload.get("strategy_revision") != challenge.strategy_revision):
                        raise StatePermission("review_observation_stale", "Observation belongs to an expired execution scope")
                prior = (await session.scalars(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.agent_id == agent.agent_id,
                    StateEventRecord.event_type == "solver_review_record",
                ).order_by(StateEventRecord.sequence))).all()
                prior_refs = {
                    int(value)
                    for row in prior
                    if row.payload["review"].get("assessment") == "new_information"
                    for value in (row.payload["review"].get("validation") or {}).get("conclusion_sequences", [])
                }
                sequence = await self._event(session, run_id, "solver_review_record", {
                    "review": review.model_dump(), "control_sequences": control_sequences,
                }, agent_id=agent.agent_id)
                eligible_refs = set(conclusions) - (revoked if validation else set())
                if (
                    review.assessment == "new_information"
                    and validation is not None
                    and bool(eligible_refs - prior_refs)
                    and not challenge.is_completed
                ):
                    self._mark_progress(challenge)
                    await self._event(
                        session,
                        run_id,
                        "challenge_progress_recorded",
                        {
                            "unique_code": agent.unique_code,
                            "progress_kinds": ["solver_review_new_information"],
                            "evidence_sequences": sorted(eligible_refs - prior_refs),
                            "strategy_revision": challenge.strategy_revision,
                        },
                        agent_id=agent.agent_id,
                    )
        await self.signal_challenge_changes(run_id, [agent.unique_code], sequence)
        return sequence
