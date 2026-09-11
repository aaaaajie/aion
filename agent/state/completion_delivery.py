"""Durable completion delivery, independent of output reads and experiment reviews."""
from sqlalchemy import select

from .models import StateEventRecord, ShellTaskRecord, NetworkTaskRecord, HttpInteractionRecord

TERMINAL = frozenset({"completed", "failed", "timeout", "stopped", "interrupted", "cancelled"})
COMPLETION_EVENTS = frozenset({"shell_task_finished", "network_task_status_changed", "http_interaction_status_changed"})


async def pending_completions(session, run_id, agent_id, *, limit=20):
    rows = (await session.scalars(select(StateEventRecord).where(
        StateEventRecord.run_id == run_id,
        StateEventRecord.agent_id == agent_id,
        StateEventRecord.event_type.in_(COMPLETION_EVENTS | {"assistant_response", "shell_task_started"}),
    ).order_by(StateEventRecord.sequence))).all()
    starts = {r.payload["task_id"]: r.payload for r in rows if r.event_type == "shell_task_started"}
    finishes = {r.payload["task_id"]: r.payload for r in rows if r.event_type == "shell_task_finished"}
    acknowledged = set()
    completions = {}
    analysis_statuses = {}
    for row in rows:
        payload = row.payload or {}
        if row.event_type == "assistant_response":
            acknowledged.update(payload.get("completion_sequences", []))
            continue
        if row.event_type == "http_interaction_status_changed":
            interaction_id = payload["interaction_id"]
            analysis_status = payload.get("analysis_status")
            if analysis_status is not None:
                previous = analysis_statuses.get(interaction_id)
                analysis_statuses[interaction_id] = analysis_status
                if analysis_status in TERMINAL and previous not in TERMINAL:
                    completions[("http_analysis", row.sequence)] = {
                        "sequence": row.sequence, "event_type": row.event_type,
                        "interaction_id": interaction_id, "phase": "analysis", "status": analysis_status,
                    }
        if row.event_type == "shell_task_started":
            continue
        status = payload.get("execution_status", payload.get("status"))
        if status not in TERMINAL:
            continue
        identity_key = "interaction_id" if row.event_type == "http_interaction_status_changed" else "task_id"
        identity = (row.event_type, payload[identity_key])
        completions.setdefault(identity, {
            "sequence": row.sequence, "event_type": row.event_type,
            identity_key: payload[identity_key], "status": status,
        })
    # One event may finish execution and analysis together. Deliver it atomically.
    pending = {}
    for item in completions.values():
        sequence = item["sequence"]
        if sequence in acknowledged:
            continue
        if sequence in pending:
            item = {**item, "analysis_status": pending[sequence]["status"],
                    "phase": "execution_and_analysis"}
        pending[sequence] = item
    result = sorted(pending.values(), key=lambda item: item["sequence"])[:limit]
    for item in result:
        if item['event_type'] == 'shell_task_finished':
            task_id = item['task_id']; meta = starts.get(task_id, {})
            row = await session.get(ShellTaskRecord, task_id)
            item.update(resource_limits=meta.get('resource_limits', {}),
                        termination_reason=finishes.get(task_id, {}).get('cleanup', {}).get('termination_reason'),
                        name=meta.get('name') or task_id,
                        exit_code=row.exit_code if row else None,
                        read_result={'tool': 'system_task_output', 'arguments': {'task_id': task_id}})
        elif item['event_type'] == 'network_task_status_changed':
            row = await session.get(NetworkTaskRecord, item['task_id'])
            item.update(name=row.scan_intent if row else item['task_id'],
                        exit_code=row.exit_code if row else None,
                        read_result={'tool': 'system_network_output', 'arguments': {'task_id': item['task_id']}})
        else:
            row = await session.get(HttpInteractionRecord, item['interaction_id'])
            item.update(name=row.kind if row else item['interaction_id'],
                        read_result={'tool': 'system_http_output', 'arguments': {'interaction_id': item['interaction_id']}})
    return result
