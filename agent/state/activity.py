"""Nonblocking activity reminders, independent of voluntary experiment reviews."""
from datetime import datetime, timezone
from agent.execution_facts import execution_fact, TERMINAL


def aware(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def activity_reminder(rows, started_at, now):
    boundary_time, boundary_sequence = aware(started_at), 0
    completed = []
    seen = set()
    for row in rows:
        payload = row['payload']; kind = row['event_type']; sequence = row['sequence']
        progress = kind == 'solver_flag_accepted' or (
            kind == 'solver_review_record' and payload['review']['assessment'] == 'new_information')
        acknowledged = kind == 'assistant_response' and bool(payload.get('activity_reminder'))
        if progress or acknowledged:
            boundary_time, boundary_sequence = aware(row['created_at']), sequence
            completed = []
        identity = None
        if kind in {'shell_task_finished', 'network_task_status_changed'} and payload.get('status') in TERMINAL:
            identity = ('task', payload['task_id'])
        elif kind == 'http_interaction_status_changed' and payload.get('execution_status') in TERMINAL:
            identity = ('http', payload['interaction_id'])
        elif kind == 'tool_result' and not payload.get('replayed'):
            fact = payload.get('execution_fact') or execution_fact(payload.get('tool_name'), payload.get('result'))
            if fact and fact.get('execution') and fact.get('status', fact.get('execution_status')) not in {'queued', 'running', 'waiting'}:
                if fact.get('task_id'):
                    identity = ('task', fact['task_id'])
                elif fact.get('interaction_id'):
                    identity = ('http', fact['interaction_id'])
                else:
                    identity = ('call', payload.get('tool_call_id', sequence))
        if identity is not None and identity not in seen:
            seen.add(identity)
            if sequence > boundary_sequence:
                completed.append(sequence)
    seconds = (aware(now) - boundary_time).total_seconds()
    if seconds < 300 or len(completed) < 12:
        return None
    return {'since_sequence': boundary_sequence, 'completed_count': len(completed),
            'elapsed_seconds': int(seconds), 'execution_through': completed[-1]}
