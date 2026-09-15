"""Read-only task projections from durable resource records, not UI event windows."""
import json
from pathlib import Path

TABLES = {"shell": ("shell_tasks", "task_id"), "http": ("http_interactions", "interaction_id"),
          "network": ("network_tasks", "task_id")}


def task_summaries(connection, run_id):
    starts = {}
    finishes = {}
    for row in connection.execute("SELECT payload FROM state_events WHERE run_id=? AND event_type='shell_task_finished' ORDER BY sequence", (run_id,)):
        data = json.loads(row['payload']); finishes[data['task_id']] = data.get('cleanup', {})
    for row in connection.execute("SELECT payload FROM state_events WHERE run_id=? AND event_type='shell_task_started' ORDER BY sequence", (run_id,)):
        data = json.loads(row['payload']); starts[data['task_id']] = data
    owners = {row['agent_id']: row['unique_code'] for row in connection.execute(
        'SELECT agent_id,unique_code FROM agents WHERE run_id=?', (run_id,))}
    tasks = []
    for kind, (table, key) in TABLES.items():
        for row in connection.execute(f'SELECT * FROM {table} WHERE run_id=?', (run_id,)):
            row = dict(row); task_id = row[key]; meta = starts.get(task_id, {}) if kind == 'shell' else {}
            if kind == 'shell' and not meta.get('background'):
                continue
            tasks.append({'key': f'{kind}:{task_id}', 'kind': kind, 'task_id': task_id,
                'agent_id': row['agent_id'], 'unique_code': owners.get(row['agent_id']),
                'name': meta.get('name') or row.get('scan_intent') or row.get('kind') or task_id,
                'launch_mode': 'background' if kind == 'shell' else 'execution',
                'status': row.get('execution_status', row['status']),
                'analysis_status': row.get('analysis_status'), 'exit_code': row.get('exit_code'),
                'error_code': row.get('error_code'), 'timeout': meta.get('timeout'),
                'resource_limits': meta.get('resource_limits', {}),
                'termination_reason': finishes.get(task_id, {}).get('termination_reason') if kind == 'shell' else None,
                'resource_usage': finishes.get(task_id, {}).get('resource_usage', {}) if kind == 'shell' else {},
                'http_summary': finishes.get(task_id, {}).get('http_summary') if kind == 'shell' else None,
                'started_at': row.get('started_at') or row.get('created_at'),
                'finished_at': row.get('execution_finished_at', row.get('finished_at')),
                'analysis_finished_at': row.get('analysis_finished_at'),
                'output_cleaned_at': row.get('output_cleaned_at'), 'truncated': row.get('truncated', False),
                'completed_count': row.get('completed_requests', row.get('tasks_completed')),
                'total_count': row.get('estimated_requests') if kind == 'http' else row.get('tasks_total')})
    return tasks


def task_detail(connection, run_id, kind, task_id, workspace_root, *, offset=0, limit=10000):
    if kind not in TABLES:
        raise LookupError('task_not_found')
    task = next((t for t in task_summaries(connection, run_id) if t['kind'] == kind and t['task_id'] == task_id), None)
    if task is None:
        raise LookupError('task_not_found')
    table, key = TABLES[kind]
    row = dict(connection.execute(f'SELECT * FROM {table} WHERE run_id=? AND {key}=?', (run_id, task_id)).fetchone())
    events = [dict(r) for r in connection.execute("""SELECT sequence,event_type,payload,created_at FROM state_events
        WHERE run_id=? AND agent_id=? AND
        (json_extract(payload,'$.task_id')=? OR json_extract(payload,'$.interaction_id')=?)
        ORDER BY sequence DESC LIMIT 10""", (run_id, row['agent_id'], task_id, task_id))]
    for event in events:
        event['payload'] = json.loads(event['payload'])
    offset = max(0, offset); limit = max(1, min(limit, 10000))
    result = {'task': task, 'events': events[::-1], 'output_available': False,
              'output': '', 'offset': offset, 'next_offset': None, 'eof': True}
    # Resolve the original invocation through its persisted execution identity.
    # Polling and result reads must never replace the command with a read call.
    identity = 'interaction_id' if kind == 'http' else 'task_id'
    invocation = connection.execute(f"""SELECT call.payload FROM state_events result
        JOIN state_events call ON call.run_id=result.run_id AND call.agent_id=result.agent_id
          AND call.event_type='tool_call'
          AND json_extract(call.payload,'$.tool_call_id')=json_extract(result.payload,'$.tool_call_id')
        WHERE result.run_id=? AND result.agent_id=? AND result.event_type='tool_result'
          AND json_extract(result.payload,'$.execution_fact.execution')=1
          AND json_extract(result.payload,'$.execution_fact.{identity}')=?
        ORDER BY result.sequence,call.sequence LIMIT 1""", (run_id, row['agent_id'], task_id)).fetchone()
    result['invocation'] = None
    if invocation:
        payload = json.loads(invocation['payload'])
        result['invocation'] = {'tool': payload.get('tool_name'), 'arguments': payload.get('arguments', {})}
    result['cwd'] = row.get('cwd')
    if workspace_root is None or row.get('output_cleaned_at'):
        return result
    root = Path(workspace_root).resolve()
    path = (root / row['output_path' if kind == 'shell' else 'result_path']).resolve()
    if kind == 'http':
        path = path / 'results.jsonl'
    try:
        path.resolve().relative_to(root)
        with path.open(encoding='utf-8', errors='replace') as stream:
            remaining = offset
            while remaining:
                skipped = stream.read(min(remaining, 65536))
                if not skipped:
                    break
                remaining -= len(skipped)
            content = stream.read(limit + 1)
    except (OSError, ValueError):
        return result
    result.update(output_available=True, output=content[:limit], eof=len(content) <= limit,
                  next_offset=offset+limit if len(content) > limit else None)
    return result
