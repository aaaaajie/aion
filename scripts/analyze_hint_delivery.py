"""Read-only hint delivery timing. Receipt is not evidence of hint adoption."""
from datetime import datetime
import json


def hint_delivery_metrics(connection, run_id):
    events = [
        {'sequence': seq, 'agent_id': agent, 'type': kind, 'payload': json.loads(payload), 'time': time}
        for seq, agent, kind, payload, time in connection.execute(
            'SELECT sequence,agent_id,event_type,payload,created_at FROM state_events '
            'WHERE run_id=? ORDER BY sequence', (run_id,)
        )
    ]
    prepared = {}
    responses = {}
    for event in events:
        payload = event['payload']
        if event['type'] == 'report_delivery_prepared':
            for report_id in payload['report_ids']:
                prepared.setdefault(report_id, event)
        if event['type'] == 'assistant_response':
            for delivery_id in payload.get('delivery_ids', []):
                responses.setdefault((event['agent_id'], delivery_id), event)
    results = []
    for report_id, code, recipient, seq, time in connection.execute(
        "SELECT report_id,unique_code,parent_id,sequence,created_at FROM reports "
        "WHERE run_id=? AND report_type='hint' AND parent_id IS NOT NULL ORDER BY sequence", (run_id,)
    ):
        batch = prepared.get(report_id)
        response = responses.get((recipient, batch['payload']['delivery_id'])) if batch else None
        def elapsed(event):
            return round((datetime.fromisoformat(event['time']) - datetime.fromisoformat(time)).total_seconds(), 3) if event else None
        results.append({
            'report_id': report_id, 'unique_code': code, 'recipient': recipient,
            'hint_sequence': seq, 'prepared_sequence': batch['sequence'] if batch else None,
            'response_sequence': response['sequence'] if response else None,
            'seconds_to_prepared': elapsed(batch), 'seconds_to_response': elapsed(response),
            'model_responses_before_delivery': sum(1 for e in events if e['agent_id'] == recipient and e['type'] == 'assistant_response' and e['sequence'] > seq and (not response or e['sequence'] < response['sequence'])),
            'first_related_validation_sequence': None,
            'adoption_review': 'Human review required; delivery or the next tool call does not prove adoption.',
        })
    return results
