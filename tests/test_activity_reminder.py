from datetime import datetime, timedelta, timezone
from agent.state.activity import activity_reminder

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(seq, kind, payload, seconds=None):
    return {'sequence': seq, 'event_type': kind, 'payload': payload,
            'created_at': START + timedelta(seconds=seq if seconds is None else seconds)}


def attempts(n=12):
    return [event(i, 'shell_task_finished', {'task_id': str(i), 'status': 'completed'}) for i in range(1, n+1)]


def test_activity_requires_both_elapsed_time_and_new_completions():
    assert activity_reminder(attempts(), START, START+timedelta(seconds=299)) is None
    assert activity_reminder(attempts(11), START, START+timedelta(minutes=20)) is None
    reminder = activity_reminder(attempts(), START, START+timedelta(minutes=5))
    assert reminder['completed_count'] == 12
    assert activity_reminder(attempts(), START, START+timedelta(minutes=5)) == reminder


def test_polling_replayed_results_and_analysis_do_not_increment_activity():
    rows = attempts(10)
    for i in range(11, 40):
        rows.append(event(i, 'tool_result', {'tool_name': 'system_task_output',
            'result': {'ok': True, 'data': {'task_id': '1', 'status': 'completed'}}}))
    rows += [event(40, 'http_interaction_status_changed', {'interaction_id': 'h', 'execution_status': 'completed'}),
             event(41, 'http_interaction_status_changed', {'interaction_id': 'h', 'execution_status': 'completed', 'analysis_status': 'completed'}),
             event(42, 'tool_result', {'tool_name': 'system_shell', 'replayed': True, 'result': {'ok': True, 'data': {'status': 'completed'}}})]
    assert activity_reminder(rows, START, START+timedelta(minutes=10)) is None


def test_only_progress_or_successful_response_ack_resets_window():
    rows = attempts()
    rows.append(event(13, 'solver_review_record', {'review': {'assessment': 'inconclusive'}}))
    assert activity_reminder(rows, START, START+timedelta(minutes=10))
    for kind, payload in [('solver_review_record', {'review': {'assessment': 'new_information'}}),
                          ('solver_flag_accepted', {}),
                          ('assistant_response', {'activity_reminder': {'execution_through': 12}})]:
        reset = rows + [event(14, kind, payload, 600)]
        assert activity_reminder(reset, START, START+timedelta(minutes=20)) is None
        new = reset + [event(i, 'shell_task_finished', {'task_id': str(i), 'status': 'completed'}, 610+i) for i in range(15,27)]
        assert activity_reminder(new, START, START+timedelta(seconds=899)) is None
        assert activity_reminder(new, START, START+timedelta(seconds=900))['completed_count'] == 12


async def test_reminder_delivery_ack_is_successful_response_only(tmp_path):
    from tests.solver_state import build_state
    from agent.runner import AgentRunner
    from agent.state import AgentStateStore
    from agent.tooling import ToolRegistry
    from tests.test_report_delivery import settings
    service, _, _ = await build_state(tmp_path)
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        for i in range(12):
            await service.append_agent_event('run', 'solver', 'tool_result', {
                'tool_name': 'system_shell', 'tool_call_id': str(i),
                'result': {'ok': True, 'data': {'status': 'completed'}}})
        service.clock = lambda: datetime.now(timezone.utc) + timedelta(minutes=6)
        message, delivery = await runner._review_context(store)
        assert delivery['activity_reminder']['completed_count'] == 12
        assert 'No review submission is required' in message['content']
        assert (await runner._review_context(store))[1] == delivery
        await store.append_event('assistant_response', {'activity_reminder': delivery['activity_reminder']})
        assert await service.activity_reminder('run', 'solver') is None
    finally:
        await runner.close()
        await service.close()
