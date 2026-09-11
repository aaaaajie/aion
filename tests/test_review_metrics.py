from agent.subagents.models import SolverReviewArguments
from scripts.analyze_run_performance import analyze_run
from tests.solver_state import build_state


async def test_metrics_distinguish_reminders_reviews_preflight_and_execution(tmp_path):
    service, _, solver = await build_state(tmp_path)
    async def event(kind, payload):
        return await service.append_agent_event('run', 'solver', kind, payload)
    try:
        source = await event('tool_result', {'tool_name': 'system_shell',
            'result': {'ok': True, 'data': {'status': 'completed', 'output': 'fixture'}}})
        await event('solver_review_delivered', {'automatic_review_recommended': True,
            'trigger_reasons': ['urgent_execution']})
        await event('solver_review_delivered', {'automatic_review_recommended': False,
            'trigger_reasons': ['task_snapshot_changed']})
        for _ in range(2):
            await service.record_solver_review('run', solver, SolverReviewArguments(
                hypothesis_id='fixture', covered_sequences=[source], assessment='inconclusive',
                summary='No calibration', next_test='Check a known fixture'))
        for name in ('solver_review', 'system_http_probe', 'system_http_plan'):
            await event('tool_result', {'tool_name': name, 'result': {'ok': False,
                'error': {'stage': 'schema', 'code': 'invalid_arguments'}}})
        await event('tool_result', {'tool_name': 'system_http_plan', 'round': 1,
            'result': {'ok': True, 'data': {'request_count': 2}}})
        await event('tool_result', {'tool_name': 'system_http_probe',
            'result': {'ok': False, 'error': {'stage': 'semantic', 'code': 'unknown_template_variable'}}})
        await service.finish_run('run', 'completed', report={'type': 'local_acceptance'})
        metrics = analyze_run(service.db.path, 'run')
        assert metrics['reviews'] == {'deliveries': 2, 'automatic_triggers': 1,
            'task_snapshot_deliveries': 1, 'successful_records': 2, 'rejected_calls': 1,
            'assessments': {'inconclusive': 2}, 'covered_result_count': 1}
        assert metrics['preflight'] == {'calls': 2, 'successes': 1, 'failures': 1}
        assert metrics['parameter_errors'] == {'solver_review': 1, 'system_http_probe': 2, 'system_http_plan': 1}
        assert metrics['http']['interaction_count'] == 0
        assert metrics['competition_flow']['first_useful_tool_round']['count'] == 0
        assert metrics['completion_reasons'] == {'local_acceptance': 1}
    finally:
        await service.close()
