"""Opt-in real-model acceptance against local fixtures, never a benchmark target."""
import json
import os
from pathlib import Path

import pytest

from agent.config import AgentSettings
from agent.model_usage import aggregate_usage
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.subagents.models import SolverReviewArguments
from agent.tooling import AccessClaim, ToolRegistry, ToolSpec
from tests.solver_state import build_state

pytestmark = [pytest.mark.live, pytest.mark.skipif(
    os.environ.get('AION_LIVE_TOOL_ACCEPTANCE') != '1', reason='real model acceptance is opt-in')]


def save_report(name, settings, events, assertions):
    root = Path(os.environ.get('AION_ACCEPTANCE_REPORT_DIR', '.aion/verification/tool-usability'))
    root.mkdir(parents=True, exist_ok=True)
    usage = aggregate_usage([{**e, 'agent_id': 'solver'} for e in events],
        [{'agent_id': 'solver', 'unique_code': 'a'}])
    report = {'model': settings.llm_model, 'assertions': assertions, 'token_usage': usage,
        'tools': [{'sequence': e['sequence'], 'tool_name': e['payload'].get('tool_name'),
                   'ok': e['payload'].get('result', {}).get('ok'),
                   'error_code': e['payload'].get('error_code')}
                  for e in events if e['event_type'] == 'tool_result']}
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    model_call = next((e['payload']['model_call_id'] for e in events if e['event_type'] == 'model_call_started'), 'no-model-call')
    (root / (name + '-' + model_call + '.json')).write_text(encoded)
    (root / (name + '.json')).write_text(encoded)


async def test_live_model_records_uncalibrated_review(tmp_path):
    settings = AgentSettings()
    service, _, solver = await build_state(tmp_path)
    sources = []
    for i in range(6):
        sources.append(await service.append_agent_event('run', 'solver', 'tool_result', {
            'tool_name': 'system_shell', 'tool_call_id': f'fixture-{i}',
            'result': {'ok': True, 'data': {'status': 'completed', 'output': f'local fixture {i}'}}}))

    class Reviews:
        def tool_specs(self):
            async def record(arguments):
                sequence = await service.record_solver_review('run', solver, arguments)
                return {'ok': True, 'data': {'review_sequence': sequence}}
            return [ToolSpec('solver_review', 'Record an evidence-scoped review of execution results.',
                SolverReviewArguments, record, lambda _: (AccessClaim('write', 'solver-review'),))]

    runner = AgentRunner(settings, ToolRegistry([Reviews()], compact=True), role='solver',
        agent_id='solver', parent_id='chief', state_service=service, run_root=tmp_path / 'runs',
        max_rounds=6, session_timeout_seconds=90,
        base_system_prompt='You are testing a local software tool interface. Discover its exact schema before calling it. Do not invent evidence or calibration.')
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path / 'runs/run')
        await runner.run_session(
            'Record one review covering the six execution results shown in the runtime reminder. '
            'They are fixture output, with no known calibration or validated application conclusion. '
            'State the uncertainty and the next check. Finish after the tool confirms the record.', store=store)
        state = await service.solver_review_state('run', 'solver')
        events = await service.list_agent_events('run', 'solver', limit=1000)
        records = [e for e in events if e['event_type'] == 'solver_review_record']
        assertions = {'one_review': len(records) == 1,
            'all_results_covered': not state['execution']['unreviewed_results'],
            'inconclusive': bool(records) and records[0]['payload']['review']['assessment'] == 'inconclusive'}
        save_report('live-review', settings, events, assertions)
        assert all(assertions.values()), assertions
        assert records[0]['payload']['review']['validation'] is None
    except Exception as exc:
        events = await service.list_agent_events('run', 'solver', limit=1000)
        save_report('live-review', settings, events, {
            'passed': False, 'error_type': type(exc).__name__,
            'http_status': getattr(exc, 'details', {}).get('http_status')})
        raise
    finally:
        await runner.close()
        await service.close()


async def test_live_model_preflights_corrects_and_reads_local_http(tmp_path):
    import httpx
    from tools.http import HttpInteractionEngine, HttpProbeManager, HttpTools
    from tools.http.manager import AgentHttpClient
    from tools.system.policy import WorkspacePolicy
    from agent.tooling import ToolResultStore, ToolResultTools
    from tests.resource_runtime import install_resource_runtime

    settings = AgentSettings()
    service, _, _ = await build_state(tmp_path)
    requests = []
    async def local_response(request):
        assert request.url.host == 'fixture.test'
        requests.append(request.url.path)
        return httpx.Response(200, json={'fixture': request.url.path, 'status': 'ok'})
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(policy, service, 'run', engine=HttpInteractionEngine(
        policy, transport=httpx.MockTransport(local_response)))
    await manager.initialize()
    install_resource_runtime(manager, service, 'run', root=tmp_path)
    run_dir = tmp_path / 'runs/run'
    registry = ToolRegistry([HttpTools(AgentHttpClient(manager, 'solver')),
        ToolResultTools(ToolResultStore(run_dir, 'solver'))], compact=True,
        allowed_tools={'system_http_plan', 'system_http_probe', 'system_http_output',
                       'system_http_response', 'tool_result_read'})
    runner = AgentRunner(settings, registry, role='solver', agent_id='solver', parent_id='chief',
        state_service=service, run_root=tmp_path / 'runs', max_rounds=10, session_timeout_seconds=180,
        base_system_prompt='You are verifying HTTP tool usability against an in-memory local fixture. '
        'Use the exact discovered tool schemas. Never fabricate a successful validation or read.')
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=run_dir)
        await runner.run_session(
            'First discover system_http_plan, then use it to preflight this draft exactly as written: '
            '{"tool_name":"system_http_probe","arguments":{"cases":[{"url":"http://fixture.test/{{path}}",'
            '"variables":{"path":["health","version"]}}]}}. '
            'If invalid, correct the draft using the returned schema/examples and preflight again. '
            'Only after a successful preflight result, execute the two requests once. '
            'Then read both full response bodies using their returned IDs. Finish with a short summary. '
            'Do not add any requests or repeat completed traffic.', store=store)
        events = await service.list_agent_events('run', 'solver', limit=1000)
        plans = [e for e in events if e['event_type'] == 'tool_result' and e['payload'].get('tool_name') == 'system_http_plan']
        successful = [e for e in plans if e['payload']['result'].get('ok')]
        interactions = [e for e in events if e['event_type'] == 'http_interaction_created']
        execution = (await service.solver_review_state('run', 'solver'))['execution']
        assertions = {'draft_rejected': any(not e['payload']['result'].get('ok') for e in plans),
            'corrected_plan': bool(successful), 'exactly_two_local_requests': sorted(requests) == ['/health', '/version'],
            'preflight_before_execution': bool(successful and interactions) and successful[0]['sequence'] < interactions[0]['sequence'],
            'both_bodies_read': sum(read['complete'] for read in execution['body_reads']) == 2,
            'no_unread_tasks': not execution['tasks']}
        save_report('live-http-plan', settings, events, assertions)
        assert all(assertions.values()), assertions
    except Exception as exc:
        events = await service.list_agent_events('run', 'solver', limit=1000)
        save_report('live-http-plan', settings, events, {'passed': False,
            'error_type': type(exc).__name__, 'http_status': getattr(exc, 'details', {}).get('http_status')})
        raise
    finally:
        await runner.close()
        await manager.finish_run()
        await service.close()
