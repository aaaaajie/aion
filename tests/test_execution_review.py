"""Regression scenarios for unreported work and observable execution state."""
import json

import pytest
from pydantic import ValidationError

from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.state.errors import StatePermission
from agent.tooling import ToolRegistry
from agent.observation import trace_batch
from agent.observation_input import observation_data
from tests.solver_state import build_state
from tests.test_report_delivery import settings
from tests.test_solver_review import record, evidence


async def append(service, kind, payload):
    return await service.append_agent_event('run', 'solver', kind, payload)


async def result(service, index, **data):
    return await append(service, 'tool_result', {'tool_name': 'system_shell',
        'tool_call_id': str(index), 'result': {'ok': True, 'data': data}})


async def test_only_urgent_execution_prompts_review_and_delivery_survives_restart(tmp_path):
    service, _, solver = await build_state(tmp_path)
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        for i in range(12):
            await result(service, i, status='completed')
            assert await runner._review_context(store) == (None, None)
        await append(service, 'shell_task_finished', {'task_id': 'timeout-task', 'status': 'timeout'})
        message, delivery = await runner._review_context(store)
        assert '"automatic_review_recommended": true' in message['content']
        assert 'urgent_execution' in delivery['trigger_reasons']
        assert (await runner._review_context(store))[1] == delivery
        await store.append_event('solver_review_delivered', delivery)
        await store.append_event('assistant_response', {'completion_sequences': delivery['completion_sequences']})
        restored = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        assert await runner._review_context(restored) == (None, None)
        for i in range(13, 25):
            await result(service, i, status='completed')
        assert await runner._review_context(restored) == (None, None)
    finally:
        await runner.close()
        await service.close()


@pytest.mark.parametrize('status', ['timeout', 'stopped', 'interrupted'])
async def test_native_terminal_without_poll_is_urgent_and_unread(tmp_path, status):
    service, _, solver = await build_state(tmp_path)
    try:
        await append(service, 'shell_task_started', {'task_id': 'task', 'status': 'running'})
        terminal = await append(service, 'shell_task_finished', {'task_id': 'task', 'status': status})
        for _ in range(8):
            await append(service, 'tool_result', {'tool_name': 'system_task_output',
                'result': {'data': {'task_id': 'task', 'status': status}}})
        execution = (await service.solver_review_state('run', 'solver'))['execution']
        assert execution['unreviewed_results'] == [terminal]
        assert execution['urgent_sequences'] == [terminal]
        assert not execution['tasks'][0]['output_read']
    finally:
        await service.close()


async def test_ps_cannot_end_other_task_and_running_is_not_valid(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        await append(service, 'shell_task_started', {'task_id': 'background', 'status': 'running'})
        source = await result(service, 1, task_id='background', status='running', output='partial')
        await result(service, 2, task_id='ps', status='completed', output='no process found')
        state = await service.solver_review_state('run', 'solver')
        assert state['execution']['tasks'][0]['status'] == 'running'
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(await evidence(service, solver), conclusion_sequences=[source]))
    finally:
        await service.close()


async def test_calibration_revocation_transitive_and_environment_change(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        first_result = await result(service, 1, status='completed', output='known fixture')
        calibration = await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[first_result]))
        second_result = await result(service, 2, status='completed', output='validated fixture')
        dependent = await service.record_solver_review('run', solver, record(ref,
            calibration_basis=None, calibration_sequences=[calibration], conclusion_sequences=[second_result]))
        await service.record_solver_review('run', solver, record(ref, revoked_sequences=[calibration], summary='Local fixture control failed'))
        state = await service.solver_review_state('run', 'solver')
        assert {calibration, first_result, dependent, second_result} <= set(state['revoked_sequences'])
        with pytest.raises(StatePermission):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[second_result], calibration_sequences=[calibration]))
        invalidation = await service.invalidate_agent_resources('run', 'solver', reason='fixture reset')
        state = await service.solver_review_state('run', 'solver')
        assert state['execution']['generation'] == invalidation
        assert state['execution']['urgent_sequences']
        assert calibration in state['revalidation_required']
    finally:
        await service.close()


def test_negative_control_cannot_claim_verified_experiment():
    with pytest.raises(ValidationError, match='calibration basis'):
        record('evidence:fixture', conclusion_sequences=[1], calibration_basis=None)


def test_field_first_input_preserves_tail_evidence_and_missing_call():
    data = {'cleanup': {'padding': 'x'*10000}, 'output': 'actual decisive output',
            'status': 'running', 'task_id': 'task'}
    projected = observation_data({'ok': True, 'data': data})
    assert projected['data']['output'] == 'actual decisive output'
    rows, _, _ = trace_batch([{'sequence': 9, 'event_type': 'tool_result',
        'payload': {'tool_name': 'system_shell', 'tool_call_id': 'missing', 'result': {'data': data}}}])
    assert rows[0]['call_context'] == {'missing': True}
    assert 'actual decisive output' in json.dumps(rows)
    assert len(json.dumps(rows)) < 2000


async def test_real_runner_continues_without_fixed_review_cadence(tmp_path):
    import asyncio
    from tests.test_solver_lifecycle import harness, completion
    reached = asyncio.Event()

    async def model(role, index, body):
        if index < 6:
            return completion('system_shell', {'command': 'printf fixture'})
        assert not any('"automatic_review_recommended": true' in str(message.get('content')) for message in body['messages'])
        reached.set()
        return completion('solver_wait')

    sup, service, _, _, chief = await harness(tmp_path, model, solver_observation=False)
    try:
        await sup.create_solver(chief, 'a')
        # Six real sandbox launches can exceed ten seconds on a busy host.
        # The assertion is uninterrupted execution, not launch throughput.
        await asyncio.wait_for(reached.wait(), 30)
    finally:
        await sup.close()
        await service.close()


async def test_covered_results_clear_reminder_without_claiming_validity(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        sources = [await result(service, i, status='completed') for i in range(6)]
        await service.record_solver_review('run', solver, record(await evidence(service, solver),
            summary='Conditions unknown', covered_sequences=sources))
        assert not (await service.solver_review_state('run', 'solver'))['execution']['unreviewed_results']
    finally:
        await service.close()


async def test_http_native_completion_counts_once_and_not_at_start(tmp_path):
    service, _, _ = await build_state(tmp_path)
    try:
        await append(service, 'http_interaction_status_changed', {'interaction_id': 'http', 'execution_status': 'running'})
        assert not (await service.solver_review_state('run', 'solver'))['execution']['unreviewed_results']
        terminal = await append(service, 'http_interaction_status_changed', {'interaction_id': 'http', 'execution_status': 'completed'})
        for i in range(8):
            await append(service, 'tool_result', {'tool_name': 'system_http_output', 'result': {
                'data': {'interaction_id': 'http', 'execution_status': 'completed', 'results': [{'status_code': 200}],
                         'cursor': 0, 'next_cursor': 100, 'page_end_cursor': 100, 'has_more': False,
                         'read_scope': {'default': True}, 'is_terminal': True}}})
        state = (await service.solver_review_state('run', 'solver'))['execution']
        assert state['unreviewed_results'] == [terminal]
        assert not state['tasks']
    finally:
        await service.close()


def test_default_observer_is_off(monkeypatch):
    from agent.config import AgentSettings
    monkeypatch.delenv('AION_SOLVER_OBSERVATION', raising=False)
    assert not AgentSettings(llm_api_key='fixture', llm_base_url='https://model.test', llm_model='fixture', _env_file=None).solver_observation


def test_large_nested_observation_does_not_starve_window():
    huge = {'results': [{'output': 'x'*20000, 'error': 'y'*20000,
                        'results': [{'output': 'z'*20000}]*10}]*10}
    rows, count, _ = trace_batch([{'sequence': 1, 'event_type': 'tool_result',
        'payload': {'tool_name': 'system_shell', 'result': huge}}])
    assert len(rows) == 1 and count == 1
    assert len(json.dumps(rows)) < 4000
    assert 'truncated' in json.dumps(rows)


async def test_reading_finished_task_clears_previous_running_context(tmp_path):
    service, _, _ = await build_state(tmp_path)
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    try:
        store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path/'solver')
        await append(service, 'shell_task_started', {'task_id': 'task', 'status': 'running'})
        _, delivery = await runner._review_context(store)
        await store.append_event('solver_review_delivered', delivery)
        assert await runner._review_context(store) == (None, None)
        await append(service, 'shell_task_finished', {'task_id': 'task', 'status': 'completed'})
        await result(service, 1, task_id='task', status='completed', output='done')
        message, delivery = await runner._review_context(store)
        assert '"tasks": []' in message['content']
        assert delivery['task_snapshot'] == '[]'
    finally:
        await runner.close()
        await service.close()


async def test_http_validation_requires_accumulated_default_pages(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        async def page(start, end, default=True):
            return await append(service, 'tool_result', {'tool_name': 'system_http_output', 'result': {'data': {
                'interaction_id': 'http', 'execution_status': 'completed', 'results': [],
                'cursor': start, 'next_cursor': end, 'page_end_cursor': 10,
                'has_more': end < 10, 'read_scope': {'default': default}, 'is_terminal': True}}})
        source = await page(5, 10)
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await page(0, 10, default=False)
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await page(0, 5)
        await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
    finally:
        await service.close()


async def test_http_body_validation_keeps_hash_and_request_coverage_separate(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        async def body(offset, count, digest='a', request='request'):
            return await append(service, 'tool_result', {'tool_name': 'system_http_response', 'result': {'data': {
                'interaction_id': 'http', 'execution_status': 'completed', 'request_id': request,
                'body_sha256': digest, 'offset_bytes': offset, 'bytes_returned': count,
                'body_bytes': 10, 'eof': offset + count == 10, 'content': 'x' * count}}})
        source = await body(5, 5)
        await body(0, 5, digest='b')
        await body(0, 5, request='other')
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await body(0, 5)
        await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
    finally:
        await service.close()


async def test_deferred_shell_validation_requires_every_result_page(tmp_path):
    from agent.execution_facts import execution_fact
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        output = {'data': {'task_id': 'task', 'status': 'completed', 'output': 'complete'}}
        fact = execution_fact('system_shell', output, result_ref='result:fixture', result_chars=10)
        assert fact['output_read']
        source = await append(service, 'tool_result', {'tool_name': 'system_shell', 'result': output, 'execution_fact': fact})
        async def read(offset, count):
            await append(service, 'tool_result', {'tool_name': 'tool_result_read', 'result': {'data': {
                'result_ref': 'result:fixture', 'offset': offset, 'next_offset': offset + count,
                'eof': offset + count == 10, 'original_chars': 10, 'content': 'x' * count}}})
        await read(5, 5)
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await read(0, 5)
        await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
    finally:
        await service.close()


async def test_deferred_result_without_task_requires_delivery(tmp_path):
    from agent.execution_facts import execution_fact
    service, _, solver = await build_state(tmp_path)
    try:
        ref = await evidence(service, solver)
        output = {'data': {'complete': True, 'status': 'completed', 'output': 'fixture'}}
        source = await append(service, 'tool_result', {'tool_name': 'system_fastcgi_request', 'result': output,
            'execution_fact': execution_fact('system_fastcgi_request', output, result_ref='result:fastcgi', result_chars=10)})
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await append(service, 'tool_result', {'tool_name': 'tool_result_read', 'result': {'data': {
            'result_ref': 'result:fastcgi', 'offset': 5, 'next_offset': 10,
            'original_chars': 10, 'eof': True, 'content': 'x' * 5}}})
        with pytest.raises(StatePermission, match='Incomplete execution'):
            await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
        await append(service, 'tool_result', {'tool_name': 'tool_result_read', 'result': {'data': {
            'result_ref': 'result:fastcgi', 'offset': 0, 'next_offset': 5,
            'original_chars': 10, 'eof': False, 'content': 'x' * 5}}})
        await service.record_solver_review('run', solver, record(ref, conclusion_sequences=[source]))
    finally:
        await service.close()
