"""Durable reports reach the next model boundary without an observe call."""
import json

import httpx
import pytest
from pydantic import BaseModel

from agent.config import AgentSettings
from agent.memory.context import build_runtime_messages
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.state.errors import StateError, StatePermission
from agent.tooling import ToolRegistry, ToolSpec
from tests.solver_state import build_state


class Empty(BaseModel):
    pass


async def hint(service, recipient='solver'):
    payload = {'type': 'hint_received', 'unique_code': 'a', 'hint': 'Inspect the export workflow', 'reason': 'blocked prerequisite'}
    await service.publish_challenge_report('run', sender_id='chief', unique_code='a', report_type='hint', status='received', payload=payload)
    return await service.publish_control_report('run', sender_id='chief', recipient_id=recipient, unique_code='a', report_type='hint', status='received', payload=payload)


def settings():
    return AgentSettings(llm_base_url='https://model.test', llm_model='test', llm_api_key='test')


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['solver', 'chief'])
async def test_hint_arriving_during_tool_reaches_next_model_call(tmp_path, role):
    service, chief, solver = await build_state(tmp_path)
    requests = []
    async def finish(_):
        await hint(service, role)
        return {'ok': True, 'data': {'finished': True}}
    class Provider:
        def tool_specs(self):
            return [ToolSpec('fixture_finish', 'Finish work', Empty, finish, lambda _: ())]
    async def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            message = {'content': '', 'tool_calls': [{'id': 'one', 'type': 'function', 'function': {'name': 'fixture_finish', 'arguments': '{}'}}]}
        else:
            assert 'Inspect the export workflow' in json.dumps(body['messages'])
            runtime = await service.get_agent_runtime('run', role)
            assert runtime['agent']['pending_delivery']
            message = {'content': 'The export prerequisite is still blocked.'}
        return httpx.Response(200, json={'choices': [{'message': message, 'finish_reason': 'tool_calls' if len(requests) == 1 else 'stop'}]})
    store = await AgentStateStore.open(service, run_id='run', agent_id=role, run_dir=tmp_path / role)
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        runner = AgentRunner(settings(), ToolRegistry([Provider()]), role=role, agent_id=role, state_service=service, http_client=client)
        await runner.run_session('Complete the fixture', store=store)
        await runner.close()
    assert len(requests) == 2
    assert 'Inspect the export workflow' not in json.dumps(requests[0])
    assert not (await service.get_agent_runtime('run', role))['agent']['pending_delivery']
    events = await store.load_events()
    received = [e for e in events if e.event_type == 'report_context']
    ack = [e for e in events if e.event_type == 'report_delivery_acknowledged']
    assert len(received) == len(ack) == 1
    assert ack[0].payload['response_sequence'] > received[0].sequence
    import sqlite3
    from scripts.analyze_hint_delivery import hint_delivery_metrics
    with sqlite3.connect(tmp_path / 'state.sqlite3') as connection:
        metrics = hint_delivery_metrics(connection, 'run')
    assert metrics[0]['response_sequence'] == ack[0].payload['response_sequence']
    assert metrics[0]['model_responses_before_delivery'] == 0
    assert metrics[0]['first_related_validation_sequence'] is None
    await service.close()


@pytest.mark.asyncio
async def test_pending_report_survives_restart_and_context_rebuild(tmp_path):
    service, _, solver = await build_state(tmp_path)
    await hint(service)
    store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path / 'solver')
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    runner._unique_code = 'a'
    message = await runner._report_context(store)
    delivery_id = next(iter(runner._delivery_ids))
    assert message and await runner._report_context(store) is None
    # No persisted model response: a restart must redeliver the same batch.
    restored = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path / 'solver')
    restarted = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service)
    restarted._unique_code = 'a'
    assert await restarted._report_context(restored)
    assert restarted._delivery_ids == {delivery_id}
    messages = build_runtime_messages(base_system_prompt='Fixture', initial_user_message={'role': 'user', 'content': 'Continue'}, checkpoint=restored.model_checkpoint(), session_memory='', recent_messages=[], max_tokens=20000, recent_message_tokens=1000)
    assert 'Inspect the export workflow' in json.dumps(messages)
    assert len(restored.checkpoint.authoritative_view['hints']) == 1
    # Explicit observe shares the batch, and is not acknowledged by unrelated output.
    observed = await service.observe_solver('run', 'a', solver)
    assert observed['delivery_id'] == delivery_id
    event = await restored.append_event('assistant_response', {'delivery_ids': [delivery_id]})
    await service.acknowledge_report_delivery('run', 'solver', delivery_id, event.sequence)
    restarted._delivery_ids.clear()
    assert await restarted._report_context(restored) is None
    await runner.close()
    await restarted.close()
    await service.close()


@pytest.mark.asyncio
async def test_explicit_observe_is_not_automatically_duplicated(tmp_path):
    service, _, solver = await build_state(tmp_path)
    await hint(service)
    observed = await service.observe_solver('run', 'a', solver)
    store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path / 'solver')
    runner = AgentRunner(settings(), ToolRegistry([]), role='solver', state_service=service, delivery_ids=[observed['delivery_id']])
    runner._unique_code = 'a'
    assert await runner._report_context(store, visible_messages=[{'role': 'user', 'content': json.dumps(observed)}]) is None
    # If compression drops the explicit observation, protect the pending batch.
    assert await runner._report_context(store, visible_messages=[])
    assert len(store.checkpoint.authoritative_view['hints']) == 1
    await runner.close()
    await service.close()


@pytest.mark.asyncio
async def test_evidence_format_and_access_are_different_failures(tmp_path):
    service, _, solver = await build_state(tmp_path)
    evidence = await service.persist_evidence('run', solver, evidence_type='text', source='fixture', content='readable output')
    ref = evidence['evidence_ref']
    assert (await service.read_evidence('run', solver, ref))['content'] == 'readable output'
    for bad in [ref.removeprefix('evidence:'), 'evidence:evidence_' + 'z' * 32]:
        with pytest.raises(StateError) as caught:
            await service.read_evidence('run', solver, bad)
        assert caught.value.code == 'invalid_evidence_ref'
        assert caught.value.status_code == 422
    with pytest.raises(StatePermission) as caught:
        await service.read_evidence('run', solver, 'evidence:evidence_' + '0' * 32)
    assert caught.value.code == 'evidence_not_accessible'
    await service.close()


@pytest.mark.asyncio
async def test_rejected_model_response_is_redelivered_on_same_runner(tmp_path):
    from agent.runner import AgentRunnerError
    service, _, _ = await build_state(tmp_path)
    await hint(service)
    calls = []
    async def respond(request):
        calls.append(json.loads(request.content))
        assert 'Inspect the export workflow' in json.dumps(calls[-1])
        return httpx.Response(200, json={'choices': [{'finish_reason': 'length' if len(calls) == 1 else 'stop', 'message': {'content': 'blocked'}}]})
    store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=tmp_path / 'solver')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        runner = AgentRunner(settings(), ToolRegistry([]), role='solver', agent_id='solver', state_service=service, http_client=client)
        with pytest.raises(AgentRunnerError):
            await runner.run_session('Fixture', store=store)
        pending = (await service.get_agent_runtime('run', 'solver'))['agent']['pending_delivery']
        assert pending
        await runner.run_session('Fixture', store=store, resume=True)
        assert not (await service.get_agent_runtime('run', 'solver'))['agent']['pending_delivery']
        await runner.close()
    assert len(calls) == 2
    await service.close()
