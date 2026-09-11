"""One durable, evidence-backed observer concern per Solver; never controls tools."""
from copy import deepcopy
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select

from agent.execution_facts import execution_fact
from agent.observation_models import Correction
from .clock import aware
from .errors import StatePermission
from .models import StateEventRecord, AgentRecord, ReportRecord
from .solver_review import validate_execution

CORRECTION_EVENTS = {
    'observer_correction_created', 'observer_correction_delivered',
    'observer_correction_checked', 'observer_correction_resolved',
    'observer_correction_revoked', 'observer_correction_escalated',
}


async def latest_correction(session, run_id, agent_id):
    event = await session.scalar(select(StateEventRecord).where(
        StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent_id,
        StateEventRecord.event_type.in_(CORRECTION_EVENTS),
    ).order_by(StateEventRecord.sequence.desc()).limit(1))
    return deepcopy(event.payload['correction']) if event else None


class ObserverCorrectionState:
    async def _correction_event(self, session, run_id, agent_id, kind, state):
        return await self._event(session, run_id, 'observer_correction_' + kind,
                                 {'correction': state}, agent_id=agent_id)

    async def maintain_observer_correction(self, run_id, context):
        """Acknowledge persisted delivery, revoke stale premises and report once atomically."""
        notification = None
        async with self._lock:
            review = await self.solver_review_state(run_id, context.agent_id)
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(session, context, run_id=run_id, roles={'solver'})
                run = await self._require_run(session, run_id)
                state = await latest_correction(session, run_id, agent.agent_id)
                if not state or state['status'] != 'open':
                    return
                if (state['generation'] != agent.resource_generation
                    or set(state['sources']) & set(review['revoked_sequences'])
                    or set(state['original_sources']) & set(review['revoked_sequences'])
                    or agent.status not in {'running', 'waiting'} or run.status != 'active'
                    or aware(self.clock()) >= aware(run.deadline_at)):
                    state['status'] = 'revoked'
                    await self._correction_event(session, run_id, agent.agent_id, 'revoked', state)
                    return
                if not state['delivered_at']:
                    responses = (await session.scalars(select(StateEventRecord).where(
                        StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.event_type == 'assistant_response',
                        StateEventRecord.sequence > state['created_sequence'],
                    ).order_by(StateEventRecord.sequence))).all()
                    delivered = next((r for r in responses if r.payload.get('observation_correction_id') == state['id']), None)
                    if delivered:
                        state['delivered_at'] = aware(delivered.created_at).isoformat()
                        state['delivery_sequence'] = delivered.sequence
                        await self._correction_event(session, run_id, agent.agent_id, 'delivered', state)
                if (state['assessment'] == 'open' and state['delivered_at'] and state['persistent_checks'] >= 2
                    and not state['escalated']
                    and (aware(self.clock()) - aware(datetime.fromisoformat(state['delivered_at']))).total_seconds() >= 300):
                    parent = await session.get(AgentRecord, agent.parent_id) if agent.parent_id else None
                    if parent is None or parent.run_id != run_id or parent.role != 'chief':
                        return
                    sequence = await self._next_sequence(session, run_id)
                    report_id = 'observer_' + state['id']
                    session.add(ReportRecord(
                        report_id=report_id, run_id=run_id, sequence=sequence,
                        agent_id=agent.agent_id, parent_id=parent.agent_id,
                        unique_code=agent.unique_code, report_type='observer_correction', status='attention',
                        payload={'summary': state['claim'], 'suggestion': state['suggestion'],
                                 'correction_id': state['id'], 'sources': state['sources'],
                                 'category': state['category'], 'original_sources': state['original_sources'],
                                 'delivered_at': state['delivered_at'], 'persistent_checks': state['persistent_checks'],
                                 'message': 'Observer concern persisted across fresh execution evidence; no task was paused.'},
                    ))
                    await self._event_with_sequence(session, run_id, sequence, 'control_report_created',
                        {'report_id': report_id, 'report_type': 'observer_correction'}, agent_id=agent.agent_id)
                    state['escalated'] = True
                    await self._correction_event(session, run_id, agent.agent_id, 'escalated', state)
                    notification = (parent.agent_id, sequence)
        if notification:
            await self.notifier.notify(self.agent_signal_key(run_id, notification[0]), notification[1])

    async def _save_observer_correction(self, session, run_id, agent, proposal, snapshot_sequence, review):
        if proposal is None:
            return
        proposal = Correction.model_validate(proposal).model_dump()
        state = await latest_correction(session, run_id, agent.agent_id)
        if state and (state['generation'] != agent.resource_generation
                      or set(state['original_sources'] + state['sources']) & set(review['revoked_sequences'])):
            if state['status'] == 'open':
                state['status'] = 'revoked'
                await self._correction_event(session, run_id, agent.agent_id, 'revoked', state)
            state = None
        if set(proposal['sources']) & set(review['revoked_sequences']):
            raise StatePermission('correction_source_revoked', 'Correction cannot reuse revoked evidence')
        # Only genuinely new, completed executions count as follow-up evidence.
        rows = (await session.scalars(select(StateEventRecord).where(
            StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
            StateEventRecord.sequence.in_(proposal['sources']),
        ))).all()
        execution_sequences = []
        for row in rows:
            if row.event_type != 'tool_result' or row.payload.get('replayed'):
                continue
            result = row.payload.get('result')
            fact = row.payload.get('execution_fact') or execution_fact(row.payload.get('tool_name'), result)
            if not fact or fact.get('status', fact.get('execution_status')) != 'completed':
                continue
            if not fact.get('execution') and row.payload.get('tool_name') != 'system_task_output':
                continue
            if not isinstance(result, dict) or result.get('ok') is False:
                continue
            if fact.get('exit_code') not in (None, 0):
                continue
            try:
                validate_execution(row, review['execution'])
            except StatePermission:
                continue
            evidence_sequence = row.sequence
            if fact.get('task_id'):
                finishes = (await session.scalars(select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent.agent_id,
                    StateEventRecord.event_type == 'shell_task_finished',
                    StateEventRecord.sequence <= row.sequence,
                ).order_by(StateEventRecord.sequence.desc()))).all()
                finish = next((r for r in finishes if r.payload.get('task_id') == fact['task_id']), None)
                if finish is None or finish.payload.get('status') != 'completed':
                    continue
                # Re-reading the same task output is not another execution.
                evidence_sequence = finish.sequence
            execution_sequences.append(evidence_sequence)
        if not state or state['status'] != 'open':
            if proposal['assessment'] != 'open':
                return
            # Do not repeatedly reopen a closed concern using the same old evidence.
            if state and max(proposal['sources']) <= state['last_evidence_sequence']:
                return
            state = {**proposal, 'id': uuid4().hex, 'status': 'open',
                     'generation': agent.resource_generation, 'created_sequence': snapshot_sequence,
                     'original_sources': proposal['sources'], 'delivered_at': None,
                     'delivery_sequence': None, 'persistent_checks': 0, 'escalated': False,
                     'last_evidence_sequence': max(proposal['sources'])}
            await self._correction_event(session, run_id, agent.agent_id, 'created', state)
            return
        fresh = [s for s in execution_sequences if s > max(state['last_evidence_sequence'], state['delivery_sequence'] or state['created_sequence'])]
        if proposal['assessment'] in {'resolved', 'withdrawn'} and not fresh:
            raise StatePermission('correction_execution_required', 'Resolution requires new completed execution evidence, not an assertion or start receipt')
        if not fresh:
            return
        # The runtime owns identity and category until this concern is closed.
        # A differently worded/category proposal cannot reset its delivery clock.
        if proposal['category'] != state['category']:
            return
        state.update(claim=proposal['claim'], suggestion=proposal['suggestion'], sources=proposal['sources'],
                     assessment=proposal['assessment'], last_evidence_sequence=max(fresh))
        if proposal['assessment'] in {'resolved', 'withdrawn'}:
            state['status'] = 'resolved' if proposal['assessment'] == 'resolved' else 'revoked'
            kind = state['status']
        else:
            if proposal['assessment'] == 'open' and state['delivered_at']:
                state['persistent_checks'] += 1
            kind = 'checked'
        await self._correction_event(session, run_id, agent.agent_id, kind, state)
