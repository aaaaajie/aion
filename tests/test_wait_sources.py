import asyncio
import pytest
from tests.solver_state import build_state, worker


async def start_shell(service, owner='solver', task='task'):
    return await service.create_shell_task('run', owner, task_id=task, pid=1,
        process_started_at=1, cwd='.', temp_dir='tmp', output_path='out', capture_limit=100)


async def test_idle_wait_is_not_a_timer_and_chief_still_waits(tmp_path):
    service, _, _ = await build_state(tmp_path)
    try:
        result = await service.record_controller_wait('run', 'solver', 'wait for initialization')
        assert result['status'] == 'ready' and result['wait_entered'] is False
        assert result['code'] == 'no_wait_source'
        await start_shell(service, 'chief')
        assert (await service.record_controller_wait('run','solver',None))['code'] == 'no_wait_source'
        assert (await service.record_controller_wait('run','chief',None))['status'] == 'waiting'
    finally:
        await service.close()


@pytest.mark.parametrize('completion_first', [True, False])
async def test_completion_race_preserves_ready_or_pending_notification(tmp_path, completion_first):
    service, _, _ = await build_state(tmp_path)
    try:
        await start_shell(service)
        async def finish():
            await service.finish_shell_task('run','solver','task',status='completed',exit_code=0,
                output_chars=0,truncated=False,timed_out=False)
        if completion_first:
            await finish()
            assert (await service.record_controller_wait('run','solver',None))['completions_available']
        else:
            assert (await service.record_controller_wait('run','solver',None))['status']=='waiting'
            await finish()
            assert await service.pending_execution_completions('run','solver')
            assert (await service.record_controller_wait('run','solver',None))['status']=='ready'
    finally:
        await service.close()


async def test_worker_is_a_wait_source(tmp_path):
    service, _, solver = await build_state(tmp_path)
    try:
        await worker(service, solver)
        assert (await service.record_controller_wait('run','solver',None))['status']=='waiting'
    finally:
        await service.close()


async def test_pending_http_analysis_remains_a_source(tmp_path):
    from agent.state.models import HttpInteractionRecord
    service, _, _ = await build_state(tmp_path)
    try:
        async with service.db.sessions.begin() as session:
            session.add(HttpInteractionRecord(interaction_id='http',run_id='run',agent_id='solver',
                kind='request',result_path='http',estimated_requests=1,requested_concurrency=1,
                estimated_disk_bytes=0,estimated_memory_bytes=0,estimated_analysis_work=0,
                execution_status='completed',analysis_status='running'))
        assert (await service.record_controller_wait('run','solver',None))['status']=='waiting'
    finally:
        await service.close()
