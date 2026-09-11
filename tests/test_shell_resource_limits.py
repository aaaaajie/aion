import sys
import pytest
from tests.test_system_tools import make_tools
from tools.system import cgroups


async def test_pipefail_and_explicit_exit_semantics(make_tools):
    async with make_tools() as tools:
        failed = await tools.shell('bash -c "exit 124" | tail -1')
        assert failed['data']['status'] == 'failed'
        assert failed['data']['exit_code'] == 124
        assert failed['data']['termination_reason'] == 'command_failed'
        good = await tools.shell('printf ok | cat')
        assert good['data']['status'] == 'completed'
        overridden = await tools.shell('false; printf intentional')
        assert overridden['data']['exit_code'] == 0
        timed = await tools.shell('sleep 3', timeout=0.1)
        assert timed['data']['termination_reason'] == 'runtime_timeout'
        if sys.platform == 'darwin':
            assert good['data']['resource_limits']['enforced'] is False


def test_invalid_operator_budget_rejected(monkeypatch):
    monkeypatch.setenv('AION_SHELL_TASK_MEMORY_MIB', 'nan')
    with pytest.raises(ValueError):
        cgroups.budgets()


def test_process_budget_defaults_and_validation(monkeypatch):
    limits = cgroups.budgets()
    assert limits["pids_max"] == 512
    assert limits["pool_pids_max"] == 2048
    monkeypatch.setenv("AION_SHELL_TASK_PIDS_MAX", "2049")
    with pytest.raises(ValueError):
        cgroups.budgets()
    monkeypatch.setenv("AION_SHELL_TASK_PIDS_MAX", "16")
    monkeypatch.setenv("AION_SHELL_POOL_PIDS_MAX", "8")
    with pytest.raises(ValueError):
        cgroups.budgets()


def test_memory_termination_does_not_require_pids_controller(tmp_path):
    events = tmp_path / 'memory.events'
    events.write_text('oom_kill 0\noom_group_kill 0\n')
    assert cgroups.termination_reason(tmp_path) is None
    events.write_text('oom_kill 1\noom_group_kill 0\n')
    assert cgroups.termination_reason(tmp_path) == 'memory_limit_exceeded'


def test_process_termination_reason_comes_from_pids_events(tmp_path):
    (tmp_path / 'memory.events').write_text('oom_kill 0\noom_group_kill 0\n')
    (tmp_path / 'pids.events').write_text('max 1\n')
    assert cgroups.termination_reason(tmp_path) == 'process_limit_exceeded'


@pytest.mark.skipif(sys.platform != 'linux', reason='requires delegated writable cgroup v2')
async def test_linux_resource_failure_preserves_output_and_sibling(make_tools, monkeypatch):
    import shlex
    monkeypatch.setenv('AION_SHELL_TASK_MEMORY_MIB', '64')
    async with make_tools() as tools:
        sibling = await tools.task_start('sleep 30', timeout=40)
        for code, reason in [
            ("print('before',flush=True); x=bytearray(256*1024*1024)", 'memory_limit_exceeded')]:
            result = await tools.shell('python3 -c '+shlex.quote(code), timeout=15)
            assert result['data']['termination_reason'] == reason
            assert 'before' in result['data']['output']
            assert result['data']['cleanup']['resources_released']
            assert (await tools.task_output(sibling['data']['task_id']))['data']['status'] == 'running'
        await tools.task_stop(sibling['data']['task_id'])


@pytest.mark.skipif(sys.platform != 'linux', reason='requires delegated writable cgroup v2')
async def test_linux_task_can_exceed_previous_thread_limit(make_tools):
    import shlex
    code = (
        "import threading; gate=threading.Event(); "
        "threads=[threading.Thread(target=gate.wait, args=(5,)) for _ in range(160)]; "
        "[t.start() for t in threads]; print('started',len(threads),flush=True); "
        "gate.set(); [t.join() for t in threads]"
    )
    async with make_tools() as tools:
        result = await tools.shell('python3 -c ' + shlex.quote(code), timeout=15)
        assert result['data']['exit_code'] == 0
        assert 'started 160' in result['data']['output']
        assert result['data']['cleanup']['resources_released']
