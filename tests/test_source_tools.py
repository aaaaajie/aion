import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from tools.source import scan
from tools.source.wrapper import SourceTools, SourceScanArguments


@pytest.mark.parametrize('code,errors,hits,state', [(0, [], True, 'completed'), (0, [], False, 'completed'), (0, [{'type':'ParseError'}], True, 'partial'), (2, [{'type':'FatalError'}], False, 'tool_failed')])
def test_scan_classifies_and_bounds_results(tmp_path, monkeypatch, capsys, code, errors, hits, state):
    source = tmp_path / 'src'; source.mkdir()
    sample = source / 'sample.py'; sample.write_text('def read(path):\n    return open(path).read()\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scan.sys, 'argv', ['scan.py', str(source)])
    def run(command, **kwargs):
        assert '--metrics=off' in command and '--disable-version-check' in command
        assert '--config' in command and Path(command[command.index('--config') + 1]).is_dir()
        assert 'SEMGREP_APP_TOKEN' not in kwargs['env']
        output = Path(command[command.index('--output') + 1])
        output.write_text(json.dumps({'results': [{'check_id':'test.read','path':str(sample),'start':{'line':2},'end':{'line':2}}] if hits else [], 'errors':errors}))
        return SimpleNamespace(returncode=code, stdout=b'', stderr=b'')
    monkeypatch.setattr(scan.subprocess, 'run', run)
    result = scan.main()
    report = json.loads(capsys.readouterr().out)
    assert report['state'] == state
    assert result == (1 if state == 'tool_failed' else 0)
    if hits:
        assert report['findings'][0]['snippet'] == '    return open(path).read()'
        assert report['findings'][0]['classification'] == 'review_lead'


async def test_source_uses_owned_background_task_and_rejects_outside(tmp_path):
    class Shell:
        agent_work_root = tmp_path
        async def run_shell(self, command, **kwargs):
            assert 'scan.py' in command
            assert kwargs['run_in_background'] is True
            return {'task_id': 'owned-task'}
    tools = SourceTools(Shell())
    assert await tools.scan(SourceScanArguments()) == {'task_id': 'owned-task'}
    with pytest.raises(Exception):
        await tools.scan(SourceScanArguments(path='..'))
