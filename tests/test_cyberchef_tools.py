import base64
import json
import shlex
import shutil
from pathlib import Path
import pytest
from pydantic import ValidationError
from tools.cyberchef.wrapper import CyberChefArguments, CyberChefTools
from agent.subagents.policy import AgentPolicy
from agent.tool_examples import examples_for


@pytest.mark.parametrize('value', [{}, {'input':'a'}, {'input':'a','input_path':'x','recipe':[{'op':'MD5'}]}, {'action':'operations','input':'x'}, {'input_path':'x','input_encoding':'hex','recipe':[{'op':'MD5'}]}])
def test_invalid_requests(value):
    with pytest.raises(ValidationError):
        CyberChefArguments(**value)


async def test_owned_binary_input_job_and_task(tmp_path):
    bundle = tmp_path / 'bundle'; (bundle/'bin').mkdir(parents=True)
    executable = bundle/'bin/cyberchef'; executable.write_text(''); executable.chmod(0o755)
    (bundle/'manifest.json').write_text(json.dumps({'system_binaries':{'cyberchef':{'path':'bin/cyberchef'}}}))
    actual = Path(__file__).resolve().parents[1]/'tools/binaries/cyberchef'
    (bundle/'cyberchef').mkdir(parents=True)
    shutil.copy(actual/'operations.json', bundle/'cyberchef/operations.json')
    shutil.copy(actual/'operation-config.json', bundle/'cyberchef/operation-config.json')
    workspace = tmp_path/'agent'; workspace.mkdir()
    data = b'\x00\xff\x80hello'; (workspace/'input.bin').write_bytes(data)
    class Shell:
        agent_work_root = workspace
        async def run_shell(self, command, **kwargs):
            argv = shlex.split(command)
            job_path = Path(argv[argv.index('--job')+1])
            assert job_path.is_relative_to(workspace)
            assert job_path.stat().st_mode & 0o777 == 0o600
            job = json.loads(job_path.read_text())
            assert base64.b64decode(job['input']) == data
            assert job['input_encoding'] == 'base64'
            assert kwargs['run_in_background'] and kwargs['timeout'] == 75
            return {'task_id':'owned'}
    provider = CyberChefTools(Shell(), bundle)
    assert await provider.run(CyberChefArguments(input_path='input.bin',recipe=[{'op':'To Hex'}])) == {'task_id':'owned'}
    with pytest.raises(Exception):
        await provider.run(CyberChefArguments(input_path='../outside',recipe=[{'op':'To Hex'}]))
    (workspace/'escape').symlink_to(tmp_path)
    with pytest.raises(Exception):
        await provider.run(CyberChefArguments(input_path='escape/outside',recipe=[{'op':'To Hex'}]))


def test_discovery_examples_and_roles():
    for example in examples_for('system_cyberchef'):
        CyberChefArguments(**example)
    for role in ('solver','worker'):
        assert 'system_cyberchef' in AgentPolicy(role).allowed_tools


async def test_native_query_and_error_correction_without_starting_task(tmp_path):
    from agent.tooling import ToolRegistry, ToolExecutor
    from tests.test_compact_tools import wire
    class Shell:
        agent_work_root = tmp_path
        async def run_shell(self, *args, **kwargs):
            raise AssertionError('Query/invalid recipe must not create a task')
    executor = ToolExecutor(ToolRegistry([CyberChefTools(Shell())], compact=True))
    await executor.execute([wire('tool_search', {'name': 'system_cyberchef'})])
    async def call(arguments):
        return (await executor.execute([wire('system_cyberchef', arguments)]))[0].result
    query = await call({'action':'operations','query':'AES Decrypt'})
    assert query['ok'] and query['data']['details'][0]['name'] == 'AES Decrypt'
    assert query['data']['details'][0]['args']
    for step in ({'op':'Magic'}, {'op':'XOR','args':{'kee':'42'}}, {'op':'From Base64','args':[]}):
        result = await call({'input':'abc','recipe':[step]})
        assert not result['ok']
        assert result['error']['details']['next_tool'] == 'system_cyberchef'
        assert 'next_arguments' in result['error']['details']
    assert not list(tmp_path.glob('cyberchef-*'))


def test_cyberchef_skill_discoverable():
    from agent.skills import SkillCatalog
    catalog = SkillCatalog()
    for query in ('CyberChef', '解密'):
        results = catalog.search(query=query, role='worker')
        assert 'cyberchef-recipes' in str(results)
