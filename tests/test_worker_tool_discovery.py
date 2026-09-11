import pytest
from agent.subagents.tools import AgentControlTools
from agent.subagents.policy import AgentPolicy
from agent.tooling import ToolRegistry, ToolExecutor
from tools.fastcgi import FastCGITools
from tests.test_compact_tools import wire


def test_delegate_is_direct_only_for_solver():
    for role in ('solver','chief','worker'):
        registry=ToolRegistry([AgentControlTools(object(),agent_id=role,role=role)],
                              compact=True,allowed_tools=AgentPolicy(role).allowed_tools)
        names={item['function']['name'] for item in registry.definitions()}
        assert ('solver_delegate' in names) == (role == 'solver')


@pytest.mark.parametrize('query', ['FastCGI','FCGI','PHP-FPM'])
async def test_protocol_discovery(query):
    provider=FastCGITools()
    try:
        registry=ToolRegistry([provider],compact=True)
        response=(await ToolExecutor(registry).execute([wire('tool_search',{'query':query})]))[0].result
        assert response['data']['tools'][0]['name']=='system_fastcgi_request'
    finally:
        await provider.close()
