"""Discoverable examples use execution's actual schemas and native calls."""
import pytest

from agent.subagents.models import SolverReviewArguments, DelegateArguments
from tools.fastcgi.wrapper import FastCGIArguments
from tools.system.models import TaskStartArguments
from agent.subagents.policy import AgentPolicy
from agent.tool_examples import examples_for
from agent.tooling import ToolRegistry, ToolExecutor, ToolSpec, AccessClaim
from tests.test_compact_tools import wire
from tools.http.models import HttpRequestArguments, HttpProbeArguments, HttpResponseArguments, HttpOutputArguments, HttpAnalyzeArguments
from tools.poc_runtime.tools import PocSearchArguments, PocInspectArguments, PocRunArguments, PocOutputArguments


@pytest.mark.parametrize('name,model', [
    ('system_http_request', HttpRequestArguments), ('system_http_probe', HttpProbeArguments),
    ('system_http_analyze', HttpAnalyzeArguments), ('system_http_response', HttpResponseArguments), ('system_http_output', HttpOutputArguments),
    ('system_poc_search', PocSearchArguments), ('system_poc_inspect', PocInspectArguments),
    ('system_poc_run', PocRunArguments), ('system_poc_output', PocOutputArguments),
    ('system_fastcgi_request', FastCGIArguments), ('solver_delegate', DelegateArguments), ('solver_review', SolverReviewArguments), ('system_task_start', TaskStartArguments),
])
async def test_exact_discovery_examples_are_executable_schema(name, model):
    class Provider:
        def tool_specs(self):
            return [ToolSpec(name, 'fixture tool', model, lambda _: {}, lambda _: (AccessClaim('read', 'fixture'),))]
    registry = ToolRegistry([Provider()], compact=True)
    result = (await ToolExecutor(registry).execute([wire('tool_search', {'name': name})]))[0].result
    assert result['data']['examples'] == examples_for(name, model)
    assert result['data']['examples']


async def test_removed_gateway_is_unknown_tool():
    registry = ToolRegistry([], compact=True)
    result = (await ToolExecutor(registry).execute([wire('tool_call', {'name': 'tool_call', 'arguments': {}})]))[0].result
    assert result['error']['code'] == 'unknown_tool'
    assert 'next_tool' in result['error']['details']


def test_existing_analysis_and_plan_are_available_to_execution_roles():
    for role in ('solver', 'worker'):
        assert {'system_http_analyze', 'system_http_plan'} <= AgentPolicy(role).allowed_tools
    assert 'system_http_plan' not in AgentPolicy('chief').allowed_tools


async def test_review_unknown_field_returns_exact_contract_and_recovers():
    called = []
    class Provider:
        def tool_specs(self):
            return [ToolSpec('solver_review', 'fixture', SolverReviewArguments,
                lambda args: called.append(args) or {'ok': True},
                lambda _: (AccessClaim('write', 'fixture'),))]
    executor = ToolExecutor(ToolRegistry([Provider()], compact=True))
    await executor.execute([wire('tool_search', {'name': 'solver_review'})])
    arguments = examples_for('solver_review')[0]
    arguments['summary_zh'] = arguments.pop('summary')
    for _ in range(2):
        result = (await executor.execute([wire('solver_review', arguments)]))[0].result
        details = result['error']['details']
        assert 'summary' in details['allowed_fields']
        assert 'summary_zh' not in details['allowed_fields']
        SolverReviewArguments.model_validate(details['minimal_example'])
        assert not called
    arguments['summary'] = arguments.pop('summary_zh')
    result = (await executor.execute([wire('solver_review', arguments)]))[0].result
    assert result['ok'] and len(called) == 1


@pytest.mark.parametrize('name,model,arguments,hint', [
    ('system_http_response', HttpResponseArguments, {'interaction_id':'i','request_id':'r','limit_chars':40}, 'offset_bytes/length_bytes'),
    ('system_http_output', HttpOutputArguments, {'offset':0}, 'cursor/limit'),
    ('system_http_analyze', HttpAnalyzeArguments, {'interaction_id':'i','offset':0}, 'cursor/limit'),
    ('system_http_probe', HttpProbeArguments, {'cases':[{'username':'fixture'}]}, 'body:'),
    ('solver_review', SolverReviewArguments, {**examples_for('solver_review')[0], 'new_information':'finding'}, 'value of assessment'),
])
async def test_runtime_mistakes_are_rejected_with_targeted_guidance(name, model, arguments, hint):
    called = []
    class Provider:
        def tool_specs(self):
            return [ToolSpec(name, 'fixture', model, lambda args: called.append(args) or {'ok':True},
                            lambda _: (AccessClaim('write','fixture'),))]
    executor = ToolExecutor(ToolRegistry([Provider()], compact=True))
    await executor.execute([wire('tool_search', {'name': name})])
    result = (await executor.execute([wire(name, arguments)]))[0].result
    assert not called
    assert hint in result['error']['message']
    assert result['error']['retry']['same_arguments'] is False
    assert result['error']['details']['execution_status'] == 'not_started'
