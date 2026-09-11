"""Exercise replay authority, real activation, restoration and honest scoring."""
import json
from pathlib import Path
import tarfile

import pytest

from agent.skills import SkillCatalog
from agent.memory.context import REQUIRED_MEMORY_SECTIONS
from scripts.replay_solver_decisions import (
    ROOT, MAX_TURNS, Condition, extract_baseline, read_cases, run_case, summarize,
)


def response(name=None, arguments=None, content='下一步验证正常对照，结论仍未定。'):
    message = {'role': 'assistant', 'content': content, 'reasoning_content': 'fixture'}
    if name:
        message['tool_calls'] = [{'id': 'call-1', 'type': 'function', 'function': {
            'name': name, 'arguments': json.dumps(arguments or {})}}]
    return {'choices': [{'message': message, 'finish_reason': 'tool_calls' if name else 'stop'}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 2}}


@pytest.fixture
def condition():
    return Condition('skills', 'Solver', (ROOT / 'agent/prompts/session_memory_system.txt').read_text(), SkillCatalog())


def case(**extra):
    return {'id': 'fixture', 'trace': 'Known endpoint /ready; readiness changed.',
            'review': 'PRIVATE RUBRIC DO NOT SEND', 'expected_skills': ['execution/internal-network-recon'],
            'skill_expectation': 'required', **extra}


async def test_native_activation_resources_and_fixed_evidence(tmp_path, condition):
    requests = []
    outputs = [
        response('tool_search', {'name': 'skill_search'}),
        response('skill_search', {'query': 'startup connection reachability'}),
        response('tool_search', {'name': 'skill_invoke'}),
        response('skill_invoke', {'skill_id': 'execution/internal-network-recon'}),
        response('tool_search', {'name': 'skill_resource_read'}),
        response('skill_resource_read', {
            'skill_id': 'execution/internal-network-recon', 'resource': 'references/fastcgi-validation.md'}),
        response('tool_search', {'name': 'replay_read_evidence'}),
        response('replay_read_evidence', {'evidence_ref': 'ready'}),
        response(),
    ]

    async def model(purpose, messages, definitions):
        requests.append({'messages': messages, 'tools': definitions})
        return outputs.pop(0)

    row = await run_case(condition, case(receipts={'ready': {'status': 200}}), 1, tmp_path / 'run', model)
    assert row['status'] == 'completed'
    assert row['active_skills'][0]['skill_id'] == 'execution/internal-network-recon'
    assert any(e['event_type'] == 'skill_activated' for e in row['state_events'])
    assert row['trace'][5]['result']['data']['content'].startswith('# Validate')
    assert row['trace'][7]['result']['data'] == {'status': 200}
    assert 'PRIVATE RUBRIC' not in json.dumps(requests)
    assert 'Reachability before' not in requests[0]['messages'][0]['content']
    assert 'Reachability before' in requests[5]['messages'][0]['content']
    names = {t['function']['name'] for t in requests[0]['tools']}
    assert names == {'tool_search'}
    summary = summarize([row])
    assert summary['required_skill_cases']['skills/fixture']['search_and_relevant_activation'] == 1
    assert summary['conditions']['skills']['uncertainty_promoted_to_fact'] is None


async def test_memory_restores_persisted_skill_without_private_rubric(tmp_path, condition):
    calls = []
    normalized = '\n'.join('# ' + h + '\n' + ('Sequence 50 is revoked; network status unknown.' if h == 'Errors & Corrections' else '') for h in REQUIRED_MEMORY_SECTIONS)

    async def model(purpose, messages, definitions):
        calls.append((purpose, messages))
        if purpose == 'memory':
            assert 'REVOCATION_EVENT' in json.dumps(messages)
            return response(content=normalized)
        assert 'RAW_TRACE_ONLY' not in json.dumps(messages)
        assert 'Sequence 50 is revoked' in json.dumps(messages)
        assert '<active_skills>' in messages[0]['content']
        return response()

    row = await run_case(condition, case(trace='RAW_TRACE_ONLY', active_skills=['execution/internal-network-recon'],
                         memory={'events': [{'sequence': 80, 'content': 'REVOCATION_EVENT'}]}), 1, tmp_path / 'run', model)
    assert row['status'] == 'completed'
    assert [c[0] for c in calls] == ['memory', 'decision']
    assert row['model_calls'] == 2 and not row['trace']
    assert row['initial_active_skills'] == row['active_skills']
    assert any(e['event_type'] == 'memory_updated' for e in row['state_events'])
    assert 'PRIVATE RUBRIC' not in json.dumps(calls)


async def test_loop_hits_budget_without_hidden_retry(tmp_path, condition):
    async def model(*args):
        return response('tool_search', {'name': 'skill_search'})
    row = await run_case(condition, case(), 1, tmp_path / 'run', model)
    assert row['status'] == 'incomplete' and row['model_calls'] == MAX_TURNS
    assert 'content' not in row


async def test_target_tools_are_unavailable_and_unknown_receipt_is_not_negative(tmp_path, condition):
    outputs = [response('system_shell', {'command': 'touch /tmp/must-not-run'}),
               response('tool_search', {'name': 'replay_read_evidence'}),
               response('replay_read_evidence', {'evidence_ref': 'unknown'}), response()]
    async def model(*args):
        return outputs.pop(0)
    row = await run_case(condition, case(), 1, tmp_path / 'run', model)
    assert row['trace'][0]['result']['error']['code'] == 'unknown_tool'
    assert row['trace'][2]['result']['error']['code'] == 'fixture_evidence_not_found'


async def test_empty_catalog_does_not_fabricate_skill(tmp_path, condition):
    outputs = [response('tool_search', {'name': 'skill_search'}), response('skill_search', {'query': 'unknown checksum'}), response()]
    async def model(*args):
        return outputs.pop(0)
    row = await run_case(condition, case(empty_catalog=True), 1, tmp_path / 'run', model)
    assert row['trace'][1]['result']['data']['count'] == 0 and row['active_skills'] == []


async def test_model_truncation_is_error_not_decision(tmp_path, condition):
    async def model(*args):
        payload = response(content='partial')
        payload['choices'][0]['finish_reason'] = 'length'
        return payload
    row = await run_case(condition, case(), 1, tmp_path / 'run', model)
    assert row['status'] == 'error' and row['model_calls'] == 1


def test_baseline_rejects_links_and_requires_catalog(tmp_path):
    archive = tmp_path / 'bad.tar'
    with tarfile.open(archive, 'w') as stream:
        info = tarfile.TarInfo('agent/skills/linked')
        info.type = tarfile.SYMTYPE
        info.linkname = '/etc/passwd'
        stream.addfile(info)
    with pytest.raises(ValueError, match='Unsafe'):
        extract_baseline(archive, tmp_path / 'out')


def test_fixtures_have_six_holdouts_and_untruncated_routable_skills(condition):
    cases = read_cases(ROOT / 'tests/fixtures/solver_decisions/cases.json')
    assert len([c for c in cases if c.get('holdout')]) == 6
    for skill_id in {s for c in cases for s in c.get('expected_skills', [])}:
        skill = condition.catalog.get('solver', skill_id)
        assert skill.activation_view == skill.instructions
        assert len(skill.activation_view) <= 6000
    queries = {
        '页面错误 认证会话失效 重定向': 'common/web-ctf-flow',
        '局部源码 文件读取 配置 路径拼接': 'execution/src-audit-workflow',
        '启动连接失败 客户端 可达性': 'execution/internal-network-recon',
        '迁移文档 令牌 服务端验证': 'execution/api-auth-and-jwt-abuse',
        'SQL 阴性结论 换工具 同一假设': 'execution/sqli-sql-injection',
    }
    for query, expected in queries.items():
        assert expected in {s['skill_id'] for s in condition.catalog.search('solver', query, limit=8)}


def test_conditions_isolate_prompt_and_catalog_changes(tmp_path):
    from scripts.replay_solver_decisions import conditions, PROMPT_FILES
    for version in ('old', 'new'):
        root = tmp_path / version
        prompts = root / 'agent/prompts'
        prompts.mkdir(parents=True)
        for name in (*PROMPT_FILES, 'session_memory_system.txt'):
            (prompts / name).write_text(version + name)
        for category in ('common', 'challenge', 'execution'):
            (root / 'agent/skills' / category).mkdir(parents=True)
        skill = root / 'agent/skills/common/example'
        skill.mkdir(parents=True)
        (skill / 'SKILL.md').write_text('---\nname: example\ndescription: Example fixture skill for testing.\n---\n' + version)
    old, prompt, skills = conditions(tmp_path / 'old', tmp_path / 'new')
    assert old.system != prompt.system == skills.system
    assert old.memory != prompt.memory == skills.memory
    assert old.catalog.content_sha256 == prompt.catalog.content_sha256 != skills.catalog.content_sha256


def test_partial_report_never_treats_unreviewed_as_zero_errors(tmp_path):
    from scripts.replay_solver_decisions import write_report
    row = {'case': 'fixture', 'condition': 'skills', 'repeat': 1, 'status': 'completed',
           'trace': [], 'usage': [], 'elapsed_seconds': 1, 'model_calls': 1,
           'skill_expectation': 'optional'}
    write_report(tmp_path, [case(skill_expectation='optional')], [row])
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert summary['not_started'] == 8
    assert summary['conditions']['skills']['uncertainty_promoted_to_fact'] is None
    assert all(r['distinguishing_pass'] is None for r in summary['acceptance'])
    review = {'case': 'fixture', 'condition': 'skills', 'repeat': 1,
              'distinguishing_next_step': False, 'uncertainty_promotions': 1,
              'rationale': 'Final decision asserted a permanent network restriction.'}
    write_report(tmp_path, [case(skill_expectation='optional')], [row], [review])
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert summary['conditions']['skills']['uncertainty_promoted_to_fact'] == 1
    assert all(r['distinguishing_pass'] is None for r in summary['acceptance'])


async def test_memory_request_counts_against_total_budget(tmp_path, condition):
    async def model(purpose, *args):
        return response(content='# Current State\nUncertain') if purpose == 'memory' else response('tool_search', {'name': 'skill_search'})
    row = await run_case(condition, case(memory={'events': []}), 1, tmp_path / 'run', model)
    assert row['status'] == 'incomplete'
    assert row['model_calls'] == MAX_TURNS and len(row['trace']) == MAX_TURNS - 1


def test_case_id_cannot_escape_output_directory(tmp_path):
    path = tmp_path / 'cases.json'
    path.write_text(json.dumps([case(id='../outside')]))
    with pytest.raises(ValueError, match='directory names'):
        read_cases(path)


def test_two_valid_decisions_meet_gate_even_if_third_model_call_fails(tmp_path):
    from scripts.replay_solver_decisions import write_report
    rows = [{'case': 'fixture', 'condition': 'skills', 'repeat': i, 'status': 'completed' if i < 3 else 'error',
             'trace': [], 'usage': [], 'elapsed_seconds': 1, 'model_calls': 1, 'skill_expectation': 'optional'} for i in range(1,4)]
    reviews = [{'case': 'fixture', 'condition': 'skills', 'repeat': i,
                'distinguishing_next_step': True, 'uncertainty_promotions': 0,
                'rationale': 'Selected the verified control before interpreting the candidate.'} for i in (1,2)]
    write_report(tmp_path, [case(skill_expectation='optional')], rows, reviews)
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert next(r for r in summary['acceptance'] if r['condition'] == 'skills')['distinguishing_pass'] is True
