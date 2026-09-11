"""Controlled decision replay using the real Skill catalog, state and tool gateway.

Default validates fixtures without model calls. --live compares a required pre-edit
archive with the current tree. Only the configured model endpoint is contacted;
evidence reads return fixed fixture receipts. Semantic judgments are reviewed
separately, never supplied to the Solver or scored by keyword matching.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hashlib
import json
import re
import shutil
from pathlib import Path
import tarfile
import tempfile
from time import monotonic
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from agent.config import (
    AgentSettings, completions_url, deepseek_agent_request_options,
    deepseek_auxiliary_request_options,
)
from agent.memory.context import normalize_session_memory
from agent.memory.summarizer import SessionMemorySummarizer
from agent.model_usage import post_model
from agent.skills import SkillCatalog, SkillSessionContext, SkillTools
from agent.state import StateService
from agent.tooling import AccessClaim, ToolExecutor, ToolRegistry, ToolSpec, tool_error

ROOT = Path(__file__).resolve().parents[1]
PROMPT_FILES = ('solver_system.txt', 'tool_surface_system.txt', 'base_system.txt')
CONDITIONS = ('baseline', 'prompt', 'skills')
REPEATS = 3
MAX_TURNS = 12  # Includes memory-model requests; no hidden retries.


def sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def append(path: Path, value: Any) -> None:
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + '\n')


def read_cases(path: Path) -> list[dict]:
    cases = json.loads(path.read_text())
    if not cases or len({c['id'] for c in cases}) != len(cases):
        raise ValueError('Cases must be nonempty with unique IDs')
    for case in cases:
        if not isinstance(case['id'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,100}', case['id']):
            raise ValueError('Case IDs must be safe lowercase directory names')
        if not case.get('trace') or not case.get('review'):
            raise ValueError('Each case needs trace and private review criteria')
        if case.get('skill_expectation', 'optional') not in {'required', 'reuse', 'none', 'no_match', 'optional'}:
            raise ValueError('Unknown Skill expectation')
    return cases


def extract_baseline(archive_path: Path, destination: Path) -> Path:
    """Extract only ordinary prompt/Skill files; never links or traversal paths."""
    with tarfile.open(archive_path) as archive:
        for member in archive:
            parts = Path(member.name).parts
            if parts[:2] not in {('agent', 'prompts'), ('agent', 'skills')}:
                continue
            if '..' in parts or member.name.startswith('/') or member.issym() or member.islnk():
                raise ValueError('Unsafe baseline member')
            if member.isfile():
                target = destination / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source:
                    target.write_bytes(source.read())
    for name in (*PROMPT_FILES, 'session_memory_system.txt'):
        if not (destination / 'agent/prompts' / name).is_file():
            raise ValueError(f'Baseline missing prompt: {name}')
    if not (destination / 'agent/skills/manifest.json').is_file():
        raise ValueError('Baseline must include the pre-edit Skill catalog')
    return destination


@dataclass(frozen=True)
class Condition:
    name: str
    system: str
    memory: str
    catalog: SkillCatalog

    def fingerprint(self) -> dict:
        return {'system_sha256': sha(self.system), 'memory_sha256': sha(self.memory),
                'catalog_sha256': self.catalog.content_sha256}


def conditions(baseline: Path, current: Path = ROOT) -> list[Condition]:
    old, new = SkillCatalog(baseline / 'agent/skills'), SkillCatalog(current / 'agent/skills')
    result = []
    for name in CONDITIONS:
        root = baseline if name == 'baseline' else current
        prompt_dir = root / 'agent/prompts'
        result.append(Condition(name, '\n\n'.join((prompt_dir / p).read_text() for p in PROMPT_FILES),
                                (prompt_dir / 'session_memory_system.txt').read_text(),
                                new if name == 'skills' else old))
    return result


class EvidenceArguments(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    evidence_ref: str = Field(min_length=1)


class FixtureEvidence:
    """No URLs, shell commands, target clients or arbitrary filesystem reads."""
    def __init__(self, receipts: dict):
        self.receipts = receipts

    def tool_specs(self):
        def read(args):
            if args.evidence_ref not in self.receipts:
                return tool_error('semantic', 'fixture_evidence_not_found', 'No recorded receipt exists for this reference; this says nothing about the target.')
            return {'ok': True, 'data': self.receipts[args.evidence_ref],
                    'evidence_refs': [args.evidence_ref]}
        return [ToolSpec('replay_read_evidence', 'Read a fixed recorded evidence receipt by its supplied reference. Sends no requests.',
                         EvidenceArguments, read, lambda _: (AccessClaim('read', 'fixture:evidence'),))]


@asynccontextmanager
async def session(catalog: SkillCatalog, directory: Path, case: dict):
    service = StateService(directory / 'state.sqlite3')
    try:
        await service.create_run('replay', challenges=[{'unique_code': 'fixture'}])
        await service.register_agent('replay', role='chief', agent_id='chief')
        await service.register_agent('replay', role='solver', agent_id='solver',
                                     parent_id='chief', unique_code='fixture')
        context = SkillSessionContext(catalog, role='solver', service=service,
                                      run_id='replay', agent_id='solver')
        for skill_id in case.get('active_skills', []):
            await context.invoke(skill_id)
        yield service, context
    finally:
        await service.close()


def user_input(case: dict) -> str:
    # Deliberately enumerate public fields; never serialize the case/review whole.
    return ('你正在为所述授权任务选择下一项实验。这里回放决策而不执行目标操作，Skill 的判断方法仍适用于该任务。'
            '本阶段只提供 Skill 与固定证据工具；HTTP、Shell 等目标执行工具明确不可用，不要反复检索它们。'
            '根据当前证据决定下一步，可使用提供的工具读取已有资源。'
            '目标操作均未执行；最后用简短中文说明下一项实验、证据依据和剩余不确定性，随后结束。'
            '不要提交答案、调用外部目标或声称拟议操作已经执行。\n\n' + case['trace'] +
            '\n可读取的固定证据引用：' + json.dumps(list(case.get('receipts', {})), ensure_ascii=False))


async def run_case(condition: Condition, case: dict, repeat: int, directory: Path, model) -> dict:
    """model(purpose, messages, definitions) returns one completion, without retries."""
    directory.mkdir(parents=True, exist_ok=False)
    result = {'case': case['id'], 'condition': condition.name, 'repeat': repeat,
              'family': case.get('family'), 'status': 'incomplete', 'model_calls': 0, 'trace': [], 'usage': [],
              'review': case['review'], 'skill_expectation': case.get('skill_expectation', 'optional'),
              'expected_skills': case.get('expected_skills', []), 'holdout': case.get('holdout', False)}
    started = monotonic()
    catalog = condition.catalog
    if case.get('empty_catalog'):
        root = directory / 'empty-skills'
        for category in ('common', 'challenge', 'execution'):
            (root / category).mkdir(parents=True)
        catalog = SkillCatalog(root)
    result['effective_catalog_sha256'] = catalog.content_sha256

    async def request(purpose, messages, definitions=None):
        result['model_calls'] += 1
        append(directory / 'requests.jsonl', {'purpose': purpose, 'messages': messages, 'tools': definitions})
        payload = await model(purpose, messages, definitions)
        result['usage'].append({'purpose': purpose, **payload.get('usage', {})})
        choice = payload['choices'][0]
        append(directory / 'responses.jsonl', {'purpose': purpose, **payload})
        if choice.get('finish_reason') not in {'stop', 'tool_calls'}:
            raise ValueError('Incomplete model response: ' + str(choice.get('finish_reason')))
        return choice['message']

    try:
        async with session(catalog, directory, case) as (service, context):
            messages = [{'role': 'user', 'content': user_input(case)}]
            result['initial_active_skills'] = [dict(x) for x in context.active_skills]
            if case.get('memory'):
                memory = case['memory']
                checkpoint = {**memory.get('checkpoint', {}), 'active_skills': list(context.active_skills)}
                prompt = SessionMemorySummarizer._build_prompt(
                    current_memory=memory.get('current_memory', ''), checkpoint=checkpoint,
                    recent_messages=messages, recent_events=memory.get('events', []))
                answer = await request('memory', [{'role': 'system', 'content': condition.memory},
                                                  {'role': 'user', 'content': prompt}])
                if not answer.get('content') or answer.get('tool_calls'):
                    raise ValueError('Missing memory document')
                result['raw_memory'] = answer['content']
                normalized, _ = normalize_session_memory(answer['content'], max_tokens=12_000)
                await service.update_agent_memory('replay', 'solver', normalized, summarized_through_sequence=0)
                # Restore from persisted state, not the previous in-memory context.
                state = (await service.get_agent_runtime('replay', 'solver'))['agent']
                context = SkillSessionContext(catalog, role='solver', service=service, run_id='replay',
                                              agent_id='solver', active_skills=state['active_skills'])
                result['memory'] = state['session_memory']
                messages = [{'role': 'user', 'content': '任务在记忆压缩后恢复。Skill 判断方法仍适用于所述授权任务；本阶段仅提供 Skill 与固定证据工具，不要检索明确不可用的 HTTP/Shell 执行工具。仅根据记忆和恢复的 Skill 选择下一项实验、说明依据和不确定性；不要声称拟议操作已经执行。\n' + state['session_memory'] + '\n固定证据引用：' + json.dumps(list(case.get('receipts', {})))}]
            registry = ToolRegistry([SkillTools(context), FixtureEvidence(case.get('receipts', {}))], compact=True)
            definitions = registry.definitions()
            result['tool_surface_sha256'] = sha(definitions)
            executor = ToolExecutor(registry)
            while result['model_calls'] < MAX_TURNS:
                system = condition.system + '\n\n' + context.render_system_context()
                message = await request('decision', [{'role': 'system', 'content': system}, *messages], definitions)
                # Preserve reasoning_content required by the configured tool protocol.
                messages.append({k: v for k, v in message.items() if k in {'role', 'content', 'reasoning_content', 'tool_calls'}})
                messages[-1]['role'] = 'assistant'
                calls = message.get('tool_calls') or []
                if not calls:
                    if not message.get('content'):
                        raise ValueError('Missing final decision')
                    result.update(status='completed', content=message['content'])
                    break
                outcomes = await executor.execute(calls)
                for call, outcome in zip(calls, outcomes, strict=True):
                    row = {'call': call, 'name': outcome.name, 'result': outcome.result}
                    result['trace'].append(row)
                    messages.append({'role': 'tool', 'tool_call_id': call['id'],
                                     'content': json.dumps(outcome.result, ensure_ascii=False)})
                definitions = registry.definitions()
            result['active_skills'] = list(context.active_skills)
            result['state_events'] = await service.list_agent_events('replay', 'solver')
    except Exception as exc:
        result.update(status='error', error=type(exc).__name__)
        if isinstance(exc, httpx.HTTPStatusError):
            result['http_status'] = exc.response.status_code
        elif isinstance(exc, (ValueError, KeyError)):
            result['error_detail'] = str(exc)[:500]
    result['elapsed_seconds'] = round(monotonic() - started, 3)
    (directory / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def summarize(results: list[dict]) -> dict:
    groups = {}
    for condition in CONDITIONS:
        rows = [r for r in results if r['condition'] == condition]
        groups[condition] = {
            'runs': len(rows), 'status': dict(Counter(r['status'] for r in rows)),
            'model_calls': sum(r['model_calls'] for r in rows),
            'http_errors': dict(Counter(str(r['http_status']) for r in rows if 'http_status' in r)),
            'elapsed_seconds_total': round(sum(r['elapsed_seconds'] for r in rows), 3),
            'prompt_tokens': sum(u.get('prompt_tokens', 0) for r in rows for u in r['usage']),
            'completion_tokens': sum(u.get('completion_tokens', 0) for r in rows for u in r['usage']),
            'skill_search_runs': sum(any(t['name'] == 'skill_search' for t in r['trace']) for r in rows),
            'activated_runs': sum(any(t['name'] == 'skill_invoke' and t['result'].get('data', {}).get('activation_status') == 'activated' for t in r['trace']) for r in rows),
            'resource_read_runs': sum(any(t['name'] == 'skill_resource_read' and 'content' in t['result'].get('data', {}) for t in r['trace']) for r in rows),
            'uncertainty_promoted_to_fact': None,
            'semantic_review': 'pending: inspect final decisions and memory; do not infer quality from activation counts',
        }
    required = {}
    for row in results:
        if row['skill_expectation'] != 'required':
            continue
        key = row['condition'] + '/' + row['case']
        bucket = required.setdefault(key, {'runs': 0, 'search_and_relevant_activation': 0})
        bucket['runs'] += 1
        searched = any(t['name'] == 'skill_search' and isinstance(t['result'].get('data', {}).get('skills'), list) for t in row['trace'])
        activated = any(t['name'] == 'skill_invoke' and t['result'].get('data', {}).get('activation_status') == 'activated'
                        and t['result'].get('data', {}).get('skill', {}).get('skill_id') in row['expected_skills'] for t in row['trace'])
        bucket['search_and_relevant_activation'] += bool(searched and activated)
    return {'conditions': groups, 'required_skill_cases': required,
            'limits': 'Fixture-only decisions, no target completion/speed claims; semantic judgments require review.'}


def write_report(output: Path, cases: list[dict], results: list[dict], assessments: list[dict] = ()) -> None:
    """Combine measured calls with explicit semantic review, leaving unknowns null."""
    known = {(r['case'], r['condition'], r['repeat']): r for r in results}
    reviewed = {}
    for review in assessments:
        key = (review['case'], review['condition'], review['repeat'])
        if key not in known or key in reviewed or known[key]['status'] != 'completed':
            raise ValueError('Review must identify one unique completed run')
        if type(review.get('distinguishing_next_step')) is not bool:
            raise ValueError('Review needs a boolean distinguishing_next_step')
        if type(review.get('uncertainty_promotions')) is not int or review['uncertainty_promotions'] < 0:
            raise ValueError('Review needs a nonnegative uncertainty_promotions count')
        if 'memory' in known[key] and type(review.get('memory_preserved')) is not bool:
            raise ValueError('Compressed run requires a boolean memory_preserved assessment')
        if not review.get('rationale'):
            raise ValueError('Review needs evidence-based rationale')
        reviewed[key] = review
    summary = summarize(results)
    planned = len(cases) * REPEATS * len(CONDITIONS)
    summary.update(planned_runs=planned, recorded_runs=len(results), not_started=planned-len(results))
    summary['acceptance'] = []
    for condition in CONDITIONS:
        group_reviews = [v for k, v in reviewed.items() if k[1] == condition]
        summary['conditions'][condition]['reviewed_runs'] = len(group_reviews)
        summary['conditions'][condition]['uncertainty_promoted_to_fact'] = (
            sum(v['uncertainty_promotions'] for v in group_reviews) if group_reviews else None)
        completed = sum(r['condition'] == condition and r['status'] == 'completed' for r in results)
        summary['conditions'][condition]['semantic_review'] = (
            'complete' if group_reviews and len(group_reviews) == completed
            else 'partial' if group_reviews else 'pending')
        for case in cases:
            rows = [r for r in results if r['condition'] == condition and r['case'] == case['id']]
            reviews = [reviewed[(r['case'], condition, r['repeat'])] for r in rows
                       if (r['case'], condition, r['repeat']) in reviewed]
            expectation = case.get('skill_expectation', 'optional')
            skill_pass = None
            if len(rows) == REPEATS:
                if expectation == 'required':
                    skill_pass = summary['required_skill_cases'][condition+'/'+case['id']]['search_and_relevant_activation'] >= 2
                elif expectation in {'reuse', 'none'} and all(r['status'] == 'completed' for r in rows):
                    skill_pass = all(not any(t['name'] in {'skill_search', 'skill_invoke'} for t in r['trace']) for r in rows)
                elif expectation == 'no_match' and all(r['status'] == 'completed' for r in rows):
                    skill_pass = all(sum(t['name'] == 'skill_search' for t in r['trace']) <= 1
                                     and not r.get('active_skills') for r in rows)
            distinguishing_pass = None
            if len(rows) == REPEATS:
                passed = sum(v['distinguishing_next_step'] for v in reviews)
                remaining = sum(r['status'] == 'completed' for r in rows) - len(reviews)
                if passed >= 2:
                    distinguishing_pass = True
                elif passed + remaining < 2:
                    distinguishing_pass = False
            summary['acceptance'].append({
                'condition': condition, 'case': case['id'], 'holdout': case.get('holdout', False),
                'recorded_runs': len(rows), 'skill_expectation': expectation, 'skill_pass': skill_pass,
                'distinguishing_pass': distinguishing_pass,
                'memory_preserved': (all(v.get('memory_preserved') is True for v in reviews)
                                     if case.get('memory') and len(reviews) == REPEATS else None),
            })
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    pending = [{'case': r['case'], 'condition': r['condition'], 'repeat': r['repeat'],
                'distinguishing_next_step': None, 'uncertainty_promotions': None,
                'memory_preserved': None, 'rationale': ''} for r in results
               if r['status'] == 'completed' and (r['case'], r['condition'], r['repeat']) not in reviewed]
    (output / 'review-pending.json').write_text(json.dumps(pending, ensure_ascii=False, indent=2))
    lines = ['# Solver 受控回放差异报告', '',
             f'计划 {planned} 次；已记录 {len(results)} 次；未启动 {planned-len(results)} 次。', '',
             '| 条件 | 完成 / 错误 / 未完成 | Skill 搜索 | 新激活 | 已语义评审 | 不确定性升级为事实 |',
             '|---|---|---|---|---|---|']
    for name, values in summary['conditions'].items():
        status = values['status']
        count = values['uncertainty_promoted_to_fact']
        lines.append(f"| {name} | {status.get('completed',0)} / {status.get('error',0)} / {status.get('incomplete',0)} | {values['skill_search_runs']} | {values['activated_runs']} | {values['reviewed_runs']} | {count if count is not None else '待评审'} |")
    lines.extend(['', 'Skill 次数为调用轨迹事实，不代表决策正确。未运行、错误或未评审不计为通过。', '',
                  'summary.json 按场景记录 2/3 调用与下一步判断门槛，以及记忆保真结果；null 表示证据不足。',
                  'requests.jsonl / responses.jsonl 保存逐次模型交互；result.json 保存工具回执、恢复记忆及状态事件。', '',
                  '语义评审：填写 review-pending.json 中的判断、事实升级次数和证据理由，然后使用 --review-output 与 --assessments 重新生成报告。评审标准从未发给 Solver。', '',
                  '仅验证离线决策和 Skill 调用，不能据此声称云端完成率、耗时或成本改善。'])
    (output / 'report.md').write_text('\n'.join(lines)+'\n')


async def replay(args, cases):
    settings = AgentSettings()
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='aion-replay-baseline-') as temporary:
        baseline = extract_baseline(args.baseline, Path(temporary) / 'baseline')
        candidate = args.output / 'candidate'
        for name in ('prompts', 'skills'):
            shutil.copytree(args.candidate / 'agent' / name, candidate / 'agent' / name,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        variants = conditions(baseline, candidate)
        manifest = {'model': settings.llm_model, 'cases_sha256': sha(cases),
                    'baseline_archive_sha256': hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
                    'conditions': {v.name: v.fingerprint() for v in variants},
                    'repeats': REPEATS, 'planned_runs': len(cases) * REPEATS * len(CONDITIONS), 'max_model_calls_per_run': MAX_TURNS, 'concurrency': args.concurrency,
                    'decision_options': {**deepseek_agent_request_options(role='solver'), 'max_tokens': 4096},
                    'memory_options': {**deepseek_auxiliary_request_options(), 'max_tokens': 4096},
                    'scope': 'real Skill gateway, fixture receipts only, no external target operations'}
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        results = []
        semaphore = asyncio.Semaphore(args.concurrency)
        abort = asyncio.Event()
        async with httpx.AsyncClient(timeout=90) as client:
            async def one(condition, case, repeat):
                async with semaphore:
                    if abort.is_set():
                        return
                    identity = {'case': case['id'], 'condition': condition.name, 'repeat': repeat}
                    async def writer(kind, payload):
                        append(args.output / 'usage.jsonl', {**identity, 'event_type': kind, 'payload': payload})
                    async def model(purpose, messages, definitions):
                        options = manifest['memory_options' if purpose == 'memory' else 'decision_options']
                        body = {'model': settings.llm_model, 'messages': messages, **options}
                        if definitions:
                            body['tools'] = definitions
                        response = await post_model(client, completions_url(settings.llm_base_url), event_writer=writer,
                                                    purpose='decision_replay_' + purpose,
                                                    headers={'Authorization': 'Bearer ' + settings.llm_api_key.get_secret_value()}, json=body)
                        response.raise_for_status()
                        return response.json()
                    row = await run_case(condition, case, repeat, args.output / case['id'] / condition.name / str(repeat), model)
                    results.append(row)
                    append(args.output / 'results.jsonl', row)
                    print(json.dumps({**identity, 'status': row['status'], 'calls': row['model_calls']}), flush=True)
                    if row.get('http_status') in {401, 403}:
                        abort.set()
                    (args.output / 'summary.json').write_text(json.dumps(summarize(results), ensure_ascii=False, indent=2))
            jobs = []
            for index, case in enumerate(cases):
                for repeat in range(1, REPEATS + 1):
                    order = variants if (index + repeat) % 2 else list(reversed(variants))
                    jobs.extend(one(v, case, repeat) for v in order)
            await asyncio.gather(*jobs)
        write_report(args.output, cases, results)
        if abort.is_set():
            raise SystemExit('Model authorization failed; remaining runs were not started. See recorded HTTP status.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=ROOT / 'tests/fixtures/solver_decisions/cases.json')
    parser.add_argument('--baseline', type=Path, help='Pre-edit archive containing agent/prompts and agent/skills')
    parser.add_argument('--candidate', type=Path, default=ROOT, help='Candidate tree; prompt and Skill files are frozen into the output before calls')
    parser.add_argument('--output', type=Path, default=ROOT / '.aion/verification/solver-decisions')
    parser.add_argument('--concurrency', type=int, choices=range(1, 9), default=6)
    parser.add_argument('--review-output', type=Path, help='Rebuild a completed/partial replay report without model calls')
    parser.add_argument('--assessments', type=Path, help='JSON array of explicit semantic assessments')
    parser.add_argument('--live', action='store_true', help='Call configured model only; never target tools')
    args = parser.parse_args()
    cases = read_cases(args.cases)
    if args.review_output:
        if args.live:
            parser.error('--review-output and --live are mutually exclusive')
        manifest = json.loads((args.review_output / 'manifest.json').read_text())
        if manifest['cases_sha256'] != sha(cases):
            parser.error('Cases do not match the recorded replay')
        results = [json.loads(line) for line in (args.review_output / 'results.jsonl').read_text().splitlines()]
        assessments = json.loads(args.assessments.read_text()) if args.assessments else []
        write_report(args.review_output, cases, results, assessments)
    elif args.live:
        if not args.baseline:
            parser.error('--live requires --baseline; a current-only run cannot establish the three conditions')
        asyncio.run(replay(args, cases))
    else:
        print(json.dumps({'valid_cases': len(cases), 'planned_runs': len(cases) * REPEATS * len(CONDITIONS), 'model_calls': 0}))


if __name__ == '__main__':
    main()
