"""Paired skill discovery rehearsal: real model/registry, synthetic read-only evidence."""
from __future__ import annotations
import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from pydantic import BaseModel, ConfigDict, Field
from agent.config import AgentSettings, deepseek_agent_request_options
from agent.runner import AgentRunner
from agent.skills import SkillCatalog, SkillSessionContext, SkillTools
from agent.state import AgentStateStore
from agent.tooling import AccessClaim, ToolRegistry, ToolSpec
from agent.model_usage import aggregate_usage
from tools.pentest.models import SqlmapArguments
from tests.solver_state import build_state

SCENARIOS = {
    'sql': {
        'expected_skill': 'execution/sqli-sql-injection',
        'stages': [
            'A local search page accepts q. Normal request: GET /search?q=book, same identity, no CSRF; stable 200 response, 12 results, 20 ms. Read the next observation to investigate.',
            '同一客户端、身份、编码，仅修改 q，出现可复现参数差异和数据库报错（database error）。正常请求重复三次稳定；差异请求也重复三次稳定。还未检查错误是否来自实际查询层。'
        ],
        'expected': {'assessment':'sql_hypothesis', 'next_step':'validate_controls', 'sqlmap_warranted':True},
    },
    'state': {
        'expected_skill': 'common/web-ctf-flow',
        'stages': [
            'A local application accepts a normal login POST. A browser recorded the request and the resulting page. Read the next observation before interpreting the result.',
            '登录后页面报错 HTTP 500，Set-Cookie 设置了新的会话值。已知 /me 身份接口使用新 Cookie 返回该用户的正确 ID；匿名对照 /me 返回 401。服务端日志说明错误发生在页面模板渲染层。'
        ],
        'expected': {'assessment':'authenticated_render_error', 'next_step':'check_business_goal', 'sqlmap_warranted':False},
    },
    'control': {
        'expected_skill': None,
        'stages': [
            'The local fixture is a static product information page. No form or application parameters are exposed. Read its content before deciding whether a security hypothesis exists.',
            'Page content: SQL database products, PostgreSQL and MySQL. This is plain documentation. No database error, timing measurement or input differential has been observed; no additional evidence is available.'
        ],
        'expected': {'assessment':'insufficient_evidence', 'next_step':'no_scan', 'sqlmap_warranted':False},
    },
}

class Next(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Conclusion(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assessment: str
    next_step: str
    sqlmap_warranted: bool
    evidence: str = Field(min_length=1)

PROMPT = '''You are analyzing a synthetic Web competition fixture. Read both staged observations using fixture_next. Decide what the evidence supports and choose a useful next step. Skills and tools are available through the normal discovery gateway; use relevant instructions when helpful. Do not run target tests: this rehearsal ends at diagnosis and choice of the next experiment. Submit your answer with fixture_conclude, then finish.
assessment: sql_hypothesis | authenticated_render_error | insufficient_evidence
next_step: validate_controls | check_business_goal | no_scan
sqlmap_warranted means a bounded run could be considered after validating prerequisites, not a request to execute it. Base all conclusions on fixture evidence.'''

async def trial(root, scenario, enhanced, repeat, settings, catalog):
    root.mkdir(parents=True)
    service, _, _ = await build_state(root)
    ctx = SkillSessionContext(catalog, role='solver', service=service, run_id='run', agent_id='solver')
    stages = SCENARIOS[scenario]['stages']; observed=[]; answer={}; forbidden=[]; delivered_rounds=[]
    runner=None
    class Fixtures:
        def tool_specs(self):
            def next_observation(_):
                index=len(observed)
                if index>=len(stages): return {'ok':True,'data':{'eof':True,'message':'No further evidence.'}}
                observed.append(stages[index]); delivered_rounds.append(runner._current_round_number)
                return {'ok':True,'data':{'observation':stages[index],'stage':index+1,'eof':index+1==len(stages)}}
            def conclude(a):
                answer.update(a.model_dump())
                return {'ok':True,'data':{'terminal':True,'saved':True}}
            def scan(a):
                forbidden.append(a.model_dump())
                return {'ok':False,'error':{'stage':'execution','code':'rehearsal_no_execution','message':'No target requests are executed in this rehearsal.','details':{},'retry':{'allowed':False}}}
            return [ToolSpec('fixture_next','Read the next staged local observation. No network traffic.',Next,next_observation,lambda _: (AccessClaim('read','fixture'),)),
                    ToolSpec('fixture_conclude','Record the evidence-supported diagnosis and next step, then finish.',Conclusion,conclude,lambda _: (AccessClaim('write','fixture'),)),
                    ToolSpec('pentest_sqlmap','Bounded SQL injection detector; unavailable for execution in this read-only rehearsal.',SqlmapArguments,scan,lambda _: (AccessClaim('write','fixture'),))]
    registry=ToolRegistry([SkillTools(ctx),Fixtures()],compact=True)
    runner=AgentRunner(settings,registry,role='solver',agent_id='solver',parent_id='chief',state_service=service,
        run_root=root/'runs',max_rounds=12,session_timeout_seconds=120,system_context_provider=ctx.render_system_context,
        base_system_prompt='Analyze evidence carefully. Tool discovery provides schemas; use the exact argument names. A keyword or error status is not a verified vulnerability.',
        capability_awareness=enhanced)
    sampling=deepseek_agent_request_options(role='solver', context_budget=settings.context_budget)
    original_completion=runner._request_completion
    async def record_completion(client, messages, **kwargs):
        public_messages=[{k:v for k,v in m.items() if k not in {'reasoning_content','reasoning','thinking'}} for m in messages]
        with (root/'model_requests.jsonl').open('a') as output:
            output.write(json.dumps({'round':runner._current_round_number,'messages':public_messages,'tools':kwargs.get('tool_definitions'), 'sampling':sampling},ensure_ascii=False,default=str)+'\n')
        return await original_completion(client,messages,**kwargs)
    runner._request_completion=record_completion
    store=await AgentStateStore.open(service,run_id='run',agent_id='solver',run_dir=root/'runs/run')
    start=time.monotonic(); failure=None; final=''
    try:
        result=await asyncio.wait_for(runner.run_session(PROMPT,store=store),120)
        final=result.final
    except Exception as exc:
        failure={'type':type(exc).__name__,'code':getattr(exc,'code',None),'message':str(exc)[:300]}
    finally:
        await runner.close(); await registry.close()
    events=await service.list_agent_events('run','solver',limit=10000)
    calls=[e['payload'] for e in events if e['event_type']=='tool_call']
    results=[e['payload'] for e in events if e['event_type']=='tool_result']
    expected_skill=SCENARIOS[scenario]['expected_skill']
    activated=[e['payload'].get('skill_id') for e in events if e['event_type']=='skill_activated']
    activation_rounds=[c['round'] for c in calls if c['tool_name']=='skill_invoke' and c.get('arguments',{}).get('skill_id')==expected_skill]
    presented=[e['payload'] for e in events if e['event_type']=='capability_awareness_presented']
    # Baseline visibility comes from search result receipts; enhanced visibility can also come from its directory.
    visible_rounds=[p['round'] for p in presented if expected_skill and expected_skill in p['directory']]
    if expected_skill:
        visible_rounds += [r['round'] for r in results if r['tool_name'] in {'skill_search','skill_invoke'} and expected_skill in json.dumps(r.get('result',{}))]
    infrastructure=any(e['event_type']=='model_call_finished' and (e['payload'].get('http_status') in (401,403,429,500,502,503,504) or e['payload'].get('error')) for e in events)
    hashes=Counter(json.dumps([c['tool_name'],c.get('arguments')],sort_keys=True) for c in calls if c['tool_name']!='fixture_next')
    correct=len(observed)==2 and all(answer.get(k)==v for k,v in SCENARIOS[scenario]['expected'].items()) and not forbidden
    signal_round=delivered_rounds[1] if len(delivered_rounds)>1 else None
    def delay(rounds):
        return max(0,min(rounds)-signal_round) if rounds and signal_round is not None else None
    report={'variant':'after' if enhanced else 'before','scenario':scenario,'repeat':repeat,'model':settings.llm_model,
        'budget':{'rounds':12,'seconds':120},'sampling':sampling,'prompt_sha256':hashlib.sha256(PROMPT.encode()).hexdigest(),'catalog_sha256':catalog.content_sha256,
        'infrastructure_failure':bool(infrastructure),'error':failure,'elapsed_seconds':round(time.monotonic()-start,2),
        'expected_skill':expected_skill,'capability_presented':bool(visible_rounds) if expected_skill else None,
        'skill_activated':expected_skill in activated if expected_skill else None,'activated_skills':activated,
        'signal_round':signal_round,'discovery_delay_rounds':delay(visible_rounds),'activation_delay_rounds':delay(activation_rounds),
        'irrelevant_activation':bool(activated) if scenario=='control' else any(s not in ({expected_skill,'execution/src-auth-business-logic'} if scenario=='state' else {expected_skill}) for s in activated),
        'correct':None if infrastructure else bool(correct and not failure),'forbidden_scan_attempts':len(forbidden),
        'duplicate_calls':sum(n-1 for n in hashes.values()),'tool_failures':sum(r.get('result',{}).get('ok') is False for r in results),
        'tool_calls':dict(Counter(c['tool_name'] for c in calls)),'answer':answer,'final':final,
        'usage':aggregate_usage(events,[{'agent_id':'solver','unique_code':'a'}]),'events':events}
    (root/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str))
    await service.close()
    print(json.dumps({k:report[k] for k in ['variant','scenario','repeat','correct','skill_activated','error','elapsed_seconds']},ensure_ascii=False),flush=True)
    return report

async def main(args):
    args.output.mkdir(parents=True,exist_ok=False)
    settings=AgentSettings(); catalog=SkillCatalog(); reports=[]
    files=['agent/runner.py','agent/skills/awareness.py','agent/skills/session.py','scripts/evaluate_skill_awareness.py']
    manifest={'files':{f:hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in files}, 'model':settings.llm_model, 'catalog_sha256':catalog.content_sha256, 'comparison':'same runtime, awareness off/on', 'sampling':deepseek_agent_request_options(role='solver',context_budget=settings.context_budget)}
    (args.output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    for scenario in SCENARIOS:
        for repeat in range(3):
            for enhanced in ([False,True] if repeat%2==0 else [True,False]):
                reports.append(await trial(args.output/f'{scenario}-{repeat}-{"after" if enhanced else "before"}',scenario,enhanced,repeat,settings,catalog))
                (args.output/'summary.json').write_text(json.dumps([{k:v for k,v in r.items() if k!='events'} for r in reports],ensure_ascii=False,indent=2,default=str))
    lines=['# Skill awareness rehearsal','', 'Same model, prompts, skills and tool surface; only awareness differs. Synthetic evidence only; no target scans. Three repeats per scenario and variant. Small sample, not a solve-speed claim.','', '| Variant | Scenario | Valid | Correct | Relevant skill activated | Capability shown |', '|---|---|---:|---:|---:|---:|']
    for variant in ['before','after']:
        for scenario in SCENARIOS:
            rs=[r for r in reports if r['variant']==variant and r['scenario']==scenario and not r['infrastructure_failure']]
            lines.append(f"| {variant} | {scenario} | {len(rs)} | {sum(r['correct'] is True for r in rs)} | {sum(r['skill_activated'] is True for r in rs)} | {sum(r['capability_presented'] is True for r in rs)} |")
    lines += ['', 'Zero activations is the expected behavior for the unrelated control. See summary.json for latency, token usage, errors, repetitions and individual outcomes. Infrastructure failures are excluded from behavior counts.']
    (args.output/'report.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    asyncio.run(main(parser.parse_args()))
