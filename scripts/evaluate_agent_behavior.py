"""Paired real-model decisions on local fixtures. No challenge/platform access.

Uses real filesystem/Shell and FastCGI tools. Worker scenario uses real model
Workers with a bounded in-process delivery adapter; production scheduling and
wakeups are tested separately. Scores are explicit fixture checks, not a judge.
"""
import argparse
import asyncio
from collections import Counter
import json
from pathlib import Path
import time

from pydantic import BaseModel
from agent.config import AgentSettings
from agent.prompts import system_prompt
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.subagents.models import DelegateArguments
from agent.tooling import ToolRegistry, ToolSpec, AccessClaim
from agent.model_usage import aggregate_usage
import agent.tool_surface as surface
from tests.solver_state import build_state
from tests.test_fastcgi import server, frame, end, decode_pairs
from tools.fastcgi import FastCGITools
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy


class Empty(BaseModel):
    pass


async def trial(root, baseline, variant, scenario, repeat):
    root.mkdir(parents=True)
    settings = AgentSettings()
    service, _, solver_context = await build_state(root)
    manager = ShellTaskManager(WorkspacePolicy(root), service, 'run', reap_interval_seconds=0)
    await manager.initialize()
    shell = manager.bind('solver', shared_root=manager.shared_workspace_root('a'))
    await shell.ensure_workspace()
    work = shell.agent_work_root
    (work/'known.txt').write_text('A complete prior read established marker ALPHA and checksum 71.\n')
    (work/'next.txt').write_text('Final marker OMEGA; checksum 71.\n')
    (work/'parser.py').write_text('def size(n):\n    return n.to_bytes(4, "big")  # always four bytes, no marker\n')
    (work/'policy.txt').write_text('Lengths below 128 use one byte; longer lengths use four bytes with the top bit set.\n')
    (work/'probe.py').write_text('import http.client\nsent=0\nfor value in ["a", "b", "c"]:\n    try:\n        encoded=http.client.quote(value)\n        sent+=1\n    except Exception:\n        pass\nprint("scan complete; no hits")\n')
    provider = SystemTools(root=root, shell=shell, agent_work_root=work, shared_work_root=shell.shared_work_root)
    jobs = {}; delivered = []; child_runners = []; runner = None; protocol_requests=[]
    async def delegate(args):
        admissions = await service.delegate_workers('run', solver_context, args.tasks)
        for admission in admissions['admissions']:
            aid = admission['agent_id']
            if aid in jobs: continue
            spec = next(task for task in args.tasks if task.task_key == admission['task_key'])
            async def child(aid=aid, spec=spec):
                reg = ToolRegistry([provider], compact=True, allowed_tools={'system_read_file','system_grep'} if spec.mode == 'execute' else set())
                child_runner = AgentRunner(settings,reg,role='worker',agent_id=aid,parent_id='solver',
                    state_service=service,run_root=root/'runs',max_rounds=4,session_timeout_seconds=60,
                    base_system_prompt=(baseline/'worker.txt').read_text() if variant=='before' else system_prompt('worker'))
                child_runners.append(child_runner)
                store = await AgentStateStore.open(service,run_id='run',agent_id=aid,run_dir=root/'runs/run')
                result = await child_runner.run_session(f'Local read-only review. Workspace {work}. {spec.objective}. Supplied local material: parser.py={ (work/"parser.py").read_text()!r}; policy.txt={ (work/"policy.txt").read_text()!r}. Report the length-encoding defect with file references. Return your report as final text.',store=store)
                return {'worker_id':aid,'summary':result.final}
            jobs[aid] = asyncio.create_task(child())
        return {'ok':True,'data':admissions}
    async def observe(_):
        reports=[]
        for aid, job in jobs.items():
            if job.done() and not job.cancelled():
                reports.append(job.result());delivered.append(aid)
        return {'ok':True,'data':{'reports':reports,'running':[aid for aid,j in jobs.items() if not j.done()]}}
    async def wait(_):
        if jobs: await asyncio.gather(*jobs.values())
        return await observe(_)
    class Controls:
        def tool_specs(self):
            return [ToolSpec('solver_delegate','Delegate independent review with task_key, objective, context_refs and success_criteria.',DelegateArguments,delegate,lambda _: (AccessClaim('write','workers'),)),
                    ToolSpec('solver_observe','Read completed Worker reports.',Empty,observe,lambda _: (AccessClaim('read','workers'),)),
                    ToolSpec('solver_wait','Wait for active Workers and read reports.',Empty,wait,lambda _: (AccessClaim('write','workers'),))]
    async def protocol(request, reader, writer):
        params=decode_pairs(request[1][4]);protocol_requests.append(params)
        writer.write(frame(6,b'Status: 200 OK\r\n\r\nLOCAL_PROTOCOL_OK')+end());await writer.drain()
    start=time.monotonic();error=None;final=''
    async with server(protocol) as port:
        tasks={
            'protocol':f'Inspect the local PHP-FPM protocol fixture at 127.0.0.1:{port}. Its script path is /fixture/health.php. Establish its response and report the returned marker. Use only this local target.',
            'bad_script':'A previous run of probe.py reported "scan complete; no hits" almost instantly. Determine whether this excludes the target. Inspect and repair the local three-item encoding diagnostic; report actual attempted/success/error counts, and distinguish this diagnostic from target coverage. No network requests are needed.',
            'reuse':'Prior complete read receipt: known.txt offset=0, eof=true; content="A complete prior read established marker ALPHA and checksum 71." This is already read, unchanged evidence. Determine whether next.txt agrees on checksum, and report its final marker. Minimize redundant reads.',
            'worker':'Two independent work items: review parser.py against policy.txt for a length-encoding defect, and check next.txt against known checksum 71. Complete both, with an independent review report and your own checksum check; use the available collaboration tools when useful.'}
        previous = surface.DIRECT_TOOLS
        if variant=='before': surface.DIRECT_TOOLS=frozenset(json.loads((baseline/'direct_tools.json').read_text()))
        try:
            registry=ToolRegistry([provider,FastCGITools(),Controls()],compact=True,allowed_tools={
                'system_read_file','system_write_file','system_edit_file','system_shell','system_grep',
                'system_fastcgi_request','solver_delegate','solver_observe','solver_wait'})
        finally: surface.DIRECT_TOOLS=previous
        runner=AgentRunner(settings,registry,role='solver',agent_id='solver',parent_id='chief',
            state_service=service,run_root=root/'runs',max_rounds=8,session_timeout_seconds=90,
            base_system_prompt=(baseline/'solver.txt').read_text() if variant=='before' else system_prompt('solver'))
        store=await AgentStateStore.open(service,run_id='run',agent_id='solver',run_dir=root/'runs/run')
        try:
            result=await asyncio.wait_for(runner.run_session(f'Local synthetic fixture only, workspace {work}. No external target or platform access. Finish with a concise report.\n'+tasks[scenario],store=store),100)
            final=result.final
        except Exception as exc: error=type(exc).__name__
        finally:
            for job in jobs.values():
                if not job.done():job.cancel()
            await asyncio.gather(*jobs.values(),return_exceptions=True)
            await runner.close()
            for child_runner in child_runners:await child_runner.close()
    events=await service.list_agent_events('run','solver',limit=10000)
    all_events=list(events)
    for aid in jobs: all_events.extend(await service.list_agent_events('run',aid,limit=10000))
    calls=[e['payload'] for e in events if e['event_type']=='tool_call']
    names=Counter(c.get('tool_name') for c in calls)
    reads=[c.get('arguments',{}).get('file_path','') for c in calls if c.get('tool_name')=='system_read_file']
    outputs='\n'.join(str(e['payload'].get('result',{}).get('data',{}).get('output','')) for e in events if e['event_type']=='tool_result')
    checks={
        'protocol': bool(names['system_fastcgi_request'] and protocol_requests and 'LOCAL_PROTOCOL_OK' in final),
        'bad_script': bool((names['system_edit_file'] or names['system_write_file']) and names['system_shell'] and ('3' in outputs) and ('quote' in final or '异常' in final or 'error' in final.lower())),
        'reuse': not any(Path(p).name=='known.txt' for p in reads) and 'OMEGA' in final and '71' in final,
        'worker': bool(jobs and delivered and '71' in final and ('128' in final or '编码' in final or 'length' in final.lower()))}
    infrastructure_failure=any(e['event_type']=='model_call_finished' and e['payload'].get('http_status') in (401,403) for e in all_events)
    report={'variant':variant,'scenario':scenario,'repeat':repeat,'model':settings.llm_model,
        'budget':{'solver_rounds':8,'solver_seconds':90,'worker_rounds':4,'worker_seconds':60},
        'passed':None if infrastructure_failure else checks[scenario] and error is None,'error':error,
        'infrastructure_failure':infrastructure_failure,'seconds':round(time.monotonic()-start,2),
        'tool_calls':dict(names),'duplicate_read_calls':sum(v-1 for v in Counter(reads).values()),
        'correction_errors':sum(e['payload'].get('result',{}).get('ok') is False for e in events if e['event_type']=='tool_result'),
        'usage':aggregate_usage(all_events,[{'agent_id':'solver','unique_code':'a'},*[{'agent_id':a,'unique_code':'a'} for a in jobs]]),
        'final':final,'events':all_events,'worker_delivery_adapter':True}
    (root/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str))
    await manager.finish_run();await service.close()
    print(json.dumps({k:report[k] for k in ['variant','scenario','repeat','passed','error','seconds']},ensure_ascii=False),flush=True)
    return report


async def main(args):
    reports=[]
    for scenario in ['protocol','bad_script','reuse','worker']:
        for repeat in range(3):
            order=['before','after'] if repeat%2==0 else ['after','before']
            for variant in order:
                root=args.output/f'{scenario}-{repeat}-{variant}'
                if (root/'report.json').exists():
                    previous=json.loads((root/'report.json').read_text())
                    if previous.get('error'): raise SystemExit('Existing failed trial: preserve it and choose a fresh output directory.')
                    reports.append(previous)
                    continue
                report=await trial(root.resolve(),args.baseline.resolve(),variant,scenario,repeat)
                reports.append(report)
                if report['infrastructure_failure']:
                    raise SystemExit('Model authentication failed; evaluation stopped. Fix local model credentials and use a fresh output directory; infrastructure failures are not behavioral scores.')
    summary=[{k:r[k] for k in ['variant','scenario','repeat','passed','error','seconds','tool_calls','duplicate_read_calls','correction_errors','usage']} for r in reports]
    (args.output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--baseline',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    asyncio.run(main(parser.parse_args()))
