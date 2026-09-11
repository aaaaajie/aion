"""Six bounded, clean local trials: old versus enhanced tool surfaces.

The runtime/model are held constant. This measures tool availability, not a
historical binary release or a claim of general solve-rate improvement.
"""
import argparse
import asyncio
from collections import Counter
import hashlib
import json
from pathlib import Path
import threading
import time
import sys
from http.server import ThreadingHTTPServer

from agent.config import AgentSettings
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.tooling import ToolRegistry
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy
from tools.http import HttpProbeManager, HttpTools
from tools.browser import BrowserTools
from tools.source import SourceTools
from tests.solver_state import build_state
from tests.resource_runtime import install_resource_runtime
from scripts.check_enhanced_toolchain import Fixture


def tool_failed(result):
    data = result.get('data', {})
    return result.get('ok') is False or data.get('exit_code') not in (None, 0) or data.get('status') in {'failed', 'timed_out'}


def parse_answer(text):
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != '{':
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except ValueError:
            continue
        if isinstance(value, dict) and {'authenticated', 'source_file', 'line'} <= value.keys():
            return value
    return {}


async def trial(root, enhanced, repeat, settings):
    root.mkdir(parents=True)
    service, _, _ = await build_state(root)
    shell_manager = ShellTaskManager(WorkspacePolicy(root), service, 'run', reap_interval_seconds=0,
        read_only_paths=(Path(sys.prefix), Path(__file__).resolve().parents[1] / 'tools' / 'source'))
    await shell_manager.initialize()
    shell = shell_manager.bind('solver', shared_root=shell_manager.shared_workspace_root('a'))
    await shell.ensure_workspace()
    preflight = await shell.run_shell('true')
    if preflight.get('exit_code') != 0:
        raise RuntimeError('Shell preflight failed; do not score model behavior')
    work = shell.agent_work_root
    (work / 'src').mkdir()
    (work / 'src' / 'reader.py').write_text('def read_user_path(path):\n    return open(path).read()\n')
    http = HttpProbeManager(WorkspacePolicy(root), service, 'run', disk_reserve_bytes=0, disk_reserve_percent=0)
    await http.initialize()
    install_resource_runtime(http, service, 'run', root=root)
    providers = [SystemTools(root=root, shell=shell, agent_work_root=work, shared_work_root=shell.shared_work_root),
                 HttpTools(http.bind('solver', workspace_root=work))]
    before = {'system_read_file', 'system_grep', 'system_shell', 'system_task_output',
              'system_http_request', 'system_http_output', 'system_http_response', 'system_http_analyze'}
    if enhanced:
        providers.extend([BrowserTools(work), SourceTools(shell)])
    allowed = before | ({'system_http_replay', 'system_http_compare', 'system_browser_open',
        'system_browser_action', 'system_browser_output', 'system_browser_export_request',
        'system_browser_close', 'system_source_scan'} if enhanced else set())
    registry = ToolRegistry(providers, allowed_tools=allowed, compact=True)
    request_keys = []
    authenticated_api = []
    class RecordedFixture(Fixture):
        def do_GET(self):
            request_keys.append(('GET', self.path))
            if self.path == '/api' and 'session=fixture' in self.headers.get('Cookie', ''):
                authenticated_api.append(True)
            super().do_GET()
        def do_POST(self):
            request_keys.append(('POST', self.path))
            super().do_POST()
    server = ThreadingHTTPServer(('127.0.0.1', 0), RecordedFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    prompt = f'''Use only the local synthetic fixture http://127.0.0.1:{server.server_port}/ and workspace {work}.
Establish a normal login, obtain the authenticated /api response, and review src/reader.py to identify its file-read operation and line number. Do not exploit anything or access external targets. Discover available tools and finish with a concise evidence-backed report. Your final response must be only a JSON object with keys authenticated (boolean), source_file (string), line (integer), and evidence (string). No historical answers are provided.'''
    runner = AgentRunner(settings, registry, role='solver', agent_id='solver', parent_id='chief',
        state_service=service, run_root=root / 'runs', max_rounds=16, session_timeout_seconds=180,
        base_system_prompt='You are verifying a local application fixture. Use tools to establish evidence, then report it. Tool search returns exact schemas. Do not assume success from HTTP status alone.')
    store = await AgentStateStore.open(service, run_id='run', agent_id='solver', run_dir=root / 'runs' / 'run')
    start = time.monotonic(); final = ''; failure = None
    try:
        result = await runner.run_session(prompt, store=store)
        final = result.final
    except Exception as exc:
        failure = type(exc).__name__
    finally:
        await runner.close()
        await registry.close()
        await http.finish_run()
        await shell_manager.finish_run()
        server.shutdown(); server.server_close()
    events = await service.list_agent_events('run', 'solver', limit=10000)
    calls = Counter(e['payload'].get('tool_name') for e in events if e['event_type'] == 'tool_call')
    infrastructure = bool(failure) and any(e['event_type'] == 'model_call_finished' and (e['payload'].get('error') or e['payload'].get('http_status') in (401,403,429,500,502,503,504)) for e in events)
    answer = parse_answer(final)
    report = {'variant': 'after' if enhanced else 'before', 'repeat': repeat, 'model': settings.llm_model,
              'comparison': 'tool_surface_ablation_same_runtime', 'budget': {'rounds':16,'seconds':180},
              'completed': None if infrastructure else (not failure and bool(authenticated_api) and answer.get('authenticated') is True and str(answer.get('source_file', '')).endswith('reader.py') and answer.get('line') == 2),
              'authenticated_api_observed': bool(authenticated_api),
              'infrastructure_failure': infrastructure, 'error': failure, 'elapsed_seconds': round(time.monotonic()-start,2),
              'tool_calls': dict(calls), 'requests': len(request_keys),
              'duplicate_requests': sum(n-1 for n in Counter(request_keys).values()),
              'tool_failures': sum(tool_failed(e['payload'].get('result', {})) for e in events if e['event_type']=='tool_result'),
              'final': final, 'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest()}
    (root / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    await service.close()
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return report


async def main(output):
    from tools.system.cgroups import prepare, cleanup
    group, _ = prepare('evaluation-preflight')
    cleanup(group)
    settings = AgentSettings()
    reports = []
    for repeat in range(3):
        for enhanced in ([False, True] if repeat % 2 == 0 else [True, False]):
            report = await trial(output / f'{repeat}-{"after" if enhanced else "before"}', enhanced, repeat, settings)
            reports.append(report)
            (output / 'summary.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2))
            if report['infrastructure_failure']:
                raise SystemExit('Model infrastructure failure; stop without assigning a behavioral score.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    asyncio.run(main(parser.parse_args().output.resolve()))
