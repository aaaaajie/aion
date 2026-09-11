"""Opt-in natural-task acceptance; real model, production prompts and providers.

Parent-run only: AION_LIVE_NATURAL_TOOL_ACCEPTANCE=1 pytest -q <this file>.
No credentials are created here. Reports are append-only, including failed runs.
"""

import json
import os
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from agent.config import AgentSettings
from agent.execution_facts import project_execution
from agent.model_usage import aggregate_usage
from agent.prompts import system_prompt
from agent.runner import AgentRunner
from agent.state import AgentStateStore
from agent.subagents.supervisor import AgentSupervisor
from agent.subagents.tools import AgentControlTools
from agent.tooling import ToolRegistry, ToolResultStore, ToolResultTools
from tests.resource_runtime import install_resource_runtime
from tests.solver_state import build_state
from tools.http import HttpProbeManager, HttpTools
from tools.http.manager import AgentHttpClient
from tools.system.policy import WorkspacePolicy

pytestmark = [pytest.mark.live, pytest.mark.skipif(
    os.environ.get("AION_LIVE_NATURAL_TOOL_ACCEPTANCE") != "1",
    reason="natural-task real-model acceptance is opt-in",
)]


@pytest.fixture
def local_target():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            path = urlsplit(self.path).path
            if path.startswith("/step/") and path.rsplit("/", 1)[-1].isdigit():
                step = int(path.rsplit("/", 1)[-1])
                data = {"step": step, "observation": "未经校准的合成回执",
                        "next": f"/step/{step + 1}" if step < 5 else None}
            else:
                data = {"path": path, "query": parse_qs(urlsplit(self.path).query),
                        "observation": "合成响应，不代表真实应用行为"}
            body = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def natural_task(url):
    return (
        f"只测试本地合成服务 {url}，不要访问其他目标。"
        "先用一次有限矩阵实验比较路径 /alpha、/beta 与查询参数 mode 的两个值 "
        "light、full 的全部组合；每种组合恰好请求一次，最多并发两个请求。"
        "读取四份完整响应正文。随后从 /step/1 开始逐项获取回执，每次必须先读完"
        "响应正文，再仅访问其中 next 指定的下一地址，直到 next 为空；不猜测"
        "后续地址，不重发已完成的请求。这些响应都是未经校准的合成回显，"
        "没有已知对照，不能验证真实应用实现。完成后整理本轮事实、仍不能判断"
        "的部分和下一项最小验证，随后结束。"
    )


def assess(events, state, requests):
    calls = [e for e in events if e["event_type"] == "tool_call"]
    results = [e for e in events if e["event_type"] == "tool_result"]
    plans = [e for e in results if e["payload"].get("tool_name") == "system_http_plan"
             and e["payload"].get("result", {}).get("ok")]
    executions = [e for e in results if e["payload"].get("tool_name") in {
        "system_http_request", "system_http_probe"} and e["payload"].get("result", {}).get("ok")]
    assertions = {
        "real_model_calls_recorded": any(e["event_type"] == "model_call_finished" for e in events),
        "nine_full_bodies_read": sum(r["complete"] for r in state["execution"]["body_reads"]) == 9,
        "no_unread_tasks": not state["execution"]["tasks"],
        "no_unreviewed_results": not state["execution"]["unreviewed_results"],
    }
    expected = Counter((path, (mode,)) for path in ("/alpha", "/beta")
                       for mode in ("light", "full"))
    matrix_requests = [p for p in requests if not p.startswith("/step/")]
    actual = Counter((urlsplit(p).path, tuple(parse_qs(urlsplit(p).query).get("mode", [])))
                     for p in matrix_requests)
    assertions["exact_matrix_traffic"] = actual == expected
    assertions["plan_adopted_before_execution"] = bool(plans and executions) and plans[0]["sequence"] < executions[0]["sequence"]
    for name in ("system_http_plan", "system_http_probe"):
        uses = [e for e in calls if e["payload"].get("tool_name") == name]
        discoveries = [e for e in calls if e["payload"].get("tool_name") == "tool_search"
                       and e["payload"].get("arguments", {}).get("name") == name]
        assertions[f"exact_schema_before_{name}"] = bool(uses and discoveries) and discoveries[0]["sequence"] < uses[0]["sequence"]
    reviews = [e for e in events if e["event_type"] == "solver_review_record"]
    reminders = [e for e in events if e["event_type"] == "solver_review_delivered"
                 and e["payload"].get("automatic_review_recommended")]
    # Completion authority is the first native event, not necessarily the later
    # tool-result event. Use the same coverage projection as the runtime.
    adopted = [e for e in reviews if not project_execution(
        events, set(e["payload"]["review"]["covered_sequences"])
    )["unreviewed_results"]]
    assertions.update({
        "six_fresh_executions": len(executions) == 6,
        "matrix_then_ordered_traffic": len(requests) == 9
            and requests[4:] == [f"/step/{i}" for i in range(1, 6)],
        "ordinary_requests_without_plan": bool(executions) and not any(
            e["payload"].get("tool_name") == "system_http_plan"
            and e["sequence"] > executions[0]["sequence"] for e in calls),
        "automatic_reminder_delivered": bool(reminders),
        "review_covers_six_results": bool(adopted),
        "uncalibrated_review_is_inconclusive": bool(adopted) and all(
            e["payload"]["review"]["assessment"] == "inconclusive"
            and e["payload"]["review"].get("validation") is None for e in adopted),
        "prompt_review_after_reminder": bool(reminders and adopted)
            and reminders[0]["sequence"] < adopted[0]["sequence"]
            and sum(e["event_type"] == "model_call_started"
                    and reminders[0]["sequence"] < e["sequence"] < adopted[0]["sequence"]
                    for e in events) <= 2,
    })
    return assertions


async def test_live_natural_tool_use(tmp_path, local_target):
    scenario = "matrix-and-six-results"
    settings = AgentSettings()
    service, _, _ = await build_state(tmp_path)
    url, requests = local_target
    manager = HttpProbeManager(WorkspacePolicy(tmp_path), service, "run")
    runner = None
    assertions = {"passed": False}
    prompt = natural_task(url)
    report_root = Path(os.environ.get("AION_ACCEPTANCE_REPORT_DIR", ".aion/verification/tool-usability"))
    report_root.mkdir(parents=True, exist_ok=True)
    report_path = report_root / f"live-natural-{scenario}-{uuid4().hex}.json"
    try:
        await manager.initialize()
        install_resource_runtime(manager, service, "run", root=tmp_path)
        supervisor = AgentSupervisor(settings, state_service=service, project_root=tmp_path,
                                     run_root=tmp_path / "runs")
        supervisor.run_id = "run"
        supervisor.chief_agent_id = "chief"
        await supervisor._sync_nodes()
        supervisor._issue_capabilities()
        run_dir = tmp_path / "runs/run"
        registry = ToolRegistry([
            HttpTools(AgentHttpClient(manager, "solver")),
            AgentControlTools(supervisor, agent_id="solver", role="solver"),
            ToolResultTools(ToolResultStore(run_dir, "solver")),
        ], compact=True, allowed_tools={
            "system_http_request", "system_http_probe", "system_http_plan",
            "system_http_output", "system_http_response", "tool_result_read", "solver_review",
        })
        runner = AgentRunner(settings, registry, role="solver", agent_id="solver", parent_id="chief",
                             state_service=service, run_root=tmp_path / "runs", max_rounds=20,
                             session_timeout_seconds=180, base_system_prompt=system_prompt("solver"))
        store = await AgentStateStore.open(service, run_id="run", agent_id="solver", run_dir=run_dir)
        await runner.run_session(prompt, store=store)
        events = await service.list_agent_events("run", "solver", limit=10000)
        state = await service.solver_review_state("run", "solver")
        assertions = assess(events, state, requests)
        assert all(assertions.values()), assertions
    except Exception as exc:
        assertions.update(passed=False, error_type=type(exc).__name__)
        raise
    finally:
        try:
            events = await service.list_agent_events("run", "solver", limit=10000)
            report = {"scenario": scenario, "model": settings.llm_model, "task": prompt,
                      "assertions": assertions, "requests": requests,
                      "token_usage": aggregate_usage([{**e, "agent_id": "solver"} for e in events],
                                                     [{"agent_id": "solver", "unique_code": "a"}]),
                      "events": [{k: e[k] for k in ("sequence", "event_type", "payload")}
                                 for e in events if e["event_type"] in {
                                     "model_call_started", "model_call_finished", "tool_call", "tool_result",
                                     "solver_review_delivered", "solver_review_record", "assistant_response",
                                     "http_interaction_status_changed", "shell_task_finished", "agent_resources_invalidated"}]}
            with report_path.open("x", encoding="utf-8") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
            print(f"Natural tool acceptance report: {report_path}")
        finally:
            try:
                if runner is not None:
                    await runner.close()
            finally:
                try:
                    await manager.finish_run()
                finally:
                    await service.close()
