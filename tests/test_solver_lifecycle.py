"""Offline integration tests through the real Runner, tools and state service."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from agent.config import AgentSettings
from agent.state import (
    StateService,
    StateDatabase,
    CapabilityContext,
    WorkerTaskInput,
    AgentReportInput,
)
from agent.state.errors import StateConflict, StatePermission
from agent.subagents import AgentSupervisor
from agent.subagents.tools import AgentControlTools
from agent.tooling import ToolExecutor, ToolRegistry
from tests.benchmark_tools import benchmark_tool_specs


class Platform:
    def __init__(self, flags=1):
        self.flags = flags
        self.accepted = 0
        self.running = False
        self.submissions = []
        self.close_calls = 0

    def tool_specs(self):
        return benchmark_tool_specs(self.dispatch)

    async def dispatch(self, name, args):
        if name == "benchmark_list_challenges":
            return {
                "ok": True,
                "data": [
                    {
                        "unique_code": "a",
                        "description": "Read shared/answer.txt and submit its exact contents.",
                        "difficulty": "easy",
                        "level": 1,
                        "total_score": 100,
                        "flag_count": self.flags,
                        "correct_flag_count": self.accepted,
                        "is_completed": self.accepted == self.flags,
                        "container_status": "running" if self.running else "stopped",
                        "container_addr": [],
                    }
                ],
            }
        if name == "benchmark_start_challenge":
            self.running = True
            return {
                "ok": True,
                "data": {"container_status": "running", "container_addr": []},
            }
        if name == "benchmark_submit_flag":
            self.submissions.append(args["flag"])
            self.accepted += 1
            return {
                "ok": True,
                "data": {
                    "correct": True,
                    "correct_flag_count": self.accepted,
                    "total_flag_count": self.flags,
                    "awarded": 100 // self.flags,
                },
            }
        if name == "benchmark_close_challenge":
            self.close_calls += 1
            self.running = False
            return {"ok": True, "data": {"closed": True}}
        raise AssertionError(name)


def completion(name=None, arguments=None, *, content=""):
    message = {
        "role": "assistant",
        "content": content,
        "reasoning_content": "offline fixture",
    }
    if name:
        message["tool_calls"] = [
            {
                "id": "call-" + name,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments or {})},
            }
        ]
    return {
        "choices": [
            {"message": message, "finish_reason": "tool_calls" if name else "stop"}
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 10,
            "prompt_cache_hit_tokens": 40,
            "prompt_cache_miss_tokens": 60,
        },
    }


async def harness(
    tmp_path,
    solver_model,
    *,
    flags=1,
    platform=None,
    resume=False,
    observation_model=None,
    compact_tools=True,
    solver_observation=True,
    selected_challenge_codes=None,
):
    platform = platform or Platform(flags)
    shared = tmp_path / ".aion/runs/run/shared/a"
    shared.mkdir(parents=True, exist_ok=True)
    (shared / "answer.txt").write_text("flag{offline_fixture}")
    service = StateService(
        StateDatabase(tmp_path / "runs" / "run" / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path,
    )
    await service.initialize()
    calls = {"solver": 0, "chief": 0, "worker": 0}

    async def model(request):
        body = json.loads(request.content)
        if not body.get("tools"):
            if observation_model and "只读旁路观察者" in body["messages"][0]["content"]:
                result = observation_model(body)
                if hasattr(result, "__await__"):
                    result = await result
                return httpx.Response(200, json=result)
            return httpx.Response(
                200,
                json=completion(
                    content="Stable facts: preserve evidence references and active tasks."
                ),
            )
        names = {t["function"]["name"] for t in body["tools"]}
        role = (
            "chief"
            if "chief_observe" in names
            else "solver" if "solver_observe" in names else "worker"
        )
        index = calls[role]
        calls[role] += 1
        if role == "chief":
            result = completion("chief_wait")
        else:
            result = solver_model(role, index, body)
            if hasattr(result, "__await__"):
                result = await result
        return httpx.Response(200, json=result)

    supervisor = AgentSupervisor(
        AgentSettings(
            llm_base_url="https://model.test",
            llm_model="fixture",
            llm_api_key="fixture",
            compact_tools=compact_tools,
            solver_observation=solver_observation,
            selected_challenge_codes=selected_challenge_codes,
        ),
        benchmark=platform,
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        state_service=service,
        catalog_reconcile_interval_seconds=0,
    )
    supervisor._model_http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(model)
    )
    chief = await supervisor.prepare_chief(
        "Solve the offline fixture.", run_id="run", resume=resume
    )
    return supervisor, service, platform, calls, chief


async def tool(supervisor, agent_id, name, arguments):
    agent = (await supervisor._service().get_agent_runtime("run", agent_id))["agent"]
    registry = ToolRegistry(
        [
            AgentControlTools(
                supervisor, agent_id=agent_id, role=agent["role"], mode=agent["mode"]
            )
        ]
    )
    result = await ToolExecutor(registry).execute(
        [
            {
                "id": "fixture-call",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ]
    )
    return result[0]


@pytest.mark.asyncio
async def test_real_runner_solves_without_worker_and_releases_resources(tmp_path):
    def solve(role, index, body):
        if index == 0:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if index == 1:
            assert "flag{offline_fixture}" in json.dumps(body)
            return completion("solver_submit_flag", {"flag": "flag{offline_fixture}"})
        return completion(content="The platform confirmed completion.")

    supervisor, service, platform, calls, chief = await harness(tmp_path, solve)
    try:
        started = await supervisor.create_solver(chief, "a")
        assert started["ok"], started
        solver = started["data"]["agent_id"]
        await asyncio.wait_for(supervisor._tasks[solver], 10)
        overview = await service.get_overview("run")
        assert [a["role"] for a in overview["agents"]].count("solver") == 1
        assert not [a for a in overview["agents"] if a["role"] == "worker"]
        assert overview["challenges"][0]["is_completed"]
        assert platform.submissions == ["flag{offline_fixture}"]
        assert calls["solver"] == 2
        if supervisor._challenge_completion_tasks:
            await asyncio.gather(*supervisor._challenge_completion_tasks.values())
        assert platform.close_calls == 1
        assert solver not in supervisor._registries
        events = await service.list_agent_events("run", solver)
        assert any(e["event_type"] == "evidence_persisted" for e in events)
        assert not any(
            "observer" in e["event_type"] or "bootstrap" in e["event_type"]
            for e in events
        )
    finally:
        await supervisor.close()
        await service.close()


@pytest.mark.asyncio
async def test_concurrent_launch_pause_resume_retains_solver(tmp_path):
    supervisor, service, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait")
    )
    try:
        launches = await asyncio.gather(
            *(supervisor.create_solver(chief, "a") for _ in range(4))
        )
        ids = {x["data"]["agent_id"] for x in launches}
        assert len(ids) == 1
        solver = ids.pop()
        await service.update_agent_memory(
            "run",
            solver,
            "Remember the fixture evidence.",
            summarized_through_sequence=0,
        )
        result = await tool(
            supervisor,
            chief,
            "chief_pause_challenges",
            {"unique_codes": ["a"], "reason": "rotate"},
        )
        assert result.result["ok"], result.result
        assert not platform.running
        assert (await service.get_agent_runtime("run", solver))["agent"][
            "status"
        ] == "paused"
        resumed = await supervisor.create_solver(chief, "a")
        assert resumed["data"]["agent_id"] == solver
        assert (await service.get_agent_runtime("run", solver))["agent"][
            "session_memory"
        ] == "Remember the fixture evidence."
    finally:
        await supervisor.close()
        await service.close()


@pytest.mark.asyncio
async def test_two_workers_parallel_continuous_steps_and_review_use_real_runner(
    tmp_path,
):
    entered = set()
    both = asyncio.Event()

    async def solve(role, index, body):
        if role == "solver":
            return completion("solver_wait")
        user = "\n".join(
            m.get("content") or "" for m in body["messages"] if m["role"] == "user"
        )
        key = (
            min(
                ("left", "right"),
                key=lambda k: (
                    user.find(k + " read then verify")
                    if k + " read then verify" in user
                    else 10**9
                ),
            )
            if "read then verify" in user.split("Assignment:")[0]
            else "review"
        )
        steps = sum(m["role"] == "assistant" for m in body["messages"])
        if key == "review":
            names = {t["function"]["name"] for t in body["tools"]}
            assert names == {
                "evidence_read",
                "evidence_search",
                "report_read",
                "worker_update",
                "worker_report",
            }
            if steps == 0:
                return completion("evidence_search")
            return completion(
                "worker_report",
                {
                    "status": "completed",
                    "summary": "Evidence reviewed",
                    "tested": ["same question evidence"],
                },
            )
        if steps == 0:
            entered.add(key)
            if len(entered) == 2:
                both.set()
            await asyncio.wait_for(both.wait(), 3)
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if steps == 1:
            return completion(
                "worker_update",
                {
                    "summary": key + " completed dependency",
                    "tested": ["file read"],
                    "untested": ["repeat check"],
                },
            )
        if steps == 2:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        return completion(
            "worker_report",
            {
                "status": "completed",
                "summary": key + " all steps complete",
                "tested": ["file read", "repeat check"],
            },
        )

    sup, s, p, c, chief = await harness(tmp_path, solve)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        args = {
            "tasks": [
                {
                    "task_key": k,
                    "objective": k + " read then verify",
                    "success_criteria": ["read twice"],
                }
                for k in ("left", "right")
            ]
        }
        result = await tool(sup, solver, "solver_delegate", args)
        workers = result.result["data"]["admissions"]
        retry = await tool(sup, solver, "solver_delegate", args)
        assert [w["agent_id"] for w in workers] == [
            w["agent_id"] for w in retry.result["data"]["admissions"]
        ]
        from agent.state import ResourceController

        controller = ResourceController(s, "run", storage_root=tmp_path)
        for w in workers:
            decision = await controller.admit(
                w["agent_id"], sample={"cpu_percent": 0.0, "memory_percent": 0.0}
            )
            assert decision["claimed"], decision
            await sup.launch_worker(w["agent_id"])
            await controller.mark_started(w["agent_id"])
        await asyncio.wait_for(
            asyncio.gather(*(sup._tasks[w["agent_id"]] for w in workers)), 10
        )
        assert entered == {"left", "right"}
        for w in workers:
            runtime = await s.get_agent_runtime("run", w["agent_id"])
            assert runtime["agent"]["status"] == "completed", runtime
            events = await s.list_agent_events("run", w["agent_id"], limit=500)
            assert sum(e["event_type"] == "worker_updated" for e in events) == 1
            assert sum(e["event_type"] == "evidence_persisted" for e in events) == 2
        review = (
            await sup.delegate_workers(
                solver,
                [WorkerTaskInput(task_key="review", objective="review", mode="review")],
            )
        )["data"]["admissions"][0]
        await sup.launch_worker(review["agent_id"])
        await asyncio.wait_for(sup._tasks[review["agent_id"]], 10)
        assert (await s.get_agent_runtime("run", review["agent_id"]))["agent"][
            "status"
        ] == "completed"
        for forbidden, args in [
            ("solver_submit_flag", {"flag": "bad"}),
            ("system_read_file", {"file_path": "shared/answer.txt"}),
            ("solver_delegate", {"tasks": []}),
        ]:
            result = await tool(sup, review["agent_id"], forbidden, args)
            assert not result.result["ok"]
        assert len((await s.get_overview("run"))["agents"]) == 5
        assert not p.submissions
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_multi_answer_solver_keeps_running_after_partial_acceptance(tmp_path):
    def solve(role, index, body):
        if index < 2:
            return completion(
                "solver_submit_flag", {"flag": "flag{part" + str(index) + "}"}
            )
        return completion(content="Done")

    sup, s, p, c, chief = await harness(tmp_path, solve, flags=2)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(sup._tasks[solver], 10)
        assert len(p.submissions) == 2
        assert (await s.list_challenges("run"))[0]["is_completed"]
        from sqlalchemy import select
        from agent.state.models import ReportRecord
        async with s.db.sessions() as session:
            reports = (await session.scalars(select(ReportRecord).where(
                ReportRecord.run_id == "run", ReportRecord.report_type == "challenge_status"
            ))).all()
        receipts = [r.payload for r in reports if r.payload.get("type") == "challenge_flag"]
        assert len(receipts) == 2
        assert all(r["correct"] is True and "accepted" not in r for r in receipts)
        assert [r["challenge_completed"] for r in receipts] == [False, True]
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_flag_counts_do_not_finish_solver_before_platform_confirmation(tmp_path):
    class DelayedPlatform(Platform):
        confirmed = False

        async def dispatch(self, name, args):
            result = await super().dispatch(name, args)
            if name == "benchmark_list_challenges":
                result["data"][0]["is_completed"] = self.confirmed
            return result

    platform = DelayedPlatform()

    def solve(role, index, body):
        if index == 0:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if index == 1:
            return completion("solver_submit_flag", {"flag": "flag{offline_fixture}"})
        return completion("solver_wait")

    sup, service, platform, calls, chief = await harness(
        tmp_path, solve, platform=platform
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        # Waiting requires a real durable producer; platform uncertainty alone
        # is not a timer/subscription (the no-wait-source contract).
        await service.create_shell_task('run', solver, task_id='pending-platform-check',
            pid=1, process_started_at=1, cwd='.', temp_dir='tmp', output_path='out', capture_limit=100)

        async with asyncio.timeout(5):
            while (await service.get_agent_runtime("run", solver))["agent"][
                "status"
            ] != "waiting":
                await asyncio.sleep(0.01)
        challenge = (await service.list_challenges("run"))[0]
        assert challenge["correct_flag_count"] == challenge["flag_count"] == 1
        assert not challenge["is_completed"] and challenge["slot_occupied"]
        assert not sup._tasks[solver].done()
        platform.confirmed = True
        await sup.refresh_challenges(chief)
        await asyncio.wait_for(sup._tasks[solver], 5)
        assert (await service.list_challenges("run"))[0]["is_completed"]
    finally:
        await sup.close()
        await service.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["malformed", "timeout", "partial"])
async def test_exact_submission_dedup_and_uncertain_result_never_blindly_retry(
    tmp_path, outcome
):
    class UncertainPlatform(Platform):
        async def dispatch(self, name, args):
            if name == "benchmark_submit_flag" and outcome != "partial":
                self.submissions.append(args["flag"])
                from agent.tooling import tool_error

                return tool_error(
                    "execution",
                    "invalid_response" if outcome == "malformed" else "transport_error",
                    "fixture uncertain response",
                    details={"status_code": 200 if outcome == "malformed" else 503},
                )
            return await super().dispatch(name, args)

    def solve(role, index, body):
        if index == 0:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if index in {1, 2}:
            return completion("solver_submit_flag", {"flag": "flag{offline_fixture}"})
        return completion("solver_wait")

    sup, s, p, c, chief = await harness(
        tmp_path, solve, platform=UncertainPlatform(flags=2)
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        # Waiting requires a real durable producer; platform uncertainty alone
        # is not a timer/subscription (the no-wait-source contract).
        await s.create_shell_task('run', solver, task_id='pending-platform-check',
            pid=1, process_started_at=1, cwd='.', temp_dir='tmp', output_path='out', capture_limit=100)

        # This checks submission deduplication, not four-round host throughput.
        async with asyncio.timeout(30):
            while (
                c["solver"] < 4
                or (await s.get_agent_runtime("run", solver))["agent"]["status"]
                != "waiting"
            ):
                await asyncio.sleep(0.01)
        assert p.submissions == ["flag{offline_fixture}"]
        operations = [
            o
            for o in await s.list_operations("run")
            if o["operation_type"] == "benchmark_submit_flag"
        ]
        assert len(operations) == 1
        assert operations[0]["status"] == (
            "completed" if outcome == "partial" else "indeterminate"
        )
        assert not (await s.list_challenges("run"))[0]["is_completed"]
    finally:
        await sup.close()
        await s.close()


@pytest.mark.asyncio
async def test_second_supervisor_cannot_take_over_live_run(tmp_path):
    from agent.state.errors import StateConflict

    sup, s, p, c, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    other = AgentSupervisor(
        sup.settings,
        benchmark=p,
        project_root=tmp_path,
        run_root=tmp_path / "runs",
        state_service=s,
        catalog_reconcile_interval_seconds=0,
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        with pytest.raises(StateConflict, match="Another Runtime"):
            await other.prepare_chief("", run_id="run", resume=True)
        await other.close()
        assert not sup._tasks[solver].done()
        assert (await s.get_agent_runtime("run", solver))["agent"]["status"] not in {
            "cancelled",
            "interrupted",
            "stopped",
        }
    finally:
        await sup.close()
        await s.close()
