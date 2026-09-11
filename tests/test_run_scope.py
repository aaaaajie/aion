"""Run scope and completion contracts, using an offline platform and real Runner."""

import asyncio
import json

import pytest

from agent.config import AgentSettings, normalize_selected_challenge_codes
from agent.runtime import AgentRuntime
from agent.state import StateService
from agent.state.errors import StateError
from agent.subagents import AgentSupervisor
from tests.test_solver_lifecycle import Platform, completion, harness, tool


class Catalog(Platform):
    async def dispatch(self, name, args):
        result = await super().dispatch(name, args)
        if name == "benchmark_list_challenges":
            result["data"].append({"unique_code": "b", "container_status": "stopped"})
        return result


@pytest.mark.parametrize("value", [[], [""], ["  "], [None], "a", ["x" * 257]])
def test_scope_rejects_invalid_codes(value):
    with pytest.raises(ValueError):
        normalize_selected_challenge_codes(value)


def test_scope_environment_normalizes_order_and_duplicates(monkeypatch):
    monkeypatch.setenv("AION_SELECTED_CHALLENGE_CODES", '[" b ", "a", "b"]')
    settings = AgentSettings(
        llm_base_url="https://model.test", llm_model="fixture", llm_api_key="fixture"
    )
    assert settings.selected_challenge_codes == ["b", "a"]


async def test_scope_persists_and_state_admission_enforces_it(tmp_path):
    path = tmp_path / "state.sqlite3"
    state = StateService(path, run_root=tmp_path / "runs", workspace_root=tmp_path)
    try:
        await state.create_run("run", selected_challenge_codes=["a", "a"], challenges=[
            {"unique_code": "a"}, {"unique_code": "b"},
        ])
        await state.validate_selected_challenges("run")
        for operation in (
            state.challenge_start_gate("run", "b"),
            state.start_challenge("run", "b"),
            state.mark_operation_started("run", "benchmark_start_challenge", unique_code="b"),
        ):
            with pytest.raises(StateError, match="outside"):
                await operation
        await state.pause_run("run", reason="runtime_pause")
        await state.close()
        state = StateService(path, run_root=tmp_path / "runs", workspace_root=tmp_path)
        await state.initialize()
        await state.resume_run("run")
        overview = await state.get_overview("run")
        assert overview["run"]["selected_challenge_codes"] == ["a"]
        assert (await state.challenge_start_gate("run", "a"))["allowed"]
        await state.project_pending_events("run", force_checkpoint=True)
        manifest = json.loads((tmp_path / "runs/run/manifest.json").read_text())
        assert manifest["selected_challenge_codes"] == ["a"]
    finally:
        await state.close()


@pytest.mark.parametrize("codes", [["missing"], ["a", "missing"]])
async def test_scope_catalog_validation_precedes_any_model_or_launch(tmp_path, codes):
    state = StateService(tmp_path / "runs/run/state.sqlite3", run_root=tmp_path / "runs", workspace_root=tmp_path)
    settings = AgentSettings(
        llm_base_url="https://model.test", llm_model="fixture", llm_api_key="fixture",
        selected_challenge_codes=codes,
    )
    platform = Catalog()
    sup = AgentSupervisor(settings, state_service=state, benchmark=platform,
                          project_root=tmp_path, run_root=tmp_path / "runs",
                          catalog_reconcile_interval_seconds=0)
    try:
        with pytest.raises(StateError, match="not found"):
            await sup.prepare_chief("Solve selected challenges", run_id="run")
        assert not sup._tasks
        assert not platform.running
        assert not platform.submissions
    finally:
        await sup.close()
        await state.close()


async def test_resume_rejects_scope_replacement_before_touching_state(tmp_path):
    settings = AgentSettings(
        llm_base_url="https://model.test", llm_model="fixture", llm_api_key="fixture",
        selected_challenge_codes=["a"],
    )
    runtime = AgentRuntime(settings, project_root=tmp_path, run_root=tmp_path / "runs")
    with pytest.raises(ValueError, match="Resume cannot replace"):
        await runtime.start("", run_id="run", resume=True)
    assert runtime.state_service is None
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("compact", [False, True])
async def test_scoped_solver_completes_without_extra_model_and_ignores_other_challenges(tmp_path, compact):
    def solve(role, index, body):
        assert index == 0, "completion must not request another model turn"
        return completion("solver_submit_flag", {"flag": "flag{selected}"})

    sup, state, platform, calls, chief = await harness(
        tmp_path, solve, platform=Catalog(), selected_challenge_codes=["a"],
        compact_tools=compact,
    )
    try:
        outside = await sup.create_solver(chief, "b")
        assert not outside["ok"]
        assert outside["error"]["code"] == "challenge_out_of_scope"
        assert not platform.running
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        await asyncio.wait_for(sup.wait_for_agents(), 5)
        overview = await state.get_overview("run")
        assert overview["run"]["status"] == "completed"
        assert calls["solver"] == 1
        a, b = sorted(overview["challenges"], key=lambda item: item["unique_code"])
        assert a["work_status"] == "completed" and not a["slot_occupied"]
        assert not b["is_completed"] and b["work_status"] == "unassigned"
        receipt = (await state.get_agent_runtime("run", solver))["agent"]["final_report"]
        assert receipt["challenge_completed"] is True and receipt["correct"] is True
        events = await state.list_agent_events("run", solver)
        submitted = [e for e in events if e["event_type"] == "tool_result"
                     and e["payload"]["tool_name"] == "solver_submit_flag"]
        assert len(submitted) == 1
        assert submitted[0]["payload"]["result"]["ok"] is True
        assert submitted[0]["payload"]["result"]["data"]["challenge_completed"] is True
        finished = next(e for e in events if e["event_type"] == "agent_finished")
        run_finished = next(e for e in await state.list_agent_events("run", chief)
                            if e["event_type"] == "run_finished")
        assert finished["sequence"] < submitted[0]["sequence"] < run_finished["sequence"]
        assert run_finished["payload"]["reason"] == "selected_challenges_completed"
        assert (await state.get_agent_runtime("run", chief))["agent"]["final_report"]["completion_reason"] == "selected_challenges_completed"
        assert not sup._tasks[solver].cancelled()
        await sup.close()
        await sup.close()
        after = await state.get_overview("run")
        assert after["run"]["status"] == "completed"
        assert (await state.get_agent_runtime("run", solver))["agent"]["final_report"] == receipt
        assert platform.close_calls == 1
    finally:
        await sup.close()
        await state.close()


@pytest.mark.parametrize("interrupted", [False, True])
async def test_scoped_run_waits_for_container_release(tmp_path, interrupted):
    entered, release = asyncio.Event(), asyncio.Event()

    class SlowRelease(Catalog):
        async def dispatch(self, name, args):
            if name == "benchmark_close_challenge":
                entered.set()
                await release.wait()
            return await super().dispatch(name, args)

    sup, state, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_submit_flag", {"flag": "flag{release}"}),
        platform=SlowRelease(), selected_challenge_codes=["a"],
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(entered.wait(), 5)
        await asyncio.wait_for(sup.wait_agent(solver), 5)
        assert (await state.get_overview("run"))["run"]["status"] == "active"
        assert not sup._tasks[chief].done()
        if interrupted:
            await state.finish_run("run", "interrupted", report={"reason": "external signal"})
        release.set()
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        expected = "interrupted" if interrupted else "completed"
        assert (await state.get_overview("run"))["run"]["status"] == expected
        if interrupted:
            await sup.close()
            assert (await state.get_overview("run"))["run"]["status"] == "interrupted"
    finally:
        release.set()
        await sup.close()
        await state.close()


async def test_completed_close_waits_for_final_write_without_cancelling_task(tmp_path):
    sup, state, platform, calls, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    entered, finish = asyncio.Event(), asyncio.Event()
    try:
        # A completed durable Solver can still be writing its final tool receipt.
        await state.start_challenge("run", "a")
        await state.register_agent("run", agent_id="finishing", role="solver", parent_id=chief, unique_code="a")
        await state.finish_agent("run", "finishing", status="completed", final_report={"receipt": "saved"})
        await sup._sync_nodes()
        sup._issue_capabilities()
        platform.running = True
        platform.accepted = 1
        await sup._sync_challenge_catalog()

        async def final_write():
            entered.set()
            await finish.wait()

        task = sup._tasks["finishing"] = asyncio.create_task(final_write())
        await entered.wait()
        closing = asyncio.create_task(sup.close_challenges(chief, ["a"], reason="finished"))
        await asyncio.sleep(0.05)
        assert not task.cancelled() and not task.done()
        assert not closing.done()
        finish.set()
        result = await asyncio.wait_for(closing, 5)
        assert result["data"]["results"][0]["status"] == "completed"
        assert not task.cancelled()
        before = (await state.get_agent_runtime("run", "finishing"))["agent"]
        await sup.close_challenges(chief, ["a"], reason="again")
        after = (await state.get_agent_runtime("run", "finishing"))["agent"]
        assert before["final_report"] == after["final_report"] == {"receipt": "saved"}
        assert after["status"] == "completed"
        assert platform.close_calls == 1
    finally:
        finish.set()
        await sup.close()
        await state.close()


@pytest.mark.parametrize("status", ["interrupted", "failed", "completed"])
async def test_terminal_run_outcome_and_receipt_are_idempotent(tmp_path, status):
    state = StateService(tmp_path / "state.sqlite3", workspace_root=tmp_path)
    try:
        await state.create_run("run")
        await state.register_agent("run", agent_id="chief", role="chief")
        first = await state.finish_run("run", status, report={"reason": "original"})
        again = await state.finish_run("run", "completed", report={"reason": "cleanup"})
        assert again["status"] == status
        assert again["last_sequence"] == first["last_sequence"]
        assert (await state.get_agent_runtime("run", "chief"))["agent"]["final_report"] == {"reason": "original"}
    finally:
        await state.close()


async def test_scoped_completion_waits_for_worker_final_cleanup(tmp_path, monkeypatch):
    entered, finish = asyncio.Event(), asyncio.Event()

    def solve(role, index, body):
        if role == "worker":
            return completion("worker_report", {"status": "completed", "summary": "evidence saved"})
        if index == 0:
            return completion("solver_wait")
        return completion("solver_submit_flag", {"flag": "flag{worker}"})

    sup, state, platform, calls, chief = await harness(
        tmp_path, solve, platform=Catalog(), selected_challenge_codes=["a"],
    )
    original_cleanup = sup._finish_agent_resources
    worker_id = None

    async def delayed_cleanup(agent_id):
        if agent_id == worker_id:
            entered.set()
            await finish.wait()
        return await original_cleanup(agent_id)

    monkeypatch.setattr(sup, "_finish_agent_resources", delayed_cleanup)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        async with asyncio.timeout(5):
            while (await state.get_agent_runtime("run", solver))["agent"]["status"] != "waiting":
                await asyncio.sleep(0.01)
        delegated = await tool(sup, solver, "solver_delegate", {"tasks": [{
            "task_key": "evidence", "objective": "Collect evidence",
        }]})
        worker_id = delegated.result["data"]["admissions"][0]["agent_id"]
        await sup.launch_worker(worker_id)
        await asyncio.wait_for(entered.wait(), 5)
        async with asyncio.timeout(5):
            while not platform.submissions:
                await asyncio.sleep(0.01)
        assert (await state.get_overview("run"))["run"]["status"] == "active"
        assert not sup._tasks[worker_id].done()
        finish.set()
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        await asyncio.wait_for(sup.wait_for_agents(), 5)
        assert (await state.get_overview("run"))["run"]["status"] == "completed"
        assert all(task.done() and not task.cancelled() for task in sup._tasks.values())
        assert calls["solver"] == 2 and calls["worker"] == 1
    finally:
        finish.set()
        await sup.close()
        await state.close()


async def test_unscoped_run_keeps_waiting_for_remaining_catalog(tmp_path):
    sup, state, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_submit_flag", {"flag": "flag{unscoped}"}),
        platform=Catalog(),
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(sup.wait_agent(solver), 5)
        assert (await state.get_overview("run"))["run"]["selected_challenge_codes"] is None
        assert (await state.get_overview("run"))["run"]["status"] == "active"
        assert not sup._tasks[chief].done()
    finally:
        await sup.close()
        await state.close()


async def test_resume_uses_persisted_scope_with_unscoped_settings(tmp_path):
    sup, state, platform, _, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait"), platform=Catalog(),
        selected_challenge_codes=["a"],
    )
    try:
        await state.pause_run("run", reason="runtime_pause")
        await sup.pause()
        await state.close()
        sup, state, platform, _, chief = await harness(
            tmp_path, lambda *_: completion("solver_wait"), platform=platform, resume=True,
        )
        assert sup.settings.selected_challenge_codes is None
        assert (await state.get_overview("run"))["run"]["selected_challenge_codes"] == ["a"]
        assert not (await sup.create_solver(chief, "b"))["ok"]
        assert (await sup.create_solver(chief, "a"))["ok"]
    finally:
        await sup.close()
        await state.close()


async def test_closed_unsolved_selection_cannot_complete_run(tmp_path):
    sup, state, platform, _, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait"), platform=Catalog(),
        selected_challenge_codes=["a"],
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await sup.close_challenges(chief, ["a"], reason="no solution")
        overview = await state.get_overview("run")
        assert overview["run"]["status"] == "active"
        challenge = next(item for item in overview["challenges"] if item["unique_code"] == "a")
        assert challenge["work_status"] == "closed" and not challenge["is_completed"]
        assert (await state.get_agent_runtime("run", solver))["agent"]["status"] == "stopped"
        assert not await sup._settle_controller(chief, "chief", {"reason": "closed"})
        assert not sup._tasks[chief].done()
    finally:
        await sup.close()
        await state.close()


async def test_solver_settlement_distinguishes_closed_from_solved(tmp_path):
    sup, state, platform, _, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    try:
        await state.start_challenge("run", "a")
        await state.register_agent("run", agent_id="closed-solver", role="solver", parent_id=chief, unique_code="a")
        await state.close_challenge("run", "a")
        assert await sup._settle_controller("closed-solver", "solver", {"reason": "closed"})
        assert (await state.get_agent_runtime("run", "closed-solver"))["agent"]["status"] == "stopped"
    finally:
        await sup.close()
        await state.close()


async def test_resume_settles_solver_completed_remotely_while_paused(tmp_path):
    sup, state, platform, _, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait"), platform=Catalog(),
        selected_challenge_codes=["a"],
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await state.pause_run("run", reason="runtime_pause")
        await sup.pause()
        assert (await state.get_agent_runtime("run", solver))["agent"]["status"] == "paused"
        await state.close()
        platform.accepted = platform.flags
        sup, state, platform, calls, chief = await harness(
            tmp_path, lambda *_: pytest.fail("completed solver must not restart"),
            platform=platform, resume=True,
        )
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        await asyncio.wait_for(sup.wait_for_agents(), 5)
        assert (await state.get_agent_runtime("run", solver))["agent"]["status"] == "completed"
        assert calls["solver"] == 0
        assert (await state.get_overview("run"))["run"]["status"] == "completed"
    finally:
        await sup.close()
        await state.close()


async def test_concurrent_completion_before_cancel_preserves_final_writer(tmp_path, monkeypatch):
    sup, state, platform, _, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    completed, finish = asyncio.Event(), asyncio.Event()
    original_finish = state.finish_agent

    async def finish_during_stop(run_id, agent_id, **kwargs):
        if agent_id == "racing" and kwargs["status"] == "stopped":
            await original_finish(run_id, agent_id, status="completed", final_report={"receipt": "saved"})
            completed.set()
        return await original_finish(run_id, agent_id, **kwargs)

    monkeypatch.setattr(state, "finish_agent", finish_during_stop)
    try:
        await state.start_challenge("run", "a")
        await state.register_agent("run", agent_id="racing", role="solver", parent_id=chief, unique_code="a")
        await sup._sync_nodes()
        sup._issue_capabilities()
        task = sup._tasks["racing"] = asyncio.create_task(finish.wait())
        stopping = asyncio.create_task(sup._stop_agent("racing"))
        await asyncio.wait_for(completed.wait(), 5)
        await asyncio.sleep(0.03)
        assert not task.cancelled() and not task.done()
        finish.set()
        assert (await asyncio.wait_for(stopping, 5))["ok"]
        current = (await state.get_agent_runtime("run", "racing"))["agent"]
        assert current["status"] == "completed" and current["final_report"] == {"receipt": "saved"}
    finally:
        finish.set()
        await sup.close()
        await state.close()


@pytest.mark.parametrize("report,reason", [
    ({"completion_reason": "deadline", "type": "other"}, "deadline"),
    ({"type": "runtime_interrupted"}, "runtime_interrupted"),
    ({"summary": "retained"}, "interrupted"),
])
async def test_run_finished_reason_precedence_preserves_report(tmp_path, report, reason):
    state = StateService(tmp_path / "state.sqlite3", workspace_root=tmp_path)
    try:
        await state.create_run("run")
        await state.register_agent("run", agent_id="chief", role="chief")
        await state.finish_run("run", "interrupted", report=report)
        event = next(e for e in await state.list_agent_events("run", "chief") if e["event_type"] == "run_finished")
        assert event["payload"] == {"status": "interrupted", "reason": reason}
        assert (await state.get_agent_runtime("run", "chief"))["agent"]["final_report"] == report
    finally:
        await state.close()


async def test_solver_setup_failure_returns_instead_of_deadlocking_challenge_lock(tmp_path, monkeypatch):
    sup, state, platform, _, chief = await harness(tmp_path, lambda *_: completion("solver_wait"))
    original_session = sup._run_agent_session

    async def fail_setup(agent_id, role, **kwargs):
        if role == "solver":
            raise RuntimeError("solver setup failed before startup signal")
        return await original_session(agent_id, role, **kwargs)

    monkeypatch.setattr(sup, "_run_agent_session", fail_setup)
    try:
        result = await asyncio.wait_for(sup.create_solver(chief, "a"), 3)
        assert not result["ok"] and result["error"]["code"] == "solver_start_failed"
        solver = next(a for a in (await state.get_overview("run"))["agents"] if a["role"] == "solver")
        await asyncio.wait_for(sup.wait_agent(solver["agent_id"]), 3)
        assert (await state.get_agent_runtime("run", solver["agent_id"]))["agent"]["status"] == "failed"
        assert not platform.running
    finally:
        await sup.close()
        await state.close()


async def test_completed_agent_cannot_be_paused_or_reopened(tmp_path):
    state = StateService(tmp_path / "state.sqlite3", workspace_root=tmp_path)
    try:
        await state.create_run("run")
        await state.register_agent("run", agent_id="chief", role="chief")
        first = await state.finish_agent("run", "chief", status="completed", final_report={"receipt": "saved"})
        for status in ("paused", "running", "stopping"):
            current = await state.transition_agent("run", "chief", status)
            assert current["status"] == "completed" and current["version"] == first["version"]
        assert (await state.get_agent_runtime("run", "chief"))["agent"]["final_report"] == {"receipt": "saved"}
    finally:
        await state.close()


@pytest.mark.parametrize("reason", ["deadline", "catalog_terminal"])
async def test_controller_emits_deterministic_completion_reason(tmp_path, reason):
    from datetime import datetime, timedelta, timezone

    state = StateService(tmp_path / "runs/run/state.sqlite3", run_root=tmp_path / "runs", workspace_root=tmp_path)
    settings = AgentSettings(llm_base_url="https://model.test", llm_model="fixture", llm_api_key="fixture")
    sup = AgentSupervisor(settings, state_service=state, project_root=tmp_path,
                          run_root=tmp_path / "runs", catalog_reconcile_interval_seconds=0)
    try:
        await state.create_run("run", duration_minutes=1,
                               started_at=datetime.now(timezone.utc),
                               challenges=[{"unique_code": "a"}])
        await state.register_agent("run", agent_id="chief", role="chief")
        sup.run_id, sup.chief_agent_id = "run", "chief"
        await sup._sync_nodes()
        sup._issue_capabilities()
        if reason == "deadline":
            expired = datetime.now(timezone.utc) + timedelta(minutes=2)
            state.clock = lambda: expired
        if reason == "catalog_terminal":
            await state.close_challenge("run", "a")
        assert await sup._settle_controller("chief", "chief", {"final": "retained"})
        report = (await state.get_agent_runtime("run", "chief"))["agent"]["final_report"]
        assert report == {"final": "retained", "completion_reason": reason}
        event = next(e for e in await state.list_agent_events("run", "chief") if e["event_type"] == "run_finished")
        assert event["payload"]["reason"] == reason
    finally:
        await sup.close()
        await state.close()


async def test_completed_selection_release_failure_blocks_completion_until_recovered(tmp_path):
    from agent.tooling import tool_error

    class FailingRelease(Catalog):
        release_fails = True
        failed_close_calls = 0

        async def dispatch(self, name, args):
            if name == "benchmark_close_challenge" and self.release_fails:
                self.failed_close_calls += 1
                return tool_error("execution", "transport_error", "platform release unavailable")
            return await super().dispatch(name, args)

    sup, state, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_submit_flag", {"flag": "flag{release_failure}"}),
        platform=FailingRelease(), selected_challenge_codes=["a"],
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(sup.wait_agent(solver), 5)
        async with asyncio.timeout(5):
            while True:
                events = await state.list_agent_events("run", chief)
                failures = [e for e in events if e["event_type"] == "completed_container_release_failed"]
                if failures:
                    break
                await asyncio.sleep(0.01)
        pending = list(sup._challenge_completion_tasks.values())
        if pending:
            await asyncio.wait_for(asyncio.gather(*pending), 5)
        assert platform.failed_close_calls == failures[-1]["payload"]["attempts"] == 3
        overview = await state.get_overview("run")
        selected = next(c for c in overview["challenges"] if c["unique_code"] == "a")
        assert selected["is_completed"] and selected["slot_occupied"]
        assert (await state.get_agent_runtime("run", solver))["agent"]["status"] == "completed"
        assert not await sup._settle_controller(chief, "chief", {"reason": "release failed"})
        assert overview["run"]["status"] == "active" and not sup._tasks[chief].done()
        assert not any(e["event_type"] == "run_finished" for e in events)

        platform.release_fails = False
        assert (await sup.refresh_challenges(chief))["ok"]
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        await asyncio.wait_for(sup.wait_for_agents(), 5)
        overview = await state.get_overview("run")
        assert overview["run"]["status"] == "completed"
        assert not next(c for c in overview["challenges"] if c["unique_code"] == "a")["slot_occupied"]
        events = await state.list_agent_events("run", chief)
        released = next(e for e in events if e["event_type"] == "completed_container_release_succeeded")
        finished = next(e for e in events if e["event_type"] == "run_finished")
        assert failures[-1]["sequence"] < released["sequence"] < finished["sequence"]
        assert finished["payload"]["reason"] == "selected_challenges_completed"
        assert calls["solver"] == 1 and platform.close_calls == 1
    finally:
        platform.release_fails = False
        await sup.close()
        await state.close()


@pytest.mark.parametrize("catalog_count,selected_count", [(2, 1), (18, 3)])
async def test_scoped_catalog_requires_every_selected_challenge(tmp_path, catalog_count, selected_count):
    class MultiCatalog(Platform):
        def __init__(self):
            super().__init__()
            self.challenges = {f"challenge-{i:02d}": Platform() for i in range(1, catalog_count + 1)}

        async def dispatch(self, name, args):
            if name == "benchmark_list_challenges":
                values = []
                for code, challenge in self.challenges.items():
                    result = await challenge.dispatch(name, args)
                    values.append({**result["data"][0], "unique_code": code})
                return {"ok": True, "data": values}
            return await self.challenges[args["unique_code"]].dispatch(name, args)

    platform = MultiCatalog()
    selected = list(platform.challenges)[:selected_count]
    sup, state, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_submit_flag", {"flag": "flag{selected_set}"}),
        platform=platform, selected_challenge_codes=selected,
    )
    try:
        outside = list(platform.challenges)[-1]
        assert not (await sup.create_solver(chief, outside))["ok"]
        for index, code in enumerate(selected, 1):
            solver = (await sup.create_solver(chief, code))["data"]["agent_id"]
            await asyncio.wait_for(sup.wait_agent(solver), 5)
            pending = list(sup._challenge_completion_tasks.values())
            if pending:
                await asyncio.wait_for(asyncio.gather(*pending), 5)
            overview = await state.get_overview("run")
            assert len(overview["challenges"]) == catalog_count
            assert overview["run"]["selected_challenge_codes"] == selected
            assert sum(c["is_completed"] for c in overview["challenges"]) == index
            if index < selected_count:
                assert overview["run"]["status"] == "active"
                assert not sup._tasks[chief].done()
                assert not await sup._settle_controller(chief, "chief", {"reason": "subset incomplete"})
        await asyncio.wait_for(sup.wait_agent(chief), 5)
        await asyncio.wait_for(sup.wait_for_agents(), 5)
        overview = await state.get_overview("run")
        assert overview["run"]["status"] == "completed"
        assert all(c["is_completed"] and not c["slot_occupied"] for c in overview["challenges"] if c["unique_code"] in selected)
        assert all(not c["is_completed"] and c["work_status"] == "unassigned" for c in overview["challenges"] if c["unique_code"] not in selected)
        assert sum(c.close_calls for c in platform.challenges.values()) == selected_count
        assert calls["solver"] == selected_count
        event = next(e for e in await state.list_agent_events("run", chief) if e["event_type"] == "run_finished")
        assert event["payload"]["reason"] == "selected_challenges_completed"
    finally:
        await sup.close()
        await state.close()
