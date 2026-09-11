"""Bounded side observations through real state, model accounting and Runner."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from pydantic import ValidationError

from agent.config import AgentSettings
from agent.observation import SolverObserver, trace_batch, MAX_TRACE_CHARS
from agent.observation_models import ObservationMap
from scripts.replay_solver_observation import replay_observation
from agent.state import StateService, StateDatabase
from agent.state.observation import TRACE_PAGE_SIZE
from agent.state.errors import StatePermission, StateConflict
from scripts.runtime_web.server import _ReadOnlyStore
from tests.solver_state import build_state, worker
from tests.test_solver_lifecycle import harness, completion


def settings():
    return AgentSettings(
        llm_base_url="https://model.test", llm_model="fixture", llm_api_key="fixture"
    )


async def trace(service, count=6, *, agent_id="solver"):
    result = []
    for index in range(count):
        result.append(
            await service.append_agent_event(
                "run",
                agent_id,
                "tool_result",
                {
                    "tool_name": "system_read_file",
                    "tool_call_id": f"read-{index}",
                    "result": {
                        "ok": True,
                        "data": {"content": f"本题已测路径 {index}"},
                    },
                },
            )
        )
    return result


def map_response(body, *, empty=False):
    context = json.loads(body["messages"][-1]["content"])
    value = ObservationMap().model_dump()
    if not empty:
        value["DEAD"] = [
            {
                "claim": "当前条件下该路径尚未取得结果，结论可被新证据推翻。",
                "sources": [context["trace"][-1]["sequence"]],
            }
        ]
    return completion(
        content=json.dumps({"map": value, "correction": None}, ensure_ascii=False)
    )


async def test_observation_is_incremental_bounded_cooldown_and_revisable(tmp_path):
    service, _, solver = await build_state(tmp_path)
    await service.transition_agent("run", "solver", "running")
    now = [service.clock()]
    service.clock = lambda: now[0]
    requests = []

    async def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        assert "tools" not in body
        assert body["response_format"] == {"type": "json_object"}
        assert body["max_tokens"] == 2048
        return httpx.Response(200, json=map_response(body, empty=len(requests) == 2))

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    observer = SolverObserver(settings(), service, solver, client)
    try:
        await trace(service, 5)
        await observer.poll()
        assert observer.task is None
        old = await trace(service, 1)
        await observer.poll()
        await asyncio.wait_for(observer.task, 2)
        await observer.poll()
        assert observer.snapshot["map"]["DEAD"]
        first_cursor = observer.snapshot["cursor"]
        assert first_cursor == old[-1]
        await trace(service)
        await observer.poll()
        assert len(requests) == 1
        now[0] += timedelta(seconds=61)
        await observer.poll()
        await asyncio.wait_for(observer.task, 2)
        await observer.poll()
        assert observer.snapshot["map"]["DEAD"] == []
        new_trace = json.loads(requests[-1]["messages"][-1]["content"])["trace"]
        assert all(row["sequence"] > first_cursor for row in new_trace)
        assert len(requests) == 2
        now[0] += timedelta(seconds=61)
        await observer.poll()
        assert observer.task is None  # health/time alone never calls a model
        usage = _ReadOnlyStore(service.db.path, "run").snapshot()["token_usage"]
        assert usage["agents"]["solver"]["calls"] == 2
        assert usage["challenges"]["a"]["input_tokens"] == 200
        assert usage["run"]["output_tokens"] == 20
    finally:
        await observer.close()
        await client.aclose()
        await service.close()


@pytest.mark.parametrize("bad", ["malformed", "tools", "unseen_source", "oversized"])
async def test_observation_invalid_output_never_changes_map_or_runs_tools(
    tmp_path, bad
):
    service, _, solver = await build_state(tmp_path)
    await service.transition_agent("run", "solver", "running")
    first = await trace(service)
    await service.save_solver_observation(
        "run",
        solver,
        generation=0,
        expected_revision=0,
        through_sequence=first[-1],
        observation={"LOCK": [{"claim": "已有证据", "sources": [first[0]]}]},
    )
    await trace(service)
    now = [service.clock()]
    service.clock = lambda: now[0]
    calls = 0

    async def respond(request):
        nonlocal calls
        calls += 1
        if calls > 1:
            return httpx.Response(200, json=map_response(json.loads(request.content)))
        if bad == "tools":
            value = completion("solver_submit_flag", {"flag": "forged"})
        elif bad == "malformed":
            value = completion(content="invalid JSON")
        else:
            value = completion(
                content=json.dumps(
                    {
                        "map": {
                            "LOCK": [
                                {
                                    "claim": "x" * (500 if bad == "oversized" else 1),
                                    "sources": [999999],
                                }
                            ]
                        },
                        "correction": None,
                    }
                )
            )
        return httpx.Response(200, json=value)

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    observer = SolverObserver(settings(), service, solver, client)
    try:
        await observer.poll()
        await asyncio.wait_for(observer.task, 2)
        await observer.poll()
        assert observer.snapshot["map"]["LOCK"][0]["claim"] == "已有证据"
        assert observer.snapshot["cursor"] > first[-1]
        assert not await service.list_operations("run")
        assert len((await service.get_overview("run"))["agents"]) == 2
        latest = await service.latest_agent_event(
            "run", "solver", event_types={"solver_observation_snapshot"}
        )
        assert latest["payload"]["status"] == "failed"
        diagnostic = latest["payload"]["diagnostics"]
        expected_stage = {
            "malformed": "json",
            "tools": "response",
            "unseen_source": "sources",
            "oversized": "schema",
        }[bad]
        assert diagnostic["failure_stage"] == expected_stage
        assert diagnostic["outcome"] == "failed"
        assert latest["payload"]["coverage"]["status"] == "failed"
        attempt = await service.latest_agent_event(
            "run", "solver", event_types={"solver_observation_started"}
        )
        assert diagnostic["attempt_sequence"] == attempt["sequence"]
        replay = replay_observation(attempt["payload"]["input"], diagnostic)
        assert replay["stage"] == expected_stage
        if bad in {"malformed", "oversized"}:
            assert diagnostic["validation_errors"]
            assert all("input" not in e for e in diagnostic["validation_errors"])
        await observer.poll()
        assert observer.task is None  # no automatic repair/retry of failed batches
        failed_cursor = observer.snapshot["cursor"]
        now[0] += timedelta(seconds=121)
        await trace(service)
        await observer.poll()
        await asyncio.wait_for(observer.task, 2)
        await observer.poll()
        assert calls == 2
        assert observer.snapshot["cursor"] > failed_cursor
        assert observer.snapshot["map"]["DEAD"]

    finally:
        await observer.close()
        await client.aclose()
        await service.close()


async def test_observation_scope_generation_and_restart(tmp_path):
    service, chief, solver = await build_state(tmp_path)
    await service.transition_agent("run", "solver", "running")
    sources = await trace(service)
    review = await worker(service, solver, mode="review")
    other = await service.append_agent_event(
        "run", review.agent_id, "tool_result", {"result": "foreign"}
    )
    kwargs = dict(
        generation=0,
        expected_revision=0,
        through_sequence=sources[-1],
        observation={"LOCK": [{"claim": "猜测", "sources": [other]}]},
    )
    with pytest.raises(StatePermission):
        await service.save_solver_observation("run", solver, **kwargs)
    for context in [
        chief,
        review,
        solver.model_copy(update={"unique_code": "b"}),
        solver.model_copy(update={"run_id": "elsewhere"}),
    ]:
        with pytest.raises(StatePermission):
            await service.solver_observation_state("run", context)
        with pytest.raises(StatePermission):
            await service.save_solver_observation("run", context, **kwargs)
    kwargs["observation"]["LOCK"][0]["sources"] = [sources[0]]
    revision = await service.save_solver_observation("run", solver, **kwargs)
    await service.invalidate_agent_resources("run", "solver", reason="fixture restart")
    more = await trace(service, 1)
    with pytest.raises(StateConflict, match="inactive"):
        await service.save_solver_observation(
            "run",
            solver,
            generation=0,
            expected_revision=revision,
            through_sequence=more[-1],
            observation={},
        )
    path = service.db.path
    await service.close()
    restored = StateService(
        StateDatabase(path), run_root=tmp_path / "runs", workspace_root=tmp_path
    )
    try:
        state = await restored.solver_observation_state("run", solver)
        assert state["revision"] == revision
        assert state["map"]["LOCK"] == []  # previous resource generation is not current evidence
        assert state["map_coverage"] is None
        assert state["cursor"] == sources[-1] and state["generation"] == 1
    finally:
        await restored.close()


async def test_bookkeeping_page_cannot_hide_later_execution_or_wake_model(tmp_path):
    service, _, solver = await build_state(tmp_path)
    await service.transition_agent("run", "solver", "running")
    requests = []

    async def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(200, json=map_response(body))

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    observer = SolverObserver(settings(), service, solver, client)
    try:
        for _ in range(TRACE_PAGE_SIZE):
            await service.append_agent_event(
                "run",
                "solver",
                "tool_result",
                {
                    "tool_name": "solver_observe",
                    "result": {},
                },
            )
        sources = await trace(service)
        await observer.poll()
        assert observer.task is not None  # latest work bypasses the old backlog
        await asyncio.wait_for(observer.task, 2)
        await observer.poll()
        assert observer.snapshot["cursor"] == sources[-1]
        assert len(requests) == 1
    finally:
        await observer.close()
        await client.aclose()
        await service.close()


def test_map_schema_and_trace_budget():
    with pytest.raises(ValidationError):
        ObservationMap.model_validate({"NEXT": ["do this"]})
    with pytest.raises(ValidationError):
        ObservationMap.model_validate(
            {"TENSION": [{"claim": "contradiction", "sources": [1]}]}
        )
    rows, count, full = trace_batch(
        [
            {
                "sequence": i + 1,
                "event_type": "tool_result",
                "payload": {"tool_name": "system_shell", "result": "x" * 50000},
            }
            for i in range(80)
        ]
    )
    assert count > 0 and full
    assert len(json.dumps(rows, ensure_ascii=False)) < MAX_TRACE_CHARS + 100


async def test_real_runner_observation_is_nonblocking_tail_context_and_pause_cancels(
    tmp_path,
):
    started = asyncio.Event()
    release = asyncio.Event()
    main_continued = asyncio.Event()
    suspended = asyncio.Event()
    requests = []
    observer_requests = []

    async def observe(body):
        observer_requests.append(body)
        started.set()
        await release.wait()
        return map_response(body)

    async def model(role, index, body):
        requests.append(body)
        if index < 6:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        if index == 6:
            await asyncio.wait_for(started.wait(), 2)
            main_continued.set()
            # The Solver reached another real model request while observation
            # is still waiting for its response.
            release.set()
            observer = next(iter(sup._solver_observers.values()))
            await asyncio.wait_for(asyncio.shield(observer.task), 2)
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        assert "<solver_observation>" in body["messages"][-1]["content"]
        assert "<solver_observation>" not in body["messages"][0]["content"]
        suspended.set()
        await asyncio.Event().wait()

    sup, service, platform, _, chief = await harness(
        tmp_path, model, observation_model=observe
    )
    try:
        result = await sup.create_solver(chief, "a")
        solver_id = result["data"]["agent_id"]
        await asyncio.wait_for(suspended.wait(), 5)
        assert main_continued.is_set() and len(observer_requests) == 1
        assert all(
            request["messages"][0] == requests[0]["messages"][0] for request in requests
        )
        snapshot = await service.latest_agent_event(
            "run", solver_id, event_types={"solver_observation_snapshot"}
        )
        assert snapshot["payload"]["map"]["DEAD"]
        await sup.pause_challenges(
            chief, ["a"], reason="fixture", release_container=False
        )
        assert not sup._solver_observers
        assert not platform.submissions
        assert len((await service.get_overview("run"))["agents"]) == 2
        assert not [
            task
            for task in asyncio.all_tasks()
            if task.get_name().startswith("solver-observation:")
        ]
    finally:
        await sup.close()
        await service.close()


async def test_pending_observation_is_cancelled_by_challenge_pause(tmp_path):
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def observe(body):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async def model(role, index, body):
        if index < 6:
            return completion("system_read_file", {"file_path": "shared/answer.txt"})
        await asyncio.Event().wait()

    sup, service, _, _, chief = await harness(
        tmp_path, model, observation_model=observe
    )
    try:
        result = await sup.create_solver(chief, "a")
        solver_id = result["data"]["agent_id"]
        await asyncio.wait_for(started.wait(), 5)
        await asyncio.wait_for(sup.pause_challenges(chief, ["a"], reason="fixture"), 3)
        assert cancelled.is_set() and not sup._solver_observers
        assert (
            await service.latest_agent_event(
                "run", solver_id, event_types={"solver_observation_snapshot"}
            )
            is None
        )
        events = await service.list_agent_events("run", solver_id)
        physical = [
            e
            for e in events
            if e["event_type"] == "model_call_finished"
            and e["payload"]["purpose"] == "observation"
        ]
        assert (
            len(physical) == 1 and physical[0]["payload"]["error"] == "CancelledError"
        )
    finally:
        await sup.close()
        await service.close()


@pytest.mark.parametrize(
    "content,stage",
    [
        ("```json\n{}\n```", "json"),
        ('{"map":{"LOCK":[{"claim":"x","sources":["1"]}]},"correction":null}', "schema"),
        ('{"map":{"LOCK":[{"claim":"x","sources":[1,2,3,4,5]}]},"correction":null}', "schema"),
        ('{"map":{"TENSION":[{"claim":"x","sources":[1,1]}]},"correction":null}', "schema"),
        ('{"map":{"NEXT":[]},"correction":null}', "schema"),
        ('{"map":{"LOCK":[{"claim":"x","sources":[99]}]},"correction":null}', "sources"),
    ],
)
def test_replay_preserves_strict_contract(content, stage):
    result = replay_observation(
        {"map": ObservationMap().model_dump(), "trace": [{"sequence": 1}]},
        {"output": content},
    )
    assert result["stage"] == stage


def test_replay_distinguishes_empty_and_unavailable():
    context = {"map": ObservationMap().model_dump(), "trace": []}
    assert replay_observation(context, {"output": '{"map":{},"correction":null}'}) == {
        "status": "accepted",
        "outcome": "empty",
        "trimmed_entries": {"LOCK": 0, "DEAD": 0, "ANGLES": 0, "TENSION": 0},
    }
    assert (
        replay_observation(context, {"output": '{"map":{},"correction":null}', "output_truncated": True})[
            "status"
        ]
        == "unavailable"
    )


def test_capacity_is_applied_only_after_every_source_and_entry_is_valid():
    from agent.observation_models import validate_observation_output
    raw = {"map": {"LOCK": [{"claim": f"priority {i}", "sources": [i]} for i in range(1, 5)]}, "correction": None}
    diagnostics = {}
    result = validate_observation_output(json.dumps(raw), {}, [{"sequence": i} for i in range(1, 5)], diagnostics=diagnostics)
    assert [e["claim"] for e in result["LOCK"]] == ["priority 1", "priority 2"]
    assert diagnostics["trimmed_entries"]["LOCK"] == 2
    raw["map"]["LOCK"][-1]["sources"] = [999]
    with pytest.raises(ValueError, match="unseen"):
        validate_observation_output(json.dumps(raw), {}, [{"sequence": i} for i in range(1, 5)])
    raw["map"]["LOCK"][-1]["sources"] = [4]
    raw["map"]["LOCK"][-1]["claim"] = "x" * 161
    with pytest.raises(ValidationError):
        validate_observation_output(json.dumps(raw), {}, [{"sequence": i} for i in range(1, 5)])


async def test_latest_window_records_skips_and_failure_preserves_map_coverage(tmp_path):
    service, _, solver = await build_state(tmp_path)
    await service.transition_agent("run", "solver", "running")
    now = [service.clock()]
    service.clock = lambda: now[0]
    requests = []
    async def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(200, json=map_response(body) if len(requests) == 1 else completion(content='invalid JSON'))
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        observer = SolverObserver(settings(), service, solver, client)
        try:
            events = await trace(service, TRACE_PAGE_SIZE + 20)
            await observer.poll()
            await asyncio.wait_for(observer.task, 2)
            await observer.poll()
            first = observer.snapshot
            seen = json.loads(requests[0]["messages"][-1]["content"])["trace"]
            assert seen[-1]["sequence"] == events[-1]
            assert first["coverage"]["skipped"]["count"] == len(events) - len(seen)
            assert first["map_coverage"]["through_sequence"] == events[-1]
            new = await trace(service)
            now[0] += timedelta(seconds=121)
            await observer.poll()
            await asyncio.wait_for(observer.task, 2)
            await observer.poll()
            assert observer.snapshot["cursor"] == new[-1]
            assert observer.snapshot["map_coverage"] == first["map_coverage"]
            assert observer.snapshot["coverage"]["status"] == "failed"
            assert "map_coverage" in observer.context_message()["content"]
        finally:
            await observer.close()
    await service.close()


async def test_revoked_batch_is_removed_from_map_without_another_model_call(tmp_path):
    from tests.test_solver_review import record, evidence
    service, _, solver = await build_state(tmp_path)
    try:
        await service.transition_agent("run", "solver", "running")
        sources = await trace(service)
        await service.save_solver_observation("run", solver, generation=0, expected_revision=0,
            through_sequence=sources[-1], observation={"DEAD": [{"claim": "fixture absent", "sources": [sources[0]]}]})
        ref = await evidence(service, solver)
        batch = await service.record_solver_review("run", solver, record(ref, conclusion_sequences=[sources[0]]))
        await service.record_solver_review("run", solver, record(ref, revoked_sequences=[batch], summary="Fixture control failure"))
        state = await service.solver_observation_state("run", solver)
        assert not state["map"]["DEAD"]
        assert state["map_coverage"]["through_sequence"] == sources[-1]
        # A model request started before the revocation can still finish later.
        more = await trace(service)
        await service.save_solver_observation("run", solver, generation=0,
            expected_revision=state["revision"], through_sequence=more[-1],
            observation={"DEAD": [{"claim": "late stale conclusion", "sources": [sources[0]]}]},
            diagnostics={"outcome": "updated"})
        saved = await service.latest_agent_event("run", "solver", event_types={"solver_observation_snapshot"})
        assert saved["payload"]["map"]["DEAD"] == []
        assert saved["payload"]["diagnostics"]["outcome"] == "empty"
    finally:
        await service.close()
