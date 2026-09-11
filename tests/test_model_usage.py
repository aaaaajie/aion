import json
import pytest
import httpx
from agent.model_usage import post_model, aggregate_usage
from agent.memory.summarizer import SessionMemorySummarizer
from agent.config import AgentSettings
from agent.api import create_state_app
from agent.state import CapabilityRegistry, AgentReportInput
from scripts.runtime_web.server import _ReadOnlyStore
from tests.solver_state import build_state, worker


@pytest.mark.asyncio
async def test_persisted_physical_requests_count_retries_auxiliary_and_unknown_metrics(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    count = 0

    async def respond(request):
        nonlocal count
        count += 1
        usage = {
            "prompt_tokens": 100,
            "prompt_cache_hit_tokens": 40,
            "prompt_cache_miss_tokens": 60,
            "completion_tokens": 10,
        }
        return httpx.Response(
            503 if count == 1 else 200,
            json={
                "usage": usage,
                "choices": [
                    {"message": {"content": "Stable facts: evidence retained."}}
                ],
            },
        )

    async def write(event, payload):
        return await s.append_agent_event("run", "solver", event, payload)

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        for _ in range(2):
            await post_model(
                client,
                "https://model.test",
                json={"model": "fixture"},
                event_writer=write,
            )
        summarizer = SessionMemorySummarizer(
            AgentSettings(
                llm_base_url="https://model.test",
                llm_model="fixture",
                llm_api_key="fixture",
            ),
            client=client,
            event_writer=write,
        )
        await summarizer.summarize(
            current_memory="", checkpoint={}, recent_messages=[], recent_events=[]
        )
        events = await s.list_agent_events("run", "solver", limit=100)
        calls = [e for e in events if e["event_type"] == "model_call_finished"]
        assert len(calls) == 3
        # A projection retry does not charge the same persisted call twice.
        await write("model_call_finished", calls[-1]["payload"])
        snapshot = _ReadOnlyStore(s.db.path, "run").snapshot()
        usage = snapshot["token_usage"]
        for scope in (
            usage["run"],
            usage["agents"]["solver"],
            usage["challenges"]["a"],
        ):
            assert scope == {
                "input_tokens": 300,
                "cache_hit_tokens": 120,
                "uncached_input_tokens": 180,
                "output_tokens": 30,
                "known_totals": {"input_tokens": 300, "cache_hit_tokens": 120, "uncached_input_tokens": 180, "output_tokens": 30},
                "calls": 3,
                "calls_with_missing_usage": 0,
            }
        await write(
            "model_call_started", {"model_call_id": "lost-at-crash", "purpose": "agent"}
        )
        unknown = _ReadOnlyStore(s.db.path, "run").snapshot()["token_usage"]["run"]
        assert unknown["input_tokens"] is None and unknown["cache_hit_tokens"] is None
        assert unknown["calls"] == 4 and unknown["calls_with_missing_usage"] == 1
        assert unknown["known_totals"]["input_tokens"] == 300
        assert usage["purposes"]["memory"]["calls"] == 1
        assert usage["purposes"]["agent"]["calls"] == 2
    finally:
        await client.aclose()
        await s.close()


@pytest.mark.asyncio
async def test_current_api_enforces_review_and_run_scope(tmp_path):
    s, c, solver = await build_state(tmp_path)
    reviewer = await worker(s, solver, "review", mode="review")
    registry = CapabilityRegistry()
    cap = registry.issue("run", reviewer.agent_id, "worker", "a")
    app = create_state_app(s, registry)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://local"
    )
    # Capability wrappers expose their bearer token to the caller, not to models.
    headers = {"X-Aion-Capability": cap.token}
    try:
        good = await client.post(
            f"/internal/v1/runs/run/workers/{reviewer.agent_id}/reports",
            headers=headers,
            json={"status": "completed", "summary": "read-only review"},
        )
        assert good.status_code == 200, good.text
        forbidden = await client.post(
            "/internal/v1/runs/run/workers/delegate",
            headers=headers,
            json=[{"task_key": "bad", "objective": "bad"}],
        )
        assert forbidden.status_code == 403
        cross = await client.get(
            "/internal/v1/runs/other/challenges/a/context", headers=headers
        )
        assert cross.status_code == 403
        assert (
            await client.post(
                "/internal/v1/runs/run/challenges/a/dispatch", headers=headers, json={}
            )
        ).status_code == 404
    finally:
        await client.aclose()
        await s.close()


@pytest.mark.asyncio
async def test_benchmark_auxiliary_calls_use_supervisor_owner_and_nullable_usage(
    tmp_path,
):
    from tools.benchmark.recovery import BenchmarkLLMRecovery
    from tests.test_solver_lifecycle import harness, completion, Platform
    from agent.model_usage import usage_values

    assert all(value is None for value in usage_values({"usage": None}).values())
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": "{}"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 2},
                },
            )
        )
    )
    recovery = BenchmarkLLMRecovery(
        AgentSettings(
            llm_base_url="https://model.test",
            llm_model="fixture",
            llm_api_key="fixture",
        ),
        client=client,
    )

    class AdapterPlatform(Platform):
        async def dispatch(self, name, args):
            await recovery._complete(
                system="fixture", user={"operation": name}, max_tokens=10
            )
            return await super().dispatch(name, args)

    sup, s, platform, calls, chief = await harness(
        tmp_path, lambda *_: completion("solver_wait"), platform=AdapterPlatform()
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await s.create_shell_task('run', solver, task_id='pending-platform-check',
            pid=1, process_started_at=1, cwd='.', temp_dir='tmp', output_path='out', capture_limit=100)

        from tests.test_solver_resources import until, status

        await until(lambda: status(s, solver, "waiting"))
        await sup._benchmark_execute("benchmark_list_challenges", {}, caller_id=solver)
        events = await s.list_agent_events("run", solver, limit=100)
        auxiliary = [
            e
            for e in events
            if e["event_type"] == "model_call_finished"
            and e["payload"]["purpose"] == "benchmark_recovery"
        ]
        assert len(auxiliary) == 1 and auxiliary[0]["payload"]["input_tokens"] == 10
        snapshot = _ReadOnlyStore(s.db.path, "run").snapshot()["token_usage"]
        assert snapshot["agents"][solver]["cache_hit_tokens"] is None
        assert snapshot["challenges"]["a"]["input_tokens"] >= 10
    finally:
        await sup.close()
        await s.close()
        await client.aclose()
