"""The real Runner continues after timeout; Chief is independent of cleanup."""

import asyncio
import json

import pytest

from tests.test_shell_lifecycle import orphan_command
from tests.test_solver_lifecycle import Platform, completion, harness, tool
from tests.test_solver_resources import until, status, technical


@pytest.mark.asyncio
async def test_solver_executes_after_shell_timeout_and_submits(tmp_path):
    async def solve(role, index, body):
        if index == 0:
            return completion(
                "system_shell",
                {"command": orphan_command(parent_wait=True), "timeout": 0.2},
            )
        if index == 1:
            results = [
                json.loads(m["content"])
                for m in body["messages"]
                if m.get("role") == "tool"
            ]
            assert results[-1]["data"]["status"] == "timeout"
            return completion(
                "system_shell", {"command": "printf 'flag{after_timeout}'"}
            )
        if index == 2:
            return completion("solver_submit_flag", {"flag": "flag{after_timeout}"})
        return completion(content="The platform confirmed completion.")

    sup, service, platform, calls, chief = await harness(tmp_path, solve)
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await asyncio.wait_for(sup._tasks[solver], 8)
        assert platform.submissions == ["flag{after_timeout}"]
        assert calls["solver"] == 3
        assert await status(service, solver, "completed")
        await sup.pause()
        assert await status(service, solver, "completed")
    finally:
        await sup.close()
        await service.close()


class TwoChallenges(Platform):
    async def dispatch(self, name, args):
        result = await super().dispatch(name, args)
        if name == "benchmark_list_challenges":
            result["data"].append({**result["data"][0], "unique_code": "b"})
        return result


@pytest.mark.asyncio
@pytest.mark.parametrize("release", [True, False])
async def test_chief_pauses_shell_and_starts_another_solver(tmp_path, release):
    sup, service, platform, calls, chief = await harness(
        tmp_path, lambda *args: completion("solver_wait"), platform=TwoChallenges()
    )
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(service, solver, "waiting"))
        registry = sup._registries[solver]
        result = await technical(
            registry,
            "system_task_start",
            {"name": "orphan fixture", "command": orphan_command(parent_wait=True)},
        )
        assert result["ok"], result
        await asyncio.sleep(0.1)
        paused = await asyncio.wait_for(
            tool(
                sup,
                chief,
                "chief_pause_challenges",
                {
                    "unique_codes": ["a"],
                    "reason": "test stuck shell",
                    "release_container": release,
                },
            ),
            7,
        )
        item = paused.result["data"]["results"][0]
        assert item["ok"] and item["cleanup"]["ok"], paused
        assert platform.close_calls == int(release)
        denied = await technical(registry, "system_shell", {"command": "printf denied"})
        assert denied["error"]["code"] == "agent_inactive"
        following = await tool(
            sup, chief, "chief_launch_challenges", {"unique_codes": ["b"]}
        )
        assert following.result["ok"], following.result
        assert following.result["data"]["results"][0]["data"]["agent_id"] != solver
        rows = await service.list_shell_tasks("run", agent_id=solver)
        assert rows and all(r["status"] != "running" for r in rows)
    finally:
        await sup.close()
        await service.close()


@pytest.mark.asyncio
async def test_cancellation_resistant_cleanup_is_retained_and_resume_blocked(
    tmp_path, monkeypatch
):
    import agent.subagents.lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "AGENT_CLEANUP_SECONDS", 0.15)
    sup, service, platform, calls, chief = await harness(
        tmp_path, lambda *args: completion("solver_wait")
    )
    release = asyncio.Event()

    class Stuck:
        calls = 0

        async def close(self):
            self.calls += 1
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    pass

    class Healthy:
        closed = False

        async def close(self):
            self.closed = True

    stuck, healthy = Stuck(), Healthy()
    try:
        solver = (await sup.create_solver(chief, "a"))["data"]["agent_id"]
        await until(lambda: status(service, solver, "waiting"))
        sup._registries[solver].providers.extend([stuck, healthy])
        paused = await asyncio.wait_for(
            sup.pause_challenges(chief, ["a"], reason="stuck provider"), 1.5
        )
        item = paused["data"]["results"][0]
        assert not item["ok"] and not item["cleanup"]["ok"]
        assert item["release"]["released"] and healthy.closed
        assert solver in sup._registries
        denied = await asyncio.wait_for(sup.create_solver(chief, "a"), 1.5)
        assert denied["error"]["code"] == "agent_cleanup_pending", denied
        assert stuck.calls == 1
        events = await service.list_agent_events("run", solver, limit=100)
        assert any(
            e["event_type"] == "agent_resource_cleanup_failed"
            and any(
                f["resource"] == "Stuck" and f["error"] == "TimeoutError"
                for f in e["payload"]["failures"]
            )
            for e in events
        )
        release.set()
        await asyncio.sleep(0.02)
        assert (await sup._finish_agent_resources(solver))["ok"]
        assert (await sup.create_solver(chief, "a"))["data"]["agent_id"] == solver
    finally:
        release.set()
        await sup.close()
        await service.close()
