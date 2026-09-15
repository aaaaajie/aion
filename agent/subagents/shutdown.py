"""One shutdown deadline: stop work, confirm containers, then flush state."""

import asyncio

from agent.container_cleanup import capture_targets, cleanup_targets
from agent.deadline import before, cancel_before


async def shutdown_supervisor(supervisor, *, preserve_run, deadline):
    s = supervisor
    if s._ownership_conflict:
        await before(s._close_model_http_client(), deadline)
        return
    s._closing = True
    s._pausing = preserve_run
    stop_deadline = min(deadline - 20, asyncio.get_running_loop().time() + 10)
    release_deadline = deadline - 5
    if not s.run_id:
        await before(s._close_model_http_client(), deadline)
        return
    service = s._service()
    overview = await service.get_overview(s._run_id())
    for agent in overview["agents"]:
        s._close_agent_admission(agent["agent_id"])
        s._cleanup_deadlines[agent["agent_id"]] = min(s._cleanup_deadlines.get(agent["agent_id"], stop_deadline), stop_deadline)
    targets = await capture_targets(service, s._run_id(), reason="runtime_pause" if preserve_run else "runtime_closed", deadline=deadline)
    tasks = [s._poll_task, s._stagnation_task, *s._challenge_completion_tasks.values()]
    s._poll_task = s._stagnation_task = None
    s._challenge_completion_tasks.clear()
    try:
        # All targets are durable before cancellation can consume the stopping budget.
        try:
            await before(asyncio.gather(
                cancel_before(tasks, stop_deadline),
                s._pause_all() if preserve_run else s._stop_all(),
                s._finish_run_managers("pause_run" if preserve_run else "finish_run", deadline=stop_deadline),
                return_exceptions=True,
            ), stop_deadline)
        except TimeoutError:
            await service.append_run_event(s._run_id(), "runtime_stop_deadline", {"deadline_monotonic": stop_deadline})
        await cleanup_targets(service, s.benchmark, s._run_id(), targets, deadline=release_deadline, locks=s._container_locks)
        # A cancellation-resistant task cannot prevent its terminal receipt from being persisted.
        # Reuse the first recorded cause; incomplete cleanup is never called successful.
        for agent in overview["agents"]:
            if agent["role"] != "worker":
                continue
            task = s._tasks.get(agent["agent_id"])
            current = (await service.get_agent_runtime(s._run_id(), agent["agent_id"]))["agent"]
            report = current.get("final_report") or {}
            closed = (report.get("system_finalized") and report.get("owned_resources_closed") is True) or (
                agent["agent_id"] in s._resources_closed and (task is None or task.done()))
            outcome = await s._record_worker_outcome(agent["agent_id"], reason="runtime_pause" if preserve_run else "runtime_closed")
            cleanup = {"resource_cleanup_status": "closed" if closed else "release_pending",
                       "owned_resources_closed": closed, "reason": "shutdown_reconciliation"}
            await service.append_agent_event(s._run_id(), agent["agent_id"], "worker_resource_cleanup", cleanup)
            await service.finalize_worker_runtime(s._run_id(), agent["agent_id"], s._state_context(agent["agent_id"]),
                                                  **outcome, **{k: cleanup[k] for k in ("resource_cleanup_status", "owned_resources_closed")})
        try:
            await before(asyncio.gather(*(r.close() for r in list(s._runners.values())), return_exceptions=True), deadline)
        except TimeoutError:
            pass
        s._runners.clear()
        await before(s._close_model_http_client(), deadline)
        await before(s._project(), deadline)
    finally:
        s._release_run_ownership()
