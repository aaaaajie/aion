from agent.state import StateService, StateDatabase, CapabilityContext, WorkerTaskInput


async def build_state(tmp_path):
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path,
    )
    await service.create_run(
        "run",
        challenges=[
            {"unique_code": "a", "container_status": "running"},
            {"unique_code": "b"},
        ],
    )
    await service.register_agent("run", role="chief", agent_id="chief")
    chief = CapabilityContext(run_id="run", role="chief", agent_id="chief")
    await service.start_challenge("run", "a", chief)
    await service.register_agent(
        "run", role="solver", agent_id="solver", parent_id="chief", unique_code="a"
    )
    solver = CapabilityContext(
        run_id="run", role="solver", agent_id="solver", unique_code="a"
    )
    return service, chief, solver


async def worker(service, solver, key="task", **kwargs):
    item = (
        await service.delegate_workers(
            "run", solver, [WorkerTaskInput(task_key=key, objective=key, **kwargs)]
        )
    )["admissions"][0]
    return CapabilityContext(
        run_id="run", role="worker", agent_id=item["agent_id"], unique_code="a"
    )
