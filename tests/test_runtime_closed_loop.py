from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent.state import CapabilityContext, ChallengeDispatchInput
from agent.state.database import StateDatabase
from agent.state.schemas import AgentReportInput, ChallengeImport
from agent.state.service import StateService


@pytest.mark.asyncio
async def test_report_arrival_and_next_dispatch_do_not_conflict(tmp_path: Path) -> None:
    service = StateService(StateDatabase(tmp_path / "state.sqlite3"), run_root=tmp_path / "runs")
    await service.initialize()
    await service.create_run(
        "run", challenges=[ChallengeImport(unique_code="c", container_status="running")]
    )
    await service.register_agent("run", agent_id="chief", role="chief", initial_prompt="x")
    await service.register_agent(
        "run", agent_id="challenge", role="challenge", parent_id="chief", unique_code="c", initial_prompt="x"
    )
    chief = CapabilityContext(run_id="run", agent_id="chief", role="chief")
    challenge = CapabilityContext(run_id="run", agent_id="challenge", role="challenge", unique_code="c")
    await service.start_challenge("run", "c", chief)
    first = await service.dispatch_challenge(
        "run", "c", challenge, ChallengeDispatchInput(summary="first", tasks=[{"objective": "slow"}])
    )
    execution_id = first["admissions"][0]["agent_id"]
    execution = CapabilityContext(run_id="run", agent_id=execution_id, role="execution", unique_code="c")

    report, dispatched = await asyncio.gather(
        service.submit_report(
            "run", execution_id, execution, AgentReportInput(status="completed", summary="result")
        ),
        service.dispatch_challenge(
            "run", "c", challenge, ChallengeDispatchInput(summary="next", tasks=[{"objective": "independent"}])
        ),
    )
    assert report["report_id"].startswith("report_")
    assert len(dispatched["admissions"]) == 1
    assert dispatched["decision_number"] == 2
    await service.close()
