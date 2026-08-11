"""Tests for the evidence-driven control model and two-pass scheduling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from agent.state import StateService, StagnationManager
from agent.state.errors import StateConflict, StateError
from agent.state.schemas import (
    AgentReportInput,
    CapabilityContext,
    ChallengeImport,
    FindingInput,
)
from tools.http import HttpInteractionEngine, HttpProbeManager
from tools.http.models import HttpOutputFilters, HttpRequestSpec
from tools.system.policy import WorkspacePolicy


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.value = start or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


async def _active_challenge(service: StateService, code: str) -> None:
    await service.start_challenge("run-1", code)
    await service.import_challenges(
        "run-1", [ChallengeImport(unique_code=code, container_status="available")]
    )


async def _execution_agent(
    service: StateService,
    *,
    unique_code: str,
    hypothesis_key: str,
    task_key: str,
    branch_key: str,
    challenge_agent: dict | None = None,
) -> dict:
    if challenge_agent is None:
        chief = await service.register_agent("run-1", role="chief")
        challenge_agent = await service.register_agent(
            "run-1",
            role="challenge",
            parent_id=chief["agent_id"],
            unique_code=unique_code,
        )
    return await service.register_agent(
        "run-1",
        role="execution",
        parent_id=challenge_agent["agent_id"],
        unique_code=unique_code,
        hypothesis_key=hypothesis_key,
        task_key=task_key,
        branch_key=branch_key,
        mission="evidence fixture",
    )


@pytest.mark.asyncio
async def test_second_pass_ready_and_begin(tmp_path) -> None:
    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[
            ChallengeImport(unique_code="a"),
            ChallengeImport(unique_code="b"),
        ],
        started_at=clock.value,
    )
    await service.import_challenges(
        "run-1",
        [
            ChallengeImport(unique_code="a", container_status="stopped"),
            ChallengeImport(unique_code="b", container_status="stopped", is_completed=True),
        ],
    )
    await service.mark_challenge_paused("run-1", "a")

    ready = await service.second_pass_ready("run-1")
    assert ready["ready"] is True
    assert ready["unique_codes"] == ["a"]

    began = await service.begin_second_pass("run-1")
    assert began["started"] is True
    assert began["unique_codes"] == ["a"]
    run = (await service.get_overview("run-1"))["run"]
    assert run["pass_number"] == 2
    challenge = next(
        item
        for item in await service.list_challenges("run-1")
        if item["unique_code"] == "a"
    )
    assert challenge["work_status"] == "unassigned"
    assert challenge["stagnation_level"] == 0
    assert challenge["control_state"] == "ok"
    assert challenge["resume_count"] == 1
    assert challenge["pass_number"] == 2

    again = await service.begin_second_pass("run-1")
    assert again["started"] is False
    await service.close()


@pytest.mark.asyncio
async def test_second_pass_requires_remaining_time(tmp_path) -> None:
    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="a")],
        started_at=clock.value,
    )
    await service.import_challenges(
        "run-1", [ChallengeImport(unique_code="a", container_status="stopped")]
    )
    await service.mark_challenge_paused("run-1", "a")
    clock.advance(340 * 60)
    ready = await service.second_pass_ready("run-1")
    assert ready["ready"] is False
    assert ready["reason"] == "insufficient_remaining_time"
    await service.close()


@pytest.mark.asyncio
async def test_waiting_external_change_freezes_stagnation_clock(tmp_path) -> None:
    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="web-1")],
        started_at=clock.value,
    )
    chief = await service.register_agent("run-1", role="chief")
    await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    await _active_challenge(service, "web-1")
    await service.set_challenge_control_state(
        "run-1", "web-1", "waiting_external_change", reason="remote_hint"
    )
    clock.advance(240)
    manager = StagnationManager(service, clock=clock)
    result = await manager.evaluate("run-1", "web-1")
    assert result["action"] == "waiting_external"
    assert result["elapsed_seconds"] == 0
    clock.advance(120)
    await manager.evaluate("run-1", "web-1")
    challenge = next(
        item
        for item in await service.list_challenges("run-1")
        if item["unique_code"] == "web-1"
    )
    assert challenge["control_state"] == "ok"
    assert challenge["work_status"] == "active"
    clock.advance(480)
    warning = await manager.evaluate("run-1", "web-1")
    assert warning["level"] == 1
    challenge = next(
        item
        for item in await service.list_challenges("run-1")
        if item["unique_code"] == "web-1"
    )
    assert challenge["control_state"] == "degraded"
    await service.close()


@pytest.mark.asyncio
async def test_observation_dedupe_and_routes_branch(tmp_path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")]
    )
    chief = await service.register_agent("run-1", role="chief")
    await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    await _active_challenge(service, "web-1")
    first = await service.record_observation(
        "run-1",
        "web-1",
        category="service",
        summary="http endpoint",
        detail={"service": "http", "port": 80},
        source="network_discovery",
    )
    assert first["created"] is True
    assert first["branches_created"] == ["http:web:stack:fingerprint"]
    second = await service.record_observation(
        "run-1",
        "web-1",
        category="service",
        summary="http endpoint",
        detail={"service": "http", "port": 80},
        source="network_discovery",
    )
    assert second["created"] is False
    assert second["branches_created"] == []
    observations = await service.list_observations("run-1", "web-1")
    assert len(observations) == 1
    await service.close()


@pytest.mark.asyncio
async def test_branch_uniqueness_and_sibling_cancel(tmp_path) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")]
    )
    await _active_challenge(service, "web-1")
    chief = await service.register_agent("run-1", role="chief")
    challenge_agent = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="web-1",
    )
    first = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="stack",
        task_key="stack-1",
        branch_key="http:web:stack:fingerprint",
        challenge_agent=challenge_agent,
    )
    await service.transition_agent("run-1", first["agent_id"], "running")
    second = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="params",
            task_key="params-1",
            branch_key="http:web:params:matrix",
            challenge_agent=challenge_agent,
        )
    with pytest.raises(StateConflict) as conflict:
        await _execution_agent(
            service,
            unique_code="web-1",
            hypothesis_key="stack-again",
            task_key="stack-2",
            branch_key="http:web:stack:fingerprint",
            challenge_agent=challenge_agent,
        )
    assert conflict.value.code == "branch_already_active"

    context = CapabilityContext(
        run_id="run-1",
        agent_id=first["agent_id"],
        role="execution",
        unique_code="web-1",
    )
    finalized = await service.finalize_execution_agent(
        "run-1",
        first["agent_id"],
        context,
        AgentReportInput(
            status="completed",
            summary="stack verified",
            findings=[
                FindingInput(
                    category="service",
                    summary="http stack identified",
                    evidence_paths=["evidence.txt"],
                    verification_status="verified",
                )
            ],
        ),
    )
    assert finalized["cancelled_branches"] == ["http:web:params:matrix"]
    branches = {
        item["branch_key"]: item["status"]
        for item in await service.list_branches("run-1", "web-1")
    }
    assert branches["http:web:stack:fingerprint"] == "completed"
    assert branches["http:web:params:matrix"] == "superseded"
    await service.close()


@pytest.mark.asyncio
async def test_evidence_path_traversal_rejected(tmp_path) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="web-1")]
    )
    await _active_challenge(service, "web-1")
    agent = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="h",
        task_key="t",
        branch_key="service:generic:probe",
    )
    context = CapabilityContext(
        run_id="run-1",
        agent_id=agent["agent_id"],
        role="execution",
        unique_code="web-1",
    )
    with pytest.raises(StateError) as error:
        await service.finalize_execution_agent(
            "run-1",
            agent["agent_id"],
            context,
            AgentReportInput(
                status="completed",
                summary="bad path",
                findings=[
                    FindingInput(
                        category="service",
                        summary="bad evidence path",
                        evidence_paths=["../escape.txt"],
                        verification_status="verified",
                    )
                ],
            ),
        )
    assert error.value.code == "invalid_evidence_path"
    await service.close()


@pytest.mark.asyncio
async def test_http_connection_context_sequence(tmp_path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"ok {request.url.path}")

    service = StateService(tmp_path / "runs" / "run-1" / "state.sqlite3", run_root=tmp_path / "runs")
    await service.create_run("run-1")
    agent = await service.register_agent("run-1", role="chief")
    policy = WorkspacePolicy(tmp_path)
    manager = HttpProbeManager(
        policy,
        service,
        "run-1",
        engine=HttpInteractionEngine(
            policy, transport=httpx.MockTransport(handler)
        ),
    )
    await manager.initialize()
    try:
        first = await manager.start_request(
            agent["agent_id"],
            request=HttpRequestSpec(
                request_intent="chain",
                url="http://example.test/1",
                connection_context_id="ctx-1",
            ),
            wait_seconds=None,
        )
        second = await manager.start_request(
            agent["agent_id"],
            request=HttpRequestSpec(
                request_intent="chain",
                url="http://example.test/2",
                connection_context_id="ctx-1",
            ),
            wait_seconds=None,
        )
        responses = [
            item
            for item in [*first["results"], *second["results"]]
            if item["type"] == "response"
        ]
        assert sorted(item["sequence_id"] for item in responses) == [0, 1]
        assert all(item["connection_context_id"] == "ctx-1" for item in responses)
        filtered = await manager.output(
            agent["agent_id"],
            interaction_id=second["interaction_id"],
            filters=HttpOutputFilters(
                connection_context_id="ctx-1", sequence_id_min=1
            ),
        )
        assert [item["sequence_id"] for item in filtered["results"]] == [1]
    finally:
        await manager.finish_run()
        await service.close()
