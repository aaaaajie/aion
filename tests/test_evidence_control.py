"""Tests for the evidence-driven control model and two-pass scheduling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from agent.state import StateService, StagnationManager
from agent.state.errors import StateConflict, StateError
from agent.state.models import ChallengeRecord
from agent.state.schemas import (
    AgentProgressInput,
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    ChallengeImport,
    CreateCycleInput,
    ExecutionTaskInput,
    FindingInput,
    FindingResolutionInput,
    HypothesisInput,
    VerificationUpdateInput,
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
    task_stage: str = "discovery",
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
        task_stage=task_stage,
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
    async with service.db.sessions.begin() as session:
        paused_challenge = await session.get(ChallengeRecord, ("run-1", "a"))
        assert paused_challenge is not None
        paused_challenge.warning_pivot_used = True

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
    assert challenge["warning_pivot_used"] is False

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
async def test_branch_uniqueness_and_independent_branch_survival(tmp_path) -> None:
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
            hypothesis_outcome="supported",
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
    assert finalized["hypothesis_outcome"] == "supported"
    branches = {
        item["branch_key"]: item["status"]
        for item in await service.list_branches("run-1", "web-1")
    }
    assert branches["http:web:stack:fingerprint"] == "completed"
    assert branches["http:web:params:matrix"] == "queued"
    await service.close()


@pytest.mark.asyncio
async def test_evidence_backed_candidate_resets_stagnation_once(tmp_path) -> None:
    clock = FakeClock()
    service = StateService(tmp_path / "state.sqlite3", clock=clock)
    await service.create_run(
        "run-1",
        challenges=[ChallengeImport(unique_code="web-1")],
        started_at=clock.value,
    )
    await _active_challenge(service, "web-1")
    agent = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="surface-map",
        task_key="surface-map-1",
        branch_key="http:web:surface:map",
    )
    context = CapabilityContext(
        run_id="run-1",
        agent_id=agent["agent_id"],
        role="execution",
        unique_code="web-1",
    )

    async with service.db.sessions.begin() as session:
        challenge = await session.get(ChallengeRecord, ("run-1", "web-1"))
        assert challenge is not None
        challenge.work_status = "warning"
        challenge.stagnation_level = 1
        challenge.warning_pivot_used = True

    before_progress_at = (await service.list_challenges("run-1"))[0]["last_progress_at"]
    clock.advance(300)
    first = await service.update_progress(
        "run-1",
        agent["agent_id"],
        context,
        AgentProgressInput(
            status="working",
            phase="surface-map",
            summary="mapped one concrete service surface",
            findings=[
                FindingInput(
                    category="service",
                    summary="POST /api/chat accepts JSON interactions",
                    detail={"method": "POST", "path": "/api/chat"},
                    confidence=0.9,
                    evidence_paths=["evidence/api-chat.json"],
                )
            ],
        ),
    )
    assert first["valid_progress"] is False
    assert first["progress_kinds"] == []
    progress_at = (await service.list_challenges("run-1"))[0]["last_progress_at"]
    assert progress_at == before_progress_at
    assert (await service.list_challenges("run-1"))[0]["warning_pivot_used"] is True

    clock.advance(60)
    duplicate = await service.update_progress(
        "run-1",
        agent["agent_id"],
        context,
        AgentProgressInput(
            status="working",
            phase="surface-map",
            summary="repeated the same finding",
            findings=[
                FindingInput(
                    category="service",
                    summary="POST /api/chat accepts JSON interactions",
                    detail={"method": "POST", "path": "/api/chat"},
                    confidence=0.95,
                    evidence_paths=["evidence/api-chat.json"],
                )
            ],
        ),
    )
    assert duplicate["valid_progress"] is False

    low_confidence = await service.update_progress(
        "run-1",
        agent["agent_id"],
        context,
        AgentProgressInput(
            status="working",
            phase="surface-map",
            summary="recorded a weak candidate",
            findings=[
                FindingInput(
                    category="other",
                    summary="possible framework marker",
                    confidence=0.79,
                    evidence_paths=["evidence/weak-marker.txt"],
                )
            ],
        ),
    )
    assert low_confidence["valid_progress"] is False

    clock.advance(60)
    upgraded_candidate = await service.update_progress(
        "run-1",
        agent["agent_id"],
        context,
        AgentProgressInput(
            status="working",
            phase="surface-map",
            summary="strengthened a previously weak candidate",
            findings=[
                FindingInput(
                    category="other",
                    summary="possible framework marker",
                    confidence=0.85,
                    evidence_paths=["evidence/weak-marker.txt"],
                )
            ],
        ),
    )
    assert upgraded_candidate["valid_progress"] is False
    assert upgraded_candidate["progress_kinds"] == []
    progress_at = (await service.list_challenges("run-1"))[0]["last_progress_at"]

    no_evidence = await service.update_progress(
        "run-1",
        agent["agent_id"],
        context,
        AgentProgressInput(
            status="working",
            phase="surface-map",
            summary="recorded an unsupported candidate",
            findings=[
                FindingInput(
                    category="other",
                    summary="possible admin route",
                    confidence=0.95,
                )
            ],
        ),
    )
    assert no_evidence["valid_progress"] is False
    assert (await service.list_challenges("run-1"))[0]["last_progress_at"] == progress_at

    await service.close()


@pytest.mark.asyncio
async def test_validation_debt_requires_a_cited_validation_task(tmp_path) -> None:
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
    source = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="candidate-source",
        task_key="candidate-source-1",
        branch_key="http:web:candidate:source",
        challenge_agent=challenge_agent,
    )
    source_context = CapabilityContext(
        run_id="run-1",
        agent_id=source["agent_id"],
        role="execution",
        unique_code="web-1",
    )
    await service.finalize_execution_agent(
        "run-1",
        source["agent_id"],
        source_context,
        AgentReportInput(
            status="completed",
            summary="found a high-confidence authorization candidate",
            hypothesis_outcome="inconclusive",
            findings=[
                FindingInput(
                    category="vulnerability",
                    summary="document endpoint may lack authorization",
                    confidence=0.9,
                    verification_status="candidate",
                    evidence_paths=["evidence/document-candidate.json"],
                )
            ],
        ),
    )
    challenge_context = CapabilityContext(
        run_id="run-1",
        agent_id=challenge_agent["agent_id"],
        role="challenge",
        unique_code="web-1",
    )
    state = await service.get_challenge_context(
        "run-1", "web-1", challenge_context
    )
    assert len(state["validation_debt"]) == 1
    debt_ref = state["validation_debt"][0]["finding_ref"]
    assert state["validation_debt"][0]["covered"] is False

    cycle = await service.begin_cycle(
        "run-1",
        "web-1",
        challenge_context,
        CreateCycleInput(
            expected_challenge_version=state["challenge"]["version"]
        ),
    )
    discovery_only = AnalysisPlanInput(
        expected_version=cycle["version"],
        analysis_summary="continue broad discovery",
        hypotheses=[
            HypothesisInput(key="more-discovery", statement="another surface exists")
        ],
        tasks=[
            ExecutionTaskInput(
                task_key="more-discovery-1",
                hypothesis_key="more-discovery",
                kind="recon",
                task_stage="discovery",
                objective="discover another surface",
            )
        ],
    )
    with pytest.raises(StateConflict) as required:
        await service.submit_analysis_plan(
            "run-1", cycle["cycle_id"], challenge_context, discovery_only
        )
    assert required.value.code == "validation_wave_required"

    mixed = AnalysisPlanInput(
        expected_version=cycle["version"],
        analysis_summary="validate debt while retaining independent discovery",
        hypotheses=[
            HypothesisInput(
                key="authorization-validation",
                statement="the document endpoint lacks authorization",
            ),
            HypothesisInput(
                key="independent-surface",
                statement="a separate protocol surface may exist",
            ),
        ],
        tasks=[
            ExecutionTaskInput(
                task_key="authorization-validation-1",
                hypothesis_key="authorization-validation",
                kind="verification",
                task_stage="validation",
                objective="validate the authorization candidate",
                context_refs=[debt_ref],
            ),
            ExecutionTaskInput(
                task_key="independent-surface-1",
                hypothesis_key="independent-surface",
                kind="recon",
                task_stage="discovery",
                objective="inspect the independent protocol surface",
            ),
        ],
    )
    planned = await service.submit_analysis_plan(
        "run-1", cycle["cycle_id"], challenge_context, mixed
    )
    assert len(planned["admissions"]) == 2
    refreshed = await service.get_challenge_context(
        "run-1", "web-1", challenge_context
    )
    assert refreshed["validation_debt"][0]["covered"] is True
    assert {
        item["task_stage"] for item in refreshed["task_ledger"][:2]
    } == {"discovery", "validation"}

    validation_agent = next(
        item
        for item in refreshed["active_agents"]
        if item["task_stage"] == "validation"
    )
    await service.finalize_execution_agent(
        "run-1",
        validation_agent["agent_id"],
        CapabilityContext(
            run_id="run-1",
            agent_id=validation_agent["agent_id"],
            role="execution",
            unique_code="web-1",
        ),
        AgentReportInput(
            status="completed",
            summary="authorization candidate was disproved",
            hypothesis_outcome="rejected",
            evidence_paths=["evidence/authorization-rejected.json"],
            finding_resolutions=[
                FindingResolutionInput(
                    finding_ref=debt_ref,
                    outcome="rejected",
                    evidence_paths=["evidence/authorization-rejected.json"],
                )
            ],
        ),
    )
    after_report = await service.get_challenge_context(
        "run-1", "web-1", challenge_context
    )
    assert next(
        item
        for item in after_report["hypotheses"]
        if item["hypothesis_key"] == "authorization-validation"
    )["status"] == "rejected"

    discovery_agent = next(
        item
        for item in after_report["active_agents"]
        if item["task_stage"] == "discovery"
    )
    await service.finalize_execution_agent(
        "run-1",
        discovery_agent["agent_id"],
        CapabilityContext(
            run_id="run-1",
            agent_id=discovery_agent["agent_id"],
            role="execution",
            unique_code="web-1",
        ),
        AgentReportInput(
            status="completed",
            summary="independent discovery was inconclusive",
            hypothesis_outcome="inconclusive",
        ),
    )
    await service.commit_cycle(
        "run-1",
        cycle["cycle_id"],
        challenge_context,
        VerificationUpdateInput(
            expected_version=planned["version"],
            summary="reject the disproved candidate",
            outcome="no_progress",
        ),
    )
    committed_state = await service.get_challenge_context(
        "run-1", "web-1", challenge_context
    )
    assert committed_state["validation_debt"] == []
    await service.close()


@pytest.mark.asyncio
async def test_candidate_progress_does_not_verify_or_cancel_sibling_branches(
    tmp_path,
) -> None:
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
    candidate_agent = await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="stack-candidate",
        task_key="stack-candidate-1",
        branch_key="http:web:stack:candidate",
        challenge_agent=challenge_agent,
    )
    await _execution_agent(
        service,
        unique_code="web-1",
        hypothesis_key="auth-boundary",
        task_key="auth-boundary-1",
        branch_key="http:web:auth:boundary",
        challenge_agent=challenge_agent,
    )
    context = CapabilityContext(
        run_id="run-1",
        agent_id=candidate_agent["agent_id"],
        role="execution",
        unique_code="web-1",
    )
    finalized = await service.finalize_execution_agent(
        "run-1",
        candidate_agent["agent_id"],
        context,
        AgentReportInput(
            status="completed",
            summary="found a strong stack candidate",
            hypothesis_outcome="inconclusive",
            findings=[
                FindingInput(
                    category="other",
                    summary="application likely uses FleaPHP",
                    confidence=0.93,
                    evidence_paths=["evidence/framework-debug.html"],
                )
            ],
        ),
    )
    assert finalized["valid_progress"] is False
    assert finalized["progress_kinds"] == []
    assert finalized["hypothesis_outcome"] == "inconclusive"
    branches = {
        item["branch_key"]: item["status"]
        for item in await service.list_branches("run-1", "web-1")
    }
    assert branches["http:web:auth:boundary"] != "superseded"
    hypotheses = {
        item["hypothesis_key"]: item["status"]
        for item in await service.list_hypotheses("run-1", "web-1")
    }
    assert hypotheses["stack-candidate"] == "inconclusive"
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
                hypothesis_outcome="supported",
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
