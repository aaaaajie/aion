from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent.config import AgentSettings
from agent.runner import AgentRunner
from agent.skills import SkillCatalog, SkillSessionContext, SkillTools
from agent.skills.awareness import CapabilityAwareness
from agent.state import AgentStateStore, CapabilityContext
from agent.state.database import StateDatabase
from agent.state.service import StateService
from agent.subagents.models import SolverReviewArguments
from agent.tooling import ToolRegistry


@pytest.mark.asyncio
async def test_chief_wait_compares_delivered_schedule_snapshot(tmp_path):
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path,
    )
    try:
        await service.create_run(
            "run", challenges=[{"unique_code": "fixture", "container_status": "running"}]
        )
        await service.register_agent("run", role="chief", agent_id="chief")
        context = CapabilityContext(run_id="run", role="chief", agent_id="chief")
        await service.start_challenge("run", "fixture", context)
        observed = await service.observe_chief("run", context)
        await service.append_agent_event(
            "run",
            "chief",
            "chief_observation_delivered",
            {
                "observation_revision": observed["observation_revision"],
                "observation_digest": observed["observation_digest"],
            },
        )

        assert (
            await service.record_controller_wait("run", "chief", "unchanged")
        )["status"] == "waiting"
        await service.close_challenge("run", "fixture", context)
        ready = await service.record_controller_wait("run", "chief", "changed")
        assert ready["status"] == "ready"
        assert ready["code"] == "state_changed"
    finally:
        await service.close()


def test_capability_claim_requires_validated_new_information():
    capability = {
        "kind": "file_read",
        "target_environment": "target web process",
        "scope": "Can read application files",
        "limitations": "Directory listing is not established",
    }
    with pytest.raises(ValidationError):
        SolverReviewArguments.model_validate(
            {
                "hypothesis_id": "access",
                "covered_sequences": [],
                "assessment": "inconclusive",
                "summary": "Candidate access",
                "next_test": "Read a known target file",
                "acquired_capabilities": [capability],
            }
        )


def test_access_keywords_only_create_a_locator_candidate():
    context = SkillSessionContext(
        SkillCatalog(),
        role="solver",
        service=None,
        run_id="run",
        agent_id="solver",
    )
    awareness = CapabilityAwareness(context, ToolRegistry([SkillTools(context)]))
    candidates = awareness.ingest(
        "command execution may be available", source="fixture", round_number=1
    )
    assert candidates and candidates[0]["skill_id"] == "common/ctf-flag-locator"
    assert not context.active_skills


@pytest.mark.asyncio
async def test_validated_capability_auto_activates_locator_once(tmp_path):
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path,
    )
    try:
        await service.create_run(
            "run", challenges=[{"unique_code": "fixture", "container_status": "running"}]
        )
        await service.register_agent("run", role="chief", agent_id="chief")
        chief = CapabilityContext(run_id="run", role="chief", agent_id="chief")
        await service.start_challenge("run", "fixture", chief)
        await service.register_agent(
            "run",
            role="solver",
            agent_id="solver",
            parent_id="chief",
            unique_code="fixture",
        )
        solver = CapabilityContext(
            run_id="run", role="solver", agent_id="solver", unique_code="fixture"
        )
        evidence = await service.persist_evidence(
            "run",
            solver,
            evidence_type="text",
            source="fixture",
            content="target-side response",
        )
        source = await service.append_agent_event(
            "run",
            "solver",
            "tool_result",
            {
                "tool_name": "system_http_request",
                "result": {"ok": True, "data": {"status_code": 200}},
                "execution_fact": {"complete": True},
            },
        )
        review = SolverReviewArguments.model_validate(
            {
                "hypothesis_id": "access",
                "covered_sequences": [source],
                "assessment": "new_information",
                "summary": "Target-side file access is verified",
                "next_test": "Check evidence-backed candidate carriers",
                "validation": {
                    "conclusion_sequences": [source],
                    "control_evidence_refs": [evidence["evidence_ref"]],
                    "calibration_basis": "Known fixture control",
                },
                "acquired_capabilities": [
                    {
                        "kind": "file_read",
                        "target_environment": "target web process",
                        "scope": "Can read application files through the target endpoint",
                        "limitations": "No directory listing or host-wide access established",
                    }
                ],
            }
        )
        await service.record_solver_review("run", solver, review)

        skill = SkillSessionContext(
            SkillCatalog(),
            role="solver",
            service=service,
            run_id="run",
            agent_id="solver",
        )
        runner = AgentRunner(
            AgentSettings(
                llm_base_url="https://model.test",
                llm_model="fixture",
                llm_api_key="fixture",
            ),
            ToolRegistry([SkillTools(skill)]),
            role="solver",
            agent_id="solver",
            state_service=service,
        )
        try:
            store = await AgentStateStore.open(
                service,
                run_id="run",
                agent_id="solver",
                run_dir=tmp_path / "solver",
            )
            await runner._review_context(store)
            runtime = await service.get_agent_runtime("run", "solver")
            active = runtime["agent"]["active_skills"]
            assert len(active) == 1
            assert active[0]["skill_id"] == "common/ctf-flag-locator"
            assert active[0]["activation_mode"] == "capability"
            assert active[0]["source_review_sequence"] > 0

            await runner._review_context(store)
            active_again = (await service.get_agent_runtime("run", "solver"))["agent"][
                "active_skills"
            ]
            assert len(active_again) == 1
        finally:
            await runner.close()
    finally:
        await service.close()
