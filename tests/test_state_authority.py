"""SQLite authority for explicit work, scopes, immutable outcomes and delivery."""

import asyncio
import sqlite3
import pytest
from sqlalchemy import select, func
from agent.state import (
    CapabilityContext,
    WorkerTaskInput,
    WorkerUpdateInput,
    AgentReportInput,
)
from agent.state.database import StateDatabase, SCHEMA_VERSION
from agent.state.errors import StateConflict, StatePermission
from agent.state.models import ReportRecord, AgentRecord, FindingRecord
from tests.solver_state import build_state, worker


@pytest.mark.asyncio
async def test_schema18_rejects_old_database_without_modifying_it(tmp_path):
    assert SCHEMA_VERSION == 19
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA user_version=18")
        db.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO schema_meta VALUES ('schema_version', '18')")
        db.execute("CREATE TABLE historical (value TEXT)")
        db.execute("INSERT INTO historical VALUES ('preserved')")
    state = StateDatabase(path)
    with pytest.raises(Exception, match="(?i)(version|schema)"):
        await state.initialize()
    await state.close()
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 18
        assert db.execute("SELECT value FROM historical").fetchone()[0] == "preserved"
        assert (
            db.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()[0]
            == "18"
        )


@pytest.mark.asyncio
async def test_solver_identity_survives_inactive_status_and_task_key_is_explicit(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    try:
        for status in ("paused", "failed", "stopped", "running"):
            await s.transition_agent("run", "solver", status)
            result = await s.register_solver_for_challenge(
                "run",
                solver_agent_id="other",
                parent_id="chief",
                unique_code="a",
                solver_prompt="resume",
            )
            assert result["agent_id"] == "solver" and result["idempotent"]
        task = WorkerTaskInput(task_key="one", objective="read dependency then verify")
        results = await asyncio.gather(
            *(s.delegate_workers("run", solver, [task]) for _ in range(5))
        )
        ids = {r["admissions"][0]["agent_id"] for r in results}
        assert len(ids) == 1
        with pytest.raises(StateConflict):
            await s.delegate_workers(
                "run", solver, [task.model_copy(update={"objective": "different"})]
            )
        with pytest.raises(StatePermission):
            w = CapabilityContext(
                run_id="run", role="worker", agent_id=ids.pop(), unique_code="a"
            )
            await s.delegate_workers("run", w, [task])
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_report_dedup_terminal_cancel_and_late_audit(tmp_path):
    s, c, solver = await build_state(tmp_path)
    try:
        w = await worker(s, solver)
        update = WorkerUpdateInput(summary="step one", tested=["one"], untested=["two"])
        first = await s.report_worker(
            "run", w.agent_id, w, update, terminal=False, call_id="update-1"
        )
        second = await s.report_worker(
            "run", w.agent_id, w, update, terminal=False, call_id="retry"
        )
        assert second["idempotent"] and first["report_id"] == second["report_id"]
        with pytest.raises(StateConflict):
            await s.report_worker(
                "run",
                w.agent_id,
                w,
                WorkerUpdateInput(summary="changed"),
                terminal=False,
                call_id="update-1",
            )
        results = await asyncio.gather(
            s.finalize_worker(
                "run",
                w.agent_id,
                w,
                AgentReportInput(summary="cancel", status="cancelled"),
            ),
            s.finalize_worker(
                "run",
                w.agent_id,
                w,
                AgentReportInput(summary="done", status="completed"),
            ),
        )
        assert len({r["report_id"] for r in results}) == 1
        assert any(
            e["event_type"] == "worker_late_result"
            for e in await s.list_agent_events("run", w.agent_id)
        )
        overview = await s.get_overview("run")
        assert len(overview["agents"]) == 3
        assert (
            next(a for a in overview["agents"] if a["agent_id"] == "solver")["status"]
            == "pending"
        )
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_delivery_replays_until_matching_persisted_response_and_wait_cannot_lose_report(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    try:
        w = await worker(s, solver)
        wait = await s.record_controller_wait("run", "solver", "pending")
        assert wait["status"] == "waiting"
        await s.report_worker(
            "run",
            w.agent_id,
            w,
            WorkerUpdateInput(summary="new evidence"),
            terminal=False,
        )
        # Writer wins between wait registration and actually suspending.
        sequence = await s.notifier.wait(
            s.agent_signal_key("run", "solver"), wait["sequence"], 0.1
        )
        assert sequence > wait["sequence"]
        batch = await s.consume_reports("run", solver)
        assert (await s.consume_reports("run", solver))["delivery_id"] == batch[
            "delivery_id"
        ]
        with pytest.raises(StateConflict):
            await s.acknowledge_report_delivery(
                "run", "solver", batch["delivery_id"], 1
            )
        assert (await s.record_controller_wait("run", "solver", "try again"))[
            "status"
        ] == "ready"
        response = await s.append_agent_event(
            "run",
            "solver",
            "assistant_response",
            {"delivery_ids": [batch["delivery_id"]]},
        )
        await s.acknowledge_report_delivery(
            "run", "solver", batch["delivery_id"], response
        )
        assert not (await s.consume_reports("run", solver))["reports"]
        assert (await s.record_controller_wait("run", "solver", "wait"))[
            "status"
        ] == "waiting"
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_recovery_interrupts_workers_once_preserves_memory_and_unacknowledged_delivery(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    try:
        w = await worker(s, solver)
        await s.update_agent_memory(
            "run", "solver", "stable memory", summarized_through_sequence=0
        )
        await s.report_worker(
            "run",
            w.agent_id,
            w,
            WorkerUpdateInput(summary="before crash"),
            terminal=False,
        )
        delivery = await s.consume_reports("run", solver)
        assert await s.interrupt_workers("run") == 1
        assert await s.interrupt_workers("run") == 0
        assert (await s.consume_reports("run", solver))["delivery_id"] == delivery[
            "delivery_id"
        ]
        assert (await s.get_agent_runtime("run", "solver"))["agent"][
            "session_memory"
        ] == "stable memory"
        assert (await s.get_agent_runtime("run", w.agent_id))["agent"][
            "status"
        ] == "interrupted"
        retry = (
            await s.delegate_workers(
                "run", solver, [WorkerTaskInput(task_key="task", objective="task")]
            )
        )["admissions"][0]
        assert retry["agent_id"] == w.agent_id and retry["status"] == "interrupted"
        assert (await worker(s, solver, "explicit-retry")).agent_id != w.agent_id
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_same_challenge_evidence_pages_cross_scope_denied_and_review_cannot_write(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    try:
        w = await worker(s, solver)
        review = await worker(s, solver, "review", mode="review")
        evidence = await s.persist_evidence(
            "run", w, evidence_type="fixture", source="test", content="0123456789"
        )
        for context in (solver, w, review):
            page = await s.read_evidence(
                "run", context, evidence["evidence_ref"], offset=3, limit_chars=4
            )
            assert page["content"] == "3456"
        await s.register_agent(
            "run", role="solver", agent_id="other", parent_id="chief", unique_code="b"
        )
        other = CapabilityContext(
            run_id="run", role="solver", agent_id="other", unique_code="b"
        )
        for run, context in [("run", other), ("wrong-run", solver)]:
            with pytest.raises(StatePermission):
                await s.read_evidence(run, context, evidence["evidence_ref"])
        with pytest.raises(StatePermission):
            await s.persist_evidence(
                "run",
                review,
                evidence_type="fixture",
                source="test",
                content="forbidden",
            )
        with pytest.raises(StatePermission):
            await s.finalize_worker(
                "run",
                review.agent_id,
                review,
                AgentReportInput(
                    status="completed",
                    summary="review",
                    findings=[{"summary": "forbidden"}],
                ),
            )
        result = await s.finalize_worker(
            "run",
            review.agent_id,
            review,
            AgentReportInput(
                status="completed",
                summary="read-only review",
                evidence_refs=[evidence["evidence_ref"]],
            ),
        )
        assert result["status"] == "completed"
        with pytest.raises(StatePermission):
            await s.delegate_workers(
                "run",
                solver,
                [
                    WorkerTaskInput(
                        task_key="cross",
                        objective="cross",
                        context_refs=["evidence:missing"],
                    )
                ],
            )
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_worker_findings_share_evidence_without_stage_or_secondary_grant(
    tmp_path,
):
    s, c, solver = await build_state(tmp_path)
    try:
        a = await worker(s, solver, "one")
        b = await worker(s, solver, "two")
        evidence = await s.persist_evidence(
            "run",
            a,
            evidence_type="fixture",
            source="read",
            content="reproducible observation",
        )
        first = await s.finalize_worker(
            "run",
            a.agent_id,
            a,
            AgentReportInput(
                status="completed",
                summary="found",
                findings=[
                    {
                        "category": "vulnerability",
                        "summary": "candidate",
                        "evidence_refs": [evidence["evidence_ref"]],
                    }
                ],
            ),
        )
        finding = first["payload"]["findings"][0]
        await s.finalize_worker(
            "run",
            b.agent_id,
            b,
            AgentReportInput(
                status="completed",
                summary="verified",
                findings=[
                    {
                        "finding_ref": finding["finding_ref"],
                        "category": "vulnerability",
                        "summary": "candidate",
                        "verification_status": "verified",
                        "evidence_refs": [evidence["evidence_ref"]],
                    }
                ],
            ),
        )
        context = await s.observe_solver("run", "a", solver)
        assert len(context["findings"]) == 1
        assert context["findings"][0]["verification_status"] == "verified"
        assert len((await s.get_overview("run"))["agents"]) == 4
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_independent_services_share_unique_solver_identity(tmp_path):
    from agent.state import StateService

    s, chief, solver = await build_state(tmp_path)
    other = StateService(
        StateDatabase(s.db.path), run_root=tmp_path / "runs", workspace_root=tmp_path
    )
    await other.initialize()
    try:
        await s.start_challenge("run", "b", chief)
        results = await asyncio.gather(
            *(
                svc.register_solver_for_challenge(
                    "run",
                    solver_agent_id="new-" + str(index),
                    parent_id="chief",
                    unique_code="b",
                    solver_prompt="solve",
                )
                for index, svc in enumerate((s, other, s, other))
            )
        )
        assert len({row["agent_id"] for row in results}) == 1
        assert sum(not row["idempotent"] for row in results) == 1
    finally:
        await other.close()
        await s.close()


@pytest.mark.asyncio
async def test_pending_candidate_report_replays_exactly_after_service_restart(tmp_path):
    from agent.state import StateService

    s, chief, solver = await build_state(tmp_path)
    w = await worker(s, solver, "candidate")
    await s.report_worker(
        "run",
        w.agent_id,
        w,
        AgentReportInput(
            status="completed",
            summary="candidate observed",
            candidate_flag="flag{durable_candidate}",
        ),
        terminal=True,
    )
    before = await s.consume_reports("run", solver)
    path = s.db.path
    await s.close()
    recovered = StateService(
        StateDatabase(path), run_root=tmp_path / "runs", workspace_root=tmp_path
    )
    await recovered.initialize()
    try:
        after = await recovered.consume_reports("run", solver)
        assert after == before
        assert (
            after["reports"][0]["payload"]["candidate_flag"]
            == "flag{durable_candidate}"
        )
    finally:
        await recovered.close()
