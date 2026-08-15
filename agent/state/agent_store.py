"""SQLite-backed persistence facade used by :class:`AgentRunner`."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent.memory.models import (
    ActiveSkillState,
    AgentNode,
    Checkpoint,
    OperationState,
    RunEvent,
    RunManifest,
    TargetState,
)

from .clock import aware, utc_now
from .resources import checkpoint_target_status
from .service import StateService


class AgentStateStore:
    """Present the small runner persistence contract over SQLite state."""

    def __init__(
        self,
        service: StateService,
        *,
        run_id: str,
        agent_id: str,
        run_dir: Path,
        manifest: RunManifest,
        checkpoint: Checkpoint,
    ) -> None:
        self.service = service
        self.run_id = run_id
        self.agent_id = agent_id
        self.run_dir = run_dir
        self.manifest = manifest
        self.checkpoint = checkpoint
        self.events_path = run_dir / "events.jsonl"
        self.checkpoint_path = run_dir / "checkpoint.json"
        self.memory_path = run_dir / "session_memory.md"
        self.report_path = run_dir / "report.json"
        self.artifacts_dir = run_dir / "artifacts"

    @classmethod
    async def open(
        cls,
        service: StateService,
        *,
        run_id: str,
        agent_id: str,
        run_dir: Path,
    ) -> "AgentStateStore":
        runtime = await service.get_agent_runtime(run_id, agent_id)
        run = runtime["run"]
        agent = runtime["agent"]
        role = agent["role"]
        unique_code = agent["unique_code"]
        if role == "chief":
            overview = await service.get_overview(run_id)
            operation_filters: dict[str, str] = {}
        elif role == "challenge":
            overview = await service.get_overview(
                run_id, unique_code=unique_code, active_agents_only=True
            )
            operation_filters = {"unique_code": unique_code}
        else:
            overview = await service.get_overview(
                run_id, unique_code=unique_code, agent_id=agent_id
            )
            operation_filters = {"agent_id": agent_id}
        targets = [
            TargetState(
                unique_code=item["unique_code"],
                status=checkpoint_target_status(item),
                is_completed=item["is_completed"],
                work_status=item["work_status"],
                container_status=item["container_status"],
                slot_occupied=item["slot_occupied"],
                container_addr=item["container_addr"],
                score_snapshot={
                    "correct_flag_count": item["correct_flag_count"],
                    "flag_count": item["flag_count"],
                    "total_score": item["total_score"],
                },
                last_event_sequence=run["last_sequence"],
            )
            for item in overview["challenges"]
        ]
        status_map = {
            "queued": "pending",
            "starting": "pending",
            "working": "running",
            "blocked": "running",
            "stopping": "running",
            "cancelled": "stopped",
        }
        agents = [
            AgentNode(
                agent_id=item["agent_id"],
                role=item["role"],
                parent_id=item["parent_id"],
                unique_code=item["unique_code"],
                status=status_map.get(item["status"], item["status"]),
                sidecar_path=str(run_dir / "agents" / item["agent_id"]),
                mission=str(item["mission"] or "")[:500],
                timeout_seconds=item["timeout_seconds"],
                report_count=1 if item["last_report_sequence"] else 0,
                last_report_sequence=item["last_report_sequence"],
            )
            for item in overview["agents"]
        ]
        indeterminate_operations = [
            OperationState(
                operation_id=item["operation_id"],
                tool_name=item["operation_type"],
                unique_code=item["unique_code"],
                status="indeterminate",
                arguments_fingerprint=item["arguments_fingerprint"],
                started_sequence=item["started_sequence"] or 0,
                completed_sequence=item["completed_sequence"],
                result_code=item["result_code"],
            )
            for item in await service.list_operations(run_id, **operation_filters)
            if item["status"] == "indeterminate"
        ]
        run_status = run["status"]
        authoritative_view: dict[str, Any]
        if role == "challenge":
            context = await service.get_challenge_context(
                run_id, str(unique_code), compact=True
            )
            challenge_state = context["challenge"]
            latest_cycle = (
                context["recent_cycles"][0]
                if context.get("recent_cycles")
                else None
            )
            if isinstance(latest_cycle, dict):
                analysis = latest_cycle.get("analysis")
                plan = latest_cycle.get("plan")
                verification = latest_cycle.get("verification")
                latest_cycle = {
                    "cycle_id": latest_cycle.get("cycle_id"),
                    "cycle_number": latest_cycle.get("cycle_number"),
                    "status": latest_cycle.get("status"),
                    "version": latest_cycle.get("version"),
                    "analysis": {
                        "summary": str(
                            analysis.get("summary") if isinstance(analysis, dict) else ""
                        )[:1_000],
                        "direction": (
                            analysis.get("direction")
                            if isinstance(analysis, dict)
                            else "unknown"
                        ),
                    },
                    "tasks": [
                        {
                            "task_key": item.get("task_key"),
                            "hypothesis_key": item.get("hypothesis_key"),
                            "task_stage": item.get("task_stage"),
                            "context_refs": list(item.get("context_refs") or [])[:5],
                        }
                        for item in list(
                            (plan.get("tasks") or []) if isinstance(plan, dict) else []
                        )[:12]
                        if isinstance(item, dict)
                    ],
                    "verification": {
                        "summary": str(
                            verification.get("summary")
                            if isinstance(verification, dict)
                            else ""
                        )[:1_000],
                        "outcome": (
                            verification.get("outcome")
                            if isinstance(verification, dict)
                            else None
                        ),
                    },
                }
            authoritative_view = {
                "authority": context["authority"],
                "challenge": {
                    "unique_code": challenge_state["unique_code"],
                    "description": str(challenge_state.get("description") or "")[:2_000],
                    "direction": challenge_state.get("direction"),
                    "work_status": challenge_state.get("work_status"),
                    "is_completed": challenge_state.get("is_completed"),
                },
                "finding_refs": [
                    item["finding_ref"]
                    for item in list(context.get("findings") or [])[-20:]
                    if isinstance(item, dict) and item.get("finding_ref")
                ],
                "report_refs": [
                    item["terminal_report_ref"]
                    for item in list(context.get("task_ledger") or [])[:20]
                    if isinstance(item, dict) and item.get("terminal_report_ref")
                ],
            }
        elif role == "execution":
            challenge_state = overview["challenges"][0] if overview["challenges"] else {}
            authoritative_view = {
                "assignment": {
                    "agent_id": agent_id,
                    "kind": agent.get("kind"),
                    "mission": str(agent.get("mission") or "")[:4_000],
                    "task_stage": agent.get("task_stage"),
                    "hypothesis_key": agent.get("hypothesis_key"),
                    "task_key": agent.get("task_key"),
                    "branch_key": agent.get("branch_key"),
                    "success_criteria": list(agent.get("success_criteria") or [])[:20],
                    "context_refs": list(agent.get("context_refs") or [])[:50],
                },
                "challenge": {
                    "unique_code": challenge_state.get("unique_code"),
                    "description": str(challenge_state.get("description") or "")[:2_000],
                    "direction": challenge_state.get("direction"),
                    "container_addr": list(challenge_state.get("container_addr") or []),
                    "evidence_root": challenge_state.get("evidence_root"),
                },
            }
            if agent.get("kind") == "bootstrap":
                cursors = dict(agent.get("report_cursors") or {})
                authoritative_view["bootstrap_shared"] = {
                    "report_cursor": int(cursors.get("bootstrap_shared", 0) or 0),
                    "hint_cursor": int(cursors.get("bootstrap_hint", 0) or 0),
                    "pending_sequence": int(
                        cursors.get("bootstrap_shared_pending", 0) or 0
                    ),
                }
        else:
            authoritative_view = {
                "deadline_at": run["deadline_at"],
                "container_capacity": overview["container_capacity"],
                "current_challenge_code": run["current_challenge_code"],
            }
        manifest = RunManifest(
            run_id=run_id,
            model=run["model"] or "unknown",
            context_window_tokens=run["context_window_tokens"],
            prompt=agent["initial_prompt"],
            role=agent["role"],
            parent_id=agent["parent_id"],
            unique_code=agent["unique_code"],
            status=run_status,
            started_at=datetime.fromisoformat(run["started_at"]),
        )
        checkpoint = Checkpoint(
            run_id=run_id,
            status=run_status,
            phase=run["phase"],
            targets=targets,
            container_capacity=overview["container_capacity"],
            current_target=run["current_challenge_code"],
            score_snapshot=run["score_snapshot"],
            last_event_sequence=run["last_sequence"],
            last_summarized_event_sequence=agent["last_summarized_sequence"],
            indeterminate_operations=indeterminate_operations,
            agents=agents,
            active_skills=[
                ActiveSkillState.model_validate(item)
                for item in agent.get("active_skills", [])
            ],
            authoritative_view=authoritative_view,
        )
        run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (run_dir / "artifacts").mkdir(parents=True, exist_ok=True, mode=0o700)
        return cls(
            service,
            run_id=run_id,
            agent_id=agent_id,
            run_dir=run_dir,
            manifest=manifest,
            checkpoint=checkpoint,
        )

    async def append_event(self, event_type: str, payload: dict[str, Any] | None = None) -> RunEvent:
        sequence = await self.service.append_agent_event(
            self.run_id,
            self.agent_id,
            event_type,
            payload or {},
        )
        self.checkpoint.last_event_sequence = sequence
        return RunEvent(
            run_id=self.run_id,
            sequence=sequence,
            event_id=uuid4().hex,
            timestamp=utc_now(),
            event_type=event_type,
            payload=payload or {},
        )

    async def append_events(
        self, events: list[dict[str, Any]]
    ) -> list[RunEvent]:
        sequences = await self.service.append_agent_events(
            self.run_id, self.agent_id, events
        )
        if sequences:
            self.checkpoint.last_event_sequence = sequences[-1]
        now = utc_now()
        return [
            RunEvent(
                run_id=self.run_id,
                sequence=sequence,
                event_id=uuid4().hex,
                timestamp=now,
                event_type=str(event["event_type"]),
                payload=dict(event.get("payload") or {}),
            )
            for sequence, event in zip(sequences, events, strict=True)
        ]

    async def save_checkpoint(self, checkpoint: Checkpoint | None = None) -> None:
        if checkpoint is not None:
            self.checkpoint = checkpoint

    def model_checkpoint(self) -> dict[str, Any]:
        """Return the compact role-specific checkpoint exposed to the model.

        SQLite owns the full target and Agent graph.  Controller prompts already
        contain a freshly generated authoritative snapshot, so repeating that
        graph here only wastes context and can make a healthy session fail.
        """

        role = self.manifest.role or "execution"
        value: dict[str, Any] = {
            "schema_version": self.checkpoint.schema_version,
            "run_id": self.checkpoint.run_id,
            "role": role,
            "status": self.checkpoint.status,
            "phase": self.checkpoint.phase,
            "last_event_sequence": self.checkpoint.last_event_sequence,
            "last_summarized_event_sequence": (
                self.checkpoint.last_summarized_event_sequence
            ),
            "active_skills": [
                item.model_dump(mode="json")
                for item in self.checkpoint.active_skills
            ],
        }
        if self.checkpoint.indeterminate_operations:
            value["indeterminate_operations"] = [
                item.model_dump(mode="json")
                for item in self.checkpoint.indeterminate_operations
            ]
        if role == "chief":
            value.update(
                {
                    "container_capacity": self.checkpoint.container_capacity,
                    "current_target": self.checkpoint.current_target,
                    "score_snapshot": self.checkpoint.score_snapshot,
                    "authority": self.checkpoint.authoritative_view,
                }
            )
        else:
            value["authority"] = self.checkpoint.authoritative_view
        return value

    async def read_memory(self) -> str:
        runtime = await self.service.get_agent_runtime(self.run_id, self.agent_id)
        return str(runtime["agent"]["session_memory"])

    async def write_memory(
        self,
        content: str,
        *,
        summarized_through_sequence: int | None = None,
    ) -> None:
        through_sequence = (
            self.checkpoint.last_summarized_event_sequence
            if summarized_through_sequence is None
            else summarized_through_sequence
        )
        await self.service.update_agent_memory(
            self.run_id,
            self.agent_id,
            content,
            summarized_through_sequence=through_sequence,
        )
        self.checkpoint.last_summarized_event_sequence = max(
            self.checkpoint.last_summarized_event_sequence,
            through_sequence,
        )

    async def load_events(
        self,
        *,
        after_sequence: int | None = None,
        limit: int = 100,
    ) -> list[RunEvent]:
        rows = await self.service.list_agent_events(
            self.run_id,
            self.agent_id,
            after_sequence=(
                self.checkpoint.last_summarized_event_sequence
                if after_sequence is None
                else after_sequence
            ),
            limit=max(1, min(limit, 100)),
        )
        return [
            RunEvent(
                run_id=self.run_id,
                sequence=item["sequence"],
                event_id=uuid4().hex,
                timestamp=datetime.fromisoformat(item["created_at"]),
                event_type=item["event_type"],
                payload=item["payload"],
            )
            for item in rows
        ]
