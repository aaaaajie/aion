"""SQLite-backed persistence facade used by :class:`AgentRunner`."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent.memory.models import (
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
        overview = await service.get_overview(run_id)
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
                mission=item["mission"],
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
            for item in await service.list_operations(run_id)
            if item["status"] == "indeterminate"
        ]
        run_status = run["status"] if run["status"] in {"active", "completed", "failed", "interrupted"} else "active"
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

    async def save_checkpoint(self, checkpoint: Checkpoint | None = None) -> None:
        if checkpoint is not None:
            self.checkpoint = checkpoint

    async def read_memory(self) -> str:
        runtime = await self.service.get_agent_runtime(self.run_id, self.agent_id)
        return str(runtime["agent"]["session_memory"])

    async def write_memory(self, content: str) -> None:
        await self.service.update_agent_memory(
            self.run_id,
            self.agent_id,
            content,
            summarized_through_sequence=self.checkpoint.last_event_sequence,
        )
        self.checkpoint.last_summarized_event_sequence = self.checkpoint.last_event_sequence

    async def load_events(self) -> list[RunEvent]:
        rows = await self.service.list_agent_events(
            self.run_id,
            self.agent_id,
            after_sequence=0,
            limit=2_000,
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
