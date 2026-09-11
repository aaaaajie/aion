"""Transactional authoritative state service for one benchmark run."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import case, delete, func, or_, select, update, text
from sqlalchemy.orm import load_only

from agent.config import normalize_selected_challenge_codes
from agent.memory.models import AgentNode, Checkpoint, TargetState
from agent.memory.redaction import redact_value
from .clock import active_seconds, aware, utc_now
from .database import StateDatabase
from .errors import StateConflict, StateError, StateNotFound, StatePermission
from .models import (
    AdmissionRecord,
    AgentRecord,
    AuditOutboxRecord,
    ChallengeRecord,
    CredentialRecord,
    DEFAULT_SESSION_MEMORY,
    EvidenceRecord,
    FindingRecord,
    HttpInteractionRecord,
    NetworkTaskRecord,
    ObservationRecord,
    OperationRecord,
    ReportRecord,
    ResourceWorkRecord,
    ResourceSampleRecord,
    RunRecord,
    ShellTaskRecord,
    StateEventRecord,
)
from .resources import (
    RELEASED_CONTAINER_STATUSES,
    MAX_CHALLENGE_SLOTS,
    challenge_work_active,
    challenge_start_gate as evaluate_challenge_start_gate,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .schemas import (
    AgentReportInput,
    CapabilityContext,
    CHALLENGE_WORK_STATUS_VALUES,
    ChallengeImport,
    ChallengeSyncResult,
    FindingInput,
)
from .wakeup import StateSignalBus

CONTROLLER_FINDING_LIMIT = 24
CONTROLLER_SUMMARY_CHARS = 1_000
CONTROLLER_MISSION_CHARS = 600
CONTROLLER_NEXT_STEP_CHARS = 300


def _controller_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _controller_refs(value: Any, limit: int = 10) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(dict.fromkeys(item for item in value if isinstance(item, str)))[:limit]


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return aware(value).isoformat()
    if isinstance(value, Mapping):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _fingerprint(category: str, summary: str, detail: Mapping[str, Any]) -> str:
    normalized = json.dumps(
        {
            "category": category,
            "summary": " ".join(summary.lower().split()),
            "detail": detail,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


from .agents import AgentStateMixin
from .observation import SolverObservationState
from .solver_review import SolverReviewState
from .stagnation import StagnationState


class StateService(AgentStateMixin, SolverObservationState, SolverReviewState, StagnationState):
    """All domain mutations for a run go through this service."""

    def __init__(
        self,
        database: StateDatabase | Path | str,
        *,
        run_root: Path | None = None,
        workspace_root: Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        notifier: StateSignalBus | None = None,
    ) -> None:
        self.db = (
            database
            if isinstance(database, StateDatabase)
            else StateDatabase(Path(database))
        )
        self.run_root = run_root
        self.workspace_root = (
            workspace_root.resolve() if workspace_root is not None else None
        )
        self.clock = clock
        self.notifier = notifier or StateSignalBus()
        self._lock = asyncio.Lock()
        self._projection_lock = asyncio.Lock()
        self._projection_sequences: dict[str, int] = {}

    async def initialize(self) -> None:
        await self.db.initialize()

    async def close(self) -> None:
        await self.db.close()

    def _evidence_directory(self, run_id: str, agent_id: str) -> Path:
        if self.run_root is None:
            raise StateError(
                "evidence_store_unavailable",
                "Evidence storage is not configured",
                status_code=500,
            )
        return self.run_root / run_id / "agents" / agent_id / "evidence"

    async def persist_evidence(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        evidence_type: str,
        source: str,
        content: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist an immutable Evidence snapshot owned by the calling Agent."""

        async with self.db.sessions() as session:
            agent = await self._authorize(
                session,
                context,
                roles={"worker", "solver"},
                agent_id=context.agent_id,
                run_id=run_id,
            )
            if agent.role == "worker" and agent.mode == "review":
                raise StatePermission(
                    "review_read_only", "Review Workers cannot create Evidence"
                )
            if not agent.unique_code:
                raise StatePermission(
                    "evidence_scope_required",
                    "Evidence requires a challenge-bound Agent",
                )
            unique_code = agent.unique_code
        evidence_id = f"evidence_{uuid4().hex}"
        storage_name = f"{evidence_id}.txt"
        directory = self._evidence_directory(run_id, context.agent_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        target = directory / storage_name
        temporary = directory / f".{storage_name}.tmp"
        encoded = content.encode("utf-8")
        try:
            with temporary.open("xb") as handle:
                os.chmod(temporary, 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
            async with self._lock:
                async with self.db.sessions.begin() as session:
                    await self._authorize(
                        session,
                        context,
                        roles={"worker", "solver"},
                        agent_id=context.agent_id,
                        run_id=run_id,
                    )
                    row = EvidenceRecord(
                        evidence_id=evidence_id,
                        run_id=run_id,
                        unique_code=unique_code,
                        agent_id=context.agent_id,
                        evidence_type=evidence_type,
                        source=source,
                        content_sha256=hashlib.sha256(encoded).hexdigest(),
                        metadata_json=dict(metadata or {}),
                        storage_name=storage_name,
                        size_chars=len(content),
                        created_at=self.clock(),
                    )
                    session.add(row)
                    challenge = await self._require_challenge(
                        session, run_id, unique_code
                    )
                    self._mark_progress(challenge)
                    sequence = await self._event(
                        session,
                        run_id,
                        "evidence_persisted",
                        {
                            "evidence_ref": f"evidence:{evidence_id}",
                            "evidence_type": evidence_type,
                            "source": source,
                            "size_chars": len(content),
                        },
                        agent_id=context.agent_id,
                    )
                    await self._event(
                        session,
                        run_id,
                        "challenge_progress_recorded",
                        {
                            "unique_code": unique_code,
                            "progress_kinds": ["evidence_persisted"],
                        },
                        agent_id=context.agent_id,
                    )
        except Exception:
            temporary.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return {
            "evidence_ref": f"evidence:{evidence_id}",
            "evidence_type": evidence_type,
            "source": source,
            "sha256": row.content_sha256,
            "size_chars": len(content),
            "sequence": sequence,
        }

    async def read_evidence(
        self,
        run_id: str,
        context: CapabilityContext,
        evidence_ref: str,
        *,
        offset: int = 0,
        limit_chars: int = 8_000,
    ) -> dict[str, Any]:
        prefix = "evidence:evidence_"
        suffix = evidence_ref.removeprefix(prefix)
        if (
            not evidence_ref.startswith(prefix)
            or len(suffix) != 32
            or any(c not in "0123456789abcdef" for c in suffix)
        ):
            raise StateError(
                "invalid_evidence_ref",
                "Use the exact evidence_ref returned by the tool: "
                "evidence:evidence_<32 lowercase hexadecimal characters>. "
                "A bare evidence ID is not a reference.",
                status_code=422,
            )
        evidence_id = evidence_ref.removeprefix("evidence:")
        async with self.db.sessions() as session:
            caller = await self._authorize(
                session,
                context,
                roles={"worker", "solver"},
                agent_id=context.agent_id,
                run_id=run_id,
            )
            row = await session.get(EvidenceRecord, evidence_id)
            allowed = row is not None and row.run_id == run_id
            allowed = (
                allowed and row is not None and row.unique_code == caller.unique_code
            )
            if not allowed or row is None:
                raise StatePermission(
                    "evidence_not_accessible",
                    "Evidence is not accessible in this Agent scope",
                )
            storage_name = row.storage_name
            metadata = {
                "evidence_type": row.evidence_type,
                "source": row.source,
                "sha256": row.content_sha256,
                "size_chars": row.size_chars,
            }
            owner_id = row.agent_id
        path = self._evidence_directory(run_id, owner_id) / storage_name
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StateError(
                "evidence_content_unavailable",
                "Evidence content is unavailable",
                status_code=500,
            ) from exc
        end = min(len(content), offset + limit_chars)
        return {
            "evidence_ref": evidence_ref,
            **metadata,
            "offset": offset,
            "content": content[offset:end],
            "next_offset": end if end < len(content) else None,
            "eof": end >= len(content),
        }

    async def list_evidence_metadata(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return compact same-Run Evidence metadata without exposing content."""

        async with self.db.sessions() as session:
            caller = await self._authorize(
                session, context, roles={"chief", "solver", "worker"}, run_id=run_id
            )
            filters = [EvidenceRecord.run_id == run_id]
            if caller.role == "solver":
                filters.append(EvidenceRecord.unique_code == caller.unique_code)
            elif caller.role == "worker":
                filters.append(EvidenceRecord.unique_code == caller.unique_code)
            rows = list(
                (
                    await session.scalars(
                        select(EvidenceRecord)
                        .where(*filters)
                        .order_by(EvidenceRecord.created_at.desc())
                        .limit(max(1, min(limit, 200)))
                    )
                ).all()
            )
        return [
            {
                "evidence_ref": f"evidence:{item.evidence_id}",
                "unique_code": item.unique_code,
                "agent_id": item.agent_id,
                "evidence_type": item.evidence_type,
                "source": item.source,
                "sha256": item.content_sha256,
                "size_chars": item.size_chars,
                "created_at": _json_value(item.created_at),
            }
            for item in rows
        ]

    @staticmethod
    def run_signal_key(run_id: str) -> str:
        return f"run:{run_id}"

    @staticmethod
    def agent_signal_key(run_id: str, agent_id: str) -> str:
        return f"run:{run_id}:agent:{agent_id}"

    async def signal_challenge_changes(
        self,
        run_id: str,
        unique_codes: Iterable[str],
        sequence: int,
    ) -> None:
        codes = set(unique_codes)
        async with self.db.sessions() as session:
            recipients = list(
                (
                    await session.scalars(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            (
                                (AgentRecord.role == "chief")
                                | (
                                    (AgentRecord.role == "solver")
                                    & AgentRecord.unique_code.in_(codes)
                                )
                            ),
                        )
                    )
                ).all()
            )
        await asyncio.gather(
            *(
                self.notifier.notify(
                    self.agent_signal_key(run_id, item.agent_id), sequence
                )
                for item in recipients
            )
        )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)

    async def create_run(
        self,
        run_id: str,
        *,
        duration_minutes: int = 360,
        model: str | None = None,
        prompt: str | None = None,
        context_window_tokens: int = 1_000_000,
        selected_challenge_codes: list[str] | None = None,
        challenges: Iterable[ChallengeImport | Mapping[str, Any]] = (),
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        if not run_id or len(run_id) > 128:
            raise StateError("invalid_run_id", "run_id is invalid", status_code=422)
        if duration_minutes < 1:
            raise StateError(
                "invalid_duration", "duration_minutes must be positive", status_code=422
            )
        selected_challenge_codes = normalize_selected_challenge_codes(selected_challenge_codes)
        await self.initialize()
        start = aware(started_at or self.clock())
        deadline = start + timedelta(minutes=duration_minutes)
        challenge_values = [
            (
                item
                if isinstance(item, ChallengeImport)
                else ChallengeImport.model_validate(item)
            )
            for item in challenges
        ]
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if await session.get(RunRecord, run_id) is not None:
                    raise StateConflict("run_exists", "run_id already exists")
                run = RunRecord(
                    run_id=run_id,
                    model=model,
                    prompt=prompt,
                    context_window_tokens=context_window_tokens,
                    selected_challenge_codes=selected_challenge_codes,
                    duration_minutes=duration_minutes,
                    started_at=start,
                    deadline_at=deadline,
                )
                session.add(run)
                await session.flush()
                for challenge in challenge_values:
                    session.add(
                        self._challenge_from_import(run_id, challenge, now=start)
                    )
                await self._event(
                    session,
                    run_id,
                    "run_created",
                    {
                        "duration_minutes": duration_minutes,
                        "challenge_count": len(challenge_values),
                        "selected_challenge_codes": selected_challenge_codes,
                    },
                )
        return await self.get_overview(run_id)

    async def import_challenges(
        self,
        run_id: str,
        challenges: Iterable[ChallengeImport | Mapping[str, Any]],
    ) -> ChallengeSyncResult:
        await self.initialize()
        values = [
            (
                item
                if isinstance(item, ChallengeImport)
                else ChallengeImport.model_validate(item)
            )
            for item in challenges
        ]
        changed_codes: list[str] = []
        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                existing_rows = (
                    await session.scalars(
                        select(ChallengeRecord).where(ChallengeRecord.run_id == run_id)
                    )
                ).all()
                capacity_before = container_capacity_summary(
                    [self._challenge_dict(item) for item in existing_rows]
                )
                for challenge in values:
                    existing = await session.get(
                        ChallengeRecord, (run_id, challenge.unique_code)
                    )
                    if existing is None:
                        session.add(self._challenge_from_import(run_id, challenge))
                        changed_codes.append(challenge.unique_code)
                    else:
                        previous_completed = existing.is_completed
                        previous_correct_count = existing.correct_flag_count
                        before = self._challenge_material_state(existing)
                        self._apply_challenge_import(existing, challenge)
                        changed = before != self._challenge_material_state(existing)
                        if existing.container_status in RELEASED_CONTAINER_STATUSES:
                            existing.active_since = None
                        if (
                            existing.is_completed != previous_completed
                            or existing.correct_flag_count > previous_correct_count
                        ):
                            self._mark_progress(existing)
                        elif changed:
                            existing.version += 1
                        if changed:
                            changed_codes.append(challenge.unique_code)
                await session.flush()
                current_rows = (
                    await session.scalars(
                        select(ChallengeRecord)
                        .where(ChallengeRecord.run_id == run_id)
                        .order_by(ChallengeRecord.unique_code)
                    )
                ).all()
                current = [self._challenge_dict(item) for item in current_rows]
                capacity_after = container_capacity_summary(current)
                capacity_changed = capacity_before != capacity_after
                if changed_codes:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "challenge_catalog_changed",
                        {
                            "changed_codes": sorted(changed_codes),
                            "challenge_count": len(current),
                            "capacity_changed": capacity_changed,
                        },
                    )
        if event_sequence is not None:
            await self.signal_challenge_changes(run_id, changed_codes, event_sequence)
        return ChallengeSyncResult(
            challenges=current,
            changed_codes=sorted(changed_codes),
            capacity_changed=capacity_changed,
            event_sequence=event_sequence,
        )

    async def get_overview(
        self,
        run_id: str,
        *,
        unique_code: str | None = None,
        agent_id: str | None = None,
        active_agents_only: bool = False,
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            return await self._overview_locked(
                session,
                run_id,
                unique_code=unique_code,
                agent_id=agent_id,
                active_agents_only=active_agents_only,
            )

    async def _overview_locked(
        self,
        session: Any,
        run_id: str,
        *,
        unique_code: str | None = None,
        agent_id: str | None = None,
        active_agents_only: bool = False,
    ) -> dict[str, Any]:
        run = await self._require_run(session, run_id)
        challenge_clauses = [ChallengeRecord.run_id == run_id]
        if unique_code is not None:
            challenge_clauses.append(ChallengeRecord.unique_code == unique_code)
        challenges = (
            await session.scalars(
                select(ChallengeRecord)
                .where(*challenge_clauses)
                .order_by(ChallengeRecord.unique_code)
            )
        ).all()
        agent_clauses = [AgentRecord.run_id == run_id]
        if agent_id is not None:
            agent_clauses.append(AgentRecord.agent_id == agent_id)
        elif unique_code is not None:
            agent_clauses.append(AgentRecord.unique_code == unique_code)
        if active_agents_only:
            agent_clauses.append(
                AgentRecord.status.not_in(
                    ["completed", "failed", "stopped", "cancelled", "interrupted"]
                )
            )
        agents = (
            await session.scalars(
                select(AgentRecord)
                .where(*agent_clauses)
                .order_by(AgentRecord.created_at)
            )
        ).all()
        challenge_values = [
            self._challenge_dict(item, run=run, now=self.clock())
            for item in challenges
        ]
        stagnation_events = (
            await session.scalars(
                select(StateEventRecord).where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.event_type.in_(
                        {
                            "solver_strategy_reset",
                            "solver_stagnation_worker_started",
                            "solver_stagnation_worker_finished",
                            "solver_stagnation_rotation_requested",
                        }
                    ),
                )
            )
        ).all()
        metrics: dict[str, dict[str, Any]] = {}
        for event in stagnation_events:
            code = (event.payload or {}).get("unique_code")
            if not isinstance(code, str):
                continue
            current = metrics.setdefault(
                code,
                {
                    "strategy_reset_count": 0,
                    "alternate_worker_count": 0,
                    "worker_finished_count": 0,
                    "rotation_count": 0,
                    "worker_results": [],
                },
            )
            if event.event_type == "solver_strategy_reset":
                if (event.payload or {}).get("trigger") == "stagnation_review_due":
                    current["strategy_reset_count"] += 1
            elif event.event_type == "solver_stagnation_worker_started":
                current["alternate_worker_count"] += 1
            elif event.event_type == "solver_stagnation_worker_finished":
                current["worker_finished_count"] += 1
                current["worker_results"].append(
                    {
                        "status": (event.payload or {}).get("status"),
                        "worker_id": (event.payload or {}).get("worker_id"),
                        "strategy_revision": (event.payload or {}).get(
                            "strategy_revision"
                        ),
                    }
                )
            elif event.event_type == "solver_stagnation_rotation_requested":
                current["rotation_count"] += 1
        for value in challenge_values:
            value["stagnation_metrics"] = metrics.get(
                value["unique_code"],
                {
                    "strategy_reset_count": 0,
                    "alternate_worker_count": 0,
                    "worker_finished_count": 0,
                    "rotation_count": 0,
                    "worker_results": [],
                },
            )
        return {
            "run": self._run_dict(run),
            "challenges": challenge_values,
            "container_capacity": container_capacity_summary(challenge_values),
            "agents": [
                {
                    **self._agent_dict(item),
                    "waiting_sources": await self._waiting_sources(
                        session, run_id, item.agent_id
                    ),
                }
                for item in agents
            ],
        }

    async def challenge_start_gate(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext | None = None,
    ) -> dict[str, Any]:
        """Return the single authoritative admission decision for a challenge start."""

        async with self.db.sessions() as session:
            if context is not None:
                await self._authorize(
                    session,
                    context,
                    roles={"chief", "solver"},
                    unique_code=unique_code,
                    run_id=run_id,
                )
            await self._require_challenge_in_scope(session, run_id, unique_code)
            challenge = await self._require_challenge(session, run_id, unique_code)
            challenges = (
                await session.scalars(
                    select(ChallengeRecord).where(ChallengeRecord.run_id == run_id)
                )
            ).all()
            gate = evaluate_challenge_start_gate(
                [self._challenge_dict(item) for item in challenges], unique_code
            )
            return {
                "allowed": gate["allowed"],
                "reason": gate["reason"],
                "challenge": self._challenge_dict(challenge),
                "container_capacity": gate["container_capacity"],
            }

    async def list_challenges(self, run_id: str) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            run = await self._require_run(session, run_id)
            rows = (
                await session.scalars(
                    select(ChallengeRecord)
                    .where(ChallengeRecord.run_id == run_id)
                    .order_by(ChallengeRecord.unique_code)
                )
            ).all()
            return [
                self._challenge_dict(item, run=run, now=self.clock()) for item in rows
            ]

    async def run_exists(self, run_id: str) -> bool:
        await self.initialize()
        async with self.db.sessions() as session:
            return await session.get(RunRecord, run_id) is not None

    async def get_agent_runtime(self, run_id: str, agent_id: str) -> dict[str, Any]:
        async with self.db.sessions() as session:
            run = await self._require_run(session, run_id)
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise StateNotFound("agent_not_found", "Agent was not found")
            return {
                "run": self._run_dict(run),
                "agent": {
                    **self._agent_dict(agent, include_runtime=True),
                    # Polling a running Agent should stay a single cheap
                    # read.  Resolve wakeable producers only for the state
                    # that exposes them; this avoids turning status polling
                    # into a four-query lock convoy.
                    "waiting_sources": (
                        await self._waiting_sources(session, run_id, agent_id)
                        if agent.status == "waiting" else []
                    ),
                },
            }

    async def activate_agent_skill(
        self,
        run_id: str,
        agent_id: str,
        *,
        skill_id: str,
        content_sha256: str,
        activation_mode: str,
        source_review_sequence: int | None = None,
    ) -> dict[str, Any]:
        """Persist one immutable Skill activation exactly once for an Agent."""

        if activation_mode not in {"model", "capability"}:
            raise StateError(
                "skill_activation_mode_invalid",
                "Skill activation mode is invalid",
                status_code=422,
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                active_skills = [dict(item) for item in (agent.active_skills or [])]
                existing = next(
                    (
                        item
                        for item in active_skills
                        if item.get("skill_id") == skill_id
                    ),
                    None,
                )
                if existing is not None:
                    if existing.get("content_sha256") != content_sha256:
                        raise StateError(
                            "skill_content_changed",
                            "An activated Skill changed after the Agent session started",
                            status_code=409,
                            detail={"skill_id": skill_id},
                        )
                    return {
                        "activated": False,
                        "active_skill": existing,
                        "agent": self._agent_dict(agent, include_runtime=True),
                    }
                activated_at = self.clock().isoformat()
                active_skill = {
                    "skill_id": skill_id,
                    "content_sha256": content_sha256,
                    "activation_mode": activation_mode,
                    "source_review_sequence": source_review_sequence,
                    "activated_at": activated_at,
                }
                active_skills.append(active_skill)
                agent.active_skills = active_skills
                agent.version += 1
                await self._event(
                    session,
                    run_id,
                    "skill_activated",
                    {
                        "skill_id": skill_id,
                        "content_sha256": content_sha256,
                        "activation_mode": activation_mode,
                        "source_review_sequence": source_review_sequence,
                    },
                    agent_id=agent_id,
                )
        return {
            "activated": True,
            "active_skill": active_skill,
            "agent": self._agent_dict(agent, include_runtime=True),
        }

    async def append_agent_event(
        self,
        run_id: str,
        agent_id: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> int:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                return await self._event(
                    session,
                    run_id,
                    event_type,
                    redact_value(dict(payload or {})),
                    agent_id=agent_id,
                )

    async def append_agent_events(
        self,
        run_id: str,
        agent_id: str,
        events: Sequence[Mapping[str, Any]],
    ) -> list[int]:
        """Append one ordered Agent event batch in a single SQLite transaction."""

        if not events:
            return []
        sequences: list[int] = []
        transaction_id = f"event_txn_{uuid4().hex}"
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                for event in events:
                    event_type = event.get("event_type")
                    if not isinstance(event_type, str) or not event_type:
                        raise StateError(
                            "agent_event_type_invalid",
                            "Agent event type must be a non-empty string",
                            status_code=422,
                        )
                    payload = event.get("payload")
                    if payload is not None and not isinstance(payload, Mapping):
                        raise StateError(
                            "agent_event_payload_invalid",
                            "Agent event payload must be an object",
                            status_code=422,
                        )
                    sequences.append(
                        await self._event(
                            session,
                            run_id,
                            event_type,
                            redact_value(
                                {
                                    **dict(payload or {}),
                                    "event_transaction_id": transaction_id,
                                },
                            ),
                            agent_id=agent_id,
                        )
                    )
        await self.notifier.notify(self.run_signal_key(run_id), sequences[-1])
        return sequences

    async def list_agent_events(
        self,
        run_id: str,
        agent_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise StateNotFound("agent_not_found", "Agent was not found")
            rows = (
                await session.scalars(
                    select(StateEventRecord)
                    .where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent_id,
                        StateEventRecord.sequence > after_sequence,
                    )
                    .order_by(StateEventRecord.sequence)
                    .limit(max(1, min(limit, 2_000)))
                )
            ).all()
            return [
                {
                    "sequence": row.sequence,
                    "event_type": row.event_type,
                    "payload": row.payload,
                    "created_at": _json_value(row.created_at),
                }
                for row in rows
            ]

    async def latest_agent_event(
        self,
        run_id: str,
        agent_id: str,
        *,
        event_types: set[str],
    ) -> dict[str, Any] | None:
        """Return the latest matching durable event for one Agent."""

        if not event_types:
            return None
        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise StateNotFound("agent_not_found", "Agent was not found")
            row = await session.scalar(
                select(StateEventRecord)
                .where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.agent_id == agent_id,
                    StateEventRecord.event_type.in_(sorted(event_types)),
                )
                .order_by(StateEventRecord.sequence.desc())
                .limit(1)
            )
            if row is None:
                return None
            return {
                "sequence": row.sequence,
                "event_type": row.event_type,
                "payload": row.payload,
                "created_at": _json_value(row.created_at),
            }

    async def update_agent_memory(
        self,
        run_id: str,
        agent_id: str,
        content: str,
        *,
        summarized_through_sequence: int,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                agent.session_memory = content
                agent.last_summarized_sequence = max(
                    agent.last_summarized_sequence,
                    summarized_through_sequence,
                )
                agent.version += 1
                await self._event(
                    session,
                    run_id,
                    "memory_updated",
                    {"summarized_through_sequence": agent.last_summarized_sequence},
                    agent_id=agent_id,
                )
        return self._agent_dict(agent, include_runtime=True)

    async def transition_agent(
        self,
        run_id: str,
        agent_id: str,
        status: str,
        *,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "pending",
            "queued",
            "starting",
            "running",
            "waiting",
            "working",
            "blocked",
            "stopping",
            "stopped",
            "completed",
            "failed",
            "cancelled",
            "interrupted",
            "indeterminate",
            "paused",
        }
        if status not in allowed:
            raise StateError(
                "invalid_agent_status", "Agent status is invalid", status_code=422
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if expected_version is not None:
                    self._check_version(agent.version, expected_version)
                if agent.status == "completed":
                    return self._agent_dict(agent)
                now = self.clock()
                agent.status = status
                if status == "starting":
                    agent.started_at = agent.started_at or now
                if status == "running":
                    agent.ended_at = None
                    agent.started_at = agent.started_at or now
                    agent.last_heartbeat_at = now
                if status == "stopping":
                    agent.stop_requested_at = now
                if status in {
                    "stopped",
                    "completed",
                    "failed",
                    "cancelled",
                    "interrupted",
                }:
                    agent.ended_at = now
                agent.version += 1
                await self._event(
                    session,
                    run_id,
                    "agent_status_changed",
                    {"agent_id": agent_id, "status": status},
                    agent_id=agent_id,
                )
        return self._agent_dict(agent)

    async def finish_agent(
        self,
        run_id: str,
        agent_id: str,
        *,
        status: str,
        final_report: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "failed", "stopped", "cancelled", "interrupted"}:
            raise StateError(
                "invalid_terminal_status",
                "Agent terminal status is invalid",
                status_code=422,
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.role == "worker":
                    if agent.terminal_report_id is None:
                        raise StateConflict(
                            "execution_finalizer_required",
                            "Execution Agents must be terminated through finalize_worker",
                        )
                    return self._agent_dict(agent, include_runtime=True)
                if agent.status == "completed":
                    return self._agent_dict(agent, include_runtime=True)
                agent.status = status
                if final_report is not None:
                    agent.final_report = redact_value(dict(final_report))
                agent.ended_at = self.clock()
                agent.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "agent_finished",
                    {"agent_id": agent_id, "status": status},
                    agent_id=agent_id,
                )
        await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        if agent.parent_id:
            await self.notifier.notify(
                self.agent_signal_key(run_id, agent.parent_id), event_sequence
            )
        data = self._agent_dict(agent, include_runtime=True)
        data["event_sequence"] = event_sequence
        return data

    async def create_shell_task(
        self,
        run_id: str,
        agent_id: str,
        *,
        task_id: str,
        pid: int,
        process_started_at: float,
        cwd: str,
        temp_dir: str,
        output_path: str,
        capture_limit: int,
        task_name: str | None = None,
        background: bool = False,
        timeout: float = 30.0,
        resource_limits: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist one successfully spawned Shell process without its command."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                if run.status != "active" or aware(run.deadline_at) <= aware(
                    self.clock()
                ):
                    raise StateConflict("run_inactive", "Run cannot create Shell tasks")
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.mode == "review":
                    raise StatePermission(
                        "review_read_only",
                        "Review Workers cannot create technical resources",
                    )
                if agent.status in {
                    "paused",
                    "blocked",
                    "completed",
                    "failed",
                    "stopped",
                    "cancelled",
                    "interrupted",
                }:
                    raise StateConflict(
                        "agent_finished", "Finished Agent cannot create Shell tasks"
                    )
                if await session.get(ShellTaskRecord, task_id) is not None:
                    raise StateConflict(
                        "shell_task_exists", "Shell task already exists"
                    )
                task = ShellTaskRecord(
                    task_id=task_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    status="running",
                    pid=pid,
                    process_started_at=process_started_at,
                    cwd=cwd,
                    temp_dir=temp_dir,
                    output_path=output_path,
                    capture_limit=capture_limit,
                    started_at=self.clock(),
                )
                session.add(task)
                await self._event(
                    session,
                    run_id,
                    "shell_task_started",
                    {"task_id": task_id, "cwd": cwd, "status": "running",
                     "name": task_name, "background": background, "timeout": timeout, "resource_limits": resource_limits or {}},
                    agent_id=agent_id,
                )
        return self._shell_task_dict(task)

    async def finish_shell_task(
        self,
        run_id: str,
        agent_id: str,
        task_id: str,
        *,
        status: str,
        exit_code: int | None,
        output_chars: int,
        truncated: bool,
        timed_out: bool,
        cleanup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        terminal = {
            "completed", "failed", "timeout", "stopped", "cancelled", "interrupted"
        }
        if status not in terminal:
            raise StateError(
                "invalid_shell_task_status",
                "Shell task terminal status is invalid",
                status_code=422,
            )
        completion_sequence = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                task = await session.get(ShellTaskRecord, task_id)
                if task is None or task.run_id != run_id or task.agent_id != agent_id:
                    raise StateNotFound(
                        "shell_task_not_found", "Shell task was not found"
                    )
                if task.status == "running":
                    finished_at = self.clock()
                    task.status = status
                    task.exit_code = exit_code
                    task.output_chars = max(0, output_chars)
                    task.truncated = truncated
                    task.timed_out = timed_out
                    task.finished_at = finished_at
                    task.expires_at = finished_at + timedelta(minutes=30)
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "shell_task_finished",
                        {
                            "task_id": task_id,
                            "status": status,
                            "exit_code": exit_code,
                            "timed_out": timed_out,
                            "truncated": truncated,
                            "cleanup": cleanup or {},
                        },
                        agent_id=agent_id,
                    )
                    completion_sequence = event_sequence
        if completion_sequence is not None:
            await self.notifier.notify(self.agent_signal_key(run_id, agent_id), completion_sequence)
        return self._shell_task_dict(task)

    async def get_shell_task(
        self, run_id: str, agent_id: str, task_id: str
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            task = await session.get(ShellTaskRecord, task_id)
            if task is None or task.run_id != run_id or task.agent_id != agent_id:
                raise StateNotFound("shell_task_not_found", "Shell task was not found")
            result = self._shell_task_dict(task)
            event = await session.scalar(
                select(StateEventRecord)
                .where(
                    StateEventRecord.run_id == run_id,
                    StateEventRecord.agent_id == agent_id,
                    StateEventRecord.event_type.in_(
                        ("shell_task_finished", "shell_task_cleanup_retried")
                    ),
                    StateEventRecord.payload["task_id"].as_string() == task_id,
                )
                .order_by(StateEventRecord.sequence.desc())
                .limit(1)
            )
            result["cleanup"] = event.payload.get("cleanup", {}) if event else {}
            started = await session.scalar(select(StateEventRecord).where(
                StateEventRecord.run_id == run_id, StateEventRecord.agent_id == agent_id,
                StateEventRecord.event_type == "shell_task_started",
                StateEventRecord.payload["task_id"].as_string() == task_id).limit(1))
            result["resource_limits"] = started.payload.get("resource_limits", {}) if started else {}
            return result

    async def list_shell_tasks(
        self,
        run_id: str,
        *,
        agent_id: str | None = None,
        statuses: Iterable[str] | None = None,
        expired_before: datetime | None = None,
        output_available_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[Any] = [ShellTaskRecord.run_id == run_id]
        if agent_id is not None:
            clauses.append(ShellTaskRecord.agent_id == agent_id)
        if statuses is not None:
            values = tuple(statuses)
            if not values:
                return []
            clauses.append(ShellTaskRecord.status.in_(values))
        if expired_before is not None:
            clauses.extend(
                [
                    ShellTaskRecord.expires_at.is_not(None),
                    ShellTaskRecord.expires_at <= aware(expired_before),
                ]
            )
        if output_available_only:
            clauses.append(ShellTaskRecord.output_cleaned_at.is_(None))
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(ShellTaskRecord)
                    .where(*clauses)
                    .order_by(ShellTaskRecord.started_at, ShellTaskRecord.task_id)
                )
            ).all()
            return [self._shell_task_dict(item) for item in rows]

    async def mark_shell_task_output_cleaned(
        self,
        run_id: str,
        agent_id: str,
        task_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                task = await session.get(ShellTaskRecord, task_id)
                if task is None or task.run_id != run_id or task.agent_id != agent_id:
                    raise StateNotFound(
                        "shell_task_not_found", "Shell task was not found"
                    )
                if task.status == "running":
                    raise StateConflict(
                        "shell_task_running", "Running Shell task cannot be cleaned"
                    )
                if task.output_cleaned_at is None:
                    task.output_cleaned_at = self.clock()
                    task.cleanup_reason = reason
                    await self._event(
                        session,
                        run_id,
                        "shell_task_output_cleaned",
                        {"task_id": task_id, "reason": reason},
                        agent_id=agent_id,
                    )
        return self._shell_task_dict(task)

    async def create_network_task(
        self,
        run_id: str,
        agent_id: str,
        *,
        task_id: str,
        scan_intent: str,
        result_path: str,
        estimated_hosts: int,
        estimated_ports: int,
        estimated_requests: int,
        requested_concurrency: int,
        priority: int,
    ) -> dict[str, Any]:
        """Persist network task metadata without targets or the scan plan."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.mode == "review":
                    raise StatePermission(
                        "review_read_only",
                        "Review Workers cannot create technical resources",
                    )
                if agent.status in {
                    "completed",
                    "failed",
                    "stopped",
                    "cancelled",
                    "interrupted",
                }:
                    raise StateConflict(
                        "agent_finished",
                        "Finished Agent cannot create network tasks",
                    )
                if await session.get(NetworkTaskRecord, task_id) is not None:
                    raise StateConflict(
                        "network_task_exists", "Network task already exists"
                    )
                task = NetworkTaskRecord(
                    task_id=task_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    scan_intent=scan_intent,
                    result_path=result_path,
                    estimated_hosts=max(0, estimated_hosts),
                    estimated_ports=max(0, estimated_ports),
                    estimated_requests=max(0, estimated_requests),
                    requested_concurrency=max(1, requested_concurrency),
                    priority=priority,
                )
                session.add(task)
                await self._event(
                    session,
                    run_id,
                    "network_task_created",
                    {
                        "task_id": task_id,
                        "scan_intent": scan_intent,
                        "estimated_hosts": task.estimated_hosts,
                        "estimated_ports": task.estimated_ports,
                        "estimated_requests": task.estimated_requests,
                    },
                    agent_id=agent_id,
                )
        return self._network_task_dict(task)

    async def update_network_task(
        self,
        run_id: str,
        agent_id: str,
        task_id: str,
        *,
        status: str | None = None,
        resource_status: str | None = None,
        pid: int | None = None,
        process_started_at: float | None = None,
        scanner_version: str | None = None,
        bridge_protocol_version: str | None = None,
        tasks_total: int | None = None,
        tasks_completed: int | None = None,
        result_count: int | None = None,
        result_bytes: int | None = None,
        hosts_alive: int | None = None,
        open_ports: int | None = None,
        services: int | None = None,
        web_ports: int | None = None,
        exit_code: int | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        statuses = {
            "queued",
            "running",
            "completed",
            "failed",
            "stopped",
            "interrupted",
        }
        resource_statuses = {
            "queued",
            "reserved",
            "starting",
            "running",
            "waiting",
            "released",
        }
        if status is not None and status not in statuses:
            raise StateError(
                "invalid_network_task_status",
                "Network task status is invalid",
                status_code=422,
            )
        if resource_status is not None and resource_status not in resource_statuses:
            raise StateError(
                "invalid_network_resource_status",
                "Network task resource status is invalid",
                status_code=422,
            )
        completion_sequence = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                task = await session.get(NetworkTaskRecord, task_id)
                if task is None or task.run_id != run_id or task.agent_id != agent_id:
                    raise StateNotFound(
                        "network_task_not_found", "Network task was not found"
                    )
                previous_status = task.status
                if status is not None:
                    task.status = status
                if resource_status is not None:
                    task.resource_status = resource_status
                for field, value in (
                    ("pid", pid),
                    ("process_started_at", process_started_at),
                    ("scanner_version", scanner_version),
                    ("bridge_protocol_version", bridge_protocol_version),
                    ("tasks_total", tasks_total),
                    ("tasks_completed", tasks_completed),
                    ("result_count", result_count),
                    ("result_bytes", result_bytes),
                    ("hosts_alive", hosts_alive),
                    ("open_ports", open_ports),
                    ("services", services),
                    ("web_ports", web_ports),
                    ("exit_code", exit_code),
                    ("error_code", error_code),
                ):
                    if value is not None:
                        setattr(task, field, value)
                now = self.clock()
                if task.status == "running" and task.started_at is None:
                    task.started_at = now
                if task.status in {"completed", "failed", "stopped", "interrupted"}:
                    task.finished_at = task.finished_at or now
                    if resource_status is None:
                        task.resource_status = "released"
                if task.status != previous_status:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "network_task_status_changed",
                        {
                            "task_id": task_id,
                            "status": task.status,
                            "resource_status": task.resource_status,
                            "error_code": task.error_code,
                        },
                        agent_id=agent_id,
                    )
                    if previous_status not in {"completed", "failed", "stopped", "interrupted"} and task.status in {"completed", "failed", "stopped", "interrupted"}:
                        completion_sequence = event_sequence
        if completion_sequence is not None:
            await self.notifier.notify(self.agent_signal_key(run_id, agent_id), completion_sequence)
        return self._network_task_dict(task)

    async def get_network_task(
        self, run_id: str, agent_id: str, task_id: str
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            task = await session.get(NetworkTaskRecord, task_id)
            if task is None or task.run_id != run_id or task.agent_id != agent_id:
                raise StateNotFound(
                    "network_task_not_found", "Network task was not found"
                )
            return self._network_task_dict(task)

    async def list_network_tasks(
        self,
        run_id: str,
        *,
        agent_id: str | None = None,
        statuses: Iterable[str] | None = None,
        output_available_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[Any] = [NetworkTaskRecord.run_id == run_id]
        if agent_id is not None:
            clauses.append(NetworkTaskRecord.agent_id == agent_id)
        if statuses is not None:
            values = tuple(statuses)
            if not values:
                return []
            clauses.append(NetworkTaskRecord.status.in_(values))
        if output_available_only:
            clauses.append(NetworkTaskRecord.output_cleaned_at.is_(None))
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(NetworkTaskRecord)
                    .where(*clauses)
                    .order_by(NetworkTaskRecord.created_at, NetworkTaskRecord.task_id)
                )
            ).all()
            return [self._network_task_dict(item) for item in rows]

    async def mark_network_task_output_cleaned(
        self,
        run_id: str,
        agent_id: str,
        task_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                task = await session.get(NetworkTaskRecord, task_id)
                if task is None or task.run_id != run_id or task.agent_id != agent_id:
                    raise StateNotFound(
                        "network_task_not_found", "Network task was not found"
                    )
                if task.status in {"queued", "running"}:
                    raise StateConflict(
                        "network_task_running",
                        "Active network task cannot be cleaned",
                    )
                if task.output_cleaned_at is None:
                    task.output_cleaned_at = self.clock()
                    task.cleanup_reason = reason
                    await self._event(
                        session,
                        run_id,
                        "network_task_cleaned",
                        {"task_id": task_id, "reason": reason},
                        agent_id=agent_id,
                    )
        return self._network_task_dict(task)

    async def create_http_interaction(
        self,
        run_id: str,
        agent_id: str,
        *,
        interaction_id: str,
        kind: str,
        result_path: str,
        estimated_requests: int,
        requested_concurrency: int,
        estimated_disk_bytes: int,
        estimated_memory_bytes: int,
        estimated_analysis_work: int,
        priority: int,
    ) -> dict[str, Any]:
        """Persist HTTP task metadata without request or response payloads."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.mode == "review":
                    raise StatePermission(
                        "review_read_only",
                        "Review Workers cannot create technical resources",
                    )
                if agent.status in {
                    "completed",
                    "failed",
                    "stopped",
                    "cancelled",
                    "interrupted",
                }:
                    raise StateConflict(
                        "agent_finished",
                        "Finished Agent cannot create HTTP interactions",
                    )
                if await session.get(HttpInteractionRecord, interaction_id) is not None:
                    raise StateConflict(
                        "http_interaction_exists", "HTTP interaction already exists"
                    )
                record = HttpInteractionRecord(
                    interaction_id=interaction_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    kind=kind,
                    result_path=result_path,
                    estimated_requests=min(
                        9_223_372_036_854_775_807, max(0, estimated_requests)
                    ),
                    requested_concurrency=max(1, requested_concurrency),
                    estimated_disk_bytes=min(
                        9_223_372_036_854_775_807, max(0, estimated_disk_bytes)
                    ),
                    estimated_memory_bytes=min(
                        9_223_372_036_854_775_807, max(0, estimated_memory_bytes)
                    ),
                    estimated_analysis_work=min(
                        9_223_372_036_854_775_807, max(0, estimated_analysis_work)
                    ),
                    priority=priority,
                )
                session.add(record)
                await self._event(
                    session,
                    run_id,
                    "http_interaction_created",
                    {
                        "interaction_id": interaction_id,
                        "kind": kind,
                        "estimated_requests": record.estimated_requests,
                        "requested_concurrency": record.requested_concurrency,
                    },
                    agent_id=agent_id,
                )
        return self._http_interaction_dict(record)

    async def create_http_interaction_with_work(
        self,
        run_id: str,
        agent_id: str,
        *,
        interaction_id: str,
        work_id: str,
        kind: str,
        result_path: str,
        estimated_requests: int,
        requested_concurrency: int,
        estimated_disk_bytes: int,
        estimated_memory_bytes: int,
        estimated_analysis_work: int,
    ) -> dict[str, dict[str, Any]]:
        """Atomically enqueue a new HTTP interaction and its execution work."""

        event_sequence: int | None = None
        maximum = 9_223_372_036_854_775_807
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.status in {
                    "completed",
                    "failed",
                    "stopped",
                    "cancelled",
                    "interrupted",
                }:
                    raise StateConflict(
                        "agent_finished",
                        "Finished Agent cannot create HTTP interactions",
                    )
                if await session.get(HttpInteractionRecord, interaction_id) is not None:
                    raise StateConflict(
                        "http_interaction_exists", "HTTP interaction already exists"
                    )
                if await session.get(ResourceWorkRecord, work_id) is not None:
                    raise StateConflict(
                        "resource_work_exists", "Resource work already exists"
                    )

                interaction = HttpInteractionRecord(
                    interaction_id=interaction_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    kind=kind,
                    status="queued",
                    execution_status="queued",
                    analysis_status="not_requested",
                    resource_status="queued",
                    result_path=result_path,
                    estimated_requests=min(maximum, max(0, estimated_requests)),
                    requested_concurrency=max(1, requested_concurrency),
                    estimated_disk_bytes=min(maximum, max(0, estimated_disk_bytes)),
                    estimated_memory_bytes=min(maximum, max(0, estimated_memory_bytes)),
                    estimated_analysis_work=min(
                        maximum, max(0, estimated_analysis_work)
                    ),
                    priority=agent.priority,
                )
                work = ResourceWorkRecord(
                    work_id=work_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    owner_type="http_interaction",
                    owner_id=interaction_id,
                    phase="execution",
                    priority=agent.priority,
                    requested_concurrency=max(1, requested_concurrency),
                    estimated_requests=min(maximum, max(0, estimated_requests)),
                    estimated_disk_bytes=min(maximum, max(0, estimated_disk_bytes)),
                    estimated_memory_bytes=min(maximum, max(0, estimated_memory_bytes)),
                )
                session.add_all([interaction, work])
                await self._event(
                    session,
                    run_id,
                    "http_interaction_created",
                    {
                        "interaction_id": interaction_id,
                        "kind": kind,
                        "estimated_requests": interaction.estimated_requests,
                        "requested_concurrency": interaction.requested_concurrency,
                    },
                    agent_id=agent_id,
                )
                event_sequence = await self._event(
                    session,
                    run_id,
                    "resource_work_queued",
                    {
                        "work_id": work_id,
                        "owner_type": "http_interaction",
                        "owner_id": interaction_id,
                        "phase": "execution",
                    },
                    agent_id=agent_id,
                )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return {
            "interaction": self._http_interaction_dict(interaction),
            "work": self._resource_work_dict(work),
        }

    async def update_http_interaction(
        self,
        run_id: str,
        agent_id: str,
        interaction_id: str,
        **changes: Any,
    ) -> dict[str, Any]:
        allowed = {
            "status",
            "execution_status",
            "analysis_status",
            "resource_status",
            "started_requests",
            "completed_requests",
            "response_bytes",
            "analyzed_responses",
            "error_code",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise StateError(
                "invalid_http_interaction_update",
                "HTTP interaction update contains unsupported fields",
                status_code=422,
            )
        completion_sequence = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                record = await session.get(HttpInteractionRecord, interaction_id)
                if (
                    record is None
                    or record.run_id != run_id
                    or record.agent_id != agent_id
                ):
                    raise StateNotFound(
                        "http_interaction_not_found",
                        "HTTP interaction was not found",
                    )
                previous = (
                    record.status,
                    record.execution_status,
                    record.analysis_status,
                    record.resource_status,
                )
                for key, value in changes.items():
                    if key in {
                        "started_requests",
                        "completed_requests",
                        "response_bytes",
                        "analyzed_responses",
                    }:
                        value = max(0, int(value))
                    setattr(record, key, value)
                now = self.clock()
                if record.started_at is None and record.execution_status == "running":
                    record.started_at = now
                if (
                    record.execution_finished_at is None
                    and record.execution_status
                    in {
                        "completed",
                        "failed",
                        "stopped",
                        "interrupted",
                    }
                ):
                    record.execution_finished_at = now
                if record.analysis_finished_at is None and record.analysis_status in {
                    "completed",
                    "failed",
                    "interrupted",
                }:
                    record.analysis_finished_at = now
                elif previous[2] in {
                    "completed",
                    "failed",
                    "interrupted",
                } and record.analysis_status in {"queued", "running"}:
                    record.analysis_finished_at = None
                current = (
                    record.status,
                    record.execution_status,
                    record.analysis_status,
                    record.resource_status,
                )
                if current != previous:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "http_interaction_status_changed",
                        {
                            "interaction_id": interaction_id,
                            "status": record.status,
                            "execution_status": record.execution_status,
                            "analysis_status": record.analysis_status,
                            "resource_status": record.resource_status,
                        },
                        agent_id=agent_id,
                    )
                    terminal = {"completed", "failed", "stopped", "interrupted"}
                    execution_finished = previous[1] not in terminal and record.execution_status in terminal
                    analysis_finished = previous[2] not in terminal and record.analysis_status in terminal
                    if execution_finished or analysis_finished:
                        completion_sequence = event_sequence
        if completion_sequence is not None:
            await self.notifier.notify(self.agent_signal_key(run_id, agent_id), completion_sequence)
        return self._http_interaction_dict(record)

    async def get_http_interaction(
        self, run_id: str, agent_id: str, interaction_id: str
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            record = await session.get(HttpInteractionRecord, interaction_id)
            if record is None or record.run_id != run_id or record.agent_id != agent_id:
                raise StateNotFound(
                    "http_interaction_not_found", "HTTP interaction was not found"
                )
            return self._http_interaction_dict(record)

    async def list_http_interactions(
        self,
        run_id: str,
        *,
        agent_id: str | None = None,
        statuses: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[Any] = [HttpInteractionRecord.run_id == run_id]
        if agent_id is not None:
            clauses.append(HttpInteractionRecord.agent_id == agent_id)
        if statuses is not None:
            values = tuple(statuses)
            if not values:
                return []
            clauses.append(HttpInteractionRecord.status.in_(values))
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(HttpInteractionRecord)
                    .where(*clauses)
                    .order_by(
                        HttpInteractionRecord.created_at,
                        HttpInteractionRecord.interaction_id,
                    )
                )
            ).all()
            return [self._http_interaction_dict(item) for item in rows]

    async def mark_http_interaction_cleaned(
        self,
        run_id: str,
        agent_id: str,
        interaction_id: str,
        *,
        reason: str,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                record = await session.get(HttpInteractionRecord, interaction_id)
                if (
                    record is None
                    or record.run_id != run_id
                    or record.agent_id != agent_id
                ):
                    raise StateNotFound(
                        "http_interaction_not_found",
                        "HTTP interaction was not found",
                    )
                if record.status in {"queued", "running", "analyzing"}:
                    raise StateConflict(
                        "http_interaction_running",
                        "Active HTTP interaction cannot be cleaned",
                    )
                if record.output_cleaned_at is None:
                    record.output_cleaned_at = self.clock()
                    record.cleanup_reason = reason
                    await self._event(
                        session,
                        run_id,
                        "http_interaction_cleaned",
                        {"interaction_id": interaction_id, "reason": reason},
                        agent_id=agent_id,
                    )
        return self._http_interaction_dict(record)

    async def create_resource_work(
        self,
        run_id: str,
        agent_id: str,
        *,
        work_id: str,
        owner_type: str,
        owner_id: str,
        phase: str,
        priority: int,
        requested_concurrency: int,
        estimated_requests: int,
        estimated_disk_bytes: int,
        estimated_memory_bytes: int,
    ) -> dict[str, Any]:
        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                record = ResourceWorkRecord(
                    work_id=work_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    owner_type=owner_type,
                    owner_id=owner_id,
                    phase=phase,
                    priority=priority,
                    requested_concurrency=max(1, requested_concurrency),
                    estimated_requests=min(
                        9_223_372_036_854_775_807, max(0, estimated_requests)
                    ),
                    estimated_disk_bytes=min(
                        9_223_372_036_854_775_807, max(0, estimated_disk_bytes)
                    ),
                    estimated_memory_bytes=min(
                        9_223_372_036_854_775_807, max(0, estimated_memory_bytes)
                    ),
                )
                session.add(record)
                event_sequence = await self._event(
                    session,
                    run_id,
                    "resource_work_queued",
                    {
                        "work_id": work_id,
                        "owner_type": owner_type,
                        "owner_id": owner_id,
                        "phase": phase,
                    },
                    agent_id=agent_id,
                )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return self._resource_work_dict(record)

    async def queue_http_analysis_work(
        self,
        run_id: str,
        agent_id: str,
        interaction_id: str,
        *,
        work_id: str,
        revision: int,
        estimated_requests: int,
        estimated_memory_bytes: int,
    ) -> dict[str, dict[str, Any]]:
        """Atomically transition an interaction and enqueue one analysis revision."""

        event_sequence: int | None = None
        maximum = 9_223_372_036_854_775_807
        async with self._lock:
            async with self.db.sessions.begin() as session:
                interaction = await session.get(HttpInteractionRecord, interaction_id)
                if (
                    interaction is None
                    or interaction.run_id != run_id
                    or interaction.agent_id != agent_id
                ):
                    raise StateNotFound(
                        "http_interaction_not_found",
                        "HTTP interaction was not found",
                    )
                if interaction.execution_status != "completed":
                    raise StateConflict(
                        "http_execution_not_completed",
                        "HTTP response analysis requires completed execution",
                    )
                if interaction.analysis_status in {"queued", "running"}:
                    active_work = await session.scalar(
                        select(ResourceWorkRecord.work_id)
                        .where(
                            ResourceWorkRecord.run_id == run_id,
                            ResourceWorkRecord.owner_id == interaction_id,
                            ResourceWorkRecord.phase.like("analysis-%"),
                            ResourceWorkRecord.status.in_(
                                {"queued", "reserved", "starting", "running"}
                            ),
                        )
                        .limit(1)
                    )
                    if active_work is not None:
                        raise StateConflict(
                            "http_analysis_running",
                            "HTTP response analysis is already queued or running",
                        )
                elif interaction.analysis_status not in {
                    "not_requested",
                    "completed",
                }:
                    raise StateConflict(
                        "http_analysis_not_repeatable",
                        "HTTP response analysis cannot be queued from its current state",
                    )
                if await session.get(ResourceWorkRecord, work_id) is not None:
                    raise StateConflict(
                        "resource_work_exists", "Resource work already exists"
                    )

                previous = (
                    interaction.status,
                    interaction.execution_status,
                    interaction.analysis_status,
                    interaction.resource_status,
                )
                interaction.status = "analyzing"
                interaction.analysis_status = "queued"
                interaction.resource_status = "queued"
                if interaction.analysis_finished_at is not None:
                    interaction.analysis_finished_at = None
                work = ResourceWorkRecord(
                    work_id=work_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    owner_type="http_interaction",
                    owner_id=interaction_id,
                    phase=f"analysis-{revision}",
                    status="queued",
                    priority=interaction.priority,
                    requested_concurrency=1,
                    estimated_requests=min(maximum, max(0, estimated_requests)),
                    estimated_disk_bytes=0,
                    estimated_memory_bytes=min(
                        maximum, max(65_536, estimated_memory_bytes)
                    ),
                )
                session.add(work)
                await self._event(
                    session,
                    run_id,
                    "http_interaction_status_changed",
                    {
                        "interaction_id": interaction_id,
                        "previous": list(previous),
                        "status": interaction.status,
                        "execution_status": interaction.execution_status,
                        "analysis_status": interaction.analysis_status,
                        "resource_status": interaction.resource_status,
                    },
                    agent_id=agent_id,
                )
                event_sequence = await self._event(
                    session,
                    run_id,
                    "resource_work_queued",
                    {
                        "work_id": work_id,
                        "owner_type": "http_interaction",
                        "owner_id": interaction_id,
                        "phase": work.phase,
                    },
                    agent_id=agent_id,
                )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return {
            "interaction": self._http_interaction_dict(interaction),
            "work": self._resource_work_dict(work),
        }

    async def update_resource_work(
        self,
        run_id: str,
        work_id: str,
        *,
        status: str,
        reason: str | None = None,
        retry_at: datetime | None = None,
    ) -> dict[str, Any]:
        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                record = await session.get(ResourceWorkRecord, work_id)
                if record is None or record.run_id != run_id:
                    raise StateNotFound(
                        "resource_work_not_found", "Resource work was not found"
                    )
                previous = record.status
                record.status = status
                record.reason = reason
                record.retry_at = retry_at
                now = self.clock()
                if status == "reserved" and record.reserved_at is None:
                    record.reserved_at = now
                if status == "running" and record.started_at is None:
                    record.started_at = now
                if status in {"completed", "failed", "stopped", "interrupted"}:
                    record.finished_at = now
                if status != previous:
                    queue_latency_ms = None
                    if status in {"reserved", "starting", "running"}:
                        queue_latency_ms = int(
                            max(
                                0.0,
                                (now - aware(record.created_at)).total_seconds(),
                            )
                            * 1_000
                        )
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "resource_work_status_changed",
                        {
                            "work_id": work_id,
                            "owner_id": record.owner_id,
                            "phase": record.phase,
                            "status": status,
                            "reason": reason,
                            "queue_latency_ms": queue_latency_ms,
                        },
                        agent_id=record.agent_id,
                    )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return self._resource_work_dict(record)

    async def claim_resource_work(self, run_id: str, work_id: str) -> dict[str, Any]:
        """Atomically claim one reserved work item for the sole Runtime launcher."""

        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                result = await session.execute(
                    update(ResourceWorkRecord)
                    .where(
                        ResourceWorkRecord.run_id == run_id,
                        ResourceWorkRecord.work_id == work_id,
                        ResourceWorkRecord.status == "reserved",
                    )
                    .values(status="starting", reason=None)
                )
                claimed = bool(result.rowcount)
                record = await session.get(ResourceWorkRecord, work_id)
                if record is None or record.run_id != run_id:
                    raise StateNotFound(
                        "resource_work_not_found", "Resource work was not found"
                    )
                if claimed:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "resource_work_claimed",
                        {
                            "work_id": work_id,
                            "owner_id": record.owner_id,
                            "phase": record.phase,
                        },
                        agent_id=record.agent_id,
                    )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return {"claimed": claimed, **self._resource_work_dict(record)}

    async def mark_resource_work_started(
        self, run_id: str, work_id: str
    ) -> dict[str, Any]:
        """Move a claimed item to running without reviving a terminal fast task."""

        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                now = self.clock()
                result = await session.execute(
                    update(ResourceWorkRecord)
                    .where(
                        ResourceWorkRecord.run_id == run_id,
                        ResourceWorkRecord.work_id == work_id,
                        ResourceWorkRecord.status == "starting",
                    )
                    .values(status="running", started_at=now)
                )
                started = bool(result.rowcount)
                record = await session.get(ResourceWorkRecord, work_id)
                if record is None or record.run_id != run_id:
                    raise StateNotFound(
                        "resource_work_not_found", "Resource work was not found"
                    )
                if started:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "resource_work_status_changed",
                        {
                            "work_id": work_id,
                            "owner_id": record.owner_id,
                            "phase": record.phase,
                            "status": "running",
                            "reason": None,
                            "queue_latency_ms": int(
                                max(
                                    0.0,
                                    (
                                        aware(now) - aware(record.created_at)
                                    ).total_seconds(),
                                )
                                * 1_000
                            ),
                        },
                        agent_id=record.agent_id,
                    )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return {"started": started, **self._resource_work_dict(record)}

    async def update_resource_work_estimate(
        self,
        run_id: str,
        work_id: str,
        *,
        estimated_requests: int,
        estimated_disk_bytes: int,
    ) -> dict[str, Any]:
        """Update a finite task's growing estimate without emitting an audit event."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                record = await session.get(ResourceWorkRecord, work_id)
                if record is None or record.run_id != run_id:
                    raise StateNotFound(
                        "resource_work_not_found", "Resource work was not found"
                    )
                record.estimated_requests = max(0, estimated_requests)
                record.estimated_disk_bytes = max(0, estimated_disk_bytes)
        return self._resource_work_dict(record)

    async def next_resource_work(self, run_id: str) -> dict[str, Any] | None:
        async with self.db.sessions() as session:
            record = await session.scalar(
                select(ResourceWorkRecord)
                .where(
                    ResourceWorkRecord.run_id == run_id,
                    ResourceWorkRecord.status == "queued",
                )
                .order_by(
                    ResourceWorkRecord.priority.desc(),
                    ResourceWorkRecord.created_at,
                )
                .limit(1)
            )
            return None if record is None else self._resource_work_dict(record)

    async def get_resource_work(self, run_id: str, work_id: str) -> dict[str, Any]:
        async with self.db.sessions() as session:
            record = await session.get(ResourceWorkRecord, work_id)
            if record is None or record.run_id != run_id:
                raise StateNotFound(
                    "resource_work_not_found", "Resource work was not found"
                )
            return self._resource_work_dict(record)

    async def list_resource_work(
        self,
        run_id: str,
        *,
        owner_id: str | None = None,
        statuses: Iterable[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[Any] = [ResourceWorkRecord.run_id == run_id]
        if owner_id is not None:
            clauses.append(ResourceWorkRecord.owner_id == owner_id)
        if statuses is not None:
            values = tuple(statuses)
            if not values:
                return []
            clauses.append(ResourceWorkRecord.status.in_(values))
        async with self.db.sessions() as session:
            rows = (
                await session.scalars(
                    select(ResourceWorkRecord)
                    .where(*clauses)
                    .order_by(
                        ResourceWorkRecord.created_at,
                        ResourceWorkRecord.work_id,
                    )
                )
            ).all()
            return [self._resource_work_dict(item) for item in rows]

    async def finish_run(
        self,
        run_id: str,
        status: str,
        *,
        report: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "failed", "interrupted"}:
            raise StateError(
                "invalid_run_status", "run terminal status is invalid", status_code=422
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                if run.status in {"completed", "failed", "interrupted"}:
                    return self._run_dict(run)
                run.status = status
                if report is not None:
                    chief = await session.scalar(
                        select(AgentRecord)
                        .where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.role == "chief",
                        )
                        .limit(1)
                    )
                    if chief is not None:
                        chief.final_report = redact_value(dict(report))
                event_sequence = await self._event(
                    session,
                    run_id,
                    "run_finished",
                    {
                        "status": status,
                        "reason": (report or {}).get("completion_reason")
                        or (report or {}).get("type") or status,
                    },
                    agent_id=(
                        chief.agent_id
                        if report is not None and chief is not None
                        else None
                    ),
                )
        await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return self._run_dict(run)

    async def pause_run(self, run_id: str, *, reason: str) -> dict[str, Any]:
        """Persist a resumable Run pause without turning it terminal."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                if run.status in {"completed", "failed", "interrupted"}:
                    return self._run_dict(run)
                if run.status == "paused" and run.pause_reason == reason:
                    return self._run_dict(run)
                run.status = "paused"
                run.paused_at = self.clock()
                run.pause_reason = reason[:128]
                sequence = await self._event(
                    session,
                    run_id,
                    "run_paused",
                    {"reason": run.pause_reason},
                )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return self._run_dict(run)

    async def resume_run(self, run_id: str) -> dict[str, Any]:
        """Mark a resumable Run active before its controllers are relaunched."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                if run.status in {"completed", "failed", "interrupted"}:
                    raise StateConflict("run_not_resumable", "Run is terminal")
                if run.status == "active":
                    return self._run_dict(run)
                previous_reason = run.pause_reason
                run.status = "active"
                run.paused_at = None
                run.pause_reason = None
                sequence = await self._event(
                    session,
                    run_id,
                    "run_resumed",
                    {"previous_pause_reason": previous_reason},
                )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return self._run_dict(run)

    async def append_run_event(
        self, run_id: str, event_type: str, payload: Mapping[str, Any]
    ) -> int:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                sequence = await self._event(session, run_id, event_type, dict(payload))
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return sequence

    async def publish_control_report(
        self,
        run_id: str,
        *,
        sender_id: str,
        recipient_id: str,
        unique_code: str | None,
        report_type: str,
        status: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                sender = await session.get(AgentRecord, sender_id)
                recipient = await session.get(AgentRecord, recipient_id)
                if (
                    sender is None
                    or recipient is None
                    or sender.run_id != run_id
                    or recipient.run_id != run_id
                ):
                    raise StateNotFound(
                        "agent_not_found", "Control report Agent was not found"
                    )
                sequence = await self._next_sequence(session, run_id)
                report = ReportRecord(
                    report_id=f"report_{uuid4().hex}",
                    run_id=run_id,
                    sequence=sequence,
                    agent_id=sender_id,
                    parent_id=recipient_id,
                    unique_code=unique_code,
                    report_type=report_type,
                    status=status,
                    payload=redact_value(dict(payload)),
                )
                session.add(report)
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "control_report_created",
                    {"report_id": report.report_id, "report_type": report_type},
                    agent_id=sender_id,
                )
        await self.notifier.notify(
            self.agent_signal_key(run_id, recipient_id), sequence
        )
        return self._report_dict(report)

    async def publish_challenge_report(
        self,
        run_id: str,
        *,
        sender_id: str,
        unique_code: str,
        report_type: str,
        status: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist a challenge-level report that survives Agent replacement."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                sender = await session.get(AgentRecord, sender_id)
                if sender is None or sender.run_id != run_id:
                    raise StateNotFound(
                        "agent_not_found", "Challenge report Agent was not found"
                    )
                sequence = await self._next_sequence(session, run_id)
                report = ReportRecord(
                    report_id=f"report_{uuid4().hex}",
                    run_id=run_id,
                    sequence=sequence,
                    agent_id=sender_id,
                    parent_id=None,
                    unique_code=unique_code,
                    report_type=report_type,
                    status=status,
                    payload=redact_value(dict(payload)),
                )
                session.add(report)
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "challenge_report_created",
                    {
                        "report_id": report.report_id,
                        "unique_code": unique_code,
                        "report_type": report_type,
                    },
                    agent_id=sender_id,
                )
        return self._report_dict(report)

    @staticmethod
    def _worker_evidence_allowed(agent: AgentRecord, row: EvidenceRecord) -> bool:
        return row.run_id == agent.run_id and row.unique_code == agent.unique_code

    async def list_reports(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        after_sequence: int = 0,
        wait_seconds: float = 0.0,
        max_reports: int = 20,
    ) -> dict[str, Any]:
        if wait_seconds < 0 or wait_seconds > 30:
            raise StateError(
                "invalid_wait", "wait_seconds must be between 0 and 30", status_code=422
            )
        max_reports = max(1, min(max_reports, 100))
        signal_key = self.agent_signal_key(run_id, context.agent_id)
        signal_sequence = await self.notifier.current(signal_key)
        while True:
            async with self.db.sessions() as session:
                agent = await self._authorize(
                    session, context, roles={"chief", "solver"}, run_id=run_id
                )
                query = (
                    select(ReportRecord)
                    .where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.sequence > after_sequence,
                        ReportRecord.parent_id == agent.agent_id,
                    )
                    .order_by(ReportRecord.sequence)
                    .limit(max_reports)
                )
                rows = (await session.scalars(query)).all()
                if rows:
                    reports = [self._report_dict(item) for item in rows]
                    return {
                        "reports": reports,
                        "count": len(rows),
                        "next_sequence": rows[-1].sequence,
                    }
            if wait_seconds <= 0:
                return {"reports": [], "count": 0, "next_sequence": after_sequence}
            started = asyncio.get_running_loop().time()
            signal_sequence = await self.notifier.wait(
                signal_key,
                signal_sequence,
                wait_seconds,
            )
            if asyncio.get_running_loop().time() - started >= wait_seconds:
                async with self.db.sessions() as session:
                    agent = await self._authorize(
                        session, context, roles={"chief", "solver"}, run_id=run_id
                    )
                    return {"reports": [], "count": 0, "next_sequence": after_sequence}
            wait_seconds = max(
                0.0, wait_seconds - (asyncio.get_running_loop().time() - started)
            )

    async def heartbeat(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        *,
        sample_event: bool = False,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session,
                    context,
                    roles={"chief", "solver", "worker"},
                    agent_id=agent_id,
                    run_id=run_id,
                )
                await session.execute(
                    update(AgentRecord)
                    .where(AgentRecord.agent_id == agent_id)
                    .values(
                        last_heartbeat_at=self.clock(),
                        updated_at=AgentRecord.updated_at,
                    )
                )
                await session.refresh(agent)
                if sample_event:
                    await self._event(
                        session,
                        run_id,
                        "agent_heartbeat",
                        {"agent_id": agent_id},
                        agent_id=agent_id,
                    )
        return self._agent_dict(agent)

    async def claim_challenge_tool_fingerprint(
        self,
        run_id: str,
        unique_code: str,
        agent_id: str,
        *,
        tool_name: str,
        digest: str,
    ) -> dict[str, Any]:
        """Atomically suppress an identical in-flight or successful expensive call.

        Only the one-way digest is stored in the Challenge controller cursor;
        request arguments and tool output never enter durable state.
        """

        if tool_name != "pentest_sqlmap":
            return {"claimed": True, "duplicate": False}
        key = f"{tool_name}:{digest}"
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_challenge(session, run_id, unique_code)
                controller = await session.scalar(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "solver",
                    )
                )
                if controller is None:
                    return {"claimed": True, "duplicate": False}
                cursors = dict(controller.tool_fingerprints or {})
                attempts = dict(cursors.get("expensive_tool_attempts") or {})
                existing = attempts.get(key)
                if isinstance(existing, Mapping):
                    status = existing.get("status")
                    owner_id = existing.get("agent_id")
                    if status == "success":
                        return {
                            "claimed": False,
                            "duplicate": True,
                            "reason": "already_succeeded",
                        }
                    if status == "running" and owner_id != agent_id:
                        owner = await session.get(AgentRecord, owner_id)
                        if owner is not None and owner.status not in {
                            "failed",
                            "stopped",
                            "completed",
                            "cancelled",
                            "interrupted",
                        }:
                            return {
                                "claimed": False,
                                "duplicate": True,
                                "reason": "already_running",
                            }
                attempts[key] = {"status": "running", "agent_id": agent_id}
                while len(attempts) > 128:
                    attempts.pop(next(iter(attempts)))
                cursors["expensive_tool_attempts"] = attempts
                controller.tool_fingerprints = cursors
                controller.version += 1
        return {"claimed": True, "duplicate": False}

    async def complete_challenge_tool_fingerprint(
        self,
        run_id: str,
        unique_code: str,
        agent_id: str,
        *,
        tool_name: str,
        digest: str,
        success: bool,
    ) -> None:
        """Commit or release an expensive-call digest without storing payloads."""

        if tool_name != "pentest_sqlmap":
            return
        key = f"{tool_name}:{digest}"
        async with self._lock:
            async with self.db.sessions.begin() as session:
                controller = await session.scalar(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "solver",
                    )
                )
                if controller is None:
                    return
                cursors = dict(controller.tool_fingerprints or {})
                attempts = dict(cursors.get("expensive_tool_attempts") or {})
                existing = attempts.get(key)
                if (
                    not isinstance(existing, Mapping)
                    or existing.get("agent_id") != agent_id
                ):
                    return
                if success:
                    attempts[key] = {"status": "success"}
                else:
                    attempts.pop(key, None)
                cursors["expensive_tool_attempts"] = attempts
                controller.tool_fingerprints = cursors
                controller.version += 1

    async def start_challenge(
        self, run_id: str, unique_code: str, context: CapabilityContext | None = None
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if context is not None:
                    await self._authorize(
                        session,
                        context,
                        roles={"chief", "solver"},
                        unique_code=unique_code,
                        run_id=run_id,
                    )
                await self._require_challenge_in_scope(session, run_id, unique_code)
                challenge = await self._require_challenge(session, run_id, unique_code)
                challenges = (
                    await session.scalars(
                        select(ChallengeRecord).where(ChallengeRecord.run_id == run_id)
                    )
                ).all()
                gate = evaluate_challenge_start_gate(
                    [self._challenge_dict(item) for item in challenges], unique_code
                )
                if not gate["allowed"]:
                    raise StateConflict(
                        "challenge_slots_exhausted",
                        f"at most {MAX_CHALLENGE_SLOTS} challenge containers may be active",
                        gate["container_capacity"],
                    )
                now = self.clock()
                run = await self._require_run(session, run_id)
                challenge.container_status = "running"
                challenge.platform_status = "started"
                challenge.work_status = "active"
                was_paused = challenge.pause_reason is not None
                challenge.started_at = challenge.started_at or now
                if challenge.active_since is None:
                    challenge.active_since = now
                    if challenge.last_progress_at is None or was_paused:
                        challenge.last_progress_at = now
                challenge.last_progress_at = challenge.last_progress_at or now
                challenge.paused_at = None
                challenge.pause_reason = None
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_started",
                    {"unique_code": unique_code},
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def close_challenge(
        self, run_id: str, unique_code: str, context: CapabilityContext | None = None
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if context is not None:
                    await self._authorize(
                        session,
                        context,
                        roles={"chief", "solver"},
                        unique_code=unique_code,
                        run_id=run_id,
                    )
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.is_completed or challenge.work_status == "closed":
                    return self._challenge_dict(challenge)
                challenge.active_since = None
                challenge.work_status = "closed"
                challenge.paused_at = self.clock()
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_closed",
                    {"unique_code": unique_code},
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def mark_completed_container_release_pending(
        self, run_id: str, unique_code: str, *, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Persist that a terminal or paused container needs an idempotent close retry."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                if (
                    not challenge.is_completed
                    and challenge.work_status not in {"closed", "paused"}
                ) or not container_slot_occupied(challenge.container_status):
                    return self._challenge_dict(challenge)
                challenge.platform_status = "close_requested"
                challenge.container_status = "release_pending"
                if challenge.is_completed:
                    challenge.work_status = "completed"
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "container_release_pending",
                    {"unique_code": unique_code},
                    agent_id=agent_id,
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def mark_operation_started(
        self,
        run_id: str,
        operation_type: str,
        *,
        agent_id: str | None = None,
        unique_code: str | None = None,
        arguments: Mapping[str, Any] | None = None,
    ) -> str:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await session.execute(text("BEGIN IMMEDIATE"))
                run = await self._require_run(session, run_id)
                if operation_type == "benchmark_start_challenge":
                    await self._require_challenge_in_scope(session, run_id, unique_code)
                operation_id = f"operation_{uuid4().hex}"
                safe_arguments = redact_value(dict(arguments or {}))
                fingerprint = _fingerprint("operation", operation_type, safe_arguments)
                if operation_type == "benchmark_submit_flag":
                    owner = await session.get(AgentRecord, agent_id)
                    if (
                        owner is None
                        or owner.role != "solver"
                        or owner.run_id != run_id
                        or owner.unique_code != unique_code
                    ):
                        raise StatePermission(
                            "solver_required",
                            "Only the bound Solver may submit an answer",
                        )
                    challenge = await self._require_challenge(
                        session, run_id, unique_code
                    )
                    if run.status != "active" or aware(self.clock()) >= aware(
                        run.deadline_at
                    ):
                        raise StateConflict(
                            "run_inactive", "Run has ended or is paused"
                        )
                    if (
                        challenge.is_completed
                        or challenge.work_status in {"paused", "closed"}
                        or owner.status == "paused"
                    ):
                        raise StateConflict(
                            "challenge_not_active",
                            "Challenge cannot accept a submission",
                        )
                    duplicate = await session.scalar(
                        select(OperationRecord.operation_id).where(
                            OperationRecord.run_id == run_id,
                            OperationRecord.unique_code == unique_code,
                            OperationRecord.operation_type == operation_type,
                            OperationRecord.arguments_fingerprint == fingerprint,
                        )
                    )
                    if duplicate:
                        raise StateConflict(
                            "duplicate",
                            "This exact answer already has a recorded submission",
                        )
                record = OperationRecord(
                    operation_id=operation_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    unique_code=unique_code,
                    operation_type=operation_type,
                    arguments_fingerprint=fingerprint,
                    request_payload=safe_arguments,
                    started_at=self.clock(),
                )
                session.add(record)
                record.started_sequence = await self._event(
                    session,
                    run_id,
                    "operation_started",
                    {
                        "operation_id": operation_id,
                        "operation_type": operation_type,
                        "unique_code": unique_code,
                    },
                    agent_id=agent_id,
                )
                return operation_id

    async def complete_operation(
        self,
        run_id: str,
        operation_id: str,
        *,
        result_code: str | None = None,
        result_payload: Mapping[str, Any] | None = None,
        challenge_updates: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        changed_unique_code: str | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                operation = await session.get(OperationRecord, operation_id)
                if operation is None or operation.run_id != run_id:
                    raise StateNotFound(
                        "operation_not_found", "operation was not found"
                    )
                if operation.status == "indeterminate":
                    raise StateConflict(
                        "operation_indeterminate",
                        "read-only synchronization is required before retry",
                    )
                operation.status = "completed"
                operation.result_code = result_code
                operation.result_payload = redact_value(dict(result_payload or {}))
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int(
                        (
                            aware(operation.completed_at) - aware(operation.started_at)
                        ).total_seconds()
                        * 1_000
                    ),
                )
                if operation.unique_code and challenge_updates:
                    changed_unique_code = operation.unique_code
                    challenge = await self._require_challenge(
                        session, run_id, operation.unique_code
                    )
                    progress_kind = self._apply_operation_challenge_updates(
                        challenge, challenge_updates
                    )
                    if progress_kind is not None:
                        self._mark_progress(challenge)
                        await self._event(
                            session,
                            run_id,
                            "challenge_progress_recorded",
                            {
                                "unique_code": operation.unique_code,
                                "progress_kinds": [progress_kind],
                            },
                            agent_id=operation.agent_id,
                        )
                        if progress_kind == "flag_accepted":
                            await self._event(
                                session,
                                run_id,
                                "solver_flag_accepted",
                                {
                                    "unique_code": operation.unique_code,
                                    "correct_flag_count": challenge.correct_flag_count,
                                },
                                agent_id=operation.agent_id,
                            )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    "operation_completed",
                    {
                        "operation_id": operation_id,
                        "result_code": result_code,
                        "duration_ms": operation.duration_ms,
                    },
                    agent_id=operation.agent_id,
                )
        if changed_unique_code is not None:
            await self.signal_challenge_changes(
                run_id, [changed_unique_code], operation.completed_sequence
            )
        return self._operation_dict(operation)

    async def fail_operation(
        self,
        run_id: str,
        operation_id: str,
        *,
        error_code: str,
        error_message: str,
        result_payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                operation = await session.get(OperationRecord, operation_id)
                if operation is None or operation.run_id != run_id:
                    raise StateNotFound(
                        "operation_not_found", "operation was not found"
                    )
                if operation.status != "started":
                    raise StateConflict(
                        "operation_not_started", "operation is not active"
                    )
                operation.status = "failed"
                operation.error_code = error_code[:128]
                operation.error_message = error_message[:512]
                operation.result_payload = redact_value(dict(result_payload or {}))
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int(
                        (
                            aware(operation.completed_at) - aware(operation.started_at)
                        ).total_seconds()
                        * 1_000
                    ),
                )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    "operation_failed",
                    {
                        "operation_id": operation_id,
                        "error_code": operation.error_code,
                        "duration_ms": operation.duration_ms,
                    },
                    agent_id=operation.agent_id,
                )
        return self._operation_dict(operation)

    async def mark_operation_indeterminate(
        self,
        run_id: str,
        operation_id: str,
        *,
        error_code: str = "operation_indeterminate",
        error_message: str = "The remote operation may have executed but could not be confirmed",
        result_payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Park one ambiguous remote operation without allowing a retry."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                operation = await session.get(OperationRecord, operation_id)
                if operation is None or operation.run_id != run_id:
                    raise StateNotFound(
                        "operation_not_found", "operation was not found"
                    )
                if operation.status != "started":
                    raise StateConflict(
                        "operation_not_started", "operation is not active"
                    )
                operation.status = "indeterminate"
                operation.error_code = error_code[:128]
                operation.error_message = error_message[:512]
                operation.result_payload = redact_value(dict(result_payload or {}))
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int(
                        (
                            aware(operation.completed_at) - aware(operation.started_at)
                        ).total_seconds()
                        * 1_000
                    ),
                )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    "operation_indeterminate",
                    {
                        "operation_id": operation.operation_id,
                        "operation_type": operation.operation_type,
                        "unique_code": operation.unique_code,
                        "error_code": operation.error_code,
                    },
                    agent_id=operation.agent_id,
                )
        return self._operation_dict(operation)

    async def reconcile_indeterminate_operation(
        self,
        run_id: str,
        operation_id: str,
        *,
        resolved: bool,
        result_code: str | None = None,
    ) -> dict[str, Any]:
        """Finalize an indeterminate operation after a read-only remote sync."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                operation = await session.get(OperationRecord, operation_id)
                if operation is None or operation.run_id != run_id:
                    raise StateNotFound(
                        "operation_not_found", "operation was not found"
                    )
                if operation.status != "indeterminate":
                    raise StateConflict(
                        "operation_not_indeterminate",
                        "operation is not awaiting reconciliation",
                    )
                operation.status = "completed" if resolved else "failed"
                operation.result_code = result_code
                if not resolved:
                    operation.error_code = result_code or "remote_state_unconfirmed"
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int(
                        (
                            aware(operation.completed_at) - aware(operation.started_at)
                        ).total_seconds()
                        * 1_000
                    ),
                )
                event_type = (
                    "operation_reconciled" if resolved else "operation_reconcile_failed"
                )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    event_type,
                    {
                        "operation_id": operation_id,
                        "resolved": resolved,
                        "result_code": result_code,
                    },
                    agent_id=operation.agent_id,
                )
        return self._operation_dict(operation)

    async def mark_indeterminate_operations(self, run_id: str) -> int:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                operations = (
                    await session.scalars(
                        select(OperationRecord).where(
                            OperationRecord.run_id == run_id,
                            OperationRecord.status == "started",
                        )
                    )
                ).all()
                for operation in operations:
                    operation.status = "indeterminate"
                    operation.completed_at = self.clock()
                    operation.completed_sequence = await self._event(
                        session,
                        run_id,
                        "operation_indeterminate",
                        {"operation_id": operation.operation_id},
                        agent_id=operation.agent_id,
                    )
                return len(operations)

    async def list_operations(
        self,
        run_id: str,
        *,
        agent_id: str | None = None,
        unique_code: str | None = None,
    ) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_run(session, run_id)
            clauses = [OperationRecord.run_id == run_id]
            if agent_id is not None:
                clauses.append(OperationRecord.agent_id == agent_id)
            elif unique_code is not None:
                clauses.append(OperationRecord.unique_code == unique_code)
            rows = (
                await session.scalars(
                    select(OperationRecord)
                    .where(*clauses)
                    .order_by(OperationRecord.started_at, OperationRecord.operation_id)
                )
            ).all()
            return [self._operation_dict(item) for item in rows]

    async def latest_completed_operation(
        self,
        run_id: str,
        *,
        operation_type: str,
        unique_code: str | None = None,
    ) -> dict[str, Any] | None:
        async with self.db.sessions() as session:
            await self._require_run(session, run_id)
            clauses = [
                OperationRecord.run_id == run_id,
                OperationRecord.operation_type == operation_type,
                OperationRecord.status == "completed",
            ]
            if unique_code is not None:
                clauses.append(OperationRecord.unique_code == unique_code)
            row = await session.scalar(
                select(OperationRecord)
                .where(*clauses)
                .order_by(OperationRecord.completed_at.desc())
                .limit(1)
            )
            return self._operation_dict(row) if row is not None else None

    async def latest_control_report(
        self,
        run_id: str,
        *,
        recipient_id: str,
        report_type: str,
    ) -> dict[str, Any] | None:
        """Return the latest persisted control report for one recipient."""

        async with self.db.sessions() as session:
            await self._require_run(session, run_id)
            row = await session.scalar(
                select(ReportRecord)
                .where(
                    ReportRecord.run_id == run_id,
                    ReportRecord.parent_id == recipient_id,
                    ReportRecord.report_type == report_type,
                )
                .order_by(ReportRecord.sequence.desc())
                .limit(1)
            )
            return self._report_dict(row) if row is not None else None

    async def sample_resources(
        self, run_id: str, cpu_percent: float, memory_percent: float
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                record = ResourceSampleRecord(
                    run_id=run_id,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    sampled_at=self.clock(),
                )
                session.add(record)
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "sampled_at": _json_value(record.sampled_at),
        }

    async def project_pending_events(
        self,
        run_id: str,
        *,
        run_dir: Path | None = None,
        limit: int = 100,
        force_checkpoint: bool = False,
    ) -> int:
        target_dir = run_dir or (
            self.run_root / run_id if self.run_root else self.db.path.parent
        )
        target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target_dir, 0o700)
        events_path = target_dir / "events.jsonl"
        async with self._projection_lock:
            projection_sequence = self._projection_sequences.get(run_id)
            async with self.db.sessions() as session:
                run = await self._require_run(session, run_id)
                if projection_sequence is None:
                    valid, file_sequence = await asyncio.to_thread(
                        self._inspect_event_log_sync, events_path, run_id
                    )
                    if not valid or file_sequence != run.last_projected_sequence:
                        all_events = (
                            await session.scalars(
                                select(StateEventRecord)
                                .where(StateEventRecord.run_id == run_id)
                                .order_by(StateEventRecord.sequence)
                            )
                        ).all()
                        await self._write_text_atomic(
                            events_path,
                            "".join(
                                self._encode_state_event(item) for item in all_events
                            ),
                        )
                        projection_sequence = (
                            all_events[-1].sequence if all_events else 0
                        )
                    else:
                        projection_sequence = file_sequence

                pending = (
                    await session.scalars(
                        select(AuditOutboxRecord)
                        .where(AuditOutboxRecord.run_id == run_id)
                        .order_by(AuditOutboxRecord.sequence)
                        .limit(max(1, limit))
                    )
                ).all()
                target_sequence = max(
                    projection_sequence,
                    pending[-1].sequence if pending else projection_sequence,
                )
                new_events = (
                    await session.scalars(
                        select(StateEventRecord)
                        .where(
                            StateEventRecord.run_id == run_id,
                            StateEventRecord.sequence > projection_sequence,
                            StateEventRecord.sequence <= target_sequence,
                        )
                        .order_by(StateEventRecord.sequence)
                    )
                ).all()
                if new_events:
                    expected = projection_sequence + 1
                    if any(
                        item.sequence != expected + index
                        for index, item in enumerate(new_events)
                    ):
                        raise RuntimeError(
                            "state event projection sequence is not continuous"
                        )
                metadata_missing = not all(
                    (target_dir / name).is_file()
                    for name in ("events.jsonl", "checkpoint.json", "manifest.json")
                )
                if (
                    not pending
                    and not new_events
                    and not metadata_missing
                    and not force_checkpoint
                ):
                    self._projection_sequences[run_id] = projection_sequence
                    return 0
            try:
                if new_events:
                    await asyncio.to_thread(
                        self._append_event_lines_sync,
                        events_path,
                        [self._encode_state_event(item) for item in new_events],
                    )
                    projection_sequence = new_events[-1].sequence
                event_only_types = {
                    "tool_call",
                    "tool_result",
                    "assistant_response",
                    "agent_runner_started",
                    "agent_session_failed",
                    "context_compacted",
                    "context_micro_compacted",
                    "context_compaction_skipped",
                    "context_budget_preflight",
                    "context_soft_limit_exceeded",
                    "context_capacity_deferred",
                    "context_budget_actual_over_target",
                    "context_budget_actual_over_limit",
                    "llm_policy_configured",
                    "llm_reasoning_missing",
                    "llm_response_rejected",
                    "controller_session_recovery_scheduled",
                    "controller_session_recovered",
                    "resume_state_sync",
                    "state_correction",
                    "skill_context_restore_failed",
                    "skill_top_k_selected",
                    "skill_discovery_started",
                    "skill_discovery_completed",
                    "skill_discovery_failed",
                    "skill_discovery_fallback",
                    "skill_candidate_presented",
                }
                dirty_agent_ids = {
                    item.agent_id
                    for item in new_events
                    if item.agent_id and item.event_type not in event_only_types
                }
                checkpoint_required = (
                    force_checkpoint
                    or metadata_missing
                    or any(
                        item.event_type not in event_only_types
                        and item.event_type != "memory_updated"
                        for item in new_events
                    )
                )
                async with self.db.sessions() as session:
                    if checkpoint_required:
                        await self._write_checkpoint(session, run_id, target_dir)
                        if force_checkpoint or metadata_missing:
                            await self._write_agent_sidecars(
                                session, run_id, target_dir, None
                            )
                        elif dirty_agent_ids:
                            await self._write_agent_sidecars(
                                session, run_id, target_dir, dirty_agent_ids
                            )
                    elif dirty_agent_ids:
                        await self._write_agent_sidecars(
                            session, run_id, target_dir, dirty_agent_ids
                        )
                await self._confirm_projection(run_id, projection_sequence)
                self._projection_sequences[run_id] = projection_sequence
            except Exception:
                self._projection_sequences.pop(run_id, None)
                if pending:
                    async with self._lock:
                        async with self.db.sessions.begin() as session:
                            await session.execute(
                                update(AuditOutboxRecord)
                                .where(
                                    AuditOutboxRecord.run_id == run_id,
                                    AuditOutboxRecord.sequence.in_(
                                        [item.sequence for item in pending]
                                    ),
                                )
                                .values(
                                    attempts=AuditOutboxRecord.attempts + 1,
                                    last_error="projection_failed",
                                )
                            )
                raise
            return len(pending)

    async def _write_agent_sidecars(
        self,
        session: Any,
        run_id: str,
        target_dir: Path,
        agent_ids: set[str] | None,
    ) -> None:
        """Project only memory/report files for explicitly dirty Agents."""

        if agent_ids is not None and not agent_ids:
            return
        clauses = [AgentRecord.run_id == run_id]
        if agent_ids is not None:
            clauses.append(AgentRecord.agent_id.in_(agent_ids))
        agents = list(
            (
                await session.scalars(
                    select(AgentRecord).where(
                        *clauses,
                    )
                )
            ).all()
        )
        for agent in agents:
            if agent.role == "chief":
                await self._write_text_atomic(
                    target_dir / "session_memory.md", agent.session_memory
                )
                if agent.final_report:
                    await self._write_json_atomic(
                        target_dir / "report.json", agent.final_report
                    )
                continue
            agent_dir = target_dir / "agents" / agent.agent_id
            agent_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(agent_dir, 0o700)
            await self._write_text_atomic(
                agent_dir / "session_memory.md", agent.session_memory
            )
            if agent.final_report:
                await self._write_json_atomic(
                    agent_dir / "report.json", agent.final_report
                )

    async def _confirm_projection(self, run_id: str, sequence: int) -> None:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                run.last_projected_sequence = max(run.last_projected_sequence, sequence)
                await session.execute(
                    delete(AuditOutboxRecord).where(
                        AuditOutboxRecord.run_id == run_id,
                        AuditOutboxRecord.sequence <= sequence,
                    )
                )

    @staticmethod
    def _encode_state_event(item: StateEventRecord) -> str:
        return (
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": item.run_id,
                    "sequence": item.sequence,
                    "event_id": item.event_id.removeprefix("event_"),
                    "timestamp": _json_value(item.created_at),
                    "event_type": item.event_type,
                    "payload": _json_value(item.payload),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )

    @staticmethod
    def _inspect_event_log_sync(path: Path, run_id: str) -> tuple[bool, int]:
        if not path.exists():
            return True, 0
        expected = 1
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.endswith("\n"):
                        return False, expected - 1
                    value = json.loads(line)
                    if (
                        value.get("run_id") != run_id
                        or value.get("sequence") != expected
                    ):
                        return False, expected - 1
                    expected += 1
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False, expected - 1
        return True, expected - 1

    @staticmethod
    def _append_event_lines_sync(path: Path, lines: list[str]) -> None:
        with path.open("a", encoding="utf-8", newline="") as stream:
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)

    async def restore_run(self, run_id: str) -> int:
        """Recovery boundary: unresolved platform operations become indeterminate."""
        return await self.mark_indeterminate_operations(run_id)

    async def _snapshot(
        self, session: Any, challenge: ChallengeRecord
    ) -> dict[str, Any]:
        findings = (
            await session.scalars(
                select(FindingRecord).where(
                    FindingRecord.run_id == challenge.run_id,
                    FindingRecord.unique_code == challenge.unique_code,
                )
            )
        ).all()
        agents = (
            await session.scalars(
                select(AgentRecord).where(
                    AgentRecord.run_id == challenge.run_id,
                    AgentRecord.unique_code == challenge.unique_code,
                )
            )
        ).all()
        projected_agents = []
        for item in agents:
            projected_agents.append({
                **self._agent_dict(item),
                "waiting_sources": await self._waiting_sources(
                    session, challenge.run_id, item.agent_id
                ),
            })
        return {
            "challenge": self._challenge_dict(challenge),
            "findings": [self._finding_dict(item) for item in findings],
            "agents": projected_agents,
        }

    async def _event(
        self,
        session: Any,
        run_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        agent_id: str | None = None,
    ) -> int:
        sequence = await self._next_sequence(session, run_id)
        await self._event_with_sequence(
            session,
            run_id,
            sequence,
            event_type,
            payload,
            agent_id=agent_id,
        )
        return sequence

    async def _event_with_sequence(
        self,
        session: Any,
        run_id: str,
        sequence: int,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        agent_id: str | None = None,
    ) -> None:
        safe_payload = _json_value(redact_value(dict(payload)))
        if agent_id is not None:
            agent = await session.get(AgentRecord, agent_id)
            if agent is not None and agent.run_id == run_id:
                now = self.clock()
                if event_type == "assistant_response" or event_type.startswith("model_"):
                    agent.last_model_activity_at = now
                if event_type in {
                    "tool_call", "tool_result", "shell_task_started",
                    "shell_task_finished", "network_task_status_changed",
                    "http_interaction_status_changed", "worker_reported", "worker_updated",
                }:
                    agent.last_tool_activity_at = now
        session.add(
            StateEventRecord(
                event_id=f"event_{uuid4().hex}",
                run_id=run_id,
                sequence=sequence,
                agent_id=agent_id,
                event_type=event_type,
                payload=safe_payload,
                created_at=self.clock(),
            )
        )
        session.add(AuditOutboxRecord(run_id=run_id, sequence=sequence))

    async def _next_sequence(self, session: Any, run_id: str) -> int:
        # Do not allocate from the ORM object's cached value.  Scheduling and
        # Runner lifecycle events can be committed by different sessions at
        # the same time (the admission controller deliberately runs outside
        # StateService's public mutation lock).  An atomic SQL increment makes
        # SQLite serialize the reservation and returns the sequence belonging
        # to this transaction, keeping state_events and audit_outbox aligned.
        result = await session.execute(
            update(RunRecord)
            .where(RunRecord.run_id == run_id)
            .values(last_sequence=RunRecord.last_sequence + 1)
            .returning(RunRecord.last_sequence)
        )
        sequence = result.scalar_one_or_none()
        if sequence is None:
            raise StateNotFound("run_not_found", "run was not found")
        return int(sequence)

    async def validate_selected_challenges(self, run_id: str) -> None:
        async with self.db.sessions() as session:
            run = await self._require_run(session, run_id)
            if run.selected_challenge_codes is None:
                return
            catalog = set(await session.scalars(
                select(ChallengeRecord.unique_code).where(ChallengeRecord.run_id == run_id)
            ))
            missing = set(run.selected_challenge_codes) - catalog
            if missing:
                raise StateError(
                    "unknown_challenge_codes",
                    "Selected challenges were not found: " + ", ".join(sorted(missing)),
                    status_code=422,
                )

    async def _require_challenge_in_scope(self, session, run_id, unique_code) -> None:
        run = await self._require_run(session, run_id)
        if run.status != "active":
            raise StateConflict("run_inactive", "Run has ended or is paused")
        if run.selected_challenge_codes is not None and unique_code not in run.selected_challenge_codes:
            raise StatePermission("challenge_out_of_scope", "Challenge is outside the selected run scope")

    async def _require_run(self, session: Any, run_id: str) -> RunRecord:
        run = await session.get(RunRecord, run_id)
        if run is None:
            raise StateNotFound("run_not_found", "run was not found")
        return run

    async def _require_challenge(
        self, session: Any, run_id: str, unique_code: str
    ) -> ChallengeRecord:
        challenge = await session.get(ChallengeRecord, (run_id, unique_code))
        if challenge is None:
            raise StateNotFound("challenge_not_found", "challenge was not found")
        self._ensure_evidence_root(challenge)
        self._ensure_evidence_root_dir(challenge)
        return challenge

    async def _authorize(
        self,
        session: Any,
        context: CapabilityContext,
        *,
        run_id: str,
        roles: set[str],
        agent_id: str | None = None,
        unique_code: str | None = None,
    ) -> AgentRecord:
        if context.run_id != run_id:
            raise StatePermission(
                "run_not_accessible", "Capability belongs to another Run"
            )
        if context.role not in roles:
            raise StatePermission(
                "role_not_allowed", "Agent role is not allowed for this operation"
            )
        if agent_id is not None and context.agent_id != agent_id:
            raise StatePermission(
                "agent_mismatch", "capability is not bound to this Agent"
            )
        agent = await session.get(AgentRecord, context.agent_id)
        if agent is None or agent.run_id != context.run_id:
            raise StatePermission(
                "invalid_capability", "capability is not valid for this run"
            )
        if agent.unique_code != context.unique_code:
            raise StatePermission(
                "challenge_binding_required",
                "Capability challenge does not match its Agent",
            )
        if agent.role != context.role:
            raise StatePermission(
                "invalid_capability", "capability role does not match Agent"
            )
        if (
            unique_code is not None
            and agent.role != "chief"
            and agent.unique_code != unique_code
        ):
            raise StatePermission(
                "challenge_binding_required", "Agent is bound to another challenge"
            )
        return agent

    @staticmethod
    def _check_version(
        current: int,
        expected: int,
        *,
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        if current != expected:
            conflict_detail = {"current_version": current}
            if detail:
                conflict_detail.update(detail)
            raise StateConflict(
                "state_conflict",
                "state version is stale",
                conflict_detail,
            )

    def _mark_progress(self, challenge: ChallengeRecord) -> None:
        now = self.clock()
        challenge.last_progress_at = now
        challenge.work_status = "completed" if challenge.is_completed else "active"
        challenge.pause_reason = None
        challenge.stagnation_stage = "normal"
        challenge.version += 1

    @staticmethod
    def _target_fingerprint(challenge: ChallengeRecord) -> str:
        addrs = sorted(str(item) for item in (challenge.container_addr or []))
        raw = json.dumps(addrs, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _ensure_evidence_root(self, challenge: ChallengeRecord) -> str:
        target_fingerprint = self._target_fingerprint(challenge)
        relative = Path(
            ".aion",
            "runs",
            challenge.run_id,
            "challenges",
            challenge.unique_code,
            "evidence",
            target_fingerprint,
        )
        if self.workspace_root is None and self.run_root is not None:
            relative = Path(
                "challenges",
                challenge.unique_code,
                "evidence",
                target_fingerprint,
            )
        if (
            not challenge.evidence_root
            or Path(challenge.evidence_root).name != target_fingerprint
        ):
            challenge.evidence_root = relative.as_posix()
        return challenge.evidence_root

    def _ensure_evidence_root_dir(self, challenge: ChallengeRecord) -> Path | None:
        if self.workspace_root is not None:
            root = self.workspace_root / ".aion" / "runs"
        elif self.run_root is not None:
            root = self.run_root
        else:
            return None
        path = (
            root
            / challenge.run_id
            / "challenges"
            / challenge.unique_code
            / "evidence"
            / self._target_fingerprint(challenge)
        ).resolve()
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in (
            path,
            path.parent,
            path.parent.parent,
            path.parent.parent.parent,
            path.parent.parent.parent.parent,
        ):
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        return path

    async def _record_observation_locked(
        self,
        session: Any,
        run_id: str,
        unique_code: str,
        *,
        category: str,
        fingerprint: str,
        summary: str,
        detail: Mapping[str, Any] | None,
        source: str,
        source_ref: str | None = None,
        confidence: float = 0.5,
        challenge: ChallengeRecord | None = None,
    ) -> tuple[str, bool]:
        if challenge is None:
            challenge = await self._require_challenge(session, run_id, unique_code)
        target = self._target_fingerprint(challenge)
        self._ensure_evidence_root(challenge)
        existing = await session.scalar(
            select(ObservationRecord).where(
                ObservationRecord.run_id == run_id,
                ObservationRecord.unique_code == unique_code,
                ObservationRecord.target_fingerprint == target,
                ObservationRecord.category == category,
                ObservationRecord.fingerprint == fingerprint,
            )
        )
        now = self.clock()
        if existing is not None:
            existing.last_seen_at = now
            existing.confidence = max(existing.confidence, confidence)
            existing.version += 1
            return existing.observation_id, False
        observation_id = f"observation_{uuid4().hex}"
        session.add(
            ObservationRecord(
                observation_id=observation_id,
                run_id=run_id,
                unique_code=unique_code,
                target_fingerprint=target,
                category=category,
                fingerprint=fingerprint,
                summary=summary,
                detail=dict(detail or {}),
                source=source,
                source_ref=source_ref,
                confidence=confidence,
                captured_at=now,
                last_seen_at=now,
            )
        )
        return observation_id, True

    def _validate_evidence_paths(
        self,
        run_id: str,
        unique_code: str,
        paths: Iterable[str],
        *,
        evidence_root_path: Path | None = None,
    ) -> list[str]:
        """Reject evidence paths that escape the challenge evidence directory."""

        normalized: list[str] = []
        evidence_root: Path | None = None
        expected_root = (
            Path(
                ".aion",
                "runs",
                run_id,
                "challenges",
                unique_code,
                "evidence",
            ).as_posix()
            if self.workspace_root is not None
            else Path("challenges", unique_code, "evidence").as_posix()
        )
        if self.workspace_root is not None:
            evidence_root = (
                evidence_root_path
                or (
                    self.workspace_root
                    / ".aion"
                    / "runs"
                    / run_id
                    / "challenges"
                    / unique_code
                    / "evidence"
                ).resolve()
            )
        for raw in paths:
            path = str(raw or "")
            if not path:
                continue
            if "://" in path:
                if self.workspace_root is not None:
                    raise StateError(
                        "invalid_evidence_path",
                        "evidence path must be a file below the exact challenge evidence directory",
                        status_code=422,
                        detail={
                            "received_path": path,
                            "expected_evidence_root": expected_root,
                        },
                    )
                normalized.append(path)
                continue
            value = Path(path)
            if evidence_root is None:
                if value.is_absolute() or ".." in value.parts:
                    raise StateError(
                        "invalid_evidence_path",
                        "evidence path must be inside the challenge evidence directory",
                        status_code=422,
                        detail={
                            "received_path": path,
                            "expected_evidence_root": expected_root,
                        },
                    )
                normalized.append(path)
                continue
            workspace_root = self.workspace_root or self.run_root.parent
            candidate = value if value.is_absolute() else workspace_root / value
            resolved = candidate.resolve()
            if not resolved.is_relative_to(evidence_root):
                raise StateError(
                    "invalid_evidence_path",
                    "evidence path must be inside the exact challenge evidence directory",
                    status_code=422,
                    detail={
                        "received_path": path,
                        "expected_evidence_root": expected_root,
                        "path_kind": "absolute" if value.is_absolute() else "relative",
                    },
                )
            if self.workspace_root is not None:
                normalized.append(resolved.relative_to(self.workspace_root).as_posix())
            else:
                normalized.append(resolved.as_posix())
        return normalized

    async def record_observation(
        self,
        run_id: str,
        unique_code: str,
        *,
        category: str,
        summary: str,
        detail: Mapping[str, Any] | None = None,
        source: str,
        source_ref: str | None = None,
        confidence: float = 0.5,
        mark_progress: bool = False,
    ) -> dict[str, Any]:
        """Persist one deduplicated Observation with its evidence references."""

        fingerprint = _fingerprint(category, summary, detail or {})
        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                observation_id, created = await self._record_observation_locked(
                    session,
                    run_id,
                    unique_code,
                    category=category,
                    fingerprint=fingerprint,
                    summary=summary,
                    detail=detail,
                    source=source,
                    source_ref=source_ref,
                    confidence=confidence,
                    challenge=challenge,
                )
                event_sequence: int | None = None
                if created:
                    if mark_progress and challenge_work_active(challenge):
                        self._mark_progress(challenge)
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "observation_recorded",
                        {
                            "unique_code": unique_code,
                            "observation_id": observation_id,
                            "category": category,
                            "source": source,
                        },
                    )
        if created and event_sequence is not None:
            await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return {
            "observation_id": observation_id,
            "created": created,
            "fingerprint": fingerprint,
        }

    async def list_observations(
        self, run_id: str, unique_code: str
    ) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_challenge(session, run_id, unique_code)
            rows = (
                await session.scalars(
                    select(ObservationRecord)
                    .where(
                        ObservationRecord.run_id == run_id,
                        ObservationRecord.unique_code == unique_code,
                    )
                    .order_by(ObservationRecord.captured_at)
                )
            ).all()
            return [
                {
                    "observation_id": item.observation_id,
                    "unique_code": item.unique_code,
                    "target_fingerprint": item.target_fingerprint,
                    "category": item.category,
                    "summary": item.summary,
                    "detail": item.detail,
                    "source": item.source,
                    "source_ref": item.source_ref,
                    "confidence": item.confidence,
                    "captured_at": _json_value(item.captured_at),
                    "version": item.version,
                }
                for item in rows
            ]

    @staticmethod
    def _challenge_from_import(
        run_id: str, value: ChallengeImport, *, now: datetime | None = None
    ) -> ChallengeRecord:
        record = ChallengeRecord(run_id=run_id, unique_code=value.unique_code)
        StateService._apply_challenge_import(record, value)
        if now is not None:
            record.created_at = now
        return record

    @staticmethod
    def _apply_challenge_import(
        record: ChallengeRecord, value: ChallengeImport
    ) -> None:
        pending_release = (
            container_slot_occupied(record.container_status)
            and record.platform_status == "close_requested"
            and record.work_status in {"paused", "closed", "completed"}
        )
        record.description = value.description
        record.difficulty = value.difficulty
        record.level = value.level
        record.total_score = value.total_score
        record.flag_count = max(int(record.flag_count or 0), int(value.flag_count or 0))
        record.correct_flag_count = max(
            int(record.correct_flag_count or 0),
            int(value.correct_flag_count or 0),
        )
        record.is_completed = bool(record.is_completed or value.is_completed)
        # Do not turn an unresolved close back into an active container merely
        # because the platform still reports it running.  A fresh stopped
        # status below is the only evidence that can free the slot.
        if pending_release and container_slot_occupied(value.container_status):
            record.container_status = "release_pending"
            record.platform_status = "close_requested"
            record.container_addr = value.container_addr
            return
        if record.is_completed:
            record.container_status = value.container_status
            record.platform_status = "completed"
            record.work_status = "completed"
            record.pause_reason = None
        elif value.container_status in {"starting", "running", "active"}:
            record.container_status = (
                "running"
                if value.container_status == "active"
                else value.container_status
            )
            record.platform_status = "started"
            if record.work_status == "unassigned":
                record.work_status = "active"
        else:
            record.container_status = value.container_status
            if (
                value.container_status in RELEASED_CONTAINER_STATUSES
                and record.work_status == "closed"
            ):
                record.platform_status = "closed"
            else:
                record.platform_status = "available"
            if record.work_status == "completed":
                record.work_status = "unassigned"
        record.container_addr = value.container_addr

    @staticmethod
    def _challenge_material_state(record: ChallengeRecord) -> tuple[Any, ...]:
        return (
            record.description,
            record.difficulty,
            record.level,
            record.total_score,
            record.flag_count,
            record.correct_flag_count,
            record.is_completed,
            record.platform_status,
            record.container_status,
            record.work_status,
            tuple(record.container_addr),
        )

    @staticmethod
    def _run_dict(item: RunRecord) -> dict[str, Any]:
        return {
            "run_id": item.run_id,
            "status": item.status,
            "model": item.model,
            "prompt": item.prompt,
            "context_window_tokens": item.context_window_tokens,
            "duration_minutes": item.duration_minutes,
            "started_at": _json_value(item.started_at),
            "deadline_at": _json_value(item.deadline_at),
            "selected_challenge_codes": item.selected_challenge_codes,
            "score_snapshot": item.score_snapshot,
            "last_sequence": item.last_sequence,
            "last_projected_sequence": item.last_projected_sequence,
            "paused_at": _json_value(item.paused_at),
            "pause_reason": item.pause_reason,
        }

    @staticmethod
    def _challenge_dict(
        item: ChallengeRecord,
        *,
        run: RunRecord | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        return {
            "run_id": item.run_id,
            "unique_code": item.unique_code,
            "description": item.description,
            "difficulty": item.difficulty,
            "level": item.level,
            "total_score": item.total_score,
            "flag_count": item.flag_count,
            "correct_flag_count": item.correct_flag_count,
            "is_completed": item.is_completed,
            "platform_status": item.platform_status,
            "container_status": item.container_status,
            "slot_occupied": container_slot_occupied(item.container_status),
            "container_addr": item.container_addr,
            "direction": item.direction,
            "work_status": item.work_status,
            "pause_reason": item.pause_reason,
            "evidence_root": item.evidence_root,
            "hint_requested": item.hint_requested,
            "active_since": _json_value(item.active_since),
            "slot_occupied_seconds": (
                active_seconds(
                    now=now or utc_now(), active_since=item.active_since
                )
                if container_slot_occupied(item.container_status)
                else 0
            ),
            "last_progress_at": _json_value(item.last_progress_at),
            "strategy_revision": item.strategy_revision,
            "stagnation_stage": item.stagnation_stage,
            "last_intervention_at": _json_value(item.last_intervention_at),
            "intervention_count": item.intervention_count,
            "alternate_worker_id": item.alternate_worker_id,
            "version": item.version,
        }

    @staticmethod
    def _agent_dict(
        item: AgentRecord, *, include_runtime: bool = False
    ) -> dict[str, Any]:
        fields = (
            "agent_id",
            "run_id",
            "parent_id",
            "unique_code",
            "role",
            "mode",
            "priority",
            "mission",
            "success_criteria",
            "context_refs",
            "task_key",
            "task_digest",
            "terminal_report_id",
            "status",
            "timeout_seconds",
            "last_heartbeat_at",
            "last_model_activity_at",
            "last_tool_activity_at",
            "last_report_sequence",
            "report_cursor",
            "pending_delivery",
            "controller_cursor",
            "last_summarized_sequence",
            "active_skills",
            "started_at",
            "ended_at",
            "stop_requested_at",
            "updated_at",
            "version",
            "resource_generation",
        )
        data = {field: _json_value(getattr(item, field)) for field in fields}
        if include_runtime:
            data.update(
                initial_prompt=item.initial_prompt,
                session_memory=item.session_memory,
                final_report=item.final_report,
                resource_processes=item.resource_processes,
            )
        return data

    @staticmethod
    async def _waiting_sources(session: Any, run_id: str, agent_id: str) -> list[dict[str, Any]]:
        """Return durable producers that can wake one Solver."""
        sources: list[dict[str, Any]] = []
        workers = (await session.scalars(select(AgentRecord).where(
            AgentRecord.run_id == run_id,
            AgentRecord.parent_id == agent_id,
            AgentRecord.role.in_(("worker", "solver")),
            AgentRecord.status.in_(("queued", "pending", "running", "starting", "working", "waiting")),
        ).order_by(AgentRecord.created_at, AgentRecord.agent_id))).all()
        sources.extend({"kind": row.role, "id": row.agent_id, "status": row.status} for row in workers)
        shells = (await session.scalars(select(ShellTaskRecord).where(
            ShellTaskRecord.run_id == run_id,
            ShellTaskRecord.agent_id == agent_id,
            ShellTaskRecord.status == "running",
        ).order_by(ShellTaskRecord.created_at, ShellTaskRecord.task_id))).all()
        sources.extend({"kind": "shell", "id": row.task_id, "status": row.status} for row in shells)
        networks = (await session.scalars(select(NetworkTaskRecord).where(
            NetworkTaskRecord.run_id == run_id,
            NetworkTaskRecord.agent_id == agent_id,
            NetworkTaskRecord.status.in_(("queued", "running", "waiting")),
        ).order_by(NetworkTaskRecord.created_at, NetworkTaskRecord.task_id))).all()
        sources.extend({"kind": "network", "id": row.task_id, "status": row.status} for row in networks)
        interactions = (await session.scalars(select(HttpInteractionRecord).where(
            HttpInteractionRecord.run_id == run_id,
            HttpInteractionRecord.agent_id == agent_id,
            or_(
                HttpInteractionRecord.execution_status.in_(("queued", "running", "waiting")),
                HttpInteractionRecord.analysis_status.in_(("queued", "running")),
            ),
        ).order_by(HttpInteractionRecord.created_at, HttpInteractionRecord.interaction_id))).all()
        sources.extend({
            "kind": "http", "id": row.interaction_id,
            "status": row.execution_status, "analysis_status": row.analysis_status,
        } for row in interactions)
        return sources

    @staticmethod
    def _finding_dict(item: FindingRecord) -> dict[str, Any]:
        return {
            "finding_id": item.finding_id,
            "finding_ref": f"finding:{item.finding_id}",
            "unique_code": item.unique_code,
            "category": item.category,
            "fingerprint": item.fingerprint,
            "summary": item.summary,
            "detail": item.detail,
            "confidence": item.confidence,
            "verification_status": item.verification_status,
            "evidence_refs": list((item.detail or {}).get("evidence_refs", [])),
        }

    @staticmethod
    def _controller_finding_dict(item: FindingRecord) -> dict[str, Any]:
        return {
            "finding_ref": f"finding:{item.finding_id}",
            "category": item.category,
            "summary": _controller_text(item.summary, CONTROLLER_SUMMARY_CHARS),
            "confidence": item.confidence,
            "verification_status": item.verification_status,
            "evidence_refs": _controller_refs((item.detail or {}).get("evidence_refs")),
        }

    @staticmethod
    def _credential_dict(
        item: CredentialRecord, *, include_secret: bool
    ) -> dict[str, Any]:
        data = {
            "credential_id": item.credential_id,
            "unique_code": item.unique_code,
            "finding_id": item.finding_id,
            "kind": item.kind,
            "principal": item.principal,
            "scope": item.scope,
            "verified": item.verified,
        }
        if include_secret:
            data["secret_value"] = item.secret_value
        return data

    @staticmethod
    def _report_dict(
        item: ReportRecord,
    ) -> dict[str, Any]:
        return {
            "report_id": item.report_id,
            "report_ref": f"report:{item.report_id}",
            "sequence": item.sequence,
            "agent_id": item.agent_id,
            "parent_id": item.parent_id,
            "unique_code": item.unique_code,
            "report_type": item.report_type,
            "status": item.status,
            "payload": item.payload,
            "created_at": _json_value(item.created_at),
        }

    @staticmethod
    def _controller_report_projection(item: Mapping[str, Any]) -> dict[str, Any]:
        return dict(item)

    @staticmethod
    def _operation_dict(item: OperationRecord) -> dict[str, Any]:
        return {
            "operation_id": item.operation_id,
            "run_id": item.run_id,
            "agent_id": item.agent_id,
            "unique_code": item.unique_code,
            "operation_type": item.operation_type,
            "arguments_fingerprint": item.arguments_fingerprint,
            "status": item.status,
            "request_payload": item.request_payload,
            "result_payload": item.result_payload,
            "result_code": item.result_code,
            "error_code": item.error_code,
            "error_message": item.error_message,
            "started_sequence": item.started_sequence,
            "completed_sequence": item.completed_sequence,
            "duration_ms": item.duration_ms,
            "started_at": _json_value(item.started_at),
            "completed_at": _json_value(item.completed_at),
        }

    @staticmethod
    def _shell_task_dict(item: ShellTaskRecord) -> dict[str, Any]:
        return {
            "task_id": item.task_id,
            "run_id": item.run_id,
            "agent_id": item.agent_id,
            "status": item.status,
            "pid": item.pid,
            "process_started_at": item.process_started_at,
            "cwd": item.cwd,
            "temp_dir": item.temp_dir,
            "output_path": item.output_path,
            "capture_limit": item.capture_limit,
            "output_chars": item.output_chars,
            "exit_code": item.exit_code,
            "timed_out": item.timed_out,
            "truncated": item.truncated,
            "started_at": _json_value(item.started_at),
            "finished_at": _json_value(item.finished_at),
            "expires_at": _json_value(item.expires_at),
            "output_cleaned_at": _json_value(item.output_cleaned_at),
            "cleanup_reason": item.cleanup_reason,
        }

    @staticmethod
    def _network_task_dict(item: NetworkTaskRecord) -> dict[str, Any]:
        return {
            "task_id": item.task_id,
            "run_id": item.run_id,
            "agent_id": item.agent_id,
            "status": item.status,
            "resource_status": item.resource_status,
            "scan_intent": item.scan_intent,
            "result_path": item.result_path,
            "pid": item.pid,
            "process_started_at": item.process_started_at,
            "scanner_version": item.scanner_version,
            "bridge_protocol_version": item.bridge_protocol_version,
            "estimated_hosts": item.estimated_hosts,
            "estimated_ports": item.estimated_ports,
            "estimated_requests": item.estimated_requests,
            "requested_concurrency": item.requested_concurrency,
            "priority": item.priority,
            "tasks_total": item.tasks_total,
            "tasks_completed": item.tasks_completed,
            "result_count": item.result_count,
            "result_bytes": item.result_bytes,
            "hosts_alive": item.hosts_alive,
            "open_ports": item.open_ports,
            "services": item.services,
            "web_ports": item.web_ports,
            "exit_code": item.exit_code,
            "error_code": item.error_code,
            "started_at": _json_value(item.started_at),
            "finished_at": _json_value(item.finished_at),
            "output_cleaned_at": _json_value(item.output_cleaned_at),
            "cleanup_reason": item.cleanup_reason,
            "created_at": _json_value(item.created_at),
            "updated_at": _json_value(item.updated_at),
        }

    @staticmethod
    def _http_interaction_dict(item: HttpInteractionRecord) -> dict[str, Any]:
        return {
            "interaction_id": item.interaction_id,
            "run_id": item.run_id,
            "agent_id": item.agent_id,
            "kind": item.kind,
            "status": item.status,
            "execution_status": item.execution_status,
            "analysis_status": item.analysis_status,
            "resource_status": item.resource_status,
            "result_path": item.result_path,
            "estimated_requests": item.estimated_requests,
            "requested_concurrency": item.requested_concurrency,
            "estimated_disk_bytes": item.estimated_disk_bytes,
            "estimated_memory_bytes": item.estimated_memory_bytes,
            "estimated_analysis_work": item.estimated_analysis_work,
            "priority": item.priority,
            "started_requests": item.started_requests,
            "completed_requests": item.completed_requests,
            "response_bytes": item.response_bytes,
            "analyzed_responses": item.analyzed_responses,
            "error_code": item.error_code,
            "started_at": _json_value(item.started_at),
            "execution_finished_at": _json_value(item.execution_finished_at),
            "analysis_finished_at": _json_value(item.analysis_finished_at),
            "output_cleaned_at": _json_value(item.output_cleaned_at),
            "cleanup_reason": item.cleanup_reason,
            "created_at": _json_value(item.created_at),
            "updated_at": _json_value(item.updated_at),
        }

    @staticmethod
    def _resource_work_dict(item: ResourceWorkRecord) -> dict[str, Any]:
        return {
            "work_id": item.work_id,
            "run_id": item.run_id,
            "agent_id": item.agent_id,
            "owner_type": item.owner_type,
            "owner_id": item.owner_id,
            "phase": item.phase,
            "status": item.status,
            "priority": item.priority,
            "requested_concurrency": item.requested_concurrency,
            "estimated_requests": item.estimated_requests,
            "estimated_disk_bytes": item.estimated_disk_bytes,
            "estimated_memory_bytes": item.estimated_memory_bytes,
            "reason": item.reason,
            "retry_at": _json_value(item.retry_at),
            "reserved_at": _json_value(item.reserved_at),
            "started_at": _json_value(item.started_at),
            "finished_at": _json_value(item.finished_at),
            "queue_latency_ms": (
                int(
                    max(
                        0.0,
                        (
                            aware(item.reserved_at or item.started_at)
                            - aware(item.created_at)
                        ).total_seconds(),
                    )
                    * 1_000
                )
                if (item.reserved_at or item.started_at) is not None
                else None
            ),
            "created_at": _json_value(item.created_at),
            "updated_at": _json_value(item.updated_at),
        }

    def _apply_operation_challenge_updates(
        self,
        challenge: ChallengeRecord,
        updates: Mapping[str, Any],
    ) -> str | None:
        previous_completed = challenge.is_completed
        previous_correct_count = challenge.correct_flag_count
        previous_container_status = challenge.container_status
        work_status = updates.get("work_status")
        if work_status is not None and work_status not in CHALLENGE_WORK_STATUS_VALUES:
            raise StateError(
                "invalid_challenge_work_status",
                "Challenge work status is invalid",
                status_code=422,
            )
        for field in (
            "platform_status",
            "container_status",
            "work_status",
            "hint_requested",
            "flag_count",
            "correct_flag_count",
            "is_completed",
        ):
            if field in updates:
                setattr(challenge, field, updates[field])
        if "container_addr" in updates:
            challenge.container_addr = list(updates["container_addr"] or [])
        if challenge.container_status in {"stopped", "closed"}:
            challenge.active_since = None
            challenge.active_since = None
            challenge.paused_at = self.clock()
        elif container_slot_occupied(
            challenge.container_status
        ) and not container_slot_occupied(previous_container_status):
            now = self.clock()
            challenge.started_at = challenge.started_at or now
            challenge.active_since = now
            challenge.last_progress_at = challenge.last_progress_at or now
            challenge.paused_at = None
        challenge.version += 1
        if updates.get("progress_kind"):
            return str(updates["progress_kind"])
        if challenge.is_completed and not previous_completed:
            return "remote_completion"
        if challenge.correct_flag_count > previous_correct_count:
            return "flag_accepted"
        return None

    async def _write_checkpoint(
        self, session: Any, run_id: str, target_dir: Path
    ) -> None:
        run = await self._require_run(session, run_id)
        challenges = (
            await session.scalars(
                select(ChallengeRecord).where(ChallengeRecord.run_id == run_id)
            )
        ).all()
        agents = (
            await session.scalars(
                select(AgentRecord).where(AgentRecord.run_id == run_id)
            )
        ).all()
        targets = [
            TargetState(
                unique_code=item.unique_code,
                status=checkpoint_target_status(self._challenge_dict(item)),
                is_completed=item.is_completed,
                work_status=item.work_status,
                container_status=item.container_status,
                slot_occupied=container_slot_occupied(item.container_status),
                container_addr=item.container_addr,
                score_snapshot={
                    "correct_flag_count": item.correct_flag_count,
                    "flag_count": item.flag_count,
                    "total_score": item.total_score,
                },
                last_event_sequence=run.last_sequence,
            ).model_dump(mode="json")
            for item in challenges
        ]
        agent_nodes = []
        for item in agents:
            node = AgentNode(
                agent_id=item.agent_id,
                role=item.role,  # type: ignore[arg-type]
                mode=item.mode,
                parent_id=item.parent_id,
                unique_code=item.unique_code,
                status=item.status,  # type: ignore[arg-type]
                sidecar_path=str(target_dir / "agents" / item.agent_id),
                mission=item.mission,
                timeout_seconds=item.timeout_seconds,
                report_count=1 if item.last_report_sequence else 0,
                last_report_sequence=item.last_report_sequence,
                started_at=aware(item.started_at or self.clock()),
                updated_at=aware(item.updated_at or self.clock()),
                last_heartbeat_at=aware(item.last_heartbeat_at) if item.last_heartbeat_at else None,
                last_model_activity_at=aware(item.last_model_activity_at) if item.last_model_activity_at else None,
                last_tool_activity_at=aware(item.last_tool_activity_at) if item.last_tool_activity_at else None,
                waiting_sources=await self._waiting_sources(session, run_id, item.agent_id),
            )
            agent_nodes.append(node.model_dump(mode="json"))
        checkpoint = Checkpoint(
            run_id=run_id,
            status=run.status,  # type: ignore[arg-type]
            targets=[TargetState.model_validate(item) for item in targets],
            container_capacity=container_capacity_summary(
                [self._challenge_dict(item) for item in challenges]
            ),
            score_snapshot=run.score_snapshot,
            last_event_sequence=run.last_sequence,
            agents=[AgentNode.model_validate(item) for item in agent_nodes],
            updated_at=aware(self.clock()),
        ).model_dump(mode="json")
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "model": run.model or "unknown",
            "selected_challenge_codes": run.selected_challenge_codes,
            "context_window_tokens": run.context_window_tokens,
            "prompt": run.prompt or "",
            "role": "chief",
            "parent_id": None,
            "unique_code": None,
            "status": run.status,
            "started_at": _json_value(run.started_at),
            "updated_at": _json_value(run.updated_at),
        }
        await self._write_json_atomic(target_dir / "checkpoint.json", checkpoint)
        await self._write_json_atomic(target_dir / "manifest.json", manifest)

    @staticmethod
    async def _write_json_atomic(path: Path, value: Any) -> None:
        await StateService._write_text_atomic(
            path,
            json.dumps(value, ensure_ascii=False, indent=2, default=str),
        )

    @staticmethod
    async def _write_text_atomic(path: Path, value: str) -> None:
        temp = path.with_name(path.name + ".tmp")
        await asyncio.to_thread(temp.write_text, value, "utf-8")
        await asyncio.to_thread(os.chmod, temp, 0o600)
        await asyncio.to_thread(os.replace, temp, path)
