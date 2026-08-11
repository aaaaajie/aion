"""Transactional authoritative state service for one benchmark run."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, func, select, update

from agent.memory.models import AgentNode, Checkpoint, TargetState
from agent.memory.redaction import redact_value
from .capabilities import fingerprint_secret
from .clock import active_seconds, aware, utc_now
from .database import StateDatabase
from .errors import StateConflict, StateError, StateNotFound, StatePermission
from .models import (
    AdmissionRecord,
    AgentRecord,
    AuditOutboxRecord,
    ChallengeRecord,
    CredentialRecord,
    CycleRecord,
    DEFAULT_SESSION_MEMORY,
    ExecutionBranchRecord,
    FindingRecord,
    HttpInteractionRecord,
    HypothesisRecord,
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
    challenge_work_active,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .routing import routes_for_observation
from .schemas import (
    AgentProgressInput,
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    CHALLENGE_CONTROL_STATE_VALUES,
    CHALLENGE_WORK_STATUS_VALUES,
    ChallengeImport,
    ChallengeSyncResult,
    CreateCycleInput,
    FindingInput,
    StagnationExtensionInput,
    VerificationUpdateInput,
)
from .wakeup import StateSignalBus


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
        {"category": category, "summary": " ".join(summary.lower().split()), "detail": detail},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def derive_phase(started_at: datetime, deadline_at: datetime, now: datetime | None = None) -> str:
    """Derive early/mid/late from the persisted deadline.

    Late has priority when short runs make the 70% boundary overlap with the
    last-30-minute boundary.
    """

    current = aware(now or utc_now())
    start = aware(started_at)
    deadline = aware(deadline_at)
    remaining = (deadline - current).total_seconds()
    duration = max(1.0, (deadline - start).total_seconds())
    used = max(0.0, (current - start).total_seconds())
    if remaining <= 30 * 60:
        return "late"
    if used < duration * 0.70:
        return "early"
    return "mid"


# Hint is deliberately a scarce, time-sensitive action.  These values are
# policy constants rather than business configuration so every caller uses
# the same admission window.
HINT_STAGNATION_PAUSE_SECONDS = 15 * 60
HINT_MIN_ACTION_WINDOW_SECONDS = 5 * 60
HINT_NEAR_DEADLINE_SECONDS = 30 * 60
HINT_ACTIVE_STATUSES = frozenset({"queued", "reserved", "running", "analyzing"})
HINT_TERMINAL_AGENT_STATES = frozenset(
    {"completed", "failed", "stopped", "cancelled", "interrupted"}
)


class StateService:
    """All domain mutations for a run go through this service."""

    def __init__(
        self,
        database: StateDatabase | Path | str,
        *,
        run_root: Path | None = None,
        clock: Callable[[], datetime] = utc_now,
        notifier: StateSignalBus | None = None,
    ) -> None:
        self.db = database if isinstance(database, StateDatabase) else StateDatabase(Path(database))
        self.run_root = run_root
        self.clock = clock
        self.notifier = notifier or StateSignalBus()
        self._lock = asyncio.Lock()
        self._projection_lock = asyncio.Lock()
        self._projection_sequences: dict[str, int] = {}
        self._ephemeral_reports: dict[str, str] = {}

    async def initialize(self) -> None:
        await self.db.initialize()

    async def close(self) -> None:
        await self.db.close()

    def ephemeral_secrets(self) -> tuple[str, ...]:
        return tuple(self._ephemeral_reports.values())

    def forget_ephemeral_secret(self, value: str) -> None:
        for report_id, candidate in list(self._ephemeral_reports.items()):
            if candidate == value:
                self._ephemeral_reports.pop(report_id, None)

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
                                    (AgentRecord.role == "challenge")
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
        challenges: Iterable[ChallengeImport | Mapping[str, Any]] = (),
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        if not run_id or len(run_id) > 128:
            raise StateError("invalid_run_id", "run_id is invalid", status_code=422)
        if duration_minutes < 1:
            raise StateError("invalid_duration", "duration_minutes must be positive", status_code=422)
        await self.initialize()
        start = aware(started_at or self.clock())
        deadline = start + timedelta(minutes=duration_minutes)
        challenge_values = [item if isinstance(item, ChallengeImport) else ChallengeImport.model_validate(item) for item in challenges]
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if await session.get(RunRecord, run_id) is not None:
                    raise StateConflict("run_exists", "run_id already exists")
                run = RunRecord(
                    run_id=run_id,
                    model=model,
                    prompt=prompt,
                    context_window_tokens=context_window_tokens,
                    duration_minutes=duration_minutes,
                    started_at=start,
                    deadline_at=deadline,
                    phase=derive_phase(start, deadline, start),
                )
                session.add(run)
                await session.flush()
                for challenge in challenge_values:
                    session.add(self._challenge_from_import(run_id, challenge, now=start))
                await self._event(session, run_id, "run_created", {
                    "duration_minutes": duration_minutes,
                    "challenge_count": len(challenge_values),
                })
        return await self.get_overview(run_id)

    async def import_challenges(
        self,
        run_id: str,
        challenges: Iterable[ChallengeImport | Mapping[str, Any]],
    ) -> ChallengeSyncResult:
        await self.initialize()
        values = [item if isinstance(item, ChallengeImport) else ChallengeImport.model_validate(item) for item in challenges]
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
                    existing = await session.get(ChallengeRecord, (run_id, challenge.unique_code))
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
                            self._freeze_exploration(existing)
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
            await self.signal_challenge_changes(
                run_id, changed_codes, event_sequence
            )
        return ChallengeSyncResult(
            challenges=current,
            changed_codes=sorted(changed_codes),
            capacity_changed=capacity_changed,
            event_sequence=event_sequence,
        )

    async def get_overview(self, run_id: str) -> dict[str, Any]:
        async with self.db.sessions() as session:
            run = await self._require_run(session, run_id)
            challenges = (await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id).order_by(ChallengeRecord.unique_code))).all()
            agents = (await session.scalars(select(AgentRecord).where(AgentRecord.run_id == run_id).order_by(AgentRecord.created_at))).all()
            challenge_values = [self._challenge_dict(item) for item in challenges]
            return {
                "run": self._run_dict(run),
                "challenges": challenge_values,
                "container_capacity": container_capacity_summary(challenge_values),
                "agents": [self._agent_dict(item) for item in agents],
            }

    async def list_challenges(self, run_id: str) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_run(session, run_id)
            rows = (await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id).order_by(ChallengeRecord.unique_code))).all()
            return [self._challenge_dict(item) for item in rows]

    async def get_challenge_context(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext | None = None,
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            challenge = await self._require_challenge(session, run_id, unique_code)
            if context is not None:
                agent = await self._authorize(session, context, roles={"chief", "challenge", "execution"}, unique_code=unique_code)
                if agent.role == "chief":
                    credentials: list[dict[str, Any]] = []
                else:
                    credentials_rows = (await session.scalars(select(CredentialRecord).where(CredentialRecord.run_id == run_id, CredentialRecord.unique_code == unique_code))).all()
                    credentials = [self._credential_dict(item, include_secret=True) for item in credentials_rows]
            else:
                credentials = []
            findings = (await session.scalars(select(FindingRecord).where(FindingRecord.run_id == run_id, FindingRecord.unique_code == unique_code).order_by(FindingRecord.first_seen_at))).all()
            task_rows = list(
                (
                    await session.scalars(
                        select(AgentRecord)
                        .where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == unique_code,
                            AgentRecord.role == "execution",
                        )
                        .order_by(AgentRecord.created_at.desc())
                        .limit(50)
                    )
                ).all()
            )
            cycle_rows = list(
                (
                    await session.scalars(
                        select(CycleRecord)
                        .where(
                            CycleRecord.run_id == run_id,
                            CycleRecord.unique_code == unique_code,
                        )
                        .order_by(CycleRecord.cycle_number.desc())
                        .limit(10)
                    )
                ).all()
            )
            observation_rows = list(
                (
                    await session.scalars(
                        select(ObservationRecord)
                        .where(
                            ObservationRecord.run_id == run_id,
                            ObservationRecord.unique_code == unique_code,
                        )
                        .order_by(ObservationRecord.captured_at.desc())
                        .limit(100)
                    )
                ).all()
            )
            hypothesis_rows = list(
                (
                    await session.scalars(
                        select(HypothesisRecord)
                        .where(
                            HypothesisRecord.run_id == run_id,
                            HypothesisRecord.unique_code == unique_code,
                        )
                        .order_by(HypothesisRecord.updated_at.desc())
                        .limit(50)
                    )
                ).all()
            )
            branch_rows = list(
                (
                    await session.scalars(
                        select(ExecutionBranchRecord)
                        .where(
                            ExecutionBranchRecord.run_id == run_id,
                            ExecutionBranchRecord.unique_code == unique_code,
                        )
                        .order_by(ExecutionBranchRecord.priority.desc())
                        .limit(50)
                    )
                ).all()
            )
            return {
                "challenge": self._challenge_dict(challenge),
                "findings": [self._finding_dict(item) for item in findings],
                "credentials": credentials,
                "observations": [
                    {
                        "observation_id": item.observation_id,
                        "category": item.category,
                        "summary": item.summary,
                        "detail": item.detail,
                        "source": item.source,
                        "confidence": item.confidence,
                        "captured_at": _json_value(item.captured_at),
                    }
                    for item in observation_rows
                ],
                "hypotheses": [
                    {
                        "hypothesis_key": item.hypothesis_key,
                        "statement": item.statement,
                        "confidence": item.confidence,
                        "based_on_observations": item.based_on_observations,
                        "status": item.status,
                    }
                    for item in hypothesis_rows
                ],
                "branches": [
                    {
                        "branch_key": item.branch_key,
                        "hypothesis_key": item.hypothesis_key,
                        "kind": item.kind,
                        "status": item.status,
                        "priority": item.priority,
                        "mission": item.mission,
                        "agent_ids": item.agent_ids,
                    }
                    for item in branch_rows
                ],
                "recent_cycles": [self._cycle_dict(item) for item in cycle_rows],
                "task_ledger": [
                    {
                        "agent_id": item.agent_id,
                        "hypothesis_key": item.hypothesis_key,
                        "task_key": item.task_key,
                        "branch_key": item.branch_key,
                        "kind": item.kind,
                        "mission": item.mission,
                        "status": item.status,
                        "context_refs": item.context_refs,
                        "terminal_report_id": item.terminal_report_id,
                        "report_summary": (
                            item.final_report.get("summary")
                            if isinstance(item.final_report, Mapping)
                            else None
                        ),
                        "evidence_paths": (
                            list(item.final_report.get("evidence_paths") or [])
                            if isinstance(item.final_report, Mapping)
                            else []
                        ),
                    }
                    for item in task_rows
                ],
                "active_agents": [
                    self._agent_dict(item)
                    for item in (
                        await session.scalars(
                            select(AgentRecord).where(
                                AgentRecord.run_id == run_id,
                                AgentRecord.unique_code == unique_code,
                                AgentRecord.status.in_(
                                    ["pending", "queued", "starting", "running", "working"]
                                ),
                            )
                        )
                    ).all()
                ],
            }

    async def register_agent(
        self,
        run_id: str,
        *,
        agent_id: str | None = None,
        role: str,
        parent_id: str | None = None,
        unique_code: str | None = None,
        cycle_id: str | None = None,
        kind: str = "general",
        priority: int = 50,
        mission: str = "",
        initial_prompt: str | None = None,
        success_criteria: list[str] | None = None,
        context_refs: list[str] | None = None,
        hypothesis_key: str | None = None,
        task_key: str | None = None,
        branch_key: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        if role not in {"chief", "challenge", "execution"}:
            raise StateError("invalid_role", "unknown Agent role", status_code=422)
        agent_id = agent_id or f"{role}_{uuid4().hex}"
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                if await session.get(AgentRecord, agent_id) is not None:
                    raise StateConflict("agent_exists", "agent_id already exists")
                if role == "chief" and parent_id is not None:
                    raise StatePermission("invalid_parent", "Chief Agent cannot have a parent")
                if role != "chief":
                    if not parent_id:
                        raise StatePermission("parent_required", "non-Chief Agent requires a parent")
                    parent = await session.get(AgentRecord, parent_id)
                    if parent is None or parent.run_id != run_id:
                        raise StateNotFound("parent_not_found", "parent Agent was not found")
                    expected_parent = "chief" if role == "challenge" else "challenge"
                    if parent.role != expected_parent:
                        raise StatePermission("invalid_parent_role", "parent role is not allowed")
                    if role == "execution" and (not unique_code or parent.unique_code != unique_code):
                        raise StatePermission("challenge_binding_required", "Execution Agent must remain bound to its parent challenge")
                if role == "execution":
                    if not hypothesis_key or not task_key:
                        raise StateError(
                            "execution_task_keys_required",
                            "Execution Agents require hypothesis_key and task_key",
                            status_code=422,
                        )
                    duplicate = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == unique_code,
                            AgentRecord.task_key == task_key,
                        )
                    )
                    if duplicate is not None:
                        data = self._agent_dict(duplicate)
                        data["duplicate"] = True
                        data["final_report"] = duplicate.final_report
                        return data
                    resolved_branch_key = branch_key or (
                        f"{hypothesis_key}:{kind}" if hypothesis_key else None
                    )
                    await self._validate_hypothesis_admission(
                        session,
                        run_id=run_id,
                        unique_code=str(unique_code),
                        hypothesis_key=hypothesis_key,
                        context_refs=context_refs or [],
                    )
                    await self._validate_branch_admission(
                        session,
                        run_id=run_id,
                        unique_code=str(unique_code),
                        hypothesis_key=hypothesis_key,
                        branch_key=resolved_branch_key,
                        task_key=task_key,
                        context_refs=context_refs or [],
                    )
                    await self._upsert_branch(
                        session,
                        run_id=run_id,
                        unique_code=str(unique_code),
                        branch_key=resolved_branch_key,
                        hypothesis_key=hypothesis_key,
                        kind=kind,
                        priority=priority,
                        mission=mission,
                        agent_id=agent_id,
                        status="queued",
                    )
                if unique_code is not None:
                    await self._require_challenge(session, run_id, unique_code)
                if role == "challenge" and unique_code is not None:
                    existing_challenge_agent = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == unique_code,
                            AgentRecord.role == "challenge",
                            AgentRecord.status.not_in(["failed", "stopped", "completed"]),
                        )
                    )
                    if existing_challenge_agent is not None:
                        raise StateConflict("challenge_agent_exists", "only one Challenge Agent may own a challenge")
                record = AgentRecord(
                    agent_id=agent_id,
                    run_id=run_id,
                    parent_id=parent_id,
                    unique_code=unique_code,
                    cycle_id=cycle_id,
                    role=role,
                    kind=kind,
                    priority=priority,
                    mission=mission,
                    initial_prompt=initial_prompt if initial_prompt is not None else mission,
                    session_memory=DEFAULT_SESSION_MEMORY,
                    success_criteria=success_criteria or [],
                    context_refs=context_refs or [],
                    hypothesis_key=hypothesis_key,
                    task_key=task_key,
                    branch_key=resolved_branch_key if role == "execution" else None,
                    timeout_seconds=timeout_seconds,
                )
                session.add(record)
                await self._event(session, run_id, "agent_created", {
                    "agent_id": agent_id, "role": role, "parent_id": parent_id,
                    "unique_code": unique_code, "cycle_id": cycle_id,
                }, agent_id=agent_id, cycle_id=cycle_id)
        return self._agent_dict(record)

    async def _validate_hypothesis_admission(
        self,
        session: Any,
        *,
        run_id: str,
        unique_code: str,
        hypothesis_key: str,
        context_refs: list[str],
    ) -> None:
        prior = list(
            (
                await session.scalars(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "execution",
                        AgentRecord.hypothesis_key == hypothesis_key,
                    )
                )
            ).all()
        )
        active = next(
            (
                item
                for item in prior
                if item.status
                not in {"completed", "failed", "stopped", "cancelled", "interrupted"}
            ),
            None,
        )
        if active is not None:
            raise StateConflict(
                "hypothesis_already_active",
                "Only one active task is allowed for a hypothesis",
                {"agent_id": active.agent_id, "task_key": active.task_key},
            )
        if not prior:
            return
        valid_reference = False
        for reference in context_refs:
            kind, separator, identifier = reference.partition(":")
            if (
                not separator
                or kind not in {"report", "finding", "observation"}
                or not identifier
            ):
                continue
            if kind == "report":
                row = await session.get(ReportRecord, identifier)
                source_agent = (
                    await session.get(AgentRecord, row.agent_id)
                    if row is not None
                    else None
                )
                valid_reference = bool(
                    row
                    and row.run_id == run_id
                    and row.unique_code == unique_code
                    and source_agent is not None
                    and source_agent.hypothesis_key == hypothesis_key
                )
            elif kind == "finding":
                row = await session.get(FindingRecord, identifier)
                valid_reference = bool(
                    row
                    and row.run_id == run_id
                    and row.unique_code == unique_code
                )
            elif kind == "observation":
                row = await session.get(ObservationRecord, identifier)
                valid_reference = bool(
                    row
                    and row.run_id == run_id
                    and row.unique_code == unique_code
                )
            if valid_reference:
                break
        if not valid_reference:
            raise StateConflict(
                "hypothesis_novelty_reference_required",
                "A later task for the same hypothesis must reference a prior report or finding",
            )

    async def _validate_branch_admission(
        self,
        session: Any,
        *,
        run_id: str,
        unique_code: str,
        hypothesis_key: str,
        branch_key: str | None,
        task_key: str,
        context_refs: list[str],
    ) -> None:
        """Shared preconditions for creating one Execution Branch task."""

        run = await self._require_run(session, run_id)
        if run.status != "active":
            raise StateConflict(
                "run_not_active", "Execution tasks require an active Run"
            )
        challenge = await self._require_challenge(session, run_id, unique_code)
        if challenge.is_completed or challenge.work_status in {"paused", "closed"}:
            raise StateConflict(
                "challenge_not_active",
                "The challenge no longer accepts execution tasks",
            )
        if branch_key:
            active_branch = await session.scalar(
                select(ExecutionBranchRecord).where(
                    ExecutionBranchRecord.run_id == run_id,
                    ExecutionBranchRecord.unique_code == unique_code,
                    ExecutionBranchRecord.branch_key == branch_key,
                    ExecutionBranchRecord.status.in_(
                        ["proposed", "queued", "running"]
                    ),
                )
            )
            if active_branch is not None:
                raise StateConflict(
                    "branch_already_active",
                    "Only one active branch is allowed for this capability key",
                    {"branch_key": branch_key},
                )
        duplicate_task = await session.scalar(
            select(AgentRecord).where(
                AgentRecord.run_id == run_id,
                AgentRecord.unique_code == unique_code,
                AgentRecord.task_key == task_key,
            )
        )
        if duplicate_task is not None:
            raise StateConflict(
                "duplicate_task_key",
                "The task key already exists",
                {"agent_id": duplicate_task.agent_id, "status": duplicate_task.status},
            )
        await self._validate_hypothesis_admission(
            session,
            run_id=run_id,
            unique_code=unique_code,
            hypothesis_key=hypothesis_key,
            context_refs=context_refs,
        )

    async def get_assignment(self, run_id: str, agent_id: str, context: CapabilityContext) -> dict[str, Any]:
        async with self.db.sessions() as session:
            agent = await self._authorize(session, context, roles={"chief", "challenge", "execution"}, agent_id=agent_id)
            return {
                "agent": self._agent_dict(agent),
                "challenge": await self.get_challenge_context(run_id, agent.unique_code, context) if agent.unique_code else None,
            }

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
                "agent": self._agent_dict(agent, include_runtime=True),
            }

    async def append_agent_event(
        self,
        run_id: str,
        agent_id: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
        *,
        cycle_id: str | None = None,
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
                    redact_value(
                        dict(payload or {}), secrets=self.ephemeral_secrets()
                    ),
                    agent_id=agent_id,
                    cycle_id=cycle_id,
                )

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
                    "cycle_id": row.cycle_id,
                    "created_at": _json_value(row.created_at),
                }
                for row in rows
            ]

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
            "pending", "queued", "starting", "running", "waiting", "working", "blocked",
            "stopping", "stopped", "completed", "failed", "cancelled",
            "interrupted", "indeterminate",
        }
        if status not in allowed:
            raise StateError("invalid_agent_status", "Agent status is invalid", status_code=422)
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if expected_version is not None:
                    self._check_version(agent.version, expected_version)
                now = self.clock()
                agent.status = status
                if status == "starting":
                    agent.started_at = agent.started_at or now
                if status == "running":
                    agent.started_at = agent.started_at or now
                    agent.last_heartbeat_at = now
                if status == "stopping":
                    agent.stop_requested_at = now
                if status in {"stopped", "completed", "failed", "cancelled", "interrupted"}:
                    agent.ended_at = now
                agent.version += 1
                await self._event(
                    session,
                    run_id,
                    "agent_status_changed",
                    {"agent_id": agent_id, "status": status},
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
        return self._agent_dict(agent)

    async def transition_controller(
        self,
        run_id: str,
        agent_id: str,
        status: str,
        *,
        controller_cursor: int | None = None,
    ) -> dict[str, Any]:
        """Persist one Chief/Challenge controller transition atomically."""

        if status not in {"running", "waiting"}:
            raise StateError(
                "invalid_controller_status",
                "Controller status must be running or waiting",
                status_code=422,
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.role not in {"chief", "challenge"}:
                    raise StatePermission(
                        "controller_required",
                        "Only Chief and Challenge Agents are persistent controllers",
                    )
                changed = agent.status != status
                if controller_cursor is not None and controller_cursor > agent.controller_cursor:
                    agent.controller_cursor = controller_cursor
                    changed = True
                event_sequence: int | None = None
                if changed:
                    now = self.clock()
                    agent.status = status
                    agent.ended_at = None
                    if status == "running":
                        agent.started_at = agent.started_at or now
                        agent.last_heartbeat_at = now
                    agent.version += 1
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "agent_status_changed",
                        {
                            "agent_id": agent_id,
                            "status": status,
                            "controller_cursor": agent.controller_cursor,
                        },
                        agent_id=agent_id,
                        cycle_id=agent.cycle_id,
                    )
        data = self._agent_dict(agent)
        data["event_sequence"] = event_sequence
        return data

    async def enqueue_agent(self, run_id: str, agent_id: str) -> dict[str, Any]:
        """Persist one execution Agent admission request without starting it."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.role != "execution":
                    raise StatePermission(
                        "execution_required",
                        "Only Execution Agents use admission",
                    )
                existing = await session.scalar(
                    select(AdmissionRecord).where(
                        AdmissionRecord.run_id == run_id,
                        AdmissionRecord.agent_id == agent_id,
                    )
                )
                if existing is None:
                    existing = AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}",
                        run_id=run_id,
                        agent_id=agent_id,
                        unique_code=agent.unique_code,
                        role=agent.role,
                        priority=agent.priority,
                        status="queued",
                    )
                    session.add(existing)
                agent.status = "queued"
                agent.version += 1
                await self._event(
                    session,
                    run_id,
                    "agent_admission_queued",
                    {
                        "agent_id": agent_id,
                        "admission_id": existing.admission_id,
                        "priority": agent.priority,
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
        return {
            "admission_id": existing.admission_id,
            "agent_id": agent_id,
            "status": existing.status,
            "priority": existing.priority,
        }

    async def finish_agent(
        self,
        run_id: str,
        agent_id: str,
        *,
        status: str,
        final_report: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "failed", "stopped", "cancelled", "interrupted"}:
            raise StateError("invalid_terminal_status", "Agent terminal status is invalid", status_code=422)
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.role == "execution":
                    if agent.terminal_report_id is None:
                        raise StateConflict(
                            "execution_finalizer_required",
                            "Execution Agents must be terminated through finalize_execution_agent",
                        )
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
                    cycle_id=agent.cycle_id,
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
    ) -> dict[str, Any]:
        """Persist one successfully spawned Shell process without its command."""

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
                        "agent_finished", "Finished Agent cannot create Shell tasks"
                    )
                if await session.get(ShellTaskRecord, task_id) is not None:
                    raise StateConflict("shell_task_exists", "Shell task already exists")
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
                    {"task_id": task_id, "cwd": cwd, "status": "running"},
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
    ) -> dict[str, Any]:
        terminal = {"completed", "failed", "timeout", "stopped", "interrupted"}
        if status not in terminal:
            raise StateError(
                "invalid_shell_task_status",
                "Shell task terminal status is invalid",
                status_code=422,
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                task = await session.get(ShellTaskRecord, task_id)
                if (
                    task is None
                    or task.run_id != run_id
                    or task.agent_id != agent_id
                ):
                    raise StateNotFound("shell_task_not_found", "Shell task was not found")
                if task.status == "running":
                    finished_at = self.clock()
                    task.status = status
                    task.exit_code = exit_code
                    task.output_chars = max(0, output_chars)
                    task.truncated = truncated
                    task.timed_out = timed_out
                    task.finished_at = finished_at
                    task.expires_at = finished_at + timedelta(minutes=30)
                    await self._event(
                        session,
                        run_id,
                        "shell_task_finished",
                        {
                            "task_id": task_id,
                            "status": status,
                            "exit_code": exit_code,
                            "timed_out": timed_out,
                            "truncated": truncated,
                        },
                        agent_id=agent_id,
                    )
        return self._shell_task_dict(task)

    async def get_shell_task(
        self, run_id: str, agent_id: str, task_id: str
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            task = await session.get(ShellTaskRecord, task_id)
            if (
                task is None
                or task.run_id != run_id
                or task.agent_id != agent_id
            ):
                raise StateNotFound("shell_task_not_found", "Shell task was not found")
            return self._shell_task_dict(task)

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
                if (
                    task is None
                    or task.run_id != run_id
                    or task.agent_id != agent_id
                ):
                    raise StateNotFound("shell_task_not_found", "Shell task was not found")
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
        resource_statuses = {"queued", "reserved", "running", "waiting", "released"}
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
                    await self._event(
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
                    estimated_requests=min(9_223_372_036_854_775_807, max(0, estimated_requests)),
                    requested_concurrency=max(1, requested_concurrency),
                    estimated_disk_bytes=min(9_223_372_036_854_775_807, max(0, estimated_disk_bytes)),
                    estimated_memory_bytes=min(9_223_372_036_854_775_807, max(0, estimated_memory_bytes)),
                    estimated_analysis_work=min(9_223_372_036_854_775_807, max(0, estimated_analysis_work)),
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
                    in {"completed", "failed", "stopped", "interrupted"}
                ):
                    record.execution_finished_at = now
                if (
                    record.analysis_finished_at is None
                    and record.analysis_status
                    in {"completed", "failed", "interrupted"}
                ):
                    record.analysis_finished_at = now
                elif (
                    previous[2] in {"completed", "failed", "interrupted"}
                    and record.analysis_status in {"pending", "queued", "running"}
                ):
                    record.analysis_finished_at = None
                current = (
                    record.status,
                    record.execution_status,
                    record.analysis_status,
                    record.resource_status,
                )
                if current != previous:
                    await self._event(
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
        return self._http_interaction_dict(record)

    async def get_http_interaction(
        self, run_id: str, agent_id: str, interaction_id: str
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            record = await session.get(HttpInteractionRecord, interaction_id)
            if (
                record is None
                or record.run_id != run_id
                or record.agent_id != agent_id
            ):
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
                    estimated_requests=min(9_223_372_036_854_775_807, max(0, estimated_requests)),
                    estimated_disk_bytes=min(9_223_372_036_854_775_807, max(0, estimated_disk_bytes)),
                    estimated_memory_bytes=min(9_223_372_036_854_775_807, max(0, estimated_memory_bytes)),
                )
                session.add(record)
                await self._event(
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
        return self._resource_work_dict(record)

    async def update_resource_work(
        self,
        run_id: str,
        work_id: str,
        *,
        status: str,
        reason: str | None = None,
        retry_at: datetime | None = None,
    ) -> dict[str, Any]:
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
                    await self._event(
                        session,
                        run_id,
                        "resource_work_status_changed",
                        {
                            "work_id": work_id,
                            "owner_id": record.owner_id,
                            "phase": record.phase,
                            "status": status,
                            "reason": reason,
                        },
                        agent_id=record.agent_id,
                    )
        return self._resource_work_dict(record)

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

    async def interrupt_execution_agents(
        self,
        run_id: str,
        *,
        failure_code: str = "runtime_interrupted",
    ) -> list[str]:
        """Finalize active Execution Agents without replaying their assignments."""

        async with self.db.sessions() as session:
            agent_ids = list(
                (
                    await session.scalars(
                        select(AgentRecord.agent_id).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.role == "execution",
                            AgentRecord.status.in_(
                                ["pending", "queued", "starting", "running", "working", "blocked", "stopping"]
                            ),
                        )
                    )
                ).all()
            )
        for agent_id in agent_ids:
            runtime = await self.get_agent_runtime(run_id, agent_id)
            agent = runtime["agent"]
            await self.finalize_execution_agent(
                run_id,
                agent_id,
                CapabilityContext(
                    run_id=run_id,
                    agent_id=agent_id,
                    role="execution",
                    unique_code=agent["unique_code"],
                ),
                AgentReportInput(
                    status="cancelled",
                    summary="Execution Agent was interrupted by the Runtime",
                    failure_code=failure_code,
                ),
                terminal_status="interrupted",
                allow_inactive=True,
            )
        return agent_ids

    async def finish_run(
        self,
        run_id: str,
        status: str,
        *,
        report: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "failed", "interrupted"}:
            raise StateError("invalid_run_status", "run terminal status is invalid", status_code=422)
        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                run.status = status
                if report is not None:
                    chief = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.role == "chief",
                        ).limit(1)
                    )
                    if chief is not None:
                        chief.final_report = redact_value(dict(report))
                event_sequence = await self._event(
                    session,
                    run_id,
                    "run_finished",
                    {"status": status},
                    agent_id=chief.agent_id if report is not None and chief is not None else None,
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
                sequence = await self._event(
                    session, run_id, event_type, dict(payload)
                )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return sequence

    async def consume_reports(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        report_type: str | None = None,
        max_reports: int = 20,
        wait_seconds: float = 0.0,
    ) -> dict[str, Any]:
        signal_key = self.agent_signal_key(run_id, context.agent_id)
        signal_sequence = await self.notifier.current(signal_key)
        while True:
            current_cursor = 0
            async with self._lock:
                async with self.db.sessions.begin() as session:
                    agent = await self._authorize(session, context, roles={"chief", "challenge"})
                    cursor_key = report_type or "*"
                    current_cursor = int(agent.report_cursors.get(cursor_key, 0))
                    clauses = [
                        ReportRecord.run_id == run_id,
                        ReportRecord.sequence > current_cursor,
                        ReportRecord.parent_id == agent.agent_id,
                    ]
                    if report_type is not None:
                        clauses.append(ReportRecord.report_type == report_type)
                    rows = (
                        await session.scalars(
                            select(ReportRecord)
                            .where(*clauses)
                            .order_by(ReportRecord.sequence)
                            .limit(max(1, min(max_reports, 100)))
                        )
                    ).all()
                    if rows:
                        current_cursor = rows[-1].sequence
                        agent.report_cursors = {
                            **agent.report_cursors,
                            cursor_key: current_cursor,
                        }
                        agent.report_cursor = max(agent.report_cursor, current_cursor)
                        agent.version += 1
                        for row in rows:
                            row.consumed_by = agent.agent_id
                            row.consumed_at = self.clock()
                        reports = [self._report_with_ephemeral(item) for item in rows]
                        await self._event(
                            session,
                            run_id,
                            "reports_consumed",
                            {"through_sequence": current_cursor, "count": len(rows), "report_type": report_type},
                            agent_id=agent.agent_id,
                        )
                        return {
                            "reports": reports,
                            "count": len(reports),
                            "next_sequence": current_cursor,
                        }
            if wait_seconds <= 0:
                return {"reports": [], "count": 0, "next_sequence": current_cursor}
            started = asyncio.get_running_loop().time()
            signal_sequence = await self.notifier.wait(
                signal_key,
                signal_sequence,
                wait_seconds,
            )
            elapsed = asyncio.get_running_loop().time() - started
            wait_seconds = max(0.0, wait_seconds - elapsed)

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
                if sender is None or recipient is None or sender.run_id != run_id or recipient.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Control report Agent was not found")
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

    async def begin_cycle(self, run_id: str, unique_code: str, context: CapabilityContext, payload: CreateCycleInput) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._authorize(session, context, roles={"challenge"}, unique_code=unique_code)
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.is_completed or challenge.work_status in {"closed", "paused"}:
                    raise StateConflict(
                        "challenge_not_active",
                        "Paused, closed, or completed challenges do not accept new cycles",
                    )
                open_cycle = await session.scalar(
                    select(CycleRecord)
                    .where(
                        CycleRecord.run_id == run_id,
                        CycleRecord.unique_code == unique_code,
                        CycleRecord.status.not_in(["completed", "invalid_cycle_output"]),
                    )
                    .order_by(CycleRecord.cycle_number.desc())
                    .limit(1)
                )
                if open_cycle is not None:
                    return self._cycle_dict(open_cycle)
                if challenge.version != payload.expected_challenge_version:
                    raise StateConflict("state_conflict", "challenge state changed", {"current_version": challenge.version})
                existing = await session.scalar(select(func.max(CycleRecord.cycle_number)).where(CycleRecord.run_id == run_id, CycleRecord.unique_code == unique_code))
                cycle_number = int(existing or 0) + 1
                cycle = CycleRecord(
                    cycle_id=f"cycle_{uuid4().hex}", run_id=run_id, unique_code=unique_code,
                    cycle_number=cycle_number, state_snapshot=await self._snapshot(session, challenge),
                )
                session.add(cycle)
                challenge.version += 1
                await self._event(
                    session,
                    run_id,
                    "cycle_state_created",
                    {"cycle_id": cycle.cycle_id, "unique_code": unique_code, "cycle_number": cycle_number},
                    agent_id=context.agent_id,
                    cycle_id=cycle.cycle_id,
                )
        return self._cycle_dict(cycle)

    async def submit_analysis_plan(self, run_id: str, cycle_id: str, context: CapabilityContext, payload: AnalysisPlanInput) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                cycle = await self._require_cycle(session, run_id, cycle_id)
                await self._authorize(session, context, roles={"challenge"}, unique_code=cycle.unique_code)
                self._check_version(cycle.version, payload.expected_version)
                if cycle.status not in {"state", "analysis"}:
                    raise StateConflict("invalid_cycle_phase", "cycle is not accepting analysis and plan")
                cycle.analysis = {
                    "summary": payload.analysis_summary,
                    "hypotheses": [
                        item.model_dump(mode="json") for item in payload.hypotheses
                    ],
                    "information_gaps": payload.information_gaps,
                    "avoid_repeating": payload.avoid_repeating,
                }
                cycle.plan = {"tasks": [item.model_dump(mode="json") for item in payload.tasks]}
                cycle.status = "execute"
                cycle.analysis_at = self.clock()
                cycle.plan_at = self.clock()
                cycle.execute_at = self.clock()
                cycle.version += 1
                admissions: list[dict[str, Any]] = []
                challenge = await self._require_challenge(session, run_id, cycle.unique_code)
                tasks = list(payload.tasks)
                if challenge.stagnation_level >= 2 or challenge.work_status in {"paused", "extended"}:
                    if tasks:
                        raise StateConflict(
                            "challenge_paused",
                            "Paused or extended challenges do not accept execution tasks",
                        )
                elif challenge.stagnation_level >= 1:
                    if len(tasks) > 1 or any(
                        item.kind != "exploration" or not item.context_refs
                        for item in tasks
                    ):
                        raise StateConflict(
                            "exploration_only",
                            "Warning state accepts one exploration task with a concrete context reference",
                        )
                    existing_explorer = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == cycle.unique_code,
                            AgentRecord.kind == "exploration",
                            AgentRecord.status.in_(
                                ["pending", "queued", "starting", "running", "working"]
                            ),
                        )
                    )
                    if existing_explorer is not None or challenge.l2_explorer_created:
                        if tasks:
                            raise StateConflict(
                                "stagnation_explorer_limit",
                                "This warning episode already used its exploration Agent",
                            )
                    elif tasks:
                        challenge.l2_explorer_created = True
                        challenge.version += 1
                        await self._event(
                            session,
                            run_id,
                            "stagnation_explorer_reserved",
                            {"unique_code": cycle.unique_code, "source": "cycle_plan"},
                            agent_id=context.agent_id,
                            cycle_id=cycle_id,
                        )
                if len({task.task_key for task in tasks}) != len(tasks):
                    raise StateConflict(
                        "duplicate_task_key", "A plan contains duplicate task keys"
                    )
                if len({task.hypothesis_key for task in tasks}) != len(tasks):
                    raise StateConflict(
                        "duplicate_active_hypothesis",
                        "A plan may start only one task per hypothesis",
                    )
                hypothesis_by_key = {
                    hypothesis.key: hypothesis
                    for hypothesis in payload.hypotheses
                }
                for task in tasks:
                    branch_key = task.branch_key or (
                        f"{task.hypothesis_key}:{task.kind}"
                    )
                    await self._validate_branch_admission(
                        session,
                        run_id=run_id,
                        unique_code=cycle.unique_code,
                        hypothesis_key=task.hypothesis_key,
                        branch_key=branch_key,
                        task_key=task.task_key,
                        context_refs=task.context_refs,
                    )
                    agent_id = f"execution_{uuid4().hex}"
                    hypothesis = hypothesis_by_key.get(task.hypothesis_key)
                    await self._upsert_hypothesis(
                        session,
                        run_id=run_id,
                        unique_code=cycle.unique_code,
                        hypothesis=hypothesis,
                        created_by=context.agent_id,
                        status="active",
                    )
                    await self._upsert_branch(
                        session,
                        run_id=run_id,
                        unique_code=cycle.unique_code,
                        branch_key=branch_key,
                        hypothesis_key=task.hypothesis_key,
                        kind=task.kind,
                        priority=task.priority,
                        mission=task.objective,
                        agent_id=agent_id,
                        status="queued",
                    )
                    agent = AgentRecord(
                        agent_id=agent_id, run_id=run_id, parent_id=context.agent_id,
                        unique_code=cycle.unique_code, cycle_id=cycle.cycle_id,
                        role="execution", kind=task.kind, priority=task.priority,
                        hypothesis_key=task.hypothesis_key,
                        task_key=task.task_key,
                        branch_key=branch_key,
                        mission=task.objective, success_criteria=task.success_criteria,
                        context_refs=task.context_refs, timeout_seconds=task.timeout_seconds,
                        initial_prompt=task.objective,
                        session_memory=DEFAULT_SESSION_MEMORY,
                        status="queued",
                    )
                    session.add(agent)
                    admission = AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}", run_id=run_id,
                        agent_id=agent_id, unique_code=cycle.unique_code, role="execution",
                        priority=task.priority,
                    )
                    session.add(admission)
                    admissions.append({"agent_id": agent_id, "admission_id": admission.admission_id, "status": "queued"})
                await self._event(
                    session,
                    run_id,
                    "cycle_analysis_plan_submitted",
                    {"cycle_id": cycle_id, "task_count": len(admissions)},
                    agent_id=context.agent_id,
                    cycle_id=cycle_id,
                )
        result = self._cycle_dict(cycle)
        result["admissions"] = admissions
        return result

    async def commit_cycle(self, run_id: str, cycle_id: str, context: CapabilityContext, payload: VerificationUpdateInput) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                cycle = await self._require_cycle(session, run_id, cycle_id)
                await self._authorize(session, context, roles={"challenge"}, unique_code=cycle.unique_code)
                self._check_version(cycle.version, payload.expected_version)
                if cycle.status not in {"execute", "verify"}:
                    raise StateConflict("invalid_cycle_phase", "cycle is not ready for verification")
                cycle.status = "completed"
                cycle.verification = {"summary": payload.summary, "outcome": payload.outcome, "rejected_finding_ids": payload.rejected_finding_ids}
                cycle.state_update = {
                    "next_steps": payload.next_steps,
                    "outcome": payload.outcome,
                    "new_attack_paths": [
                        item.model_dump(mode="json")
                        for item in payload.new_attack_paths
                    ],
                }
                cycle.verify_at = self.clock()
                cycle.update_at = self.clock()
                cycle.version += 1
                valid_progress, added = await self._record_findings(
                    session,
                    run_id,
                    cycle.unique_code,
                    context.agent_id,
                    payload.findings,
                )
                attack_paths = [
                    FindingInput(
                        category="attack_path",
                        summary=path.summary,
                        detail={"verification_steps": path.verification_steps},
                        confidence=path.confidence,
                        verification_status="candidate",
                        evidence_paths=path.evidence_paths,
                    )
                    for path in payload.new_attack_paths
                ]
                attack_path_progress, added_paths = await self._record_findings(
                    session,
                    run_id,
                    cycle.unique_code,
                    context.agent_id,
                    attack_paths,
                    count_candidate_attack_paths=True,
                )
                valid_progress = valid_progress or attack_path_progress
                added.extend(added_paths)
                for finding_id in payload.rejected_finding_ids:
                    finding = await session.get(FindingRecord, finding_id)
                    if finding and finding.run_id == run_id and finding.unique_code == cycle.unique_code:
                        finding.verification_status = "rejected"
                        finding.version += 1
                for credential in payload.credentials:
                    await self._record_credential(session, run_id, cycle.unique_code, None, credential)
                if any(credential.verified for credential in payload.credentials):
                    valid_progress = True
                challenge = await self._require_challenge(session, run_id, cycle.unique_code)
                if valid_progress:
                    self._mark_progress(challenge)
                    progress_kinds = []
                    if attack_path_progress:
                        progress_kinds.append("new_attack_path")
                    if valid_progress and not attack_path_progress:
                        progress_kinds.append("verified_evidence")
                    if any(credential.verified for credential in payload.credentials):
                        progress_kinds.append("verified_credential")
                    await self._event(
                        session,
                        run_id,
                        "stagnation_progress_recorded",
                        {
                            "unique_code": cycle.unique_code,
                            "progress_kinds": progress_kinds,
                        },
                        agent_id=context.agent_id,
                        cycle_id=cycle_id,
                    )
                cycle.completed_at = self.clock()
                await self._event(
                    session,
                    run_id,
                    "cycle_committed",
                    {"cycle_id": cycle_id, "finding_count": len(added), "valid_progress": valid_progress, "outcome": payload.outcome},
                    agent_id=context.agent_id,
                    cycle_id=cycle_id,
                )
        return {"cycle": self._cycle_dict(cycle), "findings": added, "valid_progress": valid_progress}

    async def mark_invalid_cycle(self, run_id: str, cycle_id: str, context: CapabilityContext, reason: str = "missing_structured_output") -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                cycle = await self._require_cycle(session, run_id, cycle_id)
                await self._authorize(session, context, roles={"challenge"}, unique_code=cycle.unique_code)
                cycle.status = "invalid_cycle_output"
                cycle.state_update = {"reason": reason}
                cycle.version += 1
                cycle.completed_at = self.clock()
                await self._event(session, run_id, "cycle_invalid", {"cycle_id": cycle_id, "reason": reason})
        return self._cycle_dict(cycle)

    async def update_progress(self, run_id: str, agent_id: str, context: CapabilityContext, payload: AgentProgressInput) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(session, context, roles={"execution"}, agent_id=agent_id)
                if agent.unique_code:
                    challenge = await self._require_challenge(session, run_id, agent.unique_code)
                    if challenge.work_status in {"paused", "closed"} or challenge.is_completed:
                        raise StateConflict(
                            "challenge_not_active",
                            "The challenge no longer accepts Execution Agent progress",
                        )
                agent.status = "running" if payload.status == "working" else payload.status
                agent.last_heartbeat_at = self.clock()
                agent.version += 1
                finding_values = [
                    item
                    if item.evidence_paths or not payload.evidence_paths
                    else item.model_copy(update={"evidence_paths": payload.evidence_paths})
                    for item in payload.findings
                ]
                valid, findings = await self._record_findings(
                    session, run_id, agent.unique_code, agent_id, finding_values
                )
                if agent.unique_code and valid:
                    challenge = await self._require_challenge(session, run_id, agent.unique_code)
                    self._mark_progress(challenge)
                    await self._event(
                        session,
                        run_id,
                        "stagnation_progress_recorded",
                        {
                            "unique_code": agent.unique_code,
                            "progress_kinds": ["verified_evidence"],
                        },
                        agent_id=agent_id,
                        cycle_id=agent.cycle_id,
                    )
                await self._event(
                    session,
                    run_id,
                    "agent_progress",
                    {
                        "agent_id": agent_id,
                        "status": payload.status,
                        "phase": payload.phase,
                        "summary": payload.summary,
                        "finding_count": len(findings),
                        "valid_progress": valid,
                        "expected_result_seconds": payload.expected_result_seconds,
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
        return {"agent": self._agent_dict(agent), "findings": findings, "valid_progress": valid}

    async def submit_report(self, run_id: str, agent_id: str, context: CapabilityContext, payload: AgentReportInput) -> dict[str, Any]:
        if context.role == "execution" and payload.status != "working":
            return await self.finalize_execution_agent(
                run_id, agent_id, context, payload
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(session, context, roles={"execution", "challenge"}, agent_id=agent_id)
                if agent.role == "execution" and context.unique_code != agent.unique_code:
                    raise StatePermission("challenge_binding_required", "Agent is bound to another challenge")
                if agent.unique_code:
                    challenge = await self._require_challenge(session, run_id, agent.unique_code)
                    if challenge.work_status in {"paused", "closed"} or challenge.is_completed:
                        raise StateConflict(
                            "challenge_not_active",
                            "The challenge no longer accepts Agent reports",
                        )
                if payload.status == "working":
                    agent.status = "running"
                else:
                    agent.status = "completed" if payload.status == "completed" else payload.status
                    agent.ended_at = self.clock()
                agent.last_heartbeat_at = self.clock()
                agent.version += 1
                finding_values = [
                    item
                    if item.evidence_paths or not payload.evidence_paths
                    else item.model_copy(update={"evidence_paths": payload.evidence_paths})
                    for item in payload.findings
                ]
                valid, findings = await self._record_findings(
                    session, run_id, agent.unique_code, agent_id, finding_values
                )
                if agent.unique_code and valid:
                    self._mark_progress(challenge)
                    await self._event(
                        session,
                        run_id,
                        "stagnation_progress_recorded",
                        {
                            "unique_code": agent.unique_code,
                            "progress_kinds": ["verified_evidence"],
                        },
                        agent_id=agent_id,
                        cycle_id=agent.cycle_id,
                    )
                safe_payload = {
                    "status": payload.status,
                    "summary": payload.summary,
                    "findings": [item.model_dump(mode="json") for item in payload.findings],
                    "evidence_paths": payload.evidence_paths,
                    "next_steps": payload.next_steps,
                    "confidence": payload.confidence,
                }
                if payload.failure_code is not None:
                    safe_payload["failure_code"] = payload.failure_code
                if payload.candidate_flag is not None:
                    safe_payload["candidate_flag"] = {"sha256": fingerprint_secret(payload.candidate_flag), "length": len(payload.candidate_flag)}
                sequence = await self._next_sequence(session, run_id)
                report = ReportRecord(
                    report_id=f"report_{uuid4().hex}", run_id=run_id, sequence=sequence,
                    agent_id=agent_id, parent_id=agent.parent_id, unique_code=agent.unique_code,
                    report_type="execution" if agent.role == "execution" else "challenge",
                    status=payload.status, payload=safe_payload,
                )
                session.add(report)
                agent.last_report_sequence = sequence
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "agent_report",
                    {"report_id": report.report_id, "agent_id": agent_id, "status": payload.status, "valid_progress": valid},
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
                result = {"report_id": report.report_id, "sequence": sequence, "status": payload.status, "valid_progress": valid, "findings": findings}
                if payload.candidate_flag is not None:
                    self._ephemeral_reports[report.report_id] = payload.candidate_flag
        if agent.parent_id:
            await self.notifier.notify(
                self.agent_signal_key(run_id, agent.parent_id), sequence
            )
        return result

    async def finalize_execution_agent(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        payload: AgentReportInput,
        *,
        terminal_status: str | None = None,
        allow_inactive: bool = False,
    ) -> dict[str, Any]:
        """Atomically persist exactly one terminal Execution report."""

        if payload.status == "working":
            raise StateError(
                "terminal_report_required",
                "Execution finalization requires a terminal report status",
                status_code=422,
            )
        parent_id: str | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session,
                    context,
                    roles={"execution"},
                    agent_id=agent_id,
                )
                if agent.terminal_report_id is not None:
                    existing = await session.get(ReportRecord, agent.terminal_report_id)
                    if existing is None:
                        raise StateError(
                            "terminal_report_missing",
                            "Execution Agent terminal report reference is invalid",
                        )
                    return {
                        "report_id": existing.report_id,
                        "sequence": existing.sequence,
                        "status": existing.status,
                        "valid_progress": False,
                        "findings": [],
                        "idempotent": True,
                    }
                challenge: ChallengeRecord | None = None
                if agent.unique_code:
                    challenge = await self._require_challenge(
                        session, run_id, agent.unique_code
                    )
                    if (
                        not allow_inactive
                        and (
                            challenge.work_status in {"paused", "closed"}
                            or challenge.is_completed
                        )
                    ):
                        raise StateConflict(
                            "challenge_not_active",
                            "The challenge no longer accepts Agent reports",
                        )
                finding_values = [
                    item
                    if item.evidence_paths or not payload.evidence_paths
                    else item.model_copy(update={"evidence_paths": payload.evidence_paths})
                    for item in payload.findings
                ]
                valid, findings = await self._record_findings(
                    session,
                    run_id,
                    agent.unique_code,
                    agent_id,
                    finding_values,
                )
                if challenge is not None and valid:
                    self._mark_progress(challenge)
                    await self._event(
                        session,
                        run_id,
                        "stagnation_progress_recorded",
                        {
                            "unique_code": agent.unique_code,
                            "progress_kinds": ["verified_evidence"],
                        },
                        agent_id=agent_id,
                        cycle_id=agent.cycle_id,
                    )
                safe_payload: dict[str, Any] = {
                    "status": payload.status,
                    "summary": payload.summary,
                    "findings": [
                        item.model_dump(mode="json") for item in payload.findings
                    ],
                    "evidence_paths": payload.evidence_paths,
                    "next_steps": payload.next_steps,
                    "confidence": payload.confidence,
                }
                if payload.failure_code is not None:
                    safe_payload["failure_code"] = payload.failure_code
                if payload.candidate_flag is not None:
                    safe_payload["candidate_flag"] = {
                        "sha256": fingerprint_secret(payload.candidate_flag),
                        "length": len(payload.candidate_flag),
                    }
                sequence = await self._next_sequence(session, run_id)
                report = ReportRecord(
                    report_id=f"report_{uuid4().hex}",
                    run_id=run_id,
                    sequence=sequence,
                    agent_id=agent_id,
                    parent_id=agent.parent_id,
                    unique_code=agent.unique_code,
                    report_type="execution",
                    status=payload.status,
                    payload=safe_payload,
                )
                session.add(report)
                resolved_status = terminal_status or {
                    "completed": "completed",
                    "cancelled": "stopped",
                    "blocked": "failed",
                    "failed": "failed",
                }.get(payload.status, "failed")
                if resolved_status not in {
                    "completed",
                    "failed",
                    "stopped",
                    "interrupted",
                }:
                    raise StateError(
                        "invalid_terminal_status",
                        "Execution terminal status is invalid",
                        status_code=422,
                    )
                durable_report = {
                    "type": "execution_report",
                    "agent_id": agent_id,
                    **safe_payload,
                    "sequence": sequence,
                    "report_id": report.report_id,
                }
                agent.status = resolved_status
                agent.final_report = redact_value(durable_report)
                agent.terminal_report_id = report.report_id
                agent.last_report_sequence = sequence
                agent.last_heartbeat_at = self.clock()
                agent.ended_at = self.clock()
                agent.version += 1
                cancelled_branches: list[str] = []
                if agent.branch_key and agent.unique_code:
                    branch = await session.get(
                        ExecutionBranchRecord,
                        (run_id, agent.unique_code, agent.branch_key),
                    )
                    if branch is not None:
                        branch.status = {
                            "completed": "completed",
                            "cancelled": "cancelled",
                            "blocked": "failed",
                            "failed": "failed",
                            "stopped": "cancelled",
                            "interrupted": "interrupted",
                        }.get(resolved_status, "failed")
                        branch.outcome = {
                            **branch.outcome,
                            "agent_id": agent_id,
                            "report_id": report.report_id,
                            "status": resolved_status,
                            "valid_progress": valid,
                        }
                        branch.updated_at = self.clock()
                        branch.version += 1
                    if agent.hypothesis_key:
                        hypothesis = await session.get(
                            HypothesisRecord,
                            (run_id, agent.unique_code, agent.hypothesis_key),
                        )
                        if hypothesis is not None:
                            if resolved_status == "completed" and valid:
                                hypothesis.status = "verified"
                            elif resolved_status == "completed":
                                hypothesis.status = "rejected"
                            hypothesis.updated_at = self.clock()
                            hypothesis.version += 1
                    if resolved_status == "completed" and valid:
                        cancelled_branches = await self._cancel_sibling_branches(
                            session,
                            run_id,
                            agent.unique_code,
                            except_branch=agent.branch_key,
                        )
                admission = await session.scalar(
                    select(AdmissionRecord).where(
                        AdmissionRecord.run_id == run_id,
                        AdmissionRecord.agent_id == agent_id,
                    )
                )
                if admission is not None:
                    admission.status = resolved_status
                    admission.updated_at = self.clock()
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "agent_report",
                    {
                        "report_id": report.report_id,
                        "agent_id": agent_id,
                        "status": payload.status,
                        "agent_status": resolved_status,
                        "valid_progress": valid,
                        "terminal": True,
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
                parent_id = agent.parent_id
                result = {
                    "report_id": report.report_id,
                    "sequence": sequence,
                    "status": payload.status,
                    "agent_status": resolved_status,
                    "valid_progress": valid,
                    "findings": findings,
                    "cancelled_branches": cancelled_branches,
                    "idempotent": False,
                }
                if payload.candidate_flag is not None:
                    self._ephemeral_reports[report.report_id] = payload.candidate_flag
        if parent_id:
            await self.notifier.notify(
                self.agent_signal_key(run_id, parent_id), sequence
            )
        await self.notifier.notify(self.run_signal_key(run_id), sequence)
        return result

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
            raise StateError("invalid_wait", "wait_seconds must be between 0 and 30", status_code=422)
        max_reports = max(1, min(max_reports, 100))
        signal_key = self.agent_signal_key(run_id, context.agent_id)
        signal_sequence = await self.notifier.current(signal_key)
        while True:
            async with self.db.sessions() as session:
                agent = await self._authorize(session, context, roles={"chief", "challenge"})
                query = select(ReportRecord).where(ReportRecord.run_id == run_id, ReportRecord.sequence > after_sequence, ReportRecord.parent_id == agent.agent_id).order_by(ReportRecord.sequence).limit(max_reports)
                rows = (await session.scalars(query)).all()
                if rows:
                    reports = [self._report_with_ephemeral(item) for item in rows]
                    return {"reports": reports, "count": len(rows), "next_sequence": rows[-1].sequence}
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
                    agent = await self._authorize(session, context, roles={"chief", "challenge"})
                    return {"reports": [], "count": 0, "next_sequence": after_sequence}
            wait_seconds = max(0.0, wait_seconds - (asyncio.get_running_loop().time() - started))

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
                agent = await self._authorize(session, context, roles={"chief", "challenge", "execution"}, agent_id=agent_id)
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
                        cycle_id=agent.cycle_id,
                    )
        return self._agent_dict(agent)

    async def start_challenge(self, run_id: str, unique_code: str, context: CapabilityContext | None = None) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if context is not None:
                    await self._authorize(session, context, roles={"chief", "challenge"}, unique_code=unique_code)
                challenge = await self._require_challenge(session, run_id, unique_code)
                active = await session.scalar(
                    select(func.count())
                    .select_from(ChallengeRecord)
                    .where(
                        ChallengeRecord.run_id == run_id,
                        ChallengeRecord.container_status.notin_(
                            sorted(RELEASED_CONTAINER_STATUSES)
                        ),
                    )
                )
                if not container_slot_occupied(challenge.container_status) and int(active or 0) >= 3:
                    raise StateConflict("challenge_slots_exhausted", "at most three challenge containers may be active")
                now = self.clock()
                run = await self._require_run(session, run_id)
                run.current_challenge_code = unique_code
                challenge.container_status = "running"
                challenge.platform_status = "started"
                challenge.work_status = "active"
                challenge.started_at = challenge.started_at or now
                if challenge.active_since is None:
                    challenge.active_since = now
                    challenge.last_progress_at = now
                challenge.last_progress_at = challenge.last_progress_at or now
                challenge.paused_at = None
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_started",
                    {"unique_code": unique_code},
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def close_challenge(self, run_id: str, unique_code: str, context: CapabilityContext | None = None) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if context is not None:
                    await self._authorize(session, context, roles={"chief", "challenge"}, unique_code=unique_code)
                challenge = await self._require_challenge(session, run_id, unique_code)
                self._freeze_exploration(challenge)
                challenge.container_status = "stopped"
                challenge.platform_status = "closed"
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

    async def mark_challenge_paused(self, run_id: str, unique_code: str) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                if container_slot_occupied(challenge.container_status):
                    raise StateConflict(
                        "container_release_unconfirmed",
                        "Challenge container release has not been confirmed",
                    )
                self._freeze_exploration(challenge)
                challenge.work_status = "paused"
                challenge.platform_status = "available"
                challenge.paused_at = self.clock()
                challenge.pause_reason = "stagnation_threshold"
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_paused",
                    {"unique_code": unique_code},
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def mark_challenge_pause_pending(
        self, run_id: str, unique_code: str, *, platform_status: str = "close_requested"
    ) -> dict[str, Any]:
        """Keep a paused challenge out of scheduling until release is confirmed."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                self._freeze_exploration(challenge)
                challenge.work_status = "paused"
                challenge.platform_status = platform_status
                challenge.paused_at = self.clock()
                challenge.pause_reason = "stagnation_pending"
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_pause_pending",
                    {
                        "unique_code": unique_code,
                        "container_status": challenge.container_status,
                    },
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def reserve_stagnation_explorer(
        self, run_id: str, unique_code: str
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.stagnation_level < 1:
                    return self._challenge_dict(challenge)
                if challenge.stagnation_level >= 2 or challenge.work_status in {"paused", "extended"}:
                    raise StateConflict(
                        "stagnation_explorer_not_allowed",
                        "Exploration is not allowed after the first stagnation level",
                    )
                if challenge.l2_explorer_created:
                    raise StateConflict(
                        "stagnation_explorer_limit",
                        "This stagnation episode already used its exploration Agent",
                    )
                challenge.l2_explorer_created = True
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "stagnation_explorer_reserved",
                    {"unique_code": unique_code},
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def grant_stagnation_extension(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext,
        payload: StagnationExtensionInput,
    ) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._authorize(session, context, roles={"chief"})
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.is_completed or challenge.work_status in {"closed", "paused"}:
                    raise StateConflict(
                        "stagnation_extension_not_allowed",
                        "Completed or paused challenges cannot be extended",
                    )
                if challenge.extension_cycle_pending:
                    raise StateConflict(
                        "stagnation_extension_used",
                        "Only one stagnation extension is allowed per episode",
                    )
                if not challenge_work_active(challenge):
                    raise StateConflict(
                        "stagnation_extension_not_allowed",
                        "The challenge container is not active",
                    )
                now = aware(self.clock())
                elapsed = active_seconds(
                    now=now,
                    active_since=challenge.active_since,
                    accumulated_seconds=challenge.exploration_seconds,
                )
                if elapsed < 8 * 60 or elapsed >= 20 * 60:
                    raise StateConflict(
                        "stagnation_extension_window",
                        "Extension is only available between 8 and 20 minutes",
                    )
                refs = set(payload.evidence_refs)
                valid = False
                if payload.reason == "high_probability_path":
                    rows = (
                        await session.scalars(
                            select(FindingRecord).where(
                                FindingRecord.run_id == run_id,
                                FindingRecord.unique_code == unique_code,
                                FindingRecord.finding_id.in_(refs),
                                FindingRecord.category.in_(["attack_path", "vulnerability"]),
                                FindingRecord.confidence >= 0.8,
                            )
                        )
                    ).all()
                    valid = any(item.evidence_paths for item in rows)
                elif payload.reason == "waiting_remote":
                    rows = (
                        await session.scalars(
                            select(OperationRecord).where(
                                OperationRecord.run_id == run_id,
                                OperationRecord.unique_code == unique_code,
                                OperationRecord.operation_id.in_(refs),
                                OperationRecord.status.in_(["started", "indeterminate"]),
                            )
                        )
                    ).all()
                    valid = bool(rows)
                else:
                    agents = (
                        await session.scalars(
                            select(AgentRecord).where(
                                AgentRecord.run_id == run_id,
                                AgentRecord.unique_code == unique_code,
                                AgentRecord.agent_id.in_(refs),
                                AgentRecord.role == "execution",
                                AgentRecord.status.in_(["running", "working"]),
                            )
                        )
                    ).all()
                    valid = any(
                        item.last_heartbeat_at is not None
                        and (now - aware(item.last_heartbeat_at)).total_seconds() <= 120
                        for item in agents
                    ) and any(
                        isinstance(event.payload, Mapping)
                        and int(event.payload.get("expected_result_seconds") or 999) <= 300
                        for event in (
                            await session.scalars(
                                select(StateEventRecord)
                                .where(
                                    StateEventRecord.run_id == run_id,
                                    StateEventRecord.event_type == "agent_progress",
                                    StateEventRecord.agent_id.in_(refs),
                                )
                                .order_by(StateEventRecord.sequence.desc())
                                .limit(20)
                            )
                        ).all()
                    )
                if not valid:
                    raise StateConflict(
                        "stagnation_extension_evidence_invalid",
                        "The supplied extension evidence does not meet the required threshold",
                    )
                challenge.extension_cycle_pending = True
                challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "stagnation_extension_granted",
                    {
                        "unique_code": unique_code,
                        "reason": payload.reason,
                        "evidence_refs": sorted(refs),
                        "elapsed_seconds": int(elapsed),
                        "expires_after_seconds": 20 * 60,
                    },
                    agent_id=context.agent_id,
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return {
            "unique_code": unique_code,
            "reason": payload.reason,
            "evidence_refs": sorted(refs),
            "expires_after_seconds": 20 * 60,
        }

    async def mark_operation_started(self, run_id: str, operation_type: str, *, agent_id: str | None = None, unique_code: str | None = None, arguments: Mapping[str, Any] | None = None) -> str:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                operation_id = f"operation_{uuid4().hex}"
                safe_arguments = redact_value(dict(arguments or {}))
                record = OperationRecord(
                    operation_id=operation_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    unique_code=unique_code,
                    operation_type=operation_type,
                    arguments_fingerprint=_fingerprint("operation", operation_type, safe_arguments),
                    request_payload=safe_arguments,
                    started_at=self.clock(),
                )
                session.add(record)
                record.started_sequence = await self._event(
                    session,
                    run_id,
                    "operation_started",
                    {"operation_id": operation_id, "operation_type": operation_type, "unique_code": unique_code},
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
                    raise StateNotFound("operation_not_found", "operation was not found")
                if operation.status == "indeterminate":
                    raise StateConflict("operation_indeterminate", "read-only synchronization is required before retry")
                operation.status = "completed"
                operation.result_code = result_code
                operation.result_payload = redact_value(dict(result_payload or {}))
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int((aware(operation.completed_at) - aware(operation.started_at)).total_seconds() * 1_000),
                )
                if operation.unique_code and challenge_updates:
                    changed_unique_code = operation.unique_code
                    challenge = await self._require_challenge(session, run_id, operation.unique_code)
                    progress_kind = self._apply_operation_challenge_updates(
                        challenge, challenge_updates
                    )
                    if progress_kind is not None:
                        self._mark_progress(challenge)
                        await self._event(
                            session,
                            run_id,
                            "stagnation_progress_recorded",
                            {
                                "unique_code": operation.unique_code,
                                "progress_kinds": [progress_kind],
                            },
                            agent_id=operation.agent_id,
                        )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    "operation_completed",
                    {"operation_id": operation_id, "result_code": result_code, "duration_ms": operation.duration_ms},
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
                    raise StateNotFound("operation_not_found", "operation was not found")
                if operation.status != "started":
                    raise StateConflict("operation_not_started", "operation is not active")
                operation.status = "failed"
                operation.error_code = error_code[:128]
                operation.error_message = error_message[:512]
                operation.result_payload = redact_value(dict(result_payload or {}))
                operation.completed_at = self.clock()
                operation.duration_ms = max(
                    0,
                    int((aware(operation.completed_at) - aware(operation.started_at)).total_seconds() * 1_000),
                )
                operation.completed_sequence = await self._event(
                    session,
                    run_id,
                    "operation_failed",
                    {"operation_id": operation_id, "error_code": operation.error_code, "duration_ms": operation.duration_ms},
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
                    raise StateNotFound("operation_not_found", "operation was not found")
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
                        (aware(operation.completed_at) - aware(operation.started_at)).total_seconds()
                        * 1_000
                    ),
                )
                event_type = "operation_reconciled" if resolved else "operation_reconcile_failed"
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
                operations = (await session.scalars(select(OperationRecord).where(OperationRecord.run_id == run_id, OperationRecord.status == "started"))).all()
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

    async def list_operations(self, run_id: str) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_run(session, run_id)
            rows = (
                await session.scalars(
                    select(OperationRecord)
                    .where(OperationRecord.run_id == run_id)
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

    async def evaluate_hint_admission(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext,
        *,
        basis: str,
        evidence_refs: list[str],
    ) -> dict[str, Any]:
        """Evaluate every Hint prerequisite in one authoritative read transaction.

        This method intentionally has no mutation side effects.  The caller
        holds the per-challenge Hint lock while it invokes Benchmark, so a
        rejected evaluation cannot create a Hint marker or an operation.
        """

        result: dict[str, Any] = {
            "eligible": False,
            "basis": basis,
            "remaining_run_seconds": 0,
            "remaining_stagnation_seconds": 0,
            "active_execution_count": 0,
            "active_resource_work_count": 0,
            "rejection_code": None,
        }

        async with self.db.sessions() as session:
            await self._authorize(session, context, roles={"chief"})
            run = await self._require_run(session, run_id)
            challenge = await self._require_challenge(session, run_id, unique_code)
            now = aware(self.clock())
            result["remaining_run_seconds"] = max(
                0, int((aware(run.deadline_at) - now).total_seconds())
            )

            elapsed = active_seconds(
                now=now,
                active_since=challenge.active_since,
                accumulated_seconds=challenge.exploration_seconds,
            )
            result["remaining_stagnation_seconds"] = max(
                0, HINT_STAGNATION_PAUSE_SECONDS - elapsed
            )

            # Load all challenge/execution owners once so resource work can be
            # attributed both to the requested challenge and to the full-run
            # near-deadline convergence check.
            agent_rows = list(
                (
                    await session.scalars(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.role.in_(["challenge", "execution"]),
                        )
                    )
                ).all()
            )
            agents_by_code: dict[str, list[AgentRecord]] = {}
            agent_code_by_id: dict[str, str] = {}
            for agent in agent_rows:
                if agent.unique_code:
                    agents_by_code.setdefault(agent.unique_code, []).append(agent)
                    agent_code_by_id[agent.agent_id] = agent.unique_code

            target_agents = agents_by_code.get(unique_code, [])
            result["active_execution_count"] = sum(
                1
                for agent in target_agents
                if agent.role == "execution"
                and agent.status not in HINT_TERMINAL_AGENT_STATES
            )

            # The four task families have different status columns.  Treat an
            # in-progress analysis as active HTTP work even when execution has
            # already completed; a Hint must not race the result pipeline.
            shell_rows = list(
                (
                    await session.scalars(
                        select(ShellTaskRecord).where(
                            ShellTaskRecord.run_id == run_id,
                            ShellTaskRecord.status.in_(HINT_ACTIVE_STATUSES),
                        )
                    )
                ).all()
            )
            network_rows = list(
                (
                    await session.scalars(
                        select(NetworkTaskRecord).where(
                            NetworkTaskRecord.run_id == run_id,
                        )
                    )
                ).all()
            )
            http_rows = list(
                (
                    await session.scalars(
                        select(HttpInteractionRecord).where(
                            HttpInteractionRecord.run_id == run_id,
                        )
                    )
                ).all()
            )
            resource_rows = list(
                (
                    await session.scalars(
                        select(ResourceWorkRecord).where(
                            ResourceWorkRecord.run_id == run_id,
                            ResourceWorkRecord.status.in_(HINT_ACTIVE_STATUSES),
                        )
                    )
                ).all()
            )

            active_task_code_counts: dict[str, int] = {}

            def add_active_task(agent_id: str) -> None:
                code = agent_code_by_id.get(agent_id)
                if code is None:
                    return
                active_task_code_counts[code] = active_task_code_counts.get(code, 0) + 1

            for row in shell_rows:
                add_active_task(row.agent_id)
            for row in network_rows:
                if row.status in HINT_ACTIVE_STATUSES or row.resource_status in HINT_ACTIVE_STATUSES:
                    add_active_task(row.agent_id)
            for row in http_rows:
                if any(
                    value in HINT_ACTIVE_STATUSES
                    for value in (
                        row.status,
                        row.execution_status,
                        row.analysis_status,
                        row.resource_status,
                    )
                ):
                    add_active_task(row.agent_id)
            for row in resource_rows:
                add_active_task(row.agent_id)

            # Count separate records, not distinct owners, for the public
            # diagnostic value.  The per-code map is restricted to known
            # challenge/execution owners, preserving Run/Challenge isolation.
            result["active_resource_work_count"] = active_task_code_counts.get(
                unique_code, 0
            )

            def reject(code: str) -> dict[str, Any]:
                result["rejection_code"] = code
                return result

            if run.status != "active":
                return reject("run_not_active")
            if challenge.is_completed or challenge.work_status in {"closed", "paused"}:
                return reject("challenge_not_active")
            if not container_slot_occupied(challenge.container_status):
                return reject("challenge_slot_released")
            if challenge.work_status != "warning":
                return reject("challenge_not_warning")
            if not challenge.hint_eligible:
                return reject("hint_not_eligible")
            if challenge.stagnation_level != 1:
                return reject("stagnation_level_required")
            if challenge.hint_requested:
                return reject("hint_already_requested")
            if result["active_execution_count"]:
                return reject("execution_active")
            if result["active_resource_work_count"]:
                return reject("resource_work_active")
            if result["remaining_stagnation_seconds"] < HINT_MIN_ACTION_WINDOW_SECONDS:
                return reject("insufficient_stagnation_window")
            if not evidence_refs:
                return reject("evidence_required")

            latest = await session.scalar(
                select(ReportRecord)
                .where(
                    ReportRecord.run_id == run_id,
                    ReportRecord.parent_id == context.agent_id,
                    ReportRecord.unique_code == unique_code,
                    ReportRecord.report_type == "challenge_status",
                )
                .order_by(ReportRecord.sequence.desc())
                .limit(1)
            )
            if latest is None or latest.status != "ready_for_hint":
                return reject("status_report_not_ready")
            if (
                challenge.control_since is not None
                and aware(latest.created_at) < aware(challenge.control_since)
            ):
                return reject("status_report_stale")
            payload = latest.payload if isinstance(latest.payload, Mapping) else {}
            if not bool(payload.get("hint_recommended")):
                return reject("hint_not_recommended")
            if not str(payload.get("blocker") or "").strip():
                return reject("blocker_required")
            report_refs = {
                str(value).strip()
                for value in (payload.get("evidence_refs") or [])
                if str(value).strip()
            }
            requested_refs = {str(value).strip() for value in evidence_refs if str(value).strip()}
            if not requested_refs:
                return reject("evidence_required")
            if not requested_refs.issubset(report_refs):
                return reject("evidence_not_in_status_report")

            for reference in requested_refs:
                kind, separator, identifier = reference.partition(":")
                if not separator or kind not in {"report", "finding", "observation"} or not identifier:
                    return reject("invalid_evidence_ref")
                if kind == "report":
                    record = await session.get(ReportRecord, identifier)
                    valid = record is not None and record.run_id == run_id and record.unique_code == unique_code
                elif kind == "finding":
                    record = await session.get(FindingRecord, identifier)
                    valid = record is not None and record.run_id == run_id and record.unique_code == unique_code
                else:
                    record = await session.get(ObservationRecord, identifier)
                    valid = record is not None and record.run_id == run_id and record.unique_code == unique_code
                if not valid:
                    return reject("evidence_not_found")

            if basis == "high_probability_path":
                if run.pass_number != 1:
                    return reject("high_probability_path_first_pass_only")
            elif basis == "second_pass_convergence":
                if run.pass_number != 2:
                    return reject("second_pass_required")
            elif basis == "near_deadline":
                if result["remaining_run_seconds"] > HINT_NEAR_DEADLINE_SECONDS:
                    return reject("near_deadline_required")
                all_challenges = list(
                    (
                        await session.scalars(
                            select(ChallengeRecord).where(ChallengeRecord.run_id == run_id)
                        )
                    ).all()
                )
                for other in all_challenges:
                    if other.unique_code == unique_code or other.is_completed or other.work_status == "closed":
                        continue
                    other_agents = agents_by_code.get(other.unique_code, [])
                    other_active_execution = any(
                        agent.role == "execution" and agent.status not in HINT_TERMINAL_AGENT_STATES
                        for agent in other_agents
                    )
                    if other_active_execution or active_task_code_counts.get(other.unique_code, 0):
                        return reject("global_convergence_required")
                    if other.work_status not in {"warning", "paused"}:
                        return reject("global_convergence_required")
            else:
                return reject("invalid_basis")

            result["eligible"] = True
            return result

    async def sample_resources(self, run_id: str, cpu_percent: float, memory_percent: float) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                record = ResourceSampleRecord(run_id=run_id, cpu_percent=cpu_percent, memory_percent=memory_percent, sampled_at=self.clock())
                session.add(record)
        return {"cpu_percent": cpu_percent, "memory_percent": memory_percent, "sampled_at": _json_value(record.sampled_at)}

    async def project_pending_events(self, run_id: str, *, run_dir: Path | None = None, limit: int = 100) -> int:
        target_dir = run_dir or (self.run_root / run_id if self.run_root else self.db.path.parent)
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
                            "".join(self._encode_state_event(item) for item in all_events),
                        )
                        projection_sequence = all_events[-1].sequence if all_events else 0
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
                    if any(item.sequence != expected + index for index, item in enumerate(new_events)):
                        raise RuntimeError("state event projection sequence is not continuous")
                metadata_missing = not all(
                    (target_dir / name).is_file()
                    for name in ("events.jsonl", "checkpoint.json", "manifest.json")
                )
                if not pending and not new_events and not metadata_missing:
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
                async with self.db.sessions() as session:
                    await self._write_checkpoint(session, run_id, target_dir)
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

    async def _confirm_projection(self, run_id: str, sequence: int) -> None:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                run.last_projected_sequence = max(
                    run.last_projected_sequence, sequence
                )
                await session.execute(
                    delete(AuditOutboxRecord).where(
                        AuditOutboxRecord.run_id == run_id,
                        AuditOutboxRecord.sequence <= sequence,
                    )
                )

    @staticmethod
    def _encode_state_event(item: StateEventRecord) -> str:
        return json.dumps(
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
        ) + "\n"

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
                    if value.get("run_id") != run_id or value.get("sequence") != expected:
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

    async def _record_findings(
        self,
        session: Any,
        run_id: str,
        unique_code: str | None,
        agent_id: str | None,
        values: Iterable[FindingInput],
        *,
        count_candidate_attack_paths: bool = False,
    ) -> tuple[bool, list[dict[str, Any]]]:
        if not unique_code:
            return False, []
        added: list[dict[str, Any]] = []
        valid_progress = False
        challenge = await self._require_challenge(session, run_id, unique_code)
        for value in values:
            self._validate_evidence_paths(run_id, unique_code, value.evidence_paths)
            fingerprint = _fingerprint(value.category, value.summary, value.detail)
            summary = value.summary
            detail = value.detail
            if value.category == "flag":
                raw_candidate = json.dumps(
                    {"summary": value.summary, "detail": value.detail},
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                )
                summary = "Flag candidate"
                detail = {
                    "sha256": fingerprint_secret(raw_candidate),
                    "length": len(raw_candidate),
                }
            existing = await session.scalar(select(FindingRecord).where(FindingRecord.run_id == run_id, FindingRecord.unique_code == unique_code, FindingRecord.category == value.category, FindingRecord.fingerprint == fingerprint))
            now = self.clock()
            if existing is None:
                record = FindingRecord(
                    finding_id=f"finding_{uuid4().hex}", run_id=run_id, unique_code=unique_code,
                    agent_id=agent_id, category=value.category, fingerprint=fingerprint,
                    summary=summary, detail=detail, confidence=value.confidence,
                    verification_status=value.verification_status, evidence_paths=value.evidence_paths,
                    first_seen_at=now, last_seen_at=now,
                    verified_at=now if value.verification_status == "verified" else None,
                )
                session.add(record)
                existing = record
                await self._record_observation_locked(
                    session,
                    run_id,
                    unique_code,
                    category=value.category,
                    fingerprint=fingerprint,
                    summary=summary,
                    detail=detail,
                    source="finding",
                    source_ref=record.finding_id,
                    confidence=value.confidence,
                    challenge=challenge,
                )
                if value.verification_status == "verified" and value.evidence_paths:
                    valid_progress = True
                elif (
                    count_candidate_attack_paths
                    and value.category == "attack_path"
                    and value.evidence_paths
                    and value.detail.get("verification_steps")
                ):
                    valid_progress = True
            else:
                existing.last_seen_at = now
                existing.confidence = max(existing.confidence, value.confidence)
                existing.evidence_paths = list(dict.fromkeys([*existing.evidence_paths, *value.evidence_paths]))
                if existing.verification_status != "verified" and value.verification_status == "verified":
                    existing.verification_status = "verified"
                    existing.verified_at = now
                    existing.version += 1
                    if existing.evidence_paths:
                        valid_progress = True
            added.append(self._finding_dict(existing))
        return valid_progress, added

    async def _record_credential(self, session: Any, run_id: str, unique_code: str, finding_id: str | None, value: Any) -> CredentialRecord:
        record = CredentialRecord(credential_id=f"credential_{uuid4().hex}", run_id=run_id, unique_code=unique_code, finding_id=finding_id, kind=value.kind, principal=value.principal, secret_value=value.secret_value, scope=value.scope, verified=value.verified)
        session.add(record)
        return record

    async def _snapshot(self, session: Any, challenge: ChallengeRecord) -> dict[str, Any]:
        findings = (await session.scalars(select(FindingRecord).where(FindingRecord.run_id == challenge.run_id, FindingRecord.unique_code == challenge.unique_code))).all()
        agents = (await session.scalars(select(AgentRecord).where(AgentRecord.run_id == challenge.run_id, AgentRecord.unique_code == challenge.unique_code))).all()
        return {"challenge": self._challenge_dict(challenge), "findings": [self._finding_dict(item) for item in findings], "agents": [self._agent_dict(item) for item in agents]}

    async def _event(
        self,
        session: Any,
        run_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        agent_id: str | None = None,
        cycle_id: str | None = None,
    ) -> int:
        sequence = await self._next_sequence(session, run_id)
        await self._event_with_sequence(
            session,
            run_id,
            sequence,
            event_type,
            payload,
            agent_id=agent_id,
            cycle_id=cycle_id,
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
        cycle_id: str | None = None,
    ) -> None:
        safe_payload = _json_value(
            redact_value(dict(payload), secrets=self.ephemeral_secrets())
        )
        session.add(StateEventRecord(event_id=f"event_{uuid4().hex}", run_id=run_id, sequence=sequence, agent_id=agent_id, cycle_id=cycle_id, event_type=event_type, payload=safe_payload))
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

    async def _require_run(self, session: Any, run_id: str) -> RunRecord:
        run = await session.get(RunRecord, run_id)
        if run is None:
            raise StateNotFound("run_not_found", "run was not found")
        run.phase = derive_phase(run.started_at, run.deadline_at, self.clock())
        return run

    async def _require_challenge(self, session: Any, run_id: str, unique_code: str) -> ChallengeRecord:
        challenge = await session.get(ChallengeRecord, (run_id, unique_code))
        if challenge is None:
            raise StateNotFound("challenge_not_found", "challenge was not found")
        return challenge

    async def _require_cycle(self, session: Any, run_id: str, cycle_id: str) -> CycleRecord:
        cycle = await session.get(CycleRecord, cycle_id)
        if cycle is None or cycle.run_id != run_id:
            raise StateNotFound("cycle_not_found", "cycle was not found")
        return cycle

    async def _authorize(self, session: Any, context: CapabilityContext, *, roles: set[str], agent_id: str | None = None, unique_code: str | None = None) -> AgentRecord:
        if context.role not in roles:
            raise StatePermission("role_not_allowed", "Agent role is not allowed for this operation")
        if agent_id is not None and context.agent_id != agent_id:
            raise StatePermission("agent_mismatch", "capability is not bound to this Agent")
        agent = await session.get(AgentRecord, context.agent_id)
        if agent is None or agent.run_id != context.run_id:
            raise StatePermission("invalid_capability", "capability is not valid for this run")
        if agent.role != context.role:
            raise StatePermission("invalid_capability", "capability role does not match Agent")
        if unique_code is not None and agent.role != "chief" and agent.unique_code != unique_code:
            raise StatePermission("challenge_binding_required", "Agent is bound to another challenge")
        return agent

    @staticmethod
    def _check_version(current: int, expected: int) -> None:
        if current != expected:
            raise StateConflict("state_conflict", "state version is stale", {"current_version": current})

    def _mark_progress(self, challenge: ChallengeRecord) -> None:
        now = self.clock()
        challenge.exploration_seconds = 0
        challenge.last_progress_at = now
        challenge.stagnation_level = 0
        challenge.hint_eligible = False
        challenge.work_status = "completed" if challenge.is_completed else "active"
        challenge.l2_explorer_created = False
        challenge.extension_cycle_pending = False
        challenge.control_state = "ok"
        challenge.control_since = None
        challenge.pause_reason = None
        challenge.version += 1
        if container_slot_occupied(challenge.container_status):
            challenge.active_since = now

    def _freeze_exploration(self, challenge: ChallengeRecord) -> None:
        now = self.clock()
        challenge.exploration_seconds = active_seconds(now=now, active_since=challenge.active_since, accumulated_seconds=challenge.exploration_seconds)
        challenge.active_since = None

    @staticmethod
    def _target_fingerprint(challenge: ChallengeRecord) -> str:
        addrs = sorted(str(item) for item in (challenge.container_addr or []))
        raw = json.dumps(addrs, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _ensure_evidence_root(self, challenge: ChallengeRecord) -> str:
        if not challenge.evidence_root:
            challenge.evidence_root = (
                f"challenges/{challenge.unique_code}/evidence/"
                f"{self._target_fingerprint(challenge)}"
            )
        return challenge.evidence_root

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

    async def _upsert_hypothesis(
        self,
        session: Any,
        *,
        run_id: str,
        unique_code: str,
        hypothesis: Any | None,
        created_by: str | None = None,
        status: str = "active",
    ) -> bool:
        if hypothesis is None:
            return False
        existing = await session.get(
            HypothesisRecord, (run_id, unique_code, hypothesis.key)
        )
        now = self.clock()
        if existing is not None:
            existing.statement = hypothesis.statement
            existing.confidence = hypothesis.confidence
            existing.based_on_observations = sorted(
                set(
                    [
                        *existing.based_on_observations,
                        *hypothesis.based_on_observations,
                    ]
                )
            )
            if status == "active" and existing.status in {"proposed", "active"}:
                existing.status = status
            existing.updated_at = now
            existing.version += 1
            return False
        session.add(
            HypothesisRecord(
                run_id=run_id,
                unique_code=unique_code,
                hypothesis_key=hypothesis.key,
                statement=hypothesis.statement,
                confidence=hypothesis.confidence,
                based_on_observations=sorted(hypothesis.based_on_observations),
                status=status,
                created_by=created_by,
                created_at=now,
                updated_at=now,
            )
        )
        return True

    async def _upsert_branch(
        self,
        session: Any,
        *,
        run_id: str,
        unique_code: str,
        branch_key: str,
        hypothesis_key: str | None,
        kind: str,
        priority: int,
        mission: str | None,
        agent_id: str | None = None,
        status: str = "proposed",
    ) -> bool:
        challenge = await self._require_challenge(session, run_id, unique_code)
        target = self._target_fingerprint(challenge)
        existing = await session.get(
            ExecutionBranchRecord, (run_id, unique_code, branch_key)
        )
        now = self.clock()
        if existing is not None:
            if agent_id and agent_id not in (existing.agent_ids or []):
                existing.agent_ids = [*existing.agent_ids, agent_id]
            if status == "queued" and existing.status in {"proposed", "queued"}:
                existing.status = status
            if priority > existing.priority:
                existing.priority = priority
            if mission:
                existing.mission = mission
            existing.updated_at = now
            existing.version += 1
            return False
        session.add(
            ExecutionBranchRecord(
                run_id=run_id,
                unique_code=unique_code,
                branch_key=branch_key,
                target_fingerprint=target,
                hypothesis_key=hypothesis_key,
                kind=kind,
                status=status,
                priority=priority,
                mission=mission,
                agent_ids=[agent_id] if agent_id else [],
                created_at=now,
                updated_at=now,
            )
        )
        return True

    async def _cancel_sibling_branches(
        self,
        session: Any,
        run_id: str,
        unique_code: str,
        *,
        except_branch: str | None,
    ) -> list[str]:
        rows = list(
            (
                await session.scalars(
                    select(ExecutionBranchRecord).where(
                        ExecutionBranchRecord.run_id == run_id,
                        ExecutionBranchRecord.unique_code == unique_code,
                        ExecutionBranchRecord.status.in_(
                            ["proposed", "queued", "running"]
                        ),
                    )
                )
            ).all()
        )
        cancelled: list[str] = []
        now = self.clock()
        for branch in rows:
            if branch.branch_key == except_branch:
                continue
            branch.status = "superseded"
            branch.outcome = {
                **branch.outcome,
                "cancelled_at": _json_value(now),
                "reason": "sibling_success",
            }
            branch.updated_at = now
            branch.version += 1
            cancelled.append(branch.branch_key)
        return cancelled

    def _validate_evidence_paths(
        self, run_id: str, unique_code: str, paths: Iterable[str]
    ) -> None:
        """Reject evidence paths that escape the challenge evidence directory."""

        for raw in paths:
            path = str(raw or "")
            if not path or "://" in path:
                continue
            value = Path(path)
            if value.is_absolute():
                if self.run_root is None:
                    continue
                evidence_root = (
                    self.run_root / run_id / "challenges" / unique_code / "evidence"
                ).resolve()
                if not value.resolve().is_relative_to(evidence_root):
                    raise StateError(
                        "invalid_evidence_path",
                        "evidence path must be inside the challenge evidence directory",
                        status_code=422,
                    )
            elif ".." in value.parts:
                raise StateError(
                    "invalid_evidence_path",
                    "evidence path must not traverse outside the challenge evidence directory",
                    status_code=422,
                )

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
        mark_progress: bool = True,
    ) -> dict[str, Any]:
        """Persist one deduplicated Observation and route capability branches."""

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
                branch_keys: list[str] = []
                if created:
                    routes = routes_for_observation(
                        {
                            "category": category,
                            "summary": summary,
                            "detail": detail or {},
                        }
                    )
                    for route in routes:
                        added = await self._upsert_branch(
                            session,
                            run_id=run_id,
                            unique_code=unique_code,
                            branch_key=route.branch_key,
                            hypothesis_key=None,
                            kind=route.kind,
                            priority=route.priority,
                            mission=route.mission,
                            status="proposed",
                        )
                        if added:
                            branch_keys.append(route.branch_key)
        if created and event_sequence is not None:
            await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return {
            "observation_id": observation_id,
            "created": created,
            "fingerprint": fingerprint,
            "branches_created": branch_keys,
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

    async def list_hypotheses(
        self, run_id: str, unique_code: str
    ) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_challenge(session, run_id, unique_code)
            rows = (
                await session.scalars(
                    select(HypothesisRecord)
                    .where(
                        HypothesisRecord.run_id == run_id,
                        HypothesisRecord.unique_code == unique_code,
                    )
                    .order_by(HypothesisRecord.created_at)
                )
            ).all()
            return [
                {
                    "hypothesis_key": item.hypothesis_key,
                    "statement": item.statement,
                    "confidence": item.confidence,
                    "based_on_observations": item.based_on_observations,
                    "status": item.status,
                    "created_by": item.created_by,
                    "updated_at": _json_value(item.updated_at),
                    "version": item.version,
                }
                for item in rows
            ]

    async def list_branches(
        self, run_id: str, unique_code: str
    ) -> list[dict[str, Any]]:
        async with self.db.sessions() as session:
            await self._require_challenge(session, run_id, unique_code)
            rows = (
                await session.scalars(
                    select(ExecutionBranchRecord)
                    .where(
                        ExecutionBranchRecord.run_id == run_id,
                        ExecutionBranchRecord.unique_code == unique_code,
                    )
                    .order_by(ExecutionBranchRecord.priority.desc())
                )
            ).all()
            return [
                {
                    "branch_key": item.branch_key,
                    "target_fingerprint": item.target_fingerprint,
                    "hypothesis_key": item.hypothesis_key,
                    "kind": item.kind,
                    "status": item.status,
                    "priority": item.priority,
                    "mission": item.mission,
                    "agent_ids": item.agent_ids,
                    "outcome": item.outcome,
                    "updated_at": _json_value(item.updated_at),
                    "version": item.version,
                }
                for item in rows
            ]

    async def cancel_challenge_branches(
        self,
        run_id: str,
        unique_code: str,
        *,
        reason: str = "challenge_completed",
    ) -> list[str]:
        """Mark every live branch of one challenge as superseded."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_challenge(session, run_id, unique_code)
                return await self._cancel_sibling_branches(
                    session,
                    run_id,
                    unique_code,
                    except_branch=None,
                )

    async def set_challenge_control_state(
        self,
        run_id: str,
        unique_code: str,
        control_state: str,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        if control_state not in CHALLENGE_CONTROL_STATE_VALUES:
            raise StateError(
                "invalid_control_state",
                "unknown challenge control state",
                status_code=422,
            )
        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                if (
                    challenge.is_completed
                    or challenge.work_status in {"paused", "closed", "completed"}
                ):
                    raise StateConflict(
                        "challenge_not_active",
                        "The challenge no longer accepts control state changes",
                    )
                now = self.clock()
                changed = challenge.control_state != control_state
                if changed:
                    challenge.control_state = control_state
                    if control_state == "ok":
                        challenge.control_since = None
                        challenge.active_since = now
                    else:
                        challenge.control_since = now
                        if control_state == "waiting_external_change":
                            self._freeze_exploration(challenge)
                    challenge.version += 1
                event_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_control_state_changed",
                    {
                        "unique_code": unique_code,
                        "control_state": control_state,
                        "reason": reason,
                    },
                )
        await self.signal_challenge_changes(run_id, [unique_code], event_sequence)
        return self._challenge_dict(challenge)

    async def second_pass_ready(
        self,
        run_id: str,
        *,
        min_remaining_seconds: int = 30 * 60,
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
            run = await self._require_run(session, run_id)
            if run.status != "active" or run.pass_number >= 2:
                return {"ready": False, "reason": "pass_limit"}
            remaining = int(
                (
                    aware(run.deadline_at) - aware(self.clock())
                ).total_seconds()
            )
            challenges = list(
                (
                    await session.scalars(
                        select(ChallengeRecord).where(
                            ChallengeRecord.run_id == run_id
                        )
                    )
                ).all()
            )
            paused = [
                item.unique_code
                for item in challenges
                if item.work_status == "paused" and not item.is_completed
            ]
            if not paused:
                return {"ready": False, "reason": "no_paused_challenges"}
            if remaining < min_remaining_seconds:
                return {
                    "ready": False,
                    "reason": "insufficient_remaining_time",
                    "remaining_seconds": remaining,
                }
            return {
                "ready": True,
                "reason": "first_pass_complete",
                "unique_codes": sorted(paused),
                "remaining_seconds": remaining,
            }

    async def begin_second_pass(self, run_id: str) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                run = await self._require_run(session, run_id)
                if run.status != "active":
                    raise StateConflict(
                        "run_not_active", "Second pass requires an active Run"
                    )
                if run.pass_number >= 2:
                    return {"started": False, "unique_codes": []}
                challenges = list(
                    (
                        await session.scalars(
                            select(ChallengeRecord).where(
                                ChallengeRecord.run_id == run_id
                            )
                        )
                    ).all()
                )
                paused = [
                    item
                    for item in challenges
                    if item.work_status == "paused" and not item.is_completed
                ]
                codes = sorted(item.unique_code for item in paused)
                now = self.clock()
                for challenge in paused:
                    challenge.pass_number = 2
                    challenge.resume_count += 1
                    challenge.stagnation_level = 0
                    challenge.extension_cycle_pending = False
                    challenge.l2_explorer_created = False
                    challenge.control_state = "ok"
                    challenge.control_since = None
                    challenge.pause_reason = None
                    challenge.work_status = "unassigned"
                    challenge.platform_status = "pending"
                    challenge.updated_at = now
                    challenge.version += 1
                run.pass_number = 2
                event_sequence = await self._event(
                    session,
                    run_id,
                    "second_pass_began",
                    {
                        "unique_codes": codes,
                        "resume_count": sum(item.resume_count for item in paused),
                    },
                )
        if event_sequence is not None:
            await self.signal_challenge_changes(run_id, codes, event_sequence)
        return {
            "started": bool(codes),
            "unique_codes": codes,
            "run": self._run_dict(run),
        }

    @staticmethod
    def _challenge_from_import(run_id: str, value: ChallengeImport, *, now: datetime | None = None) -> ChallengeRecord:
        record = ChallengeRecord(run_id=run_id, unique_code=value.unique_code)
        StateService._apply_challenge_import(record, value)
        if now is not None:
            record.created_at = now
        return record

    @staticmethod
    def _apply_challenge_import(record: ChallengeRecord, value: ChallengeImport) -> None:
        record.description = value.description
        record.difficulty = value.difficulty
        record.level = value.level
        record.total_score = value.total_score
        record.flag_count = value.flag_count
        record.correct_flag_count = value.correct_flag_count
        record.is_completed = value.is_completed
        if value.is_completed:
            record.container_status = value.container_status
            record.platform_status = "completed"
            record.work_status = "completed"
            record.control_state = "ok"
            record.control_since = None
            record.pause_reason = None
        elif value.container_status in {"starting", "running", "active"}:
            record.container_status = "running" if value.container_status == "active" else value.container_status
            record.platform_status = "started"
            if record.work_status in {"completed", "closed", "unassigned"}:
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
        return {"run_id": item.run_id, "status": item.status, "phase": item.phase, "pass_number": item.pass_number, "model": item.model, "prompt": item.prompt, "context_window_tokens": item.context_window_tokens, "duration_minutes": item.duration_minutes, "started_at": _json_value(item.started_at), "deadline_at": _json_value(item.deadline_at), "current_challenge_code": item.current_challenge_code, "score_snapshot": item.score_snapshot, "last_sequence": item.last_sequence, "last_projected_sequence": item.last_projected_sequence, "stagnation_epoch": item.stagnation_epoch, "paused_at": _json_value(item.paused_at), "pause_reason": item.pause_reason}

    @staticmethod
    def _challenge_dict(item: ChallengeRecord) -> dict[str, Any]:
        return {"run_id": item.run_id, "unique_code": item.unique_code, "description": item.description, "difficulty": item.difficulty, "level": item.level, "total_score": item.total_score, "flag_count": item.flag_count, "correct_flag_count": item.correct_flag_count, "is_completed": item.is_completed, "platform_status": item.platform_status, "container_status": item.container_status, "slot_occupied": container_slot_occupied(item.container_status), "container_addr": item.container_addr, "work_status": item.work_status, "control_state": item.control_state, "control_since": _json_value(item.control_since), "pause_reason": item.pause_reason, "pass_number": item.pass_number, "resume_count": item.resume_count, "evidence_root": item.evidence_root, "stagnation_level": item.stagnation_level, "hint_eligible": item.hint_eligible, "hint_requested": item.hint_requested, "l2_explorer_created": item.l2_explorer_created, "extension_active": item.extension_cycle_pending, "exploration_seconds": item.exploration_seconds, "active_since": _json_value(item.active_since), "last_progress_at": _json_value(item.last_progress_at), "version": item.version}

    @staticmethod
    def _agent_dict(item: AgentRecord, *, include_runtime: bool = False) -> dict[str, Any]:
        data = {"agent_id": item.agent_id, "run_id": item.run_id, "parent_id": item.parent_id, "unique_code": item.unique_code, "cycle_id": item.cycle_id, "role": item.role, "kind": item.kind, "priority": item.priority, "mission": item.mission, "success_criteria": item.success_criteria, "context_refs": item.context_refs, "hypothesis_key": item.hypothesis_key, "task_key": item.task_key, "branch_key": item.branch_key, "terminal_report_id": item.terminal_report_id, "status": item.status, "timeout_seconds": item.timeout_seconds, "last_heartbeat_at": _json_value(item.last_heartbeat_at), "last_report_sequence": item.last_report_sequence, "report_cursor": item.report_cursor, "report_cursors": item.report_cursors, "controller_cursor": item.controller_cursor, "last_summarized_sequence": item.last_summarized_sequence, "started_at": _json_value(item.started_at), "ended_at": _json_value(item.ended_at), "stop_requested_at": _json_value(item.stop_requested_at), "updated_at": _json_value(item.updated_at), "version": item.version}
        if include_runtime:
            data.update({"initial_prompt": item.initial_prompt, "session_memory": item.session_memory, "final_report": item.final_report})
        return data

    @staticmethod
    def _cycle_dict(item: CycleRecord) -> dict[str, Any]:
        return {"cycle_id": item.cycle_id, "run_id": item.run_id, "unique_code": item.unique_code, "cycle_number": item.cycle_number, "status": item.status, "state_snapshot": item.state_snapshot, "analysis": item.analysis, "plan": item.plan, "verification": item.verification, "state_update": item.state_update, "version": item.version, "state_at": _json_value(item.state_at), "analysis_at": _json_value(item.analysis_at), "plan_at": _json_value(item.plan_at), "execute_at": _json_value(item.execute_at), "verify_at": _json_value(item.verify_at), "update_at": _json_value(item.update_at), "completed_at": _json_value(item.completed_at)}

    @staticmethod
    def _finding_dict(item: FindingRecord) -> dict[str, Any]:
        return {"finding_id": item.finding_id, "unique_code": item.unique_code, "category": item.category, "fingerprint": item.fingerprint, "summary": item.summary, "detail": item.detail, "confidence": item.confidence, "verification_status": item.verification_status, "evidence_paths": item.evidence_paths, "version": item.version}

    @staticmethod
    def _credential_dict(item: CredentialRecord, *, include_secret: bool) -> dict[str, Any]:
        data = {"credential_id": item.credential_id, "unique_code": item.unique_code, "finding_id": item.finding_id, "kind": item.kind, "principal": item.principal, "scope": item.scope, "verified": item.verified}
        if include_secret:
            data["secret_value"] = item.secret_value
        return data

    @staticmethod
    def _report_dict(item: ReportRecord) -> dict[str, Any]:
        return {"report_id": item.report_id, "sequence": item.sequence, "agent_id": item.agent_id, "parent_id": item.parent_id, "unique_code": item.unique_code, "report_type": item.report_type, "status": item.status, "payload": item.payload, "created_at": _json_value(item.created_at)}

    def _report_with_ephemeral(self, item: ReportRecord) -> dict[str, Any]:
        data = self._report_dict(item)
        candidate = self._ephemeral_reports.get(item.report_id)
        if candidate is not None:
            data["payload"] = {**data["payload"], "candidate_flag": candidate}
        return data

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
        if (
            work_status is not None
            and work_status not in CHALLENGE_WORK_STATUS_VALUES
        ):
            raise StateError(
                "invalid_challenge_work_status",
                "Challenge work status is invalid",
                status_code=422,
            )
        for field in (
            "platform_status", "container_status", "work_status",
            "hint_requested", "flag_count", "correct_flag_count", "is_completed",
        ):
            if field in updates:
                setattr(challenge, field, updates[field])
        if "container_addr" in updates:
            challenge.container_addr = list(updates["container_addr"] or [])
        if challenge.container_status in {"stopped", "closed"}:
            self._freeze_exploration(challenge)
            challenge.active_since = None
            challenge.paused_at = self.clock()
        elif (
            container_slot_occupied(challenge.container_status)
            and not container_slot_occupied(previous_container_status)
        ):
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

    async def _write_checkpoint(self, session: Any, run_id: str, target_dir: Path) -> None:
        run = await self._require_run(session, run_id)
        challenges = (await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id))).all()
        agents = (await session.scalars(select(AgentRecord).where(AgentRecord.run_id == run_id))).all()
        targets = [
            TargetState(
                unique_code=item.unique_code,
                status=checkpoint_target_status(self._challenge_dict(item)),
                is_completed=item.is_completed,
                work_status=item.work_status,
                container_status=item.container_status,
                slot_occupied=container_slot_occupied(item.container_status),
                container_addr=item.container_addr,
                score_snapshot={"correct_flag_count": item.correct_flag_count, "flag_count": item.flag_count, "total_score": item.total_score},
                last_event_sequence=run.last_sequence,
            ).model_dump(mode="json")
            for item in challenges
        ]
        legacy_status = {
            "queued": "pending",
            "starting": "pending",
            "working": "running",
            "blocked": "running",
            "stopping": "running",
            "cancelled": "stopped",
        }
        agent_nodes = [
            AgentNode(
                agent_id=item.agent_id,
                role=item.role,  # type: ignore[arg-type]
                parent_id=item.parent_id,
                unique_code=item.unique_code,
                status=legacy_status.get(item.status, item.status),  # type: ignore[arg-type]
                sidecar_path=str(target_dir / "agents" / item.agent_id),
                mission=item.mission,
                timeout_seconds=item.timeout_seconds,
                report_count=1 if item.last_report_sequence else 0,
                last_report_sequence=item.last_report_sequence,
                started_at=aware(item.started_at or self.clock()),
                updated_at=aware(item.updated_at or self.clock()),
            ).model_dump(mode="json")
            for item in agents
        ]
        checkpoint = Checkpoint(
            run_id=run_id,
            status=run.status,  # type: ignore[arg-type]
            phase=run.phase,
            targets=[TargetState.model_validate(item) for item in targets],
            container_capacity=container_capacity_summary(
                [self._challenge_dict(item) for item in challenges]
            ),
            current_target=run.current_challenge_code,
            score_snapshot=run.score_snapshot,
            last_event_sequence=run.last_sequence,
            agents=[AgentNode.model_validate(item) for item in agent_nodes],
            updated_at=aware(self.clock()),
        ).model_dump(mode="json")
        chief = next((item for item in agents if item.role == "chief"), None)
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "model": run.model or "unknown",
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
        if chief is not None:
            await self._write_text_atomic(target_dir / "session_memory.md", chief.session_memory)
            if chief.final_report:
                await self._write_json_atomic(target_dir / "report.json", chief.final_report)
        for agent in agents:
            if agent.role == "chief":
                continue
            agent_dir = target_dir / "agents" / agent.agent_id
            agent_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(agent_dir, 0o700)
            await self._write_text_atomic(
                agent_dir / "session_memory.md", agent.session_memory
            )
            if agent.final_report:
                await self._write_json_atomic(agent_dir / "report.json", agent.final_report)

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
