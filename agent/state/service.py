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

from sqlalchemy import delete, func, select, update

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
    CycleRecord,
    DEFAULT_SESSION_MEMORY,
    EvidenceRecord,
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
    MAX_CHALLENGE_SLOTS,
    challenge_work_active,
    challenge_start_gate as evaluate_challenge_start_gate,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .routing import routes_for_observation
from .schemas import (
    AgentReportInput,
    CapabilityContext,
    CHALLENGE_CONTROL_STATE_VALUES,
    CHALLENGE_WORK_STATUS_VALUES,
    ChallengeImport,
    ChallengeDispatchInput,
    ChallengeSyncResult,
    ExecutionTaskInput,
    FindingInput,
    HypothesisInput,
)
from .wakeup import StateSignalBus


EVIDENCE_BACKED_PROGRESS_CONFIDENCE = 0.8
BOOTSTRAP_FOLLOWUP_CATEGORIES = frozenset(
    {"vulnerability", "credential", "privilege", "attack_path", "flag"}
)
REPORT_FINDING_CATEGORIES = frozenset(
    {"service", "vulnerability", "credential", "privilege", "attack_path", "flag", "other"}
)
REPORT_FINDING_REF_PATTERN = re.compile(r"^finding:finding_[0-9a-f]{32}$")
HYPOTHESIS_OUTCOME_ALIASES = {
    "supported": "supported",
    "confirmed": "supported",
    "positive": "supported",
    "partially_confirmed": "supported",
    "rejected": "rejected",
    "refuted": "rejected",
    "excluded": "rejected",
    "negative": "rejected",
    "inconclusive": "inconclusive",
    "completed": "inconclusive",
    "not_found": "inconclusive",
    "unknown": "inconclusive",
}
REPORT_CONFIDENCE_ALIASES = {"high": 0.9, "medium": 0.6, "low": 0.3}
REPORT_VERIFICATION_ALIASES = {
    "candidate": "candidate",
    "verified": "verified",
    "confirmed": "verified",
    "rejected": "rejected",
    "refuted": "rejected",
}
CONTROLLER_REPORT_PAGE_LIMIT = 8
CONTROLLER_FINDING_LIMIT = 24
CONTROLLER_TASK_LIMIT = 24
CONTROLLER_CYCLE_LIMIT = 3
CONTROLLER_OBSERVATION_LIMIT = 12
CONTROLLER_HYPOTHESIS_LIMIT = 24
CONTROLLER_SUMMARY_CHARS = 1_000
CONTROLLER_MISSION_CHARS = 600
CONTROLLER_NEXT_STEP_CHARS = 300


def _controller_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _controller_refs(value: Any, limit: int = 10) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return list(dict.fromkeys(item for item in value if isinstance(item, str)))[:limit]


def _stable_task_digest(
    *,
    objective: str,
    kind: str,
    task_stage: str,
    context_refs: Sequence[str] = (),
    success_criteria: Sequence[str] = (),
    explicit_task_key: str | None = None,
) -> str:
    identity = {
        "objective": " ".join(objective.lower().split()),
        "kind": kind,
        "task_stage": task_stage,
        "context_refs": sorted(set(context_refs)),
        "success_criteria": sorted(" ".join(item.lower().split()) for item in success_criteria),
        "explicit_task_key": explicit_task_key or "",
    }
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def _bootstrap_stop_reason(challenge: ChallengeRecord) -> str | None:
    if challenge.is_completed or challenge.work_status in {
        "closed",
        "completed",
    }:
        return "challenge_stopped"
    if (
        challenge.flag_count > 0
        and challenge.correct_flag_count >= challenge.flag_count
    ):
        return "all_flags_submitted"
    return None


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


ACTIVE_EXECUTION_STATUSES = frozenset(
    {"pending", "queued", "reserved", "starting", "running", "working"}
)
EVIDENCE_PROGRESS_CATEGORIES = frozenset(
    {"vulnerability", "credential", "privilege", "attack_path", "flag"}
)


class StateService:
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
        self.db = database if isinstance(database, StateDatabase) else StateDatabase(Path(database))
        self.run_root = run_root
        self.workspace_root = (
            workspace_root.resolve()
            if workspace_root is not None
            else None
        )
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
                roles={"execution", "challenge"},
                agent_id=context.agent_id,
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
                        roles={"execution", "challenge"},
                        agent_id=context.agent_id,
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
                    )
                    session.add(row)
                    challenge = await self._require_challenge(
                        session, run_id, unique_code
                    )
                    challenge.last_progress_at = self.clock()
                    challenge.stagnation_level = 0
                    challenge.version += 1
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
        if not evidence_ref.startswith(prefix) or len(evidence_ref) != len(prefix) + 32:
            raise StatePermission(
                "evidence_not_accessible",
                "Evidence is not accessible in this Agent scope",
            )
        evidence_id = evidence_ref.removeprefix("evidence:")
        async with self.db.sessions() as session:
            caller = await self._authorize(
                session,
                context,
                roles={"execution", "challenge"},
                agent_id=context.agent_id,
            )
            row = await session.get(EvidenceRecord, evidence_id)
            allowed = row is not None and row.run_id == run_id
            if caller.role == "execution":
                if caller.kind == "bootstrap":
                    allowed = (
                        allowed
                        and row is not None
                        and row.unique_code == caller.unique_code
                    )
                else:
                    allowed = allowed and row is not None and row.agent_id == caller.agent_id
            else:
                allowed = (
                    allowed
                    and row is not None
                    and row.unique_code == caller.unique_code
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
                session,
                context,
                roles={"chief", "challenge", "execution"},
            )
            filters = [EvidenceRecord.run_id == run_id]
            if caller.role == "challenge":
                filters.append(EvidenceRecord.unique_code == caller.unique_code)
            elif caller.role == "execution":
                filters.append(EvidenceRecord.unique_code == caller.unique_code)
                if caller.kind != "bootstrap":
                    filters.append(EvidenceRecord.agent_id == caller.agent_id)
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

    async def get_overview(
        self,
        run_id: str,
        *,
        unique_code: str | None = None,
        agent_id: str | None = None,
        active_agents_only: bool = False,
    ) -> dict[str, Any]:
        async with self.db.sessions() as session:
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
            challenge_values = [self._challenge_dict(item) for item in challenges]
            return {
                "run": self._run_dict(run),
                "challenges": challenge_values,
                "container_capacity": container_capacity_summary(challenge_values),
                "agents": [self._agent_dict(item) for item in agents],
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
                    roles={"chief", "challenge"},
                    unique_code=unique_code,
                )
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
            await self._require_run(session, run_id)
            rows = (await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id).order_by(ChallengeRecord.unique_code))).all()
            return [self._challenge_dict(item) for item in rows]

    async def _latest_cycle_in_session(
        self, session: Any, run_id: str, unique_code: str
    ) -> CycleRecord | None:
        return await session.scalar(
            select(CycleRecord)
            .where(
                CycleRecord.run_id == run_id,
                CycleRecord.unique_code == unique_code,
            )
            .order_by(CycleRecord.cycle_number.desc())
            .limit(1)
        )

    def _authority(
        self,
        run_id: str,
        challenge: ChallengeRecord,
        cycle: CycleRecord | None,
    ) -> dict[str, Any]:
        return {
            "challenge": {
                "unique_code": challenge.unique_code,
                "status": challenge.work_status,
                "is_completed": challenge.is_completed,
                "direction": challenge.direction,
            },
        }

    async def get_challenge_context(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext | None = None,
        *,
        compact: bool = False,
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
            findings_query = select(FindingRecord).where(
                FindingRecord.run_id == run_id,
                FindingRecord.unique_code == unique_code,
            )
            if compact:
                findings_query = findings_query.order_by(
                    FindingRecord.first_seen_at.desc()
                ).limit(CONTROLLER_FINDING_LIMIT)
            else:
                findings_query = findings_query.order_by(FindingRecord.first_seen_at)
            findings = list((await session.scalars(findings_query)).all())
            if compact:
                findings.reverse()
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
                        .limit(CONTROLLER_TASK_LIMIT if compact else 50)
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
                        .limit(CONTROLLER_CYCLE_LIMIT if compact else 10)
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
                        .limit(CONTROLLER_OBSERVATION_LIMIT if compact else 100)
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
                        .limit(CONTROLLER_HYPOTHESIS_LIMIT if compact else 50)
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
                        .limit(CONTROLLER_TASK_LIMIT if compact else 50)
                    )
                ).all()
            )
            result = {
                "authority": self._authority(
                    run_id, challenge, cycle_rows[0] if cycle_rows else None
                ),
                "challenge": self._challenge_dict(challenge),
                "findings": [
                    self._controller_finding_dict(item) if compact else self._finding_dict(item)
                    for item in findings
                ],
                "credentials": (
                    [self._credential_dict(item, include_secret=False) for item in credentials_rows]
                    if compact and context is not None and context.role != "chief"
                    else credentials
                ),
                "observations": [
                    {
                        "observation_id": item.observation_id,
                        "category": item.category,
                        "summary": _controller_text(item.summary, CONTROLLER_SUMMARY_CHARS)
                        if compact
                        else item.summary,
                        **({}
                           if compact
                           else {"detail": item.detail, "source": item.source}),
                        "confidence": item.confidence,
                        "captured_at": _json_value(item.captured_at),
                    }
                    for item in observation_rows
                ],
                "hypotheses": [
                    {
                        "hypothesis_key": item.hypothesis_key,
                        "statement": _controller_text(item.statement, CONTROLLER_MISSION_CHARS)
                        if compact
                        else item.statement,
                        "confidence": item.confidence,
                        "based_on_observations": (
                            _controller_refs(item.based_on_observations)
                            if compact
                            else item.based_on_observations
                        ),
                        "status": item.status,
                    }
                    for item in hypothesis_rows
                ],
                "branches": [
                    {
                        "branch_key": item.branch_key,
                        "hypothesis_key": item.hypothesis_key,
                        "kind": item.kind,
                        "task_stage": item.task_stage,
                        "status": item.status,
                        "priority": item.priority,
                        "mission": _controller_text(item.mission, CONTROLLER_MISSION_CHARS)
                        if compact
                        else item.mission,
                        "agent_ids": item.agent_ids[:8] if compact else item.agent_ids,
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
                        "task_stage": item.task_stage,
                        "mission": _controller_text(item.mission, CONTROLLER_MISSION_CHARS)
                        if compact
                        else item.mission,
                        "status": item.status,
                        "context_refs": item.context_refs,
                        "task_contract": extract_task_contract(
                            item.initial_prompt
                        ),
                        "terminal_report_id": item.terminal_report_id,
                        "terminal_report_ref": (
                            f"report:{item.terminal_report_id}"
                            if item.terminal_report_id
                            else None
                        ),
                        "report_summary": (
                            _controller_text(
                                item.final_report.get("summary"),
                                CONTROLLER_SUMMARY_CHARS,
                            )
                            if isinstance(item.final_report, Mapping)
                            else None
                        ),
                        "hypothesis_outcome": (
                            item.final_report.get("hypothesis_outcome")
                            if isinstance(item.final_report, Mapping)
                            else None
                        ),
                        "evidence_refs": (
                            _controller_refs(item.final_report.get("evidence_refs"))
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
            if compact:
                activity = await self._execution_activity_in_session(
                    session, run_id, unique_code
                )
                for key in (
                    "active_execution_count",
                    "active_executions",
                    "all_execution_terminal",
                    "evidence_root",
                ):
                    result[key] = activity[key]
                result.pop("active_agents", None)
                result.pop("recent_cycles", None)
            return result

    async def observe_challenge(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext,
        *,
        max_reports: int = CONTROLLER_REPORT_PAGE_LIMIT,
        replay_pending_snapshot: bool = False,
    ) -> dict[str, Any]:
        """Consume one bounded report page and return the compact controller view."""

        max_reports = max(1, min(max_reports, CONTROLLER_REPORT_PAGE_LIMIT))
        reports = await self.consume_reports(
            run_id,
            context,
            report_type="execution",
            max_reports=max_reports,
            wait_seconds=0.0,
            compact=True,
        )
        snapshot_replayed = False
        if replay_pending_snapshot and not reports.get("reports"):
            async with self.db.sessions() as session:
                controller = await self._authorize(
                    session,
                    context,
                    roles={"challenge"},
                    unique_code=unique_code,
                )
                decided_through = int(
                    await session.scalar(
                        select(func.max(CycleRecord.decision_report_sequence)).where(
                            CycleRecord.run_id == run_id,
                            CycleRecord.unique_code == unique_code,
                        )
                    )
                    or 0
                )
                snapshots = list(
                    (
                        await session.scalars(
                            select(StateEventRecord)
                            .where(
                                StateEventRecord.run_id == run_id,
                                StateEventRecord.agent_id == controller.agent_id,
                                StateEventRecord.event_type == "controller_snapshot",
                            )
                            .order_by(StateEventRecord.sequence.desc())
                            .limit(50)
                        )
                    ).all()
                )
            for snapshot in snapshots:
                payload = snapshot.payload or {}
                through = int(payload.get("through_sequence") or 0)
                saved_reports = payload.get("reports")
                if (
                    payload.get("report_type") == "execution"
                    and through > decided_through
                    and isinstance(saved_reports, list)
                    and saved_reports
                ):
                    reports = {
                        **reports,
                        "reports": saved_reports[:max_reports],
                        "count": min(len(saved_reports), max_reports),
                        "next_sequence": through,
                    }
                    snapshot_replayed = True
                    break
        state = await self.get_challenge_context(
            run_id,
            unique_code,
            context,
            compact=True,
        )
        async with self.db.sessions() as session:
            controller = await self._authorize(
                session,
                context,
                roles={"challenge"},
                unique_code=unique_code,
            )
            cursor = int((controller.report_cursors or {}).get("execution", 0))
            has_more = bool(
                await session.scalar(
                    select(ReportRecord.report_id)
                    .where(
                        ReportRecord.run_id == run_id,
                        ReportRecord.parent_id == controller.agent_id,
                        ReportRecord.report_type == "execution",
                        ReportRecord.sequence > cursor,
                    )
                    .limit(1)
                )
            )
        visible_reports = [
            {key: value for key, value in item.items() if key != "cycle_id"}
            for item in list(reports.get("reports") or [])
        ]
        candidate_flags = []
        for item in visible_reports:
            payload = item.get("payload")
            if not isinstance(payload, Mapping):
                continue
            candidate = payload.get("candidate_flag")
            if not isinstance(candidate, str) or not candidate:
                continue
            candidate_flags.append(
                {
                    "report_ref": item.get("report_ref"),
                    "agent_id": item.get("agent_id"),
                    "candidate_flag": candidate,
                    "summary": str(payload.get("summary") or "")[:1_000],
                    "evidence_refs": list(payload.get("evidence_refs") or [])[:20],
                }
            )
        return {
            **state,
            "candidate_flags": candidate_flags,
            "reports": visible_reports,
            "report_count": int(reports.get("count") or 0),
            "report_cursor": int(reports.get("next_sequence") or cursor),
            "has_more": has_more,
            "snapshot_replayed": snapshot_replayed,
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
        task_stage: str | None = None,
        priority: int = 50,
        mission: str = "",
        initial_prompt: str | None = None,
        success_criteria: list[str] | None = None,
        context_refs: list[str] | None = None,
        hypothesis_key: str | None = None,
        task_key: str | None = None,
        branch_key: str | None = None,
        timeout_seconds: int | None = None,
        enqueue: bool = False,
    ) -> dict[str, Any]:
        if role not in {"chief", "challenge", "execution"}:
            raise StateError("invalid_role", "unknown Agent role", status_code=422)
        if kind == "bootstrap":
            raise StatePermission(
                "bootstrap_internal",
                "Bootstrap Agents are created only with a Challenge",
            )
        agent_id = agent_id or f"{role}_{uuid4().hex}"
        event_sequence: int | None = None
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
                    task_stage = task_stage or "discovery"
                    digest = _stable_task_digest(
                        objective=mission or hypothesis_key or kind,
                        kind=kind,
                        task_stage=task_stage,
                        context_refs=context_refs or (),
                        explicit_task_key=task_key,
                    )
                    task_key = task_key or f"task:{digest}"
                    hypothesis_key = hypothesis_key or f"hypothesis:{digest}"
                    resolved_branch_key = branch_key or f"{hypothesis_key}:{kind}:{task_stage}"
                    duplicate = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.unique_code == unique_code,
                            AgentRecord.task_key == task_key,
                        )
                    )
                    if duplicate is not None:
                        data = self._agent_dict(duplicate)
                        data["idempotent"] = True
                        return data
                    await self._upsert_hypothesis(
                        session,
                        run_id=run_id,
                        unique_code=str(unique_code),
                        hypothesis=HypothesisInput(
                            key=hypothesis_key,
                            statement=mission or hypothesis_key,
                            based_on_observations=list(context_refs or []),
                        ),
                        created_by=parent_id,
                        status="active",
                    )
                    await self._upsert_branch(
                        session,
                        run_id=run_id,
                        unique_code=str(unique_code),
                        branch_key=resolved_branch_key,
                        hypothesis_key=hypothesis_key,
                        kind=kind,
                        task_stage=task_stage,
                        priority=priority,
                        mission=mission,
                        agent_id=agent_id,
                        status="queued",
                    )
                    branch_key = resolved_branch_key
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
                    task_stage=task_stage,
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
                admission: AdmissionRecord | None = None
                if role == "execution" and enqueue:
                    admission = AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}",
                        run_id=run_id,
                        agent_id=agent_id,
                        unique_code=unique_code,
                        role="execution",
                        priority=priority,
                        status="queued",
                    )
                    session.add(admission)
                    record.status = "queued"
                await self._event(session, run_id, "agent_created", {
                    "agent_id": agent_id, "role": role, "parent_id": parent_id,
                    "unique_code": unique_code, "cycle_id": cycle_id,
                    "kind": kind, "task_stage": task_stage,
                }, agent_id=agent_id, cycle_id=cycle_id)
                if admission is not None:
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "agent_admission_queued",
                        {
                            "agent_id": agent_id,
                            "admission_id": admission.admission_id,
                            "priority": priority,
                        },
                        agent_id=agent_id,
                        cycle_id=cycle_id,
                    )
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        result = self._agent_dict(record)
        if admission is not None:
            result["admission_id"] = admission.admission_id
            result["admission_status"] = admission.status
        return result

    async def register_challenge_with_bootstrap(
        self,
        run_id: str,
        *,
        challenge_agent_id: str,
        bootstrap_agent_id: str,
        parent_id: str,
        unique_code: str,
        challenge_prompt: str,
        bootstrap_prompt: str,
        bootstrap_enabled: bool = True,
        bootstrap_priority: int = 100,
    ) -> dict[str, Any]:
        """Atomically create a Challenge controller and its optional Bootstrap.

        Bootstrap is an internal execution kind.  It deliberately bypasses
        hypothesis/branch creation so the controller never sees it as a normal
        planned task.  The admission row is committed with the two Agent rows,
        then one run signal wakes the scheduler.
        """

        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                if await session.get(AgentRecord, challenge_agent_id) is not None:
                    raise StateConflict("agent_exists", "challenge Agent id already exists")
                if await session.get(AgentRecord, bootstrap_agent_id) is not None:
                    raise StateConflict("agent_exists", "bootstrap Agent id already exists")
                parent = await session.get(AgentRecord, parent_id)
                if parent is None or parent.run_id != run_id or parent.role != "chief":
                    raise StatePermission("invalid_parent", "Challenge Agent requires the run Chief")
                challenge = await self._require_challenge(session, run_id, unique_code)
                if challenge.is_completed or challenge.work_status in {"closed", "paused", "completed"}:
                    raise StateConflict("challenge_not_active", "challenge is not active")
                bootstrap_stop_reason = _bootstrap_stop_reason(challenge)
                bootstrap_enabled_now = bool(bootstrap_enabled) and (
                    bootstrap_stop_reason is None
                )
                existing = await session.scalar(
                    select(AgentRecord).where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "challenge",
                        AgentRecord.status.not_in(["failed", "stopped", "completed"]),
                    )
                )
                if existing is not None:
                    bootstrap = await session.scalar(
                        select(AgentRecord).where(
                            AgentRecord.run_id == run_id,
                            AgentRecord.parent_id == existing.agent_id,
                            AgentRecord.kind == "bootstrap",
                        )
                    )
                    result = self._agent_dict(existing)
                    result["idempotent"] = True
                    result["bootstrap"] = (
                        {"enabled": True, **self._agent_dict(bootstrap)}
                        if bootstrap is not None
                        else {"enabled": False}
                    )
                    return result

                challenge_agent = AgentRecord(
                    agent_id=challenge_agent_id,
                    run_id=run_id,
                    parent_id=parent_id,
                    unique_code=unique_code,
                    role="challenge",
                    kind="general",
                    mission=challenge.description or "",
                    initial_prompt=challenge_prompt,
                    session_memory=DEFAULT_SESSION_MEMORY,
                )
                session.add(challenge_agent)
                await self._event(
                    session,
                    run_id,
                    "agent_created",
                    {
                        "agent_id": challenge_agent_id,
                        "role": "challenge",
                        "parent_id": parent_id,
                        "unique_code": unique_code,
                        "kind": "general",
                    },
                    agent_id=challenge_agent_id,
                )
                await self._event(
                    session,
                    run_id,
                    "challenge_agent_created",
                    {"agent_id": challenge_agent_id, "unique_code": unique_code},
                    agent_id=challenge_agent_id,
                )

                bootstrap_data: dict[str, Any] = {
                    "enabled": bootstrap_enabled_now,
                    "agent_id": None,
                    "status": None,
                }
                if bootstrap_enabled_now:
                    bootstrap_agent = AgentRecord(
                        agent_id=bootstrap_agent_id,
                        run_id=run_id,
                        parent_id=challenge_agent_id,
                        unique_code=unique_code,
                        cycle_id=None,
                        role="execution",
                        kind="bootstrap",
                        task_stage="discovery",
                        priority=bootstrap_priority,
                        mission=(
                            "Autonomously advance this Challenge and obtain an exact candidate result."
                        ),
                        initial_prompt=bootstrap_prompt,
                        session_memory=DEFAULT_SESSION_MEMORY,
                        success_criteria=[],
                        context_refs=[],
                        report_cursors={
                            "bootstrap_shared_challenge": int(
                                int.from_bytes(
                                    hashlib.sha256(
                                        json.dumps(
                                            {
                                                "direction": challenge.direction,
                                                "is_completed": challenge.is_completed,
                                                "work_status": challenge.work_status,
                                                "container_status": challenge.container_status,
                                                "container_addr": challenge.container_addr,
                                            },
                                            sort_keys=True,
                                            ensure_ascii=False,
                                            default=str,
                                        ).encode("utf-8")
                                    ).digest()[:8],
                                    "big",
                                )
                            )
                        },
                        hypothesis_key=None,
                        task_key=None,
                        branch_key=None,
                        timeout_seconds=None,
                        status="queued",
                    )
                    session.add(bootstrap_agent)
                    admission = AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}",
                        run_id=run_id,
                        agent_id=bootstrap_agent_id,
                        unique_code=unique_code,
                        role="execution",
                        priority=bootstrap_priority,
                        status="queued",
                    )
                    session.add(admission)
                    await self._event(
                        session,
                        run_id,
                        "agent_created",
                        {
                            "agent_id": bootstrap_agent_id,
                            "role": "execution",
                            "parent_id": challenge_agent_id,
                            "unique_code": unique_code,
                            "kind": "bootstrap",
                            "task_stage": "discovery",
                        },
                        agent_id=bootstrap_agent_id,
                    )
                    await self._event(
                        session,
                        run_id,
                        "bootstrap_policy_configured",
                        {
                            "bootstrap_enabled": True,
                            "priority": bootstrap_priority,
                            "lifecycle": "challenge_bound",
                        },
                        agent_id=challenge_agent_id,
                    )
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "bootstrap_created",
                        {
                            "agent_id": bootstrap_agent_id,
                            "parent_id": challenge_agent_id,
                            "admission_id": admission.admission_id,
                            "priority": bootstrap_priority,
                        },
                        agent_id=bootstrap_agent_id,
                    )
                    event_sequence = await self._event(
                        session,
                        run_id,
                        "agent_admission_queued",
                        {
                            "agent_id": bootstrap_agent_id,
                            "admission_id": admission.admission_id,
                            "priority": bootstrap_priority,
                        },
                        agent_id=bootstrap_agent_id,
                    )
                    bootstrap_data = {
                        "enabled": True,
                        "agent_id": bootstrap_agent_id,
                        "status": "queued",
                        "admission_id": admission.admission_id,
                    }
                else:
                    if bootstrap_stop_reason is not None:
                        bootstrap_data["reason"] = bootstrap_stop_reason
                    await self._event(
                        session,
                        run_id,
                        "bootstrap_policy_configured",
                        {
                            "bootstrap_enabled": False,
                            "reason": bootstrap_stop_reason,
                        },
                        agent_id=challenge_agent_id,
                    )
                result = self._agent_dict(challenge_agent)
                result["bootstrap"] = bootstrap_data
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return result

    async def ensure_bootstrap_for_challenge(
        self,
        run_id: str,
        unique_code: str,
        *,
        parent_id: str,
        bootstrap_prompt: str,
        bootstrap_priority: int = 100,
    ) -> dict[str, Any]:
        """Return the live Bootstrap or queue a fresh one for an active Challenge."""

        event_sequence: int | None = None
        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                stop_reason = _bootstrap_stop_reason(challenge)
                if stop_reason is not None:
                    return {
                        "enabled": False,
                        "agent_id": None,
                        "status": None,
                        "reason": stop_reason,
                    }
                parent = await session.get(AgentRecord, parent_id)
                if (
                    parent is None
                    or parent.run_id != run_id
                    or parent.role != "challenge"
                    or parent.unique_code != unique_code
                    or parent.status in {
                        "failed",
                        "stopped",
                        "completed",
                        "cancelled",
                        "interrupted",
                    }
                ):
                    return {
                        "enabled": False,
                        "agent_id": None,
                        "status": None,
                        "reason": "challenge_stopped",
                    }
                existing = await session.scalar(
                    select(AgentRecord)
                    .where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.parent_id == parent_id,
                        AgentRecord.role == "execution",
                        AgentRecord.kind == "bootstrap",
                        AgentRecord.status.not_in(
                            [
                                "failed",
                                "stopped",
                                "completed",
                                "cancelled",
                                "interrupted",
                            ]
                        ),
                    )
                    .order_by(AgentRecord.created_at.desc())
                    .limit(1)
                )
                if existing is not None:
                    result = self._agent_dict(existing)
                    result.update({"enabled": True, "idempotent": True})
                    return result

                bootstrap_agent_id = f"execution_{uuid4().hex}"
                bootstrap_agent = AgentRecord(
                    agent_id=bootstrap_agent_id,
                    run_id=run_id,
                    parent_id=parent_id,
                    unique_code=unique_code,
                    cycle_id=None,
                    role="execution",
                    kind="bootstrap",
                    task_stage="discovery",
                    priority=bootstrap_priority,
                    mission=(
                        "Autonomously advance this Challenge and obtain an exact candidate result."
                    ),
                    initial_prompt=bootstrap_prompt,
                    session_memory=DEFAULT_SESSION_MEMORY,
                    success_criteria=[],
                    context_refs=[],
                    report_cursors={
                        "bootstrap_shared_challenge": int(
                            int.from_bytes(
                                hashlib.sha256(
                                    json.dumps(
                                        {
                                            "direction": challenge.direction,
                                            "is_completed": challenge.is_completed,
                                            "work_status": challenge.work_status,
                                            "container_status": challenge.container_status,
                                            "container_addr": challenge.container_addr,
                                        },
                                        sort_keys=True,
                                        ensure_ascii=False,
                                        default=str,
                                    ).encode("utf-8")
                                ).digest()[:8],
                                "big",
                            )
                        )
                    },
                    hypothesis_key=None,
                    task_key=None,
                    branch_key=None,
                    timeout_seconds=None,
                    status="queued",
                )
                session.add(bootstrap_agent)
                admission = AdmissionRecord(
                    admission_id=f"admission_{uuid4().hex}",
                    run_id=run_id,
                    agent_id=bootstrap_agent_id,
                    unique_code=unique_code,
                    role="execution",
                    priority=bootstrap_priority,
                    status="queued",
                )
                session.add(admission)
                await self._event(
                    session,
                    run_id,
                    "agent_created",
                    {
                        "agent_id": bootstrap_agent_id,
                        "role": "execution",
                        "parent_id": parent_id,
                        "unique_code": unique_code,
                        "kind": "bootstrap",
                        "task_stage": "discovery",
                    },
                    agent_id=bootstrap_agent_id,
                )
                await self._event(
                    session,
                    run_id,
                    "bootstrap_created",
                    {
                        "agent_id": bootstrap_agent_id,
                        "parent_id": parent_id,
                        "admission_id": admission.admission_id,
                        "priority": bootstrap_priority,
                        "reason": "bootstrap_cycle",
                    },
                    agent_id=bootstrap_agent_id,
                )
                event_sequence = await self._event(
                    session,
                    run_id,
                    "agent_admission_queued",
                    {
                        "agent_id": bootstrap_agent_id,
                        "admission_id": admission.admission_id,
                        "priority": bootstrap_priority,
                    },
                    agent_id=bootstrap_agent_id,
                )
                result = {
                    **self._agent_dict(bootstrap_agent),
                    "enabled": True,
                    "created": True,
                    "admission_id": admission.admission_id,
                    "admission_status": admission.status,
                }
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
        return result

    async def prepare_bootstrap_shared_update(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        max_reports: int = 20,
        max_chars: int = 8_000,
    ) -> dict[str, Any] | None:
        """Prepare a replayable sibling-report snapshot for a Bootstrap Agent."""

        max_reports = max(1, min(max_reports, 20))
        max_chars = max(1_000, min(max_chars, 8_000))
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session, context, roles={"execution"}, agent_id=context.agent_id
                )
                if agent.kind != "bootstrap" or not agent.unique_code:
                    return None
                cursors = dict(agent.report_cursors or {})
                pending = int(cursors.get("bootstrap_shared_pending", 0) or 0)
                if pending:
                    event = await session.scalar(
                        select(StateEventRecord)
                        .where(
                            StateEventRecord.run_id == run_id,
                            StateEventRecord.agent_id == agent.agent_id,
                            StateEventRecord.event_type == "bootstrap_shared_snapshot",
                            StateEventRecord.sequence >= pending,
                        )
                        .order_by(StateEventRecord.sequence.desc())
                        .limit(1)
                    )
                    if event is not None:
                        return {**dict(event.payload or {}), "replayed": True}
                cursor = int(cursors.get("bootstrap_shared", 0) or 0)
                hint_cursor = int(cursors.get("bootstrap_hint", 0) or 0)
                rows = list(
                    (
                        await session.scalars(
                            select(ReportRecord)
                            .where(
                                ReportRecord.run_id == run_id,
                                ReportRecord.unique_code == agent.unique_code,
                                ReportRecord.report_type == "execution",
                                ReportRecord.sequence > cursor,
                                ReportRecord.agent_id != agent.agent_id,
                            )
                            .order_by(ReportRecord.sequence)
                            .limit(max_reports)
                        )
                    ).all()
                )
                hints = list(
                    (
                        await session.scalars(
                            select(ReportRecord)
                            .where(
                                ReportRecord.run_id == run_id,
                                ReportRecord.unique_code == agent.unique_code,
                                ReportRecord.report_type == "hint",
                                ReportRecord.sequence > hint_cursor,
                            )
                            .order_by(ReportRecord.sequence)
                            .limit(4)
                        )
                    ).all()
                )
                challenge = await self._require_challenge(session, run_id, agent.unique_code)
                challenge_token = int.from_bytes(
                    hashlib.sha256(
                        json.dumps(
                            {
                                "direction": challenge.direction,
                                "is_completed": challenge.is_completed,
                                "work_status": challenge.work_status,
                                "container_status": challenge.container_status,
                                "container_addr": challenge.container_addr,
                            },
                            sort_keys=True,
                            ensure_ascii=False,
                            default=str,
                        ).encode("utf-8")
                    ).digest()[:8],
                    "big",
                )
                if (
                    not rows
                    and not hints
                    and cursors.get("bootstrap_shared_challenge") == challenge_token
                ):
                    return None
                reports: list[dict[str, Any]] = []
                for row in rows:
                    payload = dict((row.payload or {}))
                    reports.append(
                        {
                            "report_ref": f"report:{row.report_id}",
                            "agent_id": row.agent_id,
                            "status": row.status,
                            "summary": str(payload.get("summary") or "")[:800],
                            "findings": [
                                {
                                    "finding_ref": item.get("finding_ref"),
                                    "summary": str(item.get("summary") or "")[:500],
                                    "verification_status": item.get("verification_status"),
                                    "evidence_refs": list(item.get("evidence_refs") or [])[:10],
                                }
                                for item in list(payload.get("findings") or [])[:5]
                                if isinstance(item, Mapping)
                            ],
                            "evidence_refs": list(payload.get("evidence_refs") or [])[:10],
                            "candidate_flag": payload.get("candidate_flag"),
                        }
                    )
                hint_values = [
                    {
                        "type": "hint",
                        "hint": str((item.payload or {}).get("hint") or "")[:1_000],
                        "reason": str((item.payload or {}).get("reason") or "")[:500],
                    }
                    for item in hints
                ]
                through_sequence = max(
                    [item.sequence for item in (*rows, *hints)] or [cursor, hint_cursor]
                )
                update_payload: dict[str, Any] = {
                    "type": "bootstrap_shared_update",
                    "through_sequence": through_sequence,
                    "challenge": {
                        "direction": challenge.direction,
                        "is_completed": challenge.is_completed,
                    },
                    "reports": reports,
                    "hints": hint_values,
                    "has_more": len(rows) >= max_reports or len(hints) >= 4,
                    "replayed": False,
                }
                encoded = json.dumps(update_payload, ensure_ascii=False, default=str)
                if len(encoded) > max_chars:
                    while len(reports) > 1 and len(encoded) > max_chars:
                        reports.pop()
                        update_payload["reports"] = reports
                        update_payload["has_more"] = True
                        encoded = json.dumps(update_payload, ensure_ascii=False, default=str)
                    while len(hint_values) > 1 and len(encoded) > max_chars:
                        hint_values.pop()
                        update_payload["hints"] = hint_values
                        update_payload["has_more"] = True
                        encoded = json.dumps(update_payload, ensure_ascii=False, default=str)
                included_report_rows = rows[: len(reports)]
                report_through = (
                    included_report_rows[-1].sequence
                    if included_report_rows
                    else cursor
                )
                through_sequence = max(
                    report_through,
                    hints[: len(hint_values)][-1].sequence
                    if hint_values
                    else hint_cursor,
                )
                update_payload["through_sequence"] = through_sequence
                agent.report_cursors = {
                    **cursors,
                    "bootstrap_shared": report_through,
                    "bootstrap_hint": (
                        hints[: len(hint_values)][-1].sequence
                        if hint_values
                        else hint_cursor
                    ),
                    "bootstrap_shared_challenge": challenge_token,
                    "bootstrap_shared_pending": through_sequence,
                }
                await self._event(
                    session,
                    run_id,
                    "bootstrap_shared_snapshot",
                    update_payload,
                    agent_id=agent.agent_id,
                )
                return update_payload

    async def acknowledge_bootstrap_shared_update(
        self,
        run_id: str,
        context: CapabilityContext,
        through_sequence: int,
    ) -> None:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session, context, roles={"execution"}, agent_id=context.agent_id
                )
                if agent.kind != "bootstrap":
                    return
                cursors = dict(agent.report_cursors or {})
                pending = int(cursors.get("bootstrap_shared_pending", 0) or 0)
                if pending and through_sequence >= pending:
                    cursors.pop("bootstrap_shared_pending", None)
                    agent.report_cursors = cursors

    async def get_assignment(self, run_id: str, agent_id: str, context: CapabilityContext) -> dict[str, Any]:
        async with self.db.sessions.begin() as session:
            agent = await self._authorize(session, context, roles={"chief", "challenge", "execution"}, agent_id=agent_id)
            if not agent.unique_code:
                return {"agent": self._agent_dict(agent), "challenge": None}
            challenge = await self._require_challenge(session, run_id, agent.unique_code)
            challenge_data = self._challenge_dict(challenge)
            assignment: dict[str, Any] = {
                "agent_id": agent.agent_id,
                "mission": agent.mission,
                "kind": agent.kind,
                "task_stage": agent.task_stage,
                "task_key": agent.task_key,
                "success_criteria": list(agent.success_criteria or []),
                "context_refs": list(agent.context_refs or []),
                "evidence_root": challenge_data["evidence_root"],
            }
            # Only material referenced context crosses the Execution boundary.
            # Full cycles, all Agents, and unrelated history remain Challenge-owned.
            referenced: list[dict[str, Any]] = []
            for reference in agent.context_refs or []:
                if reference.startswith("finding:"):
                    finding = await session.get(FindingRecord, reference.removeprefix("finding:"))
                    if finding is not None and finding.run_id == run_id and finding.unique_code == agent.unique_code:
                        referenced.append(
                            {
                                "ref": reference,
                                "type": "finding",
                                "summary": finding.summary,
                                "confidence": finding.confidence,
                                "verification_status": finding.verification_status,
                                "evidence_refs": list(
                                    (finding.detail or {}).get(
                                        "evidence_refs", []
                                    )
                                ),
                            }
                        )
                elif reference.startswith("observation:"):
                    observation = await session.get(ObservationRecord, reference.removeprefix("observation:"))
                    if observation is not None and observation.run_id == run_id and observation.unique_code == agent.unique_code:
                        referenced.append({"ref": reference, "type": "observation", "summary": observation.summary, "confidence": observation.confidence})
                elif reference.startswith("report:"):
                    report = await session.get(ReportRecord, reference.removeprefix("report:"))
                    if report is not None and report.run_id == run_id and report.unique_code == agent.unique_code:
                        referenced.append({"ref": reference, "type": "report", "summary": str((report.payload or {}).get("summary", ""))[:1000], "status": report.status})
            challenge_data = {
                "run_id": challenge_data["run_id"],
                "unique_code": challenge_data["unique_code"],
                "description": challenge_data["description"],
                "target": challenge_data["container_addr"],
                "direction": challenge_data["direction"],
                "work_status": challenge_data["work_status"],
                "container_status": challenge_data["container_status"],
                "container_addr": challenge_data["container_addr"],
                "evidence_root": challenge_data["evidence_root"],
                "referenced_context": referenced,
            }
            candidate_findings = []
            for reference in agent.context_refs or []:
                if not reference.startswith("finding:finding_"):
                    continue
                finding = await session.get(
                    FindingRecord, reference.removeprefix("finding:")
                )
                if (
                    finding is not None
                    and finding.run_id == run_id
                    and finding.unique_code == agent.unique_code
                    and finding.verification_status == "candidate"
                ):
                    candidate_findings.append(
                        {
                            "finding_ref": reference,
                            "summary": finding.summary,
                            "expected_outcomes": ["verified", "rejected"],
                            "status": finding.verification_status,
                            "confidence": finding.confidence,
                        }
                    )
            assignment["candidate_findings"] = candidate_findings
            return {
                "assignment": assignment,
                "challenge": challenge_data,
                "evidence_root": challenge_data["evidence_root"],
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

    async def activate_agent_skill(
        self,
        run_id: str,
        agent_id: str,
        *,
        skill_id: str,
        content_sha256: str,
        activation_mode: str,
    ) -> dict[str, Any]:
        """Persist one immutable Skill activation exactly once for an Agent."""

        if activation_mode not in {"auto", "model"}:
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
                    (item for item in active_skills if item.get("skill_id") == skill_id),
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
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
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
                                secrets=self.ephemeral_secrets(),
                            ),
                            agent_id=agent_id,
                            cycle_id=(
                                str(event["cycle_id"])
                                if event.get("cycle_id") is not None
                                else None
                            ),
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
                    "cycle_id": row.cycle_id,
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
                "cycle_id": row.cycle_id,
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

        event_sequence: int | None = None
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
                event_sequence = await self._event(
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
        if event_sequence is not None:
            await self.notifier.notify(self.run_signal_key(run_id), event_sequence)
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
                    cycle_id=agent.cycle_id,
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
        resource_statuses = {"queued", "reserved", "starting", "running", "waiting", "released"}
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
                    estimated_analysis_work=min(maximum, max(0, estimated_analysis_work)),
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
                    and record.analysis_status in {"queued", "running"}
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
                    estimated_requests=min(9_223_372_036_854_775_807, max(0, estimated_requests)),
                    estimated_disk_bytes=min(9_223_372_036_854_775_807, max(0, estimated_disk_bytes)),
                    estimated_memory_bytes=min(9_223_372_036_854_775_807, max(0, estimated_memory_bytes)),
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
                interaction = await session.get(
                    HttpInteractionRecord, interaction_id
                )
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
                    estimated_requests=min(
                        maximum, max(0, estimated_requests)
                    ),
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
                                (
                                    now - aware(record.created_at)
                                ).total_seconds(),
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

    async def mark_resource_work_started(self, run_id: str, work_id: str) -> dict[str, Any]:
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
                                max(0.0, (aware(now) - aware(record.created_at)).total_seconds())
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

    async def interrupt_execution_agents(
        self,
        run_id: str,
        *,
        exclude_kinds: Sequence[str] = (),
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
                            AgentRecord.kind.not_in(list(exclude_kinds))
                            if exclude_kinds
                            else True,
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
                    hypothesis_outcome="inconclusive",
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
        compact: bool = False,
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
                    report_agents: dict[str, AgentRecord] = {}
                    if rows:
                        report_agents = {
                            item.agent_id: item
                            for item in (
                                await session.scalars(
                                    select(AgentRecord).where(
                                        AgentRecord.run_id == run_id,
                                        AgentRecord.agent_id.in_({
                                            row.agent_id for row in rows
                                        }),
                                    )
                                )
                            ).all()
                        }
                    activity = (
                        await self._execution_activity_in_session(
                            session,
                            run_id,
                            agent.unique_code,
                        )
                        if report_type == "execution" and agent.unique_code
                        else None
                    )
                    if rows:
                        current_cursor = rows[-1].sequence
                        agent.report_cursors = {
                            **agent.report_cursors,
                            cursor_key: current_cursor,
                        }
                        agent.report_cursor = max(agent.report_cursor, current_cursor)
                        agent.version += 1
                        consumed_at = self.clock()
                        for row in rows:
                            row.consumed_by = agent.agent_id
                            row.consumed_at = consumed_at
                        reports = [
                            self._report_with_ephemeral(
                                item,
                                cycle_id=(
                                    report_agents[item.agent_id].cycle_id
                                    if item.agent_id in report_agents
                                    else None
                                ),
                            )
                            for item in rows
                        ]
                        if compact:
                            reports = [
                                self._controller_report_projection(item)
                                for item in reports
                            ]
                        await self._event(
                            session,
                            run_id,
                            "controller_snapshot",
                            {
                                "through_sequence": current_cursor,
                                "count": len(rows),
                                "report_type": report_type,
                                "reports": redact_value(reports),
                                "activity": redact_value(activity or {}),
                            },
                            agent_id=agent.agent_id,
                        )
                        result = {
                            "reports": reports,
                            "count": len(reports),
                            "next_sequence": current_cursor,
                            "consumed_at": consumed_at.isoformat(),
                        }
                        if activity is not None:
                            result.update(activity)
                        return result
                    if wait_seconds <= 0:
                        await self._event(
                            session,
                            run_id,
                            "controller_snapshot",
                            {
                                "through_sequence": current_cursor,
                                "count": 0,
                                "report_type": report_type,
                                "reports": [],
                                "activity": redact_value(activity or {}),
                            },
                            agent_id=agent.agent_id,
                        )
                        result = {
                            "reports": [],
                            "count": 0,
                            "next_sequence": current_cursor,
                        }
                        if activity is not None:
                            result.update(activity)
                        return result
            started = asyncio.get_running_loop().time()
            signal_sequence = await self.notifier.wait(
                signal_key,
                signal_sequence,
                wait_seconds,
            )
            elapsed = asyncio.get_running_loop().time() - started
            wait_seconds = max(0.0, wait_seconds - elapsed)

    async def replay_unacknowledged_controller_reports(
        self,
        run_id: str,
        context: CapabilityContext,
        *,
        report_type: str,
        max_reports: int = 20,
    ) -> dict[str, Any] | None:
        """Replay a durable snapshot only when no model response acknowledged it."""

        async with self.db.sessions() as session:
            agent = await self._authorize(
                session, context, roles={"chief", "challenge"}
            )
            snapshots = list(
                (
                    await session.scalars(
                        select(StateEventRecord)
                        .where(
                            StateEventRecord.run_id == run_id,
                            StateEventRecord.agent_id == agent.agent_id,
                            StateEventRecord.event_type == "controller_snapshot",
                        )
                        .order_by(StateEventRecord.sequence.desc())
                        .limit(50)
                    )
                ).all()
            )
            for snapshot in snapshots:
                payload = snapshot.payload or {}
                saved = payload.get("reports")
                if (
                    payload.get("report_type") != report_type
                    or not isinstance(saved, list)
                    or not saved
                ):
                    continue
                acknowledged = await session.scalar(
                    select(StateEventRecord.sequence)
                    .where(
                        StateEventRecord.run_id == run_id,
                        StateEventRecord.agent_id == agent.agent_id,
                        StateEventRecord.event_type == "assistant_response",
                        StateEventRecord.sequence > snapshot.sequence,
                    )
                    .limit(1)
                )
                if acknowledged is None:
                    return {
                        "reports": saved[:max_reports],
                        "count": min(len(saved), max_reports),
                        "next_sequence": int(
                            payload.get("through_sequence") or 0
                        ),
                    }
                return None
        return None

    async def _execution_activity_in_session(
        self,
        session: Any,
        run_id: str,
        unique_code: str,
    ) -> dict[str, Any]:
        """Return the compact Execution view used for report-driven decisions."""

        active = list(
            (
                await session.scalars(
                    select(AgentRecord)
                    .where(
                        AgentRecord.run_id == run_id,
                        AgentRecord.unique_code == unique_code,
                        AgentRecord.role == "execution",
                        AgentRecord.status.in_(ACTIVE_EXECUTION_STATUSES),
                    )
                    .order_by(AgentRecord.created_at, AgentRecord.agent_id)
                )
            ).all()
        )
        current_cycle = await session.scalar(
            select(CycleRecord)
            .where(
                CycleRecord.run_id == run_id,
                CycleRecord.unique_code == unique_code,
            )
            .order_by(CycleRecord.cycle_number.desc())
            .limit(1)
        )
        challenge = await self._require_challenge(session, run_id, unique_code)
        evidence_root = self._ensure_evidence_root(challenge)
        executions = [
            {
                "agent_id": item.agent_id,
                "cycle_id": item.cycle_id,
                "task_key": item.task_key,
                "hypothesis_key": item.hypothesis_key,
                "branch_key": item.branch_key,
                "status": item.status,
                "started_at": _json_value(item.started_at),
                "timeout_seconds": item.timeout_seconds,
            }
            for item in active
        ]
        return {
            "authority": self._authority(run_id, challenge, current_cycle),
            "current_cycle_id": current_cycle.cycle_id if current_cycle else None,
            "active_execution_count": len(executions),
            "active_executions": executions,
            "all_execution_terminal": not executions,
            "evidence_root": evidence_root,
        }

    async def _active_execution_ids_in_session(
        self,
        session: Any,
        run_id: str,
        unique_code: str,
        cycle_id: str | None,
    ) -> list[str]:
        clauses = [
            AgentRecord.run_id == run_id,
            AgentRecord.unique_code == unique_code,
            AgentRecord.role == "execution",
            AgentRecord.status.in_(ACTIVE_EXECUTION_STATUSES),
        ]
        if cycle_id is not None:
            clauses.append(AgentRecord.cycle_id == cycle_id)
        rows = list(
            (
                await session.scalars(
                    select(AgentRecord.agent_id)
                    .where(*clauses)
                    .order_by(AgentRecord.created_at, AgentRecord.agent_id)
                )
            ).all()
        )
        return [str(agent_id) for agent_id in rows]

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

    async def dispatch_challenge(
        self,
        run_id: str,
        unique_code: str,
        context: CapabilityContext,
        payload: ChallengeDispatchInput,
    ) -> dict[str, Any]:
        """Persist one immutable controller decision and enqueue its tasks.

        The model does not own a mutable Cycle.  Every call records a completed
        decision batch, so append-only reports can arrive concurrently without
        invalidating the dispatch.
        """

        started_at = asyncio.get_running_loop().time()
        final_sequence = 0
        async with self._lock:
            async with self.db.sessions.begin() as session:
                controller = await self._authorize(
                    session,
                    context,
                    roles={"challenge"},
                    unique_code=unique_code,
                )
                challenge = await self._require_challenge(
                    session, run_id, unique_code
                )
                if challenge.is_completed or challenge.work_status in {
                    "closed",
                    "paused",
                    "completed",
                }:
                    raise StateConflict(
                        "challenge_not_active",
                        "The challenge no longer accepts Execution tasks",
                    )

                warnings: list[dict[str, Any]] = []
                if payload.direction is not None and payload.direction != challenge.direction:
                    if challenge.direction != "unknown":
                        warnings.append(
                            {
                                "code": "direction_changed",
                                "message": "The controller changed the challenge direction",
                                "details": {
                                    "previous": challenge.direction,
                                    "current": payload.direction,
                                },
                            }
                        )
                    challenge.direction = payload.direction
                    challenge.version += 1

                previous_cycle = await self._latest_cycle_in_session(
                    session, run_id, unique_code
                )
                previous_decision_sequence = int(
                    previous_cycle.decision_report_sequence or 0
                ) if previous_cycle is not None else 0
                report_cursor = int(
                    (controller.report_cursors or {}).get("execution", 0)
                )
                decision_report = None
                if report_cursor > previous_decision_sequence:
                    decision_report = await session.scalar(
                        select(ReportRecord)
                        .where(
                            ReportRecord.run_id == run_id,
                            ReportRecord.unique_code == unique_code,
                            ReportRecord.report_type == "execution",
                            ReportRecord.consumed_by == context.agent_id,
                            ReportRecord.sequence <= report_cursor,
                            ReportRecord.sequence > previous_decision_sequence,
                        )
                        .order_by(ReportRecord.sequence.desc())
                        .limit(1)
                    )

                now = self.clock()
                transition_latency_ms: int | None = None
                decision_report_sequence: int | None = None
                if decision_report is not None:
                    decision_report_sequence = decision_report.sequence
                    if decision_report.consumed_at is not None:
                        transition_latency_ms = int(
                            max(
                                0.0,
                                (
                                    aware(now) - aware(decision_report.consumed_at)
                                ).total_seconds(),
                            )
                            * 1_000
                        )

                bootstrap_followup_tasks: list[ExecutionTaskInput] = []
                if not payload.tasks and report_cursor > previous_decision_sequence:
                    bootstrap_followup_tasks = await self._bootstrap_followup_tasks(
                        session,
                        run_id=run_id,
                        unique_code=unique_code,
                        controller_id=context.agent_id,
                        after_sequence=previous_decision_sequence,
                        through_sequence=report_cursor,
                    )
                dispatch_tasks = list(payload.tasks) or bootstrap_followup_tasks

                cycle_number = int(
                    await session.scalar(
                        select(func.max(CycleRecord.cycle_number)).where(
                            CycleRecord.run_id == run_id,
                            CycleRecord.unique_code == unique_code,
                        )
                    )
                    or 0
                ) + 1
                cycle = CycleRecord(
                    cycle_id=f"cycle_{uuid4().hex}",
                    run_id=run_id,
                    unique_code=unique_code,
                    cycle_number=cycle_number,
                    status="completed",
                    state_snapshot=await self._snapshot(session, challenge),
                    analysis={
                        "summary": payload.summary,
                        "direction": payload.direction or challenge.direction,
                    },
                    verification={
                        "summary": payload.summary,
                        "outcome": payload.outcome,
                        "evidence_refs": list(payload.evidence_refs),
                    },
                    state_update={"next_steps": list(payload.next_steps)},
                    report_cursor_at_start=report_cursor,
                    decision_report_sequence=decision_report_sequence,
                    version=1,
                    state_at=now,
                    analysis_at=now,
                    plan_at=now,
                    execute_at=now,
                    verify_at=now,
                    update_at=now,
                    started_at=now,
                    completed_at=now,
                )
                session.add(cycle)

                admissions: list[dict[str, Any]] = []
                idempotent_tasks: list[dict[str, Any]] = []
                normalized_tasks: list[dict[str, Any]] = []
                known_task_keys: dict[str, AgentRecord] = {}
                for task in dispatch_tasks:
                    digest = _stable_task_digest(
                        objective=task.objective,
                        kind=task.kind,
                        task_stage=task.task_stage,
                        context_refs=task.context_refs,
                        success_criteria=task.success_criteria,
                        explicit_task_key=task.task_key,
                    )
                    task_key = task.task_key or f"task:{digest}"
                    hypothesis_key = task.hypothesis_key or f"hypothesis:{digest}"
                    branch_key = task.branch_key or f"{hypothesis_key}:{task.kind}:{task.task_stage}"
                    existing: AgentRecord | None = None
                    if task_key:
                        existing = known_task_keys.get(task_key)
                        if existing is None:
                            existing = await session.scalar(
                                select(AgentRecord)
                                .where(
                                    AgentRecord.run_id == run_id,
                                    AgentRecord.unique_code == unique_code,
                                    AgentRecord.role == "execution",
                                    AgentRecord.task_key == task_key,
                                )
                                .limit(1)
                            )
                    if existing is not None:
                        idempotent_tasks.append(
                            {
                                "task_key": task_key,
                                "agent_id": existing.agent_id,
                                "status": existing.status,
                            }
                        )
                        continue

                    if task.hypothesis_key:
                        same_hypothesis = await session.scalar(
                            select(AgentRecord.agent_id)
                            .where(
                                AgentRecord.run_id == run_id,
                                AgentRecord.unique_code == unique_code,
                                AgentRecord.role == "execution",
                                AgentRecord.hypothesis_key == hypothesis_key,
                            )
                            .limit(1)
                        )
                        if same_hypothesis is not None:
                            warnings.append(
                                {
                                    "code": "duplicate_hypothesis",
                                    "message": "A task reuses an existing hypothesis",
                                    "details": {
                                        "hypothesis_key": hypothesis_key,
                                        "existing_agent_id": same_hypothesis,
                                    },
                                }
                            )
                    if task.branch_key:
                        same_branch = await session.scalar(
                            select(AgentRecord.agent_id)
                            .where(
                                AgentRecord.run_id == run_id,
                                AgentRecord.unique_code == unique_code,
                                AgentRecord.role == "execution",
                                AgentRecord.branch_key == branch_key,
                            )
                            .limit(1)
                        )
                        if same_branch is not None:
                            warnings.append(
                                {
                                    "code": "duplicate_branch",
                                    "message": "A task reuses an existing branch",
                                    "details": {
                                        "branch_key": branch_key,
                                        "existing_agent_id": same_branch,
                                    },
                                }
                            )

                    agent_id = f"execution_{uuid4().hex}"
                    hypothesis = HypothesisInput(
                        key=hypothesis_key,
                        statement=task.objective,
                    )
                    await self._upsert_hypothesis(
                        session,
                        run_id=run_id,
                        unique_code=unique_code,
                        hypothesis=hypothesis,
                        created_by=context.agent_id,
                        status="active",
                    )
                    await self._upsert_branch(
                        session,
                        run_id=run_id,
                        unique_code=unique_code,
                        branch_key=branch_key,
                        hypothesis_key=hypothesis_key,
                        kind=task.kind,
                        task_stage=task.task_stage,
                        priority=task.priority,
                        mission=task.objective,
                        agent_id=agent_id,
                        status="queued",
                    )
                    agent = AgentRecord(
                        agent_id=agent_id,
                        run_id=run_id,
                        parent_id=context.agent_id,
                        unique_code=unique_code,
                        cycle_id=cycle.cycle_id,
                        role="execution",
                        kind=task.kind,
                        task_stage=task.task_stage,
                        priority=task.priority,
                        hypothesis_key=hypothesis_key,
                        task_key=task_key,
                        branch_key=branch_key,
                        mission=task.objective,
                        success_criteria=list(task.success_criteria),
                        context_refs=list(task.context_refs),
                        timeout_seconds=task.timeout_seconds,
                        initial_prompt=task.objective,
                        session_memory=DEFAULT_SESSION_MEMORY,
                        status="queued",
                    )
                    session.add(agent)
                    known_task_keys[task_key] = agent
                    admission = AdmissionRecord(
                        admission_id=f"admission_{uuid4().hex}",
                        run_id=run_id,
                        agent_id=agent_id,
                        unique_code=unique_code,
                        role="execution",
                        priority=task.priority,
                    )
                    session.add(admission)
                    admissions.append(
                        {
                            "agent_id": agent_id,
                            "admission_id": admission.admission_id,
                            "status": "queued",
                            "task_key": task_key,
                        }
                    )
                    normalized_tasks.append(
                        {
                            **task.model_dump(mode="json"),
                            "task_key": task_key,
                            "hypothesis_key": hypothesis_key,
                            "branch_key": branch_key,
                        }
                    )

                cycle.plan = {"tasks": normalized_tasks}
                final_sequence = await self._event(
                    session,
                    run_id,
                    "challenge_dispatched",
                    {
                        "cycle_id": cycle.cycle_id,
                        "cycle_number": cycle.cycle_number,
                        "outcome": payload.outcome,
                        "task_count": len(admissions),
                        "bootstrap_followup_task_count": len(
                            bootstrap_followup_tasks
                        ),
                        "idempotent_task_count": len(idempotent_tasks),
                        "warning_count": len(warnings),
                        "soft_guard_warning_count": len(warnings),
                        "evidence_ref_count": len(payload.evidence_refs),
                        "dispatch_latency_ms": int(
                            (asyncio.get_running_loop().time() - started_at) * 1_000
                        ),
                        "decision_report_sequence": decision_report_sequence,
                        "transition_latency_ms": transition_latency_ms,
                    },
                    agent_id=context.agent_id,
                    cycle_id=cycle.cycle_id,
                )
                final_sequence = await self._event(
                    session,
                    run_id,
                    "cycle_transition_completed",
                    {
                        "cycle_id": cycle.cycle_id,
                        "next_cycle_id": cycle.cycle_id,
                        "remaining_execution_count": len(
                            await self._active_execution_ids_in_session(
                                session, run_id, unique_code, None
                            )
                        ),
                        "decision_report_sequence": decision_report_sequence,
                        "transition_latency_ms": transition_latency_ms,
                    },
                    agent_id=context.agent_id,
                    cycle_id=cycle.cycle_id,
                )

        await self.notifier.notify(self.run_signal_key(run_id), final_sequence)
        return {
            "decision_number": cycle.cycle_number,
            "admissions": admissions,
            "idempotent_tasks": idempotent_tasks,
            "warnings": warnings,
            "bootstrap_followup_task_count": len(bootstrap_followup_tasks),
            "decision_report_sequence": decision_report_sequence,
            "transition_latency_ms": transition_latency_ms,
        }

    async def _bootstrap_followup_tasks(
        self,
        session: Any,
        *,
        run_id: str,
        unique_code: str,
        controller_id: str,
        after_sequence: int,
        through_sequence: int,
    ) -> list[ExecutionTaskInput]:
        """Build deterministic validation/exploitation work from new Bootstrap findings."""

        rows = (
            await session.execute(
                select(ReportRecord, AgentRecord)
                .join(AgentRecord, AgentRecord.agent_id == ReportRecord.agent_id)
                .where(
                    ReportRecord.run_id == run_id,
                    ReportRecord.unique_code == unique_code,
                    ReportRecord.report_type == "execution",
                    ReportRecord.consumed_by == controller_id,
                    ReportRecord.sequence > after_sequence,
                    ReportRecord.sequence <= through_sequence,
                    ReportRecord.status.in_({"completed", "blocked"}),
                    AgentRecord.run_id == run_id,
                    AgentRecord.unique_code == unique_code,
                    AgentRecord.role == "execution",
                    AgentRecord.kind == "bootstrap",
                )
                .order_by(ReportRecord.sequence)
            )
        ).all()
        tasks: list[ExecutionTaskInput] = []
        seen_finding_refs: set[str] = set()
        for report, _bootstrap in rows:
            payload = report.payload if isinstance(report.payload, Mapping) else {}
            raw_findings = payload.get("findings")
            if not isinstance(raw_findings, list):
                continue
            candidate_flag_present = isinstance(
                payload.get("candidate_flag"), str
            ) and bool(str(payload.get("candidate_flag") or "").strip())
            for raw_finding in raw_findings:
                if not isinstance(raw_finding, Mapping):
                    continue
                finding_ref = raw_finding.get("finding_ref")
                if (
                    not isinstance(finding_ref, str)
                    or not REPORT_FINDING_REF_PATTERN.fullmatch(finding_ref)
                    or finding_ref in seen_finding_refs
                ):
                    continue
                finding = await session.get(
                    FindingRecord, finding_ref.removeprefix("finding:")
                )
                if (
                    finding is None
                    or finding.run_id != run_id
                    or finding.unique_code != unique_code
                    or finding.category not in BOOTSTRAP_FOLLOWUP_CATEGORIES
                    or finding.verification_status == "rejected"
                ):
                    continue
                detail = finding.detail if isinstance(finding.detail, Mapping) else {}
                raw_evidence_refs = detail.get("evidence_refs")
                if not isinstance(raw_evidence_refs, list):
                    continue
                candidate_evidence_refs = list(
                    dict.fromkeys(
                        ref
                        for ref in raw_evidence_refs
                        if isinstance(ref, str) and ref.startswith("evidence:")
                    )
                )
                if not candidate_evidence_refs:
                    continue
                evidence_ids = [
                    ref.removeprefix("evidence:")
                    for ref in candidate_evidence_refs
                ]
                valid_evidence_ids = set(
                    (
                        await session.scalars(
                            select(EvidenceRecord.evidence_id).where(
                                EvidenceRecord.run_id == run_id,
                                EvidenceRecord.unique_code == unique_code,
                                EvidenceRecord.evidence_id.in_(evidence_ids),
                            )
                        )
                    ).all()
                )
                evidence_refs = [
                    ref
                    for ref, evidence_id in zip(
                        candidate_evidence_refs, evidence_ids
                    )
                    if evidence_id in valid_evidence_ids
                ]
                if not evidence_refs:
                    continue
                verified = finding.verification_status == "verified"
                if not verified and finding.confidence < EVIDENCE_BACKED_PROGRESS_CONFIDENCE:
                    continue
                if finding.category == "flag" and candidate_flag_present:
                    continue

                finding_token = finding_ref.removeprefix("finding:")
                if verified:
                    task_stage = "exploitation"
                    kind = {
                        "vulnerability": "exploit",
                        "attack_path": "exploit",
                        "credential": "credential",
                        "privilege": "privilege",
                        "flag": "verification",
                    }[finding.category]
                    if finding.category == "flag":
                        task_stage = "validation"
                    priority = 95 if kind == "exploit" else 90
                    if finding.category == "flag":
                        objective = (
                            f"Validate verified Bootstrap flag finding {finding_ref}: "
                            f"{finding.summary}. Use the assigned Evidence and do not "
                            "repeat the same discovery branch."
                        )
                    else:
                        objective = (
                            f"Validate impact and perform the narrowest authorized "
                            f"exploitation of verified Bootstrap finding {finding_ref}: "
                            f"{finding.summary}. Use the assigned Evidence and do not "
                            "repeat the same discovery branch."
                        )
                else:
                    task_stage = "validation"
                    kind = "verification"
                    priority = 85
                    objective = (
                        f"Validate Bootstrap finding {finding_ref}: {finding.summary}. "
                        "Use the assigned Evidence to confirm or reject the claim; "
                        "do not repeat the same discovery branch."
                    )
                tasks.append(
                    ExecutionTaskInput(
                        objective=objective,
                        task_key=f"bootstrap:{finding_ref}:{task_stage}",
                        hypothesis_key=f"finding:{finding_token}",
                        branch_key=f"finding:{finding_ref}:{task_stage}",
                        kind=kind,
                        task_stage=task_stage,
                        priority=priority,
                        success_criteria=[
                            "Use the assigned finding and Evidence references as context.",
                            "Do not create another discovery task for the same finding.",
                            "Report verified or rejected with fresh Evidence references when available.",
                        ],
                        context_refs=[finding_ref, *evidence_refs[:10]],
                    )
                )
                seen_finding_refs.add(finding_ref)
        return tasks

    async def submit_report(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        payload: AgentReportInput,
    ) -> dict[str, Any]:
        return await self.finalize_execution_agent(
            run_id, agent_id, context, payload
        )
    async def _filter_report_evidence_refs(
        self,
        session: Any,
        run_id: str,
        agent: AgentRecord,
        values: Sequence[Any],
        warnings: list[dict[str, Any]],
        *,
        field: str,
    ) -> list[str]:
        accepted: list[str] = []
        for index, value in enumerate(values):
            if (
                not isinstance(value, str)
                or not value.startswith("evidence:evidence_")
                or len(value) != len("evidence:evidence_") + 32
            ):
                warnings.append(
                    {
                        "code": "invalid_evidence_ref",
                        "message": "Evidence reference was dropped",
                        "details": {"field": field, "index": index},
                    }
                )
                continue
            row = await session.get(EvidenceRecord, value.removeprefix("evidence:"))
            same_challenge = row is not None and row.unique_code == agent.unique_code
            owned = row is not None and row.agent_id == agent.agent_id
            bootstrap_shared = agent.kind == "bootstrap" and same_challenge
            if row is None or row.run_id != run_id or not (owned or bootstrap_shared):
                warnings.append(
                    {
                        "code": "evidence_not_accessible",
                        "message": "Evidence reference was dropped",
                        "details": {"field": field, "index": index},
                    }
                )
                continue
            accepted.append(value)
        return accepted

    async def _record_report_findings_best_effort(
        self,
        session: Any,
        run_id: str,
        agent: AgentRecord,
        values: Sequence[Mapping[str, Any]],
        warnings: list[dict[str, Any]],
    ) -> tuple[set[str], list[dict[str, Any]], dict[str, int]]:
        progress_kinds: set[str] = set()
        saved: list[dict[str, Any]] = []
        stats = {
            "received": len(values),
            "persisted": 0,
            "dropped": 0,
            "normalized": 0,
        }
        for index, raw in enumerate(values):
            if not isinstance(raw, Mapping):
                warnings.append(
                    {
                        "code": "invalid_finding_dropped",
                        "message": "Malformed optional finding was dropped",
                        "details": {"index": index},
                    }
                )
                stats["dropped"] += 1
                continue
            normalized = False
            finding_ref = raw.get("finding_ref")
            existing: FindingRecord | None = None
            downgraded_finding_ref: str | None = None
            if isinstance(finding_ref, str) and REPORT_FINDING_REF_PATTERN.fullmatch(
                finding_ref
            ):
                existing = await session.get(
                    FindingRecord, finding_ref.removeprefix("finding:")
                )
                if (
                    existing is None
                    or existing.run_id != run_id
                    or existing.unique_code != agent.unique_code
                    or existing.verification_status != "candidate"
                    or finding_ref not in (agent.context_refs or [])
                ):
                    existing = None
                    downgraded_finding_ref = finding_ref
                    warnings.append(
                        {
                            "code": "finding_ref_downgraded",
                            "message": "Finding reference was not an active assigned candidate; item was treated as a new finding",
                            "details": {"index": index},
                        }
                    )
            elif finding_ref is not None:
                downgraded_finding_ref = str(finding_ref)
                warnings.append(
                    {
                        "code": "invalid_finding_ref",
                        "message": "Malformed finding reference was ignored",
                        "details": {"index": index},
                    }
                )

            summary_value = raw.get("summary")
            if not isinstance(summary_value, str) or not summary_value.strip():
                title = raw.get("title")
                if isinstance(title, str) and title.strip():
                    summary_value = title
                    normalized = True
            if not isinstance(summary_value, str) or not summary_value.strip():
                warnings.append(
                    {
                        "code": "invalid_finding_dropped",
                        "message": "Optional finding without a usable summary was dropped",
                        "details": {"index": index},
                    }
                )
                stats["dropped"] += 1
                continue
            summary = summary_value.strip()
            if len(summary) > 2_000:
                summary = summary[:2_000]
                normalized = True

            category_value = raw.get("category", "other")
            category = (
                category_value.strip().lower()
                if isinstance(category_value, str)
                else "other"
            )
            if category not in REPORT_FINDING_CATEGORIES:
                category = "other"
                normalized = True

            detail_value = raw.get("detail")
            if isinstance(detail_value, Mapping):
                detail = dict(detail_value)
            elif isinstance(detail_value, str) and detail_value.strip():
                detail = {"description": detail_value.strip()}
                normalized = True
            else:
                detail = {}
                if detail_value is not None and detail_value != "":
                    normalized = True
            if downgraded_finding_ref:
                detail.setdefault(
                    "client_finding_ref", downgraded_finding_ref[:256]
                )
                normalized = True
            client_label = raw.get("finding_id", raw.get("id"))
            if isinstance(client_label, str) and client_label.strip():
                detail.setdefault("client_label", client_label.strip()[:256])
                normalized = True
            severity = raw.get("severity")
            if isinstance(severity, str) and severity.strip():
                detail.setdefault("severity", severity.strip()[:64])
                normalized = True

            confidence_value = raw.get("confidence", 0.5)
            if isinstance(confidence_value, str):
                confidence = REPORT_CONFIDENCE_ALIASES.get(
                    confidence_value.strip().lower(), 0.5
                )
                normalized = True
            elif isinstance(confidence_value, (int, float)) and not isinstance(
                confidence_value, bool
            ):
                confidence = float(confidence_value)
                if not 0.0 <= confidence <= 1.0:
                    confidence = 0.5
                    normalized = True
            else:
                confidence = 0.5
                if confidence_value is not None:
                    normalized = True

            verification_value = raw.get("verification_status", "candidate")
            verification_status = (
                REPORT_VERIFICATION_ALIASES.get(
                    verification_value.strip().lower(), "candidate"
                )
                if isinstance(verification_value, str)
                else "candidate"
            )
            if verification_status != verification_value:
                normalized = True

            raw_item_evidence = raw.get("evidence_refs", [])
            if not isinstance(raw_item_evidence, list):
                warnings.append(
                    {
                        "code": "invalid_evidence_refs_dropped",
                        "message": "Malformed optional finding Evidence refs were dropped",
                        "details": {"field": f"findings[{index}].evidence_refs"},
                    }
                )
                raw_item_evidence = []
            evidence_refs = await self._filter_report_evidence_refs(
                session,
                run_id,
                agent,
                raw_item_evidence,
                warnings,
                field=f"findings[{index}].evidence_refs",
            )
            try:
                parsed = FindingInput(
                    category=category,
                    summary=summary,
                    detail=detail,
                    confidence=confidence,
                    verification_status=verification_status,
                    evidence_paths=[],
                )
            except Exception:
                warnings.append(
                    {
                        "code": "invalid_finding_dropped",
                        "message": "Invalid optional finding was dropped",
                        "details": {"index": index},
                    }
                )
                stats["dropped"] += 1
                continue
            if existing is not None:
                previous = existing.verification_status
                previous_refs = list((existing.detail or {}).get("evidence_refs", []))
                merged_refs = list(dict.fromkeys([*previous_refs, *evidence_refs]))
                next_detail = {**parsed.detail, "evidence_refs": merged_refs}
                changed = (
                    existing.summary != parsed.summary
                    or existing.detail != next_detail
                    or parsed.confidence > existing.confidence
                    or existing.verification_status != parsed.verification_status
                )
                existing.summary = parsed.summary
                existing.detail = next_detail
                existing.confidence = max(existing.confidence, parsed.confidence)
                existing.verification_status = parsed.verification_status
                existing.last_seen_at = self.clock()
                if changed:
                    existing.version += 1
                if (
                    previous == "candidate"
                    and parsed.verification_status in {"verified", "rejected"}
                    and evidence_refs
                ):
                    progress_kinds.add(f"finding_{parsed.verification_status}")
                elif set(merged_refs) - set(previous_refs):
                    progress_kinds.add(f"finding_{parsed.verification_status}")
                saved.append(self._finding_dict(existing))
                stats["persisted"] += 1
                if normalized:
                    stats["normalized"] += 1
                continue

            fingerprint = _fingerprint(parsed.category, parsed.summary, parsed.detail)
            previous_record = await session.scalar(
                select(FindingRecord).where(
                    FindingRecord.run_id == run_id,
                    FindingRecord.unique_code == agent.unique_code,
                    FindingRecord.category == parsed.category,
                    FindingRecord.fingerprint == fingerprint,
                )
            )
            previous_refs = (
                list((previous_record.detail or {}).get("evidence_refs", []))
                if previous_record is not None
                else []
            )
            item_progress, items = await self._record_findings(
                session,
                run_id,
                agent.unique_code,
                agent.agent_id,
                [parsed],
                task_stage=None,
                count_evidence_backed_candidates=False,
            )
            progress_kinds.update(item_progress)
            if items:
                record = await session.get(FindingRecord, items[0]["finding_id"])
                if record is not None:
                    merged_refs = list(dict.fromkeys([*previous_refs, *evidence_refs]))
                    if merged_refs != previous_refs:
                        record.detail = {**(record.detail or {}), "evidence_refs": merged_refs}
                        if previous_record is not None:
                            record.version += 1
                        progress_kinds.add(f"finding_{record.verification_status}")
                    saved.append(self._finding_dict(record))
                else:
                    saved.extend(items)
            stats["persisted"] += 1
            if normalized:
                stats["normalized"] += 1
        return progress_kinds, saved, stats

    async def _finalize_lightweight_execution(
        self,
        run_id: str,
        agent_id: str,
        context: CapabilityContext,
        payload: AgentReportInput,
        *,
        terminal_status: str | None,
        allow_inactive: bool,
    ) -> dict[str, Any]:
        parent_id: str | None = None
        bootstrap_ids: list[str] = []
        warnings: list[dict[str, Any]] = []
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await self._authorize(
                    session, context, roles={"execution"}, agent_id=agent_id
                )
                if agent.terminal_report_id is not None:
                    existing = await session.get(ReportRecord, agent.terminal_report_id)
                    if existing is None:
                        raise StateError(
                            "terminal_report_missing",
                            "Execution Agent terminal report reference is invalid",
                            status_code=409,
                        )
                    return {
                        "report_id": existing.report_id,
                        "sequence": existing.sequence,
                        "status": existing.status,
                        "idempotent": True,
                        "warnings": [],
                    }
                challenge = (
                    await self._require_challenge(session, run_id, agent.unique_code)
                    if agent.unique_code
                    else None
                )
                if (
                    challenge is not None
                    and not allow_inactive
                    and (challenge.work_status in {"paused", "closed"} or challenge.is_completed)
                ):
                    raise StateConflict(
                        "challenge_not_active",
                        "The challenge no longer accepts Agent reports",
                    )
                raw_outcome = payload.hypothesis_outcome
                outcome = (
                    HYPOTHESIS_OUTCOME_ALIASES.get(raw_outcome.strip().lower())
                    if isinstance(raw_outcome, str)
                    else None
                )
                if outcome is None:
                    warnings.append(
                        {
                            "code": "invalid_hypothesis_outcome",
                            "message": "Unknown hypothesis outcome was recorded as inconclusive",
                            "details": {"received": raw_outcome},
                        }
                    )
                    outcome = "inconclusive"
                raw_evidence_refs = payload.evidence_refs
                if not isinstance(raw_evidence_refs, list):
                    warnings.append(
                        {
                            "code": "invalid_evidence_refs_dropped",
                            "message": "Malformed optional Evidence refs were dropped",
                            "details": {},
                        }
                    )
                    raw_evidence_refs = []
                evidence_refs = await self._filter_report_evidence_refs(
                    session,
                    run_id,
                    agent,
                    raw_evidence_refs,
                    warnings,
                    field="evidence_refs",
                )
                raw_findings = payload.findings
                if not isinstance(raw_findings, list):
                    warnings.append(
                        {
                            "code": "invalid_findings_dropped",
                            "message": "Malformed optional findings were dropped",
                            "details": {},
                        }
                    )
                    raw_findings = []
                progress_kinds, findings, finding_stats = await self._record_report_findings_best_effort(
                    session,
                    run_id,
                    agent,
                    raw_findings,
                    warnings,
                )
                valid = bool(progress_kinds) or bool(payload.candidate_flag)
                if challenge is not None and valid:
                    self._mark_progress(challenge)
                safe_payload: dict[str, Any] = {
                    "status": payload.status,
                    "summary": payload.summary,
                    "findings": findings,
                    "evidence_refs": evidence_refs,
                    "next_steps": payload.next_steps,
                    "confidence": payload.confidence,
                    "hypothesis_outcome": outcome,
                }
                if payload.candidate_flag is not None:
                    safe_payload["candidate_flag"] = payload.candidate_flag
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
                }[payload.status]
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
                        }[payload.status]
                        branch.outcome = {
                            **branch.outcome,
                            "report_id": report.report_id,
                            "hypothesis_outcome": outcome,
                        }
                        branch.last_progress_at = self.clock()
                parent_id = agent.parent_id
                if agent.unique_code:
                    bootstrap_ids = list(
                        (
                            await session.scalars(
                                select(AgentRecord.agent_id).where(
                                    AgentRecord.run_id == run_id,
                                    AgentRecord.unique_code == agent.unique_code,
                                    AgentRecord.kind == "bootstrap",
                                    AgentRecord.status.not_in(
                                        ["failed", "stopped", "completed", "cancelled", "interrupted"]
                                    ),
                                    AgentRecord.agent_id != agent.agent_id,
                                )
                            )
                        ).all()
                    )
                await self._event_with_sequence(
                    session,
                    run_id,
                    sequence,
                    "agent_report",
                    {
                        "report_id": report.report_id,
                        "agent_id": agent_id,
                        "status": payload.status,
                        "valid_progress": valid,
                        "progress_kinds": sorted(progress_kinds),
                        "findings_received": finding_stats["received"],
                        "findings_persisted": finding_stats["persisted"],
                        "findings_dropped": finding_stats["dropped"],
                        "findings_normalized": finding_stats["normalized"],
                        "candidate_flag_present": payload.candidate_flag is not None,
                        "report_items_dropped": sum(
                            1
                            for warning in warnings
                            if warning["code"].endswith("dropped")
                            or warning["code"].endswith("accessible")
                        ),
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
                if agent.kind == "bootstrap":
                    await self._event(
                        session,
                        run_id,
                        "bootstrap_completed",
                        {
                            "agent_id": agent.agent_id,
                            "terminal_status": resolved_status,
                            "candidate_flag_present": payload.candidate_flag is not None,
                        },
                        agent_id=agent.agent_id,
                    )
                result = {
                    "report_id": report.report_id,
                    "sequence": sequence,
                    "status": payload.status,
                    "hypothesis_outcome": outcome,
                    "valid_progress": valid,
                    "progress_kinds": sorted(progress_kinds),
                    "findings": findings,
                    "warnings": warnings,
                }
                if payload.candidate_flag is not None:
                    self._ephemeral_reports[report.report_id] = payload.candidate_flag
        if parent_id:
            await self.notifier.notify(
                self.agent_signal_key(run_id, parent_id), sequence
            )
        for bootstrap_id in bootstrap_ids:
            await self.notifier.notify(
                self.agent_signal_key(run_id, bootstrap_id), sequence
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

        return await self._finalize_lightweight_execution(
            run_id,
            agent_id,
            context,
            payload,
            terminal_status=terminal_status,
            allow_inactive=allow_inactive,
        )
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

    async def record_controller_wait(
        self,
        run_id: str,
        agent_id: str,
        reason: str | None,
    ) -> dict[str, Any]:
        """Yield a Challenge controller unless unread state is already ready."""

        normalized_reason = (reason or "waiting for new challenge state").strip()
        async with self._lock:
            async with self.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != run_id:
                    raise StateNotFound("agent_not_found", "Agent was not found")
                if agent.role != "challenge" or not agent.unique_code:
                    raise StatePermission(
                        "challenge_controller_required",
                        "Only a Challenge Agent can wait on Execution dependencies",
                    )
                current_cursor = int(
                    (agent.report_cursors or {}).get("execution", 0)
                )
                available_report_sequences = list(
                    (
                        await session.scalars(
                            select(ReportRecord.sequence)
                            .where(
                                ReportRecord.run_id == run_id,
                                ReportRecord.parent_id == agent.agent_id,
                                ReportRecord.report_type == "execution",
                                ReportRecord.sequence > current_cursor,
                            )
                            .order_by(ReportRecord.sequence)
                            .limit(20)
                        )
                    ).all()
                )
                if available_report_sequences:
                    return {
                        "status": "ready",
                        "reason": normalized_reason,
                        "reports_available": len(available_report_sequences),
                        "next_report_sequence": available_report_sequences[0],
                    }
                decided_through = int(
                    await session.scalar(
                        select(func.max(CycleRecord.decision_report_sequence)).where(
                            CycleRecord.run_id == run_id,
                            CycleRecord.unique_code == agent.unique_code,
                        )
                    )
                    or 0
                )
                snapshots = list(
                    (
                        await session.scalars(
                            select(StateEventRecord)
                            .where(
                                StateEventRecord.run_id == run_id,
                                StateEventRecord.agent_id == agent_id,
                                StateEventRecord.event_type == "controller_snapshot",
                            )
                            .order_by(StateEventRecord.sequence.desc())
                            .limit(50)
                        )
                    ).all()
                )
                for snapshot in snapshots:
                    snapshot_payload = snapshot.payload or {}
                    through_sequence = int(
                        snapshot_payload.get("through_sequence") or 0
                    )
                    snapshot_reports = snapshot_payload.get("reports")
                    if (
                        snapshot_payload.get("report_type") == "execution"
                        and through_sequence > decided_through
                        and isinstance(snapshot_reports, list)
                        and snapshot_reports
                    ):
                        return {
                            "status": "ready",
                            "reason": normalized_reason,
                            "reports_available": len(snapshot_reports),
                            "next_report_sequence": through_sequence,
                            "pending_snapshot": True,
                        }
                agent.status = "waiting"
                agent.ended_at = None
                agent.version += 1
                sequence = await self._event(
                    session,
                    run_id,
                    "challenge_wait_requested",
                    {
                        "agent_id": agent_id,
                        "reason": normalized_reason,
                    },
                    agent_id=agent_id,
                    cycle_id=agent.cycle_id,
                )
        return {
            "status": "waiting",
            "reason": normalized_reason,
            "sequence": sequence,
        }

    async def start_challenge(self, run_id: str, unique_code: str, context: CapabilityContext | None = None) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                if context is not None:
                    await self._authorize(session, context, roles={"chief", "challenge"}, unique_code=unique_code)
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
                challenge.pause_reason = None
                challenge.stagnation_level = 0
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

    async def mark_completed_container_release_pending(
        self, run_id: str, unique_code: str, *, agent_id: str | None = None
    ) -> dict[str, Any]:
        """Persist that a completed container needs an idempotent close retry."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                challenge = await self._require_challenge(session, run_id, unique_code)
                if not challenge.is_completed or not container_slot_occupied(
                    challenge.container_status
                ):
                    return self._challenge_dict(challenge)
                challenge.platform_status = "close_requested"
                challenge.container_status = "release_pending"
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

    async def sample_resources(self, run_id: str, cpu_percent: float, memory_percent: float) -> dict[str, Any]:
        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_run(session, run_id)
                record = ResourceSampleRecord(run_id=run_id, cpu_percent=cpu_percent, memory_percent=memory_percent, sampled_at=self.clock())
                session.add(record)
        return {"cpu_percent": cpu_percent, "memory_percent": memory_percent, "sampled_at": _json_value(record.sampled_at)}

    async def project_pending_events(
        self,
        run_id: str,
        *,
        run_dir: Path | None = None,
        limit: int = 100,
        force_checkpoint: bool = False,
    ) -> int:
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
        task_stage: str | None = None,
        count_candidate_attack_paths: bool = False,
        count_evidence_backed_candidates: bool = False,
    ) -> tuple[set[str], list[dict[str, Any]]]:
        if not unique_code:
            return set(), []
        added: list[dict[str, Any]] = []
        progress_kinds: set[str] = set()
        challenge = await self._require_challenge(session, run_id, unique_code)
        for value in values:
            if (
                task_stage == "discovery"
                and value.category in EVIDENCE_PROGRESS_CATEGORIES
                and value.verification_status != "candidate"
            ):
                value = value.model_copy(update={"verification_status": "candidate"})
            normalized_paths = self._validate_evidence_paths(
                run_id,
                unique_code,
                value.evidence_paths,
                evidence_root_path=self._ensure_evidence_root_dir(challenge),
            )
            if normalized_paths != value.evidence_paths:
                value = value.model_copy(update={"evidence_paths": normalized_paths})
            fingerprint = _fingerprint(value.category, value.summary, value.detail)
            summary = value.summary
            detail = value.detail
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
                    progress_kinds.add("verified_finding")
                elif value.verification_status == "rejected" and value.evidence_paths:
                    progress_kinds.add("rejected_finding")
                elif (
                    count_candidate_attack_paths
                    and value.category == "attack_path"
                    and value.evidence_paths
                    and value.detail.get("verification_steps")
                ):
                    progress_kinds.add("new_attack_path")
                elif (
                    task_stage in {"validation", "exploitation"}
                    and value.category == "attack_path"
                    and value.evidence_paths
                    and value.detail.get("verification_steps")
                ):
                    progress_kinds.add("new_attack_path")
                elif (
                    task_stage != "discovery"
                    and count_evidence_backed_candidates
                    and value.verification_status == "candidate"
                    and value.confidence >= EVIDENCE_BACKED_PROGRESS_CONFIDENCE
                    and value.evidence_paths
                ):
                    progress_kinds.add("evidence_backed_discovery")
            else:
                existing.last_seen_at = now
                was_evidence_backed_candidate = (
                    existing.verification_status == "candidate"
                    and existing.confidence >= EVIDENCE_BACKED_PROGRESS_CONFIDENCE
                    and bool(existing.evidence_paths)
                )
                previous_confidence = existing.confidence
                previous_evidence_paths = list(existing.evidence_paths)
                existing.confidence = max(existing.confidence, value.confidence)
                existing.evidence_paths = list(dict.fromkeys([*existing.evidence_paths, *value.evidence_paths]))
                changed = (
                    existing.confidence != previous_confidence
                    or existing.evidence_paths != previous_evidence_paths
                )
                if existing.verification_status != "verified" and value.verification_status == "verified":
                    existing.verification_status = "verified"
                    existing.verified_at = now
                    changed = True
                    if value.evidence_paths:
                        progress_kinds.add("verified_finding")
                elif (
                    existing.verification_status == "candidate"
                    and value.verification_status == "rejected"
                ):
                    existing.verification_status = "rejected"
                    existing.verified_at = None
                    changed = True
                    if value.evidence_paths:
                        progress_kinds.add("rejected_finding")
                elif (
                    task_stage != "discovery"
                    and count_evidence_backed_candidates
                    and not was_evidence_backed_candidate
                    and existing.verification_status == "candidate"
                    and existing.confidence >= EVIDENCE_BACKED_PROGRESS_CONFIDENCE
                    and existing.evidence_paths
                ):
                    progress_kinds.add("evidence_backed_discovery")
                if changed:
                    existing.version += 1
            added.append(self._finding_dict(existing))
        return progress_kinds, added

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
        self._ensure_evidence_root(challenge)
        self._ensure_evidence_root_dir(challenge)
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
        challenge.exploration_seconds = 0
        challenge.last_progress_at = now
        challenge.stagnation_level = 0
        challenge.hint_eligible = False
        challenge.work_status = "completed" if challenge.is_completed else "active"
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
        if not challenge.evidence_root or Path(challenge.evidence_root).name != target_fingerprint:
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
        task_stage: str,
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
            existing.task_stage = task_stage
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
                task_stage=task_stage,
                status=status,
                priority=priority,
                mission=mission,
                agent_ids=[agent_id] if agent_id else [],
                created_at=now,
                updated_at=now,
            )
        )
        return True

    async def _cancel_live_branches(
        self,
        session: Any,
        run_id: str,
        unique_code: str,
        *,
        reason: str,
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
            branch.status = "cancelled"
            branch.outcome = {
                **branch.outcome,
                "cancelled_at": _json_value(now),
                "reason": reason,
            }
            branch.updated_at = now
            branch.version += 1
            cancelled.append(branch.branch_key)
        return cancelled

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
            evidence_root = evidence_root_path or (
                self.workspace_root
                / ".aion"
                / "runs"
                / run_id
                / "challenges"
                / unique_code
                / "evidence"
            ).resolve()
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
                if created and route_branches:
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
                            task_stage=route.task_stage,
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
                    "task_stage": item.task_stage,
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
        """Cancel every live branch after an explicit Challenge termination."""

        async with self._lock:
            async with self.db.sessions.begin() as session:
                await self._require_challenge(session, run_id, unique_code)
                return await self._cancel_live_branches(
                    session,
                    run_id,
                    unique_code,
                    reason=reason,
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
        record.flag_count = max(
            int(record.flag_count or 0), int(value.flag_count or 0)
        )
        record.correct_flag_count = max(
            int(record.correct_flag_count or 0),
            int(value.correct_flag_count or 0),
        )
        record.is_completed = bool(
            record.is_completed
            or value.is_completed
        )
        if record.is_completed:
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
        return {"run_id": item.run_id, "status": item.status, "phase": item.phase, "model": item.model, "prompt": item.prompt, "context_window_tokens": item.context_window_tokens, "duration_minutes": item.duration_minutes, "started_at": _json_value(item.started_at), "deadline_at": _json_value(item.deadline_at), "current_challenge_code": item.current_challenge_code, "score_snapshot": item.score_snapshot, "last_sequence": item.last_sequence, "last_projected_sequence": item.last_projected_sequence, "stagnation_epoch": item.stagnation_epoch, "paused_at": _json_value(item.paused_at), "pause_reason": item.pause_reason}

    @staticmethod
    def _challenge_dict(item: ChallengeRecord) -> dict[str, Any]:
        return {"run_id": item.run_id, "unique_code": item.unique_code, "description": item.description, "difficulty": item.difficulty, "level": item.level, "total_score": item.total_score, "flag_count": item.flag_count, "correct_flag_count": item.correct_flag_count, "is_completed": item.is_completed, "platform_status": item.platform_status, "container_status": item.container_status, "slot_occupied": container_slot_occupied(item.container_status), "container_addr": item.container_addr, "direction": item.direction, "work_status": item.work_status, "control_state": item.control_state, "control_since": _json_value(item.control_since), "pause_reason": item.pause_reason, "evidence_root": item.evidence_root, "low_yield": item.stagnation_level > 0, "hint_eligible": item.hint_eligible, "hint_requested": item.hint_requested, "exploration_seconds": item.exploration_seconds, "active_since": _json_value(item.active_since), "last_progress_at": _json_value(item.last_progress_at)}

    @staticmethod
    def _agent_dict(item: AgentRecord, *, include_runtime: bool = False) -> dict[str, Any]:
        data = {"agent_id": item.agent_id, "run_id": item.run_id, "parent_id": item.parent_id, "unique_code": item.unique_code, "cycle_id": item.cycle_id, "role": item.role, "kind": item.kind, "task_stage": item.task_stage, "priority": item.priority, "mission": item.mission, "success_criteria": item.success_criteria, "context_refs": item.context_refs, "hypothesis_key": item.hypothesis_key, "task_key": item.task_key, "branch_key": item.branch_key, "terminal_report_id": item.terminal_report_id, "status": item.status, "timeout_seconds": item.timeout_seconds, "last_heartbeat_at": _json_value(item.last_heartbeat_at), "last_report_sequence": item.last_report_sequence, "report_cursor": item.report_cursor, "report_cursors": item.report_cursors, "controller_cursor": item.controller_cursor, "last_summarized_sequence": item.last_summarized_sequence, "active_skills": item.active_skills or [], "started_at": _json_value(item.started_at), "ended_at": _json_value(item.ended_at), "stop_requested_at": _json_value(item.stop_requested_at), "updated_at": _json_value(item.updated_at), "version": item.version}
        if include_runtime:
            data.update({"initial_prompt": item.initial_prompt, "session_memory": item.session_memory, "final_report": item.final_report})
        return data

    @staticmethod
    def _cycle_dict(item: CycleRecord) -> dict[str, Any]:
        return {"cycle_id": item.cycle_id, "run_id": item.run_id, "unique_code": item.unique_code, "cycle_number": item.cycle_number, "status": item.status, "state_snapshot": item.state_snapshot, "analysis": item.analysis, "plan": item.plan, "verification": item.verification, "state_update": item.state_update, "report_cursor_at_start": item.report_cursor_at_start, "decision_report_sequence": item.decision_report_sequence, "version": item.version, "state_at": _json_value(item.state_at), "analysis_at": _json_value(item.analysis_at), "plan_at": _json_value(item.plan_at), "execute_at": _json_value(item.execute_at), "verify_at": _json_value(item.verify_at), "update_at": _json_value(item.update_at), "completed_at": _json_value(item.completed_at)}

    @staticmethod
    def _compact_cycle_dict(item: CycleRecord) -> dict[str, Any]:
        return {
            "cycle_id": item.cycle_id,
            "cycle_number": item.cycle_number,
            "status": item.status,
            "version": item.version,
            "analysis": {
                "summary": str((item.analysis or {}).get("summary", ""))[:2_000],
                "direction": (item.analysis or {}).get("direction", "unknown"),
            },
            "plan": {
                "tasks": [
                    {
                        "task_key": task.get("task_key"),
                        "hypothesis_key": task.get("hypothesis_key"),
                        "task_stage": task.get("task_stage"),
                        "context_refs": task.get("context_refs", []),
                    }
                    for task in list((item.plan or {}).get("tasks", []))[:20]
                    if isinstance(task, Mapping)
                ]
            },
            "verification": {
                "summary": str((item.verification or {}).get("summary", ""))[:2_000],
                "outcome": (item.verification or {}).get("outcome"),
            },
            "completed_at": _json_value(item.completed_at),
        }

    @staticmethod
    def _finding_dict(item: FindingRecord) -> dict[str, Any]:
        return {"finding_id": item.finding_id, "finding_ref": f"finding:{item.finding_id}", "unique_code": item.unique_code, "category": item.category, "fingerprint": item.fingerprint, "summary": item.summary, "detail": item.detail, "confidence": item.confidence, "verification_status": item.verification_status, "evidence_refs": list((item.detail or {}).get("evidence_refs", []))}

    @staticmethod
    def _controller_finding_dict(item: FindingRecord) -> dict[str, Any]:
        return {
            "finding_ref": f"finding:{item.finding_id}",
            "category": item.category,
            "summary": _controller_text(item.summary, CONTROLLER_SUMMARY_CHARS),
            "confidence": item.confidence,
            "verification_status": item.verification_status,
            "evidence_refs": _controller_refs(
                (item.detail or {}).get("evidence_refs")
            ),
        }

    @staticmethod
    def _credential_dict(item: CredentialRecord, *, include_secret: bool) -> dict[str, Any]:
        data = {"credential_id": item.credential_id, "unique_code": item.unique_code, "finding_id": item.finding_id, "kind": item.kind, "principal": item.principal, "scope": item.scope, "verified": item.verified}
        if include_secret:
            data["secret_value"] = item.secret_value
        return data

    @staticmethod
    def _report_dict(
        item: ReportRecord,
        *,
        cycle_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "report_id": item.report_id,
            "report_ref": f"report:{item.report_id}",
            "sequence": item.sequence,
            "agent_id": item.agent_id,
            "parent_id": item.parent_id,
            "unique_code": item.unique_code,
            "cycle_id": cycle_id,
            "report_type": item.report_type,
            "status": item.status,
            "payload": item.payload,
            "created_at": _json_value(item.created_at),
        }

    @staticmethod
    def _controller_report_projection(item: Mapping[str, Any]) -> dict[str, Any]:
        payload = item.get("payload")
        payload_map = payload if isinstance(payload, Mapping) else {}
        projected_payload: dict[str, Any] = {
            "status": payload_map.get("status") or item.get("status"),
            "summary": _controller_text(
                payload_map.get("summary"), CONTROLLER_SUMMARY_CHARS
            ),
            "confidence": payload_map.get("confidence"),
            "hypothesis_outcome": payload_map.get("hypothesis_outcome"),
            "evidence_refs": _controller_refs(payload_map.get("evidence_refs")),
            "next_steps": [
                _controller_text(value, CONTROLLER_NEXT_STEP_CHARS)
                for value in list(payload_map.get("next_steps") or [])[:4]
            ],
            "findings": [],
        }
        for raw_finding in list(payload_map.get("findings") or [])[:CONTROLLER_FINDING_LIMIT]:
            if not isinstance(raw_finding, Mapping):
                continue
            projected_payload["findings"].append(
                {
                    "finding_ref": raw_finding.get("finding_ref"),
                    "category": raw_finding.get("category"),
                    "summary": _controller_text(
                        raw_finding.get("summary") or raw_finding.get("title"),
                        CONTROLLER_SUMMARY_CHARS,
                    ),
                    "confidence": raw_finding.get("confidence"),
                    "verification_status": raw_finding.get("verification_status"),
                    "evidence_refs": _controller_refs(raw_finding.get("evidence_refs")),
                }
            )
        candidate_flag = payload_map.get("candidate_flag")
        if isinstance(candidate_flag, str) and candidate_flag:
            projected_payload["candidate_flag"] = candidate_flag
        return {
            "report_id": item.get("report_id"),
            "report_ref": item.get("report_ref"),
            "sequence": item.get("sequence"),
            "agent_id": item.get("agent_id"),
            "parent_id": item.get("parent_id"),
            "unique_code": item.get("unique_code"),
            "cycle_id": item.get("cycle_id"),
            "report_type": item.get("report_type"),
            "status": item.get("status"),
            "payload": projected_payload,
            "created_at": item.get("created_at"),
        }

    def _report_with_ephemeral(
        self,
        item: ReportRecord,
        *,
        cycle_id: str | None = None,
    ) -> dict[str, Any]:
        data = self._report_dict(item, cycle_id=cycle_id)
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
