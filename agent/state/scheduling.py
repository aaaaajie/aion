"""Offline scheduling, resource admission, and stagnation control."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import psutil
from sqlalchemy import func, select

from .clock import active_seconds, aware, utc_now
from .models import (
    AdmissionRecord,
    AgentRecord,
    ChallengeRecord,
    FindingRecord,
    ResourceWorkRecord,
)
from .resources import challenge_work_active
from .service import StateService, derive_phase


DIFFICULTY_RANK = {"easy": 0, "medium": 1, "hard": 2}


class ResourceController:
    """Gate execution starts using live samples and durable reservations."""

    def __init__(
        self,
        service: StateService,
        run_id: str,
        *,
        cpu_limit_percent: float = 70.0,
        memory_limit_percent: float = 70.0,
        start_interval_seconds: float = 5.0,
        storage_root: Path | None = None,
        disk_reserve_bytes: int = 1_073_741_824,
        disk_reserve_percent: float = 5.0,
        psutil_module: Any = psutil,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.service = service
        self.run_id = run_id
        self.cpu_limit_percent = cpu_limit_percent
        self.memory_limit_percent = memory_limit_percent
        self.start_interval_seconds = start_interval_seconds
        self.storage_root = (storage_root or service.db.path.parent).resolve()
        self.disk_reserve_bytes = max(0, disk_reserve_bytes)
        self.disk_reserve_percent = max(0.0, disk_reserve_percent)
        self.psutil = psutil_module
        self.clock = clock
        self._lock = asyncio.Lock()
        self._sampling_task: asyncio.Task[None] | None = None

    async def sample(self) -> dict[str, float]:
        cpu = float(self.psutil.cpu_percent(interval=None))
        memory = float(self.psutil.virtual_memory().percent)
        await self.service.sample_resources(self.run_id, cpu, memory)
        return {"cpu_percent": cpu, "memory_percent": memory}

    async def start_sampling(self, *, interval_seconds: float = 2.0) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if self._sampling_task is not None and not self._sampling_task.done():
            return

        async def loop() -> None:
            while True:
                await self.sample()
                await asyncio.sleep(interval_seconds)

        self._sampling_task = asyncio.create_task(loop(), name=f"aion-resource-sampler-{self.run_id}")

    async def stop_sampling(self) -> None:
        if self._sampling_task is None:
            return
        self._sampling_task.cancel()
        try:
            await self._sampling_task
        except asyncio.CancelledError:
            pass
        self._sampling_task = None

    async def admit(
        self,
        agent_id: str,
        *,
        sample: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            now = aware(self.clock())
            cpu = float(
                sample["cpu_percent"]
                if sample is not None
                else self.psutil.cpu_percent(interval=None)
            )
            memory = float(
                sample["memory_percent"]
                if sample is not None
                else self.psutil.virtual_memory().percent
            )
            async with self.service.db.sessions.begin() as session:
                agent = await session.get(AgentRecord, agent_id)
                if agent is None or agent.run_id != self.run_id:
                    return {"ok": False, "code": "agent_not_found", "reason": "agent was not found"}
                admission = await session.scalar(select(AdmissionRecord).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.agent_id == agent_id))
                if admission is None:
                    admission = AdmissionRecord(admission_id=f"admission_{uuid4().hex}", run_id=self.run_id, agent_id=agent_id, unique_code=agent.unique_code, role=agent.role, priority=agent.priority)
                    session.add(admission)
                if admission.status in {"starting", "running"}:
                    return {"ok": True, "status": admission.status, "admission_id": admission.admission_id}
                reason: str | None = None
                retry_at: datetime | None = None
                if cpu >= self.cpu_limit_percent:
                    reason = "cpu_limit"
                elif memory >= self.memory_limit_percent:
                    reason = "memory_limit"
                else:
                    latest_agent = await session.scalar(select(AdmissionRecord.started_at).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.status.in_(["starting", "running"]), AdmissionRecord.started_at.is_not(None)).order_by(AdmissionRecord.started_at.desc()).limit(1))
                    latest_work = await session.scalar(
                        select(ResourceWorkRecord.started_at)
                        .where(
                            ResourceWorkRecord.run_id == self.run_id,
                            ResourceWorkRecord.started_at.is_not(None),
                        )
                        .order_by(ResourceWorkRecord.started_at.desc())
                        .limit(1)
                    )
                    latest_values = [
                        aware(value)
                        for value in (latest_agent, latest_work)
                        if value is not None
                    ]
                    latest = max(latest_values, default=None)
                    if latest is not None and (now - latest).total_seconds() < self.start_interval_seconds:
                        reason = "start_interval"
                if reason is not None:
                    admission.status = "queued"
                    admission.reason = reason
                    admission.retry_at = now + timedelta(seconds=max(1.0, self.start_interval_seconds))
                    admission.updated_at = now
                    await self.service._event(session, self.run_id, "agent_admission_queued", {"agent_id": agent_id, "reason": reason, "cpu_percent": cpu, "memory_percent": memory})
                    return {"ok": False, "status": "queued", "admission_id": admission.admission_id, "retry_at": admission.retry_at.isoformat(), "reason": reason, "cpu_percent": cpu, "memory_percent": memory}
                admission.status = "starting"
                admission.reason = None
                admission.retry_at = None
                admission.reserved_at = now
                admission.updated_at = now
                await self.service._event(session, self.run_id, "agent_admission_reserved", {"agent_id": agent_id, "admission_id": admission.admission_id, "cpu_percent": cpu, "memory_percent": memory})
                return {"ok": True, "status": "starting", "admission_id": admission.admission_id, "cpu_percent": cpu, "memory_percent": memory}

    async def mark_started(self, agent_id: str) -> dict[str, Any]:
        async with self._lock:
            async with self.service.db.sessions.begin() as session:
                admission = await session.scalar(select(AdmissionRecord).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.agent_id == agent_id))
                if admission is None:
                    return {"ok": False, "code": "admission_not_found"}
                admission.status = "running"
                admission.started_at = self.clock()
                admission.updated_at = self.clock()
                await self.service._event(session, self.run_id, "agent_started", {"agent_id": agent_id, "admission_id": admission.admission_id})
                return {"ok": True, "status": "running", "admission_id": admission.admission_id}

    async def next_queued_agent_id(self) -> str | None:
        async with self.service.db.sessions() as session:
            return await session.scalar(
                select(AdmissionRecord.agent_id)
                .where(
                    AdmissionRecord.run_id == self.run_id,
                    AdmissionRecord.status == "queued",
                )
                .order_by(AdmissionRecord.priority.desc(), AdmissionRecord.created_at)
                .limit(1)
            )

    async def next_queued_work_item(self) -> dict[str, Any] | None:
        """Return the highest-priority Agent or generic resource work item."""

        async with self.service.db.sessions() as session:
            agent = await session.scalar(
                select(AdmissionRecord)
                .where(
                    AdmissionRecord.run_id == self.run_id,
                    AdmissionRecord.status == "queued",
                )
                .order_by(AdmissionRecord.priority.desc(), AdmissionRecord.created_at)
                .limit(1)
            )
            work = await session.scalar(
                select(ResourceWorkRecord)
                .where(
                    ResourceWorkRecord.run_id == self.run_id,
                    ResourceWorkRecord.status == "queued",
                )
                .order_by(ResourceWorkRecord.priority.desc(), ResourceWorkRecord.created_at)
                .limit(1)
            )
            if agent is None and work is None:
                return None
            if work is None or (
                agent is not None
                and (agent.priority, -agent.created_at.timestamp())
                >= (work.priority, -work.created_at.timestamp())
            ):
                assert agent is not None
                return {"kind": "agent", "id": agent.agent_id}
            assert work is not None
            return {
                "kind": "resource",
                "id": work.work_id,
                "owner_type": work.owner_type,
                "owner_id": work.owner_id,
                "phase": work.phase,
            }

    async def admit_resource_work(
        self,
        work_id: str,
        *,
        sample: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        """Apply live CPU, memory, disk, and reservation admission to work."""

        async with self._lock:
            work = await self.service.get_resource_work(self.run_id, work_id)
            if work["status"] in {"reserved", "running"}:
                return {"ok": True, **work}
            cpu = float(
                sample["cpu_percent"]
                if sample is not None
                else self.psutil.cpu_percent(interval=None)
            )
            memory = float(
                sample["memory_percent"]
                if sample is not None
                else self.psutil.virtual_memory().percent
            )
            disk = shutil.disk_usage(self.storage_root)
            reserve_floor = max(
                self.disk_reserve_bytes,
                int(disk.total * self.disk_reserve_percent / 100.0),
            )
            active = await self.service.list_resource_work(
                self.run_id, statuses={"reserved", "running"}
            )
            reserved_disk = sum(
                int(item["estimated_disk_bytes"])
                for item in active
                if item["work_id"] != work_id
            )
            available_disk = max(0, disk.free - reserve_floor - reserved_disk)
            memory_state = self.psutil.virtual_memory()
            available_memory = int(
                getattr(memory_state, "available", 9_223_372_036_854_775_807)
            )
            reserved_memory = sum(
                int(item["estimated_memory_bytes"])
                for item in active
                if item["work_id"] != work_id
            )
            available_memory = max(0, available_memory - reserved_memory)
            reason: str | None = None
            if cpu >= self.cpu_limit_percent:
                reason = "cpu_limit"
            elif memory >= self.memory_limit_percent:
                reason = "memory_limit"
            elif int(work["estimated_memory_bytes"]) > available_memory:
                reason = "memory_reservation"
            elif int(work["estimated_disk_bytes"]) > available_disk:
                reason = "disk_reservation"
            if reason is None and self.start_interval_seconds > 0:
                async with self.service.db.sessions() as session:
                    latest_agent = await session.scalar(
                        select(AdmissionRecord.started_at)
                        .where(
                            AdmissionRecord.run_id == self.run_id,
                            AdmissionRecord.started_at.is_not(None),
                        )
                        .order_by(AdmissionRecord.started_at.desc())
                        .limit(1)
                    )
                    latest_work = await session.scalar(
                        select(ResourceWorkRecord.started_at)
                        .where(
                            ResourceWorkRecord.run_id == self.run_id,
                            ResourceWorkRecord.started_at.is_not(None),
                        )
                        .order_by(ResourceWorkRecord.started_at.desc())
                        .limit(1)
                    )
                latest_values = [
                    aware(value)
                    for value in (latest_agent, latest_work)
                    if value is not None
                ]
                latest = max(latest_values, default=None)
                if (
                    latest is not None
                    and (aware(self.clock()) - latest).total_seconds()
                    < self.start_interval_seconds
                ):
                    reason = "start_interval"
            if reason is not None:
                retry_at = aware(self.clock()) + timedelta(
                    seconds=max(1.0, self.start_interval_seconds)
                )
                queued = await self.service.update_resource_work(
                    self.run_id,
                    work_id,
                    status="queued",
                    reason=reason,
                    retry_at=retry_at,
                )
                return {
                    "ok": False,
                    **queued,
                    "cpu_percent": cpu,
                    "memory_percent": memory,
                    "available_disk_bytes": available_disk,
                    "available_memory_bytes": available_memory,
                }
            reserved = await self.service.update_resource_work(
                self.run_id, work_id, status="reserved"
            )
            return {
                "ok": True,
                **reserved,
                "cpu_percent": cpu,
                "memory_percent": memory,
                "available_disk_bytes": available_disk,
                "available_memory_bytes": available_memory,
            }

    async def mark_resource_started(self, work_id: str) -> dict[str, Any]:
        return await self.service.update_resource_work(
            self.run_id, work_id, status="running"
        )

    async def check_resource_work(self, work_id: str) -> dict[str, Any]:
        """Decide whether an admitted task may dispatch another unit of work."""

        work = await self.service.get_resource_work(self.run_id, work_id)
        if work["status"] not in {"reserved", "running"}:
            return {"ok": False, **work, "reason": work.get("reason") or "not_running"}
        cpu = float(self.psutil.cpu_percent(interval=None))
        memory = float(self.psutil.virtual_memory().percent)
        disk = shutil.disk_usage(self.storage_root)
        reserve_floor = max(
            self.disk_reserve_bytes,
            int(disk.total * self.disk_reserve_percent / 100.0),
        )
        reason: str | None = None
        if cpu >= self.cpu_limit_percent:
            reason = "cpu_limit"
        elif memory >= self.memory_limit_percent:
            reason = "memory_limit"
        elif disk.free <= reserve_floor:
            reason = "disk_pressure"
        return {
            "ok": reason is None,
            **work,
            "reason": reason,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "disk_free_bytes": disk.free,
            "retry_after_seconds": max(1.0, self.start_interval_seconds),
        }

    async def finish_resource_work(
        self,
        work_id: str,
        *,
        status: str = "completed",
        reason: str | None = None,
    ) -> dict[str, Any]:
        return await self.service.update_resource_work(
            self.run_id, work_id, status=status, reason=reason
        )

    async def mark_failed(self, agent_id: str, *, reason: str) -> dict[str, Any]:
        async with self._lock:
            async with self.service.db.sessions.begin() as session:
                admission = await session.scalar(
                    select(AdmissionRecord).where(
                        AdmissionRecord.run_id == self.run_id,
                        AdmissionRecord.agent_id == agent_id,
                    )
                )
                if admission is None:
                    return {"ok": False, "code": "admission_not_found"}
                admission.status = "failed"
                admission.reason = reason[:128]
                admission.updated_at = self.clock()
                await self.service._event(
                    session,
                    self.run_id,
                    "agent_start_failed",
                    {"agent_id": agent_id, "reason": admission.reason},
                    agent_id=agent_id,
                )
                return {"ok": True, "status": "failed", "admission_id": admission.admission_id}

    async def finish(self, agent_id: str, *, status: str = "completed") -> dict[str, Any]:
        async with self._lock:
            async with self.service.db.sessions.begin() as session:
                admission = await session.scalar(select(AdmissionRecord).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.agent_id == agent_id))
                if admission is None:
                    return {"ok": False, "code": "admission_not_found"}
                admission.status = status
                admission.updated_at = self.clock()
                await self.service._event(session, self.run_id, "agent_admission_finished", {"agent_id": agent_id, "status": status})
                return {"ok": True, "status": status, "admission_id": admission.admission_id}

class StagnationManager:
    """Apply the deterministic 8/15/20 minute challenge state machine."""

    WARNING_SECONDS = 8 * 60
    PAUSE_SECONDS = 15 * 60
    HARD_STOP_SECONDS = 20 * 60

    def __init__(self, service: StateService, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.service = service
        self.clock = clock
        self._lock = asyncio.Lock()

    async def evaluate(self, run_id: str, unique_code: str) -> dict[str, Any]:
        async with self._lock:
            async with self.service.db.sessions.begin() as session:
                challenge = await self.service._require_challenge(session, run_id, unique_code)
                now = aware(self.clock())
                if (
                    not challenge_work_active(challenge)
                    or challenge.last_progress_at is None
                    or challenge.is_completed
                    or challenge.work_status in {"closed", "paused"}
                ):
                    return {"unique_code": unique_code, "level": challenge.stagnation_level, "status": challenge.work_status, "elapsed_seconds": 0, "action": "none"}
                if (
                    challenge.control_state == "waiting_external_change"
                    and challenge.control_since is not None
                ):
                    waiting_seconds = (
                        now - aware(challenge.control_since)
                    ).total_seconds()
                    if waiting_seconds < 300:
                        return {
                            "unique_code": unique_code,
                            "level": challenge.stagnation_level,
                            "status": challenge.work_status,
                            "elapsed_seconds": 0,
                            "action": "waiting_external",
                            "control_state": challenge.control_state,
                        }
                    challenge.control_state = "ok"
                    challenge.control_since = None
                    challenge.active_since = now
                    challenge.version += 1
                    await self.service._event(
                        session,
                        run_id,
                        "challenge_control_state_changed",
                        {
                            "unique_code": unique_code,
                            "control_state": "ok",
                            "reason": "waiting_external_timeout",
                        },
                    )
                elapsed = active_seconds(
                    now=now,
                    active_since=challenge.active_since,
                    accumulated_seconds=challenge.exploration_seconds,
                )
                target_level = 1 if elapsed >= self.WARNING_SECONDS else 0
                hard_stop = elapsed >= self.HARD_STOP_SECONDS
                pause_due = elapsed >= self.PAUSE_SECONDS and not challenge.extension_cycle_pending
                if hard_stop or pause_due:
                    challenge.stagnation_level = 2
                    challenge.work_status = "paused"
                    challenge.hint_eligible = False
                    challenge.control_state = "degraded"
                    challenge.control_since = now
                    challenge.version += 1
                    event_sequence = await self.service._event(
                        session,
                        run_id,
                        "stagnation_level_changed",
                        {
                            "unique_code": unique_code,
                            "level": challenge.stagnation_level,
                            "elapsed_seconds": elapsed,
                            "action": "pause",
                            "extension_active": bool(challenge.extension_cycle_pending),
                        },
                    )
                    return {
                        "unique_code": unique_code,
                        "level": challenge.stagnation_level,
                        "status": challenge.work_status,
                        "elapsed_seconds": elapsed,
                        "action": "pause",
                        "event_sequence": event_sequence,
                    }
                if elapsed >= self.PAUSE_SECONDS and challenge.extension_cycle_pending:
                    event_sequence: int | None = None
                    if challenge.stagnation_level < 2 or challenge.work_status != "extended":
                        challenge.stagnation_level = 2
                        challenge.work_status = "extended"
                        challenge.version += 1
                        event_sequence = await self.service._event(
                            session,
                            run_id,
                            "stagnation_level_changed",
                            {
                                "unique_code": unique_code,
                                "level": challenge.stagnation_level,
                                "elapsed_seconds": elapsed,
                                "action": "extension_active",
                            },
                        )
                    return {
                        "unique_code": unique_code,
                        "level": challenge.stagnation_level,
                        "status": challenge.work_status,
                        "elapsed_seconds": elapsed,
                        "action": "extension_active",
                        "event_sequence": event_sequence,
                    }
                if target_level <= challenge.stagnation_level:
                    return {"unique_code": unique_code, "level": challenge.stagnation_level, "status": challenge.work_status, "elapsed_seconds": elapsed, "action": "none"}
                challenge.stagnation_level = target_level
                challenge.control_state = "degraded"
                challenge.control_since = now
                challenge.version += 1
                challenge.work_status = "warning"
                challenge.hint_eligible = True
                event_sequence = await self.service._event(
                    session,
                    run_id,
                    "stagnation_level_changed",
                    {
                        "unique_code": unique_code,
                        "level": target_level,
                        "elapsed_seconds": elapsed,
                        "action": "warning_review",
                    },
                )
                return {"unique_code": unique_code, "level": target_level, "status": challenge.work_status, "elapsed_seconds": elapsed, "action": "warning_review", "event_sequence": event_sequence}

class ChallengeScheduler:
    """Stable phase-aware challenge selection."""

    def __init__(self, service: StateService, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.service = service
        self.clock = clock

    async def select(self, run_id: str, *, limit: int = 3) -> list[dict[str, Any]]:
        async with self.service.db.sessions() as session:
            run = await self.service._require_run(session, run_id)
            challenges = list((await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id, ChallengeRecord.is_completed.is_(False)))).all())
            challenges = [
                item
                for item in challenges
                if item.work_status not in {"paused", "completed", "closed"}
            ]
            phase = derive_phase(run.started_at, run.deadline_at, self.clock())
            if phase == "early":
                selected = self._early(challenges, limit)
            elif phase == "mid":
                selected = sorted(challenges, key=self._mid_key, reverse=True)[:limit]
            else:
                candidate_codes = set((await session.scalars(select(FindingRecord.unique_code).where(FindingRecord.run_id == run_id, FindingRecord.category == "flag", FindingRecord.verification_status.in_(["candidate", "verified"])))).all())
                selected = sorted(challenges, key=lambda item: self._late_key(item, candidate_codes), reverse=True)[:limit]
            return [self.service._challenge_dict(item) for item in selected]

    async def choose_one(self, run_id: str) -> dict[str, Any] | None:
        values = await self.select(run_id, limit=1)
        return values[0] if values else None

    def _early(self, values: list[ChallengeRecord], limit: int) -> list[ChallengeRecord]:
        ordered = sorted(values, key=lambda item: (DIFFICULTY_RANK.get(item.difficulty, 99), item.unique_code))
        result: list[ChallengeRecord] = []
        for item in ordered:
            if DIFFICULTY_RANK.get(item.difficulty, 99) == 0 and len([x for x in result if DIFFICULTY_RANK.get(x.difficulty, 99) == 0]) < 2:
                result.append(item)
        high_value = sorted((item for item in values if item not in result and DIFFICULTY_RANK.get(item.difficulty, 99) >= 1), key=lambda item: (-item.total_score, -DIFFICULTY_RANK.get(item.difficulty, 99), item.unique_code))
        if high_value and len(result) < limit:
            result.append(high_value[0])
        for item in ordered:
            if item not in result and len(result) < limit:
                result.append(item)
        return result[:limit]

    @staticmethod
    def _mid_key(item: ChallengeRecord) -> tuple[Any, ...]:
        progress = aware(item.last_progress_at).timestamp() if item.last_progress_at else 0
        completion = item.correct_flag_count / item.flag_count if item.flag_count else 0
        return (progress > 0, completion, progress, item.total_score, -DIFFICULTY_RANK.get(item.difficulty, 99), item.unique_code)

    @staticmethod
    def _late_key(item: ChallengeRecord, candidate_codes: set[str] | None = None) -> tuple[Any, ...]:
        completion = item.correct_flag_count / item.flag_count if item.flag_count else 0
        return (item.unique_code in (candidate_codes or set()), item.hint_eligible, item.correct_flag_count > 0, completion, item.total_score, -DIFFICULTY_RANK.get(item.difficulty, 99), item.unique_code)

class ChallengeLoopController:
    """Drive the two model calls and the six persisted cycle stages."""

    def __init__(self, service: StateService) -> None:
        self.service = service

    async def run_cycle(
        self,
        run_id: str,
        unique_code: str,
        context: Any,
        *,
        analyze_and_plan: Callable[[dict[str, Any]], Any],
        verify_and_update: Callable[[dict[str, Any], list[dict[str, Any]]], Any],
        execute: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        challenge = await self.service.get_challenge_context(run_id, unique_code, context)
        from .schemas import CreateCycleInput

        cycle = await self.service.begin_cycle(run_id, unique_code, context, CreateCycleInput(expected_challenge_version=challenge["challenge"]["version"]))
        plan = analyze_and_plan(cycle)
        if hasattr(plan, "__await__"):
            plan = await plan
        if not isinstance(plan, dict):
            await self.service.mark_invalid_cycle(run_id, cycle["cycle_id"], context)
            return {"status": "invalid_cycle_output", "cycle_id": cycle["cycle_id"]}
        plan["expected_version"] = cycle["version"]
        from .schemas import AnalysisPlanInput

        plan_payload = AnalysisPlanInput.model_validate(plan)
        cycle = await self.service.submit_analysis_plan(run_id, cycle["cycle_id"], context, plan_payload)
        if execute is not None:
            executed = execute(cycle)
            if hasattr(executed, "__await__"):
                await executed
        reports = await self.service.list_reports(run_id, context, after_sequence=0, wait_seconds=0, max_reports=100)
        update = verify_and_update(cycle, reports["reports"])
        if hasattr(update, "__await__"):
            update = await update
        if not isinstance(update, dict):
            await self.service.mark_invalid_cycle(run_id, cycle["cycle_id"], context)
            return {"status": "invalid_cycle_output", "cycle_id": cycle["cycle_id"]}
        update["expected_version"] = cycle["version"]
        result = await self.service.commit_cycle(run_id, cycle["cycle_id"], context, VerificationUpdateInput.model_validate(update))
        return result
