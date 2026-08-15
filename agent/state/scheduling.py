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
                    return {
                        "ok": True,
                        "claimed": False,
                        "status": admission.status,
                        "admission_id": admission.admission_id,
                    }
                # A queued Bootstrap can outlive a failed/closed Challenge
                # during startup.  Re-check ownership at the point of
                # reservation so the scheduler never launches an orphan.
                if agent.status not in {"queued", "pending"}:
                    if admission.status == "queued":
                        admission.status = "cancelled"
                        admission.reason = "agent_not_queued"
                    return {
                        "ok": False,
                        "code": "agent_not_queued",
                        "status": admission.status,
                        "admission_id": admission.admission_id,
                    }
                if agent.parent_id:
                    parent = await session.get(AgentRecord, agent.parent_id)
                    if (
                        parent is None
                        or parent.run_id != self.run_id
                        or parent.role != "challenge"
                        or parent.status in {"failed", "stopped", "completed", "cancelled", "interrupted"}
                    ):
                        if admission.status == "queued":
                            admission.status = "cancelled"
                            admission.reason = "parent_challenge_inactive"
                        return {
                            "ok": False,
                            "code": "parent_challenge_inactive",
                            "status": admission.status,
                            "admission_id": admission.admission_id,
                        }
                reason: str | None = None
                retry_at: datetime | None = None
                if cpu >= self.cpu_limit_percent:
                    reason = "cpu_limit"
                elif memory >= self.memory_limit_percent:
                    reason = "memory_limit"
                if reason is not None:
                    admission.status = "queued"
                    admission.reason = reason
                    admission.retry_at = now + timedelta(seconds=0.5)
                    admission.updated_at = now
                    await self.service._event(session, self.run_id, "agent_admission_queued", {"agent_id": agent_id, "reason": reason, "cpu_percent": cpu, "memory_percent": memory})
                    return {"ok": False, "status": "queued", "admission_id": admission.admission_id, "retry_at": admission.retry_at.isoformat(), "reason": reason, "cpu_percent": cpu, "memory_percent": memory}
                admission.status = "starting"
                admission.reason = None
                admission.retry_at = None
                admission.reserved_at = now
                admission.updated_at = now
                queue_latency_ms = int(
                    max(0.0, (now - aware(admission.created_at or now)).total_seconds())
                    * 1_000
                )
                await self.service._event(
                    session,
                    self.run_id,
                    "agent_admission_reserved",
                    {
                        "agent_id": agent_id,
                        "admission_id": admission.admission_id,
                        "cpu_percent": cpu,
                        "memory_percent": memory,
                        "queue_latency_ms": queue_latency_ms,
                    },
                )
                return {
                    "ok": True,
                    "claimed": True,
                    "status": "starting",
                    "admission_id": admission.admission_id,
                    "cpu_percent": cpu,
                    "memory_percent": memory,
                    "queue_latency_ms": queue_latency_ms,
                }

    async def mark_started(self, agent_id: str) -> dict[str, Any]:
        async with self._lock:
            event_sequence: int | None = None
            async with self.service.db.sessions.begin() as session:
                admission = await session.scalar(select(AdmissionRecord).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.agent_id == agent_id))
                if admission is None:
                    return {"ok": False, "code": "admission_not_found"}
                admission.status = "running"
                admission.started_at = self.clock()
                admission.updated_at = self.clock()
                event_sequence = await self.service._event(session, self.run_id, "agent_started", {"agent_id": agent_id, "admission_id": admission.admission_id})
                result = {"ok": True, "status": "running", "admission_id": admission.admission_id}
            if event_sequence is not None:
                await self.service.notifier.notify(self.service.run_signal_key(self.run_id), event_sequence)
            return result

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
            if work is None:
                assert agent is not None
                return {"kind": "agent", "id": agent.agent_id}
            if agent is None:
                return {
                    "kind": "resource",
                    "id": work.work_id,
                    "owner_type": work.owner_type,
                    "owner_id": work.owner_id,
                    "phase": work.phase,
                }
            # Resource work is deliberately ahead of Agent admission. It
            # commonly releases a gate needed by an already planned Agent.
            if work is not None:
                return {
                    "kind": "resource",
                    "id": work.work_id,
                    "owner_type": work.owner_type,
                    "owner_id": work.owner_id,
                    "phase": work.phase,
                }

    async def next_queued_resource_work_item(self) -> dict[str, Any] | None:
        async with self.service.db.sessions() as session:
            work = await session.scalar(
                select(ResourceWorkRecord)
                .where(
                    ResourceWorkRecord.run_id == self.run_id,
                    ResourceWorkRecord.status == "queued",
                )
                .order_by(ResourceWorkRecord.priority.desc(), ResourceWorkRecord.created_at)
                .limit(1)
            )
            if work is None:
                return None
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
            if work["status"] in {"reserved", "starting", "running"}:
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
                self.run_id, statuses={"reserved", "starting", "running"}
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
            if reason is not None:
                retry_at = aware(self.clock()) + timedelta(seconds=0.5)
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
        return await self.service.mark_resource_work_started(self.run_id, work_id)

    async def claim_resource_work(self, work_id: str) -> dict[str, Any]:
        return await self.service.claim_resource_work(self.run_id, work_id)

    async def check_resource_work(self, work_id: str) -> dict[str, Any]:
        """Decide whether an admitted task may dispatch another unit of work."""

        work = await self.service.get_resource_work(self.run_id, work_id)
        if work["status"] not in {"reserved", "starting", "running"}:
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
            "retry_after_seconds": 0.5,
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
            event_sequence: int | None = None
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
                event_sequence = await self.service._event(
                    session,
                    self.run_id,
                    "agent_start_failed",
                    {"agent_id": agent_id, "reason": admission.reason},
                    agent_id=agent_id,
                )
                result = {"ok": True, "status": "failed", "admission_id": admission.admission_id}
            if event_sequence is not None:
                await self.service.notifier.notify(self.service.run_signal_key(self.run_id), event_sequence)
            return result

    async def finish(self, agent_id: str, *, status: str = "completed") -> dict[str, Any]:
        async with self._lock:
            event_sequence: int | None = None
            async with self.service.db.sessions.begin() as session:
                admission = await session.scalar(select(AdmissionRecord).where(AdmissionRecord.run_id == self.run_id, AdmissionRecord.agent_id == agent_id))
                if admission is None:
                    return {"ok": False, "code": "admission_not_found"}
                admission.status = status
                admission.updated_at = self.clock()
                event_sequence = await self.service._event(session, self.run_id, "agent_admission_finished", {"agent_id": agent_id, "status": status})
                result = {"ok": True, "status": status, "admission_id": admission.admission_id}
            if event_sequence is not None:
                await self.service.notifier.notify(self.service.run_signal_key(self.run_id), event_sequence)
            return result

class StagnationManager:
    """Turn prolonged lack of progress into a soft signal, then a hard pause."""

    LOW_YIELD_SECONDS = 8 * 60
    PAUSE_SECONDS = 15 * 60
    STAGNATION_PAUSE_REASON = "stagnation_timeout"

    def __init__(
        self,
        service: StateService,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.service = service
        self.clock = clock
        self._lock = asyncio.Lock()

    async def evaluate(self, run_id: str, unique_code: str) -> dict[str, Any]:
        async with self._lock:
            result: dict[str, Any]
            async with self.service.db.sessions.begin() as session:
                challenge = await self.service._require_challenge(
                    session, run_id, unique_code
                )
                if (
                    not challenge_work_active(challenge)
                    or challenge.is_completed
                    or challenge.work_status == "closed"
                ):
                    result = {
                        "unique_code": unique_code,
                        "status": challenge.work_status,
                        "elapsed_seconds": 0,
                        "action": "none",
                    }
                else:
                    now = aware(self.clock())
                    baseline = challenge.last_progress_at or challenge.active_since
                    elapsed = (
                        max(0, int((now - aware(baseline)).total_seconds()))
                        if baseline is not None
                        else 0
                    )
                    if elapsed < self.LOW_YIELD_SECONDS:
                        result = {
                            "unique_code": unique_code,
                            "status": challenge.work_status,
                            "elapsed_seconds": elapsed,
                            "action": "none",
                        }
                    elif elapsed >= self.PAUSE_SECONDS and challenge.stagnation_level < 2:
                        self.service._freeze_exploration(challenge)
                        challenge.stagnation_level = 2
                        challenge.work_status = "paused"
                        challenge.paused_at = now
                        challenge.pause_reason = self.STAGNATION_PAUSE_REASON
                        challenge.version += 1
                        event_sequence = await self.service._event(
                            session,
                            run_id,
                            "challenge_stagnation_paused",
                            {
                                "unique_code": unique_code,
                                "elapsed_seconds": elapsed,
                                "pause_reason": self.STAGNATION_PAUSE_REASON,
                            },
                        )
                        result = {
                            "unique_code": unique_code,
                            "status": challenge.work_status,
                            "elapsed_seconds": elapsed,
                            "action": "pause_stagnation",
                            "pause_reason": self.STAGNATION_PAUSE_REASON,
                            "event_sequence": event_sequence,
                        }
                    elif challenge.stagnation_level < 1:
                        challenge.stagnation_level = 1
                        challenge.version += 1
                        event_sequence = await self.service._event(
                            session,
                            run_id,
                            "challenge_low_yield",
                            {
                                "unique_code": unique_code,
                                "elapsed_seconds": elapsed,
                            },
                        )
                        result = {
                            "unique_code": unique_code,
                            "status": challenge.work_status,
                            "elapsed_seconds": elapsed,
                            "action": "low_yield",
                            "event_sequence": event_sequence,
                        }
                    else:
                        result = {
                            "unique_code": unique_code,
                            "status": challenge.work_status,
                            "elapsed_seconds": elapsed,
                            "action": "none",
                        }
            if result["action"] not in {"low_yield", "pause_stagnation"}:
                return result
            overview = await self.service.get_overview(run_id)
            chief = next(
                (item for item in overview["agents"] if item["role"] == "chief"),
                None,
            )
            controller = next(
                (
                    item
                    for item in overview["agents"]
                    if item["role"] == "challenge"
                    and item["unique_code"] == unique_code
                ),
                None,
            )
            if chief is not None and controller is not None:
                report = await self.service.publish_control_report(
                    run_id,
                    sender_id=controller["agent_id"],
                    recipient_id=chief["agent_id"],
                    unique_code=unique_code,
                    report_type="challenge_status",
                    status=(
                        "stagnation_paused"
                        if result["action"] == "pause_stagnation"
                        else "low_yield"
                    ),
                    payload={
                        "type": (
                            "challenge_stagnation_paused"
                            if result["action"] == "pause_stagnation"
                            else "challenge_low_yield"
                        ),
                        "unique_code": unique_code,
                        "elapsed_seconds": result["elapsed_seconds"],
                        **(
                            {"pause_reason": result["pause_reason"]}
                            if result["action"] == "pause_stagnation"
                            else {}
                        ),
                    },
                )
                result["chief_report_ref"] = report["report_ref"]
            return result


class ChallengeScheduler:
    """Stable phase-aware challenge selection."""

    def __init__(self, service: StateService, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.service = service
        self.clock = clock

    async def select(self, run_id: str, *, limit: int = 3) -> list[dict[str, Any]]:
        async with self.service.db.sessions() as session:
            run = await self.service._require_run(session, run_id)
            unfinished = list((await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id, ChallengeRecord.is_completed.is_(False)))).all())
            runnable = [
                item
                for item in unfinished
                if item.work_status not in {"paused", "completed", "closed"}
            ]
            paused = [item for item in unfinished if item.work_status == "paused"]
            restart_required = not runnable and bool(paused)
            challenges = paused if restart_required else runnable
            phase = derive_phase(run.started_at, run.deadline_at, self.clock())
            if phase == "early":
                selected = self._early(challenges, limit)
            elif phase == "mid":
                selected = sorted(challenges, key=self._mid_key, reverse=True)[:limit]
            else:
                candidate_codes = set((await session.scalars(select(FindingRecord.unique_code).where(FindingRecord.run_id == run_id, FindingRecord.category == "flag", FindingRecord.verification_status.in_(["candidate", "verified"])))).all())
                selected = sorted(challenges, key=lambda item: self._late_key(item, candidate_codes), reverse=True)[:limit]
            result = [self.service._challenge_dict(item) for item in selected]
            if restart_required:
                for item in result:
                    item["restart_required"] = True
            return result

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
