"""Generation-scoped container reclamation, shared by shutdown and offline recovery.

The platform exposes addresses, not immutable instance IDs. A successful local
start operation, unchanged addresses, exclusive Runtime ownership and absence of
a newer start are all required before closing. Unknown ownership fails closed.
"""

import asyncio
from collections import Counter
from contextlib import ExitStack
from datetime import timedelta
import json
import logging
from pathlib import Path
import re
import sqlite3

from sqlalchemy import select

from agent.deadline import before
from agent.run_ownership import RunOwnership
from agent.state import StateService
from agent.state.clock import aware
from agent.state.errors import StateConflict
from agent.state.models import ChallengeRecord, OperationRecord
from agent.state.resources import container_slot_occupied
from agent.state.database import SCHEMA_VERSION
from agent.tooling import ToolExecutor, ToolRegistry


logger = logging.getLogger(__name__)


async def platform_call(benchmark, name, arguments, deadline):
    if asyncio.get_running_loop().time() >= deadline:
        raise TimeoutError("cleanup deadline exceeded before platform call")
    if benchmark is None:
        raise RuntimeError("benchmark unavailable")
    executor = ToolExecutor(ToolRegistry([benchmark]))
    outcomes = await before(executor.execute([{"id": "cleanup", "function": {
        "name": name, "arguments": json.dumps(arguments)}}]), deadline)
    result = outcomes[0].result
    if not isinstance(result, dict):
        raise ValueError("invalid platform result")
    return result


async def capture_targets(service, run_id, *, reason, deadline):
    """Commit every target before spending the shutdown budget on any one target."""
    targets = []
    async with service._lock:
        async with service.db.sessions.begin() as session:
            challenges = (await session.scalars(select(ChallengeRecord).where(ChallengeRecord.run_id == run_id))).all()
            for challenge in challenges:
                if not container_slot_occupied(challenge.container_status):
                    continue
                operation = await session.scalar(select(OperationRecord).where(
                    OperationRecord.run_id == run_id, OperationRecord.unique_code == challenge.unique_code,
                    OperationRecord.operation_type == "benchmark_start_challenge",
                ).order_by(OperationRecord.started_sequence.desc()).limit(1))
                start_result = (operation.result_payload or {}) if operation else {}
                start_data = start_result.get("data") or {}
                start_addresses = sorted(start_data.get("container_addr") or []) if isinstance(start_data, dict) else []
                target = {"unique_code": challenge.unique_code,
                    "generation": operation.operation_id if operation else None,
                    "start_confirmed": bool(operation and operation.status == "completed" and start_result.get("ok") is True
                                            and start_addresses == sorted(challenge.container_addr or [])),
                    "addresses": start_addresses,
                    "requested_at": aware(service.clock()).isoformat(), "reason": reason}
                targets.append(target)
                challenge.container_status = "release_pending"
                challenge.platform_status = "close_requested"
                challenge.version += 1
            await service._event(session, run_id, "runtime_cleanup_started", {
                "reason": reason, "deadline_monotonic": deadline,
                "deadline_at": (aware(service.clock()) + timedelta(seconds=max(0, deadline - asyncio.get_running_loop().time()))).isoformat(),
                "targets": targets})
    return targets


async def _confirm(service, run_id, target, observed):
    """Only resource state changes here: never rewrite facts, reviews or Agent outcomes."""
    async with service._lock:
        async with service.db.sessions.begin() as session:
            latest = await session.scalar(select(OperationRecord.operation_id).where(
                OperationRecord.run_id == run_id, OperationRecord.unique_code == target["unique_code"],
                OperationRecord.operation_type == "benchmark_start_challenge",
            ).order_by(OperationRecord.started_sequence.desc()).limit(1))
            if latest != target["generation"]:
                raise StateConflict("cleanup_generation_conflict", "A newer target generation exists")
            challenge = await session.get(ChallengeRecord, (run_id, target["unique_code"]))
            challenge.container_status = observed["container_status"]
            challenge.platform_status = "completed" if challenge.is_completed else "closed"
            challenge.container_addr = list(observed.get("container_addr") or [])
            challenge.version += 1


async def cleanup_targets(service, benchmark, run_id, targets, *, deadline, locks=None):
    semaphore = asyncio.Semaphore(3)
    locks = {} if locks is None else locks

    async def one(target):
        result = {**target, "released": False, "resource_cleanup_status": "release_pending"}
        started = asyncio.get_running_loop().time()
        operation_id = None
        await service.append_run_event(run_id, "container_cleanup_attempt", result)
        try:
            async with asyncio.timeout_at(deadline), semaphore, locks.setdefault(target["unique_code"], asyncio.Lock()):
                catalog = await platform_call(benchmark, "benchmark_list_challenges", {}, deadline)
                def observed(value):
                    if not value.get("ok") or not isinstance(value.get("data"), list):
                        raise ValueError("catalog_unavailable")
                    match = next((c for c in value["data"] if c.get("unique_code") == target["unique_code"]), None)
                    if match is None:
                        raise ValueError("target_not_observed")
                    return match
                current = observed(catalog)
                operations = await service.list_operations(run_id)
                starts = [o for o in operations if o["unique_code"] == target["unique_code"] and o["operation_type"] == "benchmark_start_challenge"]
                latest = max(starts, key=lambda o: o["started_sequence"] or 0, default=None)
                if (latest or {}).get("operation_id") != target["generation"]:
                    raise StateConflict("cleanup_generation_conflict", "Target generation changed")
                if container_slot_occupied(current["container_status"]):
                    if not target["start_confirmed"] or not target["addresses"] or sorted(current.get("container_addr") or []) != target["addresses"]:
                        raise StateConflict("cleanup_ownership_unproven", "Cannot prove target belongs to this start operation")
                    # A previous uncertain close may have executed. Only observe it; do not blindly repeat.
                    uncertain = [o for o in operations if o["unique_code"] == target["unique_code"] and
                        o["operation_type"] == "benchmark_close_challenge" and o["status"] in {"started", "indeterminate"}]
                    if uncertain:
                        raise StateConflict("cleanup_result_unknown", "Previous close outcome is still uncertain")
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError("cleanup deadline exceeded before close")
                    operation_id = await service.mark_operation_started(run_id, "benchmark_close_challenge",
                        unique_code=target["unique_code"], arguments={"unique_code": target["unique_code"], "generation": target["generation"]})
                    response = await platform_call(benchmark, "benchmark_close_challenge", {"unique_code": target["unique_code"]}, deadline)
                    result["request_ok"] = response.get("ok") is True
                    if response.get("ok"):
                        await service.complete_operation(run_id, operation_id, result_payload=response)
                    else:
                        error = response.get("error") or {}
                        code = error.get("code", "close_rejected")
                        if code in {"timeout", "http_error", "transport_error", "network_error", "execution_error", "invalid_tool_result"}:
                            await service.mark_operation_indeterminate(run_id, operation_id, result_payload={"error_code": code})
                        else:
                            await service.fail_operation(run_id, operation_id, error_code=code, error_message="Container close rejected")
                    # Accepted close is not release. Poll read-only within the same global deadline.
                    while True:
                        current = observed(await platform_call(benchmark, "benchmark_list_challenges", {}, deadline))
                        if not container_slot_occupied(current["container_status"]):
                            break
                        await before(asyncio.sleep(0.25), deadline)
                await _confirm(service, run_id, target, current)
                for op in await service.list_operations(run_id):
                    if op["unique_code"] == target["unique_code"] and op["operation_type"] == "benchmark_close_challenge" and op["status"] in {"started", "indeterminate"}:
                        if op["status"] == "started":
                            await service.mark_operation_indeterminate(run_id, op["operation_id"], result_payload={"recovered": True})
                        await service.reconcile_indeterminate_operation(run_id, op["operation_id"], resolved=True, result_code="release_confirmed")
                result.update(released=True, resource_cleanup_status="closed", confirmed_at=aware(service.clock()).isoformat())
        except (TimeoutError, asyncio.CancelledError) as exc:
            result["error_code"] = "cleanup_deadline" if isinstance(exc, TimeoutError) else "cleanup_interrupted"
            if operation_id:
                op = next(o for o in await service.list_operations(run_id) if o["operation_id"] == operation_id)
                if op["status"] == "started":
                    await service.mark_operation_indeterminate(run_id, operation_id, result_payload={"error_code": result["error_code"]})
        except Exception as exc:
            result["error_code"] = getattr(exc, "code", str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
            if operation_id:
                op = next(o for o in await service.list_operations(run_id) if o["operation_id"] == operation_id)
                if op["status"] == "started":
                    await service.mark_operation_indeterminate(run_id, operation_id, result_payload={"error_code": result["error_code"]})
        result["duration_ms"] = int((asyncio.get_running_loop().time() - started) * 1000)
        await service.append_run_event(run_id, "container_cleanup_result", result)
        return result

    results = await asyncio.gather(*(one(target) for target in targets))
    summary = {"results": results, "unreleased": [r for r in results if not r["released"]]}
    await service.append_run_event(run_id, "container_release_summary", summary)
    return summary


def _read_schema_version(path: Path) -> str | None:
    """Read the version marker without initializing or migrating a database."""
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
            ).fetchone()
            if table is None:
                return None
            row = db.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            return str(row[0]) if row is not None else None
    except sqlite3.Error:
        return None


def pending_databases(run_root):
    """Return only current-schema runs eligible for offline container recovery."""
    pending = []
    skipped_versions: Counter[str] = Counter()
    for path in sorted(Path(run_root).glob("*/state.sqlite3")):
        version = _read_schema_version(path)
        if version != str(SCHEMA_VERSION):
            skipped_versions[version or "unknown"] += 1
            continue
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            if db.execute("SELECT 1 FROM challenges WHERE container_status NOT IN ('stopped','closed') LIMIT 1").fetchone():
                pending.append(path)
    if skipped_versions:
        logger.warning(
            "offline_cleanup_history_skipped supported_schema=%s skipped=%s",
            SCHEMA_VERSION,
            dict(sorted(skipped_versions.items())),
        )
    return pending


async def cleanup_offline(benchmark, run_root, workspace_root, *, run_id=None, deadline=None):
    """Caller holds the run-root Runtime lock; acquire every per-run lock before touching any target."""
    if run_id is not None and (not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}", run_id) or run_id == "latest"):
        raise ValueError("cleanup requires one explicit run ID")
    root = Path(run_root).resolve()
    paths = sorted(root.glob("*/state.sqlite3"))
    selected = [root / run_id / "state.sqlite3"] if run_id else pending_databases(root)
    if any(not p.is_file() for p in selected):
        raise ValueError("cleanup run database does not exist")
    deadline = deadline or asyncio.get_running_loop().time() + 30
    with ExitStack() as stack:
        for path in paths:
            stack.callback(RunOwnership(path).close)
        # Any newer start in another run invalidates an old run's ownership claim, even at a reused address.
        newest = {}
        for path in paths:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
                for code, started_at, op_id in db.execute("SELECT unique_code,started_at,operation_id FROM operations WHERE operation_type='benchmark_start_challenge' AND status != 'failed'"):
                    if code not in newest or started_at > newest[code][0]:
                        newest[code] = (started_at, op_id)
        results = []
        for path in selected:
            service = StateService(path, run_root=root, workspace_root=workspace_root)
            try:
                await service.initialize()  # schema 19 only; rejects historical unsupported schemas.
                code_run = path.parent.name
                targets = await capture_targets(service, code_run, reason="offline_recovery", deadline=deadline)
                for target in targets:
                    if target["generation"] != newest.get(target["unique_code"], (None, None))[1]:
                        target["start_confirmed"] = False
                summary = await cleanup_targets(service, benchmark, code_run, targets, deadline=deadline - 5)
                results.extend({"run_id": code_run, **item} for item in summary["results"])
            finally:
                await before(service.close(), deadline)
    return {"results": results, "unreleased": [r for r in results if not r["released"]]}
