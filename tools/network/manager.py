"""Run-level lifecycle and bridge protocol for persistent network tasks."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

import psutil

from agent.state import StateService
from agent.state.errors import StateNotFound
from tools.system.policy import SystemToolError, WorkspacePolicy


DEFAULT_PORTS = (
    "21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,"
    "8000,8080,8089,9000,9200,11211,27017"
)
BRIDGE_PROTOCOL_VERSION = "1"
TERMINAL = {"completed", "failed", "stopped", "interrupted"}
ACTIVE = {"queued", "running"}


def default_binary_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    if sys.platform == "darwin":
        return root / "deploy" / "bin" / "aion-fscan-darwin-arm64"
    return root / "deploy" / "bin" / "aion-fscan-linux-amd64"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(error_type: str, code: str, message: str) -> SystemToolError:
    return SystemToolError(error_type=error_type, code=code, message=message)


@dataclass
class LiveNetworkTask:
    task_id: str
    agent_id: str
    work_id: str
    process: asyncio.subprocess.Process
    task_dir: Path
    results_path: Path
    stderr_path: Path
    done: asyncio.Event = field(default_factory=asyncio.Event)
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    stdin_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    stop_requested: bool = False
    interrupted: bool = False
    resource_paused: bool = False
    scanner_version: str | None = None
    protocol_version: str | None = None
    protocol_error: str | None = None
    finished_received: bool = False
    counters: dict[str, Any] = field(default_factory=dict)
    last_db_update: float = 0.0


class AgentNetworkClient:
    """Agent-owned view over one Run-level network discovery manager."""

    def __init__(self, manager: "NetworkDiscoveryManager", agent_id: str) -> None:
        self.manager = manager
        self.agent_id = agent_id

    async def discovery(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.start_discovery(self.agent_id, **kwargs)

    async def output(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.output(self.agent_id, **kwargs)

    async def stop(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.stop(self.agent_id, str(kwargs.get("task_id") or ""))

    async def cleanup(self, **kwargs: Any) -> dict[str, Any]:
        return await self.manager.cleanup(
            self.agent_id, str(kwargs.get("task_id") or "")
        )

    async def close(self) -> None:
        return None


class NetworkDiscoveryManager:
    """Own persistent fscan bridge tasks for a single Run."""

    def __init__(
        self,
        policy: WorkspacePolicy,
        service: StateService,
        run_id: str,
        *,
        binary_path: Path | None = None,
        resource_guard: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self.policy = policy
        self.service = service
        self.run_id = run_id
        self.binary_path = Path(binary_path or default_binary_path())
        self.resource_guard = resource_guard
        self.runtime_root = policy.root / ".system-tools" / "runs" / run_id
        self._live: dict[str, LiveNetworkTask] = {}
        self._task_locks: dict[str, asyncio.Lock] = {}
        self._agent_cleanup_locks: dict[str, asyncio.Lock] = {}
        self._run_cleanup_lock = asyncio.Lock()
        self._closed = False

    def bind(self, agent_id: str) -> AgentNetworkClient:
        return AgentNetworkClient(self, agent_id)

    async def initialize(self, *, resume: bool = False) -> None:
        tasks = await self.service.list_network_tasks(self.run_id)
        for row in tasks:
            self._repair_jsonl(self._task_dir(row["agent_id"], row["task_id"]) / "results.jsonl")
        if not resume:
            return
        for row in tasks:
            if row["status"] not in ACTIVE:
                continue
            await self._terminate_recorded_process(row)
            await self.service.update_network_task(
                self.run_id,
                row["agent_id"],
                row["task_id"],
                status="interrupted",
                resource_status="released",
                exit_code=-1,
                error_code="runtime_recovered",
            )
            await self._finish_work(row["task_id"], "interrupted", "runtime_recovered")

    async def start_discovery(
        self,
        agent_id: str,
        *,
        targets: str,
        ports: str | None = None,
        ping: bool = True,
        ping_tcp: bool = False,
        concurrency: int | None = None,
        timeout_seconds: float | None = None,
        web_mark: bool = True,
        scan_intent: str = "network_discovery",
        priority: int = 50,
        wait_seconds: float | None = 20.0,
        result_limit: int = 100,
    ) -> dict[str, Any]:
        self._require_open()
        if not self.binary_path.is_file():
            raise _error(
                "execution",
                "network_binary_missing",
                f"aion-fscan bridge not found at {self.binary_path}",
            )
        owner = await self.service.get_agent_runtime(self.run_id, agent_id)
        if owner["agent"]["status"] in {
            "completed",
            "failed",
            "stopped",
            "cancelled",
            "interrupted",
        }:
            raise _error(
                "conflict", "agent_terminal", "Finished Agent cannot start a network task"
            )
        task_id = f"network-{uuid4().hex}"
        task_dir = self._task_dir(agent_id, task_id)
        task_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        results_path = task_dir / "results.jsonl"
        results_path.touch(mode=0o600, exist_ok=False)
        params = {
            "targets": targets,
            "ports": ports or DEFAULT_PORTS,
            "ping": bool(ping),
            "ping_tcp": bool(ping_tcp),
            "concurrency": concurrency or 600,
            "timeout_seconds": timeout_seconds or 3.0,
            "web_mark": bool(web_mark),
            "scan_intent": scan_intent,
        }
        self._atomic_json(task_dir / "plan.json", params)
        estimated_hosts = self._estimate_hosts(targets)
        estimated_ports = self._estimate_ports(params["ports"])
        estimated_requests = max(1, estimated_hosts * estimated_ports)
        estimated_disk = estimated_requests * 1024
        estimated_memory = params["concurrency"] * 65_536
        work_id = self._work_id(task_id)
        try:
            await self.service.create_network_task(
                self.run_id,
                agent_id,
                task_id=task_id,
                scan_intent=scan_intent,
                result_path=self.policy.relative_lexical(results_path),
                estimated_hosts=estimated_hosts,
                estimated_ports=estimated_ports,
                estimated_requests=estimated_requests,
                requested_concurrency=params["concurrency"],
                priority=priority,
            )
        except Exception:
            shutil.rmtree(task_dir, ignore_errors=True)
            raise
        try:
            await self.service.create_resource_work(
                self.run_id,
                agent_id,
                work_id=work_id,
                owner_type="network_task",
                owner_id=task_id,
                phase="execution",
                priority=priority,
                requested_concurrency=params["concurrency"],
                estimated_requests=estimated_requests,
                estimated_disk_bytes=estimated_disk,
                estimated_memory_bytes=estimated_memory,
            )
        except Exception:
            await self.service.update_network_task(
                self.run_id,
                agent_id,
                task_id,
                status="failed",
                resource_status="released",
                error_code="resource_work_persistence_failed",
            )
            raise
        await self.service.update_network_task(
            self.run_id,
            agent_id,
            task_id,
            resource_status="queued",
        )
        return await self.output(
            agent_id,
            task_id=task_id,
            cursor=0,
            limit=result_limit,
            wait_seconds=wait_seconds,
        )

    async def launch_queued(
        self, task_id: str, *, work_id: str | None = None
    ) -> None:
        async with self._task_lock(task_id):
            if self._closed:
                return
            rows = await self.service.list_network_tasks(self.run_id)
            row = next((item for item in rows if item["task_id"] == task_id), None)
            if row is None:
                raise _error("not_found", "task_not_found", "Network task was not found")
            if row["status"] != "queued" or row["output_cleaned_at"] is not None:
                return
            task_dir = self._task_dir(row["agent_id"], task_id)
            plan_path = task_dir / "plan.json"
            if not plan_path.is_file():
                await self.service.update_network_task(
                    self.run_id,
                    row["agent_id"],
                    task_id,
                    status="failed",
                    error_code="plan_missing",
                )
                raise _error("persistence", "plan_missing", "Network scan plan is missing")
            params = json.loads(plan_path.read_text(encoding="utf-8"))
            await self._spawn(
                row,
                task_dir,
                params,
                work_id or self._work_id(task_id),
            )

    async def output(
        self,
        agent_id: str,
        *,
        task_id: str,
        cursor: int = 0,
        limit: int = 100,
        filters: dict[str, Any] | None = None,
        wait_seconds: float | None = 20.0,
    ) -> dict[str, Any]:
        row = await self._owned(agent_id, task_id)
        if row["output_cleaned_at"] is not None:
            raise _error(
                "not_found", "task_output_expired", "Network task output was cleaned"
            )
        task_dir = self._task_dir(agent_id, task_id)
        results_path = task_dir / "results.jsonl"
        if row["status"] not in TERMINAL and wait_seconds != 0:
            await self._wait_for_output_change(
                agent_id,
                task_id,
                cursor,
                results_path,
                wait_seconds,
            )
            row = await self._owned(agent_id, task_id)
        records, next_cursor = self._read_results(results_path, cursor, limit, filters)
        summary = self._summary(task_id, task_dir)
        progress = self._read_json(task_dir / "progress.json")
        return {
            "task_id": task_id,
            "status": row["status"],
            "resource_status": row["resource_status"],
            "scan_intent": row["scan_intent"],
            "estimated_hosts": row["estimated_hosts"],
            "estimated_ports": row["estimated_ports"],
            "hosts_alive": summary.get("hosts_alive", row["hosts_alive"]),
            "open_ports": summary.get("open_ports", row["open_ports"]),
            "services": summary.get("services", row["services"]),
            "web_ports": summary.get("web_ports", row["web_ports"]),
            "progress": progress,
            "scanner_version": row["scanner_version"],
            "bridge_protocol_version": row["bridge_protocol_version"],
            "exit_code": row["exit_code"],
            "error_code": row["error_code"],
            "summary": summary,
            "results": records,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "recommended_wait_seconds": 20 if row["status"] not in TERMINAL else 0,
        }

    async def stop(self, agent_id: str, task_id: str) -> dict[str, Any]:
        async with self._task_lock(task_id):
            row = await self._owned(agent_id, task_id)
            if row["status"] == "queued":
                await self.service.update_network_task(
                    self.run_id,
                    agent_id,
                    task_id,
                    status="stopped",
                    resource_status="released",
                    error_code="stopped_by_agent",
                )
                await self._finish_work(task_id, "stopped", "stopped_by_agent")
            elif row["status"] == "running":
                live = self._live.get(task_id)
                if live is not None:
                    live.stop_requested = True
                    await self._send_control(live, "stop")
                    try:
                        await asyncio.wait_for(live.done.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        await self._terminate_process(live.process)
                        await live.done.wait()
                else:
                    await self._terminate_recorded_process(row)
                    await self.service.update_network_task(
                        self.run_id,
                        agent_id,
                        task_id,
                        status="stopped",
                        resource_status="released",
                        error_code="stopped_by_agent",
                    )
                    await self._finish_work(task_id, "stopped", "stopped_by_agent")
        current = await self._owned(agent_id, task_id)
        return {
            "task_id": task_id,
            "status": current["status"],
            "stopped": current["status"] in TERMINAL,
            "summary": self._summary(task_id, self._task_dir(agent_id, task_id)),
        }

    async def cleanup(self, agent_id: str, task_id: str) -> dict[str, Any]:
        async with self._task_lock(task_id):
            row = await self._owned(agent_id, task_id)
            if row["status"] in ACTIVE:
                raise _error(
                    "conflict",
                    "task_still_running",
                    "Active network task must be stopped before cleanup",
                )
            already_cleaned = row["output_cleaned_at"] is not None
            if not already_cleaned:
                task_dir = self._task_dir(agent_id, task_id)
                await asyncio.to_thread(shutil.rmtree, task_dir, True)
                await self.service.mark_network_task_output_cleaned(
                    self.run_id, agent_id, task_id, reason="explicit"
                )
            return {
                "task_id": task_id,
                "status": row["status"],
                "cleaned": True,
                "already_cleaned": already_cleaned,
            }

    async def pause_run(self) -> None:
        self._closed = True
        for row in await self.service.list_network_tasks(
            self.run_id, statuses=ACTIVE
        ):
            live = self._live.get(row["task_id"])
            if live is not None:
                live.interrupted = True
                await self._send_control(live, "stop")
                try:
                    await asyncio.wait_for(live.done.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    await self._terminate_process(live.process)
                    await live.done.wait()
            else:
                await self._terminate_recorded_process(row)
                await self.service.update_network_task(
                    self.run_id,
                    row["agent_id"],
                    row["task_id"],
                    status="interrupted",
                    resource_status="released",
                    error_code="runtime_paused",
                )
                await self._finish_work(row["task_id"], "interrupted", "runtime_paused")

    async def finish_agent(self, agent_id: str) -> None:
        async with self._agent_cleanup_lock(agent_id):
            for row in await self.service.list_network_tasks(
                self.run_id, agent_id=agent_id, statuses=ACTIVE
            ):
                await self.stop(agent_id, row["task_id"])
            for row in await self.service.list_network_tasks(
                self.run_id, agent_id=agent_id, output_available_only=True
            ):
                if row["status"] in TERMINAL:
                    await self.cleanup(agent_id, row["task_id"])

    async def finish_run(self) -> None:
        async with self._run_cleanup_lock:
            if self._closed:
                return
            rows = await self.service.list_network_tasks(self.run_id)
            agent_ids = list(dict.fromkeys(str(row["agent_id"]) for row in rows))
            for agent_id in agent_ids:
                await self.finish_agent(agent_id)
            self._closed = True

    async def _spawn(
        self,
        row: dict[str, Any],
        task_dir: Path,
        params: dict[str, Any],
        work_id: str,
    ) -> None:
        stderr_path = task_dir / "stderr.log"
        process = await asyncio.create_subprocess_exec(
            str(self.binary_path),
            cwd=str(self.policy.root),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            process_started_at = float(
                await asyncio.to_thread(psutil.Process(process.pid).create_time)
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_started_at = 0.0
        counters = {
            "estimated_hosts": row["estimated_hosts"],
            "estimated_ports": row["estimated_ports"],
            "hosts_alive": set(),
            "open_ports": 0,
            "services": 0,
            "web_ports": 0,
            "by_service": {},
            "errors": 0,
            "records": 0,
            "result_bytes": 0,
            "tasks_total": 0,
            "tasks_completed": 0,
            "started_at": _now(),
            "finished_at": None,
            "duration_ms": 0,
            "stopped": False,
            "interrupted": False,
        }
        live = LiveNetworkTask(
            task_id=row["task_id"],
            agent_id=row["agent_id"],
            work_id=work_id,
            process=process,
            task_dir=task_dir,
            results_path=task_dir / "results.jsonl",
            stderr_path=stderr_path,
            counters=counters,
        )
        self._live[live.task_id] = live
        try:
            await self.service.update_network_task(
                self.run_id,
                live.agent_id,
                live.task_id,
                status="running",
                resource_status="running",
                pid=process.pid,
                process_started_at=process_started_at,
            )
        except Exception:
            self._live.pop(live.task_id, None)
            await self._terminate_process(process)
            raise
        asyncio.create_task(self._monitor(live), name=f"aion-network-{live.task_id}")
        start = {
            "type": "start",
            "protocol_version": BRIDGE_PROTOCOL_VERSION,
            "task_id": live.task_id,
            "targets": params["targets"],
            "ports": params["ports"],
            "ping": params["ping"],
            "ping_tcp": params["ping_tcp"],
            "concurrency": params["concurrency"],
            "timeout_seconds": params["timeout_seconds"],
            "web_mark": params["web_mark"],
        }
        await self._write_command(live, start)
        ready_wait = asyncio.create_task(live.ready.wait())
        done_wait = asyncio.create_task(live.done.wait())
        done, pending = await asyncio.wait(
            {ready_wait, done_wait}, timeout=5.0, return_when=asyncio.FIRST_COMPLETED
        )
        for waiter in pending:
            waiter.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if ready_wait not in done or not live.ready.is_set():
            live.protocol_error = live.protocol_error or "bridge_handshake_failed"
            await self._terminate_process(process)
            await live.done.wait()
            raise _error(
                "execution",
                "bridge_handshake_failed",
                "fscan bridge did not complete protocol handshake",
            )
        await self.service.update_network_task(
            self.run_id,
            live.agent_id,
            live.task_id,
            resource_status="running",
            scanner_version=live.scanner_version,
            bridge_protocol_version=live.protocol_version,
        )
        if self.resource_guard is not None:
            asyncio.create_task(
                self._resource_monitor(live),
                name=f"aion-network-resources-{live.task_id}",
            )

    async def _monitor(self, live: LiveNetworkTask) -> None:
        assert live.process.stdout is not None
        assert live.process.stderr is not None
        started = time.perf_counter()
        stdout_reader = asyncio.create_task(self._consume_stdout(live))
        stderr_reader = asyncio.create_task(self._consume_stderr(live))
        await live.process.wait()
        reader_results = await asyncio.gather(
            stdout_reader, stderr_reader, return_exceptions=True
        )
        if any(isinstance(item, Exception) for item in reader_results):
            live.protocol_error = live.protocol_error or "bridge_output_persistence_failed"
        live.counters["duration_ms"] = int((time.perf_counter() - started) * 1000)
        live.counters["finished_at"] = _now()
        if live.interrupted:
            status, error_code = "interrupted", "runtime_interrupted"
            live.counters["interrupted"] = True
        elif live.stop_requested:
            status, error_code = "stopped", "stopped_by_agent"
            live.counters["stopped"] = True
        elif live.protocol_error:
            status, error_code = "failed", live.protocol_error
        elif live.process.returncode == 0 and live.finished_received:
            status, error_code = "completed", None
        elif live.process.returncode == 0:
            status, error_code = "failed", "bridge_unexpected_eof"
        else:
            status, error_code = "failed", "bridge_exit_nonzero"
        try:
            self._write_summary(live)
        except OSError:
            status, error_code = "failed", "result_persistence_failed"
        try:
            await self._persist_progress(live, force=True)
            await self.service.update_network_task(
                self.run_id,
                live.agent_id,
                live.task_id,
                status=status,
                resource_status="released",
                tasks_total=int(live.counters["tasks_total"]),
                tasks_completed=int(live.counters["tasks_completed"]),
                result_count=int(live.counters["records"]),
                result_bytes=int(live.counters["result_bytes"]),
                hosts_alive=len(live.counters["hosts_alive"]),
                open_ports=int(live.counters["open_ports"]),
                services=int(live.counters["services"]),
                web_ports=int(live.counters["web_ports"]),
                exit_code=live.process.returncode,
                error_code=error_code,
            )
        finally:
            await self._finish_work(live.task_id, status, error_code)
            live.changed.set()
            live.done.set()
            self._live.pop(live.task_id, None)

    async def _consume_stdout(self, live: LiveNetworkTask) -> None:
        assert live.process.stdout is not None
        while True:
            raw = await live.process.stdout.readline()
            if not raw:
                break
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                live.protocol_error = "bridge_protocol_error"
                live.counters["errors"] += 1
                continue
            event_type = event.get("type")
            if event_type == "ready":
                protocol = str(event.get("protocol_version") or "")
                if protocol != BRIDGE_PROTOCOL_VERSION:
                    live.protocol_error = "bridge_protocol_version_mismatch"
                    continue
                live.protocol_version = protocol
                live.scanner_version = str(event.get("scanner_version") or "unknown")
                live.ready.set()
            elif event_type == "progress":
                for name in ("tasks_total", "tasks_completed"):
                    if event.get(name) is not None:
                        live.counters[name] = max(0, int(event[name]))
                self._atomic_json(live.task_dir / "progress.json", event)
                await self._persist_progress(live)
            elif event_type == "result":
                await self._store_result(live, event.get("result") or {})
            elif event_type == "error":
                live.protocol_error = str(event.get("code") or "bridge_error")
                live.counters["errors"] += 1
            elif event_type == "finished":
                live.finished_received = True
                stats = event.get("stats") or {}
                for name in ("tasks_total", "tasks_completed"):
                    if stats.get(name) is not None:
                        live.counters[name] = max(0, int(stats[name]))
            else:
                live.protocol_error = "bridge_protocol_error"
                live.counters["errors"] += 1
            live.changed.set()

    async def _store_result(self, live: LiveNetworkTask, result: dict[str, Any]) -> None:
        result_type = str(result.get("type") or "").upper()
        if result_type not in {"HOST", "PORT", "SERVICE"}:
            return
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        target = str(result.get("target") or "")
        host = str(details.get("host") or target.split(":", 1)[0])
        record = {
            "type": result_type,
            "target": target,
            "status": result.get("status"),
            "host": host,
            "port": details.get("port"),
            "service": details.get("service"),
            "protocol": details.get("protocol"),
            "banner": details.get("banner"),
            "title": details.get("title"),
            "url": details.get("url"),
            "version": details.get("version"),
            "os": details.get("os"),
            "plugin": details.get("plugin"),
            "time": result.get("time") or _now(),
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            with live.results_path.open("a", encoding="utf-8") as output:
                output.write(line)
                output.flush()
        except OSError:
            live.protocol_error = "result_persistence_failed"
            await self._send_control(live, "stop")
            return
        counters = live.counters
        counters["records"] += 1
        counters["result_bytes"] += len(line.encode("utf-8"))
        if result_type == "HOST" and host:
            counters["hosts_alive"].add(host)
        elif result_type == "PORT":
            if host:
                counters["hosts_alive"].add(host)
            counters["open_ports"] += 1
        elif result_type == "SERVICE":
            counters["services"] += 1
            service = str(details.get("service") or "unknown")
            counters["by_service"][service] = counters["by_service"].get(service, 0) + 1
            if details.get("is_web") or service.lower() in {"http", "https"}:
                counters["web_ports"] += 1
            await self._record_service_observation(live, record)
        await self._persist_progress(live)

    async def _record_service_observation(
        self, live: LiveNetworkTask, record: dict[str, Any]
    ) -> None:
        try:
            runtime = await self.service.get_agent_runtime(
                self.run_id, live.agent_id
            )
        except Exception:
            return
        unique_code = runtime["agent"].get("unique_code")
        if not unique_code:
            return
        try:
            await self.service.record_observation(
                self.run_id,
                unique_code,
                category="service",
                summary=(
                    f"{record.get('host')}:{record.get('port')} "
                    f"{record.get('service') or 'unknown'}"
                ),
                detail=dict(record),
                source="network_discovery",
                source_ref=live.task_id,
                confidence=0.7,
            )
        except Exception:
            pass

    async def _consume_stderr(self, live: LiveNetworkTask) -> None:
        assert live.process.stderr is not None
        with live.stderr_path.open("ab") as output:
            while True:
                chunk = await live.process.stderr.read(65_536)
                if not chunk:
                    break
                output.write(chunk)
                output.flush()

    async def _resource_monitor(self, live: LiveNetworkTask) -> None:
        assert self.resource_guard is not None
        while not live.done.is_set() and not live.stop_requested and not live.interrupted:
            try:
                decision = await self.resource_guard(live.work_id)
                if live.stop_requested or live.interrupted:
                    return
                allowed = bool(decision.get("ok"))
                if not allowed and not live.resource_paused:
                    await self._send_control(live, "pause")
                    live.resource_paused = True
                    await self.service.update_network_task(
                        self.run_id,
                        live.agent_id,
                        live.task_id,
                        resource_status="waiting",
                    )
                elif allowed and live.resource_paused:
                    await self._send_control(live, "resume")
                    live.resource_paused = False
                    await self.service.update_network_task(
                        self.run_id,
                        live.agent_id,
                        live.task_id,
                        resource_status="running",
                    )
                try:
                    await asyncio.wait_for(
                        live.done.wait(),
                        timeout=max(1.0, float(decision.get("retry_after_seconds", 2.0))),
                    )
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception:
                try:
                    await asyncio.wait_for(live.done.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

    async def _persist_progress(self, live: LiveNetworkTask, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - live.last_db_update < 5.0:
            return
        live.last_db_update = now
        await self.service.update_network_task(
            self.run_id,
            live.agent_id,
            live.task_id,
            tasks_total=int(live.counters["tasks_total"]),
            tasks_completed=int(live.counters["tasks_completed"]),
            result_count=int(live.counters["records"]),
            result_bytes=int(live.counters["result_bytes"]),
            hosts_alive=len(live.counters["hosts_alive"]),
            open_ports=int(live.counters["open_ports"]),
            services=int(live.counters["services"]),
            web_ports=int(live.counters["web_ports"]),
        )

    async def _wait_for_output_change(
        self,
        agent_id: str,
        task_id: str,
        cursor: int,
        results_path: Path,
        wait_seconds: float | None,
    ) -> None:
        live = self._live.get(task_id)
        if live is not None:
            if wait_seconds is None:
                await live.done.wait()
                return
            if results_path.exists() and results_path.stat().st_size > cursor:
                return
            live.changed.clear()
            if live.done.is_set() or (
                results_path.exists() and results_path.stat().st_size > cursor
            ):
                return
            try:
                await asyncio.wait_for(live.changed.wait(), timeout=wait_seconds)
            except asyncio.TimeoutError:
                pass
            return
        deadline = None if wait_seconds is None else time.monotonic() + wait_seconds
        while True:
            row = await self._owned(agent_id, task_id)
            if row["status"] in TERMINAL:
                return
            if (
                wait_seconds is not None
                and results_path.exists()
                and results_path.stat().st_size > cursor
            ):
                return
            if deadline is not None and time.monotonic() >= deadline:
                return
            await asyncio.sleep(1.0)

    async def _send_control(self, live: LiveNetworkTask, command: str) -> None:
        await self._write_command(live, {"type": command, "task_id": live.task_id})

    async def _write_command(self, live: LiveNetworkTask, payload: dict[str, Any]) -> None:
        if live.process.stdin is None or live.process.returncode is not None:
            return
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        async with live.stdin_lock:
            try:
                live.process.stdin.write(encoded)
                await live.process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                live.protocol_error = "bridge_control_channel_closed"

    async def _finish_work(
        self, task_id: str, status: str, reason: str | None
    ) -> None:
        try:
            await self.service.update_resource_work(
                self.run_id,
                self._work_id(task_id),
                status="completed" if status == "completed" else status,
                reason=reason,
            )
        except StateNotFound:
            pass

    async def _owned(self, agent_id: str, task_id: str) -> dict[str, Any]:
        try:
            return await self.service.get_network_task(self.run_id, agent_id, task_id)
        except StateNotFound as exc:
            raise _error("not_found", "task_not_found", "Network task was not found") from exc

    async def _terminate_recorded_process(self, row: dict[str, Any]) -> None:
        pid = row.get("pid")
        started_at = row.get("process_started_at")
        if not pid or started_at is None:
            return
        try:
            process = psutil.Process(int(pid))
            actual = float(await asyncio.to_thread(process.create_time))
            if abs(actual - float(started_at)) > 0.01:
                return
            await asyncio.to_thread(process.terminate)
            try:
                await asyncio.to_thread(process.wait, 2.0)
            except psutil.TimeoutExpired:
                await asyncio.to_thread(process.kill)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

    async def _terminate_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()

    def _write_summary(self, live: LiveNetworkTask) -> None:
        counters = live.counters
        self._atomic_json(
            live.task_dir / "summary.json",
            {
                "task_id": live.task_id,
                "estimated_hosts": counters["estimated_hosts"],
                "estimated_ports": counters["estimated_ports"],
                "hosts_alive": len(counters["hosts_alive"]),
                "open_ports": counters["open_ports"],
                "services": counters["services"],
                "web_ports": counters["web_ports"],
                "by_service": dict(counters["by_service"]),
                "errors": counters["errors"],
                "records": counters["records"],
                "result_bytes": counters["result_bytes"],
                "tasks_total": counters["tasks_total"],
                "tasks_completed": counters["tasks_completed"],
                "started_at": counters["started_at"],
                "finished_at": counters["finished_at"],
                "duration_ms": counters["duration_ms"],
                "stopped": counters["stopped"],
                "interrupted": counters["interrupted"],
            },
        )

    def _summary(self, task_id: str, task_dir: Path) -> dict[str, Any]:
        saved = self._read_json(task_dir / "summary.json")
        if saved:
            return saved
        live = self._live.get(task_id)
        if live is None:
            return {}
        counters = live.counters
        return {
            "task_id": task_id,
            "estimated_hosts": counters["estimated_hosts"],
            "estimated_ports": counters["estimated_ports"],
            "hosts_alive": len(counters["hosts_alive"]),
            "open_ports": counters["open_ports"],
            "services": counters["services"],
            "web_ports": counters["web_ports"],
            "by_service": dict(counters["by_service"]),
            "errors": counters["errors"],
            "records": counters["records"],
            "tasks_total": counters["tasks_total"],
            "tasks_completed": counters["tasks_completed"],
        }

    @staticmethod
    def _read_results(
        path: Path,
        cursor: int,
        limit: int,
        filters: dict[str, Any] | None,
    ) -> tuple[list[dict[str, Any]], int]:
        records: list[dict[str, Any]] = []
        next_cursor = cursor
        if not path.exists():
            return records, next_cursor
        with path.open("rb") as source:
            source.seek(min(cursor, path.stat().st_size))
            while len(records) < limit:
                line = source.readline()
                if not line:
                    break
                next_cursor = source.tell()
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if NetworkDiscoveryManager._matches_filter(record, filters):
                    records.append(record)
        return records, next_cursor

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_name(path.name + ".part")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _repair_jsonl(path: Path) -> None:
        if not path.is_file() or path.stat().st_size == 0:
            return
        with path.open("rb+") as output:
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(size - 1)
            if output.read(1) == b"\n":
                return
            position = size - 1
            while position >= 0:
                output.seek(position)
                if output.read(1) == b"\n":
                    output.truncate(position + 1)
                    return
                position -= 1
            output.truncate(0)

    def _task_dir(self, agent_id: str, task_id: str) -> Path:
        return self._agent_root(agent_id) / "network-tasks" / task_id

    def _agent_root(self, agent_id: str) -> Path:
        return self.runtime_root / "agents" / str(agent_id)

    @staticmethod
    def _work_id(task_id: str) -> str:
        return f"{task_id}-execution-1"

    @staticmethod
    def _estimate_hosts(targets: str) -> int:
        total = 0
        for raw in targets.split(","):
            value = raw.strip()
            if not value:
                continue
            try:
                total += max(1, ipaddress.ip_network(value, strict=False).num_addresses)
                continue
            except ValueError:
                pass
            try:
                ipaddress.ip_address(value)
                total += 1
                continue
            except ValueError:
                pass
            if "-" in value:
                left, _, right = value.partition("-")
                try:
                    if "." not in right:
                        prefix, _, _ = left.rpartition(".")
                        right = f"{prefix}.{right}"
                    start = ipaddress.ip_address(left)
                    end = ipaddress.ip_address(right)
                    total += max(1, int(end) - int(start) + 1)
                    continue
                except ValueError:
                    pass
            total += 1
        return max(1, total)

    @staticmethod
    def _estimate_ports(ports: str) -> int:
        if not ports:
            return len(DEFAULT_PORTS.split(","))
        if ports.strip().lower() == "all":
            return 65_535
        count = 0
        for token in ports.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                try:
                    start, end = token.split("-", 1)
                    count += max(1, int(end) - int(start) + 1)
                except ValueError:
                    count += 1
            else:
                count += 1
        return max(1, count)

    @staticmethod
    def _matches_filter(record: dict[str, Any], filters: dict[str, Any] | None) -> bool:
        if not filters:
            return True
        if filters.get("status") and record.get("status") != filters["status"]:
            return False
        if filters.get("port") is not None and record.get("port") != int(filters["port"]):
            return False
        if filters.get("service") and str(record.get("service") or "") != str(filters["service"]):
            return False
        if filters.get("host") and str(record.get("host") or "") != str(filters["host"]):
            return False
        return True

    def _require_open(self) -> None:
        if self._closed:
            raise _error("conflict", "network_manager_closed", "Network manager is closed")

    def _task_lock(self, task_id: str) -> asyncio.Lock:
        return self._task_locks.setdefault(task_id, asyncio.Lock())

    def _agent_cleanup_lock(self, agent_id: str) -> asyncio.Lock:
        return self._agent_cleanup_locks.setdefault(agent_id, asyncio.Lock())
