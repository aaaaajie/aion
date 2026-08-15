"""A read-only, test-only Web flight recorder for one SQLite run.

The monitor has no dependency on the Runtime event loop.  A small polling
thread keeps a bounded summary cache, while detail and history requests read
the SQLite file through a short-lived read-only connection.  This makes the
page useful both while agents are running and after the Runtime has closed.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from agent.state.resources import (
    container_capacity_summary,
    container_slot_occupied,
)


WEB_ROOT = Path(__file__).resolve().parent
POLL_SECONDS = 0.75
GLOBAL_EVENT_LIMIT = 5_000
AGENT_EVENT_LIMIT = 500

LOGGER = logging.getLogger("aion.runtime_web")
if not LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("[AION monitor] %(asctime)s %(levelname)s %(message)s")
    )
    LOGGER.addHandler(_handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


def _json_load(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _redact(value: Any, *, key: str | None = None) -> Any:
    """Return persisted JSON unchanged for local plaintext analysis."""

    del key
    return value


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _row_value(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    value = row[key] if key in row.keys() else default
    return value if value is not None else default


def _run(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "run_id": row["run_id"],
        "status": row["status"],
        "model": row["model"],
        "prompt": row["prompt"],
        "context_window_tokens": row["context_window_tokens"],
        "phase": row["phase"],
        "duration_minutes": row["duration_minutes"],
        "started_at": _iso(row["started_at"]),
        "deadline_at": _iso(row["deadline_at"]),
        "current_challenge_code": row["current_challenge_code"],
        "score_snapshot": _redact(_json_load(row["score_snapshot"], {})),
        "last_sequence": row["last_sequence"],
        "last_projected_sequence": row["last_projected_sequence"],
        "stagnation_epoch": row["stagnation_epoch"],
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def _challenge(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "run_id": row["run_id"],
        "unique_code": row["unique_code"],
        "description": row["description"],
        "difficulty": row["difficulty"],
        "level": row["level"],
        "total_score": row["total_score"],
        "flag_count": row["flag_count"],
        "correct_flag_count": row["correct_flag_count"],
        "is_completed": bool(row["is_completed"]),
        "platform_status": row["platform_status"],
        "container_status": row["container_status"],
        "slot_occupied": container_slot_occupied(row["container_status"]),
        "container_addr": _redact(_json_load(row["container_addr"], [])),
        "work_status": row["work_status"],
        "low_yield": bool(row["stagnation_level"]),
        "hint_eligible": bool(row["hint_eligible"]),
        "hint_requested": bool(row["hint_requested"]),
        "exploration_seconds": row["exploration_seconds"],
        "active_since": _iso(row["active_since"]),
        "last_progress_at": _iso(row["last_progress_at"]),
        "paused_at": _iso(row["paused_at"]),
        "version": row["version"],
        "started_at": _iso(row["started_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def _agent(row: sqlite3.Row, *, include_runtime: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "agent_id": row["agent_id"],
        "run_id": row["run_id"],
        "parent_id": row["parent_id"],
        "unique_code": row["unique_code"],
        "cycle_id": row["cycle_id"],
        "role": row["role"],
        "kind": row["kind"],
        "priority": row["priority"],
        "mission": row["mission"],
        "success_criteria": _redact(_json_load(row["success_criteria"], [])),
        "context_refs": _redact(_json_load(row["context_refs"], [])),
        "status": row["status"],
        "timeout_seconds": row["timeout_seconds"],
        "last_heartbeat_at": _iso(row["last_heartbeat_at"]),
        "last_report_sequence": row["last_report_sequence"],
        "report_cursor": row["report_cursor"],
        "report_cursors": _redact(_json_load(row["report_cursors"], {})),
        "last_summarized_sequence": row["last_summarized_sequence"],
        "started_at": _iso(row["started_at"]),
        "ended_at": _iso(row["ended_at"]),
        "stop_requested_at": _iso(row["stop_requested_at"]),
        "version": row["version"],
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }
    if include_runtime:
        result.update(
            {
                "initial_prompt": _redact(row["initial_prompt"]),
                "session_memory": _redact(row["session_memory"]),
                "final_report": _redact(_json_load(row["final_report"], {})),
            }
        )
    else:
        result["initial_prompt"] = _redact(row["initial_prompt"])
    return result


def _cycle(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "cycle_id": row["cycle_id"],
        "run_id": row["run_id"],
        "unique_code": row["unique_code"],
        "cycle_number": row["cycle_number"],
        "status": row["status"],
        "state_snapshot": _redact(_json_load(row["state_snapshot"], {})),
        "analysis": _redact(_json_load(row["analysis"], {})),
        "plan": _redact(_json_load(row["plan"], {})),
        "verification": _redact(_json_load(row["verification"], {})),
        "state_update": _redact(_json_load(row["state_update"], {})),
        "version": row["version"],
        "state_at": _iso(row["state_at"]),
        "analysis_at": _iso(row["analysis_at"]),
        "plan_at": _iso(row["plan_at"]),
        "execute_at": _iso(row["execute_at"]),
        "verify_at": _iso(row["verify_at"]),
        "update_at": _iso(row["update_at"]),
        "completed_at": _iso(row["completed_at"]),
    }


def _finding(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "finding_id": row["finding_id"],
        "run_id": row["run_id"],
        "unique_code": row["unique_code"],
        "agent_id": row["agent_id"],
        "category": row["category"],
        "fingerprint": row["fingerprint"],
        "summary": row["summary"],
        "detail": _redact(_json_load(row["detail"], {})),
        "confidence": row["confidence"],
        "verification_status": row["verification_status"],
        "evidence_paths": _redact(_json_load(row["evidence_paths"], [])),
        "first_seen_at": _iso(row["first_seen_at"]),
        "last_seen_at": _iso(row["last_seen_at"]),
        "verified_at": _iso(row["verified_at"]),
        "version": row["version"],
    }


def _report(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "report_id": row["report_id"],
        "run_id": row["run_id"],
        "sequence": row["sequence"],
        "agent_id": row["agent_id"],
        "parent_id": row["parent_id"],
        "unique_code": row["unique_code"],
        "report_type": row["report_type"],
        "status": row["status"],
        "payload": _redact(_json_load(row["payload"], {})),
        "consumed_by": row["consumed_by"],
        "consumed_at": _iso(row["consumed_at"]),
        "created_at": _iso(row["created_at"]),
    }


def _credential(row: sqlite3.Row) -> dict[str, Any]:
    """Expose the complete credential record for local plaintext analysis."""

    return {
        "credential_id": row["credential_id"],
        "run_id": row["run_id"],
        "unique_code": row["unique_code"],
        "finding_id": row["finding_id"],
        "kind": row["kind"],
        "principal": row["principal"],
        "secret_value": row["secret_value"],
        "scope": row["scope"],
        "verified": bool(row["verified"]),
        "created_at": _iso(row["created_at"]),
    }


def _operation(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "operation_id": row["operation_id"],
        "run_id": row["run_id"],
        "agent_id": row["agent_id"],
        "unique_code": row["unique_code"],
        "operation_type": row["operation_type"],
        "status": row["status"],
        "arguments_fingerprint": row["arguments_fingerprint"],
        "request_payload": _redact(_json_load(row["request_payload"], {})),
        "result_payload": _redact(_json_load(row["result_payload"], {})),
        "result_code": row["result_code"],
        "error_code": row["error_code"],
        "error_message": _redact(row["error_message"]),
        "started_sequence": row["started_sequence"],
        "completed_sequence": row["completed_sequence"],
        "duration_ms": row["duration_ms"],
        "started_at": _iso(row["started_at"]),
        "completed_at": _iso(row["completed_at"]),
    }


def _admission(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "admission_id": row["admission_id"],
        "run_id": row["run_id"],
        "agent_id": row["agent_id"],
        "unique_code": row["unique_code"],
        "role": row["role"],
        "status": row["status"],
        "priority": row["priority"],
        "reason": row["reason"],
        "retry_at": _iso(row["retry_at"]),
        "reserved_at": _iso(row["reserved_at"]),
        "started_at": _iso(row["started_at"]),
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def _resource(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "sample_id": row["sample_id"],
        "cpu_percent": row["cpu_percent"],
        "memory_percent": row["memory_percent"],
        "sampled_at": _iso(row["sampled_at"]),
    }


def _event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "sequence": row["sequence"],
        "agent_id": row["agent_id"],
        "cycle_id": row["cycle_id"],
        "event_type": row["event_type"],
        "payload": _redact(_json_load(row["payload"], {})),
        "created_at": _iso(row["created_at"]),
    }


@dataclass(frozen=True)
class _MonitorState:
    mode: str = "live"
    test_result: str | None = None
    test_code: int | None = None
    frozen_at: str | None = None
    message: str | None = None


class _ReadOnlyStore:
    def __init__(self, database_path: Path, run_id: str) -> None:
        self.database_path = database_path.resolve()
        self.run_id = run_id

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{self.database_path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection

    def snapshot(self, after_sequence: int = 0) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            run_row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (self.run_id,)
            ).fetchone()
            if run_row is None:
                raise LookupError("run_not_found")

            run = _run(run_row)
            challenges = [
                _challenge(row)
                for row in connection.execute(
                    "SELECT * FROM challenges WHERE run_id = ? ORDER BY unique_code",
                    (self.run_id,),
                )
            ]
            agents = [
                _agent(row)
                for row in connection.execute(
                    "SELECT * FROM agents WHERE run_id = ? ORDER BY created_at, agent_id",
                    (self.run_id,),
                )
            ]
            cycles = [
                _cycle(row)
                for row in connection.execute(
                    "SELECT * FROM cycles WHERE run_id = ? ORDER BY cycle_number, cycle_id",
                    (self.run_id,),
                )
            ]
            findings = [
                _finding(row)
                for row in connection.execute(
                    "SELECT * FROM findings WHERE run_id = ? ORDER BY first_seen_at, finding_id",
                    (self.run_id,),
                )
            ]
            credentials = [
                _credential(row)
                for row in connection.execute(
                    """
                    SELECT credential_id, run_id, unique_code, finding_id,
                           kind, principal, secret_value, scope, verified, created_at
                    FROM credentials
                    WHERE run_id = ? ORDER BY created_at, credential_id
                    """,
                    (self.run_id,),
                )
            ]
            reports = [
                _report(row)
                for row in connection.execute(
                    "SELECT * FROM reports WHERE run_id = ? ORDER BY sequence DESC LIMIT 500",
                    (self.run_id,),
                )
            ][::-1]
            operations = [
                _operation(row)
                for row in connection.execute(
                    "SELECT * FROM operations WHERE run_id = ? ORDER BY started_at, operation_id",
                    (self.run_id,),
                )
            ]
            admissions = [
                _admission(row)
                for row in connection.execute(
                    "SELECT * FROM admission_queue WHERE run_id = ? ORDER BY priority, created_at, admission_id",
                    (self.run_id,),
                )
            ]
            resources = [
                _resource(row)
                for row in connection.execute(
                    "SELECT * FROM resource_samples WHERE run_id = ? ORDER BY sampled_at DESC LIMIT 120",
                    (self.run_id,),
                )
            ][::-1]
            outbox = connection.execute(
                """
                SELECT COUNT(*) AS pending_count,
                       COALESCE(MAX(attempts), 0) AS max_attempts,
                       MAX(last_error) AS last_error
                FROM audit_outbox
                WHERE run_id = ?
                """,
                (self.run_id,),
            ).fetchone()

            if after_sequence > 0:
                event_rows = list(
                    connection.execute(
                        """
                        SELECT * FROM state_events
                        WHERE run_id = ? AND sequence > ?
                        ORDER BY sequence ASC LIMIT ?
                        """,
                        (self.run_id, after_sequence, GLOBAL_EVENT_LIMIT),
                    )
                )
                truncated = False
            else:
                event_rows = list(
                    connection.execute(
                        """
                        SELECT * FROM state_events
                        WHERE run_id = ?
                        ORDER BY sequence DESC LIMIT ?
                        """,
                        (self.run_id, GLOBAL_EVENT_LIMIT),
                    )
                )[::-1]
                truncated = bool(event_rows) and event_rows[0]["sequence"] > 1
            events = [_event(row) for row in event_rows]
            latest_sequence = int(run["last_sequence"] or 0)
            event_cursor = events[-1]["sequence"] if events else after_sequence
            return {
                "run": run,
                "challenges": challenges,
                "container_capacity": container_capacity_summary(challenges),
                "agents": agents,
                "cycles": cycles,
                "findings": findings,
                "credentials": credentials,
                "reports": reports,
                "operations": operations,
                "admissions": admissions,
                "resources": resources,
                "projection": {
                    "last_projected_sequence": run["last_projected_sequence"],
                    "pending_count": int(outbox["pending_count"] or 0),
                    "max_attempts": int(outbox["max_attempts"] or 0),
                    "last_error": _redact(outbox["last_error"]),
                },
                "events": events,
                "event_cursor": event_cursor,
                "latest_sequence": latest_sequence,
                "events_truncated": truncated,
                "events_has_more": len(event_rows) >= GLOBAL_EVENT_LIMIT,
            }
        finally:
            connection.rollback()
            connection.close()

    def agent_detail(
        self, agent_id: str, *, before_sequence: int = 0, limit: int = AGENT_EVENT_LIMIT
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT * FROM agents WHERE run_id = ? AND agent_id = ?",
                (self.run_id, agent_id),
            ).fetchone()
            if row is None:
                raise LookupError("agent_not_found")
            bounded_limit = max(1, min(int(limit), AGENT_EVENT_LIMIT))
            if before_sequence > 0:
                event_rows = list(
                    connection.execute(
                        """
                        SELECT * FROM state_events
                        WHERE run_id = ? AND agent_id = ? AND sequence < ?
                        ORDER BY sequence DESC LIMIT ?
                        """,
                        (self.run_id, agent_id, before_sequence, bounded_limit),
                    )
                )[::-1]
            else:
                event_rows = list(
                    connection.execute(
                        """
                        SELECT * FROM state_events
                        WHERE run_id = ? AND agent_id = ?
                        ORDER BY sequence DESC LIMIT ?
                        """,
                        (self.run_id, agent_id, bounded_limit),
                    )
                )[::-1]
            events = [_event(item) for item in event_rows]
            return {
                "agent": _agent(row, include_runtime=True),
                "events": events,
                "next_before_sequence": events[0]["sequence"] if events else None,
                "has_more": len(events) >= bounded_limit,
            }
        finally:
            connection.rollback()
            connection.close()


class RuntimeMonitor:
    """Serve a local read-only dashboard for a single SQLite run."""

    def __init__(
        self,
        database_path: Path | str,
        run_id: str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("RuntimeMonitor only binds to localhost")
        self.database_path = Path(database_path).resolve()
        self.run_id = run_id
        self.host = host
        self.port = port
        self._store = _ReadOnlyStore(self.database_path, run_id)
        self._snapshot: dict[str, Any] | None = None
        self._state = _MonitorState()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._poll_thread: threading.Thread | None = None
        self._last_refresh_error: str | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("RuntimeMonitor has not started")
        actual_port = int(self._server.server_address[1])
        return f"http://{self.host}:{actual_port}/"

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("RuntimeMonitor has not started")
        return self.host, int(self._server.server_address[1])

    def start(self) -> str:
        if self._server is not None:
            return self.url
        if not self.database_path.is_file():
            raise FileNotFoundError(self.database_path)
        handler = self._handler_class()
        server = ThreadingHTTPServer((self.host, self.port), handler)
        server.daemon_threads = True
        server.monitor = self  # type: ignore[attr-defined]
        self._server = server
        self._refresh()
        self._server_thread = threading.Thread(
            target=server.serve_forever,
            name=f"aion-monitor-http-{self.run_id}",
            daemon=True,
        )
        self._server_thread.start()
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name=f"aion-monitor-poll-{self.run_id}",
            daemon=True,
        )
        self._poll_thread.start()
        LOGGER.info(
            "monitor_started run_id=%s database=%s address=%s",
            self.run_id,
            self.database_path,
            self.url,
        )
        return self.url

    def freeze(self, test_result: int | str, *, message: str | None = None) -> None:
        """Capture the final SQLite state and stop polling while serving it."""

        self._refresh()
        result_text = str(test_result)
        with self._lock:
            self._state = _MonitorState(
                mode="frozen",
                test_result=result_text,
                test_code=int(test_result) if isinstance(test_result, int) else None,
                frozen_at=datetime.now(timezone.utc).isoformat(),
                message=message,
            )
        LOGGER.info(
            "monitor_frozen run_id=%s result=%s message=%s",
            self.run_id,
            test_result,
            message or "",
        )
        self._refresh()
        self._stop.set()
        if self._poll_thread is not None and self._poll_thread is not threading.current_thread():
            self._poll_thread.join(timeout=2.0)

    def close(self) -> None:
        LOGGER.info("monitor_closing run_id=%s", self.run_id)
        self._stop.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._server_thread is not None and self._server_thread is not threading.current_thread():
            self._server_thread.join(timeout=2.0)
        if self._poll_thread is not None and self._poll_thread is not threading.current_thread():
            self._poll_thread.join(timeout=2.0)
        self._server = None
        self._server_thread = None
        self._poll_thread = None

    def _poll_loop(self) -> None:
        while not self._stop.wait(POLL_SECONDS):
            self._refresh()

    def _refresh(self) -> None:
        try:
            data = self._store.snapshot()
        except (LookupError, OSError, sqlite3.Error) as exc:
            error_key = f"{type(exc).__name__}:{exc}"
            if error_key != self._last_refresh_error:
                LOGGER.warning(
                    "monitor_refresh_failed run_id=%s error=%s",
                    self.run_id,
                    error_key,
                    exc_info=True,
                )
                self._last_refresh_error = error_key
            with self._lock:
                data = {
                    "run": {"run_id": self.run_id, "status": "unavailable"},
                    "challenges": [],
                    "agents": [],
                    "cycles": [],
                    "findings": [],
                    "credentials": [],
                    "reports": [],
                    "operations": [],
                    "admissions": [],
                    "resources": [],
                    "projection": {},
                    "events": [],
                    "event_cursor": 0,
                    "latest_sequence": 0,
                    "events_truncated": False,
                    "events_has_more": False,
                    "read_error": type(exc).__name__,
                }
        else:
            if self._last_refresh_error is not None:
                LOGGER.info("monitor_refresh_recovered run_id=%s", self.run_id)
                self._last_refresh_error = None
        with self._lock:
            data["monitor"] = {
                "mode": self._state.mode,
                "test_result": self._state.test_result,
                "test_code": self._state.test_code,
                "frozen_at": self._state.frozen_at,
                "message": self._state.message,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "poll_seconds": POLL_SECONDS,
            }
            self._snapshot = data

    def _snapshot_for(self, after_sequence: int) -> dict[str, Any]:
        with self._lock:
            cached = dict(self._snapshot or {})
        if after_sequence <= 0 or not cached:
            return cached
        events = [item for item in cached.get("events", []) if item["sequence"] > after_sequence]
        cached["events"] = events
        earliest = min((item["sequence"] for item in self._snapshot.get("events", [])), default=0)  # type: ignore[union-attr]
        cached["events_truncated"] = bool(earliest and earliest > after_sequence + 1)
        cached["events_gap_after"] = after_sequence if cached["events_truncated"] else None
        cached["event_cursor"] = events[-1]["sequence"] if events else after_sequence
        return cached

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        monitor = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AIONFlightRecorder/1.0"

            def do_GET(self) -> None:  # noqa: N802
                self._dispatch(send_body=True)

            def do_HEAD(self) -> None:  # noqa: N802
                self._dispatch(send_body=False)

            def do_POST(self) -> None:  # noqa: N802
                self._method_not_allowed()

            def do_PUT(self) -> None:  # noqa: N802
                self._method_not_allowed()

            def do_DELETE(self) -> None:  # noqa: N802
                self._method_not_allowed()

            def _dispatch(self, *, send_body: bool) -> None:
                parsed = urlsplit(self.path)
                path = unquote(parsed.path)
                if ".." in Path(path).parts:
                    self._send_json({"error": "invalid_path"}, HTTPStatus.BAD_REQUEST, send_body)
                    return
                params = parse_qs(parsed.query, keep_blank_values=False)
                try:
                    if path == "/" or path == "/index.html":
                        self._send_file("index.html", "text/html; charset=utf-8", send_body)
                    elif path == "/assets/app.js":
                        self._send_file("app.js", "text/javascript; charset=utf-8", send_body)
                    elif path == "/assets/styles.css":
                        self._send_file("styles.css", "text/css; charset=utf-8", send_body)
                    elif path in {"/assets/Challenge.svg", "/assets/Chief.svg", "/assets/Execution.svg"}:
                        self._send_file(Path(path).name, "image/svg+xml", send_body)
                    elif path == "/api/snapshot":
                        after = self._int_param(params, "after_sequence", 0)
                        self._send_json(monitor._snapshot_for(after), HTTPStatus.OK, send_body)
                    elif path.startswith("/api/agents/"):
                        agent_id = path.removeprefix("/api/agents/")
                        if not agent_id or "/" in agent_id:
                            raise LookupError("agent_not_found")
                        before = self._int_param(params, "before_sequence", 0)
                        limit = self._int_param(params, "limit", AGENT_EVENT_LIMIT)
                        detail = monitor._store.agent_detail(
                            agent_id, before_sequence=before, limit=limit
                        )
                        self._send_json(detail, HTTPStatus.OK, send_body)
                    elif path == "/api/health":
                        with monitor._lock:
                            state = monitor._state
                        self._send_json(
                            {
                                "ok": True,
                                "run_id": monitor.run_id,
                                "mode": state.mode,
                                "test_code": state.test_code,
                                "message": state.message,
                            },
                            HTTPStatus.OK,
                            send_body,
                        )
                    else:
                        self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND, send_body)
                except LookupError:
                    self._send_json({"error": "agent_not_found"}, HTTPStatus.NOT_FOUND, send_body)
                except (ValueError, TypeError):
                    self._send_json({"error": "invalid_query"}, HTTPStatus.BAD_REQUEST, send_body)
                except (OSError, sqlite3.Error):
                    self._send_json({"error": "state_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE, send_body)

            @staticmethod
            def _int_param(params: dict[str, list[str]], name: str, default: int) -> int:
                raw = params.get(name, [str(default)])[0]
                value = int(raw)
                if value < 0:
                    raise ValueError(name)
                return value

            def _send_file(self, filename: str, content_type: str, send_body: bool) -> None:
                content = (WEB_ROOT / filename).read_bytes()
                self.send_response(HTTPStatus.OK)
                self._headers(content_type, len(content))
                self.end_headers()
                if send_body:
                    self.wfile.write(content)

            def _send_json(self, payload: Any, status: HTTPStatus, send_body: bool) -> None:
                content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self._headers("application/json; charset=utf-8", len(content))
                self.end_headers()
                if send_body:
                    self.wfile.write(content)

            def _headers(self, content_type: str, length: int) -> None:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:;",
                )
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")

            def _method_not_allowed(self) -> None:
                self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
                self.send_header("Allow", "GET, HEAD")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                try:
                    message = format % args
                except (TypeError, ValueError):
                    message = format
                LOGGER.info(
                    "http_request run_id=%s client=%s message=%s",
                    monitor.run_id,
                    self.address_string(),
                    message,
                )

        return Handler


__all__ = ["RuntimeMonitor"]
