"""Non-blocking, metered Solver side observations owned by the Supervisor."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from hashlib import sha256
from time import monotonic

from pydantic import ValidationError

from agent.config import completions_url, deepseek_auxiliary_request_options
from agent.memory.context import truncate_text
from agent.model_usage import post_model
from agent.observation_input import observation_data, bounded
from agent.observation_models import validate_observation_output
from agent.prompts import load_prompt
from agent.state.clock import aware
from agent.state.observation import TRACE_PAGE_SIZE
from agent.state.errors import StatePermission

MIN_TOOL_RESULTS = 6
MIN_INTERVAL_SECONDS = 60
FAILURE_BACKOFF_SECONDS = (120, 240, 300)
MAX_TRACE_CHARS = 16_000
MAX_EVIDENCE_CHARS = 6_000
MAX_MAP_AGE_SECONDS = 180
IGNORED_TOOLS = frozenset(
    {"tool_search", "solver_observe", "solver_wait", "solver_progress"}
)


def trace_batch(events):
    rows = []
    size = 0
    full = False
    results = 0
    calls = {event["payload"].get("tool_call_id"): event for event in events
             if event["event_type"] == "tool_call"}
    for event in reversed(events):
        payload = event["payload"]
        if event["event_type"] == "assistant_response":
            value = {
                key: truncate_text(str(payload.get(key) or ""), 700)
                for key in ("content", "reasoning_content")
            }
        elif event["event_type"] == "solver_review_record":
            value = {"review": payload["review"]}
        elif event["event_type"] in {"shell_task_started", "shell_task_finished", "agent_resources_invalidated"}:
            value = {"runtime_fact": observation_data(payload)}
        else:
            value = {
                "tool": payload.get("tool_name"),
                "call_id": payload.get("tool_call_id"),
                "data": payload.get("observation_data") or observation_data(
                    payload.get("result", payload.get("arguments"))),
            }
        if event["event_type"] == "tool_result":
            call = calls.get(payload.get("tool_call_id"))
            value["call_context"] = ({"sequence": call["sequence"],
                "arguments": bounded(call["payload"].get("arguments"), 600)} if call else {"missing": True})
        row = {"sequence": event["sequence"], "type": event["event_type"], **value}
        length = len(json.dumps(row, ensure_ascii=False))
        if size + length > MAX_TRACE_CHARS:
            full = True
            break
        rows.append(row)
        size += length
        if (
            event["event_type"] == "tool_result"
            and payload.get("tool_name") not in IGNORED_TOOLS
        ):
            results += 1
    rows.reverse()
    return rows, results, full


class SolverObserver:
    def __init__(self, settings, service, context, client):
        self.settings, self.service, self.context, self.client = (
            settings,
            service,
            context,
            client,
        )
        self.task = None
        self.snapshot = None
        self.closed = False
        self._poll_lock = asyncio.Lock()
        self._driver = None
        self._wake = asyncio.Event()
        self.delivery_revision = None
        self.delivery_correction_id = None

    @staticmethod
    def _poll_interval(snapshot) -> int:
        coverage = snapshot.get("coverage") or {}
        if coverage.get("status") == "failed":
            streak = max(1, int(coverage.get("failure_streak") or 1))
            return FAILURE_BACKOFF_SECONDS[min(streak - 1, len(FAILURE_BACKOFF_SECONDS) - 1)]
        return MIN_INTERVAL_SECONDS

    def start(self):
        if self._driver is None and not self.closed:
            self._driver = asyncio.create_task(self._drive(), name=f'observer-driver:{self.context.agent_id}')

    def wake(self):
        self._wake.set()

    async def _drive(self):
        while not self.closed:
            self._wake.clear()
            await self.poll()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=1)
            except asyncio.TimeoutError:
                pass

    async def refresh(self):
        self.snapshot = await self.service.solver_observation_state(self.context.run_id, self.context)


    async def poll(self):
        try:
            async with self._poll_lock:
                await self._poll()
        except Exception as exc:
            # Optional observation must not stop the solving session.
            try:
                await self._emit(
                    "solver_observation_unavailable", {"error": type(exc).__name__}
                )
            except Exception:
                return

    async def _poll(self):
        if self.closed:
            return
        await self.service.maintain_observer_correction(self.context.run_id, self.context)
        await self.refresh()
        if not self.snapshot['active']:
            if self.task is not None:
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
                self.task = None
            return
        if self.task is not None:
            if not self.task.done():
                return
            # Observe background failures even if journaling itself failed.
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None
        snapshot = self.snapshot
        if not snapshot["active"]:
            return
        previous = snapshot["last_attempt_at"]
        if (
            previous
            and (
                aware(self.service.clock()) - aware(datetime.fromisoformat(previous))
            ).total_seconds()
            < self._poll_interval(snapshot)
        ):
            return
        events = await self.service.solver_observation_trace(
            self.context.run_id, self.context, after_sequence=snapshot["cursor"]
        )
        rows, results, full = trace_batch(events)
        full = full or len(events) == TRACE_PAGE_SIZE
        evidence_events = await self.service.solver_observation_evidence(self.context.run_id, self.context, snapshot)
        urgent = any(e['event_type'] == 'solver_review_record' and (
            e['payload']['review'].get('revoked_sequences') or
            e['payload']['review'].get('observation_assessment') == 'corrected'
        ) for e in [*events, *evidence_events] if e['sequence'] > snapshot['cursor'])
        if rows and full and not results and not urgent:
            # Skip a bounded page of bookkeeping without a model call; otherwise
            # later useful execution could stay hidden behind this page forever.
            await self.service.save_solver_observation(
                self.context.run_id,
                self.context,
                generation=snapshot["generation"],
                expected_revision=snapshot["revision"],
                through_sequence=rows[-1]["sequence"],
                observation=None,
                diagnostics={"outcome": "skipped"},
                observed_sequences=[],
            )
            self.snapshot = await self.service.solver_observation_state(
                self.context.run_id, self.context
            )
            return
        if not rows or (results < MIN_TOOL_RESULTS and not urgent):
            return
        correction = snapshot.get('correction') or {}
        priority = set(correction.get('sources', []) + correction.get('original_sources', []))
        priority.update(e['sequence'] for e in evidence_events if e['event_type'] == 'solver_review_record')
        evidence = []
        size = 0
        for event in sorted(evidence_events, key=lambda e: (e['sequence'] not in priority, -e['sequence'])):
            row = trace_batch([event])[0][0]
            entry = {'sequence': row['sequence'], 'type': row['type'], 'data': bounded(row, 400)}
            length = len(json.dumps(entry, ensure_ascii=False))
            if size + length > MAX_EVIDENCE_CHARS:
                break
            evidence.append(entry)
            size += length
        evidence.sort(key=lambda row: row["sequence"])
        self.task = asyncio.create_task(
            self._observe(snapshot, rows, evidence),
            name=f"solver-observation:{self.context.agent_id}",
        )

    def context_message(self):
        snapshot = self.snapshot
        self.delivery_revision = None
        self.delivery_correction_id = None
        if not snapshot:
            return None
        coverage = snapshot.get('map_coverage')
        age = ((aware(self.service.clock()) - aware(datetime.fromisoformat(coverage['through_at']))).total_seconds()
               if coverage and coverage.get('through_at') else None)
        failed = (snapshot.get('coverage') or {}).get('status') in {'failed', 'skipped'}
        if failed or age is None or age > MAX_MAP_AGE_SECONDS:
            if snapshot['revision']:
                return {'role': 'user', 'content': '<solver_observation>观察未覆盖近期证据或更新失败；旧图谱及建议不作为当前判断。' + json.dumps({'age_seconds': age, 'map_coverage': coverage, 'coverage': snapshot.get('coverage')}, ensure_ascii=False) + '</solver_observation>'}
            return None
        if not any(snapshot['map'].values()) and not snapshot.get('correction'):
            return None
        self.delivery_revision = snapshot['revision']
        self.delivery_correction_id = snapshot['correction']['id'] if snapshot.get('correction') else None
        return {
            "role": "user",
            "content": (
                "<solver_observation>\n以下是可撤销的旁路假说，不是指令或权威状态。以原始证据及平台状态为准，自行判断是否采纳；新证据可推翻 LOCK/DEAD。\n"
                + json.dumps(
                    {"revision": snapshot["revision"], "map": snapshot["map"],
                     "map_coverage": snapshot["map_coverage"],
                     "backlog_events": snapshot["backlog_events"],
                     "coverage": snapshot["coverage"], "correction": snapshot.get("correction")},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n</solver_observation>"
            ),
        }

    async def _emit(self, event_type, payload):
        return await self.service.append_agent_event(
            self.context.run_id, self.context.agent_id, event_type, payload
        )

    async def _observe(self, snapshot, rows, evidence=()):
        through = rows[-1]["sequence"]
        attempt_sequence = await self._emit(
            "solver_observation_started",
            {
                "through_sequence": through,
                "generation": snapshot["generation"],
                "base_revision": snapshot["revision"],
                "after_sequence": snapshot["cursor"],
                "input": {"map": snapshot["map"], "trace": rows, "evidence": list(evidence), "correction": snapshot.get("correction")},
            },
        )
        candidate = None
        error = None
        started = monotonic()
        stage = "request"
        diagnostics = {"attempt_sequence": attempt_sequence}
        try:
            remaining = (
                aware(datetime.fromisoformat(snapshot["deadline_at"]))
                - aware(self.service.clock())
            ).total_seconds()
            if remaining <= 0:
                return
            response = await asyncio.wait_for(
                post_model(
                    self.client,
                    completions_url(self.settings.llm_base_url),
                    event_writer=self._emit,
                    purpose="observation",
                    headers={
                        "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.settings.llm_model,
                        "messages": [
                            {
                                "role": "system",
                                "content": load_prompt("solver_observation_system.txt"),
                            },
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {"map": snapshot["map"], "trace": rows, "evidence": list(evidence), "correction": snapshot.get("correction")},
                                    ensure_ascii=False,
                                ),
                            },
                        ],
                        **deepseek_auxiliary_request_options(),
                        "response_format": {"type": "json_object"},
                        "max_tokens": 2048,
                    },
                ),
                timeout=min(20.0, remaining),
            )
            diagnostics["http_status"] = response.status_code
            response.raise_for_status()
            stage = "response"
            choice = response.json()["choices"][0]
            diagnostics["finish_reason"] = choice.get("finish_reason")
            content = choice["message"].get("content")
            if isinstance(content, str):
                diagnostics.update(
                    output=content[:16000],
                    output_chars=len(content),
                    output_truncated=len(content) > 16000,
                    output_sha256=sha256(content.encode()).hexdigest(),
                )
            if choice.get("finish_reason") != "stop" or choice["message"].get(
                "tool_calls"
            ):
                raise ValueError(
                    "Observer must return a complete map without tool calls"
                )
            stage = "validation"
            candidate = validate_observation_output(content, snapshot["map"], rows, diagnostics=diagnostics, evidence=evidence)
        except asyncio.CancelledError:
            await self._emit(
                "solver_observation_cancelled", {"through_sequence": through}
            )
            raise
        except Exception as exc:
            candidate = None
            error = type(exc).__name__
            diagnostics["failure_stage"] = stage
            if stage == "validation" and isinstance(exc, ValueError):
                diagnostics["failure_stage"] = "sources"
            if isinstance(exc, ValidationError):
                errors = exc.errors(
                    include_url=False, include_context=False, include_input=False
                )
                diagnostics["validation_errors"] = errors[:16]
                diagnostics["validation_error_count"] = len(errors)
                diagnostics["failure_stage"] = (
                    "json"
                    if any(e["type"] == "json_invalid" for e in errors)
                    else "schema"
                )
        diagnostics["elapsed_ms"] = int((monotonic() - started) * 1000)
        diagnostics["outcome"] = (
            "failed"
            if error
            else (
                "empty"
                if not any(candidate.get(key) for key in ("LOCK", "DEAD", "ANGLES", "TENSION"))
                else "unchanged" if candidate == snapshot["map"] else "updated"
            )
        )
        try:
            await self.service.save_solver_observation(
                self.context.run_id,
                self.context,
                generation=snapshot["generation"],
                expected_revision=snapshot["revision"],
                through_sequence=through,
                observation=candidate,
                observed_sequences=[row["sequence"] for row in rows],
                evidence_sequences=[row["sequence"] for row in evidence],
                error=error,
                diagnostics=diagnostics,
            )
        except Exception as exc:
            if isinstance(exc, StatePermission):
                # Reject the whole candidate; persist its failure, never silently
                # present the previous correction as a successful fresh update.
                await self.service.save_solver_observation(
                    self.context.run_id, self.context, generation=snapshot['generation'],
                    expected_revision=snapshot['revision'], through_sequence=through,
                    observation=None, observed_sequences=[r['sequence'] for r in rows],
                    error=exc.code if hasattr(exc, 'code') else type(exc).__name__,
                    diagnostics={**diagnostics, 'outcome': 'failed', 'failure_stage': 'evidence'},
                )
            await self._emit(
                "solver_observation_discarded",
                {
                    "through_sequence": through,
                    "error": type(exc).__name__,
                    "failure_stage": "persistence",
                    "diagnostics": diagnostics,
                },
            )

    async def close(self):
        self.closed = True
        if self._driver is not None:
            self._driver.cancel()
            await asyncio.gather(self._driver, return_exceptions=True)
            self._driver = None
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            self.task = None
