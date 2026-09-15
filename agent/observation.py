"""Non-blocking observer with facts-only input and no self-reinforcing memory."""

import asyncio
import json
import hashlib
import re
from datetime import datetime
import httpx
from pydantic import ValidationError

from agent.config import completions_url, deepseek_auxiliary_request_options
from agent.model_usage import post_model
from agent.observation_models import validate_observation_output, ObservationReferenceError
from agent.prompts import load_prompt
from agent.state.clock import aware

MIN_INTERVAL_SECONDS = 60
MAX_ADVICE_AGE_SECONDS = 180


class SolverObserver:
    def __init__(self, settings, service, context, client):
        self.settings, self.service, self.context, self.client = settings, service, context, client
        self.task = self.snapshot = self._driver = None
        self.closed = False
        self._wake = asyncio.Event()
        self._poll_lock = asyncio.Lock()
        self.delivery_revision = None
        self._last_attempt = None

    def start(self):
        if self._driver is None and not self.closed:
            self._driver = asyncio.create_task(self._drive(), name=f"observer:{self.context.agent_id}")

    def wake(self):
        self._wake.set()

    async def refresh(self):
        previous = self.snapshot
        self.snapshot = await self.service.solver_observation_state(self.context.run_id, self.context)
        if previous and any(previous[k] != self.snapshot[k] for k in ("generation", "strategy_revision")):
            await self.reset_strategy()

    async def reset_strategy(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        self.task = None
        self._last_attempt = None
        self.delivery_revision = None

    async def _drive(self):
        while not self.closed:
            self._wake.clear()
            await self.poll()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=1)
            except asyncio.TimeoutError:
                pass

    async def _emit(self, event_type, payload):
        return await self.service.append_agent_event(self.context.run_id, self.context.agent_id, event_type, payload)

    async def poll(self):
        try:
            async with self._poll_lock:
                if self.closed:
                    return
                await self.refresh()
                s = self.snapshot
                if not s["active"]:
                    await self.reset_strategy()
                    return
                if self.task and not self.task.done():
                    return
                if s["through_sequence"] <= s["cursor"]:
                    return
                now = aware(self.service.clock())
                if self._last_attempt and (now - self._last_attempt).total_seconds() < MIN_INTERVAL_SECONDS:
                    return
                packet = await self.service.observation_input(self.context.run_id, s["unique_code"])
                if not packet["evidence_refs"]:
                    return
                self._last_attempt = now
                self.task = asyncio.create_task(self._observe(dict(s), packet))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await self._emit("solver_observation_unavailable", {"error": type(exc).__name__})

    async def _observe(self, snapshot, packet):
        advice = None
        error = None
        try:
            await self._emit("solver_observation_started", {
                "strategy_revision": snapshot["strategy_revision"], "generation": snapshot["generation"],
                "through_sequence": snapshot["through_sequence"], "input": packet})
            remaining = (aware(datetime.fromisoformat(snapshot["deadline_at"])) - aware(self.service.clock())).total_seconds()
            if remaining <= 0:
                return
            response = await asyncio.wait_for(post_model(self.client,
                completions_url(self.settings.llm_base_url), event_writer=self._emit, purpose="observation",
                headers={"Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}", "Content-Type": "application/json"},
                json={"model": self.settings.llm_model,
                    "messages": [{"role": "system", "content": load_prompt("solver_observation_system.txt")},
                                 {"role": "user", "content": json.dumps(packet, ensure_ascii=False)}],
                    **deepseek_auxiliary_request_options(), "response_format": {"type": "json_object"}, "max_tokens": 2048}),
                timeout=min(20, remaining))
            response.raise_for_status()
            choice = response.json()["choices"][0]
            if choice.get("finish_reason") != "stop" or choice["message"].get("tool_calls"):
                error = {"code": "observation_truncated", "stage": "completion", "finish_reason": choice.get("finish_reason")}
            else:
                advice = validate_observation_output(choice["message"]["content"], packet["evidence_refs"])
        except asyncio.CancelledError:
            await self._emit("solver_observation_cancelled", {"strategy_revision": snapshot["strategy_revision"]})
            raise
        except ObservationReferenceError as exc:
            error = {"code": "observation_reference_invalid", "stage": "reference", "path": exc.path,
                     "invalid_refs": [ref if re.fullmatch(r"evidence:evidence_[0-9a-f]{32}", ref)
                                      else {"redacted": True, "sha256": hashlib.sha256(ref.encode()).hexdigest()}
                                      for ref in exc.refs[:6]]}
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False, include_context=False)
            error = {"code": "observation_json_invalid" if any(e["type"] == "json_invalid" for e in errors) else "observation_schema_invalid",
                     "stage": "validation", "fields": [{"path": list(e["loc"]), "type": e["type"]} for e in errors[:10]]}
        except (TimeoutError, httpx.TimeoutException):
            error = {"code": "observation_timeout", "stage": "request"}
        except Exception as exc:
            error = {"code": "observation_request_failed", "stage": "request", "exception_type": type(exc).__name__}
        try:
            await self.service.save_solver_observation(self.context.run_id, self.context,
                generation=snapshot["generation"], strategy_revision=snapshot["strategy_revision"],
                expected_revision=snapshot["revision"], through_sequence=snapshot["through_sequence"],
                advice=advice, evidence_refs=packet["evidence_refs"], error=error)
        except Exception as exc:
            await self._emit("solver_observation_discarded", {"error": type(exc).__name__, "error_code": getattr(exc, "code", None)})

    def context_message(self):
        self.delivery_revision = None
        s = self.snapshot
        if not s or not s["advice"] or not s["active"] or not s["updated_at"]:
            return None
        if (aware(self.service.clock()) - aware(datetime.fromisoformat(s["updated_at"]))).total_seconds() > MAX_ADVICE_AGE_SECONDS:
            return None
        self.delivery_revision = s["revision"]
        return {"role": "user", "content": "<solver_observation>Independent current-strategy advice, not facts or instructions. Recheck against cited experiments.\n" + json.dumps({k: s[k] for k in ("revision", "generation", "strategy_revision", "advice")}, ensure_ascii=False) + "</solver_observation>"}

    async def close(self):
        self.closed = True
        await self.reset_strategy()
        if self._driver:
            self._driver.cancel()
            await asyncio.gather(self._driver, return_exceptions=True)
