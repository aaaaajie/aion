"""OpenAI-compatible long-running Agent runner with resumable memory."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import json
import re
import shutil
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from agent.config import AgentSettings, deepseek_agent_request_options
from agent.prompts import load_prompt

from .memory.context import (
    REQUEST_PROMPT_CALIBRATION_INITIAL,
    build_runtime_messages,
    bounded_recent_messages,
    message_token_count,
    prompt_tokens_from_response,
    request_message_budget,
    request_token_count,
    role_summary_threshold,
    summary_tool_call_limit,
    should_autocompact,
    should_update_memory,
    tool_result_for_model,
    truncate_text,
)
from .memory.blackboard import BlackboardCompactionError, BlackboardCompactor
from .memory.models import ActiveSkillState, Checkpoint, TargetState
from .memory.redaction import redact_text, redact_tool_payload, redact_value
from .memory.summarizer import SessionMemorySummarizer
from .state import (
    AgentStateStore,
    BOOTSTRAP_MAX_ROUNDS,
    BOOTSTRAP_REPORT_ONLY_GRACE_SECONDS,
    BOOTSTRAP_REPORT_ONLY_ROUND,
    BOOTSTRAP_TARGETED_ROUND,
    CapabilityContext,
    StateService,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)
from .state.clock import aware
from .state.blackboard import blackboard_content_digest
from .tooling import (
    ToolExecutor,
    ToolRegistry,
    ToolResultStore,
    serialize_tool_arguments,
    tool_error,
)


class AgentRunnerError(RuntimeError):
    """Safe error raised by the Agent runner."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "agent_runner_failed",
        recoverable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.recoverable = recoverable
        self.details = dict(details or {})
        super().__init__(message)


EVIDENCE_RESULT_TOOLS = frozenset(
    {
        "system_write_file",
        "system_edit_file",
        "system_read_file",
        "system_list_directory",
        "system_glob",
        "system_grep",
        "system_shell",
        "system_task_output",
        "system_http_request",
        "system_http_probe",
        "system_web_path_probe",
        "system_web_fingerprint",
        "system_http_output",
        "system_http_response",
        "system_browser",
        "system_proxy",
        "system_network_discovery",
        "system_network_output",
        "pwn_process_open",
        "pwn_tcp_open",
        "pwn_session_io",
        "pentest_ssh_open",
        "pentest_ssh_exec",
        "pentest_ssh_transfer",
        "pentest_ssh_pivot_open",
        "pentest_channel_io",
    }
)
BOOTSTRAP_BROAD_DISCOVERY_TOOLS = frozenset(
    {
        "system_http_probe",
        "system_web_path_probe",
        "system_network_discovery",
        "skill_search",
    }
)
BOOTSTRAP_REPORT_TOOLS = frozenset(
    {
        "execution_report",
        "bootstrap_checkpoint",
        "bootstrap_cycle_yield",
        "evidence_read",
        # Recovery may finish one already-proven extraction path. Discovery
        # tools remain disabled, so this does not reopen broad exploration.
        "system_http_request",
        "system_http_response",
        "system_http_output",
    }
)
HTTP_REPLAY_TOOLS = frozenset(
    {
        "system_http_request",
        "system_http_probe",
        "system_http_response",
        "system_http_output",
        "system_web_path_probe",
        "system_web_fingerprint",
    }
)


@dataclass(frozen=True)
class AgentSessionResult:
    """Outcome of one model session without an Agent lifecycle decision."""

    run_id: str
    final: str
    last_event_sequence: int
    structured_report_seen: bool
    yield_reason: str


def default_chief_prompt() -> str:
    """Return the centrally managed prompt for a new online Run."""

    return load_prompt("chief_agent.txt")


class AgentRunner:
    """Run a single Agent task with bounded context and durable state."""

    def __init__(
        self,
        settings: AgentSettings,
        registry: ToolRegistry,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_rounds: int | None = 1_000,
        run_root: Path | None = None,
        role: str | None = None,
        agent_id: str | None = None,
        parent_id: str | None = None,
        base_system_prompt: str | None = None,
        system_context_provider: Callable[[], str] | None = None,
        live_context_provider: Callable[[], Any] | None = None,
        live_context_ack: Callable[[Mapping[str, Any]], Any] | None = None,
        bootstrap_mode: bool = False,
        require_structured_report: bool = False,
        session_timeout_seconds: float | None = None,
        state_service: StateService,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.max_rounds = (
            BOOTSTRAP_MAX_ROUNDS
            if bootstrap_mode and max_rounds is None
            else max_rounds
        )
        self.run_root = run_root or settings.run_root
        self.role = role
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.base_system_prompt = base_system_prompt
        self.system_context_provider = system_context_provider
        self.live_context_provider = live_context_provider
        self.live_context_ack = live_context_ack
        self.bootstrap_mode = bootstrap_mode
        self.require_structured_report = require_structured_report
        self._session_timeout_seconds = session_timeout_seconds
        self.state_service = state_service
        self._tool_executor = ToolExecutor(registry, max_concurrency=10)
        self._http_client = http_client
        self._owns_http_client = http_client is None
        self._summary_failures = 0
        self._summary_task: asyncio.Task[bool] | None = None
        self._structured_report_seen = False
        self._forced_report_recovery_used = False
        self._report_recovery_used = False
        self._probe_argument_failure_streak = 0
        self._probe_recovery_exhausted = False
        self._probe_recovery_notice_emitted = False
        self._probe_invalid_argument_digest: str | None = None
        self._challenge_dispatch_argument_failure_streak = 0
        self._challenge_dispatch_correction_notice_emitted = False
        self._challenge_dispatch_correction_pending = False
        self._challenge_dispatch_invalid_argument_digest: str | None = None
        self._disabled_tool_names: set[str] = set()
        self._force_context_compaction = False
        self._soft_limit_bypass_tokens: int | None = None
        self._prompt_calibration_ratio = REQUEST_PROMPT_CALIBRATION_INITIAL
        self._run_deadline_monotonic: float | None = None
        self._agent_deadline_monotonic: float | None = None
        self._unique_code: str | None = None
        self._pending_live_context: Mapping[str, Any] | None = None
        self._last_bootstrap_content_digest: str | None = None
        self._blackboard_compaction_cache: dict[str, Mapping[str, Any]] = {}
        self._current_round_number = 0
        self._bootstrap_targeted_notice_emitted = False
        self._bootstrap_report_only_notice_emitted = False
        self._http_result_cache: dict[str, dict[str, Any]] = {}
        self._last_tool_yield_reason: str | None = None
        self._checkpoint_nudge_count = 0
        self._persisted_evidence_total = 0
        self._last_checkpoint_nudge_evidence_total = 0
        self._claimed_challenge_tool_digests: dict[str, str] = {}

    async def close(self) -> None:
        if self._summary_task is not None:
            await self._wait_for_summary()
        await self.registry.close()
        if self._owns_http_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def run_session(
        self,
        prompt: str | None = None,
        *,
        store: AgentStateStore,
        resume: bool = False,
    ) -> AgentSessionResult:
        self._structured_report_seen = False
        self._forced_report_recovery_used = False
        self._report_recovery_used = False
        self._probe_argument_failure_streak = 0
        self._probe_recovery_exhausted = False
        self._probe_recovery_notice_emitted = False
        self._probe_invalid_argument_digest = None
        self._challenge_dispatch_argument_failure_streak = 0
        self._challenge_dispatch_correction_notice_emitted = False
        self._challenge_dispatch_correction_pending = False
        self._challenge_dispatch_invalid_argument_digest = None
        self._disabled_tool_names = set()
        self._force_context_compaction = False
        self._soft_limit_bypass_tokens = None
        self._prompt_calibration_ratio = REQUEST_PROMPT_CALIBRATION_INITIAL
        self._agent_deadline_monotonic = (
            asyncio.get_running_loop().time() + self._session_timeout_seconds
            if self._session_timeout_seconds is not None
            else None
        )
        self._pending_live_context = None
        self._last_bootstrap_content_digest = None
        self._blackboard_compaction_cache = {}
        self._current_round_number = 0
        self._bootstrap_targeted_notice_emitted = False
        self._bootstrap_report_only_notice_emitted = False
        self._http_result_cache = {}
        self._last_tool_yield_reason = None
        self._checkpoint_nudge_count = 0
        self._persisted_evidence_total = 0
        self._last_checkpoint_nudge_evidence_total = 0
        self._claimed_challenge_tool_digests = {}
        runtime = await self.state_service.get_agent_runtime(
            store.run_id, store.agent_id
        )
        self._unique_code = runtime["agent"].get("unique_code")
        deadline_at = runtime["run"].get("deadline_at")
        if isinstance(deadline_at, str):
            remaining = max(
                0.0,
                (
                    aware(datetime.fromisoformat(deadline_at))
                    - aware(self.state_service.clock())
                ).total_seconds(),
            )
            self._run_deadline_monotonic = (
                asyncio.get_running_loop().time() + remaining
            )
        if resume:
            if store.manifest.status == "completed":
                raise AgentRunnerError(
                    "completed runs cannot be resumed",
                    code="authoritative_state_corrupt",
                )
            prompt = prompt or store.manifest.prompt
            if not prompt:
                raise AgentRunnerError(
                    "run manifest does not contain a resumable prompt",
                    code="authoritative_state_corrupt",
                )
            await self._prepare_resume(store)
        else:
            if not prompt or not prompt.strip():
                raise AgentRunnerError(
                    "a non-empty prompt is required",
                    code="authoritative_state_corrupt",
                )
            prompt = redact_text(prompt)

        assert prompt is not None
        fixed_system_prompt = self.base_system_prompt or load_prompt("base_system.txt")
        base_system_prompt = self._compose_system_prompt(fixed_system_prompt)
        initial_user_message = {"role": "user", "content": prompt}
        memory = await store.read_memory()
        durable_events = await store.load_events() if resume else []
        tool_definitions = self.registry.definitions()
        active_tool_definitions = tool_definitions
        context_budget = self.settings.context_budget
        profile = context_budget.profile(self.role)
        absolute_prompt_tokens = context_budget.absolute_prompt_tokens(
            self.role, bootstrap=self.bootstrap_mode
        )
        soft_prompt_tokens = min(
            profile.soft_prompt_tokens, absolute_prompt_tokens
        )
        message_budget = request_message_budget(
            context_budget=context_budget,
            tool_definitions=tool_definitions,
            role=self.role,
            bootstrap=self.bootstrap_mode,
            calibration_ratio=self._prompt_calibration_ratio,
        )
        messages = build_runtime_messages(
            base_system_prompt=base_system_prompt,
            initial_user_message=initial_user_message,
            checkpoint=store.model_checkpoint(),
            session_memory=memory,
            recent_messages=self._recovered_event_context(
                durable_events,
                after_sequence=store.checkpoint.last_summarized_event_sequence,
            ),
            max_tokens=message_budget,
            recent_message_tokens=profile.recent_message_tokens,
        )
        current_tokens = int(
            request_token_count(messages, tool_definitions)
            * self._prompt_calibration_ratio
            * 1.05
        )
        last_summary_tokens = current_tokens if resume else 0
        tool_calls_since_summary = 0
        final_content = ""
        yield_reason = "model_return"

        try:
            async with self._main_client() as client:
                round_number = 0
                while self.max_rounds is None or round_number < self.max_rounds:
                    round_number += 1
                    self._current_round_number = round_number
                    await self._apply_bootstrap_phase(
                        store, messages, round_number
                    )
                    await self._activate_deadline_report_recovery_if_needed(
                        store, messages, round_number
                    )
                    active_tool_definitions = self._active_tool_definitions(
                        tool_definitions
                    )
                    if self.bootstrap_mode and self.live_context_provider is not None:
                        try:
                            update = self.live_context_provider()
                            if inspect.isawaitable(update):
                                update = await update
                            if isinstance(update, Mapping):
                                raw_update = update
                                through = raw_update.get("through_sequence")
                                digest = raw_update.get("content_digest")
                                if not isinstance(digest, str) or not digest:
                                    digest = blackboard_content_digest(raw_update)
                                compacted_update = await self._maybe_compact_bootstrap_update(
                                    raw_update, store=store
                                )
                                already_injected = (
                                    digest == self._last_bootstrap_content_digest
                                )
                                if not already_injected or not raw_update.get("replayed"):
                                    self._replace_live_context_message(
                                        messages, compacted_update
                                    )
                                if not already_injected:
                                    content_chars = len(
                                        json.dumps(
                                            dict(compacted_update),
                                            ensure_ascii=False,
                                            default=str,
                                        )
                                    )
                                    await store.append_event(
                                        "bootstrap_shared_snapshot_injected",
                                        {
                                            "through_sequence": through,
                                            "report_count": len(
                                                raw_update.get("reports") or []
                                            ),
                                            "replayed": bool(raw_update.get("replayed")),
                                            "content_digest": digest,
                                            "content_chars": content_chars,
                                        },
                                    )
                                if update.get("replayed"):
                                    if not already_injected:
                                        await store.append_event(
                                            "bootstrap_shared_snapshot_replayed",
                                            {
                                                "through_sequence": through,
                                                "content_digest": digest,
                                            },
                                        )
                                if isinstance(store.checkpoint.authoritative_view, dict):
                                    store.checkpoint.authoritative_view[
                                        "bootstrap_shared"
                                    ] = {
                                        "through_sequence": through,
                                        "report_count": len(
                                            raw_update.get("reports") or []
                                        ),
                                        "hint_count": len(raw_update.get("hints") or []),
                                        "content_digest": digest,
                                    }
                                    await store.save_checkpoint()
                                self._last_bootstrap_content_digest = digest
                                self._pending_live_context = compacted_update
                        except Exception as exc:
                            await store.append_event(
                                "bootstrap_shared_snapshot_failed",
                                {"error_type": type(exc).__name__},
                            )
                    message_budget = request_message_budget(
                        context_budget=context_budget,
                        tool_definitions=active_tool_definitions,
                        role=self.role,
                        bootstrap=self.bootstrap_mode,
                        calibration_ratio=self._prompt_calibration_ratio,
                    )
                    estimated_before_request = request_token_count(
                        messages, active_tool_definitions
                    )
                    calibrated_estimate = int(
                        estimated_before_request
                        * self._prompt_calibration_ratio
                        * 1.05
                    )
                    await store.append_event(
                        "context_budget_preflight",
                        {
                            "role": self.role,
                            "round": round_number,
                            "estimated_prompt_tokens": estimated_before_request,
                            "calibrated_prompt_tokens": calibrated_estimate,
                            "soft_target_tokens": soft_prompt_tokens,
                            "absolute_limit_tokens": absolute_prompt_tokens,
                            "calibration_ratio": self._prompt_calibration_ratio,
                            "action": (
                                "compact"
                                if self._force_context_compaction
                                or (
                                    calibrated_estimate > soft_prompt_tokens
                                    and (
                                        self._soft_limit_bypass_tokens is None
                                        or calibrated_estimate
                                        > self._soft_limit_bypass_tokens
                                        + max(8_000, soft_prompt_tokens // 10)
                                    )
                                )
                                else "send_over_soft"
                                if calibrated_estimate > soft_prompt_tokens
                                else "send"
                            ),
                        },
                    )
                    over_soft_requires_compaction = (
                        calibrated_estimate > soft_prompt_tokens
                        and (
                            self._soft_limit_bypass_tokens is None
                            or calibrated_estimate
                            > self._soft_limit_bypass_tokens
                            + max(8_000, soft_prompt_tokens // 10)
                        )
                    )
                    if (
                        self._force_context_compaction
                        or over_soft_requires_compaction
                    ):
                        compacted_recent = await self._compact(
                            store,
                            base_system_prompt=fixed_system_prompt,
                            initial_user_message=initial_user_message,
                            messages=messages,
                            max_tokens=message_budget,
                            recent_message_tokens=profile.recent_message_tokens,
                            allow_model_summary=self.role != "execution",
                        )
                        if compacted_recent is None:
                            raise AgentRunnerError(
                                "Agent context could not be rebuilt below the model limit",
                                code="context_capacity_deferred",
                                recoverable=self.role in {"chief", "challenge"},
                                details={
                                    "role": self.role,
                                    "soft_target_tokens": soft_prompt_tokens,
                                    "absolute_limit_tokens": absolute_prompt_tokens,
                                },
                            )
                        memory = await store.read_memory()
                        messages = build_runtime_messages(
                            base_system_prompt=self._compose_system_prompt(
                                fixed_system_prompt
                            ),
                            initial_user_message=initial_user_message,
                            checkpoint=store.model_checkpoint(),
                            session_memory=memory,
                            recent_messages=compacted_recent,
                            max_tokens=message_budget,
                            recent_message_tokens=profile.recent_message_tokens,
                        )
                        if self.bootstrap_mode and self._pending_live_context:
                            self._replace_live_context_message(
                                messages, self._pending_live_context
                            )
                        estimated_before_request = request_token_count(
                            messages, active_tool_definitions
                        )
                        calibrated_estimate = int(
                            estimated_before_request
                            * self._prompt_calibration_ratio
                            * 1.05
                        )
                        current_tokens = calibrated_estimate
                        last_summary_tokens = current_tokens
                        tool_calls_since_summary = 0
                        self._force_context_compaction = False
                        if calibrated_estimate > soft_prompt_tokens:
                            self._soft_limit_bypass_tokens = calibrated_estimate
                            await store.append_event(
                                "context_soft_limit_exceeded",
                                {
                                    "role": self.role,
                                    "round": round_number,
                                    "estimated_prompt_tokens": estimated_before_request,
                                    "calibrated_prompt_tokens": calibrated_estimate,
                                    "soft_target_tokens": soft_prompt_tokens,
                                    "absolute_limit_tokens": absolute_prompt_tokens,
                                    "action": (
                                        "send_over_soft"
                                        if calibrated_estimate <= absolute_prompt_tokens
                                        else "defer"
                                    ),
                                },
                            )
                        else:
                            self._soft_limit_bypass_tokens = None
                    if calibrated_estimate > absolute_prompt_tokens:
                        await store.append_event(
                            "context_capacity_deferred",
                            {
                                "role": self.role,
                                "round": round_number,
                                "estimated_prompt_tokens": estimated_before_request,
                                "calibrated_prompt_tokens": calibrated_estimate,
                                "soft_target_tokens": soft_prompt_tokens,
                                "absolute_limit_tokens": absolute_prompt_tokens,
                                "action": "defer",
                            },
                        )
                        raise AgentRunnerError(
                            "Agent request exceeds the model context capacity",
                            code="context_capacity_deferred",
                            recoverable=self.role in {"chief", "challenge"},
                            details={
                                "role": self.role,
                                "estimated_prompt_tokens": estimated_before_request,
                                "calibrated_prompt_tokens": calibrated_estimate,
                                "soft_target_tokens": soft_prompt_tokens,
                                "absolute_limit_tokens": absolute_prompt_tokens,
                            },
                        )
                    request = self._request_completion(
                        client,
                        messages,
                        tool_definitions=active_tool_definitions,
                        report_recovery=self._report_recovery_used,
                    )
                    payload = await request
                    if self.bootstrap_mode and isinstance(
                        getattr(self, "_pending_live_context", None), Mapping
                    ):
                        try:
                            if self.live_context_ack is not None:
                                ack = self.live_context_ack(self._pending_live_context)
                                if inspect.isawaitable(ack):
                                    await ack
                            self._pending_live_context = None
                        except Exception as exc:
                            await store.append_event(
                                "bootstrap_shared_snapshot_ack_failed",
                                {"error_type": type(exc).__name__},
                            )
                    usage_tokens = prompt_tokens_from_response(payload)
                    if usage_tokens is not None:
                        observed_ratio = usage_tokens / max(1, estimated_before_request)
                        self._prompt_calibration_ratio = min(
                            2.0,
                            max(self._prompt_calibration_ratio, observed_ratio),
                        )
                        if usage_tokens > soft_prompt_tokens:
                            await store.append_event(
                                "context_budget_actual_over_target",
                                {
                                    "role": self.role,
                                    "round": round_number,
                                    "prompt_tokens": usage_tokens,
                                    "soft_target_tokens": soft_prompt_tokens,
                                    "absolute_limit_tokens": absolute_prompt_tokens,
                                    "calibration_ratio": self._prompt_calibration_ratio,
                                    "action": "observe_over_soft",
                                },
                            )
                        if usage_tokens > absolute_prompt_tokens:
                            await store.append_event(
                                "context_budget_actual_over_limit",
                                {
                                    "role": self.role,
                                    "round": round_number,
                                    "prompt_tokens": usage_tokens,
                                    "absolute_limit_tokens": absolute_prompt_tokens,
                                    "action": "compact_next_round",
                                },
                            )
                            self._force_context_compaction = True
                    current_tokens = max(
                        usage_tokens or 0,
                        message_token_count(messages),
                    )
                    choice = self._response_choice(payload)
                    finish_reason = choice.get("finish_reason")
                    if finish_reason == "insufficient_system_resource":
                        await store.append_event(
                            "llm_response_rejected",
                            {
                                "round": round_number,
                                "reason": "insufficient_system_resource",
                                "recoverable": True,
                            },
                        )
                        raise AgentRunnerError(
                            "DeepSeek could not allocate sufficient inference resources",
                            code="llm_temporarily_unavailable",
                            recoverable=self.role in {"chief", "challenge"},
                            details={"finish_reason": finish_reason},
                        )
                    if finish_reason == "length":
                        await store.append_event(
                            "llm_response_rejected",
                            {
                                "round": round_number,
                                "reason": "length",
                                "recoverable": (
                                    self.role in {"chief", "challenge"}
                                    or self.require_structured_report
                                ),
                            },
                        )
                        if self.require_structured_report and not self._report_recovery_used:
                            self._report_recovery_used = True
                            active_tool_definitions = self._report_only_definitions(
                                tool_definitions
                            )
                            self._force_context_compaction = True
                            messages.append(
                                {
                                    "role": "user",
                                    "content": (
                                        "The previous response was truncated. Preserve the work already completed, "
                                        "do not call any other tool, and call execution_report now with the "
                                        "required structured terminal result."
                                    ),
                                }
                            )
                            await store.append_event(
                                "llm_length_report_recovery",
                                {"round": round_number, "attempt": 1},
                            )
                            continue
                        raise AgentRunnerError(
                            "DeepSeek completion reached its output limit",
                            code="llm_completion_truncated",
                            recoverable=self.role in {"chief", "challenge"},
                            details={"finish_reason": finish_reason},
                        )
                    message = choice["message"]
                    tool_calls = message.get("tool_calls") or []
                    if tool_calls and self._requires_reasoning_content():
                        reasoning_content = message.get("reasoning_content")
                        if not isinstance(reasoning_content, str):
                            await store.append_event(
                                "llm_reasoning_missing",
                                {
                                    "round": round_number,
                                    "tool_count": len(tool_calls),
                                },
                            )
                            raise AgentRunnerError(
                                "DeepSeek Tool Call response omitted reasoning_content",
                                code="invalid_llm_response",
                                details={
                                    "reason": "reasoning_content_required_for_tool_calls",
                                    "tool_count": len(tool_calls),
                                },
                            )
                    assistant_message: dict[str, Any] = {
                        "role": "assistant",
                        "content": (
                            ""
                            if tool_calls and message.get("content") is None
                            else message.get("content")
                        ),
                    }
                    if isinstance(message.get("reasoning_content"), str):
                        assistant_message["reasoning_content"] = message[
                            "reasoning_content"
                        ]
                    if tool_calls:
                        assistant_message["tool_calls"] = tool_calls
                    messages.append(assistant_message)
                    usage = payload.get("usage")
                    usage_map = usage if isinstance(usage, Mapping) else {}
                    completion_details = usage_map.get("completion_tokens_details")
                    completion_details = (
                        completion_details
                        if isinstance(completion_details, Mapping)
                        else {}
                    )
                    reasoning_content_value = message.get("reasoning_content")
                    await store.append_event(
                        "assistant_response",
                        {
                            "round": round_number,
                            "content": truncate_text(
                                redact_text(str(message.get("content") or "")),
                                4_000,
                            ),
                            "tool_names": self._tool_names(tool_calls),
                            "prompt_tokens": usage_tokens,
                            "latency_ms": payload.get("_aion_latency_ms"),
                            "attempts": payload.get("_aion_attempts", 1),
                            "retry_delay_ms": payload.get("_aion_retry_delay_ms", 0),
                            "http_status": payload.get("_aion_http_status"),
                            "finish_reason": finish_reason,
                            "completion_tokens": usage_map.get("completion_tokens"),
                            "reasoning_tokens": completion_details.get(
                                "reasoning_tokens"
                            ),
                            "reasoning_present": isinstance(
                                reasoning_content_value, str
                            ),
                            "reasoning_chars": (
                                len(reasoning_content_value)
                                if isinstance(reasoning_content_value, str)
                                else 0
                            ),
                            "prompt_cache_hit_tokens": usage_map.get(
                                "prompt_cache_hit_tokens"
                            ),
                            "prompt_cache_miss_tokens": usage_map.get(
                                "prompt_cache_miss_tokens"
                            ),
                        },
                    )

                    if not tool_calls:
                        if self.require_structured_report and not self._structured_report_seen:
                            if not str(message.get("content") or "").strip() and not self._forced_report_recovery_used:
                                self._forced_report_recovery_used = True
                                # Treat an empty response as a recovery
                                # boundary even when the provider omitted
                                # usage. The next request must micro-compact
                                # before receiving the recovery instruction.
                                self._force_context_compaction = True
                                messages.append(
                                    {
                                        "role": "user",
                                        "content": (
                                            "The previous model response was empty. "
                                            "Call execution_report now with the required structured result."
                                        ),
                                    }
                                )
                                await store.append_event(
                                    "llm_empty_report_recovery",
                                    {"round": round_number, "attempt": 1},
                                )
                                continue
                            if not str(message.get("content") or "").strip():
                                raise AgentRunnerError(
                                    "invalid_llm_response: model returned a second empty response while a structured report was required",
                                    code="invalid_llm_response",
                                    details={"recovery_attempted": True},
                                )
                            raise AgentRunnerError(
                                "execution Agent ended without a structured report",
                                code="missing_structured_report",
                            )
                        final_content = str(message.get("content") or "")
                        break

                    tool_messages, yield_session = await self._execute_tool_calls(
                        store, tool_calls, round_number=round_number
                    )
                    tool_yield_reason = self._last_tool_yield_reason
                    messages.extend(tool_messages)
                    if self._probe_recovery_exhausted:
                        self._disabled_tool_names.add("system_http_probe")
                        active_tool_definitions = self._active_tool_definitions(
                            tool_definitions
                        )
                        if not self._probe_recovery_notice_emitted:
                            self._probe_recovery_notice_emitted = True
                            messages.append(
                                {
                                    "role": "user",
                                    "content": (
                                        "system_http_probe is disabled for this session after repeated invalid "
                                        "arguments. Continue with system_http_request or other available tools; "
                                        "submit execution_report only when the task is actually complete or blocked."
                                    ),
                                }
                            )
                            await store.append_event(
                                "probe_argument_recovery_exhausted",
                                {"round": round_number, "tool": "system_http_probe"},
                            )
                    if (
                        self._challenge_dispatch_correction_pending
                        and not self._challenge_dispatch_correction_notice_emitted
                    ):
                        self._challenge_dispatch_correction_pending = False
                        self._challenge_dispatch_correction_notice_emitted = True
                        messages.append(
                            {
                                "role": "user",
                                "content": (
                                    "challenge_dispatch needs a canonical argument object. Use {} for a "
                                    "deterministic checkpoint follow-up or provide only the documented "
                                    "top-level fields; do not hand-write stable task, hypothesis, or branch keys."
                                ),
                            }
                        )
                        await store.append_event(
                            "challenge_dispatch_argument_correction",
                            {"round": round_number, "tool": "challenge_dispatch"},
                        )
                    tool_calls_since_summary += len(tool_calls)
                    current_tokens = int(
                        request_token_count(messages, active_tool_definitions)
                        * self._prompt_calibration_ratio
                        * 1.05
                    )
                    if should_update_memory(
                        current_tokens=current_tokens,
                        last_summary_tokens=last_summary_tokens,
                        tool_calls_since_summary=tool_calls_since_summary,
                        threshold_tokens=min(
                            role_summary_threshold(profile),
                            absolute_prompt_tokens,
                        ),
                        tool_call_limit=summary_tool_call_limit(self.role),
                    ):
                        if self.role == "execution":
                            # Short-lived workers get deterministic compaction only.
                            # A second model request for memory maintenance was both
                            # slower than the work and almost always timed out online.
                            self._force_context_compaction = True
                        else:
                            self._schedule_summary(
                                store,
                                messages,
                                last_summary_tokens=current_tokens,
                            )
                        last_summary_tokens = current_tokens
                        tool_calls_since_summary = 0

                    if yield_session:
                        yield_reason = tool_yield_reason or "controller_wait"
                        break

                    over_soft_requires_compaction = (
                        should_autocompact(
                            current_tokens,
                            soft_prompt_tokens=soft_prompt_tokens,
                        )
                        and (
                            self._soft_limit_bypass_tokens is None
                            or current_tokens
                            > self._soft_limit_bypass_tokens
                            + max(8_000, soft_prompt_tokens // 10)
                        )
                    )
                    if over_soft_requires_compaction:
                        compacted_recent = await self._compact(
                            store,
                            base_system_prompt=fixed_system_prompt,
                            initial_user_message=initial_user_message,
                            messages=messages,
                            max_tokens=message_budget,
                            recent_message_tokens=profile.recent_message_tokens,
                            allow_model_summary=self.role != "execution",
                        )
                        if compacted_recent is None:
                            raise AgentRunnerError(
                                "Agent context could not be rebuilt below the model limit",
                                code="context_capacity_deferred",
                                recoverable=self.role in {"chief", "challenge"},
                            )
                        memory = await store.read_memory()
                        messages = build_runtime_messages(
                            base_system_prompt=self._compose_system_prompt(
                                fixed_system_prompt
                            ),
                            initial_user_message=initial_user_message,
                            checkpoint=store.model_checkpoint(),
                            session_memory=memory,
                            recent_messages=compacted_recent,
                            max_tokens=message_budget,
                            recent_message_tokens=profile.recent_message_tokens,
                        )
                        if self.bootstrap_mode and self._pending_live_context:
                            self._replace_live_context_message(
                                messages, self._pending_live_context
                            )
                        current_tokens = int(
                            request_token_count(messages, active_tool_definitions)
                            * self._prompt_calibration_ratio
                            * 1.05
                        )
                        self._soft_limit_bypass_tokens = (
                            current_tokens
                            if current_tokens > soft_prompt_tokens
                            else None
                        )
                        last_summary_tokens = current_tokens
                        tool_calls_since_summary = 0

                else:
                    if self.bootstrap_mode:
                        await store.append_event(
                            "bootstrap_cycle_round_limit",
                            {"round": round_number, "max_rounds": self.max_rounds},
                        )
                        await self.state_service.yield_bootstrap_cycle(
                            store.run_id,
                            store.agent_id,
                            CapabilityContext(
                                run_id=store.run_id,
                                agent_id=store.agent_id,
                                role="execution",
                                unique_code=self._unique_code,
                            ),
                            summary="Bootstrap cycle reached its round budget; resume the same lane with persisted context.",
                        )
                        yield_reason = "bootstrap_cycle_yield"
                        final_content = ""
                        # The supervisor resumes this same logical lane with a
                        # fresh bounded session and the persisted memory/context.
                        pass
                    else:
                        raise AgentRunnerError(
                            "maximum Agent rounds exceeded",
                            code="invalid_llm_response",
                            recoverable=self.role in {"chief", "challenge"},
                        )

            final = truncate_text(redact_text(final_content), 8_000)
            await store.append_event(
                "agent_session_yielded",
                {
                    "final": final,
                    "structured_report_seen": self._structured_report_seen,
                    "yield_reason": yield_reason,
                },
            )
            return AgentSessionResult(
                run_id=store.manifest.run_id,
                final=final,
                last_event_sequence=store.checkpoint.last_event_sequence,
                structured_report_seen=self._structured_report_seen,
                yield_reason=yield_reason,
            )
        except Exception as exc:
            if self.bootstrap_mode and isinstance(exc, AgentRunnerError) and exc.code == "bootstrap_cycle_yield":
                await self.state_service.yield_bootstrap_cycle(
                    store.run_id,
                    store.agent_id,
                    CapabilityContext(
                        run_id=store.run_id,
                        agent_id=store.agent_id,
                        role="execution",
                        unique_code=self._unique_code,
                    ),
                    summary="Bootstrap cycle reached its time budget; resume the same lane with persisted context.",
                )
                final = ""
                await store.append_event(
                    "agent_session_yielded",
                    {
                        "final": final,
                        "structured_report_seen": False,
                        "yield_reason": "bootstrap_cycle_yield",
                    },
                )
                return AgentSessionResult(
                    run_id=store.manifest.run_id,
                    final=final,
                    last_event_sequence=store.checkpoint.last_event_sequence,
                    structured_report_seen=False,
                    yield_reason="bootstrap_cycle_yield",
                )
            safe_message = self._safe_error_message(exc)
            failure = {"message": safe_message}
            if isinstance(exc, AgentRunnerError):
                failure["code"] = exc.code
                failure["recoverable"] = exc.recoverable
                failure.update(exc.details)
            await store.append_event("agent_session_failed", failure)
            raise
        finally:
            await self._wait_for_summary()

    async def _prepare_resume(self, store: Any) -> None:
        store.checkpoint.active_tool_calls = []
        await store.save_checkpoint()
        if self.registry.has_tool("benchmark_list_challenges"):
            prepared = await self._tool_executor.execute(
                [{"id": "resume-state-sync", "function": {"name": "benchmark_list_challenges", "arguments": "{}"}}]
            )
            result = prepared[0].result or {"ok": False}
            await self._apply_tool_state(store, "benchmark_list_challenges", result)
            await store.append_event(
                "resume_state_sync",
                {"ok": result.get("ok"), "error_code": self._error_code(result)},
            )
            await store.save_checkpoint()

    async def _execute_tool_calls(
        self,
        store: AgentStateStore,
        tool_calls: Sequence[Mapping[str, Any]],
        *,
        round_number: int | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        prepared = self._tool_executor.prepare(tool_calls)
        self._apply_probe_recovery_budget(prepared)
        self._apply_challenge_dispatch_recovery_budget(prepared)
        self._apply_http_replay_cache(prepared)
        await self._apply_challenge_expensive_tool_dedup(prepared, run_id=store.run_id)
        result_store = ToolResultStore(store.run_dir, store.agent_id)
        call_events: list[dict[str, Any]] = []
        for item in prepared:
            arguments: Any = {
                "unparsed": True,
                "raw_length": item.raw_arguments_length,
            }
            if item.arguments is not None:
                compact_arguments = item.name.startswith("system_http_") or item.name in {
                    "system_web_path_probe",
                    "system_web_fingerprint",
                }
                arguments = redact_tool_payload(
                    item.name,
                    serialize_tool_arguments(
                        item.arguments,
                        exclude_unset=compact_arguments,
                        exclude_none=compact_arguments,
                    ),
                    secrets=self._secrets(),
                )
                arguments = self._redact_candidate_arguments_for_event(
                    item.name, arguments
                )
            call_events.append(
                {
                    "event_type": "tool_call",
                    "payload": {
                        "tool_call_id": item.tool_call_id,
                        "tool_name": item.name,
                        "stage": "validated" if item.arguments is not None else "rejected",
                        "concurrency_wave": item.concurrency_wave,
                        "round": round_number,
                        "arguments": arguments,
                    },
                }
            )
        await store.append_events(call_events)
        prepared = await self._tool_executor.execute_prepared(prepared)
        await self._complete_challenge_expensive_tool_dedup(prepared, run_id=store.run_id)
        tool_messages: list[dict[str, Any]] = []
        result_events: list[dict[str, Any]] = []
        yield_session = False
        yield_reason: str | None = None
        evidence_persisted = 0
        checkpoint_called = any(
            item.name == "execution_checkpoint" for item in prepared
        )
        checkpoint_succeeded = False
        for item in prepared:
            result = item.result or {
                "ok": False,
                "error": {"stage": "internal", "code": "missing_result", "message": "Tool did not return a result", "retry": {"allowed": False, "action": "none", "tool": None, "same_arguments": False}, "details": {}},
            }
            if item.name == "execution_report" and result.get("ok"):
                data = result.get("data")
                self._structured_report_seen = self._structured_report_seen or bool(
                    isinstance(data, Mapping) and data.get("terminal")
                )
            if item.name == "execution_checkpoint" and result.get("ok"):
                checkpoint_succeeded = True
            internal_evidence = item.evidence_payload
            result_for_model = dict(result)
            safe_result = redact_tool_payload(
                item.name, result_for_model, secrets=self._secrets()
            )
            if (
                self.role == "execution"
                and item.name in EVIDENCE_RESULT_TOOLS
                and safe_result.get("ok") is True
                and self.agent_id is not None
                and not item.replayed
            ):
                try:
                    evidence_content = (
                        internal_evidence.get("content")
                        if isinstance(internal_evidence, Mapping)
                        and isinstance(internal_evidence.get("content"), str)
                        else json.dumps(
                            result_for_model,
                            ensure_ascii=False,
                            default=str,
                            separators=(",", ":"),
                        )
                    )
                    raw_data = result_for_model.get("data")
                    if (
                        item.name == "system_http_response"
                        and isinstance(raw_data, Mapping)
                        and isinstance(raw_data.get("content"), str)
                    ):
                        evidence_content = raw_data["content"]
                    evidence_type = (
                        str(internal_evidence.get("evidence_type"))
                        if isinstance(internal_evidence, Mapping)
                        and internal_evidence.get("evidence_type")
                        else self._evidence_type(item.name)
                    )
                    evidence_metadata = {
                        "tool_call_id": item.tool_call_id,
                        **(
                            dict(internal_evidence.get("metadata") or {})
                            if isinstance(internal_evidence, Mapping)
                            and isinstance(
                                internal_evidence.get("metadata"), Mapping
                            )
                            else {}
                        ),
                    }
                    if isinstance(raw_data, Mapping):
                        for metadata_key in (
                            "interaction_id",
                            "request_id",
                            "method",
                            "status",
                            "body_sha256",
                        ):
                            metadata_value = raw_data.get(metadata_key)
                            if isinstance(metadata_value, (str, int, float, bool)):
                                evidence_metadata[metadata_key] = metadata_value
                    evidence = await self.state_service.persist_evidence(
                        store.run_id,
                        CapabilityContext(
                            run_id=store.run_id,
                            agent_id=self.agent_id,
                            role="execution",
                            unique_code=self._unique_code,
                        ),
                        evidence_type=evidence_type,
                        source=item.name,
                        content=evidence_content,
                        metadata=evidence_metadata,
                    )
                    evidence_persisted += 1
                    data = safe_result.get("data")
                    if isinstance(data, Mapping):
                        safe_result = {
                            **safe_result,
                            "data": {
                                **dict(data),
                                "evidence_refs": [evidence["evidence_ref"]],
                            },
                        }
                    else:
                        safe_result = {
                            **safe_result,
                            "evidence_refs": [evidence["evidence_ref"]],
                        }
                except Exception:
                    warnings = list(safe_result.get("warnings") or [])
                    warnings.append(
                        {
                            "code": "evidence_persist_failed",
                            "message": "Tool succeeded but its Evidence snapshot could not be persisted",
                            "details": {},
                        }
                    )
                    safe_result = {**safe_result, "warnings": warnings}
            if (
                item.name in HTTP_REPLAY_TOOLS
                and not item.replayed
                and safe_result.get("ok") is True
            ):
                cache_key = self._http_replay_key(item)
                if cache_key is not None:
                    encoded = json.dumps(
                        safe_result,
                        ensure_ascii=False,
                        default=str,
                        separators=(",", ":"),
                    )
                    if len(encoded) <= 50_000:
                        self._http_result_cache[cache_key] = json.loads(encoded)
            safe_projection = (
                redact_tool_payload(
                    item.name, item.result_projection, secrets=self._secrets()
                )
                if item.result_projection is not None
                else None
            )
            model_result, result_ref, result_chars = self._project_model_result(
                item.name, safe_result, result_store, safe_projection
            )
            error = model_result.get("error") if isinstance(model_result, Mapping) else None
            event_result = self._compact_skill_result(item.name, model_result)
            result_events.append(
                {
                    "event_type": "tool_result",
                    "payload": {
                        "tool_call_id": item.tool_call_id,
                        "tool_name": item.name,
                        "result": event_result,
                        "queue_latency_ms": item.queue_latency_ms,
                        "execution_latency_ms": item.execution_latency_ms,
                        "total_latency_ms": item.total_latency_ms,
                        "concurrency_wave": item.concurrency_wave,
                        "round": round_number,
                        "result_chars": result_chars,
                        "result_ref": result_ref,
                        "result_persisted": result_ref is not None,
                        "error_stage": (
                            error.get("stage") if isinstance(error, Mapping) else None
                        ),
                        "error_code": (
                            error.get("code") if isinstance(error, Mapping) else None
                        ),
                        "replayed": bool(item.replayed),
                    },
                },
            )
            await self._apply_tool_state(store, item.name, result)
            tool_messages.append(
                self._tool_message(tool_calls[item.index], model_result)
            )
            yield_session = yield_session or item.yield_session
            if (
                item.yield_session
                and isinstance(result.get("data"), Mapping)
                and result["data"].get("cycle_yield")
            ):
                yield_reason = "bootstrap_cycle_yield"
            elif (
                item.yield_session
                and isinstance(result.get("data"), Mapping)
                and result["data"].get("handoff_terminal")
            ):
                yield_reason = "execution_checkpoint_handoff"
        # Models sometimes continue broad probing after a useful response even
        # though the Execution contract requires an immediate checkpoint.  A
        # bounded, content-free nudge makes the handoff decision explicit while
        # leaving value classification to the model and preserving Evidence
        # isolation.  Cap it per session so routine recon does not dominate the
        # context or create artificial turns.
        self._persisted_evidence_total += evidence_persisted
        if checkpoint_succeeded:
            self._checkpoint_nudge_count = 0
            self._last_checkpoint_nudge_evidence_total = (
                self._persisted_evidence_total
            )
        new_evidence_frontier = self._persisted_evidence_total
        if (
            self.role == "execution"
            and not self.bootstrap_mode
            and evidence_persisted
            and not checkpoint_called
            and new_evidence_frontier > self._last_checkpoint_nudge_evidence_total
            and self._checkpoint_nudge_count < 2
        ):
            self._checkpoint_nudge_count += 1
            self._last_checkpoint_nudge_evidence_total = new_evidence_frontier
            tool_messages.append(
                {
                    "role": "user",
                    "content": (
                        "Runtime checkpoint review: the preceding technical action produced "
                        "persisted Evidence. If it verifies a vulnerability, credential, "
                        "privilege, attack path, or concrete extraction route, call "
                        "execution_checkpoint now with its Evidence reference before any "
                        "further broad exploration; otherwise continue with one narrow "
                        "discriminating action."
                    ),
                }
            )
            await store.append_event(
                "execution_checkpoint_nudge",
                {"round": round_number, "evidence_count": evidence_persisted},
            )
        await store.append_events(result_events)
        await store.save_checkpoint()
        self._last_tool_yield_reason = yield_reason
        return tool_messages, yield_session

    async def _apply_bootstrap_phase(
        self,
        store: AgentStateStore,
        messages: list[dict[str, Any]],
        round_number: int,
    ) -> None:
        """Turn Bootstrap's flag-first contract into runtime-enforced phases."""

        if not self.bootstrap_mode:
            return
        if (
            round_number >= BOOTSTRAP_TARGETED_ROUND
            and not self._bootstrap_targeted_notice_emitted
        ):
            self._bootstrap_targeted_notice_emitted = True
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Bootstrap is entering targeted exploitation. Broad discovery tools "
                        "are now disabled. Use the strongest Evidence and the narrowest "
                        "Flag-producing request; call bootstrap_checkpoint or execution_report."
                    ),
                }
            )
            await store.append_event(
                "bootstrap_targeted_phase_started",
                {"round": round_number, "tool_count_reduced": True},
            )
        if (
            round_number >= BOOTSTRAP_REPORT_ONLY_ROUND
            and not self._bootstrap_report_only_notice_emitted
        ):
            self._bootstrap_report_only_notice_emitted = True
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Bootstrap cycle budget is nearly exhausted. Finish the current narrow route "
                        "if it can produce an exact candidate; otherwise call bootstrap_cycle_yield "
                        "with a concise progress summary. Do not submit a meaningless terminal blocked "
                        "report or start broad reconnaissance."
                    ),
                }
            )
            await store.append_event(
                "bootstrap_report_only_phase_started",
                {"round": round_number, "report_round": BOOTSTRAP_REPORT_ONLY_ROUND},
            )

    def _apply_http_replay_cache(self, prepared: Sequence[Any]) -> None:
        """Replay exact successful HTTP calls instead of paying for another request."""

        for item in prepared:
            if item.result is not None or item.name not in HTTP_REPLAY_TOOLS:
                continue
            cache_key = self._http_replay_key(item)
            if cache_key is None:
                continue
            cached = self._http_result_cache.get(cache_key)
            if cached is None:
                continue
            item.result = json.loads(
                json.dumps(cached, ensure_ascii=False, default=str)
            )
            item.replayed = True

    async def _apply_challenge_expensive_tool_dedup(
        self, prepared: Sequence[Any], *, run_id: str
    ) -> None:
        """Guard cross-Agent repeats of successful high-cost tool calls."""

        if self.role != "execution" or not self._unique_code:
            return
        for item in prepared:
            if item.name != "pentest_sqlmap" or item.arguments is None or item.result is not None:
                continue
            try:
                encoded = json.dumps(
                    {
                        "tool": item.name,
                        "arguments": serialize_tool_arguments(
                            item.arguments, exclude_none=True
                        ),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                    separators=(",", ":"),
                )
            except (TypeError, ValueError):
                continue
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            try:
                decision = await self.state_service.claim_challenge_tool_fingerprint(
                    run_id,
                    self._unique_code,
                    self.agent_id or "",
                    tool_name=item.name,
                    digest=digest,
                )
            except Exception:
                # Deduplication is an optimization.  A transient state-store
                # failure must not prevent the assigned technical action.
                continue
            if decision.get("duplicate"):
                item.result = tool_error(
                    "execution",
                    "duplicate_expensive_request",
                    "An identical SQLMap request already succeeded or is running; consume the shared Evidence instead of repeating it.",
                    retry_allowed=False,
                    retry_action="none",
                    retry_tool=None,
                    details={"tool": item.name, "reason": decision.get("reason")},
                )
                continue
            if decision.get("claimed"):
                self._claimed_challenge_tool_digests[item.tool_call_id] = digest

    async def _complete_challenge_expensive_tool_dedup(
        self, prepared: Sequence[Any], *, run_id: str
    ) -> None:
        if self.role != "execution" or not self._unique_code:
            return
        for item in prepared:
            digest = self._claimed_challenge_tool_digests.pop(item.tool_call_id, None)
            if digest is None:
                continue
            try:
                await self.state_service.complete_challenge_tool_fingerprint(
                    run_id,
                    self._unique_code,
                    self.agent_id or "",
                    tool_name=item.name,
                    digest=digest,
                    success=bool(
                        isinstance(item.result, Mapping)
                        and item.result.get("ok") is True
                    ),
                )
            except Exception:
                # The durable attempt marker is best effort and contains no
                # payload; never turn tool completion into an Agent failure.
                continue

    @staticmethod
    def _http_replay_key(item: Any) -> str | None:
        if getattr(item, "arguments", None) is None:
            return None
        try:
            arguments = serialize_tool_arguments(
                item.arguments,
                exclude_none=True,
            )
            encoded = json.dumps(
                {"tool": item.name, "arguments": arguments},
                ensure_ascii=False,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _apply_probe_recovery_budget(
        self, prepared: Sequence[Any]
    ) -> None:
        for item in prepared:
            if item.name != "system_http_probe":
                continue
            error = item.result.get("error") if isinstance(item.result, Mapping) else None
            is_argument_error = (
                isinstance(error, Mapping)
                and error.get("stage") in {"parse", "schema"}
                and error.get("code") in {"invalid_json", "invalid_arguments"}
            )
            if is_argument_error:
                same_arguments = (
                    getattr(item, "raw_arguments_digest", None) is not None
                    and getattr(item, "raw_arguments_digest", None)
                    == getattr(self, "_probe_invalid_argument_digest", None)
                )
                self._probe_argument_failure_streak += 1
                if same_arguments or self._probe_argument_failure_streak > 1:
                    item.result = tool_error(
                        str(error.get("stage") or "schema"),
                        "probe_argument_recovery_exhausted",
                        (
                            "system_http_probe repeated the same invalid arguments; do not retry them"
                            if same_arguments
                            else "system_http_probe received a second invalid argument shape in this session"
                        )
                        + "; use system_http_request or continue with the available tools",
                        retry_allowed=False,
                        retry_action="none",
                        details={
                            "recovery_budget": 1,
                            "previous_error_code": error.get("code"),
                            "canonical_tool": "system_http_request",
                            "same_arguments": same_arguments,
                        },
                    )
                    self._probe_recovery_exhausted = True
                else:
                    self._probe_invalid_argument_digest = getattr(
                        item, "raw_arguments_digest", None
                    )
            elif item.arguments is not None:
                self._probe_argument_failure_streak = 0
                self._probe_invalid_argument_digest = None

    def _apply_challenge_dispatch_recovery_budget(
        self, prepared: Sequence[Any]
    ) -> None:
        """Keep malformed controller dispatches recoverable within the session.

        The dispatch tool remains available after an argument error.  Runtime
        correction is intentionally bounded to a single prompt notice, while
        each malformed call receives a structured, retryable error.
        """

        if self.role != "challenge":
            return
        for item in prepared:
            if item.name != "challenge_dispatch":
                continue
            error = item.result.get("error") if isinstance(item.result, Mapping) else None
            is_argument_error = (
                isinstance(error, Mapping)
                and error.get("stage") in {"parse", "schema"}
                and error.get("code") in {"invalid_json", "invalid_arguments"}
            )
            if is_argument_error:
                same_arguments = (
                    getattr(item, "raw_arguments_digest", None) is not None
                    and getattr(item, "raw_arguments_digest", None)
                    == getattr(
                        self, "_challenge_dispatch_invalid_argument_digest", None
                    )
                )
                self._challenge_dispatch_argument_failure_streak += 1
                item.result = tool_error(
                    str(error.get("stage") or "schema"),
                    "challenge_dispatch_invalid_arguments",
                    "rewrite the dispatch as {} or use the documented top-level fields",
                    retry_allowed=True,
                    retry_action="rewrite_arguments",
                    details={
                        "previous_error_code": error.get("code"),
                        "same_arguments": same_arguments,
                        "argument_failure_streak": self._challenge_dispatch_argument_failure_streak,
                    },
                )
                self._challenge_dispatch_correction_pending = True
                self._challenge_dispatch_invalid_argument_digest = getattr(
                    item, "raw_arguments_digest", None
                )
            elif item.arguments is not None:
                self._challenge_dispatch_argument_failure_streak = 0
                self._challenge_dispatch_invalid_argument_digest = None

    @staticmethod
    def _evidence_type(tool_name: str) -> str:
        if tool_name in {"system_write_file", "system_edit_file"}:
            return "file"
        if (
            tool_name.startswith("system_http_")
            or tool_name.startswith("system_web_")
            or tool_name in {"system_browser", "system_proxy"}
        ):
            return "http"
        if tool_name.startswith("system_network_"):
            return "network"
        return "shell"

    @staticmethod
    def _project_model_result(
        tool_name: str,
        result: Mapping[str, Any],
        result_store: ToolResultStore,
        result_projection: Mapping[str, Any] | None = None,
    ) -> tuple[dict[str, Any], str | None, int]:
        encoded = json.dumps(result, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(encoded) <= 12_000 or tool_name == "tool_result_read":
            return dict(result), None, len(encoded)
        result_ref = result_store.persist(encoded)
        authority = None
        data = result.get("data")
        if isinstance(data, Mapping):
            authority = data.get("authority")
        projected: dict[str, Any] = {
            "ok": bool(result.get("ok")),
            "result_ref": result_ref,
            "original_chars": len(encoded),
            "preview": truncate_text(encoded, 2_000),
        }
        if result_projection is not None:
            projected.update(result_projection)
        if authority is not None:
            projected["authority"] = authority
        evidence_refs: list[str] = []
        if isinstance(data, Mapping):
            evidence_refs = [
                item
                for item in list(data.get("evidence_refs") or [])
                if isinstance(item, str)
            ]
        if evidence_refs:
            projected["evidence_refs"] = evidence_refs
        if result.get("ok") is False and isinstance(result.get("error"), Mapping):
            projected["error"] = result["error"]
        return projected, result_ref, len(encoded)

    async def _apply_tool_state(
        self,
        store: AgentStateStore,
        tool_name: str,
        result: Mapping[str, Any],
    ) -> None:
        before = {
            target.unique_code: {
                "is_completed": target.is_completed,
                "work_status": target.work_status,
                "container_status": target.container_status,
                "slot_occupied": target.slot_occupied,
                "correct_flag_count": target.score_snapshot.get("correct_flag_count"),
            }
            for target in store.checkpoint.targets
        }
        self._update_checkpoint_from_tool(store.checkpoint, tool_name, result)
        corrections = []
        for target in store.checkpoint.targets:
            previous = before.get(target.unique_code)
            current = {
                "is_completed": target.is_completed,
                "work_status": target.work_status,
                "container_status": target.container_status,
                "slot_occupied": target.slot_occupied,
                "correct_flag_count": target.score_snapshot.get("correct_flag_count"),
            }
            if previous is not None and previous != current:
                corrections.append(
                    {
                        "unique_code": target.unique_code,
                        "previous": previous,
                        "current": current,
                    }
                )
        if not corrections:
            return
        # Remove stale per-challenge prose from the memory summary. The new
        # checkpoint remains the authoritative context supplied after memory.
        memory = await store.read_memory()
        lines = memory.splitlines()
        changed_codes = {item["unique_code"] for item in corrections}
        filtered = [
            line for line in lines if not any(code in line for code in changed_codes)
        ]
        correction_lines = [
            "# Authoritative corrections",
            *(
                f"- {item['unique_code']}: is_completed={item['current']['is_completed']}; "
                f"work_status={item['current']['work_status']}; "
                f"container_status={item['current']['container_status']}; "
                f"slot_occupied={item['current']['slot_occupied']}"
                for item in corrections
            ),
        ]
        await store.write_memory("\n".join(filtered + ["", *correction_lines]) + "\n")
        await store.append_event(
            "state_correction",
            {
                "tool_name": tool_name,
                "corrections": [
                    {
                        "unique_code": item["unique_code"],
                        "previous": item["previous"],
                        "current": item["current"],
                    }
                    for item in corrections
                ],
            },
        )

    async def _compact(
        self,
        store: AgentStateStore,
        *,
        base_system_prompt: str,
        initial_user_message: Mapping[str, Any],
        messages: Sequence[Mapping[str, Any]],
        max_tokens: int,
        recent_message_tokens: int,
        allow_model_summary: bool = True,
    ) -> list[dict[str, Any]] | None:
        await self._wait_for_summary()
        summary_ok = False
        if allow_model_summary and self._summary_failures < 3:
            summary_ok = await self._update_summary(store, messages)
        compacted_messages = self._compact_tool_messages(messages[4:])
        if summary_ok:
            recent = bounded_recent_messages(
                compacted_messages, max_tokens=recent_message_tokens
            )
            event_type = "context_compacted"
            payload = {"last_event_sequence": store.checkpoint.last_event_sequence}
        else:
            recent = bounded_recent_messages(
                compacted_messages, max_tokens=recent_message_tokens
            )
            rebuilt = build_runtime_messages(
                base_system_prompt=self._compose_system_prompt(base_system_prompt),
                initial_user_message=initial_user_message,
                checkpoint=store.model_checkpoint(),
                session_memory=await store.read_memory(),
                recent_messages=recent,
                max_tokens=max_tokens,
                recent_message_tokens=recent_message_tokens,
            )
            if message_token_count(rebuilt) > max_tokens:
                await store.append_event(
                    "context_compaction_skipped",
                    {
                        "reason": "summary_and_micro_compaction_failed",
                        "consecutive_failures": self._summary_failures,
                    },
                )
                return None
            event_type = "context_micro_compacted"
            payload = {
                "reason": (
                    "summary_failed"
                    if allow_model_summary
                    else "execution_deterministic"
                ),
                "consecutive_failures": self._summary_failures,
                "history_preserved_in_events": True,
            }
        await store.append_event(event_type, payload)
        await store.save_checkpoint()
        return recent

    def _schedule_summary(
        self,
        store: AgentStateStore,
        messages: Sequence[Mapping[str, Any]],
        *,
        last_summary_tokens: int,
    ) -> None:
        if self.role == "execution":
            return
        if self._summary_failures >= 3:
            return
        if self._summary_task is not None and not self._summary_task.done():
            return
        snapshot = [dict(message) for message in messages]
        self._summary_task = asyncio.create_task(
            self._update_summary(store, snapshot, last_summary_tokens=last_summary_tokens)
        )

    async def _update_summary(
        self,
        store: AgentStateStore,
        messages: Sequence[Mapping[str, Any]],
        *,
        last_summary_tokens: int | None = None,
    ) -> bool:
        summarizer = SessionMemorySummarizer(self.settings, client=await self._get_http_client())
        try:
            events = await store.load_events(
                after_sequence=store.checkpoint.last_summarized_event_sequence,
                limit=100,
            )
            summarized_through = (
                events[-1].sequence
                if events
                else store.checkpoint.last_summarized_event_sequence
            )
            content = await summarizer.summarize(
                current_memory=await store.read_memory(),
                checkpoint=store.model_checkpoint(),
                recent_messages=redact_value(
                    bounded_recent_messages(
                        self._compact_tool_messages(messages),
                        max_tokens=self.settings.context_budget.profile(
                            self.role
                        ).recent_message_tokens,
                    ),
                    secrets=self._secrets(),
                ),
                recent_events=[event.model_dump(mode="json") for event in events[-100:]],
                deadline_monotonic=min(
                    value
                    for value in (
                        self._run_deadline_monotonic,
                        asyncio.get_running_loop().time() + 20.0,
                    )
                    if value is not None
                ),
            )
            await store.write_memory(
                content,
                summarized_through_sequence=summarized_through,
            )
            await store.save_checkpoint()
            self._summary_failures = 0
            return True
        except Exception:
            self._summary_failures += 1
            await store.append_event(
                "memory_update_failed",
                {
                    "code": "summary_unavailable",
                    "consecutive_failures": self._summary_failures,
                    **summarizer.last_metrics,
                },
            )
            return False

    async def _wait_for_summary(self) -> None:
        task = self._summary_task
        if task is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=20.0)
        except asyncio.TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        except Exception:
            # Background memory maintenance is non-critical and must never
            # mask the main Agent result or leave an unobserved task error.
            pass
        finally:
            if self._summary_task is task:
                self._summary_task = None

    async def _request_completion(
        self,
        client: httpx.AsyncClient,
        messages: Sequence[Mapping[str, Any]],
        *,
        tool_definitions: Sequence[Mapping[str, Any]],
        report_recovery: bool = False,
    ) -> dict[str, Any]:
        estimated_prompt_tokens = request_token_count(messages, tool_definitions)
        calibrated_prompt_tokens = int(
            estimated_prompt_tokens * self._prompt_calibration_ratio * 1.05
        )
        absolute_prompt_tokens = (
            self.settings.context_budget.absolute_prompt_tokens(
                self.role, bootstrap=self.bootstrap_mode
            )
        )
        soft_prompt_tokens = min(
            self.settings.context_budget.profile(self.role).soft_prompt_tokens,
            absolute_prompt_tokens,
        )
        if calibrated_prompt_tokens > absolute_prompt_tokens:
            raise AgentRunnerError(
                "Agent request exceeds the model context capacity",
                code="context_capacity_deferred",
                recoverable=self.role in {"chief", "challenge"},
                details={
                    "role": self.role,
                    "estimated_prompt_tokens": estimated_prompt_tokens,
                    "calibrated_prompt_tokens": calibrated_prompt_tokens,
                    "soft_target_tokens": soft_prompt_tokens,
                    "absolute_limit_tokens": absolute_prompt_tokens,
                },
            )
        started = asyncio.get_running_loop().time()
        attempts = 0
        retry_delay_ms = 0
        payload: Any = None
        response_status: int | None = None
        while attempts < 3:
            attempts += 1
            try:
                remaining = self._remaining_run_seconds()
                if remaining is not None and remaining <= 0:
                    raise AgentRunnerError(
                        "The Run deadline has expired",
                        code=(
                            "bootstrap_cycle_yield"
                            if self.bootstrap_mode
                            else "llm_temporarily_unavailable"
                        ),
                        recoverable=self.role in {"chief", "challenge"},
                        details={
                            "attempts": attempts,
                            "retry_delay_ms": retry_delay_ms,
                            "http_status": response_status,
                            "latency_ms": int(
                                (asyncio.get_running_loop().time() - started) * 1_000
                            ),
                        },
                    )
                request = client.post(
                    self._completion_endpoint(),
                    headers={
                        "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.settings.llm_model,
                        "messages": list(messages),
                        "tools": list(tool_definitions),
                        **deepseek_agent_request_options(
                            role=self.role,
                            bootstrap=self.bootstrap_mode,
                            context_budget=self.settings.context_budget,
                            report_recovery=report_recovery,
                        ),
                    },
                )
                response = (
                    await asyncio.wait_for(request, timeout=remaining)
                    if remaining is not None
                    else await request
                )
                response_status = response.status_code
                response.raise_for_status()
                payload = response.json()
                break
            except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
                status = (
                    exc.response.status_code
                    if isinstance(exc, httpx.HTTPStatusError)
                    else response_status
                )
                retryable = isinstance(
                    exc, (httpx.TransportError, asyncio.TimeoutError)
                ) or status in {
                    408,
                    429,
                    500,
                    502,
                    503,
                    504,
                }
                context_rejected = False
                if status == 400 and isinstance(exc, httpx.HTTPStatusError):
                    response_text = exc.response.text.lower()[:2_000]
                    context_rejected = any(
                        marker in response_text
                        for marker in (
                            "context length",
                            "context_length",
                            "maximum context",
                            "too many tokens",
                            "max context",
                        )
                    )
                if not retryable or attempts >= 3:
                    raise AgentRunnerError(
                        f"LLM request failed ({status or 'transport'}) after {attempts} attempt(s)",
                        code=(
                            "context_capacity_deferred"
                            if context_rejected
                            else "bootstrap_cycle_yield"
                            if self.bootstrap_mode and isinstance(exc, asyncio.TimeoutError)
                            else "llm_temporarily_unavailable"
                            if retryable
                            else "llm_request_failed"
                        ),
                        recoverable=context_rejected or retryable,
                        details={
                            "attempts": attempts,
                            "retry_delay_ms": retry_delay_ms,
                            "http_status": status,
                            "latency_ms": int(
                                (asyncio.get_running_loop().time() - started) * 1_000
                            ),
                        },
                    ) from exc
                retry_after = 0.0
                if isinstance(exc, httpx.HTTPStatusError):
                    try:
                        retry_after = float(exc.response.headers.get("Retry-After", "0"))
                    except ValueError:
                        retry_after = 0.0
                delay = min(2.0, max(retry_after, 0.25 * (2 ** (attempts - 1))))
                remaining = self._remaining_run_seconds()
                if remaining is not None and remaining <= delay:
                    raise AgentRunnerError(
                        "LLM retry would exceed the remaining Run deadline",
                        code=(
                            "bootstrap_cycle_yield"
                            if self.bootstrap_mode
                            else "llm_temporarily_unavailable"
                        ),
                        recoverable=self.role in {"chief", "challenge"},
                        details={
                            "attempts": attempts,
                            "retry_delay_ms": retry_delay_ms,
                            "http_status": status,
                            "latency_ms": int(
                                (asyncio.get_running_loop().time() - started) * 1_000
                            ),
                        },
                    ) from exc
                retry_delay_ms += int(delay * 1_000)
                await asyncio.sleep(delay)
        if not isinstance(payload, dict):
            raise AgentRunnerError(
                "LLM response was not an object",
                code="invalid_llm_response",
                recoverable=True,
                details={
                    "attempts": attempts,
                    "retry_delay_ms": retry_delay_ms,
                    "http_status": response_status,
                    "latency_ms": int(
                        (asyncio.get_running_loop().time() - started) * 1_000
                    ),
                },
            )
        payload["_aion_latency_ms"] = int(
            (asyncio.get_running_loop().time() - started) * 1_000
        )
        payload["_aion_attempts"] = attempts
        payload["_aion_retry_delay_ms"] = retry_delay_ms
        payload["_aion_http_status"] = response_status
        return payload

    def _remaining_run_seconds(self) -> float | None:
        deadlines = [
            deadline
            for deadline in (
                self._run_deadline_monotonic,
                getattr(self, "_agent_deadline_monotonic", None),
            )
            if deadline is not None
        ]
        if not deadlines:
            return None
        return max(0.0, min(deadlines) - asyncio.get_running_loop().time())

    @staticmethod
    def _report_only_definitions(
        definitions: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            dict(definition)
            for definition in definitions
            if definition.get("function", {}).get("name") == "execution_report"
        ]

    def _active_tool_definitions(
        self, definitions: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        if self._report_recovery_used:
            return self._report_only_definitions(definitions)
        disabled = set(self._disabled_tool_names)
        if self.bootstrap_mode:
            if self._current_round_number >= BOOTSTRAP_REPORT_ONLY_ROUND:
                return [
                    dict(definition)
                    for definition in definitions
                    if definition.get("function", {}).get("name")
                    in BOOTSTRAP_REPORT_TOOLS
                ]
            if self._current_round_number >= BOOTSTRAP_TARGETED_ROUND:
                disabled.update(BOOTSTRAP_BROAD_DISCOVERY_TOOLS)
        return [
            dict(definition)
            for definition in definitions
            if definition.get("function", {}).get("name")
            not in disabled
        ]

    async def _activate_deadline_report_recovery_if_needed(
        self,
        store: AgentStateStore,
        messages: list[dict[str, Any]],
        round_number: int,
    ) -> None:
        if (
            not self.require_structured_report
            or self._report_recovery_used
            or self._session_timeout_seconds is None
        ):
            return
        remaining = self._remaining_run_seconds()
        if remaining is None or remaining > BOOTSTRAP_REPORT_ONLY_GRACE_SECONDS:
            return
        self._report_recovery_used = True
        self._force_context_compaction = True
        messages.append(
            {
                "role": "user",
                "content": (
                    "The execution deadline is near. Preserve completed work, do not call any other tool, "
                    "and call execution_report now with the required structured terminal result."
                ),
            }
        )
        await store.append_event(
            "execution_deadline_report_recovery",
            {"round": round_number, "remaining_seconds": int(remaining)},
        )

    @staticmethod
    def _response_choice(payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            choice = payload["choices"][0]
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentRunnerError(
                "LLM response did not contain a choice",
                code="invalid_llm_response",
                recoverable=True,
            ) from exc
        if not isinstance(choice, dict):
            raise AgentRunnerError(
                "LLM choice was invalid",
                code="invalid_llm_response",
                recoverable=True,
            )
        message = choice.get("message")
        if not isinstance(message, dict):
            raise AgentRunnerError(
                "LLM message was invalid",
                code="invalid_llm_response",
                recoverable=True,
            )
        return {**choice, "message": message}

    @classmethod
    def _response_message(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        return cls._response_choice(payload)["message"]

    def _requires_reasoning_content(self) -> bool:
        """Require DeepSeek's tool-call reasoning field for the target model."""

        return self.settings.llm_model.startswith("deepseek-")

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=20.0))
        return self._http_client

    def _main_client(self) -> httpx.AsyncClient:
        client = self._http_client
        if client is None:
            client = httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=20.0))
            self._http_client = client
        return _ExistingAsyncClientContext(client)

    def _completion_endpoint(self) -> str:
        from agent.config import completions_url

        return completions_url(self.settings.llm_base_url)

    def _secrets(self) -> tuple[str, ...]:
        transient = (
            self.state_service.ephemeral_secrets()
        )
        return (self.settings.llm_api_key.get_secret_value(), *transient)

    def _tool_message(
        self, tool_call: Mapping[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": tool_call.get("id", "unknown"),
            "content": tool_result_for_model(
                result,
                max_chars=(
                    6_000
                    if self.role == "challenge"
                    else 8_000
                    if self.role == "chief"
                    else 12_000
                ),
            ),
        }

    @staticmethod
    def _replace_live_context_message(
        messages: list[dict[str, Any]], update: Mapping[str, Any]
    ) -> None:
        """Keep one authoritative runtime update instead of appending history."""

        marker = "# Runtime shared Bootstrap update"
        messages[:] = [
            item
            for item in messages
            if marker not in str(item.get("content") or "")
        ]
        visible_update = {
            key: value
            for key, value in update.items()
            if key not in {"content_digest", "authority_digest", "compacted"}
        }
        messages.append(
            {
                "role": "user",
                "content": marker
                + "\n"
                + json.dumps(visible_update, ensure_ascii=False, default=str),
            }
        )

    async def _maybe_compact_bootstrap_update(
        self,
        update: Mapping[str, Any],
        *,
        store: AgentStateStore,
    ) -> Mapping[str, Any]:
        """Compress only large safe projections; never alter authority fields."""

        digest = update.get("content_digest")
        if not isinstance(digest, str) or not digest:
            digest = blackboard_content_digest(update)
        encoded_length = len(
            json.dumps(dict(update), ensure_ascii=False, default=str)
        )
        if encoded_length < 6_000 or not list(update.get("reports") or []):
            return update
        cached = self._blackboard_compaction_cache.get(digest)
        if cached is not None:
            return cached
        compactor = BlackboardCompactor(
            self.settings,
            client=await self._get_http_client(),
        )
        try:
            compacted = await compactor.compact(
                update,
                deadline_monotonic=(
                    self._agent_deadline_monotonic
                    or self._run_deadline_monotonic
                ),
            )
        except BlackboardCompactionError as exc:
            await store.append_event(
                "blackboard_compaction_fallback",
                {
                    "content_digest": digest,
                    "error_type": type(exc).__name__,
                },
            )
            return update
        await store.append_event(
            "blackboard_compacted",
            {
                "content_digest": digest,
                "report_count": len(update.get("reports") or []),
                "input_chars": encoded_length,
                "output_chars": len(
                    json.dumps(dict(compacted), ensure_ascii=False, default=str)
                ),
                "latency_ms": compactor.last_metrics.get("latency_ms"),
            },
        )
        compacted["content_digest"] = digest
        compacted["authority_digest"] = update.get("authority_digest")
        self._blackboard_compaction_cache[digest] = compacted
        if len(self._blackboard_compaction_cache) > 8:
            oldest = next(iter(self._blackboard_compaction_cache))
            self._blackboard_compaction_cache.pop(oldest, None)
        return compacted

    @staticmethod
    def _tool_names(tool_calls: Any) -> list[str]:
        if not isinstance(tool_calls, list):
            return []
        names: list[str] = []
        for call in tool_calls:
            if isinstance(call, Mapping) and isinstance(call.get("function"), Mapping):
                name = call["function"].get("name")
                if isinstance(name, str):
                    names.append(name)
        return names

    @staticmethod
    def _redact_candidate_arguments_for_event(
        tool_name: str, arguments: Any
    ) -> Any:
        """Keep exact candidate values out of durable tool-call events."""

        if tool_name not in {"execution_report", "challenge_submit_flag"}:
            return arguments
        if not isinstance(arguments, Mapping):
            return arguments
        safe = dict(arguments)
        field = "candidate_flag" if tool_name == "execution_report" else "flag"
        value = safe.pop(field, None)
        if isinstance(value, str) and value:
            safe[f"{field}_present"] = True
            safe[f"{field}_sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return safe

    def _recovered_event_context(
        self,
        events: Sequence[Any],
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        recent: list[dict[str, Any]] = []
        for event in events:
            if event.sequence <= after_sequence:
                continue
            payload = event.payload
            if self.role in {"chief", "challenge"}:
                if event.event_type == "controller_snapshot":
                    # The current durable snapshot is injected directly into the
                    # controller request; historical copies only dilute decisions.
                    continue
                if event.event_type in {"tool_call", "tool_result"} and isinstance(
                    payload, Mapping
                ):
                    tool_name = payload.get("tool_name")
                    if tool_name in {"chief_observe", "challenge_observe"}:
                        continue
                if event.event_type == "assistant_response" and isinstance(
                    payload, Mapping
                ):
                    payload = {
                        key: payload.get(key)
                        for key in (
                            "round",
                            "tool_names",
                            "prompt_tokens",
                            "latency_ms",
                            "attempts",
                            "http_status",
                        )
                    }
            if event.event_type == "controller_snapshot" and isinstance(
                payload, Mapping
            ):
                reports = payload.get("reports")
                payload = {
                    "through_sequence": payload.get("through_sequence"),
                    "count": payload.get("count"),
                    "report_type": payload.get("report_type"),
                    "report_refs": [
                        item.get("report_ref")
                        for item in list(reports or [])
                        if isinstance(item, Mapping) and item.get("report_ref")
                    ],
                }
            recent.append(
                {
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "payload": payload,
                }
            )
        recent = recent[-100:]
        if not recent:
            return []
        recovered_chars = self.settings.context_budget.profile(
            self.role
        ).recovered_event_chars
        if self.role == "chief":
            recovered_chars = min(recovered_chars, 48_000)
        elif self.role == "challenge":
            recovered_chars = min(recovered_chars, 32_000)
        return [
            {
                "role": "system",
                "content": "Recent durable Agent events:\n"
                + truncate_text(
                    json.dumps(recent, ensure_ascii=False, default=str),
                    recovered_chars,
                ),
            }
        ]

    @staticmethod
    def _error_code(result: Any) -> str | None:
        if isinstance(result, Mapping) and isinstance(result.get("error"), Mapping):
            code = result["error"].get("code")
            return code if isinstance(code, str) else None
        return None

    @staticmethod
    def _update_checkpoint_from_tool(
        checkpoint: Checkpoint,
        tool_name: str,
        result: Mapping[str, Any],
    ) -> None:
        data = result.get("data") if isinstance(result, Mapping) else None
        if tool_name == "skill_invoke" and result.get("ok") and isinstance(data, Mapping):
            active = data.get("active_skill")
            if isinstance(active, Mapping):
                state = ActiveSkillState.model_validate(active)
                existing = next(
                    (
                        item
                        for item in checkpoint.active_skills
                        if item.skill_id == state.skill_id
                    ),
                    None,
                )
                if existing is None:
                    checkpoint.active_skills.append(state)
                elif existing.content_sha256 != state.content_sha256:
                    raise AgentRunnerError(
                        "An activated Skill changed during the Agent session",
                        code="authoritative_state_corrupt",
                    )
            return
        if not result.get("ok") or not isinstance(data, Mapping):
            return
        if tool_name in {"challenge_observe", "challenge_dispatch"}:
            challenge = data.get("challenge")
            if not isinstance(challenge, Mapping):
                authority = data.get("authority")
                challenge = (
                    authority.get("challenge")
                    if isinstance(authority, Mapping)
                    else {}
                )
            checkpoint.authoritative_view = {
                "challenge": dict(challenge) if isinstance(challenge, Mapping) else {},
                "latest_cycle": data.get("latest_cycle") or data.get("cycle"),
                "active_executions": list(data.get("active_executions") or [])[:20],
                "reports": [
                    {
                        "report_ref": item.get("report_ref"),
                        "agent_id": item.get("agent_id"),
                        "status": item.get("status"),
                        "summary": str(
                            (item.get("payload") or {}).get("summary", "")
                            if isinstance(item.get("payload"), Mapping)
                            else item.get("summary", "")
                        )[:1_000],
                    }
                    for item in list(data.get("reports") or [])[-20:]
                    if isinstance(item, Mapping)
                ],
                "report_cursor": data.get("report_cursor"),
                "has_more": data.get("has_more"),
            }
            return
        if tool_name == "chief_observe":
            catalog = data.get("challenges")
            capacity = data.get("capacity")
            if isinstance(catalog, list):
                checkpoint.targets = [
                    TargetState(
                        unique_code=item["unique_code"],
                        status=checkpoint_target_status(item),
                        is_completed=bool(item.get("is_completed")),
                        work_status=str(item.get("work_status") or "unassigned"),
                        container_status=str(item.get("container_status") or ""),
                        slot_occupied=container_slot_occupied(
                            item.get("container_status")
                        ),
                        container_addr=list(item.get("container_addr") or []),
                        score_snapshot={
                            "correct_flag_count": item.get("correct_flag_count"),
                            "total_score": item.get("total_score"),
                        },
                    )
                    for item in catalog
                    if isinstance(item, Mapping)
                    and isinstance(item.get("unique_code"), str)
                ]
                checkpoint.container_capacity = (
                    dict(capacity)
                    if isinstance(capacity, Mapping)
                    else container_capacity_summary(catalog)
                )
    @staticmethod
    def _safe_error_message(exc: Exception) -> str:
        if isinstance(exc, AgentRunnerError):
            return str(exc)
        return "Agent run failed unexpectedly"

    def _compose_system_prompt(self, fixed_prompt: str) -> str:
        if self.system_context_provider is None:
            return fixed_prompt
        context = self.system_context_provider().strip()
        return f"{fixed_prompt.rstrip()}\n\n{context}" if context else fixed_prompt

    @staticmethod
    def _compact_skill_result(
        tool_name: str, result: Mapping[str, Any]
    ) -> dict[str, Any]:
        value = dict(result)
        if tool_name != "skill_invoke" or value.get("ok") is False:
            return value
        data = value.get("data")
        if not isinstance(data, Mapping):
            return value
        skill = data.get("skill")
        compact_skill = (
            {
                "skill_id": skill.get("skill_id"),
                "content_sha256": skill.get("content_sha256"),
            }
            if isinstance(skill, Mapping)
            else {}
        )
        return {
            "ok": True,
            "data": {
                "skill": compact_skill,
                "activation_status": data.get("activation_status"),
                "instructions_in_context": True,
                "active_skill": data.get("active_skill"),
            },
        }

    @classmethod
    def _compact_skill_messages(
        cls, messages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        skill_call_ids: set[str] = set()
        for message in messages:
            if message.get("role") != "assistant":
                continue
            calls = message.get("tool_calls")
            if not isinstance(calls, list):
                continue
            for call in calls:
                if not isinstance(call, Mapping):
                    continue
                function = call.get("function")
                if (
                    isinstance(function, Mapping)
                    and function.get("name") == "skill_invoke"
                ):
                    skill_call_ids.add(str(call.get("id") or "unknown"))
        compacted: list[dict[str, Any]] = []
        for message in messages:
            value = dict(message)
            if value.get("role") == "system" and isinstance(value.get("content"), str):
                value["content"] = cls._compact_active_skill_context(value["content"])
            if (
                value.get("role") == "tool"
                and str(value.get("tool_call_id") or "unknown") in skill_call_ids
            ):
                try:
                    decoded = json.loads(str(value.get("content") or "{}"))
                except ValueError:
                    decoded = {}
                value["content"] = json.dumps(
                    cls._compact_skill_result("skill_invoke", decoded),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            compacted.append(value)
        return compacted

    @classmethod
    def _compact_tool_messages(
        cls, messages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Create a deterministic, reference-preserving view of old tool results."""

        compacted = cls._compact_skill_messages(messages)
        for value in compacted:
            if value.get("role") != "tool":
                continue
            try:
                decoded = json.loads(str(value.get("content") or "{}"))
            except ValueError:
                value["content"] = json.dumps(
                    {"ok": False, "compacted": True, "error": {"code": "unreadable_tool_result"}},
                    separators=(",", ":"),
                )
                continue
            if not isinstance(decoded, Mapping):
                continue
            if decoded.get("ok") is False:
                projected: dict[str, Any] = {
                    "ok": False,
                    "compacted": True,
                    "error": decoded.get("error", {}),
                }
            else:
                data = decoded.get("data")
                projected_data: dict[str, Any] = {}
                if isinstance(data, Mapping):
                    for key, item in data.items():
                        if (
                            key == "authority"
                            or key in {
                                "status",
                                "execution_status",
                                "analysis_status",
                                "recommended_action",
                                "is_terminal",
                                "can_cleanup",
                                "cursor",
                                "next_cursor",
                                "next_offset",
                                "eof",
                                "evidence_root",
                                "request_catalog",
                            }
                            or key.endswith(("_id", "_ids", "_ref", "_refs", "_count"))
                        ):
                            projected_data[key] = item
                projected = {
                    "ok": True,
                    "compacted": True,
                    "data": projected_data,
                }
            value["content"] = json.dumps(
                projected, ensure_ascii=False, separators=(",", ":")
            )
        return compacted

    @staticmethod
    def _compact_active_skill_context(content: str) -> str:
        """Keep activated Skill identity in summary input without copying its body."""

        pattern = re.compile(r"<active_skills>.*?</active_skills>", re.DOTALL)

        def replace(match: re.Match[str]) -> str:
            active = re.findall(
                r'<skill id="([^"]+)" sha256="([0-9a-f]{64})">',
                match.group(0),
            )
            lines = ["<active_skills>"]
            lines.extend(
                f'- {skill_id} sha256={content_hash} instructions_in_context=true'
                for skill_id, content_hash in active
            )
            lines.append("</active_skills>")
            return "\n".join(lines)

        return pattern.sub(replace, content)


class _ExistingAsyncClientContext:
    """Async context wrapper that does not close a runner-owned client."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def __aenter__(self) -> httpx.AsyncClient:
        return self.client

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None


async def _cli_async() -> int:
    parser = argparse.ArgumentParser(description="Run or resume the AION Agent Runtime")
    parser.add_argument(
        "--prompt",
        help="optional temporary Chief prompt override; defaults to chief_agent.txt",
    )
    parser.add_argument("--resume")
    parser.add_argument("--cleanup")
    parser.add_argument(
        "--duration-minutes",
        type=int,
        default=None,
        help="persist the run deadline using this duration",
    )
    args = parser.parse_args()
    if args.duration_minutes is not None and args.duration_minutes < 1:
        parser.error("--duration-minutes must be positive")
    if args.resume is not None and args.cleanup is not None:
        parser.error("--resume and --cleanup are mutually exclusive")
    if args.prompt is not None and (args.resume is not None or args.cleanup is not None):
        parser.error("--prompt cannot be combined with --resume or --cleanup")

    if args.cleanup:
        from agent.config import PROJECT_ROOT

        run_root = (PROJECT_ROOT / ".aion" / "runs").resolve()
        target = (run_root / args.cleanup).resolve()
        if not args.cleanup or target.parent != run_root:
            raise AgentRunnerError("invalid cleanup run_id")
        if target.exists():
            await asyncio.to_thread(shutil.rmtree, target)
        print(json.dumps({"ok": True, "cleaned_run_id": args.cleanup}))
        return 0

    from agent.runtime import AgentRuntime
    settings = AgentSettings()
    if args.duration_minutes is not None:
        settings = settings.model_copy(
            update={"run_duration_minutes": args.duration_minutes}
        )
    runtime = AgentRuntime.from_env(settings=settings)
    try:
        result = await runtime.run(
            args.prompt or default_chief_prompt(),
            run_id=args.resume,
            resume=args.resume is not None,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        await runtime.close()


def main() -> None:
    from agent.state.errors import StateError
    from agent.subagents import SubagentError

    try:
        raise SystemExit(asyncio.run(_cli_async()))
    except (AgentRunnerError, StateError, SubagentError) as exc:
        print(f"Agent error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
