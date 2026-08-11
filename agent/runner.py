"""OpenAI-compatible long-running Agent runner with resumable memory."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from agent.config import AgentSettings
from agent.prompts import load_prompt

from .memory.context import (
    build_runtime_messages,
    message_token_count,
    prompt_tokens_from_response,
    should_autocompact,
    should_update_memory,
    tool_result_for_model,
    truncate_text,
)
from .memory.models import Checkpoint, TargetState
from .memory.redaction import redact_text, redact_tool_payload, redact_value
from .memory.summarizer import SessionMemorySummarizer, SummarizerError
from .state import (
    AgentStateStore,
    StateService,
    checkpoint_target_status,
    container_capacity_summary,
    container_slot_occupied,
)


class AgentRunnerError(RuntimeError):
    """Safe error raised by the Agent runner."""


@dataclass(frozen=True)
class AgentSessionResult:
    """Outcome of one model session without an Agent lifecycle decision."""

    run_id: str
    final: str
    last_event_sequence: int
    structured_report_seen: bool
    yield_reason: str


@dataclass(frozen=True)
class ToolDispatchOutcome:
    """Internal tool result carrying Runner control outside model payloads."""

    result: dict[str, Any]
    yield_session: bool = False


def default_chief_prompt() -> str:
    """Return the centrally managed prompt for a new online Run."""

    return load_prompt("chief_agent.txt")


class ToolRegistry:
    """Combine independent wrappers without coupling the Agent to a framework."""

    def __init__(self, wrappers: Sequence[Any], *, allowed_tools: set[str] | frozenset[str] | None = None) -> None:
        self.wrappers = list(wrappers)
        self.allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self._definitions: list[dict[str, Any]] = []
        self._owners: dict[str, Any] = {}
        for wrapper in self.wrappers:
            for definition in wrapper.tool_definitions():
                name = definition.get("function", {}).get("name")
                if (
                    isinstance(name, str)
                    and (self.allowed_tools is None or name in self.allowed_tools)
                    and name not in self._owners
                ):
                    self._definitions.append(definition)
                    self._owners[name] = wrapper

    def definitions(self) -> list[dict[str, Any]]:
        return json.loads(json.dumps(self._definitions, ensure_ascii=False))

    def has_tool(self, name: str) -> bool:
        return name in self._owners

    async def dispatch(
        self, name: str, arguments: Mapping[str, Any]
    ) -> dict[str, Any] | ToolDispatchOutcome:
        if self.allowed_tools is not None and name not in self.allowed_tools:
            return {
                "ok": False,
                "error": {
                    "type": "permission",
                    "code": "tool_not_allowed_for_role",
                    "message": "This Agent role cannot use that tool",
                    "status_code": None,
                    "detail": {},
                },
            }
        owner = self._owners.get(name)
        if owner is None:
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "unknown_tool",
                    "message": "Unknown Agent tool",
                    "status_code": None,
                    "detail": {},
                },
            }
        return await owner.dispatch(name, arguments)

    async def close(self) -> None:
        for wrapper in self.wrappers:
            await wrapper.close()


class AgentRunner:
    """Run a single Agent task with bounded context and durable state."""

    def __init__(
        self,
        settings: AgentSettings,
        registry: ToolRegistry,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_rounds: int = 1_000,
        run_root: Path | None = None,
        role: str | None = None,
        agent_id: str | None = None,
        parent_id: str | None = None,
        base_system_prompt: str | None = None,
        require_structured_report: bool = False,
        state_service: StateService,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.max_rounds = max_rounds
        self.run_root = run_root or settings.run_root
        self.role = role
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.base_system_prompt = base_system_prompt
        self.require_structured_report = require_structured_report
        self.state_service = state_service
        self._http_client = http_client
        self._owns_http_client = http_client is None
        self._summary_failures = 0
        self._summary_task: asyncio.Task[None] | None = None
        self._structured_report_seen = False

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
        if resume:
            if store.manifest.status == "completed":
                raise AgentRunnerError("completed runs cannot be resumed")
            prompt = store.manifest.prompt
            if not prompt:
                raise AgentRunnerError("run manifest does not contain a resumable prompt")
            await self._prepare_resume(store)
        else:
            if not prompt or not prompt.strip():
                raise AgentRunnerError("a non-empty prompt is required")
            prompt = redact_text(prompt)

        assert prompt is not None
        base_system_prompt = self.base_system_prompt or load_prompt("base_system.txt")
        initial_user_message = {"role": "user", "content": prompt}
        memory = await store.read_memory()
        durable_events = await store.load_events() if resume else []
        messages = build_runtime_messages(
            base_system_prompt=base_system_prompt,
            initial_user_message=initial_user_message,
            checkpoint=store.checkpoint.model_dump(mode="json"),
            session_memory=memory,
            recent_messages=self._recovered_event_context(
                durable_events,
                after_sequence=store.checkpoint.last_summarized_event_sequence,
            ),
        )
        current_tokens = message_token_count(messages)
        last_summary_tokens = current_tokens if resume else 0
        tool_calls_since_summary = 0
        final_content = ""
        yield_reason = "model_return"

        try:
            async with self._main_client() as client:
                for round_number in range(1, self.max_rounds + 1):
                    payload = await self._request_completion(client, messages)
                    usage_tokens = prompt_tokens_from_response(payload)
                    current_tokens = max(
                        usage_tokens or 0,
                        message_token_count(messages),
                    )
                    message = self._response_message(payload)
                    tool_calls = message.get("tool_calls") or []
                    assistant_message: dict[str, Any] = {
                        "role": "assistant",
                        "content": message.get("content"),
                    }
                    if tool_calls:
                        assistant_message["tool_calls"] = tool_calls
                    messages.append(assistant_message)
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
                        },
                    )

                    if not tool_calls:
                        if self.require_structured_report and not self._structured_report_seen:
                            raise AgentRunnerError("execution Agent ended without a structured report")
                        final_content = str(message.get("content") or "")
                        break

                    yield_session = False
                    for tool_call in tool_calls:
                        result, tool_message, requested_yield = await self._execute_tool_call(
                            store,
                            tool_call,
                            allow_yield=len(tool_calls) == 1,
                        )
                        messages.append(tool_message)
                        yield_session = yield_session or requested_yield
                        tool_calls_since_summary += 1
                        current_tokens = message_token_count(messages)
                        if should_update_memory(
                            current_tokens=current_tokens,
                            last_summary_tokens=last_summary_tokens,
                            tool_calls_since_summary=tool_calls_since_summary,
                        ):
                            self._schedule_summary(
                                store,
                                messages,
                                last_summary_tokens=current_tokens,
                            )
                            last_summary_tokens = current_tokens
                            tool_calls_since_summary = 0

                    if yield_session:
                        yield_reason = "controller_wait"
                        break

                    if should_autocompact(current_tokens, self.settings.context_budget):
                        await self._compact(
                            store,
                            base_system_prompt=base_system_prompt,
                            initial_user_message=initial_user_message,
                            messages=messages,
                        )
                        memory = await store.read_memory()
                        messages = build_runtime_messages(
                            base_system_prompt=base_system_prompt,
                            initial_user_message=initial_user_message,
                            checkpoint=store.checkpoint.model_dump(mode="json"),
                            session_memory=memory,
                            recent_messages=messages[4:],
                        )
                        current_tokens = message_token_count(messages)
                        last_summary_tokens = current_tokens
                        tool_calls_since_summary = 0

                else:
                    raise AgentRunnerError("maximum Agent rounds exceeded")

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
            safe_message = self._safe_error_message(exc)
            await store.append_event("agent_session_failed", {"message": safe_message})
            raise
        finally:
            await self._wait_for_summary()

    async def _prepare_resume(self, store: Any) -> None:
        store.checkpoint.active_tool_calls = []
        await store.save_checkpoint()
        if self.registry.has_tool("benchmark_list_challenges"):
            result = await self.registry.dispatch("benchmark_list_challenges", {})
            await self._apply_tool_state(store, "benchmark_list_challenges", result)
            await store.append_event(
                "resume_state_sync",
                {"ok": result.get("ok"), "error_code": self._error_code(result)},
            )
            await store.save_checkpoint()

    async def _execute_tool_call(
        self,
        store: AgentStateStore,
        tool_call: Mapping[str, Any],
        *,
        allow_yield: bool,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        function = tool_call.get("function")
        if not isinstance(function, Mapping):
            result = self._invalid_tool_result()
            return result, self._tool_message(tool_call, result), False
        name = function.get("name")
        raw_arguments = function.get("arguments", "{}")
        if not isinstance(name, str):
            result = self._invalid_tool_result()
            return result, self._tool_message(tool_call, result), False
        try:
            arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else raw_arguments
        except json.JSONDecodeError:
            arguments = {"_invalid_json": True}
        if not isinstance(arguments, Mapping):
            arguments = {"_invalid_arguments": True}

        safe_arguments = redact_tool_payload(name, arguments, secrets=self._secrets())
        await store.append_event(
            "tool_call",
            {
                "tool_call_id": tool_call.get("id"),
                "tool_name": name,
                "arguments": safe_arguments,
            },
        )
        dispatched = await self.registry.dispatch(name, arguments)
        requested_yield = isinstance(dispatched, ToolDispatchOutcome) and dispatched.yield_session
        result = dispatched.result if isinstance(dispatched, ToolDispatchOutcome) else dispatched
        if requested_yield and not allow_yield:
            requested_yield = False
            result = {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "controller_wait_must_be_solo",
                    "message": "Controller wait must be the only tool call in the response",
                    "status_code": None,
                    "detail": {},
                },
            }
        if name == "execution_report" and result.get("ok"):
            data = result.get("data")
            self._structured_report_seen = self._structured_report_seen or bool(
                isinstance(data, Mapping) and data.get("terminal")
            )
        safe_result = redact_tool_payload(name, result, secrets=self._secrets())
        await store.append_event(
            "tool_result",
            {
                "tool_call_id": tool_call.get("id"),
                "tool_name": name,
                "result": self._bounded_payload(safe_result),
            },
        )
        await self._apply_tool_state(store, name, result)
        await store.save_checkpoint()
        return result, self._tool_message(tool_call, result), requested_yield

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
    ) -> None:
        await self._wait_for_summary()
        if self._summary_failures < 3:
            await self._update_summary(store, messages)
        await store.append_event(
            "context_compacted",
            {"last_event_sequence": store.checkpoint.last_event_sequence},
        )
        await store.save_checkpoint()

    def _schedule_summary(
        self,
        store: AgentStateStore,
        messages: Sequence[Mapping[str, Any]],
        *,
        last_summary_tokens: int,
    ) -> None:
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
    ) -> None:
        summarizer = SessionMemorySummarizer(self.settings, client=await self._get_http_client())
        try:
            events = await store.load_events()
            content = await summarizer.summarize(
                current_memory=await store.read_memory(),
                checkpoint=store.checkpoint.model_dump(mode="json"),
                recent_messages=redact_value(list(messages), secrets=self._secrets())[-80:],
                recent_events=[event.model_dump(mode="json") for event in events[-100:]],
            )
            await store.write_memory(content)
            store.checkpoint.last_summarized_event_sequence = store.checkpoint.last_event_sequence
            await store.append_event(
                "memory_updated",
                {"last_event_sequence": store.checkpoint.last_summarized_event_sequence},
            )
            await store.save_checkpoint()
            self._summary_failures = 0
        except SummarizerError:
            self._summary_failures += 1
            await store.append_event(
                "memory_update_failed",
                {"consecutive_failures": self._summary_failures},
            )

    async def _wait_for_summary(self) -> None:
        if self._summary_task is None:
            return
        try:
            await asyncio.wait_for(self._summary_task, timeout=30.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, SummarizerError):
            self._summary_task.cancel()
        except Exception:
            # Background memory maintenance is non-critical and must never
            # mask the main Agent result or leave an unobserved task error.
            pass
        finally:
            self._summary_task = None

    async def _request_completion(
        self,
        client: httpx.AsyncClient,
        messages: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        try:
            response = await client.post(
                self._completion_endpoint(),
                headers={
                    "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.settings.llm_model,
                    "messages": list(messages),
                    "tools": self.registry.definitions(),
                    "tool_choice": "auto",
                    "temperature": 0,
                    "max_tokens": self.settings.context_budget.max_output_tokens,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AgentRunnerError("LLM request failed") from exc
        if not isinstance(payload, dict):
            raise AgentRunnerError("LLM response was not an object")
        return payload

    @staticmethod
    def _response_message(payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            message = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentRunnerError("LLM response did not contain a message") from exc
        if not isinstance(message, dict):
            raise AgentRunnerError("LLM message was invalid")
        return message

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

    @staticmethod
    def _tool_message(tool_call: Mapping[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": tool_call.get("id", "unknown"),
            "content": tool_result_for_model(result),
        }

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
    def _recovered_event_context(
        events: Sequence[Any],
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        recent = [
            {
                "sequence": event.sequence,
                "event_type": event.event_type,
                "payload": event.payload,
            }
            for event in events
            if event.sequence > after_sequence
        ][-100:]
        if not recent:
            return []
        return [
            {
                "role": "system",
                "content": "Recent durable Agent events:\n"
                + truncate_text(
                    json.dumps(recent, ensure_ascii=False, default=str), 16_000
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
    def _bounded_payload(value: Any) -> Any:
        if isinstance(value, str):
            return truncate_text(value, 12_000)
        encoded = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(encoded) <= 12_000:
            return value
        return {"truncated": True, "preview": truncate_text(encoded, 12_000)}

    @staticmethod
    def _invalid_tool_result() -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": "validation",
                "code": "invalid_tool_call",
                "message": "The model returned an invalid tool call",
                "status_code": None,
                "detail": {},
            },
        }

    @staticmethod
    def _update_checkpoint_from_tool(
        checkpoint: Checkpoint,
        tool_name: str,
        result: Mapping[str, Any],
    ) -> None:
        data = result.get("data") if isinstance(result, Mapping) else None
        catalog: Any = None
        capacity: Any = None
        if tool_name == "benchmark_list_challenges" and isinstance(data, list):
            catalog = data
        elif tool_name in {"chief_refresh_challenges", "chief_get_core_state"} and isinstance(data, Mapping):
            catalog = data.get("challenges")
            capacity = data.get("container_capacity")
        if isinstance(catalog, list):
            states: list[TargetState] = []
            for item in catalog:
                if not isinstance(item, Mapping) or not isinstance(item.get("unique_code"), str):
                    continue
                states.append(
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
                )
            if states:
                checkpoint.targets = states
                checkpoint.container_capacity = (
                    dict(capacity)
                    if isinstance(capacity, Mapping)
                    else container_capacity_summary(catalog)
                )
            return
        unique_code = data.get("unique_code") if isinstance(data, Mapping) else None
        if not isinstance(unique_code, str):
            return
        target = next((item for item in checkpoint.targets if item.unique_code == unique_code), None)
        if target is None:
            target = TargetState(unique_code=unique_code)
            checkpoint.targets.append(target)
        checkpoint.current_target = unique_code
        if tool_name == "benchmark_start_challenge" and result.get("ok"):
            target.status = "started"
            target.work_status = "active"
            target.container_status = "running"
            target.slot_occupied = True
            target.container_addr = list(data.get("container_addr") or [])
        elif tool_name == "benchmark_submit_flag" and result.get("ok"):
            target.status = "submitted" if data.get("correct") else "in_progress"
            target.score_snapshot = dict(data)
        elif tool_name == "benchmark_close_challenge" and result.get("ok"):
            target.status = "closed"
            target.work_status = "closed"
            target.container_status = "stopped"
            target.slot_occupied = False

    @staticmethod
    def _safe_error_message(exc: Exception) -> str:
        if isinstance(exc, AgentRunnerError):
            return str(exc)
        return "Agent run failed unexpectedly"


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
