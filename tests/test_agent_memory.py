"""Offline tests for the single-run Agent memory and context layer."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from agent.config import AgentSettings, ContextBudget, ROLE_CONTEXT_PROFILES
from agent.memory.context import (
    build_runtime_messages,
    message_token_count,
    normalize_session_memory,
    rough_token_count,
    should_autocompact,
    should_update_memory,
    tool_result_for_model,
)
from agent.memory.models import ActiveSkillState, Checkpoint, OperationState, TargetState
from agent.memory.redaction import redact_tool_payload, redact_value
from agent.memory.summarizer import SessionMemorySummarizer
from agent.runner import AgentRunner, AgentRunnerError
from agent.tooling import ToolDispatchOutcome, ToolRegistry, ToolSpec
from agent.state import AgentStateStore, StateService
from agent.state.models import DEFAULT_SESSION_MEMORY
from agent.state.schemas import ChallengeImport


def _settings(**overrides: Any) -> AgentSettings:
    values = {
        "llm_base_url": "https://llm.test",
        "llm_model": "test-model",
        "llm_api_key": "test-api-key",
    }
    values.update(overrides)
    return AgentSettings(**values)


def test_context_budget_defaults_to_one_million_tokens() -> None:
    budget = ContextBudget()
    assert budget.context_window_tokens == 1_000_000
    assert budget.absolute_prompt_tokens("chief") == 959_040
    assert budget.absolute_prompt_tokens("challenge") == 959_040
    assert budget.absolute_prompt_tokens("execution") == 975_424
    assert budget.max_output_tokens("chief") == 32_768
    assert budget.max_output_tokens("execution") == 16_384
    assert budget.max_output_tokens("execution", bootstrap=True) == 32_768
    assert ROLE_CONTEXT_PROFILES["chief"].soft_prompt_tokens == 128_000
    assert ROLE_CONTEXT_PROFILES["challenge"].soft_prompt_tokens == 96_000
    assert ROLE_CONTEXT_PROFILES["execution"].soft_prompt_tokens == 64_000
    assert _settings().context_budget.context_window_tokens == 1_000_000


def test_context_window_override_is_optional_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AION_CONTEXT_WINDOW_TOKENS", "50000")
    assert _settings().context_window_tokens == 50_000

    monkeypatch.setenv("AION_CONTEXT_WINDOW_TOKENS", "100")
    with pytest.raises(ValidationError):
        _settings()


def test_payloads_remain_plaintext_for_local_analysis() -> None:
    payload = {
        "flag": "flag{secret-value}",
        "BENCHMARK_TOKEN": "benchmark-secret",
        "nested": {"authorization": "Bearer api-secret"},
    }
    plaintext = redact_tool_payload(
        "benchmark_submit_flag",
        payload,
        secrets=("api-secret",),
    )
    encoded = json.dumps(plaintext)
    assert "flag{secret-value}" in encoded
    assert "benchmark-secret" in encoded
    assert "api-secret" in encoded
    assert plaintext["flag"] == "flag{secret-value}"
    assert redact_value("api-secret", secrets=("api-secret",)) == "api-secret"


def test_context_estimation_and_tool_result_limits() -> None:
    assert rough_token_count("abcd") == 2
    assert message_token_count([{"role": "user", "content": "hello"}]) > 0
    result = tool_result_for_model({"ok": True, "data": "x" * 500}, max_chars=100)
    assert len(result) <= 220
    assert '"truncated":true' in result
    assert should_update_memory(
        current_tokens=50_000,
        last_summary_tokens=0,
        tool_calls_since_summary=0,
        threshold_tokens=48_000,
    )
    assert should_update_memory(
        current_tokens=50_000,
        last_summary_tokens=1,
        tool_calls_since_summary=20,
        threshold_tokens=48_000,
    )
    assert should_autocompact(64_000, soft_prompt_tokens=64_000)


def test_live_context_replaces_previous_runtime_update() -> None:
    messages = [
        {"role": "user", "content": "before"},
        {
            "role": "user",
            "content": '# Runtime shared Bootstrap update\n{"through_sequence":1}',
        },
    ]
    AgentRunner._replace_live_context_message(
        messages, {"through_sequence": 2, "reports": []}
    )
    encoded = json.dumps(messages)
    assert encoded.count("Runtime shared Bootstrap update") == 1
    assert '"through_sequence": 2' in messages[-1]["content"]


def test_challenge_dispatch_has_one_argument_recovery() -> None:
    runner = object.__new__(AgentRunner)
    runner.role = "challenge"
    runner._challenge_dispatch_argument_failure_streak = 0
    runner._challenge_dispatch_recovery_exhausted = False
    item = SimpleNamespace(
        name="challenge_dispatch",
        arguments=None,
        result={
            "ok": False,
            "error": {
                "stage": "schema",
                "code": "invalid_arguments",
            },
        },
    )

    runner._apply_challenge_dispatch_recovery_budget([item])
    assert item.result["error"]["code"] == "invalid_arguments"
    second_item = SimpleNamespace(
        name="challenge_dispatch",
        arguments=None,
        result={
            "ok": False,
            "error": {
                "stage": "schema",
                "code": "invalid_arguments",
            },
        },
    )
    runner._apply_challenge_dispatch_recovery_budget([second_item])
    assert second_item.result["error"]["code"] == "challenge_dispatch_recovery_exhausted"
    assert runner._challenge_dispatch_recovery_exhausted is True


def test_session_memory_is_structured_and_bounded() -> None:
    content = "# Current State\n\n" + "x" * 10_000
    normalized, changed = normalize_session_memory(content, max_tokens=400)
    assert changed is True
    for heading in (
        "Current State",
        "Task Specification",
        "Targets",
        "Important Observations",
        "Workflow",
        "Errors & Corrections",
        "Next Steps",
        "Worklog",
    ):
        assert f"# {heading}" in normalized
    assert rough_token_count(normalized) <= 500


def test_authoritative_checkpoint_follows_and_overrides_session_memory() -> None:
    checkpoint = Checkpoint(
        run_id="run-one",
        targets=[
            TargetState(
                unique_code="a-02",
                status="submitted",
                is_completed=True,
                work_status="completed",
                container_status="available",
                slot_occupied=True,
            )
        ],
        container_capacity={
            "limit": 3,
            "occupied_count": 1,
            "free_count": 2,
            "occupied_codes": ["a-02"],
            "completed_pending_release_codes": ["a-02"],
        },
    )
    messages = build_runtime_messages(
        base_system_prompt="base",
        initial_user_message={"role": "user", "content": "run"},
        checkpoint=checkpoint.model_dump(mode="json"),
        session_memory="# Current State\n\na-02 is closed and free",
        recent_messages=[],
        max_tokens=64_000,
        recent_message_tokens=8_000,
    )
    assert "<session_memory>" in messages[1]["content"]
    assert "latest authoritative state" in messages[2]["content"]
    assert '"slot_occupied": true' in messages[2]["content"]
    assert '"completed_pending_release_codes"' in messages[2]["content"]


def test_context_rebuild_preserves_current_goal_when_it_exceeds_capacity() -> None:
    current_goal = "g" * 3_000_000
    messages = build_runtime_messages(
        base_system_prompt="fixed safety contract",
        initial_user_message={"role": "user", "content": current_goal},
        checkpoint={"run_id": "oversize"},
        session_memory="old summary",
        recent_messages=[],
        max_tokens=800_000,
        recent_message_tokens=96_000,
    )
    assert messages[0]["content"] == "fixed safety contract"
    assert messages[3]["content"] == current_goal
    assert message_token_count(messages) > 800_000


def test_skill_instructions_are_removed_from_summary_input_but_checkpointed() -> None:
    content_hash = "a" * 64
    checkpoint = Checkpoint(
        run_id="skill-run",
        active_skills=[
            ActiveSkillState(
                skill_id="common/direction",
                content_sha256=content_hash,
                activation_mode="model",
            )
        ],
    )
    assert checkpoint.schema_version == 2
    assert checkpoint.model_dump(mode="json")["active_skills"][0][
        "content_sha256"
    ] == content_hash

    messages = [
        {
            "role": "system",
            "content": (
                "fixed\n<active_skills>\n"
                f'<skill id="common/direction" sha256="{content_hash}">\n'
                "never-copy-this-skill-body\n</skill>\n</active_skills>"
            ),
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "invoke-one",
                    "function": {
                        "name": "skill_invoke",
                        "arguments": '{"skill_id":"common/direction"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "invoke-one",
            "content": json.dumps(
                {
                    "ok": True,
                    "data": {
                        "skill": {
                            "skill_id": "common/direction",
                            "content_sha256": content_hash,
                        },
                        "activation_status": "activated",
                        "instructions": "never-copy-this-tool-body",
                    },
                }
            ),
        },
    ]
    compacted = AgentRunner._compact_skill_messages(messages)
    encoded = json.dumps(compacted)
    assert "never-copy-this-skill-body" not in encoded
    assert "never-copy-this-tool-body" not in encoded
    assert "common/direction" in encoded
    assert content_hash in encoded


@pytest.mark.asyncio
async def test_concurrent_session_end_and_close_share_captured_summary_task(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3")
    runner = AgentRunner(
        _settings(),
        ToolRegistry([]),
        role="chief",
        agent_id="chief-summary-race",
        state_service=service,
    )
    release = asyncio.Event()

    async def summary() -> bool:
        await release.wait()
        return True

    captured = asyncio.create_task(summary())
    runner._summary_task = captured
    session_end = asyncio.create_task(runner._wait_for_summary())
    first_close = asyncio.create_task(runner.close())
    second_close = asyncio.create_task(runner.close())
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(session_end, first_close, second_close)
    assert captured.done()
    assert runner._summary_task is None

    cancelled = asyncio.Event()

    async def pending_summary() -> bool:
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    captured = asyncio.create_task(pending_summary())
    runner._summary_task = captured
    session_end = asyncio.create_task(runner._wait_for_summary())
    close = asyncio.create_task(runner.close())
    await asyncio.sleep(0)
    session_end.cancel()
    await asyncio.gather(session_end, close, return_exceptions=True)
    assert captured.cancelled()
    assert cancelled.is_set()
    assert runner._summary_task is None
    await service.close()


@pytest.mark.asyncio
async def test_summary_cursor_reads_only_the_next_hundred_events(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("cursor-run")
    chief = await service.register_agent("cursor-run", role="chief")
    sequences = await service.append_agent_events(
        "cursor-run",
        chief["agent_id"],
        [
            {"event_type": "cursor_fixture", "payload": {"index": index}}
            for index in range(2_100)
        ],
    )
    cursor = sequences[999]
    await service.update_agent_memory(
        "cursor-run",
        chief["agent_id"],
        DEFAULT_SESSION_MEMORY,
        summarized_through_sequence=cursor,
    )
    store = await AgentStateStore.open(
        service,
        run_id="cursor-run",
        agent_id=chief["agent_id"],
        run_dir=tmp_path / "cursor-run",
    )
    events = await store.load_events()
    assert len(events) == 100
    assert events[0].sequence == cursor + 1
    assert events[-1].sequence == cursor + 100
    await service.close()


@pytest.mark.asyncio
async def test_failed_summary_uses_micro_compaction_without_advancing_memory(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("micro-run")
    chief = await service.register_agent("micro-run", role="chief")
    await service.update_agent_memory(
        "micro-run",
        chief["agent_id"],
        DEFAULT_SESSION_MEMORY,
        summarized_through_sequence=1,
    )
    store = await AgentStateStore.open(
        service,
        run_id="micro-run",
        agent_id=chief["agent_id"],
        run_dir=tmp_path / "micro-run",
    )
    runner = AgentRunner(
        _settings(),
        ToolRegistry([]),
        role="chief",
        agent_id=chief["agent_id"],
        state_service=service,
    )
    runner._summary_failures = 3
    before_memory = await store.read_memory()
    before_cursor = store.checkpoint.last_summarized_event_sequence
    recent = await runner._compact(
        store,
        base_system_prompt="system",
        initial_user_message={"role": "user", "content": "goal"},
        messages=[
            {"role": "system", "content": "system"},
            {"role": "system", "content": "memory"},
            {"role": "system", "content": "checkpoint"},
            {"role": "user", "content": "goal"},
            {"role": "assistant", "content": "latest decision"},
        ],
        max_tokens=64_000,
        recent_message_tokens=8_000,
    )
    assert recent is not None
    assert await store.read_memory() == before_memory
    assert store.checkpoint.last_summarized_event_sequence == before_cursor
    events = await service.list_agent_events("micro-run", chief["agent_id"])
    event_types = [item["event_type"] for item in events]
    assert "context_micro_compacted" in event_types
    assert "context_compacted" not in event_types
    await runner.close()
    await service.close()


@pytest.mark.asyncio
async def test_role_checkpoint_does_not_duplicate_full_run_graph(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("compact-run")
    chief = await service.register_agent(
        "compact-run", role="chief", initial_prompt="coordinate"
    )
    await service.import_challenges(
        "compact-run",
        [
            {
                "unique_code": f"c-{index:02d}",
                "description": "long challenge description " * 40,
            }
            for index in range(63)
        ],
    )
    store = await AgentStateStore.open(
        service,
        run_id="compact-run",
        agent_id=chief["agent_id"],
        run_dir=tmp_path / "compact-run",
    )
    model_checkpoint = store.model_checkpoint()
    assert "targets" not in model_checkpoint
    assert "agents" not in model_checkpoint
    assert rough_token_count(model_checkpoint) < 1_000
    await service.close()


@pytest.mark.asyncio
async def test_execution_compaction_never_calls_model_summarizer(tmp_path: Path) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run(
        "execution-compact-run",
        challenges=[
            ChallengeImport(
                unique_code="compact-challenge",
                description="context compaction test",
            )
        ],
    )
    chief = await service.register_agent(
        "execution-compact-run", role="chief", initial_prompt="chief"
    )
    challenge = await service.register_agent(
        "execution-compact-run",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="compact-challenge",
        initial_prompt="challenge",
    )
    execution = await service.register_agent(
        "execution-compact-run",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="compact-challenge",
        mission="bounded task",
        initial_prompt="bounded task",
    )
    store = await AgentStateStore.open(
        service,
        run_id="execution-compact-run",
        agent_id=execution["agent_id"],
        run_dir=tmp_path / "execution-compact-run",
    )
    runner = AgentRunner(
        _settings(),
        ToolRegistry([]),
        role="execution",
        agent_id=execution["agent_id"],
        state_service=service,
    )
    update_summary = AsyncMock(side_effect=AssertionError("summary must not run"))
    runner._update_summary = update_summary  # type: ignore[method-assign]
    runner._schedule_summary(store, [], last_summary_tokens=48_000)
    assert runner._summary_task is None

    recent = await runner._compact(
        store,
        base_system_prompt="system",
        initial_user_message={"role": "user", "content": "assignment"},
        messages=[
            {"role": "system", "content": "system"},
            {"role": "system", "content": "memory"},
            {"role": "system", "content": "checkpoint"},
            {"role": "user", "content": "assignment"},
            *[
                {"role": "tool", "tool_call_id": f"call-{index}", "content": "x" * 2_000}
                for index in range(50)
            ],
            {"role": "assistant", "content": "prepare report"},
        ],
        max_tokens=64_000,
        recent_message_tokens=8_000,
        allow_model_summary=False,
    )
    assert recent is not None
    update_summary.assert_not_awaited()
    events = await service.list_agent_events(
        "execution-compact-run", execution["agent_id"]
    )
    assert any(
        item["event_type"] == "context_micro_compacted"
        and item["payload"]["reason"] == "execution_deterministic"
        for item in events
    )
    assert not any(item["event_type"] == "memory_update_failed" for item in events)
    await runner.close()
    await service.close()


@pytest.mark.asyncio
async def test_soft_context_is_sent_and_only_provider_capacity_is_hard(
    tmp_path: Path,
) -> None:
    requests = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = StateService(tmp_path / "state.sqlite3")
    runner: AgentRunner | None = None
    # Each request is over its role's soft target after calibration, but well
    # below the 983,616-token provider capacity.
    for index, (role, chars) in enumerate(
        (("chief", 750_000), ("challenge", 500_000), ("execution", 200_000)),
        start=1,
    ):
        runner = AgentRunner(
            _settings(),
            ToolRegistry([]),
            role=role,
            agent_id=role,
            state_service=service,
            http_client=client,
        )
        result = await runner._request_completion(
            client,
            [{"role": "user", "content": "x" * chars}],
            tool_definitions=[],
        )
        assert result["choices"][0]["message"]["content"] == "ok"
        assert requests == index

    assert runner is not None
    runner = AgentRunner(
        _settings(),
        ToolRegistry([]),
        role="chief",
        agent_id="chief-hard-limit",
        state_service=service,
        http_client=client,
    )
    with pytest.raises(AgentRunnerError) as blocked:
        await runner._request_completion(
            client,
            [{"role": "user", "content": "x" * 2_500_000}],
            tool_definitions=[],
        )
    assert blocked.value.code == "context_capacity_deferred"
    assert blocked.value.recoverable is True
    assert requests == 3
    await runner.close()
    await client.aclose()
    await service.close()


def test_chief_state_tools_refresh_the_durable_checkpoint() -> None:
    checkpoint = Checkpoint(run_id="run-one")
    AgentRunner._update_checkpoint_from_tool(
        checkpoint,
        "chief_observe",
        {
            "ok": True,
            "data": {
                "challenges": [
                    {
                        "unique_code": "a-02",
                        "is_completed": True,
                        "work_status": "completed",
                        "container_status": "stopped",
                        "slot_occupied": False,
                        "correct_flag_count": 1,
                        "flag_count": 1,
                        "total_score": 500,
                        "container_addr": [],
                    }
                ],
                "capacity": {
                    "limit": 3,
                    "occupied_count": 0,
                    "free_count": 3,
                    "occupied_codes": [],
                    "completed_pending_release_codes": [],
                },
            },
        },
    )
    assert checkpoint.targets[0].is_completed is True
    assert checkpoint.targets[0].status == "submitted"
    assert checkpoint.targets[0].slot_occupied is False
    assert checkpoint.container_capacity["free_count"] == 3


@pytest.mark.asyncio
async def test_same_model_summarizer_uses_no_tools() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        assert "tools" not in body
        assert body["model"] == "test-model"
        assert body["thinking"] == {"type": "disabled"}
        assert body["temperature"] == 0
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": DEFAULT_SESSION_MEMORY + "\n# Current State\nupdated"
                        }
                    }
                ]
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    summarizer = SessionMemorySummarizer(_settings(), client=client)
    result = await summarizer.summarize(
        current_memory=DEFAULT_SESSION_MEMORY,
        checkpoint={"run_id": "run-one", "status": "active"},
        recent_messages=[],
        recent_events=[],
    )
    await client.aclose()
    assert requests
    assert "# Current State" in result
    assert "# Worklog" in result


@pytest.mark.asyncio
async def test_deepseek_max_policy_preserves_reasoning_for_tool_roundtrip(
    tmp_path: Path,
) -> None:
    fake_tools = _FakeTools(
        {"system_read_file": {"ok": True, "data": {"content": "ok"}}}
    )
    settings = _settings(llm_model="deepseek-v4-flash")
    requests: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "reasoning_content": "private reasoning",
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "system_read_file",
                                            "arguments": '{"file_path":"README.md"}',
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 4},
                },
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "done"},
                    }
                ],
                "usage": {"prompt_tokens": 30, "completion_tokens": 2},
            },
        )

    run_root = tmp_path / "runs"
    service = StateService(run_root / "deepseek" / "state.sqlite3", run_root=run_root)
    await service.create_run("deepseek", model=settings.llm_model, prompt="task")
    agent = await service.register_agent("deepseek", role="chief", initial_prompt="task")
    await service.transition_controller("deepseek", agent["agent_id"], "running")
    store = await AgentStateStore.open(
        service,
        run_id="deepseek",
        agent_id=agent["agent_id"],
        run_dir=run_root / "deepseek",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runner = AgentRunner(
        settings,
        ToolRegistry([fake_tools]),
        http_client=client,
        run_root=run_root,
        state_service=service,
        agent_id=agent["agent_id"],
        role="chief",
    )

    result = await runner.run_session("task", store=store)
    assert result.final == "done"
    assert requests[0]["thinking"] == {"type": "enabled"}
    assert requests[0]["reasoning_effort"] == "max"
    assert requests[0]["max_tokens"] == 32_768
    assert "temperature" not in requests[0]
    assert "tool_choice" not in requests[0]
    assistant = next(
        item
        for item in requests[1]["messages"]
        if item.get("role") == "assistant" and item.get("tool_calls")
    )
    assert assistant["content"] == ""
    assert assistant["reasoning_content"] == "private reasoning"
    events = await service.list_agent_events("deepseek", agent["agent_id"])
    assert "private reasoning" not in json.dumps(events)

    await runner.close()
    await client.aclose()
    await service.close()


@pytest.mark.asyncio
async def test_deepseek_tool_call_without_reasoning_is_rejected_before_handler(
    tmp_path: Path,
) -> None:
    fake_tools = _FakeTools({"system_read_file": {"ok": True, "data": {}}})
    settings = _settings(llm_model="deepseek-v4-flash")

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-missing-reasoning",
                                    "type": "function",
                                    "function": {
                                        "name": "system_read_file",
                                        "arguments": '{"file_path":"README.md"}',
                                    },
                                }
                            ],
                        },
                    }
                ]
            },
        )

    run_root = tmp_path / "runs"
    service = StateService(run_root / "missing" / "state.sqlite3", run_root=run_root)
    await service.create_run("missing", model=settings.llm_model, prompt="task")
    agent = await service.register_agent("missing", role="chief", initial_prompt="task")
    await service.transition_controller("missing", agent["agent_id"], "running")
    store = await AgentStateStore.open(
        service,
        run_id="missing",
        agent_id=agent["agent_id"],
        run_dir=run_root / "missing",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runner = AgentRunner(
        settings,
        ToolRegistry([fake_tools]),
        http_client=client,
        run_root=run_root,
        state_service=service,
        agent_id=agent["agent_id"],
        role="chief",
    )

    with pytest.raises(AgentRunnerError) as failure:
        await runner.run_session("task", store=store)
    assert failure.value.code == "invalid_llm_response"
    assert fake_tools.calls == []

    await runner.close()
    await client.aclose()
    await service.close()


class _FakeTools:
    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def tool_specs(self) -> list[ToolSpec]:
        class ReadArguments(BaseModel):
            model_config = ConfigDict(extra="forbid", strict=True)
            file_path: str

        async def handler(arguments: BaseModel) -> dict[str, Any]:
            values = arguments.model_dump()
            self.calls.append(("system_read_file", values))
            return self.responses.get("system_read_file", {"ok": True, "data": {}})

        return [ToolSpec("system_read_file", "test", ReadArguments, handler, lambda _arguments: ())]

    async def close(self) -> None:
        return None


class _ControllerWaitTools:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def tool_specs(self) -> list[ToolSpec]:
        class EmptyArguments(BaseModel):
            model_config = ConfigDict(extra="forbid", strict=True)

        specs = []
        for name in ("challenge_wait", "challenge_observe"):
            async def handler(arguments: BaseModel, *, tool_name: str = name) -> Any:
                self.calls.append(tool_name)
                result = {"ok": True, "data": {"name": tool_name}}
                if tool_name == "challenge_wait":
                    return ToolDispatchOutcome(result=result, yield_session=True)
                return result

            specs.append(
                ToolSpec(
                    name,
                    "test",
                    EmptyArguments,
                    handler,
                    access_claims=lambda _arguments: (),
                    requires_solo=name == "challenge_wait",
                )
            )
        return specs

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_runner_persists_tool_loop_without_persisting_api_key(tmp_path: Path) -> None:
    fake_tools = _FakeTools({"system_read_file": {"ok": True, "data": {"content": "ok"}}})
    registry = ToolRegistry([fake_tools])
    settings = _settings()
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "system_read_file",
                                            "arguments": '{"file_path":"README.md"}',
                                        },
                                    }
                                ],
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 100},
                },
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "done"}}]},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = StateService(
        tmp_path / "runs" / "run-agent" / "state.sqlite3",
        run_root=tmp_path / "runs",
    )
    await service.create_run(
        "run-agent",
        model=settings.llm_model,
        prompt="complete local task",
    )
    chief = await service.register_agent(
        "run-agent", role="chief", initial_prompt="complete local task"
    )
    await service.transition_controller("run-agent", chief["agent_id"], "running")
    store = await AgentStateStore.open(
        service,
        run_id="run-agent",
        agent_id=chief["agent_id"],
        run_dir=tmp_path / "runs" / "run-agent",
    )
    runner = AgentRunner(
        settings,
        registry,
        http_client=client,
        run_root=tmp_path / "runs",
        state_service=service,
        agent_id=chief["agent_id"],
        role="chief",
    )
    result = await runner.run_session("complete local task", store=store)
    assert result.final == "done"
    assert result.structured_report_seen is False
    assert fake_tools.calls == [("system_read_file", {"file_path": "README.md"})]
    assert runner.agent_id is not None
    events = await service.list_agent_events("run-agent", runner.agent_id)
    event_text = json.dumps(events)
    assert "test-api-key" not in event_text
    await runner.close()
    await service.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_controller_wait_yields_without_an_extra_model_round(tmp_path: Path) -> None:
    tools = _ControllerWaitTools()
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "wait-1",
                                    "type": "function",
                                    "function": {
                                        "name": "challenge_wait",
                                        "arguments": "{}",
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

    run_root = tmp_path / "runs"
    service = StateService(
        run_root / "controller-wait" / "state.sqlite3", run_root=run_root
    )
    await service.create_run("controller-wait", model="test-model", prompt="wait")
    agent = await service.register_agent(
        "controller-wait", role="chief", initial_prompt="wait"
    )
    store = await AgentStateStore.open(
        service,
        run_id="controller-wait",
        agent_id=agent["agent_id"],
        run_dir=run_root / "controller-wait",
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runner = AgentRunner(
        _settings(),
        ToolRegistry([tools]),
        http_client=client,
        run_root=run_root,
        state_service=service,
        agent_id=agent["agent_id"],
        role="chief",
    )

    result = await runner.run_session("wait", store=store)
    assert result.yield_reason == "controller_wait"
    assert requests == 1
    assert tools.calls == ["challenge_wait"]

    tool_messages, requested_yield = await runner._execute_tool_calls(
        store,
        [
            {
                "id": "wait-parallel",
                "type": "function",
                "function": {"name": "challenge_wait", "arguments": "{}"},
            },
            {
                "id": "state-parallel",
                "type": "function",
                "function": {"name": "challenge_observe", "arguments": "{}"},
            },
        ],
    )
    assert requested_yield is False
    rejected = json.loads(tool_messages[0]["content"])
    assert rejected["error"]["code"] == "solo_tool_must_be_only_call"
    blocked = json.loads(tool_messages[1]["content"])
    assert blocked["error"]["code"] == "blocked_by_solo_tool"
    assert tools.calls == ["challenge_wait"]

    await runner.close()
    await client.aclose()
    await service.close()
