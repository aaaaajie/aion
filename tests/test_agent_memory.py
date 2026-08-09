"""Offline tests for the single-run Agent memory and context layer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from agent.config import AgentSettings, ContextBudget
from agent.memory.context import (
    build_runtime_messages,
    message_token_count,
    normalize_session_memory,
    rough_token_count,
    should_autocompact,
    should_update_memory,
    tool_result_for_model,
)
from agent.memory.models import Checkpoint, OperationState, TargetState
from agent.memory.redaction import redact_tool_payload, redact_value
from agent.memory.summarizer import SessionMemorySummarizer
from agent.runner import AgentRunner, ToolRegistry
from agent.state import AgentStateStore, StateService
from agent.state.models import DEFAULT_SESSION_MEMORY


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
    assert budget.autocompact_threshold == 967_000
    assert _settings().context_budget.context_window_tokens == 1_000_000


def test_context_window_override_is_optional_and_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AION_CONTEXT_WINDOW_TOKENS", "50000")
    assert _settings().context_window_tokens == 50_000

    monkeypatch.setenv("AION_CONTEXT_WINDOW_TOKENS", "100")
    with pytest.raises(ValidationError):
        _settings()


def test_sensitive_payloads_are_redacted_without_losing_safe_metadata() -> None:
    payload = {
        "flag": "flag{secret-value}",
        "BENCHMARK_TOKEN": "benchmark-secret",
        "nested": {"authorization": "Bearer api-secret"},
    }
    redacted = redact_tool_payload(
        "benchmark_submit_flag",
        payload,
        secrets=("api-secret",),
    )
    encoded = json.dumps(redacted)
    assert "flag{secret-value}" not in encoded
    assert "benchmark-secret" not in encoded
    assert "api-secret" not in encoded
    assert redacted["flag"]["redacted"] is True
    assert redact_value("api-secret", secrets=("api-secret",)) == "[REDACTED]"


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
    )
    assert should_update_memory(
        current_tokens=50_000,
        last_summary_tokens=1,
        tool_calls_since_summary=20,
    )
    assert should_autocompact(967_000, ContextBudget())


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
    )
    assert "<session_memory>" in messages[1]["content"]
    assert "latest authoritative state" in messages[2]["content"]
    assert '"slot_occupied": true' in messages[2]["content"]
    assert '"completed_pending_release_codes"' in messages[2]["content"]


def test_chief_state_tools_refresh_the_durable_checkpoint() -> None:
    checkpoint = Checkpoint(run_id="run-one")
    AgentRunner._update_checkpoint_from_tool(
        checkpoint,
        "chief_get_core_state",
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
                "container_capacity": {
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


class _FakeTools:
    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "system_read_file",
                    "description": "test",
                    "parameters": {
                        "type": "object",
                        "properties": {"file_path": {"type": "string"}},
                        "required": ["file_path"],
                        "additionalProperties": False,
                    },
                },
            }
        ]

    async def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        return self.responses.get(name, {"ok": True, "data": {}})

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
