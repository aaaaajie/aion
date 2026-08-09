"""Production prompt resources are centralized and renderable."""

from __future__ import annotations

import json

import pytest

from agent.prompts import load_prompt, render_prompt, system_prompt
from agent.runner import default_chief_prompt


def test_all_production_prompt_resources_are_available() -> None:
    names = (
        "base_system.txt",
        "chief_system.txt",
        "chief_agent.txt",
        "challenge_system.txt",
        "execution_system.txt",
        "challenge_agent.txt",
        "execution_agent.txt",
        "session_memory_system.txt",
        "exploration_mission.txt",
    )
    assert all(load_prompt(name).strip() for name in names)
    assert "long-running" in system_prompt("challenge")


def test_default_chief_prompt_is_centrally_managed() -> None:
    prompt = default_chief_prompt()
    assert prompt == load_prompt("chief_agent.txt")
    assert "benchmark_list_challenges" in prompt
    assert "multiple Flags" in prompt


def test_challenge_prompt_requires_a_persistent_report_loop() -> None:
    prompt = render_prompt(
        "challenge_agent.txt",
        challenge_data=json.dumps({"unique_code": "web-1"}),
    )
    assert "one-shot task" in prompt
    assert "A consumed report" in prompt
    assert "challenge_data" in prompt


def test_execution_prompt_explains_http_tool_selection_and_lifecycle() -> None:
    prompt = system_prompt("execution")
    assert "system_http_request" in prompt
    assert "system_http_probe" in prompt
    assert "system_http_output" in prompt
    assert "Never call" in prompt
    assert "Session" in prompt
    assert "system_http_cleanup" in prompt


def test_prompt_loader_rejects_missing_templates() -> None:
    with pytest.raises(RuntimeError, match="missing"):
        load_prompt("does-not-exist.txt")
