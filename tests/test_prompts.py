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


@pytest.mark.parametrize("role", ["chief", "challenge", "execution"])
def test_role_system_prompts_include_shared_base_prompt(role: str) -> None:
    base = load_prompt("base_system.txt")
    role_prompt = system_prompt(role)

    assert role_prompt.endswith("\n\n" + base)
    assert role_prompt.startswith(load_prompt(f"{role}_system.txt"))


def test_challenge_prompt_requires_a_persistent_report_loop() -> None:
    prompt = render_prompt(
        "challenge_agent.txt",
        challenge_data=json.dumps({"unique_code": "web-1"}),
    )
    assert "one-shot task" in prompt
    assert "consume every" in prompt.lower()
    assert "challenge_wait_for_state" in prompt
    assert "challenge_data" in prompt
    system = system_prompt("challenge")
    assert "recognize-challenge-direction" in system
    assert "skill_list" in system
    assert "common/" in system
    assert "Never preload" in system


def test_challenge_prompt_prefers_breadth_first_parallel_decomposition() -> None:
    prompt = load_prompt("challenge_agent.txt")
    system = system_prompt("challenge")

    assert "breadth-first" in prompt
    assert "In every planning cycle" in prompt
    assert "Do not impose an arbitrary minimum or" in prompt
    assert "resulting task set" in prompt
    assert "Resources are intentionally abundant" in system
    assert "limits only one discovery pivot" in system
    assert "validation/exploitation concurrency" in system


def test_execution_prompt_explains_http_tool_selection_and_lifecycle() -> None:
    prompt = system_prompt("execution")
    assert "system_http_request" in prompt
    assert "system_http_probe" in prompt
    assert "system_http_output" in prompt
    assert "Never call" in prompt
    assert "Session" in prompt
    assert "system_http_cleanup" in prompt
    assert "run_in_background=true" in prompt
    assert "system_task_output(wait_seconds=...)" in prompt
    assert "nohup" in prompt
    assert "for + curl" in prompt
    assert "skill_list" in prompt
    assert "skill_read" in prompt
    assert "$AION_SKILLS_ROOT" in prompt
    assert "$AION_PYTHON" in prompt


def test_prompt_loader_rejects_missing_templates() -> None:
    with pytest.raises(RuntimeError, match="missing"):
        load_prompt("does-not-exist.txt")
