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
    assert "timed challenge" in system_prompt("challenge")


def test_default_chief_prompt_is_centrally_managed() -> None:
    prompt = default_chief_prompt()
    assert prompt == load_prompt("chief_agent.txt")
    assert "chief_launch_challenges" in prompt
    assert "chief_wait" in prompt
    assert "restart_required" in prompt
    assert "stagnation_paused" in prompt


@pytest.mark.parametrize("role", ["chief", "challenge", "execution"])
def test_role_system_prompts_include_shared_base_prompt(role: str) -> None:
    base = load_prompt("base_system.txt")
    role_prompt = system_prompt(role)

    assert role_prompt.endswith("\n\n" + base)
    assert role_prompt.startswith(load_prompt(f"{role}_system.txt"))


def test_challenge_prompt_requires_a_lightweight_report_loop() -> None:
    prompt = render_prompt(
        "challenge_agent.txt",
        challenge_data=json.dumps({"unique_code": "web-1"}),
    )
    assert "challenge_dispatch" in prompt
    assert "challenge_wait" in prompt
    assert "lightweight" in prompt
    assert "challenge_data" in prompt
    system = system_prompt("challenge")
    assert "direction Skill is already active" in system
    assert "challenge/challenge-threat-modeling Skill is available" in system
    assert "do not invoke it merely to restate state" in system
    assert "skill_invoke" in system
    assert "skill_resource_read" in system
    assert "Copy report" in system
    assert "untrusted data" in system


def test_challenge_prompt_prefers_parallel_independent_work() -> None:
    prompt = load_prompt("challenge_agent.txt")
    system = system_prompt("challenge")

    assert "useful independent work" in prompt
    assert "stable task_key" in prompt
    assert "ENTRY_UNREACHABLE" in prompt
    assert "BRANCH_EXHAUSTED" in system
    assert "Similar work is" not in prompt
    assert "low-yield" in prompt
    assert "episode" in prompt
    assert "kind=exploration" in prompt
    assert "second exploration" in prompt
    assert "slow Execution never blocks" in system
    assert "low_yield=true" in system


def test_execution_prompt_starts_work_without_management_rounds() -> None:
    prompt = system_prompt("execution")
    assert "first request already contains" in prompt
    assert "Start useful technical work immediately" in prompt
    assert "execution_report" in prompt
    assert "evidence_refs" in prompt


def test_prompt_loader_rejects_missing_templates() -> None:
    with pytest.raises(RuntimeError, match="missing"):
        load_prompt("does-not-exist.txt")
