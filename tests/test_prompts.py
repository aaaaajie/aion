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
        "bootstrap_agent.txt",
        "bootstrap_system.txt",
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
    assert "easy challenges before medium or hard" in prompt
    assert "priority overrides any Web-category" in prompt
    assert "preference during early" in prompt


@pytest.mark.parametrize("role", ["chief", "challenge", "execution"])
def test_role_system_prompts_include_shared_base_prompt(role: str) -> None:
    base = load_prompt("base_system.txt")
    role_prompt = system_prompt(role)

    assert role_prompt.endswith("\n\n" + base)
    assert role_prompt.startswith(load_prompt(f"{role}_system.txt"))


def test_chief_system_prompt_prioritizes_difficulty_during_early_phase() -> None:
    prompt = system_prompt("chief")

    assert "During the early phase, difficulty takes priority over category" in prompt
    assert "Do not let Web preference override this early-phase ordering" in prompt


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
    assert "ranking signals, not activation commands" in prompt
    assert "solo first-turn" not in prompt
    assert "requires a solo" not in prompt
    assert "execution_report" in prompt
    assert "evidence_refs" in prompt
    assert "AION_AGENT_WORKDIR" in prompt
    assert "AION_SHARED_WORKDIR" in prompt
    assert "screenshot.png" in prompt


def test_bootstrap_prompt_is_flag_first_and_checkpoint_aware() -> None:
    prompt = load_prompt("bootstrap_agent.txt")
    system = system_prompt("bootstrap")

    assert "240 seconds" in prompt
    assert "final 30 seconds" in prompt
    assert "candidate_flag" in prompt
    assert "bootstrap_checkpoint" in prompt
    assert "Generic reconnaissance" in prompt
    assert "Do not stop or restart solely" not in prompt
    assert "bootstrap_checkpoint" in system
    assert "AION_AGENT_WORKDIR" in prompt
    assert "AION_SHARED_WORKDIR" in system
    assert "captcha.png" in prompt


def test_execution_prompt_prioritizes_bounded_sqlmap_for_exact_parameters() -> None:
    system = system_prompt("execution")
    agent = load_prompt("execution_agent.txt")

    for prompt in (system, agent):
        assert "pentest_sqlmap" in prompt
        assert "exact" in prompt
        assert "Do not repeat" in prompt or "repeat the same arguments" in prompt
        assert "level=1" in prompt
        assert "risk=1" in prompt

    assert "bare landing page" in system
    assert "capture it with the HTTP tools first" in agent


def test_prompt_loader_rejects_missing_templates() -> None:
    with pytest.raises(RuntimeError, match="missing"):
        load_prompt("does-not-exist.txt")
