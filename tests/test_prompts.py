"""Production role prompts and resources reflect the current protocol."""

import json
import pytest
from agent.prompts import load_prompt, render_prompt, system_prompt
from agent.runner import default_chief_prompt


@pytest.mark.parametrize("role", ["chief", "solver", "worker", "review"])
def test_role_prompt_includes_shared_base(role):
    assert system_prompt(role).endswith("\n\n" + load_prompt("base_system.txt"))


def test_solver_direct_execution_and_partial_completion():
    prompt = render_prompt(
        "solver_agent.txt", challenge_data=json.dumps({"unique_code": "a"})
    )
    assert "a" in prompt
    system = system_prompt("solver")
    for term in [
        "solver_submit_flag",
        "solver_wait",
        "solver_delegate",
        "task_key",
        "partially",
        "technical",
        "untrusted data",
    ]:
        assert term in system


def test_chief_controls_are_explicit():
    prompt = default_chief_prompt()
    for tool in [
        "chief_launch_challenges",
        "chief_pause_challenges",
        "chief_close_challenges",
        "chief_wait",
    ]:
        assert tool in prompt
    for removed in [
        "restart_required",
        "stagnation_paused",
        "Bootstrap",
        "Observer",
        "quiescence",
    ]:
        assert removed not in prompt


def test_chief_uses_full_catalog_without_fixed_challenge_allowlist():
    prompt = default_chief_prompt()
    assert "complete challenge catalog" in prompt
    assert "full challenge directory" in prompt
    assert "Do not impose a fixed challenge-code allowlist" in prompt
    for code in ["a-03", "a-05", "a-18"]:
        assert code not in prompt


def test_worker_continuity_and_technical_rules():
    prompt = system_prompt("worker")
    for term in [
        "worker_update",
        "worker_report",
        "same task",
        "tested and untested",
        "evidence_refs",
        "AION_AGENT_WORKDIR",
        "AION_SHARED_WORKDIR",
    ]:
        assert term in prompt


def test_review_has_read_only_contract():
    prompt = system_prompt("review")
    assert "read" in prompt and "worker_report" in prompt


def test_missing_prompt_is_an_error():
    with pytest.raises(RuntimeError, match="missing"):
        load_prompt("does-not-exist.txt")
