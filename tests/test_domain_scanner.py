"""Low-cost challenge domain triage and atomic contract tests."""

from __future__ import annotations

import json

import pytest

from agent.state.schemas import ExecutionTaskInput
from scan.contracts import (
    TASK_CONTRACT_END,
    TASK_CONTRACT_START,
    dependency_batches,
    extract_task_contract,
)
from scan.domain import assess_probe_reports, classify_challenge
from scan.registry import (
    COMPETITION_SCANNER_REGISTRY,
    SCANNER_REGISTRY,
    SKILL_ID_FOR_DOMAIN,
    build_first_round_tasks,
    scanner_for,
    skill_for_domain,
)


@pytest.mark.parametrize(
    ("challenge", "domain", "subdomain", "profile"),
    [
        (
            {
                "unique_code": "web-sqli",
                "description": "Inspect a Flask HTTP API for SQL injection",
                "container_addr": ["http://127.0.0.1:8000"],
            },
            "web",
            None,
            "web_light",
        ),
        (
            {
                "unique_code": "evm-vault",
                "description": "Audit the Solidity smart contract with Foundry",
                "container_addr": ["http://127.0.0.1:8545"],
            },
            "blockchain",
            None,
            "blockchain_light",
        ),
        (
            {
                "unique_code": "llm-prompt",
                "description": "Analyze prompt injection against a RAG language model",
            },
            "ai",
            None,
            "ai_light",
        ),
        (
            {
                "unique_code": "elf-reverse",
                "description": "Reverse engineer an ELF binary and inspect its architecture",
            },
            "other",
            "reverse",
            "binary_light",
        ),
    ],
)
def test_high_confidence_metadata_selects_one_profile(
    challenge: dict[str, object], domain: str, subdomain: str | None, profile: str
) -> None:
    result = classify_challenge(challenge)
    assert result.decision == "direct"
    assert result.domain == domain
    assert result.subdomain == subdomain
    assert result.scanner_profile == profile
    assert result.confidence >= 0.75


def test_unknown_metadata_requests_only_domain_probes() -> None:
    result = classify_challenge(
        {"unique_code": "challenge-17", "description": "Find the hidden Flag"}
    )
    assert result.decision == "probe"
    assert result.domain is None
    assert set(result.candidate_domains) == {"web", "blockchain", "ai", "other"}


def test_model_api_shapes_outweigh_plain_http_transport() -> None:
    result = classify_challenge(
        {
            "unique_code": "gateway-17",
            "description": (
                'POST body uses "messages": and "model":; '
                'response exposes "choices": and "usage":'
            ),
            "container_addr": ["http://127.0.0.1:8000/v1/chat/completions"],
        }
    )
    assert result.decision == "direct"
    assert result.domain == "ai"
    assert result.scanner_profile == "ai_light"
    assert "target_addresses:model_api_path" in result.evidence
    assert result.scores["ai"] > result.scores["web"]


def test_traditional_business_surface_remains_web() -> None:
    result = classify_challenge(
        {
            "unique_code": "portal-17",
            "description": "Traditional login, register, upload, download and CMS admin panel",
            "container_addr": ["http://127.0.0.1:8080"],
        }
    )
    assert result.decision == "direct"
    assert result.domain == "web"
    assert "description:web_business_surface" in result.evidence


@pytest.mark.parametrize(
    ("domain", "profile", "expected_tools"),
    [
        (
            "web",
            "web_light",
            {
                "execution_get_assignment",
                "system_web_fingerprint",
                "system_http_output",
                "system_http_analyze",
                "system_read_file",
                "system_glob",
                "system_grep",
                "execution_report",
            },
        ),
        (
            "blockchain",
            "blockchain_light",
            {
                "execution_get_assignment",
                "system_read_file",
                "system_glob",
                "system_grep",
                "system_http_request",
                "system_http_output",
                "system_http_analyze",
                "execution_report",
            },
        ),
        (
            "ai",
            "ai_light",
            {
                "execution_get_assignment",
                "system_read_file",
                "system_glob",
                "system_grep",
                "system_http_request",
                "system_http_output",
                "system_http_analyze",
                "system_http_response",
                "execution_report",
            },
        ),
        (
            "other",
            "binary_light",
            {
                "execution_get_assignment",
                "system_read_file",
                "system_list_directory",
                "system_glob",
                "system_shell",
                "system_task_output",
                "execution_report",
            },
        ),
    ],
)
def test_four_domain_scanners_are_registered_and_emit_valid_atomic_tasks(
    domain: str, profile: str, expected_tools: set[str]
) -> None:
    assert set(COMPETITION_SCANNER_REGISTRY) == {
        "web",
        "blockchain",
        "ai",
        "other",
    }
    assert set(SCANNER_REGISTRY) == {
        "web",
        "blockchain",
        "ai",
        "binary",
        "other",
    }
    scanner = scanner_for(domain)  # type: ignore[arg-type]
    assert scanner.domain == domain
    assert scanner.scanner_profile == profile

    tasks = build_first_round_tasks(
        domain,  # type: ignore[arg-type]
        unique_code="fixture-1",
        target_scope=["TARGET"],
        description="中文调试题目描述",
        evidence_refs=["observation:fixture"],
    )
    assert len(tasks) == 2
    expected_task_fields = {
        "task_key",
        "hypothesis_key",
        "branch_key",
        "kind",
        "task_phase",
        "entry_point",
        "capability_class",
        "verification_question",
        "objective",
        "target_scope",
        "tool_names",
        "priority",
        "success_criteria",
        "failure_criteria",
        "evidence_requirements",
        "stop_conditions",
        "depends_on",
        "scanner_profile",
        "cost_class",
        "context_refs",
        "max_http_requests",
        "max_shell_tasks",
        "max_network_tasks",
        "timeout_seconds",
    }
    assert len({task["task_key"] for task in tasks}) == 2
    assert {
        tool_name
        for task in tasks
        for tool_name in task["tool_names"]
    } == expected_tools
    for task in tasks:
        assert set(task) == expected_task_fields
        assert task["scanner_profile"] == profile
        assert task["target_scope"] == ["TARGET"]
        assert task["context_refs"] == ["observation:fixture"]
        assert task["cost_class"] == "low"
        assert task["timeout_seconds"] in {180, 300}
        assert ExecutionTaskInput.model_validate(task).task_key == task["task_key"]
    skill_id = SKILL_ID_FOR_DOMAIN[domain]  # type: ignore[index]
    definition = skill_for_domain(domain)  # type: ignore[arg-type]
    assert definition.manifest.id == skill_id
    assert set(definition.manifest.requires.tools) == expected_tools


def test_probe_reports_require_a_clear_positive_margin() -> None:
    direct = assess_probe_reports(
        [
            {
                "domain": "web",
                "is_match": True,
                "confidence": 0.92,
                "status": "completed",
                "evidence_ref": "report:web",
            },
            {
                "domain": "ai",
                "is_match": False,
                "confidence": 0.8,
                "status": "completed",
                "evidence_ref": "report:ai",
            },
        ]
    )
    assert direct.decision == "direct"
    assert direct.domain == "web"
    assert direct.scanner_profile == "web_light"

    review = assess_probe_reports(
        [
            {"domain": "web", "is_match": True, "confidence": 0.8},
            {"domain": "ai", "is_match": True, "confidence": 0.72},
        ]
    )
    assert review.decision == "review"


def test_dependency_batches_are_parallel_and_cycle_checked() -> None:
    tasks = [
        {"task_key": "metadata", "depends_on": []},
        {"task_key": "headers", "depends_on": []},
        {"task_key": "verify", "depends_on": ["metadata", "headers"]},
    ]
    assert dependency_batches(tasks) == [["headers", "metadata"], ["verify"]]
    with pytest.raises(ValueError, match="cycle"):
        dependency_batches(
            [
                {"task_key": "a", "depends_on": ["b"]},
                {"task_key": "b", "depends_on": ["a"]},
            ]
        )


def test_task_contract_is_recoverable_from_persisted_prompt() -> None:
    contract = {
        "task_key": "one-check",
        "scanner_profile": "web_light",
        "tool_names": ["system_http_request"],
    }
    prompt = (
        f"{TASK_CONTRACT_START}\n"
        f"{json.dumps(contract)}\n"
        f"{TASK_CONTRACT_END}"
    )
    assert extract_task_contract(prompt) == contract
