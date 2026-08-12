"""Scanner profiles and durable contracts for one atomic execution task."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Mapping, Protocol, Sequence

CompetitionDomainName = Literal["web", "blockchain", "ai", "other"]
DomainName = Literal["web", "blockchain", "ai", "binary", "other"]
DomainSubtype = Literal["binary", "pwn", "reverse", "forensics", "cryptography"]
ScannerProfileName = Literal[
    "web_light",
    "blockchain_light",
    "ai_light",
    "binary_light",
    "other_light",
    "domain_recognition",
]
CostClass = Literal["low", "medium", "high"]
TaskPhase = Literal[
    "domain_recognition",
    "reconnaissance",
    "validation",
    "exploitation",
    "flag_acquisition",
]

EXECUTION_CONTROL_TOOLS = frozenset(
    {
        "execution_get_assignment",
        "execution_update_progress",
        "execution_report",
    }
)
READ_ONLY_FILE_TOOLS = frozenset(
    {
        "system_read_file",
        "system_list_directory",
        "system_glob",
        "system_grep",
    }
)
MUTATING_FILE_TOOLS = frozenset(
    {
        "system_write_file",
        "system_edit_file",
        "system_create_directory",
        "system_delete_path",
    }
)
SHELL_TOOLS = frozenset(
    {
        "system_shell",
        "system_task_output",
        "system_task_stop",
        "system_task_cleanup",
    }
)
HTTP_SINGLE_TOOLS = frozenset(
    {
        "system_http_request",
        "system_http_analyze",
        "system_http_output",
        "system_http_response",
        "system_http_stop",
        "system_http_cleanup",
    }
)
HTTP_DISCOVERY_TOOLS = frozenset(
    {
        "system_http_probe",
        "system_web_path_probe",
        "system_web_fingerprint",
    }
)
NETWORK_TOOLS = frozenset(
    {
        "system_network_discovery",
        "system_network_output",
        "system_network_stop",
        "system_network_cleanup",
    }
)
HTTP_WORK_TOOLS = frozenset(
    {
        "system_http_request",
        "system_http_probe",
        "system_web_path_probe",
        "system_web_fingerprint",
    }
)
SHELL_WORK_TOOLS = frozenset({"system_shell"})
NETWORK_WORK_TOOLS = frozenset({"system_network_discovery"})


@dataclass(frozen=True)
class ScannerProfile:
    name: ScannerProfileName
    domain: DomainName | None
    description: str
    allowed_tools: frozenset[str]


@dataclass(frozen=True)
class ScannerContext:
    """Metadata passed to a domain scanner planner; no network request is made here."""

    unique_code: str
    target_scope: tuple[str, ...]
    description: str = ""
    evidence_refs: tuple[str, ...] = ()
    observations: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class ScannerTaskSpec:
    """One first-round task produced by a lightweight scanner planner."""

    task_key: str
    hypothesis_key: str
    branch_key: str
    kind: str
    task_phase: TaskPhase
    entry_point: str
    capability_class: str
    verification_question: str
    objective: str
    target_scope: tuple[str, ...]
    tool_names: tuple[str, ...]
    priority: int
    success_criteria: tuple[str, ...]
    failure_criteria: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    scanner_profile: ScannerProfileName
    cost_class: CostClass
    context_refs: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    max_http_requests: int = 0
    max_shell_tasks: int = 0
    max_network_tasks: int = 0
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        validate_profile_tools(self.scanner_profile, self.tool_names)
        values = (
            self.target_scope,
            self.tool_names,
            self.success_criteria,
            self.failure_criteria,
            self.evidence_requirements,
            self.stop_conditions,
        )
        if any(not item.strip() for group in values for item in group):
            raise ValueError("scanner task contract items must not be blank")
        if any(
            not value.strip()
            for value in (
                self.entry_point,
                self.capability_class,
                self.verification_question,
                self.objective,
            )
        ):
            raise ValueError("scanner task atomic fields must not be blank")
        if min(
            self.max_http_requests,
            self.max_shell_tasks,
            self.max_network_tasks,
        ) < 0:
            raise ValueError("scanner task budgets must not be negative")
        validate_task_budgets(
            self.tool_names,
            max_http_requests=self.max_http_requests,
            max_shell_tasks=self.max_shell_tasks,
            max_network_tasks=self.max_network_tasks,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_key": self.task_key,
            "hypothesis_key": self.hypothesis_key,
            "branch_key": self.branch_key,
            "kind": self.kind,
            "task_phase": self.task_phase,
            "entry_point": self.entry_point,
            "capability_class": self.capability_class,
            "verification_question": self.verification_question,
            "objective": self.objective,
            "target_scope": list(self.target_scope),
            "tool_names": list(self.tool_names),
            "priority": self.priority,
            "success_criteria": list(self.success_criteria),
            "failure_criteria": list(self.failure_criteria),
            "evidence_requirements": list(self.evidence_requirements),
            "stop_conditions": list(self.stop_conditions),
            "depends_on": list(self.depends_on),
            "scanner_profile": self.scanner_profile,
            "cost_class": self.cost_class,
            "context_refs": list(self.context_refs),
            "max_http_requests": self.max_http_requests,
            "max_shell_tasks": self.max_shell_tasks,
            "max_network_tasks": self.max_network_tasks,
            "timeout_seconds": self.timeout_seconds,
        }


class LightScanner(Protocol):
    """Stable interface implemented by each domain-specific task planner."""

    domain: DomainName
    scanner_profile: ScannerProfileName

    def build_first_round(self, context: ScannerContext) -> list[ScannerTaskSpec]:
        ...


_FILES = READ_ONLY_FILE_TOOLS | MUTATING_FILE_TOOLS
_HTTP = HTTP_SINGLE_TOOLS | HTTP_DISCOVERY_TOOLS
_FULL_EXECUTION = (
    EXECUTION_CONTROL_TOOLS | _FILES | SHELL_TOOLS | _HTTP | NETWORK_TOOLS
)

SCANNER_PROFILES: dict[ScannerProfileName, ScannerProfile] = {
    "web_light": ScannerProfile(
        name="web_light",
        domain="web",
        description="HTTP fingerprinting, bounded path discovery, and one-purpose web checks.",
        allowed_tools=EXECUTION_CONTROL_TOOLS
        | _FILES
        | SHELL_TOOLS
        | _HTTP
        | NETWORK_TOOLS,
    ),
    "blockchain_light": ScannerProfile(
        name="blockchain_light",
        domain="blockchain",
        description="Contract/source inspection and bounded RPC or local-chain experiments.",
        allowed_tools=EXECUTION_CONTROL_TOOLS
        | _FILES
        | SHELL_TOOLS
        | HTTP_SINGLE_TOOLS
        | frozenset({"system_http_probe"}),
    ),
    "ai_light": ScannerProfile(
        name="ai_light",
        domain="ai",
        description="Model/API surface inspection and one bounded AI-behavior experiment.",
        allowed_tools=EXECUTION_CONTROL_TOOLS
        | _FILES
        | SHELL_TOOLS
        | _HTTP,
    ),
    "binary_light": ScannerProfile(
        name="binary_light",
        domain="other",
        description="Bounded local artifact inventory and one-purpose binary profile tasks.",
        allowed_tools=EXECUTION_CONTROL_TOOLS | READ_ONLY_FILE_TOOLS | SHELL_TOOLS,
    ),
    "other_light": ScannerProfile(
        name="other_light",
        domain="other",
        description="Generic local, protocol, binary, or artifact inspection for other domains.",
        allowed_tools=_FULL_EXECUTION,
    ),
    "domain_recognition": ScannerProfile(
        name="domain_recognition",
        domain=None,
        description="Metadata-first classification with read-only files and at most one HTTP interaction.",
        allowed_tools=EXECUTION_CONTROL_TOOLS
        | READ_ONLY_FILE_TOOLS
        | HTTP_SINGLE_TOOLS,
    ),
}

PROFILE_FOR_DOMAIN: dict[DomainName, ScannerProfileName] = {
    "web": "web_light",
    "blockchain": "blockchain_light",
    "ai": "ai_light",
    "binary": "binary_light",
    "other": "binary_light",
}

TASK_CONTRACT_START = "<execution_task_contract>"
TASK_CONTRACT_END = "</execution_task_contract>"


def profile_for_domain(domain: DomainName) -> ScannerProfileName:
    return PROFILE_FOR_DOMAIN[domain]


def validate_profile_tools(
    scanner_profile: ScannerProfileName,
    tool_names: Iterable[str],
) -> None:
    profile = SCANNER_PROFILES.get(scanner_profile)
    if profile is None:
        raise ValueError("unknown scanner profile")
    values = list(tool_names)
    unknown = sorted(set(values) - profile.allowed_tools)
    if unknown:
        raise ValueError(
            f"tools are outside scanner profile {scanner_profile}: {', '.join(unknown)}"
        )


def validate_task_budgets(
    tool_names: Iterable[str],
    *,
    max_http_requests: int,
    max_shell_tasks: int,
    max_network_tasks: int,
) -> None:
    values = set(tool_names)
    requirements = (
        (HTTP_WORK_TOOLS, max_http_requests, "max_http_requests"),
        (SHELL_WORK_TOOLS, max_shell_tasks, "max_shell_tasks"),
        (NETWORK_WORK_TOOLS, max_network_tasks, "max_network_tasks"),
    )
    for work_tools, limit, field_name in requirements:
        if values & work_tools and limit < 1:
            raise ValueError(f"{field_name} must allow the selected work tool")


def validate_domain_profile(domain: DomainName, scanner_profile: ScannerProfileName) -> None:
    expected = profile_for_domain(domain)
    if domain == "other" and scanner_profile == "other_light":
        return
    if scanner_profile != expected:
        raise ValueError(
            f"scanner profile {scanner_profile} does not match domain {domain}; expected {expected}"
        )


def task_contract_json(contract: Mapping[str, Any]) -> str:
    """Return stable JSON embedded in prompts and recovered after a Run resumes."""

    return json.dumps(dict(contract), ensure_ascii=False, sort_keys=True)


def extract_task_contract(prompt: str) -> dict[str, Any] | None:
    """Recover the durable task contract from an Execution Agent prompt."""

    start = prompt.find(TASK_CONTRACT_START)
    if start < 0:
        return None
    start += len(TASK_CONTRACT_START)
    end = prompt.find(TASK_CONTRACT_END, start)
    if end < 0:
        return None
    try:
        value = json.loads(prompt[start:end].strip())
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def dependency_batches(
    tasks: Sequence[Mapping[str, Any]],
    *,
    completed: Iterable[str] = (),
) -> list[list[str]]:
    """Topologically group independent tasks and reject missing or cyclic dependencies."""

    keys = [str(task.get("task_key") or "") for task in tasks]
    if any(not key for key in keys) or len(set(keys)) != len(keys):
        raise ValueError("task keys must be non-empty and unique")
    known = set(keys)
    done = set(completed)
    dependencies: dict[str, set[str]] = {}
    for task, key in zip(tasks, keys):
        values = {str(value) for value in task.get("depends_on") or []}
        if key in values:
            raise ValueError(f"task {key} depends on itself")
        missing = values - known - done
        if missing:
            raise ValueError(
                f"task {key} references unknown dependencies: {', '.join(sorted(missing))}"
            )
        dependencies[key] = values - done

    batches: list[list[str]] = []
    remaining = set(keys)
    while remaining:
        ready = sorted(
            key for key in remaining if not (dependencies[key] & remaining)
        )
        if not ready:
            raise ValueError("task dependencies contain a cycle")
        batches.append(ready)
        remaining.difference_update(ready)
    return batches
