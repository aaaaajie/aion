"""Role-scoped Agent control tools.

These wrappers deliberately expose a small fixed surface. The Supervisor is
the authority for parent/child identity and benchmark state transitions.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, ClassVar

from pydantic import ValidationError

from agent.runner import ToolDispatchOutcome
from agent.state.errors import StateError
from agent.state.schemas import (
    AttackPathInput,
    CredentialInput,
    ExecutionTaskInput,
    FindingInput,
    FindingResolutionInput,
    HypothesisInput,
)

from .models import (
    AgentRole,
    AnalysisPlanArguments,
    ChallengeStatusArguments,
    CommitCycleArguments,
    CycleArguments,
    CreateExecutionArguments,
    EmptyArguments,
    ExecutionReport,
    HintArguments,
    ReportQueryArguments,
    SubmitFlagArguments,
    UniqueCodeArguments,
    ProgressArguments,
    StagnationExtensionArguments,
)
from .policy import AgentPolicy


def _definition(
    name: str,
    description: str,
    properties: dict[str, Any],
    required: list[str],
) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


_REPORT_QUERY_PROPERTIES = {
    "max_reports": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
}

_CHALLENGE_REFRESH_GATED_TOOLS = frozenset(
    {
        "challenge_begin_cycle",
        "challenge_submit_analysis_plan",
        "challenge_commit_cycle",
        "challenge_create_execution_agent",
        "challenge_wait_for_state",
    }
)


def _model_schema(model: type[Any]) -> dict[str, Any]:
    """Inline one canonical Pydantic model in an Agent tool schema."""

    schema = deepcopy(model.model_json_schema())
    schema.pop("title", None)
    return schema


_HYPOTHESIS_SCHEMA = _model_schema(HypothesisInput)
_TASK_SCHEMA = _model_schema(ExecutionTaskInput)
_FINDING_SCHEMA = _model_schema(FindingInput)
_FINDING_RESOLUTION_SCHEMA = _model_schema(FindingResolutionInput)
_CREDENTIAL_SCHEMA = _model_schema(CredentialInput)
_ATTACK_PATH_SCHEMA = _model_schema(AttackPathInput)


class AgentControlTools:
    """Base class for one fixed role's Agent-facing control surface."""

    ROLE: ClassVar[AgentRole]
    _ROUTES: ClassVar[dict[str, tuple[type[Any], str]]] = {}
    _DEFINITIONS: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, supervisor: Any, *, agent_id: str, unique_code: str | None = None) -> None:
        self.supervisor = supervisor
        self.agent_id = agent_id
        self.unique_code = unique_code
        self.policy = AgentPolicy(self.ROLE)

    @classmethod
    def tool_definitions(cls) -> list[dict[str, Any]]:
        return deepcopy(cls._DEFINITIONS)

    async def close(self) -> None:
        return None

    async def dispatch(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | ToolDispatchOutcome:
        if not isinstance(name, str) or not self.policy.allows(name):
            return self._error("unknown_tool", "This Agent role cannot use that tool")
        route = self._ROUTES.get(name)
        if route is None:
            return self._error("unknown_tool", "Unknown Agent control tool")
        if self.ROLE == "challenge" and name in _CHALLENGE_REFRESH_GATED_TOOLS:
            refresh_error = self.supervisor.challenge_state_refresh_error(
                self.agent_id, name
            )
            if refresh_error is not None:
                return refresh_error
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            return self._error("invalid_arguments", "Tool arguments must be a JSON object")
        argument_model, method_name = route
        try:
            validated = argument_model.model_validate(arguments)
            method = getattr(self, method_name)
            result = await method(**validated.model_dump(mode="json"))
            if (
                self.ROLE == "challenge"
                and name == "challenge_get_state"
                and isinstance(result, Mapping)
                and result.get("ok") is True
            ):
                self.supervisor.clear_challenge_state_refresh_required(self.agent_id)
            return self._decorate_conflict_result(name, result)
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "type": "validation",
                    "code": "invalid_arguments",
                    "message": "Invalid arguments for Agent control tool",
                    "status_code": None,
                    "detail": self._validation_detail(exc),
                },
            }
        except StateError as exc:
            detail = dict(exc.detail)
            if (
                self.ROLE == "challenge"
                and name in _CHALLENGE_REFRESH_GATED_TOOLS
                and exc.status_code == 409
            ):
                self.supervisor.mark_challenge_state_refresh_required(
                    self.agent_id, exc.code, exc.detail
                )
                detail.update(
                    {
                        "required_tool": "challenge_get_state",
                        "retry_same_arguments": False,
                        "original_conflict_code": exc.code,
                    }
                )
            return {
                "ok": False,
                "error": {
                    "type": "conflict" if exc.status_code == 409 else "state",
                    "code": exc.code,
                    "message": exc.message,
                    "status_code": exc.status_code,
                    "detail": detail,
                },
            }
        except Exception:
            return self._error("internal_error", "Agent control operation failed", error_type="internal")

    async def chief_refresh_challenges(self) -> dict[str, Any]:
        return await self.supervisor.refresh_challenges(self.agent_id)

    async def chief_get_core_state(self) -> dict[str, Any]:
        return await self.supervisor.get_core_state(self.agent_id)

    async def chief_get_schedule(self) -> dict[str, Any]:
        return await self.supervisor.get_schedule(self.agent_id)

    async def chief_create_challenge_agent(self, unique_code: str) -> dict[str, Any]:
        return await self.supervisor.create_challenge_agent(self.agent_id, unique_code)

    async def chief_get_challenge_reports(self, max_reports: int = 20) -> dict[str, Any]:
        return await self.supervisor.get_challenge_reports(self.agent_id, 0.0, max_reports)

    async def chief_wait_for_state(self) -> ToolDispatchOutcome:
        return ToolDispatchOutcome(
            {"ok": True, "data": {"status": "waiting"}}, yield_session=True
        )

    async def chief_request_hint(
        self,
        unique_code: str,
        basis: str,
        evidence_refs: list[str],
        reason: str,
    ) -> dict[str, Any]:
        return await self.supervisor.request_hint(
            self.agent_id, unique_code, basis, evidence_refs, reason
        )

    async def chief_extend_stagnation(
        self,
        unique_code: str,
        reason: str,
        evidence_refs: list[str],
        note: str | None = None,
    ) -> dict[str, Any]:
        return await self.supervisor.extend_stagnation(
            self.agent_id, unique_code, reason, evidence_refs, note
        )

    async def challenge_create_execution_agent(self, mission: str, hypothesis_key: str, task_key: str, task_stage: str, cycle_id: str | None = None, kind: str = "general", priority: int = 50, success_criteria: list[str] | None = None, context_refs: list[str] | None = None, branch_key: str | None = None, timeout_seconds: int = 1_800) -> dict[str, Any]:
        return await self.supervisor.create_execution_agent(
            self.agent_id,
            mission,
            timeout_seconds,
            hypothesis_key=hypothesis_key,
            task_key=task_key,
            task_stage=task_stage,
            cycle_id=cycle_id,
            kind=kind,
            priority=priority,
            success_criteria=success_criteria or [],
            context_refs=context_refs or [],
            branch_key=branch_key,
        )

    async def challenge_get_state(self) -> dict[str, Any]:
        return await self.supervisor.get_challenge_state(self.agent_id)

    def _decorate_conflict_result(
        self,
        name: str,
        result: dict[str, Any] | ToolDispatchOutcome,
    ) -> dict[str, Any] | ToolDispatchOutcome:
        if self.ROLE != "challenge" or name not in _CHALLENGE_REFRESH_GATED_TOOLS:
            return result
        if isinstance(result, ToolDispatchOutcome) or not isinstance(result, Mapping):
            return result
        error = result.get("error")
        if not isinstance(error, Mapping) or error.get("type") != "conflict":
            return result
        conflict_code = error.get("code")
        if not isinstance(conflict_code, str):
            return result
        self.supervisor.mark_challenge_state_refresh_required(
            self.agent_id,
            conflict_code,
            error.get("detail") if isinstance(error.get("detail"), Mapping) else {},
        )
        updated_error = dict(error)
        updated_error["status_code"] = error.get("status_code") or 409
        updated_detail = dict(
            error.get("detail") if isinstance(error.get("detail"), Mapping) else {}
        )
        updated_detail.update(
            {
                "required_tool": "challenge_get_state",
                "retry_same_arguments": False,
                "original_conflict_code": conflict_code,
            }
        )
        updated_error["detail"] = updated_detail
        return {**result, "error": updated_error}

    async def challenge_begin_cycle(self, expected_challenge_version: int) -> dict[str, Any]:
        return await self.supervisor.begin_cycle(self.agent_id, expected_challenge_version)

    async def challenge_submit_analysis_plan(
        self,
        cycle_id: str,
        expected_version: int,
        analysis_summary: str,
        direction: str = "unknown",
        hypotheses: list[dict[str, Any]] | None = None,
        information_gaps: list[str] | None = None,
        avoid_repeating: list[str] | None = None,
        tasks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return await self.supervisor.submit_analysis_plan(
            self.agent_id,
            cycle_id,
            expected_version,
            analysis_summary=analysis_summary,
            direction=direction,
            hypotheses=hypotheses or [],
            information_gaps=information_gaps or [],
            avoid_repeating=avoid_repeating or [],
            tasks=tasks or [],
        )

    async def challenge_commit_cycle(
        self,
        cycle_id: str,
        expected_version: int,
        summary: str,
        outcome: str,
        findings: list[dict[str, Any]] | None = None,
        credentials: list[dict[str, Any]] | None = None,
        next_steps: list[str] | None = None,
        new_attack_paths: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return await self.supervisor.commit_cycle(
            self.agent_id,
            cycle_id,
            expected_version,
            summary=summary,
            findings=findings or [],
            credentials=credentials or [],
            next_steps=next_steps or [],
            new_attack_paths=new_attack_paths or [],
            outcome=outcome,
        )

    async def challenge_get_execution_reports(self, max_reports: int = 20) -> dict[str, Any]:
        return await self.supervisor.get_execution_reports(self.agent_id, 0.0, max_reports)

    async def challenge_get_updates(self, max_reports: int = 20) -> dict[str, Any]:
        return await self.supervisor.get_challenge_updates(self.agent_id, 0.0, max_reports)

    async def challenge_wait_for_state(self) -> ToolDispatchOutcome:
        return ToolDispatchOutcome(
            {"ok": True, "data": {"status": "waiting"}}, yield_session=True
        )

    async def challenge_report_status(self, **payload: Any) -> dict[str, Any]:
        return await self.supervisor.report_challenge_status(self.agent_id, payload)

    async def challenge_submit_flag(self, flag: str) -> dict[str, Any]:
        return await self.supervisor.submit_flag(self.agent_id, flag)

    async def challenge_close_challenge(self) -> dict[str, Any]:
        return await self.supervisor.close_challenge(self.agent_id)

    async def execution_report(self, **payload: Any) -> dict[str, Any]:
        report = ExecutionReport.model_validate(payload)
        return await self.supervisor.report_execution(self.agent_id, report)

    async def execution_get_assignment(self) -> dict[str, Any]:
        return await self.supervisor.get_execution_assignment(self.agent_id)

    async def execution_update_progress(self, **payload: Any) -> dict[str, Any]:
        return await self.supervisor.update_execution_progress(self.agent_id, payload)

    @staticmethod
    def _error(code: str, message: str, *, error_type: str = "validation") -> dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": error_type,
                "code": code,
                "message": message,
                "status_code": None,
                "detail": {},
            },
        }

    @staticmethod
    def _validation_detail(exc: ValidationError) -> list[dict[str, Any]]:
        return [
            {"loc": list(item.get("loc", ())), "type": item.get("type", "value_error")}
            for item in exc.errors()
        ]


class ChiefAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "chief"
    _ROUTES = {
        "chief_refresh_challenges": (EmptyArguments, "chief_refresh_challenges"),
        "chief_get_core_state": (EmptyArguments, "chief_get_core_state"),
        "chief_get_schedule": (EmptyArguments, "chief_get_schedule"),
        "chief_create_challenge_agent": (UniqueCodeArguments, "chief_create_challenge_agent"),
        "chief_get_challenge_reports": (ReportQueryArguments, "chief_get_challenge_reports"),
        "chief_wait_for_state": (EmptyArguments, "chief_wait_for_state"),
        "chief_request_hint": (HintArguments, "chief_request_hint"),
        "chief_extend_stagnation": (StagnationExtensionArguments, "chief_extend_stagnation"),
    }
    _DEFINITIONS = [
        _definition(
            "chief_refresh_challenges",
            "Refresh benchmark challenge status using a read-only request. Do not analyze vulnerabilities here.",
            {},
            [],
        ),
        _definition(
            "chief_get_core_state",
            "Read the authoritative persisted run state and score snapshot.",
            {},
            [],
        ),
        _definition(
            "chief_get_schedule",
            "Read the phase-aware deterministic challenge schedule.",
            {},
            [],
        ),
        _definition(
            "chief_create_challenge_agent",
            "Start one challenge only when the deterministic scheduler permits it, then create its one Challenge Agent. At most 3 challenge containers may be active.",
            {"unique_code": {"type": "string", "minLength": 1}},
            ["unique_code"],
        ),
        _definition(
            "chief_get_challenge_reports",
            "Read a non-blocking bounded snapshot of structured progress reports sent by Challenge Agents.",
            _REPORT_QUERY_PROPERTIES,
            [],
        ),
        _definition(
            "chief_wait_for_state",
            "Yield this model session after all current decisions are persisted. Runtime resumes only for a newer state sequence or the five-minute safety wakeup. Call this as the only tool in the response.",
            {},
            [],
        ),
        _definition(
            "chief_request_hint",
            "Request the single challenge Hint only after Runtime admission: the challenge must be in warning, all execution and resource work must be terminal, the latest status report must be ready_for_hint with hint_recommended=true, and the cited evidence must support a high-probability path, second-pass convergence, or near-deadline convergence. Warning alone never authorizes a Hint.",
            {
                "unique_code": {"type": "string", "minLength": 1},
                "basis": {"type": "string", "enum": ["high_probability_path", "second_pass_convergence", "near_deadline"]},
                "evidence_refs": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1, "maxItems": 20},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
            },
            ["unique_code", "basis", "evidence_refs", "reason"],
        ),
        _definition(
            "chief_extend_stagnation",
            "Grant the one structured stagnation extension only when the cited evidence meets a high-probability, waiting-remote, or imminent-result rule. Runtime enforces the 20-minute hard cap.",
            {
                "unique_code": {"type": "string", "minLength": 1},
                "reason": {"type": "string", "enum": ["high_probability_path", "waiting_remote", "imminent_result"]},
                "evidence_refs": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1, "maxItems": 20},
                "note": {"type": "string", "maxLength": 1000},
            },
            ["unique_code", "reason", "evidence_refs"],
        ),
    ]


class ChallengeAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "challenge"
    _ROUTES = {
        "challenge_get_state": (EmptyArguments, "challenge_get_state"),
        "challenge_begin_cycle": (CycleArguments, "challenge_begin_cycle"),
        "challenge_submit_analysis_plan": (AnalysisPlanArguments, "challenge_submit_analysis_plan"),
        "challenge_commit_cycle": (CommitCycleArguments, "challenge_commit_cycle"),
        "challenge_create_execution_agent": (CreateExecutionArguments, "challenge_create_execution_agent"),
        "challenge_get_execution_reports": (ReportQueryArguments, "challenge_get_execution_reports"),
        "challenge_get_updates": (ReportQueryArguments, "challenge_get_updates"),
        "challenge_wait_for_state": (EmptyArguments, "challenge_wait_for_state"),
        "challenge_report_status": (ChallengeStatusArguments, "challenge_report_status"),
        "challenge_submit_flag": (SubmitFlagArguments, "challenge_submit_flag"),
        "challenge_close_challenge": (EmptyArguments, "challenge_close_challenge"),
    }
    _DEFINITIONS = [
        _definition(
            "challenge_create_execution_agent",
            "Create one atomic execution experiment. kind selects the technical capability; task_stage selects discovery, validation, or exploitation. Validation/exploitation requires a same-Challenge report/finding/observation reference. Warning permits parallel validation/exploitation but only one evidence-backed discovery pivot. A conflict requires challenge_get_state before retrying or waiting.",
            {
                "mission": {"type": "string", "minLength": 1, "maxLength": 4000},
                "hypothesis_key": {"type": "string", "minLength": 1, "maxLength": 128},
                "task_key": {"type": "string", "minLength": 1, "maxLength": 128},
                "cycle_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "kind": {"type": "string", "enum": ["general", "recon", "web", "exploit", "credential", "privilege", "verification", "exploration"], "default": "general"},
                "task_stage": {"type": "string", "enum": ["discovery", "validation", "exploitation"]},
                "priority": {"type": "integer", "minimum": 0, "maximum": 100, "default": 50},
                "success_criteria": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
                "context_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "branch_key": {"type": "string", "minLength": 1, "maxLength": 256},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 1800},
            },
            ["mission", "hypothesis_key", "task_key", "task_stage"],
        ),
        _definition("challenge_get_state", "Read the bound challenge's authoritative state, findings, cycle ledger, and permitted credentials. This is mandatory after any cycle mutation conflict before retrying or waiting.", {}, []),
        _definition("challenge_begin_cycle", "Freeze a STATE snapshot and begin a structured cycle. If a conflict is returned, reread challenge_get_state and do not retry cached arguments.", {"expected_challenge_version": {"type": "integer", "minimum": 1}}, ["expected_challenge_version"]),
        _definition(
            "challenge_submit_analysis_plan",
            "Submit an explicit analysis summary, hypotheses, information gaps, and bounded execution tasks. If validation_debt is non-empty, every non-empty plan must include a validation/exploitation task citing one debt finding; independent discovery may run in the same batch. Use the latest cycle version; after a conflict, challenge_get_state is required before another mutation.",
            {
                "cycle_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "expected_version": {"type": "integer", "minimum": 1},
                "analysis_summary": {"type": "string", "minLength": 1, "maxLength": 8000},
                "direction": {"type": "string", "enum": ["unknown", "web", "binary", "ai", "blockchain"], "default": "unknown"},
                "hypotheses": {"type": "array", "items": _HYPOTHESIS_SCHEMA, "maxItems": 50},
                "information_gaps": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "avoid_repeating": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "tasks": {"type": "array", "items": _TASK_SCHEMA, "maxItems": 50},
            },
            ["cycle_id", "expected_version", "analysis_summary"],
        ),
        _definition(
            "challenge_commit_cycle",
            "Commit explicit findings, credentials, attack paths, and the cycle outcome atomically. Use only the current cycle phase and version from challenge_get_state or the latest successful tool result.",
            {
                "cycle_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "expected_version": {"type": "integer", "minimum": 1},
                "summary": {"type": "string", "minLength": 1, "maxLength": 8000},
                "findings": {"type": "array", "items": _FINDING_SCHEMA, "maxItems": 100},
                "credentials": {"type": "array", "items": _CREDENTIAL_SCHEMA, "maxItems": 50},
                "next_steps": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "new_attack_paths": {"type": "array", "items": _ATTACK_PATH_SCHEMA, "maxItems": 20},
                "outcome": {"type": "string", "enum": ["progress", "no_progress", "completed", "blocked", "failed"]},
            },
            ["cycle_id", "expected_version", "summary", "outcome"],
        ),
        _definition(
            "challenge_get_execution_reports",
            "Read a non-blocking bounded snapshot of new Execution Agent reports. Consume every completed, failed, blocked, or cancelled child before deciding the cycle.",
            _REPORT_QUERY_PROPERTIES,
            [],
        ),
        _definition(
            "challenge_get_updates",
            "Read a non-blocking bounded snapshot of control updates delivered by the Chief Agent, including the one persisted Hint result.",
            _REPORT_QUERY_PROPERTIES,
            [],
        ),
        _definition(
            "challenge_wait_for_state",
            "Yield this model session after all current evidence and decisions are persisted. Runtime resumes only for a newer state sequence or the five-minute safety wakeup. Call this as the only tool in the response. It is rejected until a required challenge_get_state refresh succeeds.",
            {},
            [],
        ),
        _definition(
            "challenge_report_status",
            "Report structured progress to the Chief Agent. Use ready_for_hint only after all child/resource work has converged; when hint_recommended=true, blocker and same-Run evidence_refs are mandatory. This report does not request a Hint or bypass Runtime admission.",
            {
                "status": {"type": "string", "enum": ["analyzing", "blocked", "ready_for_hint", "flag_candidate", "completed", "failed"]},
                "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
                "hint_recommended": {"type": "boolean", "default": False},
                "blocker": {"type": "string", "maxLength": 1000},
                "next_steps": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
                "evidence_refs": {"type": "array", "items": {"type": "string", "minLength": 1}, "maxItems": 20},
            },
            ["status", "summary"],
        ),
        _definition(
            "challenge_submit_flag",
            "Request one Flag submission for this challenge. The Supervisor performs the state-checked API call and prevents automatic retries.",
            {"flag": {"type": "string", "minLength": 1, "maxLength": 4096}},
            ["flag"],
        ),
        _definition(
            "challenge_close_challenge",
            "Request closing this challenge and releasing its container resources.",
            {},
            [],
        ),
    ]


class ExecutionAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "execution"
    _ROUTES = {
        "execution_get_assignment": (EmptyArguments, "execution_get_assignment"),
        "execution_update_progress": (ProgressArguments, "execution_update_progress"),
        "execution_report": (ExecutionReport, "execution_report"),
    }
    _DEFINITIONS = [
        _definition("execution_get_assignment", "First tool call. Read the compact persisted mission, task_stage, context references, target, direction, and the non-empty Challenge-specific evidence_root. Write evidence only below that root; do not use shared workspace or Run artifacts.", {}, []),
        _definition(
            "execution_update_progress",
            "Persist bounded in-session progress and structured findings. This never finalizes the Execution Agent; finish exactly once with execution_report.",
            {
                "status": {"type": "string", "enum": ["working", "blocked", "completed", "failed", "cancelled"]},
                "phase": {"type": "string", "minLength": 1, "maxLength": 64},
                "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
                "findings": {"type": "array", "items": _FINDING_SCHEMA, "maxItems": 50},
                "evidence_paths": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "expected_result_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
            },
            ["status", "phase", "summary"],
        ),
        _definition(
            "execution_report",
            "Save the one terminal structured result for the parent Challenge Agent. hypothesis_outcome is mandatory; Discovery may only report actionable Findings as candidate. Validation/Exploitation may resolve a cited candidate with finding_resolutions; supported/rejected requires evidence. Do not copy all context Findings into verified state.",
            {
                "status": {"type": "string", "enum": ["completed", "blocked", "failed", "cancelled"]},
                "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
                "findings": {"type": "array", "items": _FINDING_SCHEMA, "maxItems": 50},
                "evidence_paths": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
                "next_steps": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
                "candidate_flag": {"type": "string", "minLength": 1, "maxLength": 4096},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "hypothesis_outcome": {"type": "string", "enum": ["supported", "rejected", "inconclusive"]},
                "finding_resolutions": {"type": "array", "items": _FINDING_RESOLUTION_SCHEMA, "maxItems": 50},
            },
            ["status", "summary", "hypothesis_outcome"],
        )
    ]
