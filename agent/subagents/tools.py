"""Role-scoped lightweight Agent control Tool Specs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from agent.state.errors import StatePermission
from agent.state.schemas import AgentReportInput, ChallengeDispatchInput, ExecutionTaskInput
from agent.tooling import AccessClaim, ToolDispatchOutcome, ToolSpec

from .models import (
    AgentRole,
    ChallengeDispatchArguments,
    ControllerWaitArguments,
    EmptyArguments,
    EvidenceReadArguments,
    ExecutionReport,
    LaunchChallengesArguments,
    ReportQueryArguments,
    SimpleHintArguments,
    SubmitFlagArguments,
)
from .policy import AgentPolicy


_EXECUTION_KINDS = {
    "general",
    "recon",
    "web",
    "pentest",
    "exploit",
    "cloud",
    "evasion",
    "credential",
    "privilege",
    "verification",
    "exploration",
}
_TASK_STAGES = {"discovery", "validation", "exploitation", "post_exploitation"}


def _normalize_dispatch_tasks(
    raw_tasks: Any,
) -> tuple[list[Any], list[dict[str, Any]], bool]:
    """Keep objective strict while treating optional model metadata as advisory."""

    warnings: list[dict[str, Any]] = []
    supplied = raw_tasks not in (None, [])
    if not isinstance(raw_tasks, list):
        if supplied:
            warnings.append(
                {
                    "code": "invalid_tasks_dropped",
                    "message": "Dispatch tasks must be an array; the decision was kept without tasks",
                    "details": {},
                }
            )
        return [], warnings, supplied

    normalized_tasks = []
    for index, item in enumerate(raw_tasks):
        if hasattr(item, "model_dump"):
            item = item.model_dump(mode="python")
        if not isinstance(item, Mapping):
            warnings.append(
                {
                    "code": "invalid_task_dropped",
                    "message": "Dispatch task without an object payload was dropped",
                    "details": {"index": index},
                }
            )
            continue
        objective = item.get("objective")
        if not isinstance(objective, str) or not objective.strip():
            warnings.append(
                {
                    "code": "invalid_task_dropped",
                    "message": "Dispatch task without a usable objective was dropped",
                    "details": {"index": index},
                }
            )
            continue

        changed_fields: list[str] = []
        kind = item.get("kind", "general")
        if kind not in _EXECUTION_KINDS:
            kind = "general"
            changed_fields.append("kind")
        task_stage = item.get("task_stage", "discovery")
        if task_stage not in _TASK_STAGES:
            task_stage = "discovery"
            changed_fields.append("task_stage")
        priority = item.get("priority", 50)
        if (
            not isinstance(priority, int)
            or isinstance(priority, bool)
            or not 0 <= priority <= 100
        ):
            priority = 50
            changed_fields.append("priority")
        timeout_seconds = item.get("timeout_seconds", 1_800)
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or not 1 <= timeout_seconds <= 3_600
        ):
            timeout_seconds = 1_800
            changed_fields.append("timeout_seconds")

        normalized: dict[str, Any] = {
            "objective": objective.strip()[:4_000],
            "kind": kind,
            "task_stage": task_stage,
            "priority": priority,
            "timeout_seconds": timeout_seconds,
        }
        if normalized["objective"] != objective:
            changed_fields.append("objective")
        for field, maximum in (
            ("task_key", 128),
            ("hypothesis_key", 128),
            ("branch_key", 256),
        ):
            value = item.get(field)
            if value is None:
                continue
            if isinstance(value, str) and value.strip() and len(value.strip()) <= maximum:
                normalized[field] = value.strip()
            else:
                changed_fields.append(field)
        for field, maximum in (("success_criteria", 20), ("context_refs", 50)):
            value = item.get(field, [])
            if not isinstance(value, list):
                normalized[field] = []
                changed_fields.append(field)
                continue
            kept = [entry.strip() for entry in value if isinstance(entry, str) and entry.strip()]
            normalized[field] = kept[:maximum]
            if len(kept) != len(value) or len(kept) > maximum:
                changed_fields.append(field)

        normalized_tasks.append(ExecutionTaskInput.model_validate(normalized))
        if changed_fields:
            warnings.append(
                {
                    "code": "task_fields_normalized",
                    "message": "Optional dispatch task metadata was defaulted or dropped",
                    "details": {"index": index, "fields": sorted(set(changed_fields))},
                }
            )
    return normalized_tasks, warnings, supplied


class AgentControlTools:
    """Base provider for one fixed role's compact control surface."""

    ROLE: ClassVar[AgentRole]
    _TOOLS: ClassVar[tuple[tuple[str, type[Any], str, str], ...]] = ()

    def __init__(
        self,
        supervisor: Any,
        *,
        agent_id: str,
        unique_code: str | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.agent_id = agent_id
        self.unique_code = unique_code
        self.policy = AgentPolicy(self.ROLE)

    def tool_specs(self) -> list[ToolSpec]:
        handlers = {
            "chief_observe": self.chief_observe,
            "chief_launch_challenges": self.chief_launch_challenges,
            "chief_wait": self.chief_wait,
            "chief_request_hint": self.chief_request_hint,
            "challenge_observe": self.challenge_observe,
            "challenge_dispatch": self.challenge_dispatch,
            "challenge_wait": self.challenge_wait,
            "challenge_submit_flag": self.challenge_submit_flag,
            "challenge_close": self.challenge_close,
            "execution_report": self.execution_report,
            "evidence_read": self.evidence_read,
        }
        specs: list[ToolSpec] = []
        role_tools = self._TOOLS
        if self.ROLE in {"challenge", "execution"}:
            role_tools = role_tools + (
                (
                    "evidence_read",
                    EvidenceReadArguments,
                    "evidence_read",
                    "Read one authorized immutable Evidence item with pagination.",
                ),
            )
        for name, argument_model, method_name, description in role_tools:
            typed_handler = handlers[method_name]

            async def handler(
                arguments: Any,
                *,
                tool_name: str = name,
                bound_handler: Any = typed_handler,
            ) -> Any:
                if not self.policy.allows(tool_name):
                    raise StatePermission(
                        "tool_not_allowed_for_role",
                        "This Agent role cannot use that tool",
                    )
                return await bound_handler(arguments)

            specs.append(
                ToolSpec(
                    name,
                    description,
                    argument_model,
                    handler,
                    access_claims=self._access_claims(name),
                    requires_solo=name in {"chief_wait", "challenge_wait"},
                    result_projector=(
                        (lambda result, tool_name=name: self._control_projection(
                            tool_name, result
                        ))
                        if name in {
                            "chief_observe",
                            "challenge_observe",
                            "challenge_dispatch",
                        }
                        else None
                    ),
                )
            )
        return specs

    @staticmethod
    def _control_projection(
        tool_name: str, result: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        data = result.get("data")
        if not isinstance(data, Mapping):
            return {}
        if tool_name == "challenge_dispatch":
            return {
                "data": {
                    key: data[key]
                    for key in (
                        "decision_number",
                        "admissions",
                        "idempotent_tasks",
                        "decision_report_sequence",
                        "transition_latency_ms",
                    )
                    if key in data
                },
                "warnings": list(result.get("warnings") or []),
            }
        if tool_name == "chief_observe":
            return {
                "data": {
                    key: data[key]
                    for key in (
                        "run",
                        "capacity",
                        "challenges",
                        "active_agents",
                        "schedule",
                        "reports",
                        "report_count",
                        "next_sequence",
                        "has_more",
                        "evidence",
                    )
                    if key in data
                }
            }
        return {
            "data": {
                key: data[key]
                for key in (
                    "authority",
                    "candidate_flags",
                    "reports",
                    "report_count",
                    "report_cursor",
                    "has_more",
                    "active_execution_count",
                    "active_executions",
                    "all_execution_terminal",
                    "evidence_root",
                )
                if key in data
            }
        }

    async def close(self) -> None:
        return None

    def _access_claims(self, name: str) -> Any:
        if name == "evidence_read":
            return lambda arguments: (
                AccessClaim("read", f"evidence:{arguments.evidence_ref}"),
            )
        if name in {"chief_observe", "challenge_observe"}:
            return lambda _arguments: (
                AccessClaim("write", f"report-cursor:{self.agent_id}"),
            )
        if name.startswith("challenge_"):
            return lambda _arguments: (
                AccessClaim("write", f"challenge:{self.unique_code}"),
            )
        if name.startswith("execution_"):
            return lambda _arguments: (
                AccessClaim("write", f"execution:{self.agent_id}"),
            )
        return lambda _arguments: (AccessClaim("write", "agent-control"),)

    async def chief_observe(self, arguments: ReportQueryArguments) -> dict[str, Any]:
        return await self.supervisor.observe_chief(
            self.agent_id, max_reports=arguments.max_reports
        )

    async def chief_launch_challenges(
        self, arguments: LaunchChallengesArguments
    ) -> dict[str, Any]:
        return await self.supervisor.launch_challenges(
            self.agent_id, arguments.unique_codes
        )

    async def chief_wait(
        self, arguments: ControllerWaitArguments
    ) -> ToolDispatchOutcome:
        return await self.supervisor.wait_chief(
            self.agent_id, reason=arguments.reason
        )

    async def chief_request_hint(
        self, arguments: SimpleHintArguments
    ) -> dict[str, Any]:
        return await self.supervisor.request_hint_light(
            self.agent_id, arguments.unique_code, arguments.reason
        )

    async def challenge_observe(
        self, arguments: ReportQueryArguments
    ) -> dict[str, Any]:
        return await self.supervisor.observe_challenge(
            self.agent_id, max_reports=arguments.max_reports
        )

    async def challenge_dispatch(
        self, arguments: ChallengeDispatchArguments
    ) -> ToolDispatchOutcome:
        tasks, normalization_warnings, tasks_supplied = _normalize_dispatch_tasks(
            arguments.tasks
        )
        result = await self.supervisor.dispatch_challenge(
            self.agent_id,
            ChallengeDispatchInput(
                summary=arguments.summary,
                outcome=arguments.outcome,
                direction=arguments.direction,
                tasks=tasks,
                evidence_refs=arguments.evidence_refs,
                next_steps=arguments.next_steps,
            ),
        )
        if normalization_warnings and isinstance(result, Mapping):
            result = {
                **dict(result),
                "warnings": [
                    *normalization_warnings,
                    *list(result.get("warnings") or []),
                ],
            }
        all_supplied_tasks_dropped = tasks_supplied and not tasks
        return ToolDispatchOutcome(
            result,
            yield_session=bool(result.get("ok")) and not all_supplied_tasks_dropped,
        )

    async def challenge_wait(
        self, arguments: ControllerWaitArguments
    ) -> ToolDispatchOutcome:
        return await self.supervisor.wait_for_state(
            self.agent_id, arguments.reason
        )

    async def challenge_submit_flag(
        self, arguments: SubmitFlagArguments
    ) -> ToolDispatchOutcome:
        result = await self.supervisor.submit_flag(self.agent_id, arguments.flag)
        data = result.get("data") if isinstance(result, Mapping) else None
        return ToolDispatchOutcome(
            result,
            yield_session=bool(
                result.get("ok")
                and isinstance(data, Mapping)
                and data.get("challenge_completed")
            ),
        )

    async def challenge_close(self, _arguments: EmptyArguments) -> dict[str, Any]:
        return await self.supervisor.close_challenge(self.agent_id)

    async def execution_report(
        self, arguments: ExecutionReport
    ) -> ToolDispatchOutcome:
        payload = AgentReportInput.model_validate(arguments, from_attributes=True)
        result = await self.supervisor.report_execution_payload(self.agent_id, payload)
        return ToolDispatchOutcome(result, yield_session=bool(result.get("ok")))

    async def evidence_read(self, arguments: EvidenceReadArguments) -> dict[str, Any]:
        return await self.supervisor.read_evidence(
            self.agent_id,
            arguments.evidence_ref,
            offset=arguments.offset,
            limit_chars=arguments.limit_chars,
        )


class ChiefAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "chief"
    _TOOLS = (
        (
            "chief_observe",
            ReportQueryArguments,
            "chief_observe",
            "Read the compact authoritative run, capacity, schedule, and new Challenge reports.",
        ),
        (
            "chief_launch_challenges",
            LaunchChallengesArguments,
            "chief_launch_challenges",
            "Refresh once and launch a bounded ordered batch of Challenge Agents.",
        ),
        (
            "chief_wait",
            ControllerWaitArguments,
            "chief_wait",
            "Yield until new run state is available. This must be the only tool call.",
        ),
        (
            "chief_request_hint",
            SimpleHintArguments,
            "chief_request_hint",
            "Request the challenge Hint subject only to authoritative remote hard rules.",
        ),
    )


class ChallengeAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "challenge"
    _TOOLS = (
        (
            "challenge_observe",
            ReportQueryArguments,
            "challenge_observe",
            "Consume a bounded page of new Execution reports and read the compact challenge state.",
        ),
        (
            "challenge_dispatch",
            ChallengeDispatchArguments,
            "challenge_dispatch",
            "Atomically record one decision and enqueue useful independent tasks. Arguments are top-level, never wrapped in arguments. Minimal JSON: {\"summary\":\"test the exposed HTTP surface\",\"tasks\":[{\"objective\":\"collect one HTTP baseline\"}]}.",
        ),
        (
            "challenge_wait",
            ControllerWaitArguments,
            "challenge_wait",
            "Yield when no immediate action is useful. This must be the only tool call.",
        ),
        (
            "challenge_submit_flag",
            SubmitFlagArguments,
            "challenge_submit_flag",
            "Submit one candidate Flag without automatic retry.",
        ),
        (
            "challenge_close",
            EmptyArguments,
            "challenge_close",
            "Close this challenge and release its container resources.",
        ),
    )


class ExecutionAgentTools(AgentControlTools):
    ROLE: ClassVar[AgentRole] = "execution"
    _TOOLS = (
        (
            "execution_report",
            ExecutionReport,
            "execution_report",
            "Persist the one terminal result. Invalid optional evidence is returned as warnings rather than losing the report.",
        ),
    )
