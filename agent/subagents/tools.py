"""Small, explicit role tools; strategy lives with Chief and Solver."""

from agent.state.schemas import AgentReportInput, ReviewAgentReportInput, WorkerUpdateInput
from agent.tooling import ToolSpec, ToolDispatchOutcome, AccessClaim
from .models import (
    ReportQueryArguments,
    SolverObserveArguments,
    LaunchChallengesArguments,
    ControllerWaitArguments,
    SimpleHintArguments,
    PauseChallengesArguments,
    CloseChallengesArguments,
    DelegateArguments,
    CancelWorkerArguments,
    SolverProgressArguments,
    SolverReviewArguments,
    SubmitFlagArguments,
    EvidenceReadArguments,
    ReportReadArguments,
    EvidenceSearchArguments,
)
from .policy import AgentPolicy


class AgentControlTools:
    def __init__(self, supervisor, *, agent_id: str, role: str, mode: str = "execute"):
        self.supervisor = supervisor
        self.agent_id = agent_id
        self.mode = mode
        self.policy = AgentPolicy(role, mode)

    def tool_specs(self):
        s = self.supervisor
        caller = self.agent_id

        async def chief_observe(a):
            return await s.observe_chief(caller, max_reports=a.max_reports)

        async def launch(a):
            return await s.launch_challenges(caller, a.unique_codes)

        async def wait(a):
            return await s.wait_for_state(caller, a.reason)

        async def hint(a):
            return await s.request_hint_light(caller, a.unique_code, reason=a.reason)

        async def pause(a):
            return await s.pause_challenges(
                caller,
                a.unique_codes,
                reason=a.reason,
                release_container=a.release_container,
            )

        async def close(a):
            return await s.close_challenges(caller, a.unique_codes, reason=a.reason)

        async def observe(a):
            return await s.observe_solver(caller, **a.model_dump())

        async def delegate(a):
            return await s.delegate_workers(caller, a.tasks)

        async def cancel(a):
            return await s.cancel_worker(caller, a.worker_id, reason=a.reason)

        async def progress(a):
            return await s.solver_progress(caller, a)

        async def review(a):
            return await s.solver_review(caller, a)

        async def submit(a):
            return await s.submit_flag(caller, a.flag)

        async def update(a):
            return await s.report_worker(caller, a, terminal=False)

        async def report(a):
            result = await s.report_worker(caller, a, terminal=True)
            return ToolDispatchOutcome(result, yield_session=bool(result.get("ok")))

        async def evidence(a):
            return await s.read_evidence(caller, **a.model_dump())

        async def search(a):
            return await s.search_evidence(caller, **a.model_dump())

        async def read_report(a):
            return await s.read_report(caller, **a.model_dump())

        controls = [
            (
                "chief_observe",
                ReportQueryArguments,
                chief_observe,
                "Observe competition, capacity and Solver reports.",
            ),
            (
                "chief_launch_challenges",
                LaunchChallengesArguments,
                launch,
                "Start challenges or resume their existing Solver.",
            ),
            (
                "chief_wait",
                ControllerWaitArguments,
                wait,
                "Wait for new state without polling the model.",
            ),
            (
                "chief_request_hint",
                SimpleHintArguments,
                hint,
                "Request one platform hint for a challenge.",
            ),
            (
                "chief_pause_challenges",
                PauseChallengesArguments,
                pause,
                "Pause work, preserving Solver identity; release targets by default.",
            ),
            (
                "chief_close_challenges",
                CloseChallengesArguments,
                close,
                "Permanently close challenges and release their resources.",
            ),
            (
                "solver_observe",
                SolverObserveArguments,
                observe,
                "Read authoritative challenge state, task ledger and incremental Worker reports.",
            ),
            (
                "solver_delegate",
                DelegateArguments,
                delegate,
                "Delegate independent source inspection, client validation or evidence review with context_refs and success_criteria. Use execute for experiments and review for read-only analysis. Review Workers cannot read parent paths or task logs; provide exact evidence/report refs for artifact-specific review. Continue independent work and reuse existing tasks.",
            ),
            (
                "solver_cancel_worker",
                CancelWorkerArguments,
                cancel,
                "Cancel one owned Worker. Does not create replacement work.",
            ),
            (
                "solver_wait",
                ControllerWaitArguments,
                wait,
                "Wait for an active task or Worker completion, preserving sessions. Not a timer or application readiness check; without a wake source, returns immediately.",
            ),
            (
                "solver_progress",
                SolverProgressArguments,
                progress,
                "Publish Solver progress to Chief.",
            ),
            (
                "solver_review",
                SolverReviewArguments,
                review,
                "Record progress, uncertainty and the next test when useful. Ordinary observations need no calibration. Supply validation for verified conclusions or ruled-out hypotheses; revoke invalidated sources explicitly.",
            ),
            (
                "solver_submit_flag",
                SubmitFlagArguments,
                submit,
                "Submit an exact candidate answer. Platform state determines challenge completion.",
            ),
            (
                "worker_update",
                WorkerUpdateInput,
                update,
                "Publish evidence, tested and untested scope, and suggestions; continue the same task.",
            ),
            (
                "worker_report",
                ReviewAgentReportInput if self.mode == "review" else AgentReportInput,
                report,
                "Finish this explicit task with a terminal report. Review Workers report summary, evidence_refs, tested, untested and next_steps only; findings are not accepted in review mode.",
            ),
            (
                "evidence_read",
                EvidenceReadArguments,
                evidence,
                "Read one Evidence reference within this challenge and Run, with pagination.",
            ),
            (
                "evidence_search",
                EvidenceSearchArguments,
                search,
                "Search same-challenge Evidence metadata with pagination.",
            ),
            (
                "report_read",
                ReportReadArguments,
                read_report,
                "Read a same-challenge report by reference with pagination.",
            ),
        ]
        read_names = {
            "chief_observe",
            "solver_observe",
            "evidence_read",
            "evidence_search",
            "report_read",
        }
        return [
            ToolSpec(
                name,
                description,
                model,
                handler,
                lambda _a, read=name in read_names: (
                    AccessClaim("read" if read else "write", "agent:" + caller),
                ),
                requires_solo=name in {"chief_wait", "solver_wait", "worker_report"},
            )
            for name, model, handler, description in controls
            if self.policy.allows(name)
        ]
