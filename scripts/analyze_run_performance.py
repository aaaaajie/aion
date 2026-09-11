"""Read-only performance summary for one or more AION run records."""

from __future__ import annotations

import argparse
import json
from agent.model_usage import aggregate_usage
from agent.state.database import SCHEMA_VERSION
from scripts.analyze_hint_delivery import hint_delivery_metrics
import sqlite3
from pathlib import Path
from statistics import median
from typing import Any


# Historical run bundles are immutable analysis inputs.  Runtime state still
# rejects old schemas; the report reader may inspect the immediately preceding
# format so downloaded failure snapshots remain auditable.
ANALYZABLE_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION, 18})


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return round(float(ordered[index]), 3)


def _summary(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "p50": round(float(median(values)), 3) if values else None,
        "p95": _percentile(values, 0.95),
        "max": round(max(values), 3) if values else None,
    }


def analyze_run(database: Path, run_id: str) -> dict[str, Any]:
    model_latency: list[float] = []
    model_attempts: list[float] = []
    model_retry_delay: list[float] = []
    completion_tokens: list[float] = []
    reasoning_tokens: list[float] = []
    prompt_cache_hits: list[float] = []
    prompt_cache_misses: list[float] = []
    resource_queue: list[float] = []
    agent_queue: list[float] = []
    transitions: list[float] = []
    prompt_tokens: list[float] = []
    tool_queue: list[float] = []
    tool_execution: list[float] = []
    tool_total: list[float] = []
    tool_failures: dict[str, int] = {}
    http_tools: dict[str, dict[str, int]] = {}
    http_execution_work = 0
    http_analysis_work = 0
    http_interactions = 0
    http_connection_pool: dict[str, int] = {}
    persisted_results = 0
    memory_updates = 0
    summary_failures = 0
    micro_compactions = 0
    compaction_skips = 0
    event_transaction_ids: set[str] = set()
    unbatched_event_count = 0
    resource_leaks: dict[str, int] = {}
    skill_catalog_init: list[float] = []
    skill_top_k: list[float] = []
    skill_search: list[float] = []
    skill_first_activation: list[float] = []
    skill_repeat_activation: list[float] = []
    skill_discovery_latency: list[float] = []
    skill_discovery_started = 0
    skill_discovery_completed = 0
    skill_discovery_failed = 0
    skill_discovery_fallback = 0
    skill_candidate_count = 0
    skill_candidate_agents: set[str] = set()
    skill_model_activation_agents: set[str] = set()
    skill_discovery_sources: dict[str, int] = {}
    skill_discovery_failures: dict[str, int] = {}
    skill_discovery_cache_hits = 0
    model_rounds_to_dispatch: list[float] = []
    first_useful_round_by_agent: dict[str, float] = {}
    evidence_ref_count = 0
    request_reference_errors = 0
    context_budget_preflights = 0
    empty_response_recoveries = 0
    context_soft_limit_exceeded = 0
    context_capacity_deferred = 0
    model_recoveries = 0
    runtime_fatal_errors = 0
    agent_roles: dict[str, str] = {}
    summary_by_role: dict[str, dict[str, int]] = {}
    findings_received = 0
    findings_persisted = 0
    candidate_flags = 0
    flag_submissions = 0
    flag_submissions_correct = 0
    critical_tool_results: dict[str, dict[str, Any]] = {}
    first_delegation_result_by_agent: dict[str, bool] = {}
    cleanup_failure_events = 0
    cleanup_failures_by_manager: dict[str, int] = {}
    llm_response_rejections: dict[str, int] = {}
    llm_reasoning_missing = 0
    llm_policy: dict[str, Any] | None = None
    observer_outcomes: dict[str, int] = {}
    observer_failures: dict[str, int] = {}
    observer_trimmed = 0
    observer_skipped = 0
    observer_received: set[tuple[str, int]] = set()
    observer_assessments: dict[str, int] = {}
    observer_tensions = 0
    observer_corrections: dict[str, int] = {}
    correction_deliveries: set[str] = set()
    review_metrics = {"deliveries": 0, "automatic_triggers": 0, "task_snapshot_deliveries": 0,
                      "successful_records": 0, "rejected_calls": 0, "assessments": {}}
    stagnation_metrics = {
        "review_due_count": 0,
        "strategy_reset_count": 0,
        "alternate_worker_started_count": 0,
        "alternate_worker_finished_count": 0,
        "rotation_requested_count": 0,
        "worker_results": {},
        "max_stalled_seconds": 0,
    }
    covered_results: set[tuple[str, int]] = set()
    execution_results: set[tuple[str, int]] = set()
    parameter_errors: dict[str, int] = {}
    preflight = {"calls": 0, "successes": 0, "failures": 0}
    completion_reasons: dict[str, int] = {}
    # Shell completion is an execution outcome, separate from tool-gateway
    # errors.  Keep one terminal record per task so repeated cleanup events do
    # not inflate the report.
    shell_terminal_by_task: dict[tuple[str, str], dict[str, Any]] = {}

    def collect_event(
        event_type: str, value: dict[str, Any], agent_id: str | None, sequence: int = 0
    ) -> None:
        nonlocal memory_updates, summary_failures, micro_compactions
        nonlocal compaction_skips, unbatched_event_count, persisted_results
        nonlocal evidence_ref_count
        nonlocal findings_received, findings_persisted, candidate_flags
        nonlocal request_reference_errors, context_budget_preflights
        nonlocal empty_response_recoveries
        nonlocal context_soft_limit_exceeded, context_capacity_deferred
        nonlocal model_recoveries
        nonlocal runtime_fatal_errors
        nonlocal flag_submissions, flag_submissions_correct
        nonlocal cleanup_failure_events
        nonlocal skill_discovery_started, skill_discovery_completed
        nonlocal skill_discovery_failed, skill_discovery_fallback
        nonlocal skill_candidate_count
        nonlocal skill_discovery_cache_hits
        nonlocal llm_reasoning_missing, llm_policy
        nonlocal observer_trimmed, observer_skipped, observer_tensions

        if event_type.startswith("observer_correction_"):
            kind = event_type.removeprefix("observer_correction_")
            observer_corrections[kind] = observer_corrections.get(kind, 0) + 1
        if event_type == "run_finished":
            reason = str(value.get("reason") or "unrecorded")
            completion_reasons[reason] = completion_reasons.get(reason, 0) + 1
        if event_type == "shell_task_finished":
            task_id = value.get("task_id")
            if isinstance(task_id, str):
                # Events in this report are filtered to one Run.  Keeping the
                # run id in the identity makes the de-duplication contract
                # explicit and safe for callers that reuse this accumulator.
                key = (run_id, task_id)
                previous = shell_terminal_by_task.get(key)
                if previous is None or sequence >= int(previous.get("sequence") or 0):
                    shell_terminal_by_task[key] = {
                        **value,
                        "sequence": sequence,
                    }
        if event_type == "solver_review_delivered":
            review_metrics["deliveries"] += 1
            review_metrics["automatic_triggers"] += int(value.get("automatic_review_recommended") is True)
            review_metrics["task_snapshot_deliveries"] += int("task_snapshot_changed" in value.get("trigger_reasons", []))
        if event_type in {
            "solver_stagnation_review_due",
            "solver_strategy_reset",
            "solver_stagnation_worker_started",
            "solver_stagnation_worker_finished",
            "solver_stagnation_rotation_requested",
        }:
            stalled = value.get("stalled_seconds")
            if isinstance(stalled, (int, float)):
                stagnation_metrics["max_stalled_seconds"] = max(
                    stagnation_metrics["max_stalled_seconds"], int(stalled)
                )
        if event_type == "solver_stagnation_review_due":
            stagnation_metrics["review_due_count"] += 1
        elif event_type == "solver_strategy_reset" and value.get("trigger") == "stagnation_review_due":
            stagnation_metrics["strategy_reset_count"] += 1
        elif event_type == "solver_stagnation_worker_started":
            stagnation_metrics["alternate_worker_started_count"] += 1
        elif event_type == "solver_stagnation_worker_finished":
            stagnation_metrics["alternate_worker_finished_count"] += 1
            status = str(value.get("status") or "unknown")
            results = stagnation_metrics["worker_results"]
            results[status] = results.get(status, 0) + 1
        elif event_type == "solver_stagnation_rotation_requested":
            stagnation_metrics["rotation_requested_count"] += 1

        if event_type == "assistant_response" and value.get("observation_correction_id"):
            correction_deliveries.add(value['observation_correction_id'])
        if event_type == "assistant_response" and value.get("observation_revision"):
            observer_received.add((str(agent_id), value["observation_revision"]))
        if event_type == "solver_review_record":
            review_metrics["successful_records"] += 1
            review = value.get("review") or {}
            outcome = review.get("assessment", "unrecorded")
            review_metrics["assessments"][outcome] = review_metrics["assessments"].get(outcome, 0) + 1
            covered_results.update((str(agent_id), seq) for seq in review.get("covered_sequences", []))
            covered_results.update((str(agent_id), seq) for seq in (review.get("validation") or {}).get("conclusion_sequences", []))
            assessment = (value.get("review") or {}).get("observation_assessment")
            if assessment:
                observer_assessments[assessment] = observer_assessments.get(assessment, 0) + 1
        if event_type == "solver_observation_snapshot":
            observer_tensions += len((value.get("map") or {}).get("TENSION", []))
            diagnostics = value.get("diagnostics") or {}
            outcome = diagnostics.get("outcome") or value.get("status", "unknown")
            observer_outcomes[outcome] = observer_outcomes.get(outcome, 0) + 1
            stage = diagnostics.get("failure_stage")
            if stage:
                observer_failures[stage] = observer_failures.get(stage, 0) + 1
            observer_trimmed += sum(diagnostics.get("trimmed_entries", {}).values())
            observer_skipped += ((value.get("coverage") or {}).get("skipped") or {}).get("count", 0)

        role = agent_roles.get(str(agent_id or ""), "unknown")
        role_summary = summary_by_role.setdefault(
            role,
            {"successes": 0, "failures": 0, "micro_compactions": 0},
        )

        transaction_id = value.get("event_transaction_id")
        if isinstance(transaction_id, str):
            event_transaction_ids.add(transaction_id)
        else:
            unbatched_event_count += 1
        if event_type == "memory_updated":
            memory_updates += 1
            role_summary["successes"] += 1
        elif event_type == "memory_update_failed":
            summary_failures += 1
            role_summary["failures"] += 1
        elif event_type == "context_micro_compacted":
            micro_compactions += 1
            role_summary["micro_compactions"] += 1
        elif event_type == "context_compaction_skipped":
            compaction_skips += 1
        elif event_type == "context_budget_preflight":
            context_budget_preflights += 1
        elif event_type == "context_soft_limit_exceeded":
            context_soft_limit_exceeded += 1
        elif event_type == "context_capacity_deferred":
            context_capacity_deferred += 1
        elif event_type == "agent_model_recovery":
            model_recoveries += 1
        elif event_type == "runtime_fatal_error":
            runtime_fatal_errors += 1
        elif event_type == "llm_policy_configured":
            llm_policy = dict(value)
        elif event_type == "llm_reasoning_missing":
            llm_reasoning_missing += 1
        elif event_type == "llm_response_rejected":
            reason = str(value.get("reason") or "unknown")
            llm_response_rejections[reason] = llm_response_rejections.get(reason, 0) + 1
        elif event_type == "llm_empty_report_recovery":
            empty_response_recoveries += 1
        elif (
            event_type == "skill_catalog_ready"
            and value.get("initialization_latency_ms") is not None
        ):
            skill_catalog_init.append(float(value["initialization_latency_ms"]))
        elif (
            event_type == "skill_top_k_selected" and value.get("latency_ms") is not None
        ):
            skill_top_k.append(float(value["latency_ms"]))
        elif event_type == "skill_discovery_started":
            skill_discovery_started += 1
        elif event_type == "skill_discovery_completed":
            skill_discovery_completed += 1
            if value.get("latency_ms") is not None:
                skill_discovery_latency.append(float(value["latency_ms"]))
            source = str(value.get("source") or "unknown")
            skill_discovery_sources[source] = skill_discovery_sources.get(source, 0) + 1
            skill_discovery_cache_hits += int(bool(value.get("cache_hit")))
        elif event_type == "skill_discovery_failed":
            skill_discovery_failed += 1
            failure_code = str(value.get("failure_code") or "unknown")
            skill_discovery_failures[failure_code] = (
                skill_discovery_failures.get(failure_code, 0) + 1
            )
        elif event_type == "skill_discovery_fallback":
            skill_discovery_fallback += 1
            if value.get("latency_ms") is not None:
                skill_discovery_latency.append(float(value["latency_ms"]))
            source = str(value.get("source") or "local_fallback")
            skill_discovery_sources[source] = skill_discovery_sources.get(source, 0) + 1
        elif event_type == "skill_candidate_presented":
            skill_candidate_count += int(value.get("candidate_count") or 0)
            if agent_id:
                skill_candidate_agents.add(str(agent_id))
        elif (
            event_type == "skill_activated"
            and value.get("activation_mode") == "model"
            and agent_id
        ):
            skill_model_activation_agents.add(str(agent_id))
        elif event_type in {"worker_reported", "worker_updated"}:
            findings_received += int(value.get("findings_received") or 0)
            findings_persisted += int(value.get("findings_persisted") or 0)
            candidate_flags += int(bool(value.get("candidate_flag_present")))
        elif event_type == "evidence_persisted":
            evidence_ref_count += 1
        elif event_type == "agent_resource_cleanup_failed":
            cleanup_failure_events += 1
            failures = value.get("failures")
            if isinstance(failures, list):
                for failure in failures:
                    if not isinstance(failure, dict):
                        continue
                    manager = str(failure.get("resource") or "unknown")
                    cleanup_failures_by_manager[manager] = (
                        cleanup_failures_by_manager.get(manager, 0) + 1
                    )

        if (
            event_type == "resource_work_status_changed"
            and value.get("status") == "reserved"
            and value.get("queue_latency_ms") is not None
        ):
            resource_queue.append(float(value["queue_latency_ms"]))
        elif (
            event_type == "agent_admission_reserved"
            and value.get("queue_latency_ms") is not None
        ):
            agent_queue.append(float(value["queue_latency_ms"]))
        elif event_type == "assistant_response":
            if value.get("latency_ms") is not None:
                model_latency.append(float(value["latency_ms"]))
            if value.get("prompt_tokens") is not None:
                prompt_tokens.append(float(value["prompt_tokens"]))
            if value.get("attempts") is not None:
                model_attempts.append(float(value["attempts"]))
            if value.get("retry_delay_ms") is not None:
                model_retry_delay.append(float(value["retry_delay_ms"]))
            if value.get("completion_tokens") is not None:
                completion_tokens.append(float(value["completion_tokens"]))
            if value.get("reasoning_tokens") is not None:
                reasoning_tokens.append(float(value["reasoning_tokens"]))
            if value.get("prompt_cache_hit_tokens") is not None:
                prompt_cache_hits.append(float(value["prompt_cache_hit_tokens"]))
            if value.get("prompt_cache_miss_tokens") is not None:
                prompt_cache_misses.append(float(value["prompt_cache_miss_tokens"]))
        elif event_type == "tool_result":
            tool_name = str(value.get("tool_name") or "")
            tool_result = value.get("result") or {}
            tool_error = tool_result.get("error") or {}
            stage = value.get("error_stage") or tool_error.get("stage")
            if stage in {"parse", "schema", "semantic"}:
                parameter_errors[tool_name] = parameter_errors.get(tool_name, 0) + 1
            if tool_name == "solver_review" and tool_result.get("ok") is False:
                review_metrics["rejected_calls"] += 1
            if tool_name == "system_http_plan" and not value.get("replayed"):
                preflight["calls"] += 1
                preflight["successes" if tool_result.get("ok") else "failures"] += 1
            if value.get("queue_latency_ms") is not None:
                tool_queue.append(float(value["queue_latency_ms"]))
            if value.get("execution_latency_ms") is not None:
                tool_execution.append(float(value["execution_latency_ms"]))
            if value.get("total_latency_ms") is not None:
                tool_total.append(float(value["total_latency_ms"]))
            if value.get("result_persisted"):
                persisted_results += 1
            error_code = value.get("error_code")
            if isinstance(error_code, str):
                key = f"{value.get('error_stage') or 'unknown'}:{error_code}"
                tool_failures[key] = tool_failures.get(key, 0) + 1
                if error_code in {
                    "http_response_not_found",
                    "http_request_not_found",
                    "http_interaction_not_found",
                    "invalid_evidence_ref",
                    "evidence_not_accessible",
                }:
                    request_reference_errors += 1
            result = value.get("result")
            successful = isinstance(result, dict) and result.get("ok") is True
            round_number = value.get("round")
            if tool_name in {
                "solver_delegate",
                "worker_report",
                "system_http_probe",
            }:
                totals = critical_tool_results.setdefault(
                    tool_name,
                    {"calls": 0, "successes": 0, "failures": {}},
                )
                totals["calls"] += 1
                if successful:
                    totals["successes"] += 1
                else:
                    failure_key = (
                        f"{value.get('error_stage') or 'unknown'}:"
                        f"{value.get('error_code') or 'unknown'}"
                    )
                    failures = totals["failures"]
                    failures[failure_key] = failures.get(failure_key, 0) + 1
            if tool_name == "solver_delegate":
                if agent_id and agent_id not in first_delegation_result_by_agent:
                    first_delegation_result_by_agent[agent_id] = successful
                if successful and isinstance(round_number, int | float):
                    model_rounds_to_dispatch.append(float(round_number))
            if tool_name == "solver_submit_flag":
                flag_submissions += 1
                data = result.get("data", {}) if isinstance(result, dict) else {}
                if successful and (
                    data.get("correct") is True
                ):
                    flag_submissions_correct += 1
            if (
                successful
                and agent_id
                and tool_name.startswith("system_")
                and tool_name != "system_http_plan"
                and isinstance(round_number, int | float)
            ):
                first_useful_round_by_agent.setdefault(agent_id, float(round_number))
            if tool_name.startswith(("system_http_", "system_web_")):
                totals = http_tools.setdefault(
                    tool_name, {"calls": 0, "successes": 0, "failures": 0}
                )
                totals["calls"] += 1
                totals["failures" if isinstance(error_code, str) else "successes"] += 1
                result = value.get("result")
                data = result.get("data") if isinstance(result, dict) else None
                stats = (
                    data.get("connection_pool")
                    if isinstance(data, dict)
                    else result.get("connection_pool")
                    if isinstance(result, dict)
                    else None
                )
                if isinstance(stats, dict):
                    for key, metric in stats.items():
                        if isinstance(metric, int):
                            http_connection_pool[key] = max(
                                metric, http_connection_pool.get(key, 0)
                            )
            if (
                tool_name == "skill_search"
                and value.get("execution_latency_ms") is not None
            ):
                skill_search.append(float(value["execution_latency_ms"]))
            elif (
                tool_name == "skill_invoke"
                and value.get("execution_latency_ms") is not None
            ):
                result = value.get("result")
                data = result.get("data") if isinstance(result, dict) else None
                status = (
                    data.get("activation_status") if isinstance(data, dict) else None
                )
                target = (
                    skill_repeat_activation
                    if status == "already_active"
                    else skill_first_activation
                )
                target.append(float(value["execution_latency_ms"]))

    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        version = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        if not version or version[0] not in {str(item) for item in ANALYZABLE_SCHEMA_VERSIONS}:
            raise ValueError(
                f"Only schemas {sorted(ANALYZABLE_SCHEMA_VERSIONS)} runs can be analyzed by this implementation"
            )
        usage_events = [
            dict(zip(("event_type", "payload", "agent_id"), item))
            for item in connection.execute(
                "SELECT event_type,payload,agent_id FROM state_events WHERE run_id=? AND event_type IN ('model_call_started','model_call_finished') ORDER BY sequence",
                (run_id,),
            )
        ]
        usage_agents = [
            dict(zip(("agent_id", "unique_code"), item))
            for item in connection.execute(
                "SELECT agent_id,unique_code FROM agents WHERE run_id=?", (run_id,)
            )
        ]
        token_usage = aggregate_usage(usage_events, usage_agents)
        tables = {
            str(item[0])
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        row = connection.execute(
            "SELECT status, last_sequence FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"run {run_id!r} was not found")
        if "agents" in tables:
            agent_roles.update(
                {
                    str(agent_id): str(role)
                    for agent_id, role in connection.execute(
                        "SELECT agent_id, role FROM agents WHERE run_id = ?",
                        (run_id,),
                    )
                }
            )
        for sequence, event_type, payload, agent_id in connection.execute(
            "SELECT sequence, event_type, payload, agent_id FROM state_events "
            "WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ):
            try:
                value = json.loads(payload or "{}")
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                if event_type in {"shell_task_finished", "http_interaction_status_changed"} or (
                    event_type == "tool_result" and value.get("tool_name") != "system_http_plan"
                ):
                    execution_results.add((str(agent_id), sequence))
                collect_event(str(event_type), value, agent_id, int(sequence))
        if "http_interactions" in tables:
            http_interactions = int(
                connection.execute(
                    "SELECT COUNT(*) FROM http_interactions WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
        if "resource_work_queue" in tables:
            for phase, count in connection.execute(
                "SELECT phase, COUNT(*) FROM resource_work_queue "
                "WHERE run_id = ? AND owner_type = 'http_interaction' GROUP BY phase",
                (run_id,),
            ):
                if str(phase).startswith("analysis-"):
                    http_analysis_work += int(count)
                elif str(phase).startswith("execution"):
                    http_execution_work += int(count)
        terminal_agents = "('completed','failed','stopped','cancelled','interrupted')"
        active_work = "('queued','reserved','starting','running')"
        resource_leaks["resource_work"] = (
            int(
                connection.execute(
                    "SELECT COUNT(*) FROM resource_work_queue w JOIN agents a "
                    "ON a.agent_id = w.agent_id WHERE w.run_id = ? "
                    f"AND a.status IN {terminal_agents} AND w.status IN {active_work}",
                    (run_id,),
                ).fetchone()[0]
            )
            if "resource_work_queue" in tables and "agents" in tables
            else 0
        )
        for label, table, active_statuses in (
            ("shell", "shell_tasks", "('running')"),
            ("network", "network_tasks", "('queued','running')"),
            (
                "http",
                "http_interactions",
                "('queued','reserved','starting','running','analyzing')",
            ),
        ):
            resource_leaks[label] = (
                int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} t JOIN agents a "
                        "ON a.agent_id = t.agent_id WHERE t.run_id = ? "
                        f"AND a.status IN {terminal_agents} AND t.status IN {active_statuses}",
                        (run_id,),
                    ).fetchone()[0]
                )
                if table in tables and "agents" in tables
                else 0
            )
        if "shell_tasks" in tables:
            # The task table remains authoritative when a terminal event was
            # not delivered before shutdown.  Preserve event cleanup details.
            terminal_statuses = {
                "completed", "failed", "timeout", "stopped", "interrupted", "cancelled"
            }
            for task_id, status, exit_code, timed_out, finished_at, cleanup_reason in connection.execute(
                "SELECT task_id,status,exit_code,timed_out,finished_at,cleanup_reason "
                "FROM shell_tasks WHERE run_id=?",
                (run_id,),
            ):
                if status not in terminal_statuses:
                    continue
                key = (run_id, str(task_id))
                event_item = shell_terminal_by_task.get(key, {})
                shell_terminal_by_task[key] = {
                    **event_item,
                    "task_id": str(task_id),
                    "status": status,
                    "exit_code": exit_code,
                    "timed_out": bool(timed_out),
                    "finished_at": finished_at,
                    "cleanup": event_item.get("cleanup") or ({"termination_reason": cleanup_reason} if cleanup_reason else {}),
                    "sequence": event_item.get("sequence", 0),
                }
        hint_delivery = hint_delivery_metrics(connection, run_id)
    shell_execution = {
        "terminal_task_count": len(shell_terminal_by_task),
        "completed_count": 0,
        "failed_count": 0,
        "timeout_count": 0,
        "stopped_count": 0,
        "interrupted_count": 0,
        "cancelled_count": 0,
        "nonzero_exit_count": 0,
        "unknown_exit_code_count": 0,
        "timed_out_count": 0,
        "termination_reasons": {},
    }
    for item in shell_terminal_by_task.values():
        status = str(item.get("status") or "unknown")
        key = f"{status}_count"
        if key in shell_execution:
            shell_execution[key] += 1
        exit_code = item.get("exit_code")
        if exit_code is None:
            shell_execution["unknown_exit_code_count"] += 1
        elif exit_code != 0:
            shell_execution["nonzero_exit_count"] += 1
        if item.get("timed_out") is True:
            shell_execution["timed_out_count"] += 1
        cleanup = item.get("cleanup") if isinstance(item.get("cleanup"), dict) else {}
        reason = cleanup.get("termination_reason")
        if reason:
            reasons = shell_execution["termination_reasons"]
            reasons[str(reason)] = reasons.get(str(reason), 0) + 1
    return {
        "reviews": {**review_metrics, "covered_result_count": len(covered_results & execution_results)},
        "stagnation": stagnation_metrics,
        "parameter_errors": parameter_errors,
        "preflight": preflight,
        "completion_reasons": completion_reasons,
        "hint_delivery": hint_delivery,
        "observer": {"outcomes": observer_outcomes, "failure_stages": observer_failures,
                     "trimmed_entries": observer_trimmed, "skipped_events": observer_skipped,
                     "received_revisions": len(observer_received), "tension_entries": observer_tensions,
                     "solver_reported_assessments": observer_assessments,
                     "verified_correction_count": observer_corrections.get("resolved", 0),
                     "corrections": {**observer_corrections,
                                     "delivered": len(correction_deliveries),
                                     "feedback": sum(observer_assessments.values())}},
        "run_id": run_id,
        "token_usage": token_usage,
        "status": row[0],
        "last_sequence": row[1],
        "model_latency_ms": _summary(model_latency),
        "model_attempts": _summary(model_attempts),
        "model_retry_delay_ms": _summary(model_retry_delay),
        "completion_tokens": _summary(completion_tokens),
        "reasoning_tokens": _summary(reasoning_tokens),
        "reasoning_token_ratio": (
            round(sum(reasoning_tokens) / sum(completion_tokens), 4)
            if completion_tokens and sum(completion_tokens)
            else None
        ),
        "prompt_cache": {
            "hit_tokens": _summary(prompt_cache_hits),
            "miss_tokens": _summary(prompt_cache_misses),
            "hit_ratio": (
                round(
                    sum(prompt_cache_hits)
                    / (sum(prompt_cache_hits) + sum(prompt_cache_misses)),
                    4,
                )
                if prompt_cache_hits or prompt_cache_misses
                else None
            ),
        },
        "llm_policy": llm_policy,
        "llm_response_rejections": dict(sorted(llm_response_rejections.items())),
        "llm_reasoning_missing_count": llm_reasoning_missing,
        "prompt_tokens": _summary(prompt_tokens),
        "resource_queue_latency_ms": _summary(resource_queue),
        "agent_queue_latency_ms": _summary(agent_queue),
        "transition_latency_ms": _summary(transitions),
        "tool_queue_latency_ms": _summary(tool_queue),
        "tool_execution_latency_ms": _summary(tool_execution),
        "tool_total_latency_ms": _summary(tool_total),
        "tool_result_persisted_count": persisted_results,
        "tool_failures": dict(sorted(tool_failures.items())),
        "shell_execution": shell_execution,
        "critical_tools": dict(sorted(critical_tool_results.items())),
        "competition_flow": {
            "model_rounds_to_dispatch": _summary(model_rounds_to_dispatch),
            "first_useful_tool_round": _summary(
                list(first_useful_round_by_agent.values())
            ),
            "evidence_ref_count": evidence_ref_count,
            "request_reference_error_count": request_reference_errors,
            "first_delegation_success_rate": (
                round(
                    sum(first_delegation_result_by_agent.values())
                    / len(first_delegation_result_by_agent),
                    4,
                )
                if first_delegation_result_by_agent
                else None
            ),
            "model_latency_share": (
                round(
                    sum(model_latency) / (sum(model_latency) + sum(tool_execution)),
                    4,
                )
                if model_latency or tool_execution
                else None
            ),
        },
        "findings": {
            "received": findings_received,
            "persisted": findings_persisted,
            "persistence_rate": (
                round(findings_persisted / findings_received, 4)
                if findings_received
                else None
            ),
        },
        "flags": {
            "candidate_count": candidate_flags,
            "submission_count": flag_submissions,
            "correct_count": flag_submissions_correct,
        },
        "context_budget": {
            "preflight_count": context_budget_preflights,
            "empty_response_recovery_count": empty_response_recoveries,
            "soft_limit_exceeded_count": context_soft_limit_exceeded,
            "capacity_deferred_count": context_capacity_deferred,
        },
        "model_recovery": {
            "attempts": model_recoveries,
            "runtime_fatal_error_count": runtime_fatal_errors,
        },
        "context_compaction": {
            "memory_update_count": memory_updates,
            "failure_count": summary_failures,
            "failure_rate": (
                round(summary_failures / (memory_updates + summary_failures), 4)
                if memory_updates + summary_failures
                else None
            ),
            "micro_compaction_count": micro_compactions,
            "skipped_count": compaction_skips,
            "by_role": {
                role: {
                    **counts,
                    "failure_rate": (
                        round(
                            counts["failures"]
                            / (counts["successes"] + counts["failures"]),
                            4,
                        )
                        if counts["successes"] + counts["failures"]
                        else None
                    ),
                }
                for role, counts in sorted(summary_by_role.items())
            },
        },
        "event_transactions": {
            "batched": len(event_transaction_ids),
            "unbatched": unbatched_event_count,
            "observed_total": len(event_transaction_ids) + unbatched_event_count,
        },
        "projection_file_count": sum(
            1 for path in database.parent.rglob("*") if path.is_file()
        ),
        "agent_resource_leaks": {
            **resource_leaks,
            "total": sum(resource_leaks.values()),
        },
        "agent_resource_cleanup_failures": {
            "event_count": cleanup_failure_events,
            "by_manager": dict(sorted(cleanup_failures_by_manager.items())),
            "failure_count": sum(cleanup_failures_by_manager.values()),
        },
        "skill": {
            "catalog_initialization_latency_ms": _summary(skill_catalog_init),
            "top_k_latency_ms": _summary(skill_top_k),
            "search_latency_ms": _summary(skill_search),
            "first_activation_latency_ms": _summary(skill_first_activation),
            "repeat_activation_latency_ms": _summary(skill_repeat_activation),
            "discovery_latency_ms": _summary(skill_discovery_latency),
            "discovery_started_count": skill_discovery_started,
            "discovery_completed_count": skill_discovery_completed,
            "discovery_failed_count": skill_discovery_failed,
            "discovery_fallback_count": skill_discovery_fallback,
            "discovery_sources": dict(sorted(skill_discovery_sources.items())),
            "discovery_failures": dict(sorted(skill_discovery_failures.items())),
            "discovery_cache_hit_count": skill_discovery_cache_hits,
            "candidate_presented_agent_count": len(skill_candidate_agents),
            "candidate_presented_count": skill_candidate_count,
            "candidate_presentation_rate": (
                round(
                    len(skill_candidate_agents)
                    / sum(role == "worker" for role in agent_roles.values()),
                    4,
                )
                if any(role == "worker" for role in agent_roles.values())
                else None
            ),
            "model_activation_agent_count": len(skill_model_activation_agents),
            "model_activation_rate": (
                round(
                    len(skill_model_activation_agents) / len(skill_candidate_agents),
                    4,
                )
                if skill_candidate_agents
                else None
            ),
            "discovery_failure_rate": (
                round(skill_discovery_failed / skill_discovery_started, 4)
                if skill_discovery_started
                else None
            ),
        },
        "http": {
            "interaction_count": http_interactions,
            "execution_resource_work_count": http_execution_work,
            "analysis_resource_work_count": http_analysis_work,
            "analysis_to_execution_ratio": (
                round(http_analysis_work / http_execution_work, 3)
                if http_execution_work
                else None
            ),
            "tools": dict(sorted(http_tools.items())),
            "connection_pool": http_connection_pool,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    root = args.run_root.expanduser().resolve()
    directories = [root / args.run_id] if args.run_id else sorted(root.iterdir())
    results = []
    for directory in directories:
        database = directory / "state.sqlite3"
        if not database.is_file():
            continue
        try:
            results.append(analyze_run(database, directory.name))
        except ValueError:
            # Ignore uninitialized run directories when producing a root-wide
            # report. An explicit --run-id remains strict above.
            if args.run_id:
                raise
    print(json.dumps({"runs": results}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
