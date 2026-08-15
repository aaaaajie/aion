"""Read-only performance summary for one or more AION run records."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from statistics import median
from typing import Any


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
    dispatch_latency: list[float] = []
    model_rounds_to_dispatch: list[float] = []
    first_useful_round_by_agent: dict[str, float] = {}
    soft_guard_warnings = 0
    report_items_dropped = 0
    evidence_ref_count = 0
    low_yield_count = 0
    request_reference_errors = 0
    context_budget_preflights = 0
    empty_response_recoveries = 0
    context_soft_limit_exceeded = 0
    context_capacity_deferred = 0
    controller_recovery_scheduled = 0
    controller_recovered = 0
    controller_recovery_latency: list[float] = []
    runtime_fatal_errors = 0
    agent_roles: dict[str, str] = {}
    summary_by_role: dict[str, dict[str, int]] = {}
    findings_received = 0
    findings_persisted = 0
    findings_dropped = 0
    findings_normalized = 0
    candidate_flags = 0
    flag_submissions = 0
    flag_submissions_accepted = 0
    critical_tool_results: dict[str, dict[str, Any]] = {}
    first_dispatch_result_by_agent: dict[str, bool] = {}
    cleanup_failure_events = 0
    cleanup_failures_by_manager: dict[str, int] = {}
    bootstrap_events: dict[str, int] = {
        "created": 0,
        "started": 0,
        "completed": 0,
        "conclude_started": 0,
        "conclude_completed": 0,
        "shared_snapshots": 0,
        "shared_replays": 0,
    }
    bootstrap_shared_reports = 0
    bootstrap_candidate_flags = 0
    llm_response_rejections: dict[str, int] = {}
    llm_reasoning_missing = 0
    llm_policy: dict[str, Any] | None = None

    def collect_event(
        event_type: str, value: dict[str, Any], agent_id: str | None
    ) -> None:
        nonlocal memory_updates, summary_failures, micro_compactions
        nonlocal compaction_skips, unbatched_event_count, persisted_results
        nonlocal soft_guard_warnings, report_items_dropped
        nonlocal evidence_ref_count, low_yield_count
        nonlocal request_reference_errors, context_budget_preflights
        nonlocal empty_response_recoveries
        nonlocal context_soft_limit_exceeded, context_capacity_deferred
        nonlocal controller_recovery_scheduled, controller_recovered
        nonlocal runtime_fatal_errors
        nonlocal findings_received, findings_persisted, findings_dropped
        nonlocal findings_normalized, candidate_flags
        nonlocal flag_submissions, flag_submissions_accepted
        nonlocal cleanup_failure_events
        nonlocal skill_discovery_started, skill_discovery_completed
        nonlocal skill_discovery_failed, skill_discovery_fallback
        nonlocal skill_candidate_count
        nonlocal skill_discovery_cache_hits
        nonlocal bootstrap_shared_reports, bootstrap_candidate_flags
        nonlocal llm_reasoning_missing, llm_policy

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
        elif event_type == "bootstrap_created":
            bootstrap_events["created"] += 1
        elif event_type == "bootstrap_started":
            bootstrap_events["started"] += 1
        elif event_type == "bootstrap_completed":
            bootstrap_events["completed"] += 1
            bootstrap_candidate_flags += int(bool(value.get("candidate_flag_present")))
        elif event_type == "bootstrap_conclude_started":
            bootstrap_events["conclude_started"] += 1
        elif event_type == "bootstrap_conclude_completed":
            bootstrap_events["conclude_completed"] += 1
        elif event_type == "bootstrap_shared_snapshot":
            bootstrap_events["shared_snapshots"] += 1
            bootstrap_shared_reports += int(value.get("report_count") or len(value.get("reports") or []))
        elif event_type == "bootstrap_shared_snapshot_replayed":
            bootstrap_events["shared_replays"] += 1
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
        elif event_type == "controller_session_recovery_scheduled":
            controller_recovery_scheduled += 1
        elif event_type == "controller_session_recovered":
            controller_recovered += 1
            if value.get("controller_recovery_latency_ms") is not None:
                controller_recovery_latency.append(
                    float(value["controller_recovery_latency_ms"])
                )
        elif event_type == "runtime_fatal_error":
            runtime_fatal_errors += 1
        elif event_type == "llm_policy_configured":
            llm_policy = dict(value)
        elif event_type == "llm_reasoning_missing":
            llm_reasoning_missing += 1
        elif event_type == "llm_response_rejected":
            reason = str(value.get("reason") or "unknown")
            llm_response_rejections[reason] = (
                llm_response_rejections.get(reason, 0) + 1
            )
        elif event_type == "llm_empty_report_recovery":
            empty_response_recoveries += 1
        elif event_type == "skill_catalog_ready" and value.get(
            "initialization_latency_ms"
        ) is not None:
            skill_catalog_init.append(float(value["initialization_latency_ms"]))
        elif event_type == "skill_top_k_selected" and value.get(
            "latency_ms"
        ) is not None:
            skill_top_k.append(float(value["latency_ms"]))
        elif event_type == "skill_discovery_started":
            skill_discovery_started += 1
        elif event_type == "skill_discovery_completed":
            skill_discovery_completed += 1
            if value.get("latency_ms") is not None:
                skill_discovery_latency.append(float(value["latency_ms"]))
            source = str(value.get("source") or "unknown")
            skill_discovery_sources[source] = (
                skill_discovery_sources.get(source, 0) + 1
            )
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
            skill_discovery_sources[source] = (
                skill_discovery_sources.get(source, 0) + 1
            )
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
        elif event_type == "challenge_dispatched":
            if value.get("dispatch_latency_ms") is not None:
                dispatch_latency.append(float(value["dispatch_latency_ms"]))
            soft_guard_warnings += int(
                value.get("soft_guard_warning_count") or 0
            )
        elif event_type == "agent_report":
            report_items_dropped += int(value.get("report_items_dropped") or 0)
            findings_received += int(value.get("findings_received") or 0)
            findings_persisted += int(value.get("findings_persisted") or 0)
            findings_dropped += int(value.get("findings_dropped") or 0)
            findings_normalized += int(value.get("findings_normalized") or 0)
            candidate_flags += int(bool(value.get("candidate_flag_present")))
        elif event_type == "evidence_persisted":
            evidence_ref_count += 1
        elif event_type == "challenge_low_yield":
            low_yield_count += 1
        elif event_type == "agent_resource_cleanup_failed":
            cleanup_failure_events += 1
            failures = value.get("failures")
            if isinstance(failures, list):
                for failure in failures:
                    if not isinstance(failure, dict):
                        continue
                    manager = str(failure.get("manager") or "unknown")
                    cleanup_failures_by_manager[manager] = (
                        cleanup_failures_by_manager.get(manager, 0) + 1
                    )

        if (
            event_type == "resource_work_status_changed"
            and value.get("status") == "reserved"
            and value.get("queue_latency_ms") is not None
        ):
            resource_queue.append(float(value["queue_latency_ms"]))
        elif event_type == "agent_admission_reserved" and value.get(
            "queue_latency_ms"
        ) is not None:
            agent_queue.append(float(value["queue_latency_ms"]))
        elif event_type == "cycle_transition_completed" and value.get(
            "transition_latency_ms"
        ) is not None:
            transitions.append(float(value["transition_latency_ms"]))
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
                }:
                    request_reference_errors += 1
            result = value.get("result")
            successful = isinstance(result, dict) and result.get("ok") is True
            round_number = value.get("round")
            if tool_name in {
                "challenge_dispatch",
                "execution_report",
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
            if (
                tool_name == "challenge_dispatch"
            ):
                if agent_id and agent_id not in first_dispatch_result_by_agent:
                    first_dispatch_result_by_agent[agent_id] = successful
                if successful and isinstance(round_number, int | float):
                    model_rounds_to_dispatch.append(float(round_number))
            if tool_name == "challenge_submit_flag":
                flag_submissions += 1
                if successful:
                    flag_submissions_accepted += 1
            if (
                successful
                and agent_id
                and tool_name.startswith("system_")
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
            if tool_name == "skill_search" and value.get(
                "execution_latency_ms"
            ) is not None:
                skill_search.append(float(value["execution_latency_ms"]))
            elif tool_name == "skill_invoke" and value.get(
                "execution_latency_ms"
            ) is not None:
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
        for event_type, payload, agent_id in connection.execute(
            "SELECT event_type, payload, agent_id FROM state_events "
            "WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ):
            try:
                value = json.loads(payload or "{}")
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                collect_event(str(event_type), value, agent_id)
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
    return {
        "run_id": run_id,
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
        "critical_tools": dict(sorted(critical_tool_results.items())),
        "competition_flow": {
            "dispatch_latency_ms": _summary(dispatch_latency),
            "model_rounds_to_dispatch": _summary(model_rounds_to_dispatch),
            "soft_guard_warning_count": soft_guard_warnings,
            "report_items_dropped": report_items_dropped,
            "first_useful_tool_round": _summary(
                list(first_useful_round_by_agent.values())
            ),
            "evidence_ref_count": evidence_ref_count,
            "low_yield_count": low_yield_count,
            "request_reference_error_count": request_reference_errors,
            "first_dispatch_success_rate": (
                round(
                    sum(first_dispatch_result_by_agent.values())
                    / len(first_dispatch_result_by_agent),
                    4,
                )
                if first_dispatch_result_by_agent
                else None
            ),
            "model_latency_share": (
                round(
                    sum(model_latency)
                    / (sum(model_latency) + sum(tool_execution)),
                    4,
                )
                if model_latency or tool_execution
                else None
            ),
        },
        "findings": {
            "received": findings_received,
            "normalized": findings_normalized,
            "persisted": findings_persisted,
            "dropped": findings_dropped,
            "persistence_rate": (
                round(findings_persisted / findings_received, 4)
                if findings_received
                else None
            ),
        },
        "flags": {
            "candidate_count": candidate_flags,
            "submission_count": flag_submissions,
            "accepted_count": flag_submissions_accepted,
        },
        "bootstrap": {
            **bootstrap_events,
            "shared_report_count": bootstrap_shared_reports,
            "candidate_flag_count": bootstrap_candidate_flags,
        },
        "context_budget": {
            "preflight_count": context_budget_preflights,
            "empty_response_recovery_count": empty_response_recoveries,
            "soft_limit_exceeded_count": context_soft_limit_exceeded,
            "capacity_deferred_count": context_capacity_deferred,
        },
        "controller_recovery": {
            "scheduled_count": controller_recovery_scheduled,
            "recovered_count": controller_recovered,
            "latency_ms": _summary(controller_recovery_latency),
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
                    / sum(role == "execution" for role in agent_roles.values()),
                    4,
                )
                if any(role == "execution" for role in agent_roles.values())
                else None
            ),
            "model_activation_agent_count": len(skill_model_activation_agents),
            "model_activation_rate": (
                round(
                    len(skill_model_activation_agents)
                    / len(skill_candidate_agents),
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
