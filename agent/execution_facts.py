"""Deterministic execution facts, independent of Solver experiment claims."""

import json

EXECUTION_TOOLS = frozenset({
    "system_fastcgi_request", "system_task_start", "system_shell", "system_http_request", "system_http_probe",
    "system_network_discovery", "system_web_path_probe", "system_web_fingerprint",
    "pentest_service_probe", "pentest_ssh_exec", "pentest_jwt", "pentest_arjun",
})
HTTP_TASK_TOOLS = frozenset({"system_http_output", "system_http_stop", "system_http_response", "system_http_analyze"})
TASK_TOOLS = frozenset({"system_shell", "system_task_start", "system_task_output", "system_task_stop", "system_network_discovery", "system_network_output", "system_network_stop"})
TERMINAL = frozenset({"completed", "failed", "timeout", "stopped", "interrupted", "cancelled"})


def execution_fact(name, result, *, result_ref=None, result_chars=None):
    if not isinstance(result, dict):
        return None
    if result.get("ok") is False and (result.get("error") or {}).get("stage") in {
        "parse", "schema", "semantic", "permission", "conflict",
    }:
        return None
    data = result.get("data", result)
    if not isinstance(data, dict):
        return None
    if name == "tool_result_read" and result.get("ok") is not False:
        return {"result_read": {key: data[key] for key in (
            "result_ref", "offset", "next_offset", "eof", "original_chars",
        ) if key in data}, "chars_returned": len(data.get("content", "")), "execution": False}
    if name not in EXECUTION_TOOLS | TASK_TOOLS | HTTP_TASK_TOOLS:
        return None
    fact = {key: data[key] for key in (
        "complete", "outcome_unknown", "execution_status", "task_id", "status", "exit_code", "timed_out", "output_incomplete", "output_available",
        "truncated", "result_state", "interaction_id",
    ) if key in data}
    fact["execution"] = name in EXECUTION_TOOLS
    fact["output_read"] = (
        isinstance(data.get("output"), str)
        and not data.get("truncated") and not data.get("output_incomplete")
        and data.get("status") in TERMINAL
    )
    if name == "system_network_output" and "page_end_cursor" in data:
        fact["network_read"] = {key: data[key] for key in ("cursor", "next_cursor", "page_end_cursor", "read_scope", "is_terminal")}
    if fact.get("interaction_id"):
        fact["output_read"] = False
        if "page_end_cursor" in data and isinstance(data.get("results"), list):
            fact["list_read"] = {key: data[key] for key in (
                "cursor", "next_cursor", "page_end_cursor", "has_more", "read_scope", "is_terminal",
            )}
        if name == "system_http_response" and "content" in data:
            fact["body_read"] = {key: data[key] for key in (
                "request_id", "body_sha256", "offset_bytes", "bytes_returned", "body_bytes", "eof",
            )}
    if result_ref:
        fact["delivery"] = {"result_ref": result_ref, "chars": result_chars}
    return fact


def merge_ranges(ranges, start, end):
    """Union half-open ranges, preserving gaps and accepting empty resources."""
    merged = []
    for a, b in sorted([*ranges, [start, end]]):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def fully_read(ranges, end):
    return bool(ranges) and ranges[0][0] == 0 and ranges[0][1] >= end


def project_execution(rows, covered):
    tasks, completions, urgent = {}, {}, []
    generation = 0
    deferred, bodies = {}, {}
    for row in rows:
        seq, kind, payload = row["sequence"], row["event_type"], row["payload"]
        if kind == "agent_resources_invalidated":
            generation = payload["generation"]
            urgent.append(seq)
        elif kind in {"shell_task_started", "shell_task_finished", "network_task_status_changed"}:
            key = payload["task_id"]
            task = tasks.setdefault(key, {"task_id": key, "output_read": False})
            task.update(payload, sequence=seq)
            if kind == "shell_task_finished" or (kind == "network_task_status_changed" and payload["status"] in TERMINAL):
                completions.setdefault(key, seq)
                if payload["status"] in {"timeout", "stopped", "interrupted"}:
                    urgent.append(seq)
        elif kind == "http_interaction_status_changed":
            key = payload["interaction_id"]
            status = payload.get("execution_status")
            task = tasks.setdefault(key, {"interaction_id": key, "output_read": False})
            task.update(status=status, sequence=seq)
            if "analysis_status" in payload:
                task["analysis_status"] = payload["analysis_status"]
            if status in TERMINAL or status == "cancelled":
                completions.setdefault(key, seq)
                if status in {"cancelled", "interrupted", "timeout"}:
                    urgent.append(completions[key])
        elif kind == "tool_result" and not payload.get("replayed"):
            fact = payload.get("execution_fact") or execution_fact(payload.get("tool_name"), payload.get("result"))
            if not fact:
                continue
            if "result_read" in fact:
                read = fact["result_read"]
                pending = deferred.get(read.get("result_ref"))
                if pending is None:
                    continue
                pending["ranges"] = merge_ranges(pending["ranges"], read["offset"], read["offset"] + fact["chars_returned"])
                if not fully_read(pending["ranges"], pending["chars"]):
                    continue
                fact = pending["fact"]
                payload = pending["payload"]
                del deferred[read["result_ref"]]
            delivery = fact.get("delivery")
            delivered = delivery is None
            if delivery:
                deferred[delivery["result_ref"]] = {
                    "fact": {k: v for k, v in fact.items() if k != "delivery"},
                    "payload": payload, "ranges": [], "chars": delivery["chars"],
                }
            key = fact.get("task_id")
            if key and payload.get("tool_name") in TASK_TOOLS:
                task = tasks.setdefault(key, {"task_id": key, "output_read": False})
                # Only task tools/native events can update these facts. Shell stdout is never parsed.
                previous_status = task.get("status")
                task.update(fact, sequence=seq)
                page = fact.get("network_read")
                if page and page["read_scope"]["default"] and delivered:
                    task["ranges"] = merge_ranges(task.get("ranges", []), page["cursor"], page["next_cursor"])
                    task["output_read"] = page["is_terminal"] and fully_read(task["ranges"], page["page_end_cursor"])
                    task["output_read"] &= not fact.get("output_incomplete", False)
                if not delivered:
                    task["output_read"] = False
                if previous_status in TERMINAL and fact.get("status") in {"queued", "running"}:
                    task["status"] = previous_status
                if fact.get("status") in TERMINAL:
                    completions.setdefault(key, seq)
                    if seq in covered:
                        covered.add(completions[key])
                    if fact.get("status") in {"timeout", "stopped", "interrupted"}:
                        urgent.append(completions[key])
            elif fact.get("interaction_id"):
                key = fact["interaction_id"]
                task = tasks.setdefault(key, {"interaction_id": key, "output_read": False})
                if fact.get("execution_status") is not None:
                    if task.get("status") not in TERMINAL or fact["execution_status"] in TERMINAL:
                        task["status"] = fact["execution_status"]
                task["sequence"] = seq
                page = fact.get("list_read")
                if page:
                    scope = page["read_scope"]
                    scope_key = json.dumps(scope, sort_keys=True)
                    # Any page can reveal journal growth, even if its filters
                    # cannot establish full default-list coverage.
                    for existing in task.get("list_coverage", {}).values():
                        if existing["scope"]["default"]:
                            existing["page_end_cursor"] = max(existing["page_end_cursor"], page["page_end_cursor"])
                            existing["terminal"] |= page["is_terminal"]
                    coverage = task.setdefault("list_coverage", {}).setdefault(scope_key, {
                        "scope": scope, "ranges": [], "page_end_cursor": 0, "terminal": False,
                    })
                    coverage["page_end_cursor"] = max(coverage["page_end_cursor"], page["page_end_cursor"])
                    coverage["terminal"] |= page["is_terminal"]
                    if delivered:
                        coverage["ranges"] = merge_ranges(coverage["ranges"], page["cursor"], page["next_cursor"])
                    task["output_read"] = any(
                        value["scope"]["default"] and value["terminal"]
                        and fully_read(value["ranges"], value["page_end_cursor"])
                        for value in task["list_coverage"].values())
                body = fact.get("body_read")
                if body and delivered:
                    body_key = (key, body["request_id"], body["body_sha256"])
                    coverage = bodies.setdefault(body_key, {"interaction_id": key,
                        "request_id": body["request_id"], "body_sha256": body["body_sha256"],
                        "body_bytes": body["body_bytes"], "ranges": []})
                    coverage["ranges"] = merge_ranges(coverage["ranges"], body["offset_bytes"], body["offset_bytes"] + body["bytes_returned"])
                    coverage["complete"] = fully_read(coverage["ranges"], body["body_bytes"])
                if fact.get("execution_status") in TERMINAL or fact.get("execution_status") == "cancelled":
                    completions.setdefault(key, seq)
                    if seq in covered:
                        covered.add(completions[key])
            elif fact.get("execution"):
                completions.setdefault(payload.get("tool_call_id", seq), seq)
    outstanding = sorted(set(completions.values()) - covered)
    return {
        "generation": generation,
        "unreviewed_results": outstanding,
        "urgent_sequences": sorted(set(urgent) - covered),
        "body_reads": list(bodies.values()),
        "unread_result_refs": sorted(deferred),
        "http_reads": [{"interaction_id": task["interaction_id"], "output_read": task["output_read"],
                        "list_coverage": list(task.get("list_coverage", {}).values())}
                       for task in tasks.values() if "interaction_id" in task],
        # Keep completed/read tasks available to review validation.  The
        # compact `tasks` view below intentionally omits them from the
        # outstanding-work context, but a native completion receipt still
        # needs to prove that its output was actually read.
        "completed_tasks": list(tasks.values()),
        "tasks": [task for task in tasks.values()
                  if task.get("status") not in TERMINAL or not task.get("output_read")
                  or task.get("analysis_status") in {"queued", "running"}],
    }
