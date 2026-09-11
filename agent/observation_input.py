"""Bounded field-first observations; metadata must not crowd out evidence."""

import json

FIELDS = (
    "bytes_received", "transport",
    "complete", "outcome_unknown", "app_status", "protocol_status", "execution_status", "generation", "reason", "content", "ok", "error", "status", "status_code", "initial_status_code", "final_url",
    "initial_url", "follow_redirects", "redirect_chain", "location", "outcome",
    "task_id", "exit_code", "timed_out", "output_incomplete", "output_available", "result_state",
    "output", "stdout", "stderr", "raw_response", "body_preview", "preview", "summary",
    "evidence_refs", "result_ref", "request_id", "interaction_id", "truncated",
)
CONTAINERS = ("data", "responses", "results", "response", "analysis")


def bounded(value, limit=350):
    encoded = json.dumps(value, ensure_ascii=False)
    if len(encoded) <= limit:
        return value
    return {"preview": encoded[:limit], "truncated": True, "original_chars": len(encoded)}


def observation_data(value, depth=0):
    if not isinstance(value, dict) or depth >= 3:
        return bounded(value, 600)
    output = {key: bounded(value[key], 600 if key in {"output", "stdout", "stderr", "redirect_chain"} else 250)
              for key in FIELDS if key in value}
    for key in CONTAINERS:
        child = value.get(key)
        if isinstance(child, dict):
            output[key] = observation_data(child, depth + 1)
        elif isinstance(child, list):
            output[key] = [observation_data(item, depth + 1) for item in child[:3]]
            if len(child) > 3:
                output[key + "_omitted"] = len(child) - 3
    if not output:
        return {"unstructured": bounded(value, 700)}
    # A single oversized result must never prevent the newest event being scanned.
    if len(json.dumps(output, ensure_ascii=False)) > 3000:
        compact, used = {}, 0
        for key, item in output.items():
            remaining = 2700 - used
            if remaining < 120:
                compact.setdefault("omitted_fields", []).append(key)
                continue
            item = bounded(item, min(700, remaining - 100))
            compact[key] = item
            used += len(json.dumps({key: item}, ensure_ascii=False))
        return compact
    return output
