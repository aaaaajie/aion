"""Deterministic experiment records. Model assertions are never fact sources."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

RECORD_TYPE = "experiment"
SECRET = re.compile(r"cookie|authorization|password|passwd|secret|token|credential|api.?key", re.I)
HANDLES = {"interaction_id", "request_id", "request_ids", "task_id", "session_id", "connection_context_id", "work_id", "tool_call_id", "parent_request_id"}
OUTPUT_FIELDS = {
    "status", "execution_status", "outcome", "status_code", "initial_status_code",
    "initial_url", "final_url", "follow_redirects", "redirect_chain", "location",
    "elapsed_ms", "body_bytes", "body_sha256", "body_complete", "content_type",
    "content_length", "exit_code", "timed_out", "truncated", "output_incomplete",
    "output_available", "complete", "outcome_unknown", "bytes_received", "transport",
    "started_requests", "completed_requests", "estimated_requests", "queued_requests",
    "running_requests", "response_bytes", "groups", "by_status", "errors",
    "has_more", "cursor", "next_cursor", "page_end_cursor", "results_omitted",
    "body_read", "list_read", "offset_bytes", "bytes_returned", "eof",
    "set_cookie_count",
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def execution_keys(agent_id, result):
    """Opaque provenance only; private resource handles never enter shared records."""
    data = result.get("data", result) if isinstance(result, dict) else {}
    if not isinstance(data, dict):
        return set()
    interaction = data.get("interaction_id")
    keys = {digest([agent_id, "task", data["task_id"]])} if data.get("task_id") else set()
    if not interaction:
        return keys
    requests = [data, *(data.get("results") or [])]
    return keys | {digest([agent_id, interaction, item["request_id"]]) for item in requests
                   if isinstance(item, dict) and item.get("request_id")}


def safe_text(text):
    if isinstance(text, str) and text.lstrip().startswith(("{", "[")):
        try:
            original = json.loads(text)
            projected = portable(original)
            if projected != original:
                return json.dumps(projected, ensure_ascii=False)
        except (ValueError, TypeError):
            pass
    text = re.sub(r"(?i)(bearer\s+)\S+", r"\1[REDACTED]", str(text))
    text = re.sub(r"(?im)^\s*(?:cookie|set-cookie|authorization):[^\r\n]*", "[REDACTED HEADER]", text)
    text = re.sub(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s&\r\n,;\"'}]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b(?:interaction_id|request_id|task_id|session_id|connection_context_id|work_id)\s*[=:]\s*[\"']?[^\s,;\"'}]+", "[OWNER_RESOURCE]", text)
    text = re.sub(r"(?:interaction|request|task|session)-[a-f0-9]{16,}", "[OWNER_RESOURCE]", text)
    text = re.sub(r"https?://[^\s\"'<>]+", lambda m: safe_url(m[0]), text)
    return text


def portable(value):
    if isinstance(value, dict):
        return {str(k): (v if (k == "set_cookie_count" and type(v) is int and v >= 0
                              or k in {"cookie_changed", "authentication_changed"} and type(v) is bool)
                        else "[REDACTED]" if SECRET.search(str(k)) else portable(v))
                for k, v in value.items() if k not in HANDLES}
    if isinstance(value, list):
        return [portable(v) for v in value]
    if isinstance(value, str):
        return safe_text(value)
    return value


def safe_url(value):
    try:
        parts = urlsplit(str(value))
        host = parts.netloc.rsplit("@", 1)[-1]
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = (urlencode([(k, "[REDACTED]" if SECRET.search(k) or k in HANDLES else v) for k, v in pairs])
                 if any(SECRET.search(k) or k in HANDLES for k, _ in pairs) else parts.query)
        return urlunsplit((parts.scheme, host, parts.path, query, parts.fragment))
    except ValueError:
        return "unknown"


def request_snapshot(spec):
    """Keep input bytes/shape, not intent labels, generated comments or conclusions."""
    spec = spec or {}
    selected = {k: spec[k] for k in (
        "method", "url", "query", "headers", "body", "follow_redirects", "verify_tls",
        "timeout_seconds", "encoding", "content_type", "max_body_bytes",
    ) if k in spec}
    if "url" in selected:
        selected["url"] = safe_url(selected["url"])
    auth = bool(spec.get("auth") or spec.get("cookies") or spec.get("session_id")
                or any(SECRET.search(k) for k in spec.get("headers", {})))
    selected["authentication"] = {"supplied": auth, "portable": not auth,
                                  "requires_reconstruction": auth}
    projected = portable(selected)
    projected["redacted"] = projected != selected or selected.get("url") != spec.get("url")
    return projected


def observation(result):
    """Select runtime fields; never promote summaries, analysis, findings or stdout."""
    if not isinstance(result, dict):
        return {"structured_output": "unavailable"}
    data = result.get("data", result)
    if not isinstance(data, dict):
        return {"structured_output": "unavailable"}
    output = {k: portable(v) for k, v in data.items() if k in OUTPUT_FIELDS}
    if isinstance(data.get("groups"), list):
        output["groups"] = [{k: portable(v) for k, v in group.items() if k in {
            "status_code", "body_bytes", "body_sha256", "count", "ordinals", "sample_ordinals"}}
            for group in data["groups"] if isinstance(group, dict)]
    if isinstance(data.get("results"), list):
        output["results"] = [observation(x) for x in data["results"]]
        output["displayed_results"] = len(data["results"])
    if isinstance(data.get("headers"), dict):
        output["headers"] = {k: safe_text(v) for k, v in data["headers"].items()
                             if k.lower() in {"content-type", "content-length", "location", "allow", "server"}}
    for k in ("initial_url", "final_url", "location"):
        if k in output and output[k]:
            output[k] = safe_url(output[k])
    if isinstance(data.get("body_preview"), str):
        output["body_preview"] = portable(data["body_preview"][:2000])
    for k in ("output", "stdout", "stderr", "raw_response", "content"):
        if isinstance(data.get(k), str):
            output.setdefault("raw_artifacts", {})[k] = {
                "sha256": hashlib.sha256(data[k].encode()).hexdigest(),
                "chars": len(data[k]), "interpretation": "unstructured_tool_output_not_a_verified_claim",
            }
    if result.get("ok") is False:
        error = result.get("error") or {}
        output["error"] = {k: error[k] for k in ("code", "stage", "retryable") if k in error}
    return output


def tool_record(tool, arguments, result):
    args = arguments if isinstance(arguments, dict) else {}
    data = result.get("data", result) if isinstance(result, dict) else {}
    requested = request_snapshot(args.get("request", args))
    if "shell" in tool or tool in {"system_task_start", "system_task_output"}:
        # Commands/scripts are artifacts, not authoritative observations.
        requested = {k: portable(args[k]) for k in ("command", "cmd", "cwd", "timeout_seconds") if k in args}
    native = data.get("executed_request") if isinstance(data, dict) else None
    return {
        "record_type": RECORD_TYPE, "tool": tool,
        "requested_input": requested,
        "executed_input": native if native is not None else {"availability": "unknown"},
        "input_digest": digest({"tool": tool, "arguments": args}),
        "target": requested.get("url", ""),
        "output": observation(result),
        "raw_output": "Read the source evidence when needed; tool text is not a verified finding.",
    }


def experiment_index(record):
    """Compact lossless metadata index; full records remain paginatable."""
    index = {k: record[k] for k in (
        "record_type", "tool", "target", "input_digest", "resource_generation",
        "strategy_revision", "source_sequence", "output", "ordinal", "batch_digest",
        "raw_evidence_ref", "tool_version", "recorded_at", "phase", "execution_key",
    ) if k in record}
    executed = record.get("executed_input") or {}
    request = executed.get("request") or (record.get("requested_input") if record.get("tool") != "shell_command" else None)
    if request:
        encoded = json.dumps(request, ensure_ascii=False)
        if len(encoded) <= 2500 and not any(k in request for k in ("command", "cmd", "scripts", "members")):
            index["request"] = request
            index["request_basis"] = executed.get("availability", "requested_only")
        else:
            index["request"] = {"availability": "read_full_evidence", "sha256": digest(request),
                                "method": request.get("method"), "url": request.get("url"),
                                "planned_members": len(request.get("members", [])) if "members" in request else None}
    return index


def shell_snapshot(command, directory):
    import shlex
    from pathlib import Path
    scripts = []
    dictionaries = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = []
    root = Path(directory).resolve()
    for token in tokens:
        if len(scripts) >= 8:
            break
        candidate = (root / token).resolve()
        if (candidate.suffix in {".py", ".sh", ".js", ".pl", ".rb"} and candidate.is_relative_to(root)
                and candidate.is_file() and candidate.stat().st_size <= 100_000):
            raw = candidate.read_bytes()
            content = raw.decode("utf-8", errors="replace")
            scripts.append({"path": str(candidate.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(),
                            "text_lossless": content.encode() == raw,
                            "content": portable(content)})
    for index, token in enumerate(tokens):
        value = None
        if token in {"-w", "--wordlist", "--dictionary"} and index + 1 < len(tokens):
            value = tokens[index + 1]
        elif token.startswith(("--wordlist=", "--dictionary=")):
            value = token.split("=", 1)[1]
        if value is None or len(dictionaries) >= 8:
            continue
        candidate = (root / value).resolve()
        item = {"argument": portable(value), "availability": "unavailable"}
        if candidate.is_relative_to(root) and candidate.is_file() and candidate.stat().st_size <= 1_048_576:
            raw = candidate.read_bytes()
            content = raw.decode("utf-8", errors="replace")
            item.update(availability="captured", sha256=hashlib.sha256(raw).hexdigest(),
                byte_length=len(raw), content=portable(content), text_lossless=content.encode() == raw,
                line_count=len(content.splitlines()))
        dictionaries.append(item)
    return {"command": portable(command), "cwd": str(root), "scripts": scripts,
            "dictionaries": dictionaries, "batch_execution_coverage": "unknown; shell output does not prove per-entry execution",
            "script_coverage": "Accessible explicit local scripts (100 KB) and dictionary arguments (1 MB) are captured; indirect dependencies and larger inputs are unknown.",
            "interpretation": "Executable input artifact, not an assertion about target behavior."}


def report_receipt(report):
    """Report text remains audit-only for solving agents."""
    report = {**report, "report_ref": report.get("report_ref") or f"report:{report['report_id']}"}
    if report.get("report_type") == "hint":
        return {k: v for k, v in report.items() if k != "report_id"}
    payload = report.get("payload") or {}
    return {k: report[k] for k in ("report_ref", "sequence", "status", "report_type", "unique_code") if k in report} | {
        "payload": {"evidence_refs": [r for r in payload.get("evidence_refs", []) if str(r).startswith("evidence:")],
                    "resource_cleanup_status": payload.get("resource_cleanup_status"),
                    "termination_reason": payload.get("termination_reason")},
    }


def challenge_facts(challenge):
    return {k: v for k, v in challenge.items() if k in {
        "run_id", "unique_code", "description", "difficulty", "level", "total_score",
        "flag_count", "correct_flag_count", "is_completed", "platform_status", "container_status",
        "container_addr", "slot_occupied", "work_status", "hint_requested", "active_since",
        "last_progress_at", "strategy_revision", "stagnation_stage", "slot_occupied_seconds",
    }}
