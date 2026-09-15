"""Small canonical examples, checked against the same input models as execution."""
from copy import deepcopy


EXAMPLES = {
    "system_read_file": [{"file_path": "agent/output.txt", "offset": 0, "limit_chars": 4000}],
    "system_write_file": [{"file_path": "agent/output.txt", "content": "owned fixture result\n"}],
    "system_edit_file": [{"file_path": "agent/output.txt", "old_string": "old", "new_string": "new"}],
    "system_list_directory": [{"path": "agent", "recursive": False, "max_entries": 100}],
    "system_glob": [{"pattern": "**/*.json", "path": "agent", "max_results": 100}],
    "system_grep": [{"pattern": "needle", "path": "agent", "glob": "*.txt", "max_results": 100}],
    "system_shell": [{"command": "printf 'check\\n'", "cwd": ".", "timeout": 30, "max_output_chars": 4000}],
    "system_cyberchef": [{"action": "operations", "query": "AES Decrypt"}, {"input": "aGVsbG8=", "recipe": [{"op": "From Base64"}]}],
    "skill_search": [{"query": "startup connection reachability", "limit": 8}],
    "skill_invoke": [{"skill_id": "execution/internal-network-recon"}],
    "skill_resource_read": [{"skill_id": "execution/internal-network-recon", "resource": "references/fastcgi-validation.md", "offset": 0, "limit": 200}],
    "system_http_replay": [{"interaction_id": "http-example", "request_id": "request-example", "overrides": {"headers": {"Accept": "application/json"}}}],
    "system_http_compare": [{"left": {"interaction_id": "http-example", "request_id": "left"}, "right": {"interaction_id": "http-example", "request_id": "right"}}],
    "system_browser_open": [{"url": "http://localhost:8000/login"}],
    "system_browser_action": [{"session_id": "0" * 32, "action": "fill", "selector": "input[name=username]", "value": "fixture"}],
    "system_browser_output": [{"session_id": "0" * 32}],
    "system_browser_export_request": [{"session_id": "0" * 32, "request_id": "1" * 32}],
    "system_browser_close": [{"session_id": "0" * 32}],
    "system_source_scan": [{"path": "src"}],
    "system_poc_search": [{"query": "Apache CVE-2024", "source": "tscan", "limit": 10}],
    "system_poc_inspect": [{"poc_ref": "returned-by-system_poc_search", "target": "http://localhost:8000", "line_offset": 0, "line_limit": 200}],
    "system_poc_run": [{"poc_ref": "returned-by-system_poc_search", "target": "http://localhost:8000", "wait_seconds": 20}],
    "system_poc_output": [{"interaction_id": "returned-by-system_poc_run", "cursor": 0, "wait_seconds": 20, "limit": 100}],
    "solver_delegate": [{"tasks": [{"task_key": "inspect-fixture-parser", "objective": "Inspect the supplied local parser for length-encoding errors; report supported findings and untested cases.", "mode": "review", "context_refs": [], "success_criteria": ["Identify the relevant code and distinguish defects from untested hypotheses"]}]}],
    "system_fastcgi_request": [{"host": "127.0.0.1", "port": 9000, "params": {"REQUEST_METHOD": "GET", "SCRIPT_FILENAME": "/fixture/health.php"}, "timeout_seconds": 5}],
    "system_task_start": [{"name": "Local fixture", "command": "sleep 45; printf done", "timeout": 60}],
    "system_task_output": [{"task_id": "task-from-system_task_start", "wait_seconds": 0, "tail_chars": 30000}],
    "system_task_stop": [{"task_id": "task-from-system_task_start"}],
    "system_network_output": [{"task_id": "task-from-network_discovery", "cursor": 0, "limit": 100, "wait_seconds": 20, "filters": {}}],
    "tool_result_read": [{"result_ref": "tool_result:tool_result_" + "0" * 32, "offset": 0, "limit_chars": 8000}],
    "evidence_read": [{"evidence_ref": "evidence:evidence_" + "0" * 32, "offset": 0, "limit_chars": 8000}],
    "evidence_search": [{"query": "system_task_output", "offset": 0, "limit": 20}],
    "report_read": [{"report_ref": "report_" + "0" * 32, "offset": 0, "limit_chars": 8000}],
    "system_http_request": [
        {"method": "GET", "url": "http://localhost:8000/health"},
        {"method": "POST", "url": "http://localhost:8000/echo", "body": {"type": "json", "value": {"message": "hello"}}},
        {"method": "POST", "url": "http://localhost:8000/echo", "body": {"type": "form", "value": {"message": "hello"}}},
        {"method": "POST", "url": "http://localhost:8000/echo", "body": {"type": "raw", "value": "hello", "content_type": "text/plain"}},
    ],
    "system_http_probe": [
        {"cases": [{"method": "GET", "url": "http://localhost:8000/{{path}}",
                    "variables": {"path": {"values": ["health", "version"], "encoding": "path"}},
                    "combine": "product"}], "concurrency": 2, "wait_seconds": 20},
        {"cases": [{"method": "POST", "url": "http://localhost:8000/echo",
                    "body": {"type": "form", "value": {"message": "{{message}}"}},
                    "variables": {"message": {"values": ["hello", "world"]}}}], "concurrency": 1},
    ],
    "system_http_analyze": [{"interaction_id": "interaction-from-request", "cursor": 0, "limit": 20}],
    "system_http_response": [
        {"interaction_id": "interaction-from-output", "request_id": "request-from-output", "offset_bytes": 0, "length_bytes": 4000},
    ],
    "system_http_output": [
        {"interaction_id": "interaction-from-request", "cursor": 0, "limit": 100, "wait_seconds": 20},
    ],
    "pentest_jwt": [
        {"operation": "decode", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.invalid"},
        {"operation": "sign", "claims": {"sub": "123", "iat": 1700000000}, "algorithm": "HS256", "key": "replace-with-owned-test-key"},
        {"operation": "validate", "token": "replace-with-owned-token", "target_url": "http://localhost:8000/me", "token_location": "header", "token_name": "Authorization"},
    ],
    "pentest_arjun": [
        {"url": "http://localhost:8000/search", "mode": "GET", "wordlist": ["q", "page"], "concurrency": 2},
        {"url": "http://localhost:8000/api", "mode": "JSON", "json_body": {"query": "hello"}, "wordlist": ["id", "filter"]},
    ],
    "pentest_sqlmap": [
        {"url": "http://localhost:8000/search?q=fixture", "data": None,
         "headers": {"Accept": "application/json"}, "cookies": {},
         "level": 1, "risk": 1, "timeout_seconds": 120},
        {"url": "http://localhost:8000/login", "data": "username=fixture&password=fixture",
         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
         "cookies": {"session": "captured-session"}, "level": 1, "risk": 1,
         "timeout_seconds": 120},
    ],
    "solver_review": [
        {"hypothesis_id": "local-fixture", "covered_sequences": [1], "assessment": "new_information",
         "summary": "The response redirected to login; authentication is still unverified.",
         "next_test": "Inspect the redirect and compare with a known authenticated response."},
        {"hypothesis_id": "local-fixture", "covered_sequences": [1], "assessment": "inconclusive",
         "summary": "The result is not calibrated; no validated application conclusion yet.",
         "next_test": "Read the pending output and check a known fixture."},
        {"hypothesis_id": "local-fixture", "covered_sequences": [1], "assessment": "new_information",
         "summary": "A known fixture produced its expected result.",
         "next_test": "Check whether the same conditions apply to the next result.",
         "validation": {"conclusion_sequences": [1], "control_evidence_refs": ["evidence:evidence_" + "0" * 32],
                        "calibration_basis": "Replace with the observed implementation-validation basis."}},
    ],
    "worker_update": [
        {"summary": "The bounded fixture check is in progress.", "tested": ["owned fixture"],
         "untested": ["production behavior"], "next_steps": ["read the next task result"]},
    ],
    "worker_report": [
        {"status": "completed", "summary": "The assigned fixture review is complete.",
         "evidence_refs": [], "tested": ["owned fixture"], "untested": ["unrelated targets"],
         "next_steps": []},
    ],
}


def examples_for(name, model=None):
    examples = deepcopy(EXAMPLES.get(name, []))
    if model is not None:
        for example in examples:
            model.model_validate(example)
    return examples
