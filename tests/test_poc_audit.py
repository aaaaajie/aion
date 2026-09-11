import json
from pathlib import Path

import pytest

from tools.poc_audit.audit import AuditFailure, AuditLimits, SourceConfig, audit_sources, main


def _run(root: Path, tmp_path: Path, *, limits: AuditLimits | None = None) -> dict:
    output = tmp_path / "audit-output"
    return audit_sources([SourceConfig("sample", root)], output, limits)


def _basic_nuclei(identifier: str, *, legacy: bool = False) -> str:
    request_key = "requests" if legacy else "http"
    return f'''id: {identifier}
info:
  name: Basic {identifier}
  severity: low
{request_key}:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/health"
    matchers:
      - type: status
        status: [200]
'''


def test_detects_supported_formats_and_static_candidates(tmp_path):
    root = tmp_path / "pocs"
    root.mkdir()
    (root / "nuclei-new.yaml").write_text(_basic_nuclei("n-new"))
    (root / "nuclei-old.yml").write_text(_basic_nuclei("n-old", legacy=True))
    (root / "afrog.yaml").write_text("""id: af-1
info: {name: Afrog, severity: low}
rules:
  r0:
    request:
      method: GET
      path: /health
    expression: response.status == 200
expression: r0()
""")
    (root / "xray.yaml").write_text("""name: x-1
detail: {name: Xray, severity: low}
transport: http
rules:
  r0:
    request:
      method: POST
      path: /health
      body: ok
    expression: response.status == 200
expression: r0()
""")
    (root / "fscan.yaml").write_text("""name: f-1
rules:
  - method: GET
    path: /health
    expression: response.status == 200
""")
    (root / "unknown.yaml").write_text("foo: bar\n")
    (root / "mixed.yaml").write_text("""id: mixed-1
info: {name: Mixed}
http:
  - method: GET
    path: ["{{BaseURL}}/health"]
rules:
  r0:
    request: {method: GET, path: /health}
expression: r0()
""")
    (root / "advanced.yaml").write_text("""id: advanced-1
info: {name: Advanced}
set: {x: "{{y}}", y: "{{x}}"}
rules:
  r0:
    request: {method: DELETE, path: /one}
    expression: mystery(response.body)
  r2:
    request: {method: GET, path: /two}
    expression: response.status == 200
expression: r0() && r2()
""")
    (root / "no-matcher.yaml").write_text("""id: no-matcher
info: {name: No matcher}
http:
  - method: GET
    path: ["{{BaseURL}}/health"]
""")

    summary = _run(root, tmp_path)

    assert summary["complete"] is True
    assert summary["yaml_documents"] == 9
    assert summary["valid_documents"] == 9
    assert summary["format_counts"] == {"afrog": 2, "fscan": 1, "mixed": 1, "nuclei": 3, "unknown": 1, "xray": 1}
    assert summary["classification_counts"]["candidate_basic_http"] == 5
    assert summary["classification_counts"]["unknown_format"] == 1
    assert summary["classification_counts"]["requires_semantic_support"] == 3
    advanced = next(json.loads(line) for line in (tmp_path / "audit-output" / "records.jsonl").read_text().splitlines() if "advanced.yaml" in line and '"record_type": "document"' in line)
    assert {"variable_cycle", "unknown_expression_function", "top_expression_not_single_rule", "multiple_or_missing_requests"} <= set(advanced["blockers"])
    no_matcher = next(json.loads(line) for line in (tmp_path / "audit-output" / "records.jsonl").read_text().splitlines() if "no-matcher.yaml" in line and '"record_type": "document"' in line)
    assert "missing_match_condition" in no_matcher["blockers"]
    assert summary["runtime"]["network_calls"] == 0
    assert summary["runtime"]["child_processes"] == 0
    assert summary["runtime"]["expression_evaluations"] == 0


def test_invalid_yaml_is_reported_without_marking_audit_incomplete(tmp_path):
    root = tmp_path / "invalid"
    root.mkdir()
    (root / "duplicate.yaml").write_text("a: 1\na: 2\n")
    (root / "empty.yaml").write_text("")
    (root / "multi.yaml").write_text("---\na: 1\n---\na: 2\n")
    (root / "non-string.yaml").write_text("1: value\n")
    (root / "tag.yaml").write_text("value: !custom hello\n")
    (root / "recursive.yaml").write_text("value: &a [*a]\n")
    (root / "bad.bin").write_bytes(b"\\x00\\xff")
    (root / "large.yaml").write_text("value: " + ("x" * 200) + "\n")
    (root / "nested.yaml").write_text("a:\n  b:\n    c: 1\n")
    (root / "link.yaml").symlink_to(root / "duplicate.yaml")

    summary = _run(root, tmp_path, limits=AuditLimits(max_file_bytes=100, max_depth=2, max_nodes=100))
    records = [json.loads(line) for line in (tmp_path / "audit-output" / "records.jsonl").read_text().splitlines()]
    reasons = {item.get("reason") for item in records if item["record_type"] == "file"}

    assert summary["complete"] is True
    assert summary["classification_counts"]["invalid_document"] >= 6
    assert "duplicate_key" in summary["blocker_counts"]
    assert "recursive_alias" in summary["blocker_counts"]
    assert "max_depth_exceeded" in summary["blocker_counts"]
    assert "file_size_limit" in summary["blocker_counts"]
    assert summary["blocker_counts"]["multi_document"] == 1
    assert "symlink_not_followed" in reasons
    assert "non_yaml_file" in reasons


def test_duplicate_content_and_id_conflicts_are_separate(tmp_path):
    root = tmp_path / "duplicates"
    root.mkdir()
    content = _basic_nuclei("same")
    (root / "a.yaml").write_text(content)
    (root / "b.yaml").write_text(content)
    (root / "c.yaml").write_text(_basic_nuclei("same").replace("/health", "/other"))

    summary = _run(root, tmp_path)

    assert summary["duplicate_content_files"] == 2
    assert summary["duplicate_content_groups"] == 1
    assert summary["duplicate_id_conflicts"]["count"] == 1
    assert summary["coverage"]["yaml_documents"] == 3
    assert summary["coverage"]["valid_documents"] == 3


def test_output_must_be_new_and_outside_sources(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "x.yaml").write_text(_basic_nuclei("x"))
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(AuditFailure):
        audit_sources([SourceConfig("s", root)], existing)
    with pytest.raises(AuditFailure):
        audit_sources([SourceConfig("s", root)], root / "nested")
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "not-created")
    with pytest.raises(AuditFailure):
        audit_sources([SourceConfig("s", root)], dangling)


def test_cli_returns_zero_for_bad_documents_and_two_for_bad_configuration(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    (root / "broken.yaml").write_text("a: 1\na: 2\n")
    assert main(["--source", f"s={root}", "--output", str(tmp_path / "report")]) == 0
    assert main(["--source", f"missing={tmp_path / 'nope'}", "--output", str(tmp_path / "bad")]) == 2
    assert json.loads(capsys.readouterr().err)["complete"] is False


def test_records_are_stable_and_no_execution_side_effects(tmp_path, monkeypatch):
    root = tmp_path / "stable"
    root.mkdir()
    (root / "b.yaml").write_text(_basic_nuclei("b"))
    (root / "a.yaml").write_text(_basic_nuclei("a"))

    import socket
    import subprocess

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("child process")))
    first = _run(root, tmp_path)
    first_records = (tmp_path / "audit-output" / "records.jsonl").read_text()
    second = audit_sources([SourceConfig("sample", root)], tmp_path / "second", AuditLimits())
    second_records = (tmp_path / "second" / "records.jsonl").read_text()

    assert first_records == second_records
    assert first["classification_counts"] == second["classification_counts"]
    assert first["runtime"]["network_calls"] == second["runtime"]["network_calls"] == 0
