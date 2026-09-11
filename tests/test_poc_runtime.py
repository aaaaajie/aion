from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from tools.poc_runtime.adapter import PocAdapterError, load_poc, parse_expression
from tools.poc_runtime.evaluate import evaluate
from tools.poc_runtime.models import BoolNode
from tools.poc_runtime.runner import run_document


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_adapter_accepts_named_static_xray_rule(tmp_path: Path) -> None:
    path = _write(tmp_path / "poc.yml", """\
name: sample
transport: http
rules:
  check-login:
    request:
      method: POST
      path: /login?next=%2F
      headers:
        Content-Type: application/x-www-form-urlencoded
      body: user=demo&password=demo
      follow_redirects: false
    expression: response.status == 200 && response.headers["set-cookie"].contains("sid=")
expression: check-login()
""")
    document = load_poc(path)
    assert document.rule_name == "check-login"
    assert document.request.method == "POST"
    assert isinstance(document.matcher, BoolNode)


def test_adapter_rejects_incomplete_documents(tmp_path: Path) -> None:
    path = _write(tmp_path / "bad.yml", "rules:\n  r0:\n    expression: response.status == 200\nexpression: r0()\n")
    with pytest.raises(PocAdapterError) as error:
        load_poc(path)
    assert error.value.code == "missing_request"


def test_adapter_rejects_dynamic_and_unconsumed_semantics(tmp_path: Path) -> None:
    path = _write(tmp_path / "dynamic.yml", """\
transport: http
set:
  token: randomLowercase(8)
rules:
  r0:
    request:
      method: GET
      path: /admin/{{token}}
    expression: response.status == 200
expression: r0()
""")
    with pytest.raises(PocAdapterError) as error:
        load_poc(path)
    assert error.value.code == "dynamic_or_invalid_path"


def test_adapter_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = _write(tmp_path / "duplicate.yml", """\
transport: http
rules:
  r0:
    request:
      method: GET
      method: POST
      path: /
    expression: response.status == 200
expression: r0()
""")
    with pytest.raises(PocAdapterError) as error:
        load_poc(path)
    assert error.value.code == "duplicate_key"


def test_expression_is_parsed_without_evaluation() -> None:
    node = parse_expression("(response.status == 500 || response.headers['location'].contains('/login')) && response.body.bcontains(b'error')")
    status, evidence = evaluate(node, {"outcome": "response", "status_code": 500, "headers": {"Location": "/login"}, "body_complete": True}, b"error")
    assert status == "matched"
    assert len(evidence) >= 2


def test_body_truncation_is_inconclusive() -> None:
    node = parse_expression("response.body.bcontains(b'secret')")
    status, evidence = evaluate(node, {"outcome": "response", "status_code": 200, "headers": {}, "body_complete": False}, b"partial")
    assert status == "inconclusive"
    assert evidence[0]["reason"] == "body_missing_or_truncated"


@pytest.mark.asyncio
async def test_runner_reuses_http_manager_and_persists_evidence(tmp_path: Path) -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nSet-Cookie: sid=ok; HttpOnly\r\nContent-Length: 5\r\n\r\nerror")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        poc = _write(tmp_path / "runner.yml", """\
transport: http
rules:
  auth_check:
    request:
      method: GET
      path: /health
    expression: response.status == 500 && response.headers["set-cookie"].contains("sid=ok") && response.body.bcontains(b"error")
expression: auth_check()
""")
        document = load_poc(poc)
        port = server.sockets[0].getsockname()[1]
        result = await run_document(document, target=f"http://127.0.0.1:{port}", output=tmp_path / "run")
        assert result.status == "matched"
        assert result.response["execution_source"] == "http"
        assert (tmp_path / "run" / "http-interaction" / "results.jsonl").exists()
        assert json.loads((tmp_path / "run" / "result.json").read_text(encoding="utf-8"))["status"] == "matched"
    finally:
        server.close()
        await server.wait_closed()
