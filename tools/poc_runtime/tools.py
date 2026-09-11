"""Agent-facing POC search, inspection, execution and output tools."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from typing import Literal

from pydantic import Field, field_validator, model_validator

from agent.tooling import AccessClaim, ToolSpec
from tools.http.models import HttpRawBody, HttpRequestSpec
from tools.system.models import ToolArguments

from .adapter import PocAdapterError, load_poc_text
from .evaluate import evaluate, matcher_from_json, matcher_to_json
from .index import PocIndex


class PocSearchArguments(ToolArguments):
    query: str = Field(min_length=1, description="One or more product, CVE, or observed-feature terms. All whitespace-separated terms must match; this never sends a request.")
    source: str | None = Field(default=None, description="Optional indexed source name, for example tscan or yak.")
    format: Literal["afrog", "xray", "fscan", "nuclei", "yak", "unknown"] | None = Field(default=None, description="Optional exact format filter.")
    status: Literal["supported", "unsupported", "reference_only"] | None = Field(default=None, description="Optional support filter. Only supported records may be run; reference_only is Yak/Yakit read-only.")
    offset: int = Field(default=0, ge=0, description="Zero-based result offset from a previous next_offset.")
    limit: int = Field(default=10, ge=1, le=30, description="Results per page, at most 30.")

    @field_validator("query")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("query must contain a non-whitespace term")
        return value


class PocInspectArguments(ToolArguments):
    poc_ref: str = Field(min_length=1, description="The exact poc_ref returned by system_poc_search; do not use a file path or display name.")
    target: str | None = Field(default=None, description="Optional http:// or https:// target origin used only to preview the resolved path; inspect never sends a request.")
    line_offset: int = Field(default=0, ge=0, description="Zero-based source line offset for paging untrusted original text.")
    line_limit: int = Field(default=200, ge=1, le=200, description="Number of source lines to return, at most 200.")

    @field_validator("target")
    @classmethod
    def valid_preview_origin(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("target must be an absolute http(s) origin without query or fragment")
        return value


class PocRunArguments(ToolArguments):
    poc_ref: str = Field(min_length=1, description="The exact poc_ref returned by system_poc_search/inspect. Run revalidates its package hash.")
    target: str = Field(min_length=1, description="Explicit http:// or https:// target origin, without query or fragment; the POC's origin-relative path is appended.")
    session_id: str | None = Field(default=None, description="Optional session_id belonging to this Agent. Omit for a stateless request; do not copy another Agent's session identifier.")
    update_session: bool = Field(default=False, description="Persist response cookies into the supplied session_id. Requires session_id; run once only.")
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0, description="HTTP timeout for this one request.")
    wait_seconds: float = Field(default=20.0, ge=0.0, le=30.0, description="Wait for resource admission and completion. If still queued, call system_poc_output; do not submit run again.")

    @field_validator("target")
    @classmethod
    def valid_target_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("target must be an absolute http(s) origin without query or fragment")
        return value

    @model_validator(mode="after")
    def session_update_requires_id(self) -> "PocRunArguments":
        if self.update_session and not self.session_id:
            raise ValueError("update_session requires session_id")
        return self


class PocOutputArguments(ToolArguments):
    interaction_id: str = Field(min_length=1, description="The interaction_id returned by system_poc_run; output only reads that existing interaction.")
    cursor: int = Field(default=0, ge=0, description="Result journal cursor from the previous output response; normally start at 0.")
    wait_seconds: float = Field(default=0.0, ge=0.0, le=30.0, description="Wait up to 30 seconds for queued/running work. Waiting does not resend the request.")
    limit: int = Field(default=100, ge=1, le=100, description="Maximum result records to read.")


def _redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    secret_names = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
    return {key: ("[redacted]" if key.lower() in secret_names else value) for key, value in headers.items()}


def _target_url(target: str, path: str) -> str:
    origin = urlsplit(target)
    if origin.scheme not in {"http", "https"} or not origin.netloc or origin.query or origin.fragment:
        raise ValueError("target must be an absolute HTTP(S) origin without query or fragment")
    parsed = urlsplit(path)
    if not parsed.path.startswith("/") or parsed.scheme or parsed.netloc:
        raise ValueError("POC path must remain origin-relative")
    return urlunsplit((origin.scheme, origin.netloc, parsed.path, parsed.query, ""))


class PocTools:
    def __init__(self, index_root: str | Path, manager: Any, agent_id: str):
        self.index_root = Path(index_root)
        self.manager = manager
        self.agent_id = agent_id
        self._loaded: PocIndex | None = None

    def _index(self) -> PocIndex:
        if self._loaded is None:
            try:
                self._loaded = PocIndex(self.index_root)
            except Exception as exc:
                raise self.manager._error("not_found", "poc_index_unavailable", "POC index package is unavailable", detail={"path": str(self.index_root), "cause": str(exc), "retry_action": "ask maintainer to install the published index package"})
        return self._loaded

    def tool_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec("system_poc_search", "POC 检索 / POC search. First step: search product, CVE, or observed feature. All terms must match; returns exact poc_ref, source, format, status and blockers. Read-only and never sends HTTP. Then call system_poc_inspect with the returned poc_ref.", PocSearchArguments, self.search, lambda _: (AccessClaim("read", "poc-index"),)),
            ToolSpec("system_poc_inspect", "POC 检查 / POC inspect. Pass the exact poc_ref from search, optionally a target origin for URL preview. Read support blockers, matcher, request preview and bounded untrusted source lines; never sends HTTP. Only status=supported is eligible for system_poc_run.", PocInspectArguments, self.inspect, lambda _: (AccessClaim("read", "poc-index"),)),
            ToolSpec("system_poc_run", "POC 执行 / POC run. Pass an exact supported poc_ref and explicit http(s) target origin. Sends at most one verified Tscan Afrog/Xray basic HTTP request through the current Agent Run/session. On return, call system_poc_output with interaction_id; if queued or failed, read output and do not resubmit. unsupported/reference_only records send zero requests.", PocRunArguments, self.run, lambda args: (AccessClaim("read", "poc-index"), AccessClaim("write", "http-new"),)),
            ToolSpec("system_poc_output", "POC 结果 / POC output. Pass interaction_id from system_poc_run. Reads and evaluates the persisted response only; wait_seconds waits for queued work and never resends. Repeat with the returned cursor if needed. Result is matched, not_matched, inconclusive, or pending; template matching is not proof of a business vulnerability.", PocOutputArguments, self.output, lambda args: (AccessClaim("read", f"http-interaction:{args.interaction_id}"),)),
        ]

    async def search(self, args: PocSearchArguments) -> dict[str, Any]:
        return self._index().search(args.query, source=args.source, format_name=args.format, status=args.status, offset=args.offset, limit=args.limit)

    def _get(self, poc_ref: str) -> dict[str, Any]:
        try:
            return self._index().get(poc_ref)
        except KeyError as exc:
            raise self.manager._error("not_found", "poc_ref_not_found", "poc_ref was not found in the installed index", detail={"poc_ref": poc_ref, "retry_action": "call system_poc_search and use an exact returned poc_ref"}) from exc

    async def inspect(self, args: PocInspectArguments) -> dict[str, Any]:
        row = self._get(args.poc_ref)
        content = row.pop("content")
        lines = content.splitlines()
        request = row.get("request")
        preview = None
        if request:
            preview = {**request, "headers": _redact_headers(request.get("headers", {})), "body": "[redacted: source body omitted]" if request.get("body") else None}
            if args.target:
                try:
                    preview["target_url"] = _target_url(args.target, request["path"])
                except ValueError as exc:
                    raise self.manager._error("validation", "poc_target_invalid", str(exc), detail={"retry_action": "use an http(s) origin without query or fragment"}) from exc
        return {**row, "request_preview": preview, "source_lines": {"offset": args.line_offset, "limit": args.line_limit, "total": len(lines), "lines": lines[args.line_offset : args.line_offset + args.line_limit]}}

    def _read_document(self, row: dict[str, Any]):
        raw = row["content"].encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise self.manager._error("conflict", "poc_index_hash_mismatch", "POC index content hash does not match its metadata", detail={"poc_ref": row["poc_ref"], "retry_action": "rebuild_index"})
        try:
            return load_poc_text(raw, path=f"index:{row['poc_ref']}")
        except PocAdapterError as exc:
            raise self.manager._error("validation", "poc_revalidation_failed", "POC failed execution validation when read from the package", detail=exc.as_dict())

    async def run(self, args: PocRunArguments) -> dict[str, Any]:
        row = self._get(args.poc_ref)
        if row["status"] != "supported":
            raise self.manager._error("validation", "poc_unsupported", "POC is not in the verified executable subset", detail={"poc_ref": args.poc_ref, "status": row["status"], "blockers": row["blockers"], "retry_action": "use system_poc_inspect or choose a supported record"})
        document = self._read_document(row)
        try:
            url = _target_url(args.target, document.request.path)
        except ValueError as exc:
            raise self.manager._error("validation", "poc_target_invalid", str(exc), detail={"retry_action": "use an http(s) origin without query or fragment"}) from exc
        headers = dict(document.request.headers)
        content_type = next((value for key, value in headers.items() if key.lower() == "content-type"), None)
        body = HttpRawBody(type="raw", value=document.request.body, content_type=content_type) if document.request.body is not None else None
        try:
            request = HttpRequestSpec(request_intent="poc", method=document.request.method, url=url, headers=headers, body=body, follow_redirects=document.request.follow_redirects, timeout_seconds=args.timeout_seconds, session_id=args.session_id, update_session=args.update_session)
        except Exception as exc:
            raise self.manager._error("validation", "poc_request_invalid", "POC request cannot be admitted by the HTTP manager", detail={"cause": str(exc)})
        result = await self.manager.start_request(self.agent_id, request=request, wait_seconds=args.wait_seconds, result_limit=1)
        interaction_id = result.get("interaction_id")
        if interaction_id:
            context = {"poc_ref": row["poc_ref"], "sha256": row["sha256"], "source_format": document.source_format, "model_version": document.model_version, "expression": document.expression, "matcher": matcher_to_json(document.matcher), "target": url}
            interaction_dir = self.manager._interaction_dir(self.agent_id, interaction_id)
            interaction_dir.mkdir(parents=True, exist_ok=True)
            (interaction_dir / "poc_context.json").write_text(json.dumps(context, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return {**result, "poc_ref": row["poc_ref"], "source_format": document.source_format, "expression": document.expression, "recommended_action": "call system_poc_output with this interaction_id; do not resubmit while pending"}

    async def output(self, args: PocOutputArguments) -> dict[str, Any]:
        page = await self.manager.output(self.agent_id, interaction_id=args.interaction_id, cursor=args.cursor, limit=args.limit, wait_seconds=args.wait_seconds)
        context_path = self.manager._interaction_dir(self.agent_id, args.interaction_id) / "poc_context.json"
        if not context_path.is_file():
            raise self.manager._error("not_found", "poc_context_not_found", "POC interaction context was not found", detail={"interaction_id": args.interaction_id, "retry_action": "use system_http_output for a non-POC interaction"})
        context = json.loads(context_path.read_text(encoding="utf-8"))
        responses = [item for item in page.get("results", []) if item.get("type") == "response"]
        if not responses and page.get("is_terminal"):
            # A caller may page past the response record; use the same
            # persisted journal rather than treating a read cursor as a new run.
            responses = [item for item in self.manager._response_records(self.agent_id, args.interaction_id) if item.get("type") == "response"]
        response_record = responses[0] if responses else None
        if response_record is None:
            terminal = bool(page.get("is_terminal"))
            return {**page, "poc": {"poc_ref": context["poc_ref"], "sha256": context["sha256"], "model_version": context["model_version"], "expression": context["expression"], "status": "inconclusive" if terminal else "pending", "transport_status": page.get("status"), "failure_stage": page.get("error_code") or ("execution" if terminal else None), "evidence": []}}
        request_id = response_record.get("request_id")
        body: bytes | None = None
        if (response_record.get("outcome") == "response" and response_record.get("body_file")
                and any(item.get("kind") == "body_contains" for item in _flatten_matcher(context["matcher"]))):
            try:
                body_result = await self.manager.response(self.agent_id, interaction_id=args.interaction_id, request_id=request_id, offset_bytes=0, length_bytes=2 * 1024 * 1024)
                if body_result.get("encoding") == "base64":
                    body = base64.b64decode(body_result.get("content", ""))
                else:
                    body = str(body_result.get("content", "")).encode("utf-8")
                if int(body_result.get("body_bytes", len(body))) > 2 * 1024 * 1024:
                    response_record = {**response_record, "body_complete": False}
            except Exception:
                response_record = {**response_record, "body_complete": False}
        status, evidence = evaluate(matcher_from_json(context["matcher"]), response_record, body)
        return {**page, "poc": {"poc_ref": context["poc_ref"], "sha256": context["sha256"], "model_version": context["model_version"], "expression": context["expression"], "status": status, "transport_status": response_record.get("outcome"), "failure_stage": response_record.get("failure_stage"), "body_complete": response_record.get("body_complete"), "evidence": evidence, "template_conclusion": "matching template conditions only; validate the business conclusion separately"}}


def _flatten_matcher(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value.get("type") == "match":
        return [value]
    return _flatten_matcher(value["left"]) + _flatten_matcher(value["right"])
