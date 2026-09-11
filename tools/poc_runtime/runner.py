"""Bridge from the internal POC model to the existing HTTP interaction engine."""

from __future__ import annotations

import json
import asyncio
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4
from urllib.parse import urlsplit, urlunsplit

from agent.state import ResourceController, StateService
from tools.http import HttpInteractionEngine, HttpProbeManager
from tools.http.models import HttpRequestSpec, HttpRawBody
from tools.system.policy import WorkspacePolicy

from .evaluate import evaluate
from .models import PocDocument, PocResponse


def _target_url(target: str, path: str) -> str:
    parsed = urlsplit(target)
    relative = urlsplit(path)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an absolute http or https URL")
    if relative.scheme or relative.netloc or relative.fragment or not relative.path.startswith("/"):
        raise ValueError("POC path must stay within the target origin")
    return urlunsplit((parsed.scheme, parsed.netloc, relative.path, relative.query, ""))


async def run_document(document: PocDocument, *, target: str, output: Path) -> PocResponse:
    """Execute exactly one adapted request through HttpProbeManager.

    A private temporary Run is used by the maintainer CLI. Its HTTP work is
    admitted through ResourceController before launch; the resulting
    interaction directory and body files are copied into the requested output
    directory so the evidence remains inspectable after shutdown.
    """
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    output.mkdir(parents=True, mode=0o700)
    run_root = output / ".run"
    run_root.mkdir(mode=0o700)
    database = run_root / "state.db"
    service = StateService(database, run_root=run_root, workspace_root=run_root)
    await service.initialize()
    run_id = "poc-" + uuid4().hex
    await service.create_run(run_id, duration_minutes=10, model="poc-runtime")
    agent_id = "poc-adapter"
    await service.register_agent(run_id, role="chief", agent_id=agent_id, mission="execute one adapted POC")
    policy = WorkspacePolicy(run_root)
    manager = HttpProbeManager(policy, service, run_id, engine=HttpInteractionEngine(policy))
    controller = ResourceController(
        service,
        run_id,
        storage_root=run_root,
        disk_reserve_bytes=0,
        disk_reserve_percent=0.0,
    )
    try:
        await manager.initialize()
        body = None if document.request.body is None else HttpRawBody(type="raw", value=document.request.body, content_type=document.request.headers.get("Content-Type"))
        spec = HttpRequestSpec(
            request_intent="poc_probe",
            method=document.request.method,
            url=_target_url(target, document.request.path),
            headers=document.request.headers,
            body=body,
            follow_redirects=document.request.follow_redirects,
            timeout_seconds=30.0,
        )
        page = await manager.start_request(agent_id, request=spec, wait_seconds=0.0, result_limit=1)
        interaction_id = page["interaction_id"]
        work = await service.list_resource_work(run_id, owner_id=interaction_id)
        if not work:
            raise RuntimeError("HTTP execution work was not created")
        work_id = work[0]["work_id"]
        admitted = False
        for _ in range(600):
            decision = await controller.admit_resource_work(
                work_id, sample={"cpu_percent": 0.0, "memory_percent": 0.0}
            )
            if decision.get("status") == "reserved":
                claim = await controller.claim_resource_work(work_id)
                if claim.get("claimed"):
                    await manager.launch_work(interaction_id, "execution", work_id=work_id)
                    await controller.mark_resource_started(work_id)
                    admitted = True
                    break
            await asyncio.sleep(0.05)
        if not admitted:
            raise RuntimeError("HTTP execution work was not admitted")
        for _ in range(600):
            page = await manager.output(agent_id, interaction_id=interaction_id, wait_seconds=0.05, limit=10)
            data = page
            if data.get("status") in {"completed", "failed", "stopped", "interrupted"}:
                break
        else:
            raise TimeoutError("POC execution did not finish within 30 seconds")
        records = page.get("results", [])
        response = next((item for item in records if item.get("type") == "response"), None)
        if response is None:
            error = {"code": "execution_failed", "message": page.get("error_code") or "no HTTP response record"}
            return PocResponse("inconclusive", interaction_id, page.get("request_id"), None, {}, error)
        body_bytes: bytes | None = None
        body_file = response.get("body_file")
        if body_file:
            body_path = run_root / ".system-tools" / "runs" / run_id / "agents" / agent_id / "http-interactions" / interaction_id / "responses" / body_file
            if body_path.exists():
                body_bytes = body_path.read_bytes()
        status, evidence = evaluate(document.matcher, response, body_bytes)
        evidence_payload = {"matcher": evidence, "model_version": document.model_version, "source_format": document.source_format}
        interaction_dir = run_root / ".system-tools" / "runs" / run_id / "agents" / agent_id / "http-interactions" / interaction_id
        if interaction_dir.exists():
            shutil.copytree(interaction_dir, output / "http-interaction")
        (output / "result.json").write_text(json.dumps({"status": status, "interaction_id": interaction_id, "request_id": response.get("request_id"), "response": response, "evidence": evidence_payload}, ensure_ascii=False, indent=2), encoding="utf-8")
        (output / "poc.json").write_text(json.dumps({"source_format": document.source_format, "path": document.path, "sha256": document.sha256, "rule_name": document.rule_name, "target": target, "request": {"method": document.request.method, "path": document.request.path, "headers": document.request.headers, "body": document.request.body, "follow_redirects": document.request.follow_redirects}, "expression": document.expression, "model_version": document.model_version}, ensure_ascii=False, indent=2), encoding="utf-8")
        return PocResponse(status, interaction_id, response.get("request_id"), response, evidence_payload)
    finally:
        try:
            await manager.finish_run()
        finally:
            await service.close()
