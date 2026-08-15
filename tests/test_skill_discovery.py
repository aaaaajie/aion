"""Two-stage Execution Skill discovery tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

import agent.skills.discovery as discovery_module
from agent.config import AgentSettings
from agent.skills import SkillCatalog, SkillDiscovery


class EventService:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def append_agent_event(
        self, run_id: str, agent_id: str, event_type: str, payload: dict[str, Any]
    ) -> int:
        self.events.append(
            {
                "sequence": len(self.events) + 1,
                "run_id": run_id,
                "agent_id": agent_id,
                "event_type": event_type,
                "payload": payload,
            }
        )
        return len(self.events)

    async def latest_agent_event(
        self, run_id: str, agent_id: str, *, event_types: set[str]
    ) -> dict[str, Any] | None:
        return next(
            (
                item
                for item in reversed(self.events)
                if item["run_id"] == run_id
                and item["agent_id"] == agent_id
                and item["event_type"] in event_types
            ),
            None,
        )


def skill_root(tmp_path: Path) -> Path:
    root = tmp_path / "skills"
    for category in ("common", "challenge", "execution"):
        (root / category).mkdir(parents=True)
    for name, description in (
        (
            "sql-injection",
            "SQL injection validation for database-backed request parameters.",
        ),
        (
            "host-header",
            "Host header trust testing for virtual-host routing and reset links.",
        ),
        (
            "javascript-recon",
            "JavaScript bundle and source-map reconnaissance.",
        ),
    ):
        directory = root / "execution" / name
        directory.mkdir()
        (directory / "SKILL.md").write_text(
            "---\n"
            f"name: {name}\n"
            f"description: {description}\n"
            f"when_to_use: Use when the task specifically requires {name}.\n"
            "---\n\n# Instructions\nUse bounded evidence.\n",
            encoding="utf-8",
        )
    return root


def settings(*, model: str | None = "discovery-model") -> AgentSettings:
    return AgentSettings(
        llm_base_url="https://model.invalid/v1",
        llm_model="main-model",
        llm_api_key="test-key",
        skill_discovery_model=model,
    )


def response(content: str, *, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={"choices": [{"message": {"content": content}}]},
    )


@pytest.mark.asyncio
async def test_discovery_model_presents_candidates_without_activation(
    tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return response(
            json.dumps(
                {
                    "candidates": [
                        {
                            "skill_id": "execution/sql-injection",
                            "confidence": 0.98,
                            "reason": "The objective explicitly asks for SQL injection.",
                        }
                    ]
                }
            )
        )

    service = EventService()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    discovery = SkillDiscovery(
        settings(), SkillCatalog(skill_root(tmp_path)), service, "run", client=client
    )
    result = await discovery.candidates_for(
        "agent",
        objective="Validate SQL injection in the login parameter",
        task_stage="validation",
        hypothesis="sql-login",
    )
    assert [item.skill_id for item in result.candidates] == [
        "execution/sql-injection"
    ]
    assert result.source == "model"
    assert calls[0]["model"] == "discovery-model"
    assert calls[0]["thinking"] == {"type": "disabled"}
    assert calls[0]["temperature"] == 0
    assert calls[0]["max_tokens"] == 512
    event_types = [item["event_type"] for item in service.events]
    assert event_types == ["skill_discovery_started", "skill_discovery_completed"]
    assert "reason" not in service.events[-1]["payload"]
    await discovery.close()
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "model_response",
    [
        response("not json"),
        response(
            '{"candidates":[{"skill_id":"execution/unknown","confidence":1,'
            '"reason":"unknown"}]}'
        ),
        response(
            '{"candidates":['
            '{"skill_id":"execution/sql-injection","confidence":1,"reason":"one"},'
            '{"skill_id":"execution/sql-injection","confidence":1,"reason":"two"}'
            "]}"
        ),
        response(""),
        response("{}", status=429),
        response("{}", status=503),
    ],
)
async def test_invalid_or_failed_discovery_falls_back_without_blocking(
    tmp_path: Path, model_response: httpx.Response
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return model_response

    service = EventService()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    discovery = SkillDiscovery(
        settings(), SkillCatalog(skill_root(tmp_path)), service, "run", client=client
    )
    result = await discovery.candidates_for(
        "agent",
        objective="Validate SQL injection",
        task_stage="validation",
        hypothesis="sql",
    )
    assert result.source == "local_fallback"
    assert result.latency_ms < 5_000
    assert any(
        item["event_type"] == "skill_discovery_failed" for item in service.events
    )
    assert service.events[-1]["event_type"] == "skill_discovery_fallback"
    await discovery.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_discovery_timeout_uses_local_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(discovery_module, "DISCOVERY_TIMEOUT_SECONDS", 0.02)

    async def handler(_request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.1)
        return response('{"candidates":[]}')

    service = EventService()
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    discovery = SkillDiscovery(
        settings(), SkillCatalog(skill_root(tmp_path)), service, "run", client=client
    )
    result = await discovery.candidates_for(
        "agent",
        objective="Inspect JavaScript bundles",
        task_stage="discovery",
        hypothesis="js",
    )
    assert result.source == "local_fallback"
    assert result.latency_ms < 500
    assert next(
        item
        for item in service.events
        if item["event_type"] == "skill_discovery_failed"
    )["payload"]["failure_code"] == "timeout"
    await discovery.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_discovery_cache_and_durable_recovery_avoid_duplicate_model_calls(
    tmp_path: Path,
) -> None:
    call_count = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return response(
            '{"candidates":[{"skill_id":"execution/javascript-recon",'
            '"confidence":0.9,"reason":"The task names JavaScript bundles."}]}'
        )

    service = EventService()
    catalog = SkillCatalog(skill_root(tmp_path))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    discovery = SkillDiscovery(settings(), catalog, service, "run", client=client)
    arguments = {
        "objective": "Inspect JavaScript bundles",
        "task_stage": "discovery",
        "hypothesis": "js-assets",
    }
    first = await discovery.candidates_for("agent-one", **arguments)
    cached = await discovery.candidates_for("agent-two", **arguments)
    excluded = await discovery.candidates_for(
        "agent-three",
        **arguments,
        excluded_ids=("execution/javascript-recon",),
    )
    assert first.source == "model"
    assert cached.cache_hit is True
    assert excluded.candidates == ()
    assert call_count == 1

    resumed = SkillDiscovery(settings(), catalog, service, "run", client=client)
    recovered = await resumed.candidates_for("agent-one", **arguments)
    assert recovered.source == "recovered"
    assert call_count == 1
    await resumed.close()
    await discovery.close()
    await client.aclose()


def test_release_catalog_replay_avoids_known_misselections_and_keeps_matches() -> None:
    catalog = SkillCatalog()

    def ids(task: str) -> set[str]:
        return {
            str(item["skill_id"])
            for item in catalog.discovery_candidates(task, limit=20)
        }

    port = ids("Scan exposed ports and identify network services")
    assert "execution/http-host-header-attacks" not in port
    assert "execution/ai-llm-agent-security" not in port
    credentials = ids("Test registration and default credentials on the login flow")
    assert "execution/php-file-upload-audit" not in credentials
    forbidden = ids("Bypass 403 protection on exposed configuration files")
    assert "execution/php-file-upload-audit" not in forbidden

    assert "execution/api-recon-and-docs" in ids(
        "Enumerate undocumented API routes and OpenAPI documentation"
    )
    assert ids("Investigate an exposed .git repository and recover source") & {
        "execution/code-auditor",
        "execution/source-code-audit",
        "execution/recon-js-analysis",
    }
    assert "execution/path-traversal-lfi" in ids(
        "Validate local file inclusion and path traversal"
    )
    assert "execution/php-file-upload-audit" in ids(
        "Exploit a confirmed PHP multipart upload endpoint and deploy a web shell"
    )
    assert "execution/src-hunter" in ids(
        "Use an established PHP foothold for internal-network tunneling"
    )
