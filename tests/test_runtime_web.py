"""Offline tests for the test-only Flight Recorder."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from agent.state import StateService
from agent.state.models import CredentialRecord
from agent.state.schemas import AgentReportInput, CapabilityContext, ChallengeImport
from scripts.runtime_web import RuntimeMonitor


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=2) as response:
        assert response.status == 200
        return json.loads(response.read().decode("utf-8"))


@pytest.mark.asyncio
async def test_flight_recorder_reads_graph_history_and_redacts_secrets(tmp_path: Path) -> None:
    state_path = tmp_path / "run" / "state.sqlite3"
    service = StateService(state_path)
    await service.create_run(
        "web-run",
        model="offline-model",
        prompt="coordinate the local fixture",
        challenges=[ChallengeImport(unique_code="fixture-1", description="local fixture")],
    )
    chief = await service.register_agent(
        "web-run",
        role="chief",
        initial_prompt="chief prompt",
    )
    challenge = await service.register_agent(
        "web-run",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="fixture-1",
        initial_prompt="challenge prompt",
    )
    execution = await service.register_agent(
        "web-run",
        role="execution",
        parent_id=challenge["agent_id"],
        unique_code="fixture-1",
        initial_prompt="execution prompt",
    )
    await service.append_agent_event(
        "web-run",
        execution["agent_id"],
        "test_effective_prompt",
        {"prompt": "execution prompt plus test guard"},
    )
    await service.append_agent_event(
        "web-run",
        execution["agent_id"],
        "tool_call",
        {
            "tool_call_id": "call-1",
            "tool_name": "system_write_file",
            "arguments": {"file_path": "fixture.txt"},
        },
    )
    await service.append_agent_event(
        "web-run",
        execution["agent_id"],
        "tool_result",
        {
            "tool_call_id": "call-1",
            "tool_name": "system_write_file",
            "result": {"ok": True},
        },
    )
    await service.append_agent_event(
        "web-run",
        execution["agent_id"],
        "tool_result",
        {"candidate_flag": "flag{monitor-secret}"},
    )
    context = CapabilityContext(
        run_id="web-run",
        agent_id=execution["agent_id"],
        role="execution",
        unique_code="fixture-1",
    )
    report = await service.submit_report(
        "web-run",
        execution["agent_id"],
        context,
        AgentReportInput(status="completed", summary="local report"),
    )
    await service.finish_agent("web-run", execution["agent_id"], status="completed")
    operation_id = await service.mark_operation_started(
        "web-run",
        "challenge.start",
        agent_id=chief["agent_id"],
        unique_code="fixture-1",
        arguments={"password": "operation-secret"},
    )
    await service.complete_operation(
        "web-run",
        operation_id,
        result_code="ok",
        result_payload={"candidate_flag": "flag{operation-secret}"},
    )
    async with service.db.sessions.begin() as session:
        session.add(
            CredentialRecord(
                credential_id="credential-monitor",
                run_id="web-run",
                unique_code="fixture-1",
                kind="fixture",
                principal="local-user",
                secret_value="credential-secret",
                scope="local",
            )
        )

    monitor = RuntimeMonitor(state_path, "web-run")
    url = monitor.start()
    snapshot = _get_json(f"{url}api/snapshot")
    body = json.dumps(snapshot, ensure_ascii=False)
    assert snapshot["run"]["prompt"] == "coordinate the local fixture"
    assert snapshot["challenges"][0]["slot_occupied"] is False
    assert snapshot["container_capacity"]["free_count"] == 3
    assert {item["role"] for item in snapshot["agents"]} == {"chief", "challenge", "execution"}
    assert next(item for item in snapshot["agents"] if item["agent_id"] == execution["agent_id"])["parent_id"] == challenge["agent_id"]
    assert any(item["event_type"] == "tool_call" for item in snapshot["events"])
    assert snapshot["reports"][0]["sequence"] == report["sequence"]
    assert snapshot["credentials"][0]["principal"] == "local-user"
    assert "secret_value" not in snapshot["credentials"][0]
    assert "flag{monitor-secret}" not in body
    assert "flag{operation-secret}" not in body
    assert "operation-secret" not in body
    assert "credential-secret" not in body

    detail = _get_json(f"{url}api/agents/{execution['agent_id']}")
    detail_body = json.dumps(detail, ensure_ascii=False)
    assert detail["agent"]["initial_prompt"] == "execution prompt"
    assert any(item["event_type"] == "test_effective_prompt" for item in detail["events"])
    assert "credential-secret" not in detail_body

    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(
            urllib.request.Request(f"{url}api/snapshot", method="POST"), timeout=2
        )
    assert error.value.code == 405

    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(f"{url}api/agents/does-not-exist", timeout=2)
    assert error.value.code == 404
    with urllib.request.urlopen(f"{url}assets/styles.css", timeout=2) as response:
        assert response.status == 200
        assert "--accent" in response.read().decode("utf-8")
    for asset_name in ("Challenge.svg", "Chief.svg", "Execution.svg"):
        with urllib.request.urlopen(f"{url}assets/{asset_name}", timeout=2) as response:
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("image/svg+xml")
            assert "<svg" in response.read().decode("utf-8")

    await service.close()
    monitor.freeze(0, message="fixture complete")
    frozen = _get_json(f"{url}api/snapshot")
    assert frozen["monitor"]["mode"] == "frozen"
    assert frozen["monitor"]["test_code"] == 0
    monitor.close()


def test_flight_recorder_only_accepts_localhost(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        RuntimeMonitor(tmp_path / "state.sqlite3", "run", host="0.0.0.0")
