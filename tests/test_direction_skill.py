"""Tests for the common challenge-direction Skill and persistence boundary."""

from __future__ import annotations

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from sqlalchemy import select

from agent.state import CapabilityRegistry, StateService
from agent.state.errors import StateConflict
from agent.state.models import StateEventRecord
from agent.state.schemas import (
    AnalysisPlanInput,
    ChallengeImport,
    CreateCycleInput,
    VerificationUpdateInput,
)


SKILL_ROOT = Path(__file__).parents[1] / "agent" / "skills" / "common" / "recognize-challenge-direction"
PROBE = SKILL_ROOT / "scripts" / "probe_target.py"


class _ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html><title>probe</title><body>ready</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        method = payload.get("method")
        result = "aion-node/v1" if method == "web3_clientVersion" else "0x7a69"
        body = json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return None


@pytest.fixture
def probe_server() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _run_probe(input_path: Path, output_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [".venv/bin/python", str(PROBE), str(input_path), str(output_path)],
        cwd=Path(__file__).parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_direction_skill_is_common_and_has_no_manifest() -> None:
    instructions = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "name: recognize-challenge-direction" in instructions
    assert "probe_script: scripts/probe_target.py" in instructions
    assert not (SKILL_ROOT / "skill.yaml").exists()
    assert {item.name for item in (SKILL_ROOT / "references").iterdir()} == {
        "web.md",
        "binary.md",
        "ai.md",
        "blockchain.md",
    }


def test_probe_classifies_evm_surface_without_external_network(
    tmp_path: Path, probe_server: ThreadingHTTPServer
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "unique_code": "blockchain-1",
                "description": "Ethereum JSON-RPC challenge",
                "target": f"127.0.0.1:{probe_server.server_port}",
                "mode": "auto",
            }
        ),
        encoding="utf-8",
    )
    completed = _run_probe(input_path, output_path)
    assert completed.returncode == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["reachable"] is True
    assert result["protocol"] == "json-rpc"
    assert result["access_surface"] == "evm_rpc"
    assert result["request_count"] == 3
    assert "blockchain" in result["direction_candidates"]


def test_probe_rejects_multiple_targets(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"target": "127.0.0.1:1,127.0.0.1:2"}), encoding="utf-8")
    completed = _run_probe(input_path, output_path)
    assert completed.returncode == 2
    assert json.loads(output_path.read_text(encoding="utf-8"))["error_code"] == "invalid_input"


@pytest.mark.asyncio
async def test_direction_is_persisted_by_analysis_plan_and_not_remote_sync(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run(
        "run-1", challenges=[ChallengeImport(unique_code="c-1", description="web")]
    )
    chief = await service.register_agent("run-1", role="chief")
    challenge_agent = await service.register_agent(
        "run-1",
        role="challenge",
        parent_id=chief["agent_id"],
        unique_code="c-1",
    )
    context = CapabilityRegistry().issue(
        "run-1", challenge_agent["agent_id"], "challenge", "c-1"
    ).context
    await service.start_challenge("run-1", "c-1", context)
    challenge = (await service.list_challenges("run-1"))[0]
    active_since = challenge["active_since"]
    last_progress_at = challenge["last_progress_at"]
    cycle = await service.begin_cycle(
        "run-1",
        "c-1",
        context,
        CreateCycleInput(expected_challenge_version=challenge["version"]),
    )
    planned = await service.submit_analysis_plan(
        "run-1",
        cycle["cycle_id"],
        context,
        AnalysisPlanInput(
            expected_version=cycle["version"],
            analysis_summary="classify before planning",
            direction="web",
        ),
    )
    assert planned["analysis"]["direction"] == "web"
    classified = (await service.list_challenges("run-1"))[0]
    assert classified["direction"] == "web"
    assert classified["active_since"] == active_since
    assert classified["last_progress_at"] == last_progress_at

    await service.import_challenges(
        "run-1",
        [ChallengeImport(unique_code="c-1", description="remote refresh", container_status="available")],
    )
    refreshed = (await service.list_challenges("run-1"))[0]
    assert refreshed["direction"] == "web"

    async with service.db.sessions() as session:
        events = list(
            (
                await session.scalars(
                    select(StateEventRecord).where(
                        StateEventRecord.run_id == "run-1",
                        StateEventRecord.event_type == "challenge_direction_changed",
                    )
                )
            ).all()
        )
    assert len(events) == 1
    await service.close()


@pytest.mark.asyncio
async def test_direction_change_requires_new_report_or_observation_reference(
    tmp_path: Path,
) -> None:
    service = StateService(tmp_path / "state.sqlite3", run_root=tmp_path)
    await service.create_run("run-1", challenges=[ChallengeImport(unique_code="c-1")])
    chief = await service.register_agent("run-1", role="chief")
    challenge_agent = await service.register_agent(
        "run-1", role="challenge", parent_id=chief["agent_id"], unique_code="c-1"
    )
    context = CapabilityRegistry().issue(
        "run-1", challenge_agent["agent_id"], "challenge", "c-1"
    ).context
    first = await service.begin_cycle(
        "run-1",
        "c-1",
        context,
        CreateCycleInput(expected_challenge_version=1),
    )
    planned = await service.submit_analysis_plan(
        "run-1",
        first["cycle_id"],
        context,
        AnalysisPlanInput(
            expected_version=first["version"],
            analysis_summary="initial classification",
            direction="web",
        ),
    )
    await service.commit_cycle(
        "run-1",
        first["cycle_id"],
        context,
        VerificationUpdateInput(
            expected_version=planned["version"],
            summary="classification cycle complete",
            outcome="no_progress",
        ),
    )
    current = (await service.list_challenges("run-1"))[0]
    second = await service.begin_cycle(
        "run-1",
        "c-1",
        context,
        CreateCycleInput(expected_challenge_version=current["version"]),
    )
    with pytest.raises(StateConflict, match="report or observation"):
        await service.submit_analysis_plan(
            "run-1",
            second["cycle_id"],
            context,
            AnalysisPlanInput(
                expected_version=second["version"],
                analysis_summary="change without evidence",
                direction="ai",
            ),
        )
    await service.close()
