from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.state import CapabilityContext
from agent.state.database import StateDatabase
from agent.state.schemas import ChallengeImport
from agent.state.service import StateService


@pytest.mark.asyncio
async def test_evidence_is_private_immutable_and_survives_source_cleanup(tmp_path: Path) -> None:
    service = StateService(
        StateDatabase(tmp_path / "state.sqlite3"),
        run_root=tmp_path / "runs",
        workspace_root=tmp_path / "workspace",
    )
    await service.initialize()
    await service.create_run(
        "run",
        challenges=[ChallengeImport(unique_code="c", container_status="running")],
    )
    await service.register_agent("run", agent_id="chief", role="chief", initial_prompt="x")
    await service.register_agent(
        "run", agent_id="challenge", role="challenge", parent_id="chief", unique_code="c", initial_prompt="x"
    )
    await service.register_agent(
        "run",
        agent_id="execution",
        role="execution",
        parent_id="challenge",
        unique_code="c",
        mission="x",
        initial_prompt="x",
    )
    context = CapabilityContext(
        run_id="run", agent_id="execution", role="execution", unique_code="c"
    )
    source = tmp_path / "workspace" / "temporary-output.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("secret result", encoding="utf-8")
    saved = await service.persist_evidence(
        "run",
        context,
        evidence_type="file",
        source="system_write_file",
        content=source.read_text(encoding="utf-8"),
    )
    source.unlink()
    restored = await service.read_evidence("run", context, saved["evidence_ref"])
    assert restored["content"] == "secret result"
    evidence_file = next(
        (tmp_path / "runs" / "run" / "agents" / "execution" / "evidence").glob("*.txt")
    )
    assert os.stat(evidence_file).st_mode & 0o777 == 0o600
    assert os.stat(evidence_file.parent).st_mode & 0o777 == 0o700
    await service.close()
