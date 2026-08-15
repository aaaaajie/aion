"""Tests for the local CTF configuration used by the quick smoke test."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import quick_runtime_test as quick
from agent.tooling import ToolExecutor, ToolRegistry
import json


def test_local_challenge_slot_normalizes_name_and_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        quick,
        "CHALLENGES",
        [
            {
                "name": "My Web CTF",
                "description": "A local web challenge",
                "address": ["http://127.0.0.1:8080", "http://127.0.0.1:8081"],
                "mission": "inspect the assigned service",
            }
        ],
    )
    selected = quick._selected_challenges(None)
    assert selected[0]["unique_code"] == "My Web CTF"
    assert selected[0]["container_addr"] == [
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8081",
    ]


def test_quick_test_default_wait_is_unbounded() -> None:
    assert quick.DEFAULT_WAIT_SECONDS == 0.0


def test_quick_test_does_not_discover_vpn_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_discovery(*_args: object, **_kwargs: object) -> Path:
        raise AssertionError("VPN discovery must stay disabled by default")

    monkeypatch.setattr(quick, "discover_vpn_config", fail_discovery)
    assert quick._create_network_manager(False, None) is None


@pytest.mark.asyncio
async def test_local_challenge_benchmark_has_no_external_dependency() -> None:
    challenge = {
        "unique_code": "local-web",
        "description": "local fixture",
        "container_addr": ["http://127.0.0.1:8080"],
    }
    benchmark = quick.LocalChallengeBenchmark([challenge])
    async def call(name: str, arguments: dict[str, str] | None = None):
        calls = await ToolExecutor(ToolRegistry([benchmark])).execute(
            [{"id": name, "function": {"name": name, "arguments": json.dumps(arguments or {})}}]
        )
        assert calls[0].result is not None
        return calls[0].result

    catalog = await call("benchmark_list_challenges")
    assert catalog["ok"] is True
    assert catalog["data"][0]["container_status"] == "stopped"

    started = await call(
        "benchmark_start_challenge", {"unique_code": "local-web"}
    )
    assert started["ok"] is True
    catalog = await call("benchmark_list_challenges")
    assert catalog["data"][0]["container_status"] == "running"


def test_quick_test_waits_for_every_execution_report() -> None:
    overview = {
        "agents": [
            {
                "agent_id": "execution-1",
                "role": "execution",
                "unique_code": "web",
                "parent_id": "challenge-1",
                "status": "failed",
                "last_report_sequence": 12,
            },
            {
                "agent_id": "execution-2",
                "role": "execution",
                "unique_code": "web",
                "parent_id": "challenge-1",
                "status": "queued",
                "last_report_sequence": 0,
            },
            {
                "agent_id": "challenge-1",
                "role": "challenge",
                "unique_code": "web",
                "status": "running",
                "report_cursors": {"execution": 0},
            },
        ]
    }
    assert quick._execution_phase_complete(overview, {"web"}) is False

    overview["agents"][1]["status"] = "completed"
    overview["agents"][1]["last_report_sequence"] = 18
    overview["agents"][2]["report_cursors"]["execution"] = 18
    assert quick._execution_phase_complete(overview, {"web"}) is False

    overview["agents"][2]["status"] = "completed"
    assert quick._execution_phase_complete(overview, {"web"}) is True
