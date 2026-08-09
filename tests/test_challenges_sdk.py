"""Contract tests and an opt-in live smoke test for the Challenges SDK."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from challenges_sdk import (
    Challenge,
    ChallengesAPIError,
    ChallengesClient,
    ChallengesResponseError,
    ChallengesSettings,
    ChallengesTransportError,
)
from scripts.network_manager import VPNManager

ROOT = Path(__file__).resolve().parents[1]
VPN_CONFIG = ROOT / "config" / "vpn" / "task_8jzOL4JBUYQ_vpn_config.ovpn"


def _client(handler: Any) -> ChallengesClient:
    return ChallengesClient(
        "https://benchmark.test",
        "test-token",
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_list_challenges_sends_auth_header_and_parses_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://benchmark.test/openapi/v1/challenges"
        assert request.headers["BENCHMARK_TOKEN"] == "test-token"
        return httpx.Response(
            200,
            json=[
                {
                    "unique_code": "web_sql_injection_01",
                    "description": "SQL injection",
                    "difficulty": "easy",
                    "level": 1,
                    "total_score": 100,
                    "flag_count": 2,
                    "correct_flag_count": 1,
                    "is_completed": False,
                    "container_status": "available",
                    "container_addr": ["10.0.1.5:8080"],
                }
            ],
        )

    async with _client(handler) as client:
        challenges = await client.list_challenges()

    assert len(challenges) == 1
    assert isinstance(challenges[0], Challenge)
    assert challenges[0].unique_code == "web_sql_injection_01"
    assert challenges[0].container_addr == ["10.0.1.5:8080"]


@pytest.mark.asyncio
async def test_start_challenge_uses_query_parameter() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.params["unique_code"] == "web_sql_injection_01"
        return httpx.Response(
            200,
            json={
                "unique_code": "web_sql_injection_01",
                "container_addr": ["10.0.1.5:8080"],
            },
        )

    async with _client(handler) as client:
        result = await client.start_challenge("web_sql_injection_01")

    assert result.unique_code == "web_sql_injection_01"
    assert result.container_addr == ["10.0.1.5:8080"]


@pytest.mark.asyncio
async def test_get_hint_uses_query_parameter() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.params["unique_code"] == "web_sql_injection_01"
        return httpx.Response(
            200,
            json={"unique_code": "web_sql_injection_01", "hint": "Try a quote."},
        )

    async with _client(handler) as client:
        result = await client.get_hint("web_sql_injection_01")

    assert result.hint == "Try a quote."


@pytest.mark.asyncio
async def test_submit_flag_sends_json_body() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers["content-type"].startswith("application/json")
        assert json.loads(request.content) == {
            "unique_code": "web_sql_injection_01",
            "flag": "flag{example}",
        }
        return httpx.Response(
            200,
            json={
                "correct": True,
                "awarded": 50,
                "cumulative_score": 80,
                "correct_flag_count": 2,
                "total_flag_count": 3,
                "matched_flag_index": 1,
            },
        )

    async with _client(handler) as client:
        result = await client.submit_flag("web_sql_injection_01", "flag{example}")

    assert result.correct is True
    assert result.awarded == 50
    assert result.matched_flag_index == 1


@pytest.mark.asyncio
async def test_close_challenge_uses_query_parameter() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.params["unique_code"] == "web_sql_injection_01"
        return httpx.Response(
            200,
            json={"unique_code": "web_sql_injection_01", "closed": True},
        )

    async with _client(handler) as client:
        result = await client.close_challenge("web_sql_injection_01")

    assert result.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "payload", "expected_code"),
    [
        (404, {"code": "task_not_found", "message": "Task not found", "detail": {}}, "task_not_found"),
        (409, {"code": "duplicate", "message": "Already submitted", "detail": {}}, "duplicate"),
        (422, {"detail": [{"loc": ["body", "flag"], "msg": "too short"}]}, None),
    ],
)
async def test_api_errors_are_typed(
    status_code: int,
    payload: dict[str, Any],
    expected_code: str | None,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload)

    async with _client(handler) as client:
        with pytest.raises(ChallengesAPIError) as caught:
            await client.list_challenges()

    assert caught.value.status_code == status_code
    assert caught.value.code == expected_code
    assert "test-token" not in str(caught.value)


@pytest.mark.asyncio
async def test_transport_errors_do_not_expose_request_details() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed", request=request)

    async with _client(handler) as client:
        with pytest.raises(ChallengesTransportError) as caught:
            await client.list_challenges()

    assert caught.value.operation == "GET /openapi/v1/challenges"
    assert "test-token" not in str(caught.value)


@pytest.mark.asyncio
async def test_response_validation_errors_are_typed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a list"})

    async with _client(handler) as client:
        with pytest.raises(ChallengesResponseError):
            await client.list_challenges()


@pytest.mark.asyncio
async def test_submit_flag_validates_length_before_request() -> None:
    requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(500)

    async with _client(handler) as client:
        with pytest.raises(ValidationError):
            await client.submit_flag("web_sql_injection_01", "")
        with pytest.raises(ValidationError):
            await client.submit_flag("web_sql_injection_01", "x" * 4097)

    assert requests == 0


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_TEST") != "1",
    reason="set RUN_LIVE_TEST=1 to enable the read-only live smoke test",
)
@pytest.mark.asyncio
async def test_live_list_challenges_over_vpn() -> None:
    settings = ChallengesSettings(_env_file=ROOT / ".env")
    vpn = VPNManager(VPN_CONFIG)
    await vpn.start()
    try:
        async with ChallengesClient.from_settings(settings) as client:
            challenges = await client.list_challenges()
    finally:
        await vpn.close()

    assert isinstance(challenges, list)
    assert all(isinstance(challenge, Challenge) for challenge in challenges)
