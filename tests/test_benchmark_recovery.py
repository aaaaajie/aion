"""Tests for bounded benchmark contract and response recovery."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agent.config import AgentSettings
from challenges_sdk import ChallengesAPIError, ChallengesClient, ChallengesResponseError
from challenges_sdk.recovery import (
    BenchmarkOperationContract,
    ResponseRecoveryContext,
    ResponseRecoveryDecision,
)
from tools.benchmark.recovery import BenchmarkLLMRecovery


BASE_URL = "https://benchmark.test"
TOKEN = "benchmark-token"
CODE = "web_sql_injection_01"


class _Recoverer:
    def __init__(self, decision: ResponseRecoveryDecision | None = None) -> None:
        self.decision = decision
        self.calls: list[ResponseRecoveryContext] = []

    async def recover(
        self, context: ResponseRecoveryContext
    ) -> ResponseRecoveryDecision | None:
        self.calls.append(context)
        return self.decision


class _ContractRecoverer:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.calls = 0

    async def recover_contract(self, context: Any) -> Any:
        self.calls += 1
        return self.value


def make_client(handler: Any, **kwargs: Any) -> ChallengesClient:
    return ChallengesClient(
        BASE_URL,
        TOKEN,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_exact_response_does_not_call_recoverer() -> None:
    recoverer = _Recoverer(
        ResponseRecoveryDecision(True, 1.0, {"unique_code": CODE, "hint": "x"}, "unused")
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unique_code": CODE, "hint": "Try a quote."})

    client = make_client(handler, response_recoverer=recoverer)
    try:
        result = await client.get_hint(CODE)
    finally:
        await client.close()

    assert result.hint == "Try a quote."
    assert recoverer.calls == []


@pytest.mark.asyncio
async def test_deterministic_envelope_and_camel_case_recovery_precedes_llm() -> None:
    recoverer = _Recoverer(None)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "items": [
                    {"uniqueCode": CODE, "containerStatus": "running"},
                ]
            },
        )

    client = make_client(handler, response_recoverer=recoverer)
    try:
        result = await client.list_challenges()
    finally:
        await client.close()

    assert result[0].unique_code == CODE
    assert result[0].container_status == "running"
    assert result[0].is_completed is False
    assert recoverer.calls == []


@pytest.mark.asyncio
async def test_unknown_success_response_calls_llm_once_and_validates_result() -> None:
    recoverer = _Recoverer(
        ResponseRecoveryDecision(
            True,
            0.95,
            {"unique_code": CODE, "hint": "Try a quote."},
            "mapped text to hint",
        )
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"text": "Try a quote."})

    client = make_client(handler, response_recoverer=recoverer)
    try:
        result = await client.get_hint(CODE)
    finally:
        await client.close()

    assert result.hint == "Try a quote."
    assert len(recoverer.calls) == 1


@pytest.mark.asyncio
async def test_low_confidence_recovery_remains_invalid_response() -> None:
    recoverer = _Recoverer(
        ResponseRecoveryDecision(
            True,
            0.89,
            {"unique_code": CODE, "hint": "maybe"},
            "uncertain",
        )
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unknown": True})

    client = make_client(handler, response_recoverer=recoverer)
    try:
        with pytest.raises(ChallengesResponseError) as caught:
            await client.get_hint(CODE)
    finally:
        await client.close()

    assert caught.value.recovery_attempted is True
    assert len(recoverer.calls) == 1


@pytest.mark.asyncio
async def test_recovery_context_redacts_token_and_flag() -> None:
    recoverer = _Recoverer(None)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"echo": TOKEN, "submitted": "flag{secret-value}"},
        )

    client = make_client(handler, response_recoverer=recoverer)
    try:
        with pytest.raises(ChallengesResponseError):
            await client.submit_flag(CODE, "flag{secret-value}")
    finally:
        await client.close()

    assert len(recoverer.calls) == 1
    payload = repr(recoverer.calls[0].payload)
    assert TOKEN not in payload
    assert "flag{secret-value}" not in payload


@pytest.mark.asyncio
async def test_openapi_contract_discovery_changes_request_without_llm() -> None:
    requests: list[httpx.Request] = []
    document = {
        "paths": {
            "/api/challenges": {
                "get": {"operationId": "listChallenges"},
            }
        }
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=document)
        assert request.url.path == "/api/challenges"
        return httpx.Response(
            200,
            json=[
                {
                    "unique_code": CODE,
                    "difficulty": "easy",
                    "level": 1,
                    "total_score": 50,
                    "flag_count": 1,
                    "correct_flag_count": 0,
                    "is_completed": False,
                    "container_status": "stopped",
                    "container_addr": [],
                }
            ],
        )

    client = make_client(handler, contract_recoverer=_ContractRecoverer({}))
    try:
        result = await client.list_challenges()
        events = client.take_call_events()
    finally:
        await client.close()

    assert result[0].unique_code == CODE
    assert [request.url.path for request in requests] == [
        "/openapi.json",
        "/api/challenges",
    ]
    assert client.contract_source == "openapi"
    assert any(item["code"] == "benchmark_contract_discovered" for item in events)


@pytest.mark.asyncio
async def test_missing_hint_endpoint_is_reported_without_response_llm() -> None:
    recoverer = _Recoverer(None)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not supported"})

    client = make_client(handler, response_recoverer=recoverer)
    try:
        with pytest.raises(ChallengesAPIError) as caught:
            await client.get_hint(CODE)
        events = client.take_call_events()
    finally:
        await client.close()

    assert caught.value.status_code == 404
    assert recoverer.calls == []
    assert any(item["code"] == "benchmark_capability_unavailable" for item in events)


@pytest.mark.asyncio
async def test_explicit_validation_error_allows_one_start_query_body_adaptation() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            assert request.url.params["unique_code"] == CODE
            return httpx.Response(
                422,
                json={
                    "detail": [
                        {
                            "loc": ["body", "unique_code"],
                            "msg": "field required",
                        }
                    ]
                },
            )
        assert str(request.url.params) == ""
        assert json.loads(request.content) == {"unique_code": CODE}
        return httpx.Response(
            200,
            json={"unique_code": CODE, "container_addr": ["10.0.0.4:8080"]},
        )

    client = make_client(handler)
    try:
        result = await client.start_challenge(CODE)
        events = client.take_call_events()
    finally:
        await client.close()

    assert result.container_addr == ["10.0.0.4:8080"]
    assert len(requests) == 2
    assert any(item["code"] == "benchmark_request_contract_adapted" for item in events)


@pytest.mark.asyncio
async def test_production_llm_recoverer_accepts_only_strict_json() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"recoverable":true,"confidence":0.97,"data":{"unique_code":"web_sql_injection_01","hint":"Try a quote."},"reason":"field mapping"}'
                        }
                    }
                ]
            },
        )

    settings = AgentSettings(
        _env_file=None,
        llm_base_url="https://llm.test",
        llm_model="test-model",
        llm_api_key="llm-secret",
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    recoverer = BenchmarkLLMRecovery(settings, client=http_client)
    try:
        decision = await recoverer.recover(
            ResponseRecoveryContext(
                operation="get_hint",
                method="GET",
                path="/openapi/v1/challenges/hint",
                status_code=200,
                content_type="application/json",
                payload={"text": "Try a quote."},
                expected_schema={"type": "object"},
                response_size=24,
            )
        )
    finally:
        await http_client.aclose()

    assert decision is not None
    assert decision.confidence == 0.97
    assert decision.data["hint"] == "Try a quote."
    assert len(requests) == 1
    assert "llm-secret" not in requests[0].content.decode()
