"""Offline contract tests for the Agent-facing Benchmark Tools wrapper."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from challenges_sdk import ChallengesClient
from tools.benchmark import BenchmarkTools

TOKEN = "test-token"
CHALLENGE_CODE = "web_sql_injection_01"
BASE_URL = "https://benchmark.test"

CHALLENGE = {
    "unique_code": CHALLENGE_CODE,
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


def make_tools(handler: Any) -> BenchmarkTools:
    client = ChallengesClient(
        BASE_URL,
        TOKEN,
        transport=httpx.MockTransport(handler),
    )
    return BenchmarkTools(client)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "arguments", "http_method", "path", "response", "expected_data"),
    [
        (
            "list_challenges",
            {},
            "GET",
            "/openapi/v1/challenges",
            [CHALLENGE],
            [CHALLENGE],
        ),
        (
            "start_challenge",
            {"unique_code": CHALLENGE_CODE},
            "POST",
            "/openapi/v1/challenges/start",
            {"unique_code": CHALLENGE_CODE, "container_addr": ["10.0.1.5:8080"]},
            {"unique_code": CHALLENGE_CODE, "container_addr": ["10.0.1.5:8080"]},
        ),
        (
            "get_hint",
            {"unique_code": CHALLENGE_CODE},
            "GET",
            "/openapi/v1/challenges/hint",
            {"unique_code": CHALLENGE_CODE, "hint": "Try a quote."},
            {"unique_code": CHALLENGE_CODE, "hint": "Try a quote."},
        ),
        (
            "submit_flag",
            {"unique_code": CHALLENGE_CODE, "flag": "flag{example}"},
            "POST",
            "/openapi/v1/challenges/submit",
            {
                "correct": True,
                "awarded": 50,
                "cumulative_score": 80,
                "correct_flag_count": 2,
                "total_flag_count": 3,
                "matched_flag_index": 1,
            },
            {
                "correct": True,
                "awarded": 50,
                "cumulative_score": 80,
                "correct_flag_count": 2,
                "total_flag_count": 3,
                "matched_flag_index": 1,
            },
        ),
        (
            "close_challenge",
            {"unique_code": CHALLENGE_CODE},
            "POST",
            "/openapi/v1/challenges/close",
            {"unique_code": CHALLENGE_CODE, "closed": True},
            {"unique_code": CHALLENGE_CODE, "closed": True},
        ),
    ],
)
async def test_named_methods_return_json_envelopes_and_call_sdk(
    method_name: str,
    arguments: dict[str, str],
    http_method: str,
    path: str,
    response: Any,
    expected_data: Any,
) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=response)

    tools = make_tools(handler)
    async with tools:
        result = await getattr(tools, method_name)(**arguments)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == http_method
    assert request.url.path == path
    assert request.headers["BENCHMARK_TOKEN"] == TOKEN
    if "flag" in arguments:
        assert json.loads(request.content) == arguments
    elif "unique_code" in arguments:
        assert request.url.params["unique_code"] == CHALLENGE_CODE

    assert result == {"ok": True, "data": expected_data}
    json.dumps(result)


@pytest.mark.asyncio
async def test_dispatch_routes_tool_name_and_accepts_env_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[CHALLENGE])

    monkeypatch.setenv("BENCHMARK_BASE_URL", BASE_URL)
    monkeypatch.setenv("BENCHMARK_TOKEN", TOKEN)
    tools = BenchmarkTools.from_env(transport=httpx.MockTransport(handler))
    async with tools:
        result = await tools.dispatch("benchmark_list_challenges", {})

    assert result["ok"] is True
    assert result["data"][0]["unique_code"] == CHALLENGE_CODE
    assert len(requests) == 1


def test_tool_definitions_are_openai_compatible_and_copy_safe() -> None:
    definitions = BenchmarkTools.tool_definitions()
    names = [definition["function"]["name"] for definition in definitions]

    assert names == [
        "benchmark_list_challenges",
        "benchmark_start_challenge",
        "benchmark_get_hint",
        "benchmark_submit_flag",
        "benchmark_close_challenge",
    ]
    for definition in definitions:
        function = definition["function"]
        parameters = function["parameters"]
        assert definition["type"] == "function"
        assert parameters["type"] == "object"
        assert parameters["additionalProperties"] is False

    submit = next(
        item for item in definitions if item["function"]["name"] == "benchmark_submit_flag"
    )
    assert submit["function"]["parameters"]["required"] == ["unique_code", "flag"]
    assert "duplicate" in submit["function"]["description"]

    definitions[0]["function"]["name"] = "mutated"
    assert BenchmarkTools.tool_definitions()[0]["function"]["name"] == "benchmark_list_challenges"


@pytest.mark.asyncio
async def test_dispatch_rejects_unknown_and_invalid_arguments_without_http_call() -> None:
    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(500)

    tools = make_tools(handler)
    async with tools:
        unknown = await tools.dispatch("benchmark_unknown", {})
        invalid_name = await tools.dispatch(123, {})  # type: ignore[arg-type]
        missing = await tools.dispatch("benchmark_start_challenge", {})
        extra = await tools.dispatch(
            "benchmark_start_challenge",
            {"unique_code": CHALLENGE_CODE, "unexpected": True},
        )
        non_object = await tools.dispatch("benchmark_list_challenges", [])
        invalid_flag = await tools.dispatch(
            "benchmark_submit_flag",
            {"unique_code": CHALLENGE_CODE, "flag": "x" * 4097},
        )

    for result in (unknown, invalid_name, missing, extra, non_object, invalid_flag):
        assert result["ok"] is False
        assert result["error"]["type"] == "validation"
    assert unknown["error"]["code"] == "unknown_tool"
    assert invalid_name["error"]["code"] == "invalid_tool_name"
    assert request_count == 0


@pytest.mark.asyncio
async def test_api_error_is_normalized_with_full_local_detail() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "code": "task_not_found",
                "message": f"invalid token: {TOKEN}",
                "detail": {"echo": TOKEN},
            },
        )

    tools = make_tools(handler)
    async with tools:
        result = await tools.dispatch("benchmark_list_challenges", {})

    assert result["ok"] is False
    assert result["error"]["type"] == "api"
    assert result["error"]["code"] == "task_not_found"
    assert result["error"]["status_code"] == 404
    assert TOKEN in json.dumps(result)


@pytest.mark.asyncio
async def test_transport_error_is_normalized_without_retry() -> None:
    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        raise httpx.ConnectError(f"failed with {TOKEN}", request=request)

    tools = make_tools(handler)
    async with tools:
        result = await tools.dispatch("benchmark_list_challenges", {})

    assert result == {
        "ok": False,
        "error": {
            "type": "transport",
            "code": "transport_error",
            "message": "Unable to reach the benchmark service",
            "status_code": None,
            "detail": {},
        },
    }
    assert TOKEN not in json.dumps(result)
    assert request_count == 1


@pytest.mark.asyncio
async def test_invalid_response_is_normalized() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a list"})

    tools = make_tools(handler)
    async with tools:
        result = await tools.list_challenges()

    assert result["ok"] is False
    assert result["error"]["type"] == "internal"
    assert result["error"]["code"] == "invalid_response"


@pytest.mark.asyncio
async def test_wrapper_context_closes_owned_sdk_client() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client = ChallengesClient(
        BASE_URL,
        TOKEN,
        transport=httpx.MockTransport(handler),
    )
    tools = BenchmarkTools(client)
    async with tools:
        await tools.list_challenges()

    assert client._client.is_closed is True
