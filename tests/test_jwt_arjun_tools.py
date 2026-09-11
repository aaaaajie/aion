from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlsplit

import pytest

from tools.pentest import PentestTools
from tools.pentest import arjun_adapter
from tools.pentest.jwt_adapter import encode
from tools.pentest.models import ArjunArguments, JwtArguments


def test_jwt_operations_are_structured_and_local() -> None:
    provider = PentestTools()
    spec = next(item for item in provider.tool_specs() if item.name == "pentest_jwt")
    token = encode({"sub": "agent", "role": "user"}, key="owned-test-key")

    async def run() -> list[dict]:
        results = []
        for value in (
            {"operation": "decode", "token": token},
            {"operation": "verify", "token": token, "key": "owned-test-key"},
            {"operation": "crack", "token": token, "dictionary": ["bad", "owned-test-key"]},
            {"operation": "tamper", "token": token, "key": "owned-test-key", "claim_updates": {"role": "admin"}},
        ):
            results.append(await spec.handler(spec.input_model.model_validate(value)))
        return results

    decoded, verified, cracked, tampered = asyncio.run(run())
    assert decoded["data"]["claims"]["sub"] == "agent"
    assert verified["data"]["valid"] is True
    assert cracked["data"]["matched"] is True
    assert tampered["data"]["claims"]["role"] == "admin"
    assert all(item["_aion_evidence"]["evidence_type"] == "token" for item in (decoded, verified, cracked, tampered))


def test_jwt_and_arjun_inputs_reject_unbounded_or_incomplete_requests() -> None:
    with pytest.raises(Exception):
        JwtArguments.model_validate({"operation": "validate", "token": "a.b.c"})
    with pytest.raises(Exception):
        ArjunArguments.model_validate({"url": "http://target", "wordlist": ["id", "id"]})
    with pytest.raises(Exception):
        ArjunArguments.model_validate({"url": "http://target", "concurrency": 9})


def test_arjun_get_mode_returns_differential_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __init__(self, body: bytes) -> None:
            self.status_code = 200
            self.content = body
            self.text = body.decode()

    class Client:
        async def __aenter__(self) -> "Client":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def request(self, method: str, url: str, **_: object) -> Response:
            query = parse_qs(urlsplit(url).query)
            return Response(b"found" if "id" in query else b"base")

    monkeypatch.setattr(arjun_adapter.httpx, "AsyncClient", lambda **_: Client())
    provider = PentestTools()
    spec = next(item for item in provider.tool_specs() if item.name == "pentest_arjun")
    result = asyncio.run(
        spec.handler(
            spec.input_model.model_validate(
                {"url": "http://owned.test/search", "wordlist": ["id", "q"]}
            )
        )
    )
    assert result["ok"] is True
    assert result["data"]["finding_count"] == 1
    assert result["data"]["findings"][0]["parameter"] == "id"
    assert result["_aion_evidence"]["content"]["tested"] == 2


def test_arjun_json_mode_preserves_existing_body(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[str] = []

    class Response:
        status_code = 200
        content = b"ok"
        text = "ok"

    class Client:
        async def __aenter__(self) -> "Client":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def request(self, method: str, url: str, **kwargs: object) -> Response:
            if kwargs.get("content") is not None:
                captured.append(str(kwargs["content"]))
            return Response()

    monkeypatch.setattr(arjun_adapter.httpx, "AsyncClient", lambda **_: Client())
    provider = PentestTools()
    spec = next(item for item in provider.tool_specs() if item.name == "pentest_arjun")
    asyncio.run(
        spec.handler(
            spec.input_model.model_validate(
                {"url": "http://owned.test/api", "mode": "JSON", "body": '{"page":1}', "wordlist": ["id"]}
            )
        )
    )
    assert any('"page":1' in value for value in captured)
    assert any('"id":"aion-probe"' in value for value in captured)
