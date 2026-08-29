from __future__ import annotations

import json

import pytest

from agent.config import AgentSettings
from agent.memory.blackboard import BlackboardCompactionError, BlackboardCompactor


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class _Client:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.requests: list[dict[str, object]] = []

    async def post(self, _url: str, **kwargs: object) -> _Response:
        self.requests.append(kwargs)
        return _Response(self.payload)


def _settings() -> AgentSettings:
    return AgentSettings(
        llm_base_url="http://llm.test",
        llm_model="test-model",
        llm_api_key="test-key",
    )


@pytest.mark.asyncio
async def test_blackboard_compactor_preserves_protected_reports_and_redacts_input() -> None:
    client = _Client(
        {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "items": [
                                    {
                                        "report_ref": "report:ordinary",
                                        "summary": "short summary",
                                        "next_step": "short next step",
                                    }
                                ]
                            }
                        )
                    }
                }
            ]
        }
    )
    payload = {
        "reports": [
            {
                "report_ref": "report:ordinary",
                "type": "execution",
                "summary": "x" * 900,
                "next_step": "y" * 900,
            },
            {
                "report_ref": "report:candidate",
                "type": "execution",
                "candidate_flag": "secret-candidate",
                "summary": "protected candidate",
            },
            {
                "report_ref": "report:checkpoint",
                "type": "execution_checkpoint",
                "summary": "protected checkpoint",
            },
        ]
    }
    compacted = await BlackboardCompactor(_settings(), client=client).compact(payload)
    assert compacted["reports"][0]["summary"] == "short summary"
    assert compacted["reports"][1]["candidate_flag"] == "secret-candidate"
    assert compacted["reports"][2]["type"] == "execution_checkpoint"
    request_text = json.dumps(client.requests[0], ensure_ascii=False)
    assert "secret-candidate" not in request_text
    assert "protected checkpoint" not in request_text


@pytest.mark.asyncio
async def test_blackboard_compactor_rejects_unknown_report_reference() -> None:
    client = _Client(
        {
            "choices": [
                {
                    "message": {
                        "content": '{"items":[{"report_ref":"report:unknown","summary":"x"}]}'
                    }
                }
            ]
        }
    )
    with pytest.raises(BlackboardCompactionError):
        await BlackboardCompactor(_settings(), client=client).compact(
            {"reports": [{"report_ref": "report:ordinary", "summary": "x"}]}
        )
