from __future__ import annotations

import json
from pathlib import Path

from agent.tooling import ToolRegistry
from tools.artifact import ArtifactTools


def _call(provider: ArtifactTools, name: str, arguments: dict) -> dict:
    registry = ToolRegistry([provider])
    spec = registry.get(name)
    assert spec is not None
    return spec.handler(spec.input_model.model_validate(arguments))


def test_artifact_tools_identify_decode_and_review_hex(tmp_path: Path) -> None:
    bytecode = tmp_path / "sample.hex"
    bytecode.write_text("0x600160005560016000f1ff", encoding="ascii")
    provider = ArtifactTools(tmp_path)

    identified = _call(provider, "artifact_identify", {"file_path": "sample.hex"})
    assert identified["data"]["format"] == "evm_hex"
    assert identified["data"]["byte_length"] == 11

    decoded = _call(provider, "artifact_disassemble", {"file_path": "sample.hex"})
    names = [item["name"] for item in decoded["data"]["instructions"]]
    assert names[:3] == ["PUSH1", "PUSH1", "SSTORE"]
    assert "CALL" in names

    review = _call(provider, "artifact_static_review", {"file_path": "sample.hex"})
    codes = {item["code"] for item in review["data"]["findings"]}
    assert {"call_present", "storage_write_present", "selfdestruct_present"} <= codes
    assert review["_aion_evidence"]["metadata"]["offline"] is True


def test_artifact_tools_summarize_abi_and_reject_extra_fields(tmp_path: Path) -> None:
    abi = tmp_path / "abi.json"
    abi.write_text(
        json.dumps(
            [
                {
                    "type": "function",
                    "name": "balanceOf",
                    "stateMutability": "view",
                    "inputs": [{"name": "owner", "type": "address"}],
                    "outputs": [{"name": "value", "type": "uint256"}],
                },
                {"type": "event", "name": "Transfer", "inputs": []},
            ]
        ),
        encoding="utf-8",
    )
    provider = ArtifactTools(tmp_path)
    result = _call(provider, "artifact_abi_summary", {"file_path": "abi.json"})
    assert result["data"]["count"] == 2
    assert result["data"]["items"][0]["name"] == "balanceOf"

    spec = ToolRegistry([provider]).get("artifact_identify")
    assert spec is not None
    try:
        spec.input_model.model_validate({"file_path": "abi.json", "extra": True})
    except Exception:
        pass
    else:
        raise AssertionError("artifact arguments must reject unknown fields")
