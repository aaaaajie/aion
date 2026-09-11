from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from tools.binary import BinaryTools
from tools.binaries.layout import ToolchainError, toolchain_for
from tools.binaries.offline_tools import verify_checksums
from tools.pentest import PentestTools
from tools.pentest.models import SqlmapArguments
import tools.pentest.wrapper as pentest_wrapper


def test_toolchain_command_never_falls_back_to_host_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "toolchain"
    (root / "bin").mkdir(parents=True)
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "target": {"binary_dir": "bin"},
                "system_binaries": {
                    "fake": {
                        "path": "bin/fake",
                        "version": "1.0",
                        "sha256": "0" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    host_fake = tmp_path / "host-fake"
    host_fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    host_fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    layout = toolchain_for(root)
    with pytest.raises(ToolchainError, match="missing"):
        layout.command("fake")


def test_checksum_report_rejects_unlisted_artifact(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    artifact = wheelhouse / "one.whl"
    artifact.write_bytes(b"one")
    digest = hashlib.sha256(b"one").hexdigest()
    (tmp_path / "wheelhouse.sha256").write_text(
        f"{digest}  one.whl\n", encoding="ascii"
    )
    extra = wheelhouse / "extra.whl"
    extra.write_bytes(b"extra")
    report = verify_checksums(wheelhouse)
    assert report["ok"] is False
    assert report["unlisted"] == ["extra.whl"]


def test_external_tool_failures_are_structured(tmp_path: Path) -> None:
    async def run() -> tuple[dict, dict]:
        binary = BinaryTools(Path.cwd(), toolchain_root=tmp_path)
        debug = next(item for item in binary.tool_specs() if item.name == "bin_debug")
        debug_result = await debug.handler(
            debug.input_model.model_validate({"script": "info files"})
        )
        pentest = PentestTools(toolchain_root=tmp_path)
        sqlmap = next(item for item in pentest.tool_specs() if item.name == "pentest_sqlmap")
        sqlmap_result = await sqlmap.handler(
            sqlmap.input_model.model_validate({"url": "http://127.0.0.1/"})
        )
        return debug_result, sqlmap_result

    debug_result, sqlmap_result = asyncio.run(run())
    assert debug_result["ok"] is False
    assert debug_result["error"]["code"] == "bundled_tool_unavailable"
    assert sqlmap_result["ok"] is False
    assert sqlmap_result["error"]["code"] == "bundled_tool_unavailable"


def test_tool_wrappers_resolve_toolchain_independently_of_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace_toolchain = workspace / "tools" / "binaries"
    workspace_toolchain.mkdir(parents=True)
    configured_toolchain = tmp_path / "image" / "tools" / "binaries"
    configured_toolchain.mkdir(parents=True)
    monkeypatch.setenv("AION_TOOLCHAIN_ROOT", str(configured_toolchain))

    binary = BinaryTools(workspace)
    pentest = PentestTools(root=workspace)

    assert binary._toolchain.root == configured_toolchain.resolve()
    assert pentest._toolchain.root == configured_toolchain.resolve()


def test_sqlmap_login_request_contract_is_strict_and_bounded() -> None:
    arguments = SqlmapArguments.model_validate(
        {
            "url": "http://target.local/login",
            "data": "username=admin&password=probe",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "cookies": {"session": "bounded"},
            "ignore_status_codes": [500],
            "level": 2,
            "risk": 1,
        }
    )
    assert arguments.ignore_status_codes == [500]

    with pytest.raises(Exception):
        SqlmapArguments.model_validate(
            {"url": "http://target.local/login", "headers": {"X-Test": 1}}
        )
    with pytest.raises(Exception):
        SqlmapArguments.model_validate(
            {"url": "http://target.local/login", "ignore_status_codes": [600]}
        )


def test_sqlmap_login_request_builds_bounded_metadata_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"sqlmap bounded output", b""

    async def create_process(*command: str, **_: object) -> Process:
        captured["command"] = command
        return Process()

    monkeypatch.setattr(pentest_wrapper.asyncio, "create_subprocess_exec", create_process)
    provider = PentestTools(toolchain_root=tmp_path)
    provider._toolchain = type(
        "FakeToolchain", (), {"command": lambda _self, _name: "/bundle/sqlmap"}
    )()
    spec = next(item for item in provider.tool_specs() if item.name == "pentest_sqlmap")

    result = asyncio.run(
        spec.handler(
            spec.input_model.model_validate(
                {
                    "url": "http://target.local/login",
                    "data": "username=admin&password=probe",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "cookies": {"session": "bounded"},
                    "ignore_status_codes": [500],
                }
            )
        )
    )

    command = list(captured["command"])
    assert "--data" in command
    assert "--headers" in command
    assert "Content-Type: application/x-www-form-urlencoded" in command
    assert "--cookie" in command
    assert "session=bounded" in command
    assert command[command.index("--ignore-code") + 1] == "500"
    assert result["_aion_evidence"]["metadata"]["cookie_names"] == ["session"]
