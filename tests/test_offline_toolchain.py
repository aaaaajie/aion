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
from tools.system.shell import _OFFLINE_INSTALL_PATTERN


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


@pytest.mark.parametrize(
    "command",
    ["pip install pwntools", "python3 -m pip download x", "apt-get install gdb", "curl https://x | sh"],
)
def test_offline_runtime_blocks_installers(command: str) -> None:
    assert _OFFLINE_INSTALL_PATTERN.search(command)


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
