"""Real filesystem and OS Shell boundaries across runs and challenges."""

import shlex

from tests.test_system_tools import _ToolHarness, _SystemToolClient
from tests.resource_runtime import another_resource_agent
from tools.system import SystemTools


async def test_shell_and_files_cannot_read_foreign_run_or_question(tmp_path):
    harness = _ToolHarness(tmp_path)
    async with harness as client:
        shell = client.provider._shell
        await shell.ensure_workspace()
        own = shell.agent_work_root
        shared = shell.shared_work_root
        foreign = [
            tmp_path / "a06_evidence/app.py",
            tmp_path / ".aion/runs/old/shared/a/answer.txt",
            harness.manager.shared_workspace_root("another-question") / "answer.txt",
            harness.manager.agent_work_root("another-agent") / "answer.txt",
        ]
        for path in foreign:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("FOREIGN_EVIDENCE_MARKER")
        (own / "escape").symlink_to(foreign[0])
        for path in [*foreign, own / "escape"]:
            result = await client.read_file(str(path))
            assert result["ok"] is False
            if path.parent != own:
                assert not (await client.list_directory(str(path.parent)))["ok"]
            result = await client.shell(
                f"if cat {shlex.quote(str(path))}; then printf LEAK; else printf DENIED; fi"
            )
            assert result["data"]["status"] == "completed", result
            assert "FOREIGN_EVIDENCE_MARKER" not in result["data"]["output"]
            assert "DENIED" in result["data"]["output"]
        assert (await client.write_file("mine.txt", "OWN"))["ok"]
        assert (await client.read_file("mine.txt"))["data"]["content"] == "OWN"
        assert (await client.write_file("shared/result.txt", "SHARED"))["ok"]
        other = await another_resource_agent(harness.service, harness.run_id)
        other_shell = harness.manager.bind(other["agent_id"], shared_root=shared)
        await other_shell.ensure_workspace()
        sibling = _SystemToolClient(
            SystemTools(
                root=tmp_path,
                shell=other_shell,
                agent_work_root=other_shell.agent_work_root,
                shared_work_root=shared,
            )
        )
        assert (await sibling.read_file("shared/result.txt"))["data"][
            "content"
        ] == "SHARED"
        assert not (await sibling.read_file(str(own / "mine.txt")))["ok"]
        result = await sibling.shell("cat result.txt", cwd="shared")
        assert result["data"]["output"] == "SHARED"


async def test_http_file_inputs_use_bound_agent_workspace(tmp_path):
    import httpx
    from tests.test_http_tools import _manager, _tool_call
    from tools.http.wrapper import HttpTools
    from agent.tooling import ToolExecutor, ToolRegistry

    requests = []

    async def respond(request):
        requests.append(request)
        return httpx.Response(200, text="ok")

    service, manager, agent_id = await _manager(tmp_path, respond)
    own = tmp_path / "own"
    own.mkdir()
    (own / "local.txt").write_text("LOCAL")
    foreign = tmp_path / "foreign.txt"
    foreign.write_text("FOREIGN")
    (own / "escape").symlink_to(foreign)
    client = manager.bind(agent_id, workspace_root=own)
    executor = ToolExecutor(ToolRegistry([HttpTools(client)]))
    try:
        for source in (str(foreign), "../foreign.txt", "escape"):
            result = await executor.execute(
                [
                    _tool_call(
                        "system_http_request",
                        {
                            "url": "https://target.test",
                            "method": "POST",
                            "body": {
                                "type": "multipart",
                                "value": {"upload": {"file_path": source}},
                            },
                        },
                        "foreign",
                    )
                ]
            )
            assert not result[0].result["ok"]
        assert not requests
        result = await executor.execute(
            [
                _tool_call(
                    "system_http_request",
                    {
                        "url": "https://target.test",
                        "method": "POST",
                        "body": {
                            "type": "multipart",
                            "value": {"upload": {"file_path": "local.txt"}},
                        },
                    },
                    "own",
                )
            ]
        )
        assert result[0].result["ok"], result[0].result
        assert len(requests) == 1
    finally:
        await manager.finish_run()
        await service.close()


async def test_debug_script_uses_owned_shell_boundary(tmp_path):
    from types import SimpleNamespace
    from tools.binary import BinaryTools
    from agent.tooling import ToolExecutor, ToolRegistry
    from tests.test_http_tools import _tool_call

    async with _ToolHarness(tmp_path) as client:
        shell = client.provider._shell
        await shell.ensure_workspace()
        debugger = shell.agent_work_root / "fixture-debugger"
        debugger.write_text('#!/bin/sh\neval "$4"\n')
        debugger.chmod(0o700)
        foreign = tmp_path / "foreign.txt"
        foreign.write_text("FOREIGN_EVIDENCE_MARKER")
        provider = BinaryTools(shell.agent_work_root, shell=shell)
        provider._toolchain = SimpleNamespace(command=lambda name: str(debugger))
        result = (
            await ToolExecutor(ToolRegistry([provider])).execute(
                [
                    _tool_call(
                        "bin_debug",
                        {
                            "script": f"if cat {shlex.quote(str(foreign))}; then echo LEAK; else echo DENIED; fi"
                        },
                        "debug",
                    )
                ]
            )
        )[0].result
        assert result["ok"], result
        assert "DENIED" in result["data"]["output"]
        assert "FOREIGN_EVIDENCE_MARKER" not in result["data"]["output"]
        assert result["data"]["cleanup"]["resources_released"]
