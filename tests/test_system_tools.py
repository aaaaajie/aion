"""Contract and security tests for the workspace system tools."""

from __future__ import annotations

import asyncio
import json
import os
import pwd
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from agent.state import StateService
from agent.state.clock import utc_now
from agent.tooling import ToolExecutor, ToolRegistry
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import SystemToolError
from tools.system.policy import WorkspacePolicy
from tools.system.shell import SandboxBackend


class _MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


class _SystemToolClient:
    """Test adapter that sends every convenience call through ToolExecutor."""

    def __init__(self, provider: SystemTools) -> None:
        self.provider = provider

    def __getattr__(self, name: str):
        return getattr(self.provider, name)

    async def _call(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        calls = await ToolExecutor(ToolRegistry([self.provider])).execute(
            [{"id": name, "function": {"name": name, "arguments": json.dumps(arguments)}}]
        )
        assert calls[0].result is not None
        return calls[0].result

    async def read_file(self, file_path: str, **kwargs: object):
        return await self._call("system_read_file", {"file_path": file_path, **kwargs})

    async def write_file(self, file_path: str, content: str):
        return await self._call("system_write_file", {"file_path": file_path, "content": content})

    async def edit_file(self, file_path: str, old_text: str, new_text: str, **kwargs: object):
        return await self._call("system_edit_file", {"file_path": file_path, "old_string": old_text, "new_string": new_text, **kwargs})

    async def create_directory(self, path: str, **kwargs: object):
        return await self._call("system_create_directory", {"path": path, **kwargs})

    async def delete_path(self, path: str, **kwargs: object):
        return await self._call("system_delete_path", {"path": path, **kwargs})

    async def list_directory(self, path: str = ".", **kwargs: object):
        return await self._call("system_list_directory", {"path": path, **kwargs})

    async def glob(self, pattern: str, path: str = "."):
        return await self._call("system_glob", {"pattern": pattern, "path": path})

    async def grep(self, pattern: str, path: str = ".", **kwargs: object):
        return await self._call("system_grep", {"pattern": pattern, "path": path, **kwargs})

    async def shell(self, command: str, **kwargs: object):
        return await self._call("system_shell", {"command": command, **kwargs})

    async def task_output(self, task_id: str, **kwargs: object):
        return await self._call("system_task_output", {"task_id": task_id, **kwargs})

    async def task_stop(self, task_id: str):
        return await self._call("system_task_stop", {"task_id": task_id})

    async def task_cleanup(self, task_id: str):
        return await self._call("system_task_cleanup", {"task_id": task_id})

    async def close(self) -> None:
        await self.provider.close()


class _ToolHarness:
    def __init__(
        self,
        root: Path,
        *,
        sandbox_executable: str | None = None,
        clock: Callable[[], datetime] = utc_now,
        reap_interval_seconds: float = 60.0,
        read_only_paths: Sequence[Path] = (),
        environment: Mapping[str, str] | None = None,
        isolated_workspace: bool = False,
    ) -> None:
        self.root = root
        self.sandbox_executable = sandbox_executable
        self.clock = clock
        self.reap_interval_seconds = reap_interval_seconds
        self.read_only_paths = tuple(read_only_paths)
        self.environment = dict(environment or {})
        self.isolated_workspace = isolated_workspace
        self.run_id = f"tools-{uuid4().hex}"
        self.agent_id: str | None = None
        self.service: StateService | None = None
        self.manager: ShellTaskManager | None = None

    async def __aenter__(self) -> _SystemToolClient:
        run_root = self.root / "runs"
        self.service = StateService(
            run_root / self.run_id / "state.sqlite3",
            run_root=run_root,
            clock=self.clock,
        )
        await self.service.create_run(self.run_id)
        agent = await self.service.register_agent(
            self.run_id,
            role="chief",
            initial_prompt="system tools test",
        )
        self.agent_id = agent["agent_id"]
        policy = WorkspacePolicy(self.root)
        self.manager = ShellTaskManager(
            policy,
            self.service,
            self.run_id,
            sandbox=SandboxBackend(
                policy.root,
                self.sandbox_executable,
                read_only_paths=self.read_only_paths,
            ),
            clock=self.clock,
            reap_interval_seconds=self.reap_interval_seconds,
            environment=self.environment,
        )
        await self.manager.initialize()
        shared_root = (
            self.manager.shared_workspace_root("challenge")
            if self.isolated_workspace
            else None
        )
        shell = self.manager.bind(self.agent_id, shared_root=shared_root)
        return _SystemToolClient(
            SystemTools(
                root=self.root,
                shell=shell,
                agent_work_root=shell.agent_work_root if self.isolated_workspace else None,
                shared_work_root=shell.shared_work_root if self.isolated_workspace else None,
            )
        )

    async def __aexit__(self, *_args: object) -> None:
        assert self.manager is not None
        assert self.service is not None
        await self.manager.finish_run()
        await self.service.close()


@pytest.fixture
def make_tools(tmp_path: Path):
    def factory(**kwargs: object) -> _ToolHarness:
        return _ToolHarness(tmp_path, **kwargs)

    return factory


@pytest.mark.asyncio
async def test_read_write_and_edit_protect_against_stale_files(make_tools) -> None:
    async with make_tools() as tools:
        target = tools._filesystem.policy.root / "notes.txt"
        target.write_text("alpha\nbeta\nbeta\n", encoding="utf-8")
        read_result = await tools.read_file("notes.txt")
        assert read_result["ok"] is True
        assert read_result["data"]["content"] == "alpha\nbeta\nbeta\n"
        page = await tools.read_file("notes.txt", offset=6, limit_chars=4)
        assert page["ok"] is True
        assert page["data"]["content"] == "beta"

        multiple = await tools.edit_file("notes.txt", "beta", "gamma")
        assert multiple["error"]["code"] == "multiple_matches"

        edited = await tools.edit_file("notes.txt", "beta", "gamma", replace_all=True)
        assert edited == {
            "ok": True,
            "data": {
                "type": "update",
                "file_path": "notes.txt",
                "replaced_count": 2,
                "bytes_written": len("alpha\ngamma\ngamma\n".encode()),
            },
        }

        await tools.read_file("notes.txt")
        target.write_text("changed outside the tool", encoding="utf-8")
        stale = await tools.write_file("notes.txt", "should not overwrite")
        assert stale["error"]["code"] == "file_modified_since_read"

        created = await tools.write_file("nested/new.txt", "new content")
        assert created["ok"] is True
        assert (tools._filesystem.policy.root / "nested/new.txt").read_text() == "new content"


@pytest.mark.asyncio
async def test_write_auto_creates_parents_then_list_glob_and_grep(make_tools) -> None:
    async with make_tools() as tools:
        await tools.write_file("src/pkg/a.py", "needle = 1\n")
        await tools.write_file("src/pkg/b.txt", "nothing\n")

        listed = await tools.list_directory("src", recursive=True)
        listed_paths = {entry["path"] for entry in listed["data"]["entries"]}
        assert {"src/pkg", "src/pkg/a.py", "src/pkg/b.txt"} <= listed_paths

        globbed = await tools.glob("**/*.py", "src")
        assert globbed["data"]["matches"] == ["src/pkg/a.py"]

        searched = await tools.grep("needle", "src", glob="**/*.py")
        assert searched["data"]["matches"] == [
            {
                "file_path": "src/pkg/a.py",
                "line_number": 1,
                "line": "needle = 1",
                "match": "needle",
            }
        ]
        assert (tools._filesystem.policy.root / "src/pkg").is_dir()


@pytest.mark.asyncio
async def test_isolated_paths_route_agent_and_shared_outputs(make_tools) -> None:
    async with make_tools(isolated_workspace=True) as tools:
        relative = await tools.write_file("artifact.txt", "agent-only")
        assert relative["ok"] is True
        agent_work = tools.provider._agent_work_root
        shared_work = tools.provider._shared_work_root
        assert agent_work is not None
        assert shared_work is not None
        assert (agent_work / "artifact.txt").read_text(encoding="utf-8") == "agent-only"
        assert not (tools._filesystem.policy.root / "artifact.txt").exists()
        assert relative["data"]["file_path"] == "agent/artifact.txt"

        shared = await tools.write_file("shared/result.txt", "sibling-readable")
        assert shared["ok"] is True
        assert (shared_work / "result.txt").read_text(encoding="utf-8") == "sibling-readable"
        read_shared = await tools.read_file("shared/result.txt")
        assert read_shared["data"]["content"] == "sibling-readable"

        project_file = tools._filesystem.policy.root / "project-result.txt"
        project_file.write_text("read-only target", encoding="utf-8")
        assert (await tools.read_file("project/project-result.txt"))["data"]["content"] == "read-only target"
        for path in (
            "project/result.txt",
            "../outside.txt",
            str(tools._filesystem.policy.root / "absolute-result.txt"),
        ):
            rejected = await tools.write_file(path, "must-not-write")
            assert rejected["error"]["code"] in {
                "project_write_protected",
                "workspace_write_rejected",
            }
        assert not (tools._filesystem.policy.root / "absolute-result.txt").exists()
        assert tools.provider._shell.manager is not None
        assert tools.provider._shell.manager.service is not None
        events = await tools.provider._shell.manager.service.list_agent_events(
            tools.provider._shell.manager.run_id,
            tools.provider._shell.agent_id,
        )
        event_types = {event["event_type"] for event in events}
        assert {
            "agent_workspace_created",
            "workspace_write_redirected",
            "workspace_write_rejected",
        } <= event_types


@pytest.mark.asyncio
async def test_agent_work_is_cleaned_but_challenge_shared_work_remains(make_tools) -> None:
    harness = make_tools(isolated_workspace=True, reap_interval_seconds=0)
    async with harness as tools:
        assert harness.manager is not None
        assert harness.agent_id is not None
        await tools.write_file("private.txt", "private")
        await tools.write_file("shared/persisted.txt", "shared")
        agent_work = harness.manager.agent_work_root(harness.agent_id)
        shared_work = harness.manager.shared_workspace_root("challenge")
        await harness.manager.finish_agent(harness.agent_id)
        assert not agent_work.exists()
        assert (shared_work / "persisted.txt").read_text(encoding="utf-8") == "shared"


@pytest.mark.asyncio
async def test_file_evidence_snapshot_is_exact_and_never_leaks_to_model(
    make_tools,
) -> None:
    async with make_tools() as tools:
        calls = await ToolExecutor(ToolRegistry([tools.provider])).execute(
            [
                {
                    "id": "write-evidence",
                    "function": {
                        "name": "system_write_file",
                        "arguments": json.dumps(
                            {"file_path": "proof.txt", "content": "exact\nproof\n"}
                        ),
                    },
                }
            ]
        )
        call = calls[0]
        assert call.result is not None
        assert "_aion_evidence" not in json.dumps(call.result)
        assert call.evidence_payload == {
            "evidence_type": "file",
            "content": "exact\nproof\n",
            "metadata": {"file_path": "proof.txt"},
        }


@pytest.mark.asyncio
async def test_path_traversal_symlink_escape_and_root_delete_are_rejected(make_tools, tmp_path: Path) -> None:
    async with make_tools() as tools:
        outside = tmp_path.parent / "system-tools-outside.txt"
        outside.write_text("outside", encoding="utf-8")
        os.symlink(outside, tools._filesystem.policy.root / "escape.txt")
        traversal = await tools.read_file("../system-tools-outside.txt")
        assert traversal["error"]["code"] == "path_outside_workspace"

        symlink = await tools.read_file("escape.txt")
        assert symlink["error"]["code"] == "path_outside_workspace"

        root_delete = await tools.delete_path(".", recursive=True)
        assert root_delete["error"]["code"] == "unknown_tool"


@pytest.mark.asyncio
async def test_runtime_control_plane_paths_are_hidden_from_filesystem_tools(make_tools) -> None:
    async with make_tools() as tools:
        root = tools._filesystem.policy.root
        (root / ".aion" / "runs").mkdir(parents=True)
        (root / ".aion" / "runs" / "old-flag.txt").write_text(
            "control-plane-secret", encoding="utf-8"
        )
        (root / ".system-tools" / "runs").mkdir(parents=True, exist_ok=True)
        (root / ".system-tools" / "runs" / "old-output.log").write_text(
            "control-plane-output", encoding="utf-8"
        )

        for path in (".aion", ".aion/runs/old-flag.txt", ".system-tools"):
            rejected = await tools.read_file(path)
            assert rejected["error"]["code"] == "project_path_protected"

        listed = await tools.list_directory(".", recursive=True)
        listed_paths = {entry["path"] for entry in listed["data"]["entries"]}
        assert not any(
            path == ".aion"
            or path.startswith(".aion/")
            or path == ".system-tools"
            or path.startswith(".system-tools/")
            for path in listed_paths
        )

        globbed = await tools.glob("**/*", ".")
        assert not any(
            path == ".aion"
            or path.startswith(".aion/")
            or path == ".system-tools"
            or path.startswith(".system-tools/")
            for path in globbed["data"]["matches"]
        )

        searched = await tools.grep("control-plane", ".")
        assert searched["data"]["matches"] == []


@pytest.mark.asyncio
async def test_shell_runs_in_sandbox_and_enforces_output_and_timeout(make_tools) -> None:
    async with make_tools() as tools:
        command = await tools.shell("printf sandbox-ok; pwd")
        assert command["ok"] is True
        assert command["data"]["output"].startswith("sandbox-ok")
        assert command["data"]["status"] == "completed"
        assert command["data"]["cwd"] == "."

        workspace_write = await tools.shell("printf shell-write > shell-created.txt")
        assert workspace_write["data"]["exit_code"] == 0
        agent_work = tools.provider._shell.agent_work_root
        assert agent_work is not None
        assert (agent_work / "shell-created.txt").read_text(encoding="utf-8") == "shell-write"
        assert not (tools._filesystem.policy.root / "shell-created.txt").exists()

        environment = await tools.shell("printf '%s' \"${BENCHMARK_TOKEN-unavailable}\"")
        assert environment["data"]["output"] == "unavailable"

        outside = await tools.shell(
            "test -r /Users/mr.li/project/secai/claude-code-analysis/README.md; printf outside=%s $?"
        )
        assert "outside=1" in outside["data"]["output"]

        truncated = await tools.shell("printf 1234567890abcdef", max_output_chars=5)
        assert truncated["data"]["output"] == "12345"
        assert truncated["data"]["truncated"] is True

        timed_out = await tools.shell("sleep 2", timeout=0.1)
        assert timed_out["data"]["status"] == "timeout"
        assert timed_out["data"]["timed_out"] is True

        failed = await tools.shell("printf command-failed; exit 7")
        assert failed["ok"] is True
        assert failed["data"]["status"] == "failed"
        assert failed["data"]["exit_code"] == 7
        assert failed["data"]["output"] == "command-failed"


@pytest.mark.asyncio
async def test_shell_runs_read_only_python_and_shell_skill_scripts(make_tools, tmp_path: Path) -> None:
    skill_root = tmp_path / "skills"
    scripts = skill_root / "execution" / "fixture" / "scripts"
    scripts.mkdir(parents=True)
    python_script = scripts / "check.py"
    shell_script = scripts / "check.sh"
    background_script = scripts / "background.sh"
    python_script.write_text("print('python-skill')\n", encoding="utf-8")
    shell_script.write_text("printf shell-skill\n", encoding="utf-8")
    background_script.write_text(
        "printf start; sleep 0.05; printf end\n", encoding="utf-8"
    )
    runtime_prefix = Path(sys.prefix).resolve()
    runtime_python = runtime_prefix / "bin" / Path(sys.executable).name
    if not runtime_python.is_file():
        runtime_python = Path(sys.executable).resolve()

    async with make_tools(
        read_only_paths=(skill_root, runtime_prefix),
        environment={
            "AION_SKILLS_ROOT": str(skill_root),
            "AION_PYTHON": str(runtime_python),
        },
    ) as tools:
        executed = await tools.shell(
            '"$AION_PYTHON" "$AION_SKILLS_ROOT/execution/fixture/scripts/check.py"; '
            'bash "$AION_SKILLS_ROOT/execution/fixture/scripts/check.sh"'
        )
        assert executed["data"]["status"] == "completed"
        assert executed["data"]["output"] == "python-skill\nshell-skill"

        write = await tools.shell(
            'printf changed > "$AION_SKILLS_ROOT/execution/fixture/scripts/check.py"'
        )
        assert write["data"]["status"] == "failed"
        assert python_script.read_text(encoding="utf-8") == "print('python-skill')\n"

        background = await tools.shell(
            'bash "$AION_SKILLS_ROOT/execution/fixture/scripts/background.sh"',
            run_in_background=True,
        )
        output = await tools.task_output(
            background["data"]["task_id"], wait_seconds=1.0
        )
        assert output["data"]["status"] == "completed"
        assert output["data"]["output"] == "startend"


@pytest.mark.asyncio
async def test_background_tasks_can_be_read_and_stopped(make_tools) -> None:
    async with make_tools() as tools:
        background = await tools.shell(
            "printf start; sleep 0.1; printf end",
            run_in_background=True,
        )
        task_id = background["data"]["task_id"]
        output = await tools.task_output(task_id, wait_seconds=1.0)
        assert output["data"]["status"] == "completed"
        assert "start" in output["data"]["output"]
        assert "end" in output["data"]["output"]
        repeated = await tools.task_output(task_id)
        assert repeated == output

        long_task = await tools.shell("sleep 10", run_in_background=True)
        active_cleanup = await tools.task_cleanup(long_task["data"]["task_id"])
        assert active_cleanup["error"]["code"] == "unknown_tool"
        stopped = await tools.task_stop(long_task["data"]["task_id"])
        assert stopped["data"]["status"] == "stopped"

        missing = await tools.task_output("task-does-not-exist")
        assert missing["error"]["code"] == "task_not_found"


@pytest.mark.asyncio
async def test_shell_client_close_keeps_task_for_same_agent(make_tools) -> None:
    harness = make_tools()
    async with harness as tools:
        background = await tools.shell(
            "printf before; sleep 0.1; printf after",
            run_in_background=True,
        )
        task_id = background["data"]["task_id"]
        await tools.close()

        assert harness.manager is not None
        assert harness.agent_id is not None
        rebound = _SystemToolClient(
            SystemTools(
                root=harness.root,
                shell=harness.manager.bind(harness.agent_id),
            )
        )
        output = await rebound.task_output(task_id, wait_seconds=1)
        assert output["data"]["status"] == "completed"
        assert output["data"]["output"] == "beforeafter"


@pytest.mark.asyncio
async def test_agent_ownership_and_persistent_temp_are_isolated(make_tools) -> None:
    harness = make_tools()
    async with harness as first:
        assert harness.service is not None
        assert harness.manager is not None
        second_agent = await harness.service.register_agent(
            harness.run_id,
            role="chief",
            initial_prompt="second owner",
        )
        second = _SystemToolClient(
            SystemTools(
                root=harness.root,
                shell=harness.manager.bind(second_agent["agent_id"]),
            )
        )

        created = await first.shell(
            "printf persistent > \"$TMPDIR/value\"; printf '%s' \"$TMPDIR\""
        )
        reread = await first.shell("cat \"$TMPDIR/value\"")
        isolated = await second.shell(
            "test ! -e \"$TMPDIR/value\"; printf isolated"
        )

        assert reread["data"]["output"] == "persistent"
        assert isolated["data"]["status"] == "completed"
        assert isolated["data"]["output"] == "isolated"
        assert created["data"]["cwd"] == "."
        assert created["data"]["temp_dir"] != isolated["data"]["temp_dir"]
        denied = await second.task_output(created["data"]["task_id"])
        assert denied["error"]["code"] == "task_not_found"


@pytest.mark.asyncio
async def test_conventional_absolute_tmp_path_is_available_on_macos(make_tools) -> None:
    if sys.platform != "darwin":
        pytest.skip("macOS sandbox-exec compatibility check")
    marker = f"aion-tmp-{uuid4().hex}"
    async with make_tools() as tools:
        result = await tools.shell(
            f"printf absolute-tmp > /tmp/{marker}; cat /tmp/{marker}; rm -f /tmp/{marker}"
        )
    assert result["data"]["status"] == "completed"
    assert result["data"]["output"] == "absolute-tmp"


@pytest.mark.asyncio
async def test_host_container_control_is_blocked(make_tools) -> None:
    async with make_tools() as tools:
        for command in (
            "docker ps",
            "sh -c 'docker exec target cat /run/secrets/flag'",
            "python3 -c 'open(\"/var/run/docker.sock\")'",
            "kubectl exec target -- cat /run/secrets/flag",
        ):
            result = await tools.shell(command)
            assert result["error"]["code"] == "container_control_blocked"


@pytest.mark.asyncio
async def test_macos_shell_cannot_connect_to_host_container_socket(make_tools) -> None:
    if sys.platform != "darwin":
        pytest.skip("macOS sandbox-exec compatibility check")
    # Build the path inside the child so this test also exercises the OS
    # sandbox instead of the command-text denylist.
    command = (
        "python3 -c 'import socket; "
        "p=chr(47)+chr(118)+chr(97)+chr(114)+chr(47)+chr(114)+chr(117)+"
        "chr(110)+chr(47)+chr(100)+chr(111)+chr(99)+chr(107)+chr(101)+"
        "chr(114)+chr(46)+chr(115)+chr(111)+chr(99)+chr(107); "
        "s=socket.socket(socket.AF_UNIX); s.connect(p); print(\"connected\")'"
    )
    async with make_tools() as tools:
        result = await tools.shell(command)
    assert result["data"]["status"] == "failed"
    assert result["data"]["exit_code"] != 0
    assert "PermissionError" in result["data"]["output"]


@pytest.mark.asyncio
async def test_completed_output_expires_after_fixed_ttl(make_tools) -> None:
    clock = _MutableClock()
    harness = make_tools(
        clock=clock,
        reap_interval_seconds=0,
    )
    async with harness as tools:
        completed = await tools.shell("printf retained")
        task_id = completed["data"]["task_id"]
        clock.advance(minutes=30)
        assert harness.manager is not None
        assert await harness.manager.reap_expired() == 1

        expired = await tools.task_output(task_id)
        assert expired["error"]["code"] == "task_output_expired"
        assert harness.service is not None
        assert harness.agent_id is not None
        row = await harness.service.get_shell_task(
            harness.run_id, harness.agent_id, task_id
        )
        assert row["cleanup_reason"] == "ttl"


@pytest.mark.asyncio
async def test_pause_and_resume_marks_running_task_interrupted(make_tools) -> None:
    harness = make_tools(reap_interval_seconds=0)
    tools = await harness.__aenter__()
    resumed: ShellTaskManager | None = None
    try:
        background = await tools.shell(
            "printf before; sleep 10; printf after",
            run_in_background=True,
        )
        task_id = background["data"]["task_id"]
        await asyncio.sleep(0.05)
        assert harness.manager is not None
        await harness.manager.pause_run()

        assert harness.service is not None
        assert harness.agent_id is not None
        policy = WorkspacePolicy(harness.root)
        resumed = ShellTaskManager(
            policy,
            harness.service,
            harness.run_id,
            sandbox=SandboxBackend(policy.root),
            reap_interval_seconds=0,
        )
        await resumed.initialize(resume=True)
        rebound = _SystemToolClient(
            SystemTools(root=harness.root, shell=resumed.bind(harness.agent_id))
        )
        output = await rebound.task_output(task_id)
        assert output["data"]["status"] == "interrupted"
        assert output["data"]["output"] == "before"
        assert "after" not in output["data"]["output"]
    finally:
        if resumed is not None:
            await resumed.finish_run()
        assert harness.service is not None
        await harness.service.close()


@pytest.mark.asyncio
async def test_agent_and_run_terminal_cleanup_remove_runtime_files(make_tools) -> None:
    harness = make_tools(reap_interval_seconds=0)
    async with harness as tools:
        completed = await tools.shell("printf terminal-output")
        task_id = completed["data"]["task_id"]
        assert harness.manager is not None
        assert harness.agent_id is not None
        owner_root = harness.manager.runtime_root / "agents" / harness.agent_id
        run_root = harness.manager.runtime_root
        assert owner_root.is_dir()

        await harness.manager.finish_agent(harness.agent_id)
        assert not owner_root.exists()
        expired = await tools.task_output(task_id)
        assert expired["error"]["code"] == "task_output_expired"

    assert not run_root.exists()


@pytest.mark.asyncio
async def test_shell_agent_and_run_cleanup_are_concurrently_idempotent(make_tools) -> None:
    harness = make_tools(reap_interval_seconds=0)
    tools = await harness.__aenter__()
    try:
        completed = await tools.shell("printf concurrent-cleanup")
        assert completed["ok"] is True
        assert harness.manager is not None
        assert harness.agent_id is not None
        await asyncio.gather(
            *(harness.manager.finish_agent(harness.agent_id) for _ in range(20)),
            *(harness.manager.finish_run() for _ in range(5)),
        )
        assert not harness.manager.runtime_root.exists()
        rows = await harness.service.list_shell_tasks(
            harness.run_id, agent_id=harness.agent_id
        )
        assert rows and all(row["output_cleaned_at"] is not None for row in rows)
    finally:
        await harness.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_sandbox_unavailable_is_reported_without_running_shell(make_tools) -> None:
    async with make_tools(
        sandbox_executable="/does/not/exist/sandbox-exec"
    ) as tools:
        result = await tools.shell("printf should-not-run")

    assert result["ok"] is False
    assert result["error"]["stage"] == "execution"
    assert result["error"]["code"] == "sandbox_unavailable"
    assert result["error"]["retry"]["allowed"] is False


@pytest.mark.asyncio
async def test_executor_validation_and_json_serialization(make_tools) -> None:
    async with make_tools() as tools:
        async def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
            calls = await ToolExecutor(ToolRegistry([tools])).execute(
                [{"id": name, "function": {"name": name, "arguments": json.dumps(arguments)}}]
            )
            assert calls[0].result is not None
            return calls[0].result

        unknown = await call("system_unknown", {})
        invalid = await call("system_read_file", {"unexpected": True})
        result = await call("system_list_directory", {})

    assert unknown["error"]["code"] == "unknown_tool"
    assert invalid["error"]["stage"] == "schema"
    assert result["ok"] is True
    json.dumps(result)


@pytest.mark.asyncio
async def test_system_tool_definitions_are_generated_from_specs(make_tools) -> None:
    async with make_tools() as tools:
        definitions = ToolRegistry([tools]).definitions()
    names = [item["function"]["name"] for item in definitions]
    assert len(names) == 9
    assert names == [
        "system_read_file",
        "system_write_file",
        "system_edit_file",
        "system_list_directory",
        "system_glob",
        "system_grep",
        "system_shell",
        "system_task_output",
        "system_task_stop",
    ]
    assert all(item["function"]["parameters"]["additionalProperties"] is False for item in definitions)
    read_schema = definitions[0]["function"]["parameters"]
    assert "limit_chars" in read_schema["properties"]
    assert "limit" not in read_schema["properties"]
    assert not hasattr(SystemTools, "tool_definitions")


def test_linux_sandbox_command_is_available_as_a_reserved_backend(tmp_path: Path) -> None:
    executable = tmp_path / "bwrap"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | 0o111)

    read_only = tmp_path / "skills"
    read_only.mkdir()
    backend = SandboxBackend(
        tmp_path,
        executable=str(executable),
        platform_name="Linux",
        read_only_paths=(read_only,),
    )

    assert backend.available is True
    persistent_tmp = tmp_path / "agent-private-tmp"
    persistent_tmp.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    command = backend.command(
        "printf linux-ok",
        work,
        persistent_tmp,
        write_paths=(work, persistent_tmp),
    )
    assert command[:2] == [str(executable), "--die-with-parent"]
    assert "--ro-bind" in command
    assert "--bind" in command
    assert ["--tmpfs", "/tmp"] not in [command[index : index + 2] for index in range(len(command) - 1)]
    tmp_bind = command.index(str(persistent_tmp))
    assert command[tmp_bind - 1 : tmp_bind + 2] == [
        "--bind",
        str(persistent_tmp),
        "/tmp",
    ]
    chdir_index = command.index("--chdir")
    assert command[chdir_index : chdir_index + 2] == ["--chdir", str(work)]
    assert command[-4:] == ["--noprofile", "--norc", "-lc", "printf linux-ok"]
    root_bind = command.index(str(tmp_path), command.index("--ro-bind"))
    assert command[root_bind - 1 : root_bind + 2] == [
        "--ro-bind",
        str(tmp_path),
        str(tmp_path),
    ]
    work_bind = command.index(str(work), root_bind + 1)
    assert command[work_bind - 1 : work_bind + 2] == ["--bind", str(work), str(work)]
    skill_bind = command.index(str(read_only), work_bind + 1)
    assert command[skill_bind - 1 : skill_bind + 2] == [
        "--ro-bind",
        str(read_only),
        str(read_only),
    ]


def test_sandbox_profile_hides_runtime_control_plane_but_reopens_agent_paths(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "sandbox-exec"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | 0o111)
    hidden = (tmp_path / ".aion", tmp_path / ".system-tools")
    shared = tmp_path / ".aion" / "runs" / "run" / "shared" / "a-05"
    backend = SandboxBackend(
        tmp_path,
        executable=str(executable),
        platform_name="Darwin",
        hidden_paths=hidden,
    )

    profile = backend._macos_profile(write_paths=(shared,))
    hidden_aion = '(deny file-read* (subpath "' + str(hidden[0]) + '"))'
    hidden_tools = '(deny file-read* (subpath "' + str(hidden[1]) + '"))'
    shared_allow = '(allow file-read* (subpath "' + str(shared) + '"))'
    assert hidden_aion in profile
    assert hidden_tools in profile
    assert "(deny network-outbound)" in profile
    assert profile.index(hidden_aion) < profile.index(shared_allow)
    assert profile.index(hidden_tools) < profile.index(shared_allow)


def test_linux_container_sandbox_drops_privileges_without_namespaces(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "setpriv"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | 0o111)
    account = pwd.getpwuid(os.getuid())
    workspace_file = tmp_path / "artifact.bin"
    workspace_file.write_bytes(b"artifact")
    backend = SandboxBackend(
        tmp_path,
        executable=str(executable),
        platform_name="Linux",
        sandbox_user=account.pw_name,
    )

    backend.prepare()
    command = backend.command("id", tmp_path)

    assert backend.available is True
    assert command[:4] == [
        str(executable),
        f"--reuid={account.pw_uid}",
        f"--regid={account.pw_gid}",
        "--clear-groups",
    ]
    assert "--no-new-privs" in command
    assert "--bounding-set=-all" in command
    assert command[-4:] == ["--noprofile", "--norc", "-lc", "id"]


def test_windows_backend_is_reserved_without_an_unsafe_fallback(tmp_path: Path) -> None:
    backend = SandboxBackend(
        tmp_path,
        executable="/bin/bash",
        platform_name="Windows",
    )

    assert backend.available is False
    with pytest.raises(SystemToolError) as error:
        backend.command("echo no", tmp_path)
    assert error.value.code == "sandbox_unsupported_platform"
