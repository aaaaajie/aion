"""Minimal Agent smoke test for local system tools and run memory.

Run from the project root with::

    ./.venv/bin/python scripts/test_agent.py

This script intentionally exposes only ``SystemTools``. It never starts a
challenge, calls the benchmark API, or touches the VPN.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import AgentSettings
from agent.runner import AgentRunner, ToolRegistry
from agent.state import AgentStateStore, StateService
from tools.system import ShellTaskManager, SystemTools
from tools.system.policy import WorkspacePolicy

EXPECTED_TOOLS = {
    "system_read_file",
    "system_write_file",
    "system_edit_file",
    "system_create_directory",
    "system_delete_path",
    "system_list_directory",
    "system_glob",
    "system_grep",
    "system_shell",
    "system_task_output",
    "system_task_stop",
    "system_task_cleanup",
}


TEST_PROMPT = """
You are running a local system-tool smoke test. Do not call any benchmark,
challenge, VPN, or network-target tool; only use the system_* tools provided.
Use every provided system tool at least once, in a safe sequence, and finish
with a short report.

Use the workspace-relative directory `.agent-smoke` and perform this sequence:
1. Create `.agent-smoke` with system_create_directory.
2. Write `.agent-smoke/hello.txt` with content `agent-smoke\n` using system_write_file.
3. Read the complete file with system_read_file.
4. Edit `agent-smoke` to `agent-smoke-updated` using system_edit_file.
5. List `.agent-smoke` recursively with system_list_directory.
6. Find `**/*.txt` under `.agent-smoke` with system_glob.
7. Search for `updated` under `.agent-smoke` with system_grep.
8. Run a foreground shell command that prints `foreground-ok` using system_shell.
9. Start a background shell command `sleep 5; printf background-ok` using system_shell.
10. Poll that task once with system_task_output using a short wait.
11. Stop that task with system_task_stop.
12. Clean the stopped background task output with system_task_cleanup.
13. Recursively delete `.agent-smoke` with system_delete_path.

Do not read `.env`, credentials, or files outside `.agent-smoke`. Do not skip
steps and do not invent tool names. The final response should only summarize
which tool names completed successfully.
""".strip()


async def run_smoke(max_rounds: int) -> int:
    smoke_directory = PROJECT_ROOT / ".agent-smoke"
    if smoke_directory.exists() or smoke_directory.is_symlink():
        print("[agent] refusing to use existing .agent-smoke directory")
        return 2

    settings = AgentSettings()
    run_id = f"agent-smoke-{uuid4().hex[:12]}"
    run_root = PROJECT_ROOT / ".aion" / "runs"
    service = StateService(run_root / run_id / "state.sqlite3", run_root=run_root)
    await service.create_run(
        run_id,
        model=settings.llm_model,
        prompt=TEST_PROMPT,
        context_window_tokens=settings.context_budget.context_window_tokens,
    )
    chief = await service.register_agent(
        run_id, role="chief", initial_prompt=TEST_PROMPT
    )
    shell_tasks = ShellTaskManager(
        WorkspacePolicy(PROJECT_ROOT), service, run_id
    )
    await shell_tasks.initialize()
    system_tools = SystemTools(
        root=PROJECT_ROOT,
        shell=shell_tasks.bind(chief["agent_id"]),
    )
    await service.transition_controller(run_id, chief["agent_id"], "running")
    store = await AgentStateStore.open(
        service,
        run_id=run_id,
        agent_id=chief["agent_id"],
        run_dir=run_root / run_id,
    )
    runner = AgentRunner(
        settings,
        ToolRegistry([system_tools]),
        max_rounds=max_rounds,
        run_root=run_root,
        state_service=service,
        role="chief",
        agent_id=chief["agent_id"],
    )
    try:
        result = await runner.run_session(TEST_PROMPT, store=store)
        if runner.agent_id is None:
            raise RuntimeError("runner did not register an agent")
        events = await service.list_agent_events(run_id, runner.agent_id)
        called = {
            event["payload"].get("tool_name")
            for event in events
            if event["event_type"] == "tool_call"
        }
        missing = sorted(EXPECTED_TOOLS - called)
        print(f"[agent] run_id: {run_id}")
        print(f"[agent] final: {result.final}")
        if missing:
            print(f"[agent] missing tool calls: {', '.join(missing)}")
            return 1
        print(f"[agent] success: {len(called)} system tools called")
        return 0
    finally:
        await runner.close()
        if smoke_directory.is_dir() and not smoke_directory.is_symlink():
            await system_tools.delete_path(".agent-smoke", recursive=True)
        await shell_tasks.finish_run()
        await service.close()


async def async_main() -> int:
    parser = argparse.ArgumentParser(description="Run the local system-tools Agent smoke test")
    parser.add_argument("--max-rounds", type=int, default=20)
    args = parser.parse_args()
    if args.max_rounds < 1:
        parser.error("--max-rounds must be positive")
    try:
        return await run_smoke(args.max_rounds)
    except Exception:
        print("[agent] smoke test failed")
        return 1


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
