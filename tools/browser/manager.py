"""Lifecycle and command bridge for Agent-private ``agent-browser`` sessions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from uuid import uuid4

from tools.system.policy import SystemToolError
from tools.system.shell import AgentShellClient

from .models import BrowserArguments


class BrowserManager:
    """Own one named browser session per Execution Agent and close it with the run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = _component(run_id, "run_id")
        self._clients: dict[str, AgentBrowserClient] = {}
        self._started: set[str] = set()
        self._closed = False

    def bind(self, agent_id: str, shell: AgentShellClient) -> "AgentBrowserClient":
        if self._closed:
            raise SystemToolError(
                error_type="internal",
                code="browser_manager_closed",
                message="The browser manager is not active",
            )
        agent_id = _component(agent_id, "agent_id")
        client = self._clients.get(agent_id)
        if client is None:
            client = AgentBrowserClient(
                self,
                agent_id,
                shell,
                session_id=_session_name(self.run_id, agent_id),
            )
            self._clients[agent_id] = client
        return client

    async def execute(
        self,
        client: "AgentBrowserClient",
        arguments: BrowserArguments,
    ) -> dict[str, Any]:
        if self._closed:
            raise SystemToolError(
                error_type="internal",
                code="browser_manager_closed",
                message="The browser manager is not active",
            )
        if arguments.action == "close":
            return await client.close_session()

        argv, artifact_path = _build_argv(
            arguments,
            workspace=getattr(client.shell, "agent_work_root", None),
        )
        self._started.add(client.agent_id)
        try:
            result = await client.shell.run_shell(
                _browser_shell_command(client.session_id, argv),
                cwd=".",
                timeout=arguments.timeout_seconds,
                max_output_chars=arguments.max_output_chars,
            )
        except SystemToolError as exc:
            if exc.code in {"sandbox_unavailable", "sandbox_unsupported_platform"}:
                raise SystemToolError(
                    error_type="execution",
                    code="browser_backend_unavailable",
                    message="The headless browser sandbox is not available",
                    detail={"cause": exc.code},
                ) from exc
            raise

        status = str(result.get("status") or "completed")
        exit_code = result.get("exit_code")
        output = str(result.get("output") or "")
        if status != "completed" or exit_code not in {None, 0}:
            unavailable = exit_code == 127 or "command not found" in output.lower()
            if unavailable:
                self._started.discard(client.agent_id)
                raise SystemToolError(
                    error_type="execution",
                    code="browser_backend_unavailable",
                    message="agent-browser is not installed in the execution image",
                    detail={"output": output[-2_000:]},
                )
            code = "browser_command_timeout" if status == "timeout" else "browser_command_failed"
            raise SystemToolError(
                error_type="execution",
                code=code,
                message="The headless browser command did not complete successfully",
                detail={
                    "action": arguments.action,
                    "status": status,
                    "exit_code": exit_code,
                    "output": output[-4_000:],
                },
            )
        data: dict[str, Any] = {
            "action": arguments.action,
            "session_id": client.session_id,
            "status": status,
            "exit_code": exit_code,
            "output": output,
            "truncated": bool(result.get("truncated")),
        }
        if artifact_path is not None:
            data["artifact_path"] = artifact_path
        return data

    async def finish_agent(self, agent_id: str) -> None:
        client = self._clients.get(agent_id)
        if client is None:
            return
        try:
            await client.close_session()
        except Exception:
            # A dead browser process is already in the desired terminal state.
            pass
        finally:
            self._started.discard(agent_id)
            self._clients.pop(agent_id, None)

    async def pause_run(self) -> None:
        await self._close_all()
        self._closed = True

    async def finish_run(self) -> None:
        await self._close_all()
        self._closed = True

    async def _close_all(self) -> None:
        clients = list(self._clients.values())
        if clients:
            await asyncio.gather(
                *(client.close_session() for client in clients if client.agent_id in self._started),
                return_exceptions=True,
            )
        self._started.clear()
        self._clients.clear()


class AgentBrowserClient:
    """Agent-bound view over a shared :class:`BrowserManager`."""

    def __init__(
        self,
        manager: BrowserManager,
        agent_id: str,
        shell: AgentShellClient,
        *,
        session_id: str,
    ) -> None:
        self.manager = manager
        self.agent_id = agent_id
        self.shell = shell
        self.session_id = session_id

    async def dispatch(self, arguments: BrowserArguments) -> dict[str, Any]:
        return await self.manager.execute(self, arguments)

    async def close_session(self) -> dict[str, Any]:
        if self.agent_id not in self.manager._started:
            return {
                "action": "close",
                "session_id": self.session_id,
                "closed": False,
                "reason": "session_not_started",
            }
        try:
            result = await self.shell.run_shell(
                _browser_shell_command(self.session_id, ["close"], cleanup=True),
                cwd=".",
                timeout=30.0,
                max_output_chars=8_000,
            )
        finally:
            self.manager._started.discard(self.agent_id)
        if str(result.get("status") or "completed") != "completed" or result.get("exit_code") not in {None, 0}:
            raise SystemToolError(
                error_type="execution",
                code="browser_close_failed",
                message="The headless browser session could not be closed",
                detail={"output": str(result.get("output") or "")[-2_000:]},
            )
        return {
            "action": "close",
            "session_id": self.session_id,
            "closed": True,
            "output": str(result.get("output") or ""),
        }


def _browser_shell_command(
    session_id: str,
    argv: Iterable[str],
    *,
    cleanup: bool = False,
) -> str:
    """Run agent-browser from a short, session-private POSIX temp path."""

    runtime_dir = _browser_runtime_dir(session_id)
    quoted_dir = shlex.quote(runtime_dir)
    command = (
        f"mkdir -p {quoted_dir} && chmod 700 {quoted_dir} && "
        + shlex.join(
            (
                "env",
                f"TMPDIR={runtime_dir}",
                f"TMP={runtime_dir}",
                f"TEMP={runtime_dir}",
                f"AGENT_BROWSER_SOCKET_DIR={runtime_dir}",
                "agent-browser",
                "--session",
                session_id,
                *argv,
            )
        )
    )
    if cleanup:
        return f"{command}; status=$?; rm -rf {quoted_dir}; exit $status"
    return command


def _browser_runtime_dir(session_id: str) -> str:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    return f"/tmp/aion-ab-{digest}"


def _build_argv(
    arguments: BrowserArguments,
    *,
    workspace: Path | None = None,
) -> tuple[list[str], str | None]:
    action = arguments.action
    if action == "open":
        return ["open", arguments.url or ""], None
    if action == "snapshot":
        argv = ["snapshot"]
        if arguments.snapshot_interactive:
            argv.append("-i")
        if arguments.snapshot_include_urls:
            argv.append("-u")
        if arguments.snapshot_compact:
            argv.append("-c")
        if arguments.snapshot_depth is not None:
            argv.extend(("-d", str(arguments.snapshot_depth)))
        if arguments.snapshot_selector:
            argv.extend(("-s", arguments.snapshot_selector))
        if arguments.snapshot_json:
            argv.append("--json")
        return argv, None
    if action == "interact":
        interaction = arguments.interaction or "click"
        if interaction == "scroll":
            return ["scroll", arguments.direction or "down", str(arguments.amount)], None
        argv = [interaction]
        if arguments.target is not None:
            argv.append(arguments.target)
        if interaction == "drag" and arguments.value is not None:
            argv.append(arguments.value)
        elif interaction == "select":
            argv.extend(arguments.values or ([arguments.value] if arguments.value is not None else []))
        elif interaction == "upload" and arguments.value is not None:
            argv.append(_workspace_relative_path(workspace, arguments.value))
        elif arguments.value is not None:
            argv.append(arguments.value)
        if arguments.new_tab:
            argv.append("--new-tab")
        return argv, None
    if action == "get":
        argv = ["get", arguments.get_kind or "text"]
        if arguments.target is not None:
            argv.append(arguments.target)
        if arguments.attribute is not None:
            argv.append(arguments.attribute)
        return argv, None
    if action == "eval":
        encoded = base64.b64encode((arguments.script or "").encode("utf-8")).decode("ascii")
        return ["eval", "-b", encoded], None
    if action == "wait":
        mode = arguments.wait_mode or "element"
        value = arguments.wait_value or ""
        if mode in {"element", "ms"}:
            return ["wait", value], None
        return ["wait", f"--{mode}", value], None
    if action == "screenshot":
        path = arguments.path or f"browser-{uuid4().hex}.png"
        if arguments.path is not None and workspace is not None:
            path = _workspace_relative_path(workspace, path)
        argv = ["screenshot", path]
        if arguments.screenshot_full:
            argv.append("--full")
        if arguments.screenshot_annotate:
            argv.append("--annotate")
        return argv, path
    if action == "tabs":
        tab_action = arguments.tab_action or "list"
        if tab_action == "list":
            return ["tab"], None
        if tab_action == "new":
            return ["tab", "new", arguments.url or ""], None
        if tab_action == "switch":
            return ["tab", arguments.tab_id or ""], None
        return ["tab", tab_action, arguments.tab_id or ""], None
    if action == "network":
        network_action = arguments.network_action or "requests"
        if network_action == "requests":
            return ["network", "requests"], None
        if network_action == "har_start":
            return ["network", "har", "start"], None
        if network_action == "har_stop":
            path = arguments.path or f"browser-{uuid4().hex}.har"
            if arguments.path is not None and workspace is not None:
                path = _workspace_relative_path(workspace, path)
            return ["network", "har", "stop", path], path
        if network_action == "route":
            return ["network", "route", arguments.network_pattern or "", "--body", arguments.network_body or ""], None
        return ["network", "route", arguments.network_pattern or "", "--abort"], None
    raise ValueError(f"unsupported browser action: {action}")


def _workspace_relative_path(workspace: Path | None, value: str) -> str:
    if workspace is None:
        raise SystemToolError(
            error_type="internal",
            code="browser_workspace_unavailable",
            message="The Agent workspace is not available for browser file access",
        )
    if not value or "\x00" in value:
        raise SystemToolError(
            error_type="validation",
            code="browser_path_invalid",
            message="Browser file paths must be non-empty and NUL-free",
        )
    root = workspace.resolve(strict=False)
    raw = Path(value).expanduser()
    if raw.is_absolute():
        raise SystemToolError(
            error_type="permission",
            code="browser_workspace_path_rejected",
            message="Browser file paths must stay inside the Agent workspace",
        )
    candidate = (root / raw).resolve(strict=False)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise SystemToolError(
            error_type="permission",
            code="browser_workspace_path_rejected",
            message="Browser file paths must stay inside the Agent workspace",
        ) from exc
    if not relative.parts:
        raise SystemToolError(
            error_type="validation",
            code="browser_path_invalid",
            message="Browser file paths must name a file inside the Agent workspace",
        )
    return relative.as_posix()


def _session_name(run_id: str, agent_id: str) -> str:
    raw = f"aion-{_slug(run_id)}-{_slug(agent_id)}"
    if len(raw) <= 48:
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{raw[:35]}-{digest}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def _component(value: str, name: str) -> str:
    if not value or value in {".", ".."} or Path(value).name != value:
        raise ValueError(f"{name} must be one path component")
    return value
