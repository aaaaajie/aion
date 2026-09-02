"""Agent-facing ToolSpec for the headless browser."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec

from .manager import AgentBrowserClient
from .models import BrowserArguments


class BrowserTools:
    """Expose one structured browser surface without adding a new Agent layer."""

    def __init__(self, client: AgentBrowserClient) -> None:
        self._client = client

    def tool_specs(self) -> list[ToolSpec]:
        async def browser(arguments: BaseModel) -> Any:
            assert isinstance(arguments, BrowserArguments)
            return await self._client.dispatch(arguments)

        return [
            ToolSpec(
                "system_browser",
                (
                    "Drive an Agent-private headless Chrome session through agent-browser. "
                    "Use open, snapshot, interact, get, eval, wait, screenshot, tabs, "
                    "network, and close actions. Follow open with snapshot; snapshot refs "
                    "are stale after page changes. Browser traffic uses the configured "
                    "HTTP_PROXY/HTTPS_PROXY environment and can therefore appear in the "
                    "system_proxy capture history."
                ),
                BrowserArguments,
                browser,
                lambda _arguments: (
                    AccessClaim("write", f"browser-session:{self._client.session_id}"),
                ),
                result_projector=self._page_projection,
            )
        ]

    @staticmethod
    def _page_projection(result: dict[str, Any]) -> dict[str, Any]:
        data = result.get("data")
        if not isinstance(data, dict):
            return {}
        return {
            key: data[key]
            for key in ("action", "session_id", "status", "exit_code", "artifact_path", "truncated")
            if key in data
        }

    async def close(self) -> None:
        """The Supervisor owns browser session cleanup."""
