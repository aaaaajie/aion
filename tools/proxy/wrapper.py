"""Agent-facing ToolSpec for the optional Caido HTTP proxy."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec
from tools.system.policy import SystemToolError

from . import caido_api
from .manager import CaidoProxyManager
from .models import ProxyArguments


class ProxyTools:
    """Expose Strix's capture/replay surface through the existing ToolExecutor."""

    def __init__(self, manager: CaidoProxyManager) -> None:
        self._manager = manager

    def tool_specs(self) -> list[ToolSpec]:
        async def proxy(arguments: BaseModel) -> Any:
            assert isinstance(arguments, ProxyArguments)
            return await self._dispatch(arguments)

        return [
            ToolSpec(
                "system_proxy",
                (
                    "Query the optional Caido HTTP/HTTPS interception proxy. Actions: "
                    "list_requests with HTTPQL and cursor pagination; view_request for "
                    "raw request/response pages or regex hits; replay_request to overlay "
                    "url, params, headers, body, or cookies; list_sitemap and "
                    "view_sitemap_entry for the discovered surface; scope_rules for "
                    "scope CRUD. Browser traffic is captured when its sandbox has "
                    "HTTP_PROXY/HTTPS_PROXY pointed at Caido."
                ),
                ProxyArguments,
                proxy,
                self._claims,
                result_projector=self._projection,
            )
        ]

    async def _dispatch(self, arguments: ProxyArguments) -> dict[str, Any]:
        try:
            if arguments.action == "list_requests":
                connection = await self._manager.call(
                    lambda client: caido_api.list_requests_with_client(
                        client,
                        httpql_filter=arguments.httpql_filter,
                        first=arguments.first,
                        after=arguments.after,
                        sort_by=arguments.sort_by,
                        sort_order=arguments.sort_order,
                        scope_id=arguments.scope_id,
                    )
                )
                return caido_api.format_request_connection(connection)
            if arguments.action == "view_request":
                result = await self._manager.call(
                    lambda client: caido_api.get_request_with_client(
                        client, arguments.request_id or "", part=arguments.part
                    )
                )
                raw = caido_api._value(
                    caido_api._value(result, "request" if arguments.part == "request" else "response"),
                    "raw",
                )
                if raw is None:
                    return {"success": False, "error": f"No raw {arguments.part} for {arguments.request_id}"}
                content = (raw if isinstance(raw, str) else bytes(raw).decode("utf-8", errors="replace"))
                if arguments.search_pattern:
                    return caido_api.format_search_hits(content, arguments.search_pattern)
                return caido_api.format_text_page(
                    content, page=arguments.page, page_size=arguments.page_size
                )
            if arguments.action == "replay_request":
                modifications = (
                    arguments.modifications.model_dump(exclude_unset=True)
                    if arguments.modifications is not None
                    else {}
                )
                replay = await self._manager.call(
                    lambda client: caido_api.replay_request_with_client(
                        client, arguments.request_id or "", modifications
                    )
                )
                return caido_api.format_replay_result(replay)
            if arguments.action == "list_sitemap":
                return await self._manager.call(
                    lambda client: caido_api.list_sitemap_with_client(
                        client,
                        scope_id=arguments.scope_id,
                        parent_id=arguments.parent_id,
                        depth=arguments.depth,
                        page=arguments.page,
                    )
                )
            if arguments.action == "view_sitemap_entry":
                return await self._manager.call(
                    lambda client: caido_api.view_sitemap_entry_with_client(
                        client, arguments.entry_id or ""
                    )
                )
            return {
                "success": True,
                "scope": await self._manager.call(
                    lambda client: caido_api.scope_rules_with_client(
                        client,
                        arguments.scope_action or "list",
                        allowlist=arguments.allowlist,
                        denylist=arguments.denylist,
                        scope_id=arguments.scope_id,
                        scope_name=arguments.scope_name,
                    )
                ),
            }
        except SystemToolError:
            raise
        except Exception as exc:
            raise SystemToolError(
                error_type="execution",
                code="proxy_operation_failed",
                message="The Caido proxy operation failed",
                detail={
                    "action": arguments.action,
                    "cause": type(exc).__name__,
                },
            ) from exc

    @staticmethod
    def _claims(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        assert isinstance(arguments, ProxyArguments)
        mode = "write" if arguments.action in {"replay_request", "scope_rules"} else "read"
        return (AccessClaim(mode, "proxy-global"),)

    @staticmethod
    def _projection(result: dict[str, Any]) -> dict[str, Any]:
        data = result.get("data")
        if not isinstance(data, dict):
            return {}
        projected: dict[str, Any] = {
            key: data[key]
            for key in ("success", "status", "session_id", "elapsed_ms", "page", "total_count", "total_pages")
            if key in data
        }
        for key in ("entries", "hits", "related_requests"):
            value = data.get(key)
            if isinstance(value, list):
                projected[f"{key}_count"] = len(value)
        return projected

    async def close(self) -> None:
        """The Supervisor owns the shared Caido client lifecycle."""
