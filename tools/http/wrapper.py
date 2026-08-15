"""Agent-facing Tool Specs for generic HTTP interactions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec

from .manager import AgentHttpClient
from .models import (
    FingerprintArguments,
    HttpAnalyzeArguments,
    HttpCleanupArguments,
    HttpOutputArguments,
    HttpProbeArguments,
    HttpRequestArguments,
    HttpResponseArguments,
    HttpStopArguments,
    PathProbeArguments,
)


class HttpTools:
    """Expose one Agent-bound HTTP engine through the shared ToolExecutor."""

    def __init__(self, client: AgentHttpClient) -> None:
        self._client = client

    def tool_specs(self) -> list[ToolSpec]:
        return [
            self._spec("system_http_request", "Send one fresh HTTP request from top-level method/URL fields. Reuse session_id for ordered multi-step protocols; poll the returned interaction_id instead of replaying work.", HttpRequestArguments, self._client.request, self._request_claims, self._page_projection),
            self._spec("system_http_probe", "Generate at most 5,000 independent requests from a finite matrix. Use top-level cases (a single case may be supplied as an object and is normalized to a list); put variables/combine inside each case and keep concurrency/rate_limit_per_second/wait_seconds at the top level. Probe never accepts request, top-level variables/combine, or session_id. Example: {\"cases\":[{\"method\":\"GET\",\"url\":\"http://host/{{path}}\",\"variables\":{\"path\":{\"values\":[\"/\",\"/admin\"],\"encoding\":\"path\"}}}],\"concurrency\":8,\"wait_seconds\":20}. Use system_http_request with session_id for ordered multi-step protocols.", HttpProbeArguments, self._client.probe, self._new_interaction_claims, self._page_projection),
            self._spec("system_web_path_probe", "Run bounded web path discovery for one base URL. Preserve interaction_id and poll for status.", PathProbeArguments, self._client.path_probe, self._scan_claims, self._page_projection),
            self._spec("system_web_fingerprint", "Identify the web technology stack using passive and optional active evidence.", FingerprintArguments, self._client.fingerprint, self._scan_claims, self._page_projection),
            self._spec("system_http_analyze", "Create or read on-demand deterministic analysis for an existing HTTP interaction without resending traffic.", HttpAnalyzeArguments, self._client.analyze, self._interaction_write, self._page_projection),
            self._spec("system_http_output", "Poll compact response and analysis records for an existing interaction. This never resends traffic.", HttpOutputArguments, self._client.output, self._interaction_read, self._page_projection),
            self._spec("system_http_response", "Read an exact owned response Body by byte range.", HttpResponseArguments, self._client.response, self._interaction_read),
            self._spec("system_http_stop", "Cancel an owned queued, running, or analyzing interaction while preserving stored output.", HttpStopArguments, self._client.stop, self._interaction_write),
        ]

    async def close(self) -> None:
        await self._client.close()

    @staticmethod
    def _spec(
        name: str,
        description: str,
        model: type[BaseModel],
        operation: Callable[[Any], Awaitable[dict[str, Any]]],
        claims: Callable[[BaseModel], tuple[AccessClaim, ...]],
        projector: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> ToolSpec:
        async def handler(arguments: BaseModel) -> Any:
            return await operation(arguments)

        return ToolSpec(
            name,
            description,
            model,
            handler,
            access_claims=claims,
            result_projector=projector,
        )

    @staticmethod
    def _request_claims(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        session = getattr(arguments, "session_id", None)
        if session:
            return (AccessClaim("write", f"http-session:{session}"),)
        return (AccessClaim("write", f"http-new:{id(arguments)}"),)

    @staticmethod
    def _new_interaction_claims(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("write", f"http-new:{id(arguments)}"),)

    @staticmethod
    def _scan_claims(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        session = getattr(arguments, "session_id", None)
        if session:
            return (AccessClaim("read", f"http-session:{session}"),)
        return HttpTools._new_interaction_claims(arguments)

    @staticmethod
    def _interaction_read(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("read", f"http-interaction:{arguments.interaction_id}"),)

    @staticmethod
    def _interaction_write(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("write", f"http-interaction:{arguments.interaction_id}"),)

    @staticmethod
    def _page_projection(result: Mapping[str, Any]) -> Mapping[str, Any]:
        data = result.get("data")
        if not isinstance(data, Mapping):
            return {}
        projected = {
            key: data.get(key)
            for key in (
                "interaction_id",
                "request_id",
                "status",
                "execution_status",
                "analysis_status",
                "resource_status",
                "cursor",
                "next_cursor",
                "recommended_wait_seconds",
                "recommended_action",
                "is_terminal",
                "can_cleanup",
                "connection_pool",
                "request_catalog",
            )
            if key in data
        }
        results = data.get("results")
        if isinstance(results, list):
            projected["result_count"] = len(results)
        return projected
