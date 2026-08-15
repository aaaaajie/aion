"""Agent-facing Tool Specs for network discovery."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from agent.tooling import AccessClaim, ToolSpec

from .manager import AgentNetworkClient
from .models import (
    NetworkCleanupArguments,
    NetworkDiscoveryArguments,
    NetworkOutputArguments,
    NetworkStopArguments,
)


class NetworkTools:
    """Expose network discovery through the shared ToolExecutor."""

    def __init__(self, client: AgentNetworkClient) -> None:
        self._client = client

    def tool_specs(self) -> list[ToolSpec]:
        async def discovery(arguments: BaseModel) -> Any:
            assert isinstance(arguments, NetworkDiscoveryArguments)
            return await self._client.discovery(
                targets=arguments.targets,
                ports=arguments.ports,
                ping=arguments.ping,
                ping_tcp=arguments.ping_tcp,
                concurrency=arguments.concurrency,
                timeout_seconds=arguments.timeout_seconds,
                web_mark=arguments.web_mark,
                scan_intent=arguments.scan_intent,
                priority=arguments.priority,
                wait_seconds=arguments.wait_seconds,
                result_limit=arguments.result_limit,
            )

        async def output(arguments: BaseModel) -> Any:
            assert isinstance(arguments, NetworkOutputArguments)
            return await self._client.output(
                task_id=arguments.task_id,
                cursor=arguments.cursor,
                limit=arguments.limit,
                wait_seconds=arguments.wait_seconds,
                filters=arguments.filters,
            )

        async def stop(arguments: BaseModel) -> Any:
            assert isinstance(arguments, NetworkStopArguments)
            return await self._client.stop(task_id=arguments.task_id)

        return [
            ToolSpec("system_network_discovery", "Discover live hosts, ports, and services. Preserve task_id and poll instead of replaying a scan.", NetworkDiscoveryArguments, discovery, lambda arguments: (AccessClaim("write", f"network-new:{id(arguments)}"),)),
            ToolSpec("system_network_output", "Poll progress and structured results for an existing network task without starting traffic.", NetworkOutputArguments, output, self._task_read),
            ToolSpec("system_network_stop", "Stop an owned queued or running network task while preserving results.", NetworkStopArguments, stop, self._task_write),
        ]

    @staticmethod
    def _task_read(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("read", f"network-task:{arguments.task_id}"),)

    @staticmethod
    def _task_write(arguments: BaseModel) -> tuple[AccessClaim, ...]:
        return (AccessClaim("write", f"network-task:{arguments.task_id}"),)

    async def close(self) -> None:
        return None
