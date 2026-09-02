"""Lazy Caido client lifecycle and serialized calls for one AION run."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from tools.system.policy import SystemToolError

from . import caido_api


T = TypeVar("T")


class CaidoProxyManager:
    """Share one lazy Caido client while keeping GraphQL transport calls ordered."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        project_name: str = "aion-proxy",
        client: Any | None = None,
    ) -> None:
        self.base_url = (base_url or caido_api.caido_url()).rstrip("/")
        self.token = token if token is not None else os.environ.get("AION_CAIDO_TOKEN")
        self.project_name = project_name
        self._client = client
        self._closed = False
        self._lock = asyncio.Lock()

    async def call(self, operation: Callable[[Any], Awaitable[T]]) -> T:
        # ponytail: one global lock matches Caido's non-concurrent GraphQL
        # transport; split locks only if the SDK gains independent transports.
        async with self._lock:
            client = await self._get_client()
            return await operation(client)

    async def initialize(self) -> None:
        """Prepare the run project before browser or shell traffic starts."""

        async with self._lock:
            await self._get_client()

    async def finish_run(self) -> None:
        await self.close()

    async def pause_run(self) -> None:
        await self.close()

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            client = self._client
            self._client = None
            self._closed = True
            if client is not None:
                close = getattr(client, "aclose", None)
                if close is not None:
                    await close()

    async def _get_client(self) -> Any:
        if self._closed:
            raise SystemToolError(
                error_type="internal",
                code="proxy_manager_closed",
                message="The HTTP proxy manager is not active",
            )
        if self._client is not None:
            return self._client
        try:
            client = await caido_api.connect_client(
                self.base_url,
                token=self.token,
            )
            await caido_api.ensure_project_with_client(client, self.project_name)
        except Exception as exc:
            if "client" in locals():
                close = getattr(client, "aclose", None)
                if close is not None:
                    await close()
            raise SystemToolError(
                error_type="execution",
                code="proxy_backend_unavailable",
                message="The Caido HTTP proxy backend is not available",
                detail={
                    "base_url": self.base_url,
                    "cause": type(exc).__name__,
                },
            ) from exc
        self._client = client
        return client
