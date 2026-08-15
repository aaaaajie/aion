"""Small Runtime admission driver for standalone HTTP/Network manager tests."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from agent.state import ResourceController, StateService


class ResourceRuntimePump:
    def __init__(
        self,
        service: StateService,
        run_id: str,
        *,
        root: Path,
        http_manager: Any = None,
        network_manager: Any = None,
        controller: ResourceController | None = None,
    ) -> None:
        self.service = service
        self.run_id = run_id
        self.http_manager = http_manager
        self.network_manager = network_manager
        self.controller = controller or ResourceController(
            service, run_id, storage_root=root
        )
        self._closed = False
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while not self._closed:
            item = await self.controller.next_queued_resource_work_item()
            if item is None:
                await asyncio.sleep(0.001)
                continue
            decision = await self.controller.admit_resource_work(
                item["id"], sample={"cpu_percent": 0.0, "memory_percent": 0.0}
            )
            if decision.get("status") != "reserved":
                await asyncio.sleep(0.001)
                continue
            claim = await self.controller.claim_resource_work(item["id"])
            if not claim.get("claimed"):
                continue
            try:
                if item["owner_type"] == "http_interaction":
                    await self.http_manager.launch_work(
                        item["owner_id"], item["phase"], work_id=item["id"]
                    )
                elif item["owner_type"] == "network_task":
                    await self.network_manager.launch_queued(
                        item["owner_id"], work_id=item["id"]
                    )
                else:
                    await self.service.update_resource_work(
                        self.run_id, item["id"], status="queued"
                    )
                    await asyncio.sleep(0.001)
                    continue
                await self.controller.mark_resource_started(item["id"])
            except Exception:
                await self.controller.finish_resource_work(
                    item["id"], status="failed", reason="test_resource_start_failed"
                )

    async def close(self) -> None:
        self._closed = True
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)


def install_resource_runtime(
    manager: Any,
    service: StateService,
    run_id: str,
    *,
    root: Path,
    controller: ResourceController | None = None,
) -> ResourceRuntimePump:
    pump = ResourceRuntimePump(
        service,
        run_id,
        root=root,
        http_manager=manager if hasattr(manager, "launch_work") else None,
        network_manager=manager if hasattr(manager, "launch_queued") else None,
        controller=controller,
    )
    original_finish = manager.finish_run
    original_pause = manager.pause_run

    async def finish_run() -> None:
        await pump.close()
        await original_finish()

    async def pause_run() -> None:
        await pump.close()
        await original_pause()

    manager.finish_run = finish_run
    manager.pause_run = pause_run
    return pump
