"""Payload-free, process-local signals for persisted state changes."""

from __future__ import annotations

import asyncio
from collections import defaultdict


class StateSignalBus:
    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._generations: dict[str, int] = defaultdict(int)

    async def current(self, key: str) -> int:
        async with self._condition:
            return self._generations[key]

    async def notify(self, key: str, sequence: int) -> int:
        async with self._condition:
            self._generations[key] = max(self._generations[key], sequence)
            self._condition.notify_all()
            return self._generations[key]

    async def wait(self, key: str, after_sequence: int, timeout: float) -> int:
        async with self._condition:
            if self._generations[key] > after_sequence:
                return self._generations[key]
            try:
                await asyncio.wait_for(
                    self._condition.wait_for(
                        lambda: self._generations[key] > after_sequence
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                pass
            return self._generations[key]


__all__ = ["StateSignalBus"]
