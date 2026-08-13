"""Ephemeral, role-scoped capabilities for one Agent process."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from threading import RLock

from .schemas import CapabilityContext


@dataclass(frozen=True)
class Capability:
    token: str
    context: CapabilityContext


class CapabilityRegistry:
    """Keep capability tokens out of durable state and model messages.

    Tokens are intentionally process-local. A restarted process must issue new
    capabilities after it has restored the authoritative SQLite state.
    """

    def __init__(self) -> None:
        self._items: dict[str, CapabilityContext] = {}
        self._lock = RLock()

    def issue(
        self,
        run_id: str | CapabilityContext,
        agent_id: str | None = None,
        role: str | None = None,
        unique_code: str | None = None,
    ) -> Capability:
        if isinstance(run_id, CapabilityContext):
            context = run_id
        else:
            if not agent_id or not role:
                raise ValueError("agent_id and role are required")
            context = CapabilityContext(
                run_id=run_id,
                agent_id=agent_id,
                role=role,  # type: ignore[arg-type]
                unique_code=unique_code,
            )
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._items[token] = context
        return Capability(token=token, context=context)

    create = issue

    def resolve(self, token: str | None) -> CapabilityContext | None:
        if not token:
            return None
        with self._lock:
            return self._items.get(token)

    def revoke(self, token: str) -> None:
        with self._lock:
            self._items.pop(token, None)

    def revoke_agent(self, run_id: str, agent_id: str) -> None:
        with self._lock:
            for token, context in list(self._items.items()):
                if context.run_id == run_id and context.agent_id == agent_id:
                    self._items.pop(token, None)

    def __len__(self) -> int:
        return len(self._items)


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
