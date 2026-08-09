"""Shared challenge-container capacity semantics."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


RELEASED_CONTAINER_STATUSES = frozenset({"stopped", "closed"})


def container_slot_occupied(status: object) -> bool:
    """Treat every state except an explicit release as occupying a slot."""

    normalized = str(status or "").strip()
    return normalized not in RELEASED_CONTAINER_STATUSES


def checkpoint_target_status(challenge: Mapping[str, Any]) -> str:
    """Project business progress without conflating completion and release."""

    occupied = container_slot_occupied(challenge.get("container_status"))
    completed = bool(challenge.get("is_completed"))
    work_status = str(challenge.get("work_status") or "")
    # Completion is a business result; ``closed`` is an explicit work
    # lifecycle state.  They are intentionally not collapsed in Checkpoint.
    if not occupied and work_status == "closed":
        return "closed"
    if completed or int(challenge.get("correct_flag_count") or 0) > 0:
        return "submitted"
    if occupied:
        return "started"
    return "pending"


def container_capacity_summary(
    challenges: Iterable[Mapping[str, Any]],
    *,
    limit: int = 3,
) -> dict[str, Any]:
    """Build the authoritative slot view exposed to Runtime controllers."""

    values = list(challenges)
    occupied_codes = sorted(
        str(item["unique_code"])
        for item in values
        if isinstance(item.get("unique_code"), str)
        and container_slot_occupied(item.get("container_status"))
    )
    pending_release = sorted(
        str(item["unique_code"])
        for item in values
        if isinstance(item.get("unique_code"), str)
        and bool(item.get("is_completed"))
        and container_slot_occupied(item.get("container_status"))
    )
    occupied_count = len(occupied_codes)
    return {
        "limit": limit,
        "occupied_count": occupied_count,
        "free_count": max(0, limit - occupied_count),
        "occupied_codes": occupied_codes,
        "completed_pending_release_codes": pending_release,
    }
