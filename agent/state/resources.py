"""Shared challenge-container capacity semantics."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


RELEASED_CONTAINER_STATUSES = frozenset({"stopped", "closed"})
ACTIVE_CHALLENGE_WORK_STATUSES = frozenset({"active", "warning", "extended"})
MAX_CHALLENGE_SLOTS = 3


def container_slot_occupied(status: object) -> bool:
    """Treat every state except an explicit release as occupying a slot."""

    normalized = str(status or "").strip()
    return normalized not in RELEASED_CONTAINER_STATUSES


def challenge_work_active(challenge: Mapping[str, Any] | object) -> bool:
    """Return whether one challenge is actively consuming exploration time."""

    if isinstance(challenge, Mapping):
        status = challenge.get("container_status")
        work_status = challenge.get("work_status")
        completed = challenge.get("is_completed")
    else:
        status = getattr(challenge, "container_status", None)
        work_status = getattr(challenge, "work_status", None)
        completed = getattr(challenge, "is_completed", False)
    return (
        container_slot_occupied(status)
        and str(work_status or "") in ACTIVE_CHALLENGE_WORK_STATUSES
        and not bool(completed)
    )


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
    limit: int = MAX_CHALLENGE_SLOTS,
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


def challenge_start_gate(
    challenges: Iterable[Mapping[str, Any]],
    unique_code: str,
    *,
    limit: int = MAX_CHALLENGE_SLOTS,
) -> dict[str, Any]:
    """Evaluate the authoritative gate for starting one challenge container."""

    values = list(challenges)
    challenge = next(
        (item for item in values if item.get("unique_code") == unique_code),
        None,
    )
    if challenge is None:
        return {
            "allowed": False,
            "reason": "challenge_not_found",
            "container_capacity": container_capacity_summary(values, limit=limit),
        }

    capacity = container_capacity_summary(values, limit=limit)
    slot_occupied = (
        bool(challenge["slot_occupied"])
        if "slot_occupied" in challenge
        else container_slot_occupied(challenge.get("container_status"))
    )
    allowed = slot_occupied or (
        int(capacity["occupied_count"]) < limit
    )
    return {
        "allowed": allowed,
        "reason": None if allowed else "challenge_slots_exhausted",
        "container_capacity": capacity,
    }
