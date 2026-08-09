"""Small clock helpers shared by scheduling tests and production code."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def active_seconds(
    *,
    now: datetime,
    active_since: datetime | None,
    accumulated_seconds: int = 0,
) -> int:
    if active_since is None:
        return max(0, accumulated_seconds)
    return max(0, accumulated_seconds + int((aware(now) - aware(active_since)).total_seconds()))
