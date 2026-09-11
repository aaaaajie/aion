"""Record every physical model request, including failures and auxiliary calls."""

from __future__ import annotations
import json
from time import monotonic
from uuid import uuid4
from typing import Any
from contextvars import ContextVar

current_model_event_writer = ContextVar("aion_model_event_writer", default=None)

METRICS = ("input_tokens", "cache_hit_tokens", "uncached_input_tokens", "output_tokens")


def usage_values(payload):
    usage = payload.get("usage") if isinstance(payload, dict) else None
    usage = usage if isinstance(usage, dict) else {}
    details = usage.get("prompt_tokens_details")
    details = details if isinstance(details, dict) else {}

    def number(value):
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )

    incoming = number(usage.get("prompt_tokens"))
    cached = number(usage.get("prompt_cache_hit_tokens", details.get("cached_tokens")))
    uncached = number(usage.get("prompt_cache_miss_tokens"))
    if (
        uncached is None
        and incoming is not None
        and cached is not None
        and incoming >= cached
    ):
        uncached = incoming - cached
    return dict(
        zip(
            METRICS,
            (incoming, cached, uncached, number(usage.get("completion_tokens"))),
        )
    )


async def post_model(client, url, *, event_writer=None, purpose="agent", **kwargs):
    event_writer = event_writer or current_model_event_writer.get()
    call_id = "model_" + uuid4().hex
    base = {
        "model_call_id": call_id,
        "purpose": purpose,
        "model": kwargs.get("json", {}).get("model"),
    }

    async def emit(kind, value):
        if event_writer:
            await event_writer(kind, value)

    await emit("model_call_started", base)
    started = monotonic()
    response = None
    error = None
    try:
        response = await client.post(url, **kwargs)
        return response
    except BaseException as exc:
        error = type(exc).__name__
        raise
    finally:
        payload = None
        if response is not None:
            try:
                payload = response.json()
            except (ValueError, UnicodeError):
                pass
        await emit(
            "model_call_finished",
            {
                **base,
                **usage_values(payload),
                "http_status": response.status_code if response is not None else None,
                "error": error,
                "latency_ms": int((monotonic() - started) * 1000),
            },
        )


def aggregate_usage(events, agents):
    """Finished replaces started for the same call; absent usage stays unknown."""
    calls = {}
    for event in events:
        if event["event_type"] not in {"model_call_started", "model_call_finished"}:
            continue
        p = event["payload"]
        if isinstance(p, str):
            p = json.loads(p)
        key = p.get("model_call_id")
        if not key:
            continue
        if key not in calls or event["event_type"] == "model_call_finished":
            calls[key] = {"agent_id": event.get("agent_id"), **p}
    by_id = {a["agent_id"]: a for a in agents}

    def total(rows):
        rows = list(rows)
        result = {
            k: sum(r[k] for r in rows)
            if all(isinstance(r.get(k), int) for r in rows)
            else None
            for k in METRICS
        }
        result["known_totals"] = {
            k: sum(r[k] for r in rows if isinstance(r.get(k), int))
            for k in METRICS
        }
        result["calls"] = len(rows)
        result["calls_with_missing_usage"] = sum(
            any(r.get(k) is None for k in METRICS) for r in rows
        )
        return result

    return {
        "run": total(calls.values()),
        "purposes": {
            purpose: total(c for c in calls.values() if c.get("purpose", "unknown") == purpose)
            for purpose in sorted({c.get("purpose", "unknown") for c in calls.values()})
        },
        "agents": {
            key: total(c for c in calls.values() if c["agent_id"] == key)
            for key in by_id
        },
        "challenges": {
            code: total(
                c
                for c in calls.values()
                if by_id.get(c["agent_id"], {}).get("unique_code") == code
            )
            for code in {a.get("unique_code") for a in agents}
            if code is not None
        },
    }
