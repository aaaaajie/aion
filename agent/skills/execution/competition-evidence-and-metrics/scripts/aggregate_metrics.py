#!/usr/bin/env python3
"""Aggregate normalized finding records into reconstructable metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("findings", type=Path)
    parser.add_argument("--max-records", type=int, default=10_000)
    args = parser.parse_args()
    if args.max_records < 1:
        parser.error("--max-records must be positive")
    try:
        value: Any = json.loads(args.findings.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    records = value.get("findings") if isinstance(value, dict) else value
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        parser.error("input must be a list of finding objects or {findings: [...]}")
    if len(records) > args.max_records:
        parser.error(f"record count exceeds --max-records={args.max_records}")
    candidates = len(records)
    verified = sum(item.get("verification_status") == "verified" for item in records)
    rejected = sum(item.get("verification_status") == "rejected" for item in records)
    high = sum(
        item.get("verification_status") == "verified"
        and str(item.get("severity", "")).lower() in {"critical", "high"}
        for item in records
    )
    print(
        json.dumps(
            {
                "candidate_count": candidates,
                "verified_count": verified,
                "rejected_count": rejected,
                "inconclusive_count": candidates - verified - rejected,
                "false_positive_rate": round(rejected / candidates, 6) if candidates else None,
                "verified_high_count": high,
                "quality": "complete" if all("verification_status" in item for item in records) else "incomplete",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
