"""Validate recorded observer outputs offline; never issue model requests."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from agent.observation_models import validate_observation_output


def replay_observation(input_data, diagnostics):
    if diagnostics.get("output_truncated") or "output" not in diagnostics:
        return {"status": "unavailable", "reason": "complete_output_not_recorded"}
    if diagnostics.get("failure_stage") in {"request", "response"}:
        return {"status": "rejected", "stage": diagnostics["failure_stage"]}
    try:
        trimming = {}
        candidate = validate_observation_output(
            diagnostics["output"], input_data["map"], input_data["trace"], diagnostics=trimming, evidence=input_data.get("evidence", [])
        )
    except ValidationError as exc:
        errors = exc.errors(
            include_url=False, include_context=False, include_input=False
        )
        return {
            "status": "rejected",
            "stage": (
                "json" if any(e["type"] == "json_invalid" for e in errors) else "schema"
            ),
            "errors": errors[:16],
        }
    except ValueError:
        return {"status": "rejected", "stage": "sources"}
    return {
        "status": "accepted",
        **trimming,
        "outcome": (
            "empty"
            if not any(candidate.get(key) for key in ("LOCK", "DEAD", "ANGLES", "TENSION"))
            else "unchanged" if candidate == input_data["map"] else "updated"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    with sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT sequence, agent_id, payload FROM state_events "
            "WHERE run_id = ? AND event_type = 'solver_observation_snapshot' ORDER BY sequence",
            (args.run_id,),
        )
        for sequence, agent_id, payload in rows:
            diagnostics = json.loads(payload).get("diagnostics") or {}
            attempt = db.execute(
                "SELECT payload FROM state_events WHERE run_id = ? AND agent_id = ? "
                "AND sequence = ? AND event_type = 'solver_observation_started'",
                (args.run_id, agent_id, diagnostics.get("attempt_sequence")),
            ).fetchone()
            result = (
                replay_observation(json.loads(attempt[0])["input"], diagnostics)
                if attempt
                else {"status": "unavailable", "reason": "input_not_recorded"}
            )
            print(
                json.dumps(
                    {"sequence": sequence, "agent_id": agent_id, **result},
                    ensure_ascii=False,
                )
            )


if __name__ == "__main__":
    main()
