"""Validate current facts-only observer outputs offline, without model calls."""

import argparse
import json
import sqlite3
from pathlib import Path

from pydantic import ValidationError
from agent.observation_models import validate_observation_output


def replay_observation(input_data, diagnostics):
    if diagnostics.get("output_truncated") or "output" not in diagnostics:
        return {"status": "unavailable", "reason": "complete_output_not_recorded"}
    if "evidence_refs" not in input_data:
        return {"status": "unavailable", "reason": "not_a_factual_observer_input"}
    try:
        advice = validate_observation_output(diagnostics["output"], input_data["evidence_refs"])
    except ValidationError:
        return {"status": "rejected", "stage": "schema"}
    except ValueError:
        return {"status": "rejected", "stage": "sources"}
    return {"status": "accepted", "outcome": "advice" if any(advice.values()) else "empty"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    with sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True) as db:
        for sequence, agent_id, payload in db.execute(
            "SELECT sequence,agent_id,payload FROM state_events WHERE run_id=? "
            "AND event_type='solver_observation_snapshot' ORDER BY sequence", (args.run_id,)):
            snapshot = json.loads(payload)
            if "advice" not in snapshot or snapshot["advice"] is None:
                result = {"status": "unavailable", "reason": "factual_advice_not_recorded"}
            else:
                result = replay_observation({"evidence_refs": snapshot["evidence_refs"]},
                    {"output": json.dumps(snapshot["advice"])})
            print(json.dumps({"sequence": sequence, "agent_id": agent_id, **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
