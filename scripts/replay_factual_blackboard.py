"""Read-only legacy trace projection; never trusts or rewrites historical Agent claims."""

import argparse
import json
import sqlite3
from pathlib import Path

from agent.experiment_records import tool_record
from agent.execution_facts import EXECUTION_TOOLS, HTTP_TASK_TOOLS, TASK_TOOLS


def replay_experiments(rows):
    calls, records = {}, []
    for row in rows:
        payload = row["payload"]
        if row["event_type"] == "tool_call":
            calls[(row["agent_id"], payload.get("tool_call_id"))] = payload.get("arguments", {})
        elif row["event_type"] == "tool_result":
            tool = payload.get("tool_name")
            if tool not in EXECUTION_TOOLS | HTTP_TASK_TOOLS | TASK_TOOLS or payload.get("replayed"):
                continue
            record = tool_record(tool, calls.get((row["agent_id"], payload.get("tool_call_id")), {}),
                                 payload.get("result", {}))
            record["source_sequence"] = row["sequence"]
            records.append(record)
    return records


def replay_database(path, run_id, unique_code):
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = [{"sequence": seq, "agent_id": owner, "event_type": kind, "payload": json.loads(payload)}
                for seq, owner, kind, payload in db.execute(
                    "SELECT sequence,agent_id,event_type,payload FROM state_events WHERE run_id=? "
                    "AND agent_id IN (SELECT agent_id FROM agents WHERE run_id=? AND unique_code=?) ORDER BY sequence",
                    (run_id, run_id, unique_code))]
    return replay_experiments(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--challenge", default="a-14")
    args = parser.parse_args()
    records = replay_database(args.database, args.run_id, args.challenge)
    statuses = {}
    for r in records:
        outputs = [r["output"], *r["output"].get("results", [])]
        for output in outputs:
            if output.get("status_code") is not None:
                key = str(output["status_code"])
                statuses[key] = statuses.get(key, 0) + 1
    print(json.dumps({"challenge": args.challenge, "records": len(records),
        "status_observations": statuses,
        "unknown_actual_input": sum(r["executed_input"].get("availability") == "unknown" for r in records),
        "note": "Read-only projection of available trace. Truncated/absent raw artifacts remain unknown; counts are observations, not unique requests."},
        ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
