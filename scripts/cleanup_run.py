"""Reclaim one explicitly selected Run without starting any model or Agent."""

import argparse
import asyncio
import json
from pathlib import Path
import re
import sqlite3
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

from agent.container_cleanup import cleanup_offline
from agent.deadline import before
from agent.run_ownership import RunOwnership
from scripts.online_runtime import _benchmark_from_token, _read_benchmark_token


async def cleanup(args):
    if args.env_file:
        load_dotenv(args.env_file, override=False)
    benchmark = _benchmark_from_token(_read_benchmark_token(args.benchmark_token_file))
    deadline = asyncio.get_running_loop().time() + 30
    ownership = None
    try:
        ownership = RunOwnership(args.run_root / "platform.sqlite3")
        result = await before(cleanup_offline(benchmark, args.run_root, args.workspace_root,
                                             run_id=args.run_id, deadline=deadline), deadline)
        print(json.dumps(result, ensure_ascii=False))
        return 1 if result["unreleased"] else 0
    except Exception as exc:
        print(json.dumps({"error_code": getattr(exc, "code", type(exc).__name__),
                          "message": "Cleanup not confirmed; no Agents started.",
                          "unreleased": unconfirmed_targets(args.run_root, args.run_id)}, ensure_ascii=False))
        return 1
    finally:
        try:
            try:
                await before(benchmark.close(), deadline)
            except Exception:
                pass
        finally:
            if ownership:
                ownership.close()


def unconfirmed_targets(run_root, run_id):
    if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}", run_id) or run_id == "latest":
        return None
    path = Path(run_root) / run_id / "state.sqlite3"
    if not path.is_file():
        return None
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            return [{"run_id": run_id, "unique_code": code, "container_status": status}
                    for code, status in db.execute("SELECT unique_code,container_status FROM challenges WHERE container_status NOT IN ('stopped','closed')")]
    except sqlite3.Error:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--benchmark-token-file", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()
    try:
        raise SystemExit(asyncio.run(cleanup(args)))
    except Exception as exc:
        print(json.dumps({"error_code": getattr(exc, "code", type(exc).__name__),
                          "message": "Cleanup not confirmed; no Agents started. Inspect release_pending records."}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
