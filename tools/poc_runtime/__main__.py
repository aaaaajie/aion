"""Maintainer CLI for the restricted Tscan POC pilot."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .adapter import PocAdapterError, load_poc
from .index import build_index
from .runner import run_document
from .yak_audit import audit_database


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.poc_runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="validate one POC without sending HTTP")
    inspect.add_argument("--poc", required=True, type=Path)
    run = sub.add_parser("run", help="execute one supported POC against one target")
    run.add_argument("--poc", required=True, type=Path)
    run.add_argument("--target", required=True)
    run.add_argument("--output", required=True, type=Path)
    yak = sub.add_parser("yak-audit", help="inventory a Yakit SQLite database read-only")
    yak.add_argument("--database", required=True, type=Path)
    yak.add_argument("--output", required=True, type=Path)
    index = sub.add_parser("index", help="build a deterministic read-only POC index package")
    index.add_argument("--source", action="append", required=True, metavar="NAME=PATH")
    index.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "yak-audit":
        try:
            print(json.dumps(audit_database(args.database, args.output), ensure_ascii=False, indent=2))
            return 0
        except Exception as exc:
            print(json.dumps({"error": {"code": "input_error", "message": str(exc)}}, ensure_ascii=False), file=sys.stderr)
            return 2
    if args.command == "index":
        sources: list[tuple[str, str]] = []
        try:
            for item in args.source:
                if "=" not in item or not item.split("=", 1)[0].strip() or not item.split("=", 1)[1].strip():
                    raise ValueError("--source must be NAME=PATH")
                name, path = item.split("=", 1)
                sources.append((name.strip(), path.strip()))
            print(json.dumps(build_index(sources, args.output), ensure_ascii=False, indent=2))
            return 0
        except Exception as exc:
            print(json.dumps({"error": {"code": "input_error", "message": str(exc)}}, ensure_ascii=False), file=sys.stderr)
            return 2
    try:
        document = load_poc(args.poc)
    except PocAdapterError as exc:
        payload = {"supported": False, "error": exc.as_dict()}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2
    if args.command == "inspect":
        print(json.dumps({"supported": True, "source_format": document.source_format, "path": document.path, "sha256": document.sha256, "rule_name": document.rule_name, "name": document.name, "model_version": document.model_version, "request": {"method": document.request.method, "path": document.request.path, "headers": document.request.headers, "body_bytes": len(document.request.body.encode()) if document.request.body is not None else 0, "follow_redirects": document.request.follow_redirects}, "expression": document.expression}, ensure_ascii=False, indent=2))
        return 0
    try:
        result = asyncio.run(run_document(document, target=args.target, output=args.output))
    except Exception as exc:
        print(json.dumps({"status": "inconclusive", "error": {"code": "execution_error", "message": str(exc)}}, ensure_ascii=False, indent=2))
        return 3
    print(json.dumps({"status": result.status, "interaction_id": result.interaction_id, "request_id": result.request_id, "evidence": result.evidence, "error": result.error}, ensure_ascii=False, indent=2))
    return 0 if result.status in {"matched", "not_matched"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
