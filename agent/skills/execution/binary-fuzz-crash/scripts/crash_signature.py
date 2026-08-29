#!/usr/bin/env python3
"""Create a stable signature for one supplied crash log or report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ADDRESS = re.compile(rb"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,16}\b")
LINE = re.compile(rb"(:|line\s+)\d+")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("crash", type=Path)
    parser.add_argument("--max-bytes", type=int, default=256_000)
    args = parser.parse_args()
    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")
    try:
        raw = args.crash.read_bytes()[: args.max_bytes]
    except OSError as exc:
        parser.error(str(exc))
    normalized = ADDRESS.sub(b"ADDR", raw)
    normalized = LINE.sub(rb"\1LINE", normalized)
    digest = hashlib.sha256(normalized).hexdigest()
    print(
        json.dumps(
            {
                "path": str(args.crash.resolve()),
                "bytes_examined": len(raw),
                "truncated": len(raw) == args.max_bytes,
                "signature": digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
