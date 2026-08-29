#!/usr/bin/env python3
"""Produce a bounded, dependency-free source inventory as JSON."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


EXTENSIONS = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sol": "solidity",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--max-files", type=int, default=2_000)
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"root is not a directory: {root}")
    if args.max_files < 1 or args.max_bytes < 1:
        parser.error("limits must be positive")

    counts: Counter[str] = Counter()
    files: list[dict[str, object]] = []
    total_lines = 0
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if len(files) >= args.max_files:
            break
        if not path.is_file() or any(
            part in {".git", ".aion", ".venv", "__pycache__", "node_modules", "vendor"}
            for part in path.parts
        ):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > args.max_bytes:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        language = EXTENSIONS.get(path.suffix.lower(), "other")
        counts[language] += 1
        total_bytes += len(data)
        total_lines += data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "language": language,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    print(
        json.dumps(
            {
                "root": str(root),
                "files_examined": len(files),
                "files_truncated": len(files) >= args.max_files,
                "bytes_examined": total_bytes,
                "loc_estimate": total_lines,
                "languages": dict(sorted(counts.items())),
                "files": files,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
