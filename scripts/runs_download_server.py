#!/usr/bin/env python3
"""Read-only HTTP server for the AION run data directory.

Authentication and TLS are intentionally handled by the local Nginx proxy.  This
process only binds to loopback and refuses requests that resolve outside the run
root, including symlink escapes.
"""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import posixpath
from pathlib import Path
import urllib.parse


class RunsRequestHandler(SimpleHTTPRequestHandler):
    server_version = "AION-Runs-Download/1.0"
    root: Path

    def __init__(self, *args: object, root: Path, **kwargs: object) -> None:
        self.root = root
        super().__init__(*args, directory=str(root), **kwargs)

    def translate_path(self, path: str) -> str:
        parsed = urllib.parse.urlsplit(path)
        decoded = urllib.parse.unquote(parsed.path)
        normalized = posixpath.normpath(decoded)
        relative = normalized.lstrip("/")
        candidate = self.root.joinpath(*relative.split("/")) if relative else self.root
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError:
            return str(self.root / ".aion-forbidden-path")
        return str(resolved)

    def _reject_mutation(self) -> None:
        self.send_error(405, "Method Not Allowed")

    do_POST = _reject_mutation
    do_PUT = _reject_mutation
    do_PATCH = _reject_mutation
    do_DELETE = _reject_mutation
    do_OPTIONS = _reject_mutation

    def log_message(self, format: str, *args: object) -> None:
        # Nginx records the authenticated client and requested path.  Keep the
        # backend log useful without ever logging Authorization headers.
        super().log_message(format, *args)


class RunsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"run root does not exist: {root}")
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    server = RunsHTTPServer(
        (args.bind, args.port),
        lambda *request_args, **request_kwargs: RunsRequestHandler(
            *request_args, root=root, **request_kwargs
        ),
    )
    print(f"serving {root} on {args.bind}:{args.port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
