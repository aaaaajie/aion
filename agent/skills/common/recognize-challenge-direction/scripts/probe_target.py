#!/usr/bin/env python3
"""Bounded, deterministic protocol evidence probe for one CTF target."""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


MAX_BODY_BYTES = 64 * 1024
MAX_DESCRIPTION_CHARS = 4_000
CONNECT_TIMEOUT_SECONDS = 1.5
TOTAL_TIMEOUT_SECONDS = 5.0
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 8545, 9545}
RPC_PORTS = {8545, 9545}


class ProbeInputError(ValueError):
    """Input is malformed or contains more than one target."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request: Request, *_args: Any, **_kwargs: Any) -> None:
        return None


def _error_result(target: str, code: str, message: str) -> dict[str, Any]:
    return {
        "target": target,
        "reachable": False,
        "access_surface": "unknown",
        "protocol": "unknown",
        "markers": [],
        "direction_candidates": ["unknown"],
        "evidence": [],
        "request_count": 0,
        "error_code": code,
        "error": message,
    }


def _load_input(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeInputError(f"invalid input: {exc}") from exc
    if not isinstance(value, dict):
        raise ProbeInputError("input must be a JSON object")
    target = value.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ProbeInputError("target must be one non-empty string")
    if any(char in target for char in "\r\n,;\x00") or len(target) > 2_048:
        raise ProbeInputError("target must identify exactly one bounded endpoint")
    value["target"] = target.strip()
    value["description"] = str(value.get("description") or "")[:MAX_DESCRIPTION_CHARS]
    value["mode"] = value.get("mode", "auto")
    if value["mode"] != "auto":
        raise ProbeInputError("only mode=auto is supported")
    return value


def _endpoint(target: str) -> tuple[str, str, int, str]:
    raw = target if "://" in target else f"tcp://{target}"
    parsed = urlsplit(raw)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ProbeInputError("target must not contain credentials and must have a host")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "tcp"}:
        raise ProbeInputError("target scheme must be http, https, or a host:port endpoint")
    if parsed.path not in {"", "/"} and scheme == "tcp":
        raise ProbeInputError("raw TCP target must not contain a path")
    default_port = {"http": 80, "https": 443, "tcp": None}[scheme]
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise ProbeInputError("target port is invalid") from exc
    if port is None or not 1 <= port <= 65_535:
        raise ProbeInputError("target must include a valid port for raw TCP")
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return scheme, parsed.hostname, port, path


def _read_limited(stream: Any) -> bytes:
    return stream.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]


def _body_markers(
    text: str, headers: dict[str, str], description: str
) -> tuple[list[str], list[dict[str, str]], list[str]]:
    haystack = "\n".join((description, text, " ".join(headers.values()))).casefold()
    groups = {
        "ai": (
            ("model", "model-api"),
            ("llm", "llm"),
            ("prompt", "prompt"),
            ("system prompt", "system-prompt"),
            ("chat/completions", "model-api"),
            ("embedding", "embedding"),
            ("vector", "vector"),
            ("rag", "rag"),
            ("tool calling", "tool-calling"),
            ("assistant", "chat-interface"),
        ),
        "blockchain": (
            ("solidity", "solidity"),
            ("ethereum", "ethereum"),
            ("json-rpc", "json-rpc"),
            ("eth_chainid", "evm-rpc"),
            ("eth_chain_id", "evm-rpc"),
            ("contract", "contract"),
            ("wallet", "wallet"),
            ("abi", "abi"),
            ("anvil", "anvil"),
        ),
        "binary": (
            ("elf", "elf"),
            ("mach-o", "mach-o"),
            ("pe32", "pe"),
            ("rop", "rop"),
            ("shellcode", "shellcode"),
            ("libc", "libc"),
            ("format string", "format-string"),
            ("gdb", "debugger"),
        ),
        "web": (
            ("sql injection", "sqli"),
            ("cross-site scripting", "xss"),
            ("ssrf", "ssrf"),
            ("html", "html"),
            ("cookie", "cookie"),
            ("login", "login"),
            ("web", "web"),
            ("api", "api"),
        ),
    }
    scores: dict[str, int] = {key: 0 for key in groups}
    evidence: list[dict[str, str]] = []
    for direction, signals in groups.items():
        for token, marker in signals:
            if token in haystack:
                scores[direction] += 3 if direction in {"ai", "blockchain", "binary"} else 2
                evidence.append({"direction": direction, "signal": marker, "source": "probe"})
    ranked = sorted(scores, key=lambda item: (-scores[item], item))
    ranked = [item for item in ranked if scores[item] > 0]
    markers = list(dict.fromkeys(item["signal"] for item in evidence))
    if ranked and scores[ranked[0]] == scores[ranked[-1]] and len(ranked) > 1:
        candidates = ranked
    else:
        candidates = ranked[:3]
    return markers, evidence, candidates or ["unknown"]


def _http_request(
    scheme: str,
    host: str,
    port: int,
    path: str,
    *,
    body: bytes | None = None,
    rpc_method: str | None = None,
) -> tuple[dict[str, Any], str, int]:
    url = f"{scheme}://{host}:{port}{path}"
    headers = {"Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "aion-direction-probe/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
    handlers: list[Any] = [NoRedirectHandler()]
    if scheme == "https":
        handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))
    opener = build_opener(*handlers)
    started = time.monotonic()
    try:
        with opener.open(request, timeout=CONNECT_TIMEOUT_SECONDS) as response:
            raw = _read_limited(response)
            headers_out = {key.casefold(): value for key, value in response.headers.items()}
            status = int(response.status)
            final_url = str(response.geturl())
    except HTTPError as exc:
        raw = _read_limited(exc)
        headers_out = {key.casefold(): value for key, value in exc.headers.items()}
        status = int(exc.code)
        final_url = url
    except (OSError, URLError, ssl.SSLError) as exc:
        raise ConnectionError(str(exc)) from exc
    elapsed_ms = int((time.monotonic() - started) * 1000)
    text = raw.decode("utf-8", errors="replace")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    summary = {
        "url": final_url,
        "status_code": status,
        "content_type": headers_out.get("content-type", ""),
        "title": " ".join(title_match.group(1).split())[:256] if title_match else None,
        "body_bytes": len(raw),
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "elapsed_ms": elapsed_ms,
        "header_features": {
            key: headers_out[key]
            for key in ("server", "location", "x-powered-by")
            if key in headers_out
        },
        "rpc_method": rpc_method,
    }
    return summary, text, status


def _raw_tcp(host: str, port: int) -> tuple[str, bool]:
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS) as connection:
        connection.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            banner = connection.recv(4_096)
        except socket.timeout:
            banner = b""
    return banner.decode("utf-8", errors="replace")[:512], True


def _record_http_result(
    result: dict[str, Any],
    value: dict[str, Any],
    description: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    summary: dict[str, Any],
    text: str,
) -> None:
    result["reachable"] = True
    result["access_surface"] = "https" if scheme == "https" else "http"
    result["protocol"] = scheme
    result["request_count"] = int(result.get("request_count", 0)) + 1
    result["response"] = summary
    headers = summary.get("header_features", {})
    combined = f"{description}\n{text}\n{json.dumps(summary, ensure_ascii=False)}"
    markers, evidence, candidates = _body_markers(combined, headers, description)
    result["markers"] = list(dict.fromkeys([*result["markers"], *markers]))
    result["evidence"] = [*result["evidence"], *evidence]
    result["direction_candidates"] = candidates
    if port not in RPC_PORTS and not any(
        token in combined.casefold() for token in ("json-rpc", "eth_chainid", "ethereum")
    ):
        return
    for method in ("web3_clientVersion", "eth_chainId"):
        if result["request_count"] >= 3 or time.monotonic() > value.get("deadline", float("inf")):
            break
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": result["request_count"],
                "method": method,
                "params": [],
            }
        ).encode()
        try:
            rpc_summary, rpc_text, _ = _http_request(
                scheme, host, port, path, body=body, rpc_method=method
            )
        except ConnectionError:
            break
        result["request_count"] += 1
        result.setdefault("rpc_responses", []).append(rpc_summary)
        markers, evidence, candidates = _body_markers(
            f"{description}\n{rpc_text}", {}, description
        )
        result["markers"] = list(
            dict.fromkeys([*result["markers"], *markers, "evm-rpc"])
        )
        result["evidence"] = [*result["evidence"], *evidence]
        result["direction_candidates"] = [
            "blockchain",
            *[item for item in candidates if item != "blockchain"],
        ]
    result["access_surface"] = "evm_rpc"
    result["protocol"] = "json-rpc"


def probe(value: dict[str, Any]) -> dict[str, Any]:
    target = value["target"]
    description = value.get("description", "")
    scheme, host, port, path = _endpoint(target)
    result: dict[str, Any] = {
        "target": target,
        "reachable": False,
        "access_surface": "https" if scheme == "https" else "http" if scheme == "http" else "raw_tcp",
        "protocol": scheme,
        "markers": [],
        "direction_candidates": ["unknown"],
        "evidence": [],
        "request_count": 0,
        "error_code": None,
    }
    if time.monotonic() > value.get("deadline", float("inf")):
        result["error_code"] = "probe_timeout"
        return result
    if scheme == "tcp":
        try:
            summary, text, _status = _http_request("http", host, port, "/")
        except ConnectionError:
            banner, reachable = _raw_tcp(host, port)
            result["reachable"] = reachable
            result["banner"] = banner
            result["request_count"] = 2
            markers, evidence, candidates = _body_markers(
                f"{description}\n{banner}", {}, description
            )
            result["markers"] = markers
            result["evidence"] = evidence
            result["direction_candidates"] = candidates
            if port in RPC_PORTS:
                result["access_surface"] = "evm_rpc"
            return result
        _record_http_result(
            result, value, description, "http", host, port, "/", summary, text
        )
        return result

    summary, text, _status = _http_request(scheme, host, port, path)
    _record_http_result(
        result, value, description, scheme, host, port, path, summary, text
    )
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: probe_target.py INPUT.json OUTPUT.json", file=sys.stderr)
        return 2
    input_path, output_path = Path(argv[1]), Path(argv[2])
    target = ""
    try:
        value = _load_input(input_path)
        target = value["target"]
        value["deadline"] = time.monotonic() + TOTAL_TIMEOUT_SECONDS
        result = probe(value)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except ProbeInputError as exc:
        result = _error_result(target, "invalid_input", str(exc))
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass
        return 2
    except TimeoutError:
        result = _error_result(target, "probe_timeout", "probe timed out")
        failure_code = 3
    except (ConnectionError, OSError, URLError, ssl.SSLError) as exc:
        result = _error_result(target, "connection_failed", str(exc))
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            return 3
        return 3
    except Exception as exc:  # keep the shell task's result deterministic
        result = _error_result(target, "probe_failed", str(exc))
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return 3
    return failure_code if "failure_code" in locals() else 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
