"""Deterministic, read-only POC index packages."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .adapter import PocAdapterError, _StrictLoader, load_poc

MAX_CONTENT_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100_000
SCHEMA = """
CREATE TABLE pocs (
  poc_ref TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  source_path TEXT NOT NULL,
  source_id TEXT NOT NULL,
  document_index INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  format TEXT NOT NULL,
  name TEXT,
  severity TEXT,
  cves_json TEXT NOT NULL,
  status TEXT NOT NULL,
  blockers_json TEXT NOT NULL,
  expression TEXT,
  request_json TEXT,
  content TEXT NOT NULL,
  UNIQUE(source, source_path, document_index)
);
CREATE INDEX idx_pocs_search ON pocs(source, format, status);
CREATE INDEX idx_pocs_sha ON pocs(sha256);
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ref(source: str, digest: str, source_id: str, document_index: int, source_path: str = "") -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", source_id).strip("-")[:80] or "document"
    path_tag = hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:12] if source_path else "0" * 12
    return f"{source}:{digest}:{slug}:{document_index}:{path_tag}"


def _metadata(value: Any) -> tuple[str | None, str | None, list[str], str | None]:
    if not isinstance(value, dict):
        return None, None, [], None
    info = value.get("info") if isinstance(value.get("info"), dict) else {}
    detail = value.get("detail") if isinstance(value.get("detail"), dict) else {}
    meta = info or detail
    name = meta.get("name") if isinstance(meta.get("name"), str) else value.get("name")
    severity = meta.get("severity") or meta.get("level")
    severity = str(severity) if severity is not None else None
    text = json.dumps(value, ensure_ascii=False, default=str)
    cves = sorted(set(re.findall(r"\b(?:CVE|CNVD|CNNVD|GHSA)-[A-Za-z0-9.-]+", text)))
    source_id = value.get("id") or value.get("name")
    return (str(source_id) if source_id is not None else None, str(name) if name is not None else None, cves, severity)


def _format(value: Any) -> str:
    if not isinstance(value, dict):
        return "unknown"
    if "transport" in value or "set" in value:
        return "xray"
    if isinstance(value.get("rules"), dict):
        return "afrog"
    if isinstance(value.get("rules"), list) or "groups" in value:
        return "fscan"
    if "http" in value or "http2" in value or "requests" in value:
        return "nuclei"
    return "unknown"


def _safe_documents(raw: bytes) -> list[Any]:
    if len(raw) > MAX_CONTENT_BYTES:
        raise ValueError("max_file_bytes_exceeded")
    text = raw.decode("utf-8")
    nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    count = 0
    active: set[int] = set()

    def walk(node: Node | None, depth: int, path: str) -> None:
        nonlocal count
        if node is None:
            return
        marker = id(node)
        if marker in active:
            raise ValueError(f"recursive_alias at {path}")
        count += 1
        if count > MAX_NODES:
            raise ValueError("max_nodes_exceeded")
        if depth > MAX_DEPTH:
            raise ValueError("max_depth_exceeded")
        active.add(marker)
        if isinstance(node, MappingNode):
            for index, (key, value) in enumerate(node.value):
                if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise ValueError(f"non_string_key at {path}[{index}]")
                walk(key, depth + 1, f"{path}.{key.value}")
                walk(value, depth + 1, f"{path}.{key.value}")
        elif isinstance(node, SequenceNode):
            for index, child in enumerate(node.value):
                walk(child, depth + 1, f"{path}[{index}]")
        active.remove(marker)

    for index, node in enumerate(nodes):
        walk(node, 1, f"$[{index}]")
    return list(yaml.load_all(text, Loader=_StrictLoader))


def _row_from_yaml(source: str, relative: str, path: Path, raw: bytes, index: int, value: Any) -> dict[str, Any]:
    digest = _sha(raw)
    source_id, name, cves, severity = _metadata(value)
    source_id = source_id or f"{relative}#{index}"
    blockers: list[dict[str, str]] = []
    document = None
    if index == 0:
        try:
            # load_poc performs the strict duplicate-key and expression checks.
            document = load_poc(path, document_index=index)
        except Exception:
            document = None
    if document is None:
        blockers.append({"code": "multi_document" if index else "unsupported_or_invalid", "message": "document requires inspect for exact reason"})
        try:
            # Re-read from a temporary in-memory equivalent is intentionally avoided;
            # the source path is retained in the package and the run path rechecks it.
            if index == 0:
                load_poc(path, document_index=index)
        except PocAdapterError as exc:
            blockers = [exc.as_dict()]
        except Exception as exc:
            blockers = [{"code": type(exc).__name__, "message": str(exc)}]
    request_json = None
    expression = None
    if document is not None:
        request_json = json.dumps({"method": document.request.method, "path": document.request.path, "headers": document.request.headers, "body": document.request.body, "follow_redirects": document.request.follow_redirects}, ensure_ascii=False, sort_keys=True)
        expression = document.expression
    return {
        "poc_ref": _ref(source, digest, source_id, index, relative),
        "source": source,
        "source_path": relative,
        "source_id": source_id,
        "document_index": index,
        "sha256": digest,
        "format": _format(value),
        "name": name,
        "severity": severity,
        "cves_json": json.dumps(cves, ensure_ascii=False),
        "status": "supported" if document is not None else "unsupported",
        "blockers_json": json.dumps(blockers, ensure_ascii=False),
        "expression": expression,
        "request_json": request_json,
        "content": raw[:MAX_CONTENT_BYTES].decode("utf-8", errors="replace"),
    }


def _iter_source(source: str, root: Path) -> Iterable[dict[str, Any]]:
    root = root.expanduser().resolve(strict=True)
    if root.is_file() and root.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
        with sqlite3.connect(f"file:{root}?mode=ro", uri=True) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(yak_scripts)")}
            if not columns:
                return
            selected = [name for name in ("id", "script_name", "type", "content", "level", "tags", "local_path") if name in columns]
            query = "SELECT " + ",".join('"' + name + '"' for name in selected) + " FROM yak_scripts ORDER BY id"
            for row in connection.execute(query):
                item = dict(zip(selected, row))
                content = str(item.get("content") or "")
                raw = content.encode("utf-8")
                digest = _sha(raw)
                source_id = str(item.get("id") or item.get("script_name") or digest[:16])
                yield {
                    "poc_ref": _ref(source, digest, source_id, 0, f"{root.name}:yak_scripts/{source_id}"), "source": source,
                    "source_path": f"{root.name}:yak_scripts/{source_id}", "source_id": source_id,
                    "document_index": 0, "sha256": digest, "format": "yak",
                    "name": str(item.get("script_name") or source_id), "severity": str(item.get("level")) if item.get("level") else None,
                    "cves_json": json.dumps(sorted(set(re.findall(r"\bCVE-[0-9-]+\b", content)))),
                    "status": "reference_only", "blockers_json": json.dumps([{"code": "yak_runtime_not_connected", "message": "Yak scripts are indexed for reference and cannot be executed by this entry point"}], ensure_ascii=False),
                    "expression": None, "request_json": None, "content": content[:MAX_CONTENT_BYTES],
                }
        return
    paths = (root,) if root.is_file() else tuple(sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()))
    for path in paths:
        if path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        raw = path.read_bytes()
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        try:
            values = _safe_documents(raw)
        except Exception as exc:
            digest = _sha(raw)
            yield {"poc_ref": _ref(source, digest, relative, 0, relative), "source": source, "source_path": relative, "source_id": relative, "document_index": 0, "sha256": digest, "format": "unknown", "name": relative, "severity": None, "cves_json": "[]", "status": "unsupported", "blockers_json": json.dumps([{"code": type(exc).__name__, "message": str(exc)}]), "expression": None, "request_json": None, "content": raw[:MAX_CONTENT_BYTES].decode("utf-8", errors="replace")}
            continue
        for index, value in enumerate(values):
            yield _row_from_yaml(source, relative, path, raw, index, value)


def build_index(sources: Iterable[tuple[str, str | Path]], output: str | Path) -> dict[str, Any]:
    destination = Path(output).expanduser().resolve()
    if destination.exists() or destination.is_symlink():
        raise ValueError("index output directory must be new")
    resolved_sources = [(name, Path(raw_root).expanduser().resolve(strict=True)) for name, raw_root in sources]
    for _, root in resolved_sources:
        if root == destination or root in destination.parents:
            raise ValueError("index output directory must be outside all input sources")
    rows: list[dict[str, Any]] = []
    source_summary: list[dict[str, Any]] = []
    for name, root in resolved_sources:
        before = len(rows)
        rows.extend(_iter_source(name, root))
        source_summary.append({"name": name, "records": len(rows) - before})
    destination.mkdir(parents=True, mode=0o700)
    db_path = destination / "pocs.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(SCHEMA)
        for row in rows:
            connection.execute("INSERT INTO pocs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(row[key] for key in ("poc_ref", "source", "source_path", "source_id", "document_index", "sha256", "format", "name", "severity", "cves_json", "status", "blockers_json", "expression", "request_json", "content")))
        connection.commit()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    manifest = {"index_version": "aion-poc-index-v1", "sources": source_summary, "records": len(rows), "status_counts": counts, "sha256": _sha(db_path.read_bytes())}
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "report.md").write_text("# AION POC index\n\n" + "\n".join(f"- `{item['name']}`: {item['records']} records" for item in source_summary) + f"\n\nTotal records: {len(rows)}\n\nStatus counts: {json.dumps(counts, ensure_ascii=False, sort_keys=True)}\n", encoding="utf-8")
    checksum_lines = [f"{_sha(db_path.read_bytes())}  pocs.sqlite3", f"{_sha((destination / 'manifest.json').read_bytes())}  manifest.json"]
    (destination / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return manifest


class PocIndex:
    """Read-only view of a built index package."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.db_path = self.root / "pocs.sqlite3"
        if not self.db_path.is_file():
            raise FileNotFoundError(self.db_path)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    def search(self, query: str, *, source: str | None = None, format_name: str | None = None, status: str | None = None, offset: int = 0, limit: int = 10) -> dict[str, Any]:
        if not query.strip():
            raise ValueError("query must not be empty")
        if not 0 <= offset <= 100000 or not 1 <= limit <= 30:
            raise ValueError("invalid pagination")
        terms = [term.casefold() for term in re.findall(r"[^\s]+", query)]
        with self._connection() as connection:
            rows = [dict(row) for row in connection.execute("SELECT * FROM pocs ORDER BY source, source_path, document_index")]
        ranked = []
        for row in rows:
            if source and row["source"] != source or format_name and row["format"] != format_name or status and row["status"] != status:
                continue
            haystack = " ".join(str(row.get(key) or "") for key in ("source_id", "name", "format", "cves_json", "content")).casefold()
            score = sum(1 for term in terms if term in haystack)
            if score == len(terms):
                ranked.append((score, row))
        ranked.sort(key=lambda item: (-item[0], item[1]["source"], item[1]["source_path"], item[1]["document_index"]))
        page = [self._public(row) for _, row in ranked[offset : offset + limit]]
        return {"results": page, "offset": offset, "limit": limit, "total": len(ranked), "next_offset": offset + limit if offset + limit < len(ranked) else None}

    def get(self, poc_ref: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM pocs WHERE poc_ref = ?", (poc_ref,)).fetchone()
        if row is None:
            raise KeyError(poc_ref)
        return self._public(dict(row), include_content=True)

    @staticmethod
    def _public(row: dict[str, Any], *, include_content: bool = False) -> dict[str, Any]:
        result = {"poc_ref": row["poc_ref"], "source": row["source"], "source_path": row["source_path"], "source_id": row["source_id"], "document_index": row["document_index"], "sha256": row["sha256"], "format": row["format"], "name": row["name"], "severity": row["severity"], "cves": json.loads(row["cves_json"]), "status": row["status"], "blockers": json.loads(row["blockers_json"]), "expression": row["expression"], "request": json.loads(row["request_json"]) if row["request_json"] else None}
        if include_content:
            result["content"] = row["content"]
        return result
