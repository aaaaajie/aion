"""Static, non-executing audit of Afrog, Xray, fscan and Nuclei POCs.

The auditor deliberately stops at syntax and semantic inventory.  It never
opens a socket, starts a child process, evaluates an expression, or converts a
template into an executable request.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import time
from typing import Any, Iterable, Iterator, Mapping, Sequence

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


AUDIT_VERSION = "http-basic-v1"
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
MAX_DIAGNOSTIC_CHARS = 600
MAX_EXAMPLES_PER_REASON = 3
YAML_SUFFIXES = frozenset({".yaml", ".yml"})
TARGET_PLACEHOLDERS = frozenset({"BaseURL", "RootURL", "Hostname", "Host"})
PROTOCOL_KEYS = frozenset(
    {"http", "requests", "dns", "tcp", "headless", "ssl", "websocket", "whois", "file", "javascript", "code", "flow"}
)
SAFE_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:timestamp",
        "tag:yaml.org,2002:binary",
        "tag:yaml.org,2002:merge",
    }
)
EXPR_TOKEN_RE = re.compile(
    r'(?P<string>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    r'|(?P<field>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)'
    r'|(?P<function>[A-Za-z_]\w*)\s*\('
    r'|(?P<operator>===|!==|==|!=|>=|<=|&&|\|\||[><+*/%!&|=-])'
)
INTERPOLATION_RE = re.compile(r"\{\{\s*([A-Za-z_][\w.-]*)\s*\}\}")
RULE_CALL_RE = re.compile(r"\b(r\d+)\s*\(")
KNOWN_FUNCTIONS = frozenset(
    {
        "bytes", "string", "bcontains", "contains", "icontains", "regex", "len",
        "randomInt", "randInt", "md5", "sha1", "sha256", "base64", "urlencode",
        "toLower", "toUpper", "startsWith", "endsWith", "int", "json", "submatch",
    }
)


@dataclass(frozen=True)
class AuditLimits:
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_nodes: int = DEFAULT_MAX_NODES


@dataclass(frozen=True)
class SourceConfig:
    name: str
    root: Path


@dataclass
class DocumentAnalysis:
    format_name: str = "unknown"
    classification: str = "unknown_format"
    identifiers: dict[str, Any] = field(default_factory=dict)
    semantic: dict[str, Any] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    positions: dict[str, dict[str, int]] = field(default_factory=dict)


class AuditFailure(Exception):
    """Configuration, traversal or output failure; distinct from bad POCs."""


def _short(value: Any, limit: int = MAX_DIAGNOSTIC_CHARS) -> str:
    text = str(value).replace("\x00", "\\0")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _line(mark: Any) -> dict[str, int]:
    return {"line": int(mark.line) + 1, "column": int(mark.column) + 1}


def _yaml_files(root: Path) -> Iterator[Path]:
    if root.is_file() or root.is_symlink():
        yield root
        return
    def onerror(error: OSError) -> None:
        raise error

    for directory, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            yield Path(directory) / name


def _parse_source(raw: str) -> SourceConfig:
    if "=" not in raw:
        raise AuditFailure(f"source must use NAME=PATH: {raw}")
    name, value = raw.split("=", 1)
    name, value = name.strip(), value.strip()
    if not name or not value:
        raise AuditFailure(f"source name and path are required: {raw}")
    root = Path(value).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    root = root.absolute()
    if root.is_symlink():
        raise AuditFailure(f"source must not be a symlink: {root}")
    if not root.is_file() and not root.is_dir():
        raise AuditFailure(f"source is not a file or directory: {root}")
    return SourceConfig(name=name, root=root)


def _node_inventory(node: Node, limits: AuditLimits) -> tuple[list[dict[str, Any]], dict[str, dict[str, int]], int, int]:
    issues: list[dict[str, Any]] = []
    positions: dict[str, dict[str, int]] = {}
    nodes = 0
    max_depth = 0
    active: set[int] = set()

    def walk(current: Node, path: str, depth: int) -> None:
        nonlocal nodes, max_depth
        marker = id(current)
        if marker in active:
            issues.append({"code": "recursive_alias", "path": path, **_line(current.start_mark)})
            return
        active.add(marker)
        nodes += 1
        max_depth = max(max_depth, depth)
        if nodes > limits.max_nodes:
            active.remove(marker)
            return
        if depth > limits.max_depth:
            issues.append({"code": "max_depth_exceeded", "path": path, **_line(current.start_mark)})
            active.remove(marker)
            return
        if current.tag not in SAFE_YAML_TAGS:
            issues.append({"code": "custom_or_unsupported_tag", "tag": current.tag, "path": path, **_line(current.start_mark)})
        if isinstance(current, MappingNode):
            seen: set[str] = set()
            for key_node, value_node in current.value:
                key_path = path + "." + str(key_node.value) if isinstance(key_node, ScalarNode) else path + ".<non-string-key>"
                if not isinstance(key_node, ScalarNode) or key_node.tag != "tag:yaml.org,2002:str":
                    issues.append({"code": "non_string_key", "path": key_path, **_line(key_node.start_mark)})
                    key = _short(getattr(key_node, "value", ""), 80)
                else:
                    key = str(key_node.value)
                    if key in seen:
                        issues.append({"code": "duplicate_key", "key": key, "path": key_path, **_line(key_node.start_mark)})
                    seen.add(key)
                    positions[key_path.lstrip(".")] = _line(key_node.start_mark)
                walk(key_node, key_path + ".<key>", depth + 1)
                walk(value_node, key_path, depth + 1)
        elif isinstance(current, SequenceNode):
            for index, child in enumerate(current.value):
                walk(child, f"{path}[{index}]", depth + 1)
        active.remove(marker)

    walk(node, "$", 1)
    if nodes > limits.max_nodes:
        issues.append({"code": "max_nodes_exceeded", "nodes": nodes, "path": "$", **_line(node.start_mark)})
    return issues, positions, nodes, max_depth


def _find_cycles(value: Any) -> bool:
    active: set[int] = set()
    visited: set[int] = set()

    def walk(item: Any) -> bool:
        if not isinstance(item, (dict, list, tuple, set)):
            return False
        marker = id(item)
        if marker in active:
            return True
        if marker in visited:
            return False
        active.add(marker)
        children = item.values() if isinstance(item, dict) else item
        result = any(walk(child) for child in children)
        active.remove(marker)
        visited.add(marker)
        return result

    return walk(value)


def _mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) and all(isinstance(key, str) for key in value) else None


def _detect_format(value: Mapping[str, Any]) -> tuple[str, list[str]]:
    keys = set(value)
    signatures: list[str] = []
    rules = value.get("rules")
    if {"id", "info", "rules"} <= keys and isinstance(rules, Mapping):
        signatures.append("afrog")
    if {"id", "info"} <= keys and keys.intersection({"http", "requests"}):
        signatures.append("nuclei")
    if {"name", "transport", "rules"} <= keys and isinstance(rules, Mapping):
        signatures.append("xray")
    if "name" in keys and (isinstance(rules, list) or "groups" in keys):
        signatures.append("fscan")
    if len(signatures) == 1:
        return signatures[0], signatures
    if len(signatures) > 1:
        return "mixed", signatures
    return "unknown", signatures


def _walk_dicts(value: Any, path: str = "$") -> Iterator[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        yield path, value
        for key, child in value.items():
            yield from _walk_dicts(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_dicts(child, f"{path}[{index}]")


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def _path_is_static(value: Any, *, allow_target_placeholders: bool) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    placeholders = INTERPOLATION_RE.findall(value)
    if not placeholders:
        return True
    if not allow_target_placeholders:
        return False
    return all(item in TARGET_PLACEHOLDERS for item in placeholders)


def _expression_info(expressions: Iterable[str]) -> dict[str, Any]:
    functions: Counter[str] = Counter()
    fields: Counter[str] = Counter()
    operators: Counter[str] = Counter()
    literals = 0
    unknown: set[str] = set()
    rule_calls: Counter[str] = Counter()
    snippets: list[str] = []
    unknown_snippets: list[str] = []
    for expression in expressions:
        text = str(expression)
        snippet = _short(text, 180)
        snippets.append(snippet)
        rule_calls.update(RULE_CALL_RE.findall(text))
        expression_has_unknown = False
        for match in EXPR_TOKEN_RE.finditer(text):
            kind, token = match.lastgroup, match.group(match.lastgroup)
            if kind == "string":
                literals += 1
            elif kind == "function":
                functions[token] += 1
                if token not in KNOWN_FUNCTIONS and not token.startswith("r"):
                    unknown.add(token)
                    expression_has_unknown = True
            elif kind == "field":
                fields[token] += 1
            elif kind == "operator":
                operators[token] += 1
        if expression_has_unknown:
            unknown_snippets.append(snippet)
    return {
        "expression_count": len(snippets),
        "functions": dict(sorted(functions.items())),
        "fields": dict(sorted(fields.items())),
        "operators": dict(sorted(operators.items())),
        "literal_count": literals,
        "rule_calls": dict(sorted(rule_calls.items())),
        "unknown_functions": sorted(unknown),
        "snippets": snippets[:3],
        "unknown_snippets": unknown_snippets[:3],
    }


def _semantic(value: Mapping[str, Any], format_name: str) -> dict[str, Any]:
    protocols = sorted(str(key) for key in PROTOCOL_KEYS if key in value)
    requests: list[dict[str, Any]] = []
    expressions: list[str] = []
    rule_expressions: list[str] = []
    extractors: list[str] = []
    feature_keys: set[str] = set()
    unknown_execution_fields: set[str] = set()
    methods: Counter[str] = Counter()
    paths: list[str] = []
    bodies = 0
    headers = 0
    known_request_fields = {
        "method", "path", "paths", "url", "urls", "body", "data", "headers", "header",
        "request", "expression", "dsl", "matchers", "matcher", "matchers-condition", "extractors",
        "extractor", "output", "search", "raw", "variables", "set", "payloads", "attack", "timeout", "redirects",
        "max-redirects", "stop-at-first-match", "host-redirects", "cookie-reuse", "unsafe", "follow_redirects",
    }
    for path, item in _walk_dicts(value):
        execution_container = bool(re.search(r"\.(?:http|requests)\[\d+\]$", path) or re.search(r"\.rules(?:\[\d+\]|\.r\d+)$", path))
        for key, child in item.items():
            key_text = str(key)
            lower = key_text.casefold()
            if lower in {"expression", "dsl"} and isinstance(child, str):
                expressions.append(child)
                if path != "$":
                    rule_expressions.append(child)
            if lower in {"extractors", "extractor", "output", "search"}:
                extractors.append(f"{path}.{key_text}")
            if lower in {"set", "variables", "payloads", "attack", "code", "script", "scripts", "flow", "interactsh", "oob", "raw", "external"}:
                feature_keys.add(lower)
            header_like = lower in {
                "accept", "authorization", "cache-control", "connection", "content-length", "content-type",
                "cookie", "host", "origin", "referer", "user-agent", "x-forwarded-for", "x-requested-with",
            } or lower.startswith(("content-", "x-"))
            if execution_container and lower not in known_request_fields and not header_like:
                unknown_execution_fields.add(f"{path}.{key_text}")
            if lower in {"method"} and isinstance(child, str):
                methods[child.upper()] += 1
            if lower in {"path", "paths", "url", "urls"}:
                if isinstance(child, str):
                    paths.append(child)
                elif isinstance(child, list):
                    paths.extend(str(item) for item in child)
            if lower in {"body", "data"}:
                bodies += 1
            if lower in {"headers", "header"}:
                headers += 1
        if "method" in item or "path" in item or "paths" in item or "url" in item or "urls" in item:
            raw_path_values = item.get("path") if "path" in item else item.get("paths")
            if isinstance(raw_path_values, list):
                path_values: Any = [_short(path, 600) for path in raw_path_values]
            elif raw_path_values is None:
                path_values = None
            else:
                path_values = _short(raw_path_values, 600)
            request = {
                "path": path,
                "method": str(item.get("method", "GET")).upper() if item.get("method") else None,
                "path_values": path_values,
                "has_body": any(key in item for key in ("body", "data")),
                "has_headers": any(key in item for key in ("headers", "header")),
            }
            requests.append(request)
    declared: set[str] = set()
    if isinstance(value.get("set"), Mapping):
        declared.update(str(key) for key in value["set"])
    if isinstance(value.get("variables"), Mapping):
        declared.update(str(key) for key in value["variables"])
    if not protocols and requests:
        protocols = ["http"]
    if not protocols and value.get("transport") == "http":
        protocols = ["http"]
    references = sorted(set(name for text in _strings(value) for name in INTERPOLATION_RE.findall(text)))
    unresolved = sorted(set(references) - declared - TARGET_PLACEHOLDERS)
    dependency_keys = sorted(feature_keys)
    return {
        "protocols": protocols,
        "request_count": len(requests),
        "requests": requests[:100],
        "methods": dict(sorted(methods.items())),
        "path_count": len(paths),
        "paths": [_short(path, 300) for path in paths[:100]],
        "body_count": bodies,
        "header_count": headers,
        "declared_variables": sorted(declared),
        "interpolated_variables": references,
        "unresolved_variables": unresolved,
        "extractor_fields": sorted(extractors),
        "feature_keys": dependency_keys,
        "unknown_execution_fields": sorted(unknown_execution_fields),
        "expressions": _expression_info(expressions),
        "rule_expression_count": len(rule_expressions),
    }


def _cycles(value: Mapping[str, Any]) -> list[list[str]]:
    declarations: dict[str, set[str]] = {}
    for key in ("set", "variables"):
        data = value.get(key)
        if isinstance(data, Mapping):
            for name, expression in data.items():
                declarations[str(name)] = set(INTERPOLATION_RE.findall(str(expression)))
    cycles: list[list[str]] = []
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(name: str) -> None:
        state[name] = 1
        stack.append(name)
        for child in sorted(declarations.get(name, set())):
            if child not in declarations:
                continue
            if state.get(child) == 1:
                cycles.append(stack[stack.index(child):] + [child])
            elif state.get(child, 0) == 0:
                visit(child)
        stack.pop()
        state[name] = 2

    for name in sorted(declarations):
        if state.get(name, 0) == 0:
            visit(name)
    return cycles


def _basic_candidate(value: Mapping[str, Any], format_name: str, semantic: Mapping[str, Any]) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    if format_name not in {"afrog", "xray", "fscan", "nuclei"}:
        blockers.append("unsupported_format")
    if len(semantic["protocols"]) != 1 or semantic["protocols"][0] not in {"http", "requests"}:
        blockers.append("non_http_protocol_or_missing_protocol")
    if semantic["request_count"] != 1:
        blockers.append("multiple_or_missing_requests")
    if semantic["feature_keys"]:
        for key in semantic["feature_keys"]:
            blockers.append({"set": "dynamic_variables", "variables": "dynamic_variables", "payloads": "payload_expansion", "attack": "payload_expansion", "code": "script_or_code", "script": "script_or_code", "scripts": "script_or_code", "flow": "complex_control_flow", "interactsh": "oob_callback", "oob": "oob_callback", "raw": "raw_http", "external": "external_dependency"}.get(key, f"unsupported_feature:{key}"))
    if semantic["extractor_fields"]:
        blockers.append("response_extraction")
    if semantic.get("unknown_execution_fields"):
        blockers.append("unknown_execution_field")
    if semantic["unresolved_variables"]:
        blockers.append("unresolved_variables")
    if semantic["expressions"]["unknown_functions"]:
        blockers.append("unknown_expression_function")
    has_nuclei_matchers = False
    if format_name == "nuclei":
        matcher_types: list[str] = []
        for _path, item in _walk_dicts(value):
            matchers = item.get("matchers") or item.get("matcher")
            if matchers is None:
                continue
            has_nuclei_matchers = True
            values = matchers if isinstance(matchers, list) else [matchers]
            for matcher in values:
                if not isinstance(matcher, Mapping):
                    blockers.append("unknown_matcher_shape")
                    continue
                matcher_type = matcher.get("type")
                if not isinstance(matcher_type, str) or not matcher_type.strip():
                    blockers.append("unknown_matcher_type")
                else:
                    matcher_types.append(matcher_type.casefold())
        unsupported_matchers = sorted(set(matcher_types) - {"status", "word"})
        blockers.extend(f"unsupported_matcher_type:{item}" for item in unsupported_matchers)
    if (semantic["rule_expression_count"] == 0 if format_name != "nuclei" else not has_nuclei_matchers):
        blockers.append("missing_match_condition")
    if format_name in {"afrog", "xray"}:
        top_expression = value.get("expression")
        rules = value.get("rules")
        rule_names = sorted(str(name) for name in rules) if isinstance(rules, Mapping) else []
        expected_call = f"{rule_names[0]}()" if len(rule_names) == 1 else None
        if not isinstance(top_expression, str) or expected_call is None or top_expression.strip() != expected_call:
            blockers.append("top_expression_not_single_rule")
        if not isinstance(rules, Mapping) or len(rules) != 1:
            blockers.append("top_expression_not_single_rule")
        elif isinstance(next(iter(rules.values())), Mapping):
            rule = next(iter(rules.values()))
            request = rule.get("request")
            if not isinstance(request, Mapping):
                blockers.append("missing_request")
            else:
                allowed_request = {"method", "path", "headers", "body", "follow_redirects", "cache"}
                blockers.extend(f"unsupported_request_field:{key}" for key in sorted(set(request) - allowed_request))
                for field in ("headers", "body"):
                    content = request.get(field)
                    if field == "headers":
                        if content is not None and (not isinstance(content, Mapping) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in content.items())):
                            blockers.append("non_static_headers")
                        elif isinstance(content, Mapping) and any("{{" in value or "${" in value for value in content.values()):
                            blockers.append("dynamic_headers")
                    elif content is not None and (not isinstance(content, str) or "{{" in content or "${" in content):
                        blockers.append("dynamic_body")
    if format_name == "nuclei":
        if not has_nuclei_matchers:
            blockers.append("missing_match_condition")
        for key in ("code", "javascript", "headless", "dns", "tcp", "ssl", "websocket", "flow"):
            if key in value:
                blockers.append(f"unsupported_protocol:{key}")
    for request in semantic["requests"]:
        path_values = request.get("path_values")
        values = path_values if isinstance(path_values, list) else [path_values]
        if not values or any(not _path_is_static(path, allow_target_placeholders=(format_name == "nuclei")) for path in values):
            blockers.append("dynamic_or_missing_path")
        method = request.get("method")
        if method not in {"GET", "POST"}:
            blockers.append("unsupported_http_method")
    return not blockers, sorted(set(blockers))


def _identifiers(value: Mapping[str, Any], format_name: str) -> dict[str, Any]:
    info = value.get("info") if isinstance(value.get("info"), Mapping) else {}
    metadata = info if info else value.get("detail") if isinstance(value.get("detail"), Mapping) else {}
    if not isinstance(metadata, Mapping):
        metadata = {}
    identifier = value.get("id") or value.get("name")
    references = metadata.get("reference") or metadata.get("references") or metadata.get("links")
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        references = []
    severity = metadata.get("severity") or metadata.get("level")
    tags = metadata.get("tags")
    if isinstance(tags, list):
        tags = [_short(item, 160) for item in tags]
    cve_text = " ".join(_strings(value))
    cves = sorted(set(re.findall(r"\b(?:CVE|CNVD|CNNVD|GHSA)-[A-Za-z0-9.-]+", cve_text)))
    return {
        "id": _short(identifier, 200) if identifier is not None else None,
        "name": _short(metadata.get("name") or value.get("name") or identifier, 300),
        "severity": _short(severity, 80) if severity is not None else None,
        "tags": tags if isinstance(tags, (str, list)) else None,
        "cves": cves,
        "references": [_short(item, 500) for item in references[:30]],
        "metadata_source": "info" if info else "detail" if value.get("detail") else "top_level",
        "format": format_name,
    }


def _analyze_document(value: Any, node: Node, document_index: int, positions: dict[str, dict[str, int]]) -> DocumentAnalysis:
    result = DocumentAnalysis()
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        result.classification = "unknown_format"
        result.blockers = ["document_not_mapping"]
        return result
    format_name, signatures = _detect_format(value)
    result.format_name = format_name
    result.positions = positions
    result.identifiers = _identifiers(value, format_name)
    semantic = _semantic(value, format_name)
    semantic["format_signatures"] = signatures
    semantic["variable_cycles"] = _cycles(value)
    result.semantic = semantic
    candidate, blockers = _basic_candidate(value, format_name, semantic)
    result.blockers = blockers
    result.classification = "candidate_basic_http" if candidate else "requires_semantic_support" if format_name != "unknown" else "unknown_format"
    if semantic["variable_cycles"]:
        result.blockers.append("variable_cycle")
        result.classification = "requires_semantic_support"
    return result


def _inspect_yaml(text: str, limits: AuditLimits) -> tuple[list[Node], list[dict[str, Any]], list[dict[str, dict[str, int]]], list[int]]:
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        return [], [{"code": "yaml_parse_error", "message": _short(exc)}], [], []
    if not nodes:
        return [], [{"code": "empty_document"}], [], []
    issues: list[dict[str, Any]] = []
    positions: list[dict[str, dict[str, int]]] = []
    counts: list[int] = []
    depths: list[int] = []
    for node in nodes:
        if node is None:
            issues.append({"code": "empty_document"})
            positions.append({})
            counts.append(0)
            depths.append(0)
            continue
        node_issues, node_positions, count, depth = _node_inventory(node, limits)
        issues.extend(node_issues)
        positions.append(node_positions)
        counts.append(count)
        depths.append(depth)
    return nodes, issues, positions, counts


def _record_file(source: SourceConfig, path: Path, status: str, digest: str, size: int, reason: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "file",
        "source": source.name,
        "path": _relative(source.root, path),
        "sha256": digest,
        "size_bytes": size,
        "suffix": path.suffix.casefold(),
        "parse_status": status,
    }
    if reason:
        record["reason"] = reason
    return record


def _record_invalid_document(
    source: SourceConfig,
    path: Path,
    digest: str,
    document_index: int,
    blockers: Sequence[str],
    positions: Mapping[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "document",
        "source": source.name,
        "path": _relative(source.root, path),
        "document_index": document_index,
        "sha256": digest,
        "format": "unknown",
        "classification": "invalid_document",
        "identifiers": {},
        "semantic": {},
        "blockers": sorted(set(blockers)),
        "positions": dict(positions or {}),
    }


def _write_report(output: Path, records: Sequence[dict[str, Any]], summary: dict[str, Any]) -> None:
    try:
        output.mkdir(parents=True)
        (output / "records.jsonl").write_text(
            "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output / "report.md").write_text(_markdown_report(summary), encoding="utf-8")
    except OSError as exc:
        raise AuditFailure(f"cannot write audit report: {exc}") from exc


def _markdown_report(summary: Mapping[str, Any]) -> str:
    counts = summary["classification_counts"]
    coverage = summary["coverage"]
    lines = [
        "# AION POC Static Compatibility Audit",
        "",
        f"- Audit version: `{summary['audit_version']}`",
        f"- Complete: `{summary['complete']}`",
        f"- Sources: {', '.join(item['name'] for item in summary['sources'])}",
        "",
        "## Counts",
        "",
        f"- Files enumerated: {summary['files_enumerated']}",
        f"- YAML documents: {summary['yaml_documents']}",
        f"- Valid documents: {summary['valid_documents']}",
        f"- Recognized valid documents: {summary['recognized_valid_documents']}",
        f"- Duplicate content files: {summary['duplicate_content_files']}",
        f"- Duplicate ID conflicts: {summary['duplicate_id_conflicts']['count']}",
        "",
        "| Classification | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| `{key}` | {value} |" for key, value in sorted(counts.items()))
    lines.extend([
        "",
        "## Candidate coverage",
        "",
        f"- All YAML documents: {coverage['candidate_documents']} / {coverage['yaml_documents']} ({coverage['all_yaml_ratio']:.4f})",
        f"- Valid documents: {coverage['candidate_documents']} / {coverage['valid_documents']} ({coverage['valid_document_ratio']:.4f})",
        f"- Recognized valid documents: {coverage['candidate_documents']} / {coverage['recognized_valid_documents']} ({coverage['recognized_valid_document_ratio']:.4f})",
        f"- SHA-256 deduplicated YAML files: {coverage['deduplicated']['candidate_files']} / {coverage['deduplicated']['yaml_files']} ({coverage['deduplicated']['candidate_all_yaml_ratio']:.4f})",
        "",
        "These are static implementation candidates, not executable templates or confirmed vulnerabilities.",
        "",
        "## Main blockers",
        "",
    ])
    for reason, item in sorted(summary["blocker_examples"].items()):
        lines.append(f"- `{reason}` ({item['count']}): " + "; ".join(example["path"] + (f" — {example['snippet']}" if example.get("snippet") else "") for example in item["examples"]))
    lines.extend([
        "",
        "## Next implementation priorities",
        "",
        "1. Basic single-request HTTP matcher and status/header/body evidence.",
        "2. Literal variable interpolation and one-step response extraction.",
        "3. Multi-request dependencies, payload expansion and dialect-specific expressions.",
        "",
        "No requests, expressions, scripts or external resources were executed by this audit.",
        "",
    ])
    return "\n".join(lines)


def audit_sources(sources: Sequence[SourceConfig], output: Path, limits: AuditLimits | None = None) -> dict[str, Any]:
    limits = limits or AuditLimits()
    if not sources:
        raise AuditFailure("at least one source is required")
    names = [source.name for source in sources]
    if len(names) != len(set(names)):
        raise AuditFailure("source names must be unique")
    raw_output = output.expanduser()
    if raw_output.exists() or raw_output.is_symlink():
        raise AuditFailure(f"output directory already exists: {raw_output}")
    output = raw_output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        raise AuditFailure(f"output directory already exists: {output}")
    for source in sources:
        if output == source.root or source.root in output.parents or output in source.root.parents:
            raise AuditFailure("output directory must be outside every source")
    started = time.monotonic()
    records: list[dict[str, Any]] = []
    classification_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    blocker_examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    content_hashes: dict[str, list[str]] = defaultdict(list)
    ids: dict[str, list[tuple[str, str]]] = defaultdict(list)
    files_enumerated = yaml_documents = valid_documents = recognized_valid_documents = 0
    yaml_hashes: set[str] = set()
    valid_hashes: set[str] = set()
    recognized_hashes: set[str] = set()
    candidate_hashes: set[str] = set()
    source_summaries: list[dict[str, Any]] = []
    incomplete = False
    for source in sources:
        source_started = time.monotonic()
        source_files = 0
        source_yaml = 0
        source_digest = hashlib.sha256()
        try:
            paths = list(_yaml_files(source.root))
        except OSError as exc:
            incomplete = True
            raise AuditFailure(f"cannot enumerate source {source.name}: {exc}") from exc
        for path in paths:
            source_files += 1
            files_enumerated += 1
            try:
                stat = path.lstat()
                size = int(stat.st_size)
                digest = _sha256(path) if path.is_file() and not path.is_symlink() else ""
                source_digest.update(f"{_relative(source.root, path)}\0{size}\0{digest}\n".encode())
                if path.is_symlink():
                    records.append(_record_file(source, path, "skipped", digest, size, "symlink_not_followed"))
                    continue
                if not path.is_file():
                    records.append(_record_file(source, path, "skipped", digest, size, "not_regular_file"))
                    continue
                content_hashes[digest].append(f"{source.name}:{_relative(source.root, path)}")
                if path.suffix.casefold() not in YAML_SUFFIXES:
                    records.append(_record_file(source, path, "skipped", digest, size, "non_yaml_file"))
                    continue
                source_yaml += 1
                yaml_hashes.add(digest)
                if size > limits.max_file_bytes:
                    records.append(_record_file(source, path, "invalid", digest, size, "file_size_limit"))
                    yaml_documents += 1
                    classification_counts["invalid_document"] += 1
                    records.append(_record_invalid_document(source, path, digest, 0, ["file_size_limit"]))
                    blocker_counts["file_size_limit"] += 1
                    blocker_examples["file_size_limit"].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": None})
                    continue
                raw = path.read_text(encoding="utf-8")
                nodes, issues, positions, _counts = _inspect_yaml(raw, limits)
                if issues:
                    records.append(_record_file(source, path, "invalid", digest, size, issues[0].get("code", "yaml_invalid")))
                    for issue in issues:
                        blocker_counts[str(issue.get("code", "yaml_invalid"))] += 1
                        blocker_examples[str(issue.get("code", "yaml_invalid"))].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": _short(issue.get("message") or issue.get("key") or issue.get("tag"), 160)})
                    document_count = max(1, len(nodes))
                    yaml_documents += document_count
                    issue_codes = [str(issue.get("code", "yaml_invalid")) for issue in issues]
                    for document_index in range(document_count):
                        classification_counts["invalid_document"] += 1
                        records.append(
                            _record_invalid_document(
                                source,
                                path,
                                digest,
                                document_index,
                                issue_codes,
                                positions[document_index] if document_index < len(positions) else {},
                            )
                        )
                    continue
                values = list(yaml.safe_load_all(raw))
                if any(_find_cycles(value) for value in values):
                    reason = "recursive_alias"
                    records.append(_record_file(source, path, "invalid", digest, size, reason))
                    yaml_documents += max(1, len(values))
                    blocker_counts[reason] += 1
                    blocker_examples[reason].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": None})
                    for document_index in range(max(1, len(values))):
                        classification_counts["invalid_document"] += 1
                        records.append(_record_invalid_document(source, path, digest, document_index, [reason]))
                    continue
                file_record = _record_file(source, path, "parsed", digest, size)
                if len(values) > 1:
                    file_record["notice"] = "multi_document"
                    blocker_counts["multi_document"] += 1
                    blocker_examples["multi_document"].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": f"{len(values)} documents"})
                records.append(file_record)
                yaml_documents += len(values)
                for document_index, (value, node) in enumerate(zip(values, nodes)):
                    analysis = _analyze_document(value, node, document_index, positions[document_index])
                    valid_documents += 1
                    valid_hashes.add(digest)
                    if analysis.format_name not in {"unknown", "mixed"}:
                        recognized_valid_documents += 1
                        recognized_hashes.add(digest)
                    classification_counts[analysis.classification] += 1
                    format_counts[analysis.format_name] += 1
                    if analysis.classification == "candidate_basic_http":
                        candidate_hashes.add(digest)
                    for reason in analysis.blockers:
                        blocker_counts[reason] += 1
                        if len(blocker_examples[reason]) < MAX_EXAMPLES_PER_REASON:
                            blocker_examples[reason].append({"path": f"{source.name}:{_relative(source.root, path)}#{document_index}", "snippet": analysis.semantic.get("expressions", {}).get("unknown_snippets", [None])[0] if reason.startswith("unknown_expression") else None})
                    identifier = analysis.identifiers.get("id")
                    if identifier:
                        ids[str(identifier)].append((f"{source.name}:{_relative(source.root, path)}#{document_index}", digest))
                    records.append({
                        "record_type": "document",
                        "source": source.name,
                        "path": _relative(source.root, path),
                        "document_index": document_index,
                        "sha256": digest,
                        "format": analysis.format_name,
                        "classification": analysis.classification,
                        "identifiers": analysis.identifiers,
                        "semantic": analysis.semantic,
                        "blockers": sorted(set(analysis.blockers)),
                        "positions": analysis.positions,
                    })
            except OSError as exc:
                incomplete = True
                records.append(_record_file(source, path, "invalid", "", 0, f"read_error:{type(exc).__name__}"))
                blocker_counts[f"read_error:{type(exc).__name__}"] += 1
                blocker_examples[f"read_error:{type(exc).__name__}"].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": _short(exc)})
            except (UnicodeDecodeError, yaml.YAMLError, ValueError, RecursionError) as exc:
                reason = f"invalid_document:{type(exc).__name__}"
                records.append(_record_file(source, path, "invalid", digest, size, reason))
                yaml_documents += 1
                classification_counts["invalid_document"] += 1
                records.append(_record_invalid_document(source, path, digest, 0, [reason]))
                blocker_counts[reason] += 1
                blocker_examples[reason].append({"path": f"{source.name}:{_relative(source.root, path)}", "snippet": _short(exc)})
        source_summaries.append({"name": source.name, "root": str(source.root), "files": source_files, "yaml_files": source_yaml, "snapshot_sha256": source_digest.hexdigest(), "duration_seconds": round(time.monotonic() - source_started, 6)})
    duplicate_content = {digest: paths for digest, paths in sorted(content_hashes.items()) if len(paths) > 1}
    duplicate_id_conflicts: dict[str, list[dict[str, str]]] = {}
    for identifier, occurrences in sorted(ids.items()):
        hashes = {digest for _path, digest in occurrences}
        if len(occurrences) > 1 and len(hashes) > 1:
            duplicate_id_conflicts[identifier] = [{"path": path, "sha256": digest} for path, digest in occurrences]
    elapsed = time.monotonic() - started
    rss = getattr(resource.getrusage(resource.RUSAGE_SELF), "ru_maxrss", 0)
    peak_rss_bytes = int(rss * 1024 if sys.platform != "darwin" else rss)
    summary: dict[str, Any] = {
        "audit_version": AUDIT_VERSION,
        "complete": not incomplete,
        "limits": {"max_file_bytes": limits.max_file_bytes, "max_depth": limits.max_depth, "max_nodes": limits.max_nodes},
        "sources": source_summaries,
        "files_enumerated": files_enumerated,
        "yaml_documents": yaml_documents,
        "valid_documents": valid_documents,
        "recognized_valid_documents": recognized_valid_documents,
        "invalid_files": sum(1 for item in records if item.get("record_type") == "file" and item.get("parse_status") == "invalid"),
        "classification_counts": dict(sorted(classification_counts.items())),
        "format_counts": dict(sorted(format_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "blocker_examples": {reason: {"count": blocker_counts[reason], "examples": sorted(examples, key=lambda item: item["path"])[:MAX_EXAMPLES_PER_REASON]} for reason, examples in sorted(blocker_examples.items())},
        "duplicate_content_files": sum(len(paths) for paths in duplicate_content.values()),
        "duplicate_content_groups": len(duplicate_content),
        "duplicate_id_conflicts": {"count": len(duplicate_id_conflicts), "ids": duplicate_id_conflicts},
        "coverage": {
            "yaml_documents": yaml_documents,
            "valid_documents": valid_documents,
            "recognized_valid_documents": recognized_valid_documents,
            "candidate_documents": classification_counts.get("candidate_basic_http", 0),
            "all_yaml_ratio": classification_counts.get("candidate_basic_http", 0) / yaml_documents if yaml_documents else 0.0,
            "valid_document_ratio": classification_counts.get("candidate_basic_http", 0) / valid_documents if valid_documents else 0.0,
            "recognized_valid_document_ratio": classification_counts.get("candidate_basic_http", 0) / recognized_valid_documents if recognized_valid_documents else 0.0,
            "deduplicated": {
                "yaml_files": len(yaml_hashes),
                "valid_files": len(valid_hashes),
                "recognized_valid_files": len(recognized_hashes),
                "candidate_files": len(candidate_hashes),
                "candidate_all_yaml_ratio": len(candidate_hashes) / len(yaml_hashes) if yaml_hashes else 0.0,
                "candidate_recognized_valid_ratio": len(candidate_hashes) / len(recognized_hashes) if recognized_hashes else 0.0,
            },
        },
        "runtime": {"duration_seconds": round(elapsed, 6), "peak_rss_bytes": peak_rss_bytes, "network_calls": 0, "child_processes": 0, "expression_evaluations": 0},
    }
    _write_report(output, records, summary)
    return summary


def _markdown_error(message: str) -> str:
    return json.dumps({"complete": False, "error": message}, ensure_ascii=False)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.poc_audit")
    parser.add_argument("--source", action="append", required=True, metavar="NAME=PATH")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES)
    args = parser.parse_args(argv)
    try:
        limits = AuditLimits(args.max_file_bytes, args.max_depth, args.max_nodes)
        if min(limits.max_file_bytes, limits.max_depth, limits.max_nodes) < 1:
            raise AuditFailure("audit limits must be positive")
        sources = [_parse_source(value) for value in args.source]
        summary = audit_sources(sources, args.output, limits)
        print(json.dumps({"ok": True, "output": str(args.output.resolve()), "summary": summary}, ensure_ascii=False, sort_keys=True))
        return 0
    except (AuditFailure, OSError, ValueError) as exc:
        print(_markdown_error(str(exc)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
