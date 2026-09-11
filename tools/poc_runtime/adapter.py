"""Strict Tscan YAML adapter.

This module deliberately accepts a narrow subset. It never evaluates a POC
expression and never fills in a missing success condition.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Mapping

import yaml

from .models import BoolNode, ExprNode, MatchNode, HttpRequest, PocDocument

_CALL_RE = re.compile(r"response\.body\.(bcontains|contains)\(")
_HEADER_RE = re.compile(
    r"response\.headers\[\s*(['\"])(?P<header>[^'\"]+)\1\s*\]\.contains\("
)
_STATUS_RE = re.compile(r"response\.status\s*(?P<op>==|!=)\s*(?P<value>[0-9]+)")
_CONTENT_TYPE_RE = re.compile(r"response\.content_type\.contains\(")


class PocAdapterError(ValueError):
    """An input POC is outside the statically supported execution subset."""

    def __init__(self, code: str, message: str, *, path: str = "$") -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader variant that refuses silent duplicate-key replacement."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise PocAdapterError("non_string_key", "YAML mapping key is not scalar") from exc
            if duplicate:
                raise PocAdapterError("duplicate_key", f"duplicate YAML key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _single_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise PocAdapterError("invalid_type", "expected a string", path=path)
    return value


def _literal(text: str, path: str) -> str:
    try:
        value = ast.literal_eval(text)
    except (SyntaxError, ValueError) as exc:
        raise PocAdapterError("invalid_literal", "matcher literal is invalid", path=path) from exc
    if not isinstance(value, (str, bytes)):
        raise PocAdapterError("invalid_literal", "matcher literal must be a string or bytes", path=path)
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PocAdapterError("invalid_literal", "matcher bytes must be UTF-8", path=path) from exc
    return value


def _split_boolean(text: str) -> tuple[str, str, str] | None:
    depth = 0
    quote: str | None = None
    escaped = False
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            i += 1
            continue
        if char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and text[i : i + 2] in {"&&", "||"}:
            return text[:i].strip(), text[i : i + 2], text[i + 2 :].strip()
        i += 1
    if quote or depth != 0:
        return None
    return None


def _unwrap(text: str) -> str:
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        quote: str | None = None
        escaped = False
        complete = True
        for i, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and i != len(text) - 1:
                    complete = False
                    break
        if complete and depth == 0 and not quote:
            text = text[1:-1].strip()
        else:
            break
    return text


def _parse_match(text: str, path: str) -> MatchNode:
    text = text.strip()
    status = _STATUS_RE.fullmatch(text)
    if status:
        value = int(status.group("value"))
        if status.group("op") == "!=":
            raise PocAdapterError("unsupported_operator", "status != is outside http-basic-v1", path=path)
        return MatchNode("status", value)

    body = _CALL_RE.match(text)
    if body:
        prefix = body.group(1)
        if prefix != "bcontains":
            raise PocAdapterError("unsupported_matcher", "body matcher must be bcontains", path=path)
        rest = text[body.end() :]
        if not rest.endswith(")"):
            raise PocAdapterError("invalid_expression", "body matcher is not fully closed", path=path)
        literal = _literal(rest[:-1].strip(), path)
        return MatchNode("body_contains", literal)

    header = _HEADER_RE.match(text)
    if header:
        rest = text[header.end() :]
        if not rest.endswith(")"):
            raise PocAdapterError("invalid_expression", "header matcher is not fully closed", path=path)
        return MatchNode("header_contains", _literal(rest[:-1].strip(), path), header=header.group("header").lower())

    content_type = _CONTENT_TYPE_RE.match(text)
    if content_type:
        rest = text[content_type.end() :]
        if not rest.endswith(")"):
            raise PocAdapterError("invalid_expression", "content type matcher is not fully closed", path=path)
        return MatchNode("header_contains", _literal(rest[:-1].strip(), path), header="content-type")

    raise PocAdapterError(
        "unsupported_expression",
        "only status ==, response.body.bcontains, response.headers[].contains and response.content_type.contains are supported",
        path=path,
    )


def parse_expression(expression: str, *, path: str = "expression") -> ExprNode:
    if not isinstance(expression, str) or not expression.strip():
        raise PocAdapterError("missing_match_condition", "rule expression is required", path=path)

    def parse(text: str) -> ExprNode:
        text = _unwrap(text.strip())
        # Split at the last top-level operator so && has higher precedence than ||.
        parts: list[tuple[int, str]] = []
        depth = 0
        quote: str | None = None
        escaped = False
        for i, char in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif depth == 0 and text[i : i + 2] in {"&&", "||"}:
                parts.append((i, text[i : i + 2]))
        if parts:
            index, operator = parts[-1]
            left = parse(text[:index])
            right = parse(text[index + 2 :])
            return BoolNode("and" if operator == "&&" else "or", left, right)
        return _parse_match(text, path)

    return parse(expression)


def _has_template(value: str) -> bool:
    return "{{" in value or "}}" in value or "${" in value or "{{" in value


def _request(rule: Mapping[str, Any], *, path: str) -> HttpRequest:
    request = rule.get("request")
    if not isinstance(request, Mapping):
        raise PocAdapterError("missing_request", "rule.request must be a mapping", path=f"{path}.request")
    allowed = {"method", "path", "headers", "body", "follow_redirects", "cache"}
    unknown = sorted(set(request) - allowed)
    if unknown:
        raise PocAdapterError("unknown_request_field", f"unsupported request field: {unknown[0]}", path=f"{path}.request.{unknown[0]}")
    method = _single_string(request.get("method"), f"{path}.request.method").upper()
    if method not in {"GET", "POST"}:
        raise PocAdapterError("unsupported_method", "only GET and POST are supported", path=f"{path}.request.method")
    path_value = _single_string(request.get("path"), f"{path}.request.path")
    if not path_value.startswith("/") or _has_template(path_value) or "\\" in path_value:
        raise PocAdapterError("dynamic_or_invalid_path", "path must be a static origin-relative path", path=f"{path}.request.path")
    headers = request.get("headers", {})
    if not isinstance(headers, Mapping) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()):
        raise PocAdapterError("invalid_headers", "headers must be a string-to-string mapping", path=f"{path}.request.headers")
    if any(_has_template(v) for v in headers.values()):
        raise PocAdapterError("dynamic_header", "header values cannot contain variables", path=f"{path}.request.headers")
    body = request.get("body")
    if body is not None:
        body = _single_string(body, f"{path}.request.body")
        if _has_template(body):
            raise PocAdapterError("dynamic_body", "body cannot contain variables", path=f"{path}.request.body")
    follow = request.get("follow_redirects", False)
    if not isinstance(follow, bool):
        raise PocAdapterError("invalid_redirect_setting", "follow_redirects must be boolean", path=f"{path}.request.follow_redirects")
    if request.get("cache", False) not in {False, True}:
        raise PocAdapterError("invalid_cache_setting", "cache must be boolean", path=f"{path}.request.cache")
    return HttpRequest(method, path_value, dict(headers), body, follow)


def load_poc_text(raw: bytes | str, *, path: str = "<memory>", document_index: int = 0) -> PocDocument:
    """Parse one packaged POC without trusting the source filesystem path."""
    file_path = Path(path)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PocAdapterError("invalid_encoding", "POC must be UTF-8 YAML") from exc
    try:
        documents = list(yaml.load_all(text, Loader=_StrictLoader))
    except PocAdapterError:
        raise
    except yaml.YAMLError as exc:
        raise PocAdapterError("invalid_yaml", str(exc)) from exc
    if len(documents) != 1 or not isinstance(documents[0], Mapping):
        raise PocAdapterError("invalid_document", "execution accepts exactly one YAML mapping")
    value = documents[0]
    if any(not isinstance(key, str) for key in value):
        raise PocAdapterError("non_string_key", "top-level YAML keys must be strings")
    keys = set(value)
    if "transport" in value or "set" in value:
        source_format = "xray"
    elif isinstance(value.get("rules"), Mapping):
        source_format = "afrog"
    else:
        raise PocAdapterError("unsupported_format", "only Afrog and Xray mapping rules are executable")
    allowed_top = {
        "id", "name", "binding", "manual", "info", "detail", "transport", "set", "rules", "expression"
    }
    unknown_top = sorted(keys - allowed_top)
    if unknown_top:
        raise PocAdapterError("unknown_top_level_field", f"unsupported top-level field: {unknown_top[0]}", path=f"$.{unknown_top[0]}")
    rules = value.get("rules")
    if not isinstance(rules, Mapping) or len(rules) != 1:
        raise PocAdapterError("multiple_requests", "execution accepts exactly one named rule")
    rule_name, rule = next(iter(rules.items()))
    if not isinstance(rule_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", rule_name):
        raise PocAdapterError("invalid_rule_name", "rule name is invalid", path="$.rules")
    if not isinstance(rule, Mapping):
        raise PocAdapterError("invalid_rule", "rule must be a mapping", path=f"$.rules.{rule_name}")
    top_expression = value.get("expression")
    if not isinstance(top_expression, str) or top_expression.strip() != f"{rule_name}()":
        raise PocAdapterError("top_expression_not_single_rule", "top expression must call the only rule exactly once", path="$.expression")
    expression = rule.get("expression")
    if not isinstance(expression, str):
        raise PocAdapterError("missing_match_condition", "rule expression is required", path=f"$.rules.{rule_name}.expression")
    allowed_rule = {"request", "expression"}
    unknown_rule = sorted(set(rule) - allowed_rule)
    if unknown_rule:
        raise PocAdapterError("unsupported_rule_field", f"unsupported rule field: {unknown_rule[0]}", path=f"$.rules.{rule_name}.{unknown_rule[0]}")
    request = _request(rule, path=f"$.rules.{rule_name}")
    matcher = parse_expression(expression, path=f"$.rules.{rule_name}.expression")
    metadata = value.get("info") or value.get("detail") or {}
    name = metadata.get("name") if isinstance(metadata, Mapping) and isinstance(metadata.get("name"), str) else value.get("name")
    return PocDocument(source_format, str(file_path), digest, document_index, rule_name, name if isinstance(name, str) else None, request, expression, matcher)


def load_poc(path: str | Path, *, document_index: int = 0) -> PocDocument:
    file_path = Path(path)
    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise PocAdapterError("read_error", str(exc)) from exc
    return load_poc_text(raw, path=str(file_path), document_index=document_index)


def load_document_text(path: str | Path) -> str:
    """Return a bounded human-readable source preview for inspect output."""
    data = Path(path).read_bytes()
    return data[:4096].decode("utf-8", errors="replace")
