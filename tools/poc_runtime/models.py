"""Small internal execution model for the supported Tscan subset."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class HttpRequest:
    method: Literal["GET", "POST"]
    path: str
    headers: dict[str, str]
    body: str | None
    follow_redirects: bool


@dataclass(frozen=True)
class MatchNode:
    kind: Literal["status", "body_contains", "header_contains"]
    value: int | str
    header: str | None = None


@dataclass(frozen=True)
class BoolNode:
    op: Literal["and", "or"]
    left: "ExprNode"
    right: "ExprNode"


ExprNode = MatchNode | BoolNode


@dataclass(frozen=True)
class PocDocument:
    source_format: Literal["afrog", "xray"]
    path: str
    sha256: str
    document_index: int
    rule_name: str
    name: str | None
    request: HttpRequest
    expression: str
    matcher: ExprNode
    model_version: str = "aion-poc-http-v1"


@dataclass(frozen=True)
class PocResponse:
    status: Literal["matched", "not_matched", "inconclusive"]
    interaction_id: str | None
    request_id: str | None
    response: dict[str, Any] | None
    evidence: dict[str, Any]
    error: dict[str, Any] | None = None
