"""Pure matcher evaluation over one persisted HTTP response."""

from __future__ import annotations

from typing import Any

from .models import BoolNode, ExprNode, MatchNode


def matcher_to_json(node: ExprNode) -> dict[str, Any]:
    if isinstance(node, MatchNode):
        return {"type": "match", "kind": node.kind, "value": node.value, "header": node.header}
    return {"type": "bool", "op": node.op, "left": matcher_to_json(node.left), "right": matcher_to_json(node.right)}


def matcher_from_json(value: dict[str, Any]) -> ExprNode:
    if value.get("type") == "match" and value.get("kind") in {"status", "body_contains", "header_contains"}:
        return MatchNode(value["kind"], value.get("value"), header=value.get("header"))
    if value.get("type") == "bool" and value.get("op") in {"and", "or"}:
        return BoolNode(value["op"], matcher_from_json(value["left"]), matcher_from_json(value["right"]))
    raise ValueError("invalid persisted matcher")


def evaluate(node: ExprNode, response: dict[str, Any], body: bytes | None) -> tuple[str, list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []

    def one(item: ExprNode) -> bool | None:
        if isinstance(item, BoolNode):
            left = one(item.left)
            right = one(item.right)
            if item.op == "and":
                if left is False or right is False:
                    return False
                if left is None or right is None:
                    return None
                return True
            if left is True or right is True:
                return True
            if left is None or right is None:
                return None
            return False
        if response.get("outcome") != "response":
            evidence.append({"kind": item.kind, "result": "inconclusive", "reason": response.get("outcome", "unknown")})
            return None
        if item.kind == "status":
            actual = response.get("status_code")
            result = actual == item.value
            evidence.append({"kind": "status", "expected": item.value, "actual": actual, "matched": result})
            return result
        if item.kind == "header_contains":
            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
            actual = headers.get(str(item.header).lower())
            if actual is None and str(item.header).lower() == "set-cookie":
                cookies = response.get("set_cookie_headers") or []
                actual = "\n".join(str(value) for value in cookies) if cookies else None
            result = actual is not None and str(item.value) in actual
            evidence.append({"kind": "header_contains", "header": item.header, "expected": item.value, "actual": actual, "matched": result})
            return result
        if body is None or not response.get("body_complete", False):
            evidence.append({"kind": "body_contains", "expected": item.value, "result": "inconclusive", "reason": "body_missing_or_truncated"})
            return None
        expected = str(item.value).encode("utf-8")
        result = expected in body
        evidence.append({"kind": "body_contains", "expected": item.value, "body_bytes": len(body), "matched": result})
        return result

    result = one(node)
    return ("matched" if result is True else "not_matched" if result is False else "inconclusive"), evidence
