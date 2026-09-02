"""Small JSON predicate evaluator used by audit-time verification."""

from __future__ import annotations

from typing import Any, Mapping


def evaluate_predicate(node: Mapping[str, Any], world: Mapping[str, Any]) -> Any:
    op = node["op"]
    if op == "field":
        return world[node["name"]]
    if op == "const":
        return node["value"]
    if op == "and":
        return all(bool(evaluate_predicate(item, world)) for item in node["args"])
    if op == "or":
        return any(bool(evaluate_predicate(item, world)) for item in node["args"])
    left = evaluate_predicate(node["left"], world)
    right = evaluate_predicate(node["right"], world)
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "gt":
        return left > right
    raise ValueError(f"unsupported predicate operation: {op}")
