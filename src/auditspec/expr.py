from __future__ import annotations

import ast
import operator
from functools import lru_cache
from typing import Any, Mapping


class UnsafeExpression(ValueError):
    pass


_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
}
_CMP = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


@lru_cache(maxsize=512)
def _parse(expression: str) -> ast.AST:
    return ast.parse(expression, mode="eval").body


def evaluate(expression: str, world: Mapping[str, Any]) -> Any:
    """Evaluate a deliberately small, side-effect-free expression language."""
    return _eval(_parse(expression), world)


def referenced_names(expression: str) -> frozenset[str]:
    """Return variable names referenced by a safe expression.

    Parsing and evaluation share the same cached AST. Callers still validate the
    returned names against the declared fact catalog.
    """

    return frozenset(
        node.id for node in ast.walk(_parse(expression)) if isinstance(node, ast.Name)
    )


def _eval(node: ast.AST, env: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise UnsafeExpression(f"Unknown variable: {node.id}")
        return env[node.id]
    if isinstance(node, ast.Tuple):
        return tuple(_eval(elt, env) for elt in node.elts)
    if isinstance(node, ast.List):
        return [_eval(elt, env) for elt in node.elts]
    if isinstance(node, ast.Set):
        return {_eval(elt, env) for elt in node.elts}
    if isinstance(node, ast.BoolOp):
        values = [_eval(v, env) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise UnsafeExpression("Unsupported boolean operator")
    if isinstance(node, ast.UnaryOp):
        value = _eval(node.operand, env)
        if isinstance(node.op, ast.Not):
            return not value
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return +value
        raise UnsafeExpression("Unsupported unary operator")
    if isinstance(node, ast.BinOp):
        fn = _BINOPS.get(type(node.op))
        if fn is None:
            raise UnsafeExpression("Unsupported arithmetic operator")
        return fn(_eval(node.left, env), _eval(node.right, env))
    if isinstance(node, ast.Compare):
        left = _eval(node.left, env)
        for op_node, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, env)
            fn = _CMP.get(type(op_node))
            if fn is None or not fn(left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        return _eval(node.body if _eval(node.test, env) else node.orelse, env)
    if isinstance(node, ast.Subscript):
        value = _eval(node.value, env)
        key = _eval(node.slice, env)
        return value[key]
    raise UnsafeExpression(f"Unsupported syntax: {ast.dump(node, include_attributes=False)}")
