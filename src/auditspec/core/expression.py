"""AuditSpec-Expr-1.0 typed AST validation, evaluation, and legacy parsing."""

from __future__ import annotations

import ast as python_ast
import copy
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .canonical import canonical_json, digest
from .wire import (
    BOOLEAN,
    INTEGER,
    STRING,
    TypeNode,
    WireError,
    canonical_value,
    decode_canonical_value,
    require_digest,
    require_exact_keys,
    require_ref,
)

LANGUAGE = "AuditSpec-Expr-1.0"
MAX_EXPR_AST_NODES = 100_000


class ExpressionError(WireError):
    pass


@dataclass(frozen=True)
class FunctionBinding:
    input_types: tuple[TypeNode, ...]
    output_type: TypeNode
    implementation: Callable[..., Any]


FunctionResolver = Callable[[dict[str, Any]], FunctionBinding]


@dataclass(frozen=True)
class Expr:
    ast: dict[str, Any]
    output_type: TypeNode
    ast_digest: str
    display: str | None = None

    @classmethod
    def build(
        cls,
        ast: dict[str, Any],
        variables: Mapping[str, TypeNode],
        *,
        display: str | None = None,
        function_resolver: FunctionResolver | None = None,
    ) -> "Expr":
        owned_ast = copy.deepcopy(ast)
        output, nodes = _validate_node(owned_ast, dict(variables), function_resolver, 0)
        if nodes > MAX_EXPR_AST_NODES:
            raise ExpressionError("expression exceeds MAX_EXPR_AST_NODES")
        return cls(owned_ast, output, digest(LANGUAGE, owned_ast), display)

    @classmethod
    def from_wire(
        cls,
        value: Any,
        variables: Mapping[str, TypeNode],
        *,
        function_resolver: FunctionResolver | None = None,
    ) -> "Expr":
        if not isinstance(value, dict):
            raise ExpressionError("expr must be an object")
        allowed = {"language", "ast", "ast_digest", "output_type", "display"}
        required = {"language", "ast", "ast_digest", "output_type"}
        if not required <= set(value) or set(value) - allowed:
            raise ExpressionError("expr envelope key mismatch")
        if value["language"] != LANGUAGE:
            raise ExpressionError("unsupported expression language")
        output_type = TypeNode.from_wire(value["output_type"])
        expression = cls.build(
            value["ast"],
            variables,
            display=value.get("display"),
            function_resolver=function_resolver,
        )
        require_digest(value["ast_digest"], "expr.ast_digest")
        if expression.ast_digest != value["ast_digest"]:
            raise ExpressionError("expression AST digest mismatch")
        if expression.output_type != output_type:
            raise ExpressionError("expression output type mismatch")
        return expression

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "language": LANGUAGE,
            "ast": copy.deepcopy(self.ast),
            "ast_digest": self.ast_digest,
            "output_type": self.output_type.to_wire(),
        }
        if self.display is not None:
            result["display"] = self.display
        return result

    def evaluate(
        self,
        values: Mapping[str, Any],
        *,
        function_resolver: FunctionResolver | None = None,
    ) -> Any:
        if digest(LANGUAGE, self.ast) != self.ast_digest:
            raise ExpressionError("expression AST mutated after construction")
        return _evaluate_node(self.ast, values, function_resolver)


def literal(value: Any, value_type: TypeNode) -> dict[str, Any]:
    return {
        "node": "literal",
        "value_type": value_type.to_wire(),
        "value": canonical_value(value, value_type),
    }


def variable(name: str, value_type: TypeNode) -> dict[str, Any]:
    return {
        "node": "variable",
        "name": require_ref(name),
        "value_type": value_type.to_wire(),
    }


def operator(
    op: str, args: list[dict[str, Any]], value_type: TypeNode
) -> dict[str, Any]:
    return {
        "node": "operator",
        "op": op,
        "args": args,
        "value_type": value_type.to_wire(),
    }


def collection(
    collection_type: str, element_type: TypeNode, elements: list[dict[str, Any]]
) -> dict[str, Any]:
    value_type = TypeNode(collection_type, item=element_type)
    return {
        "node": "collection",
        "collection_type": collection_type,
        "element_type": element_type.to_wire(),
        "elements": elements,
        "value_type": value_type.to_wire(),
    }


def parse_legacy_expression(
    text: str,
    variables: Mapping[str, TypeNode],
) -> Expr:
    """Translate the historical Python-like subset into a Core typed AST.

    This is a migration parser only. The returned Core expression is evaluated
    by this module, never by Python ``eval`` or the historical evaluator.
    """

    try:
        parsed = python_ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise ExpressionError("legacy expression is not parseable") from exc
    node = _translate_python(parsed.body, variables)
    return Expr.build(node, variables, display=text)


def _translate_python(
    node: python_ast.AST, variables: Mapping[str, TypeNode]
) -> dict[str, Any]:
    if isinstance(node, python_ast.Constant):
        if isinstance(node.value, bool):
            return literal(node.value, BOOLEAN)
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return literal(node.value, INTEGER)
        if isinstance(node.value, str):
            return literal(node.value, STRING)
        raise ExpressionError("legacy literal has no Core representation")
    if isinstance(node, python_ast.Name):
        if node.id not in variables:
            raise ExpressionError(
                f"legacy expression references unknown variable: {node.id}"
            )
        return variable(node.id, variables[node.id])
    if isinstance(node, python_ast.BoolOp):
        op = (
            "and"
            if isinstance(node.op, python_ast.And)
            else "or"
            if isinstance(node.op, python_ast.Or)
            else None
        )
        if op is None:
            raise ExpressionError("unsupported legacy boolean operator")
        return operator(
            op, [_translate_python(item, variables) for item in node.values], BOOLEAN
        )
    if isinstance(node, python_ast.UnaryOp):
        operand = _translate_python(node.operand, variables)
        if isinstance(node.op, python_ast.Not):
            return operator("not", [operand], BOOLEAN)
        if isinstance(node.op, python_ast.USub):
            return operator("sub", [literal(0, INTEGER), operand], INTEGER)
        if isinstance(node.op, python_ast.UAdd):
            return operand
        raise ExpressionError("unsupported legacy unary operator")
    if isinstance(node, python_ast.BinOp):
        operations = {
            python_ast.Add: "add",
            python_ast.Sub: "sub",
            python_ast.Mult: "mul",
        }
        op = operations.get(type(node.op))
        if op is None:
            raise ExpressionError("legacy arithmetic operator is outside Core Expr")
        return operator(
            op,
            [
                _translate_python(node.left, variables),
                _translate_python(node.right, variables),
            ],
            INTEGER,
        )
    if isinstance(node, python_ast.Compare):
        operations = {
            python_ast.Eq: "eq",
            python_ast.NotEq: "neq",
            python_ast.Lt: "lt",
            python_ast.LtE: "lte",
            python_ast.Gt: "gt",
            python_ast.GtE: "gte",
            python_ast.In: "in",
            python_ast.NotIn: None,
        }
        comparisons: list[dict[str, Any]] = []
        left = node.left
        for op_node, right in zip(node.ops, node.comparators):
            op = operations.get(type(op_node), "__missing__")
            if op == "__missing__":
                raise ExpressionError("unsupported legacy comparison")
            translated = operator(
                "in" if op is None else op,
                [
                    _translate_python(left, variables),
                    _translate_python(right, variables),
                ],
                BOOLEAN,
            )
            if op is None:
                translated = operator("not", [translated], BOOLEAN)
            comparisons.append(translated)
            left = right
        return (
            comparisons[0]
            if len(comparisons) == 1
            else operator("and", comparisons, BOOLEAN)
        )
    if isinstance(node, (python_ast.List, python_ast.Tuple, python_ast.Set)):
        elements = [_translate_python(item, variables) for item in node.elts]
        if not elements:
            raise ExpressionError(
                "legacy empty collection has no inferred element type"
            )
        element_type = TypeNode.from_wire(elements[0]["value_type"])
        kind = "set" if isinstance(node, python_ast.Set) else "list"
        return collection(kind, element_type, elements)
    if isinstance(node, python_ast.IfExp):
        body = _translate_python(node.body, variables)
        return operator(
            "if_then_else",
            [
                _translate_python(node.test, variables),
                body,
                _translate_python(node.orelse, variables),
            ],
            TypeNode.from_wire(body["value_type"]),
        )
    raise ExpressionError(f"unsupported legacy syntax: {type(node).__name__}")


def _validate_node(
    node: Any,
    variables: dict[str, TypeNode],
    function_resolver: FunctionResolver | None,
    depth: int,
) -> tuple[TypeNode, int]:
    if (
        depth > 100_000
        or not isinstance(node, dict)
        or not isinstance(node.get("node"), str)
    ):
        raise ExpressionError("invalid or over-deep expression node")
    kind = node["node"]
    if kind == "literal":
        require_exact_keys(node, {"node", "value_type", "value"}, "Expr.literal")
        value_type = TypeNode.from_wire(node["value_type"])
        decode_canonical_value(node["value"], value_type)
        return value_type, 1
    if kind == "variable":
        require_exact_keys(node, {"node", "name", "value_type"}, "Expr.variable")
        name = require_ref(node["name"], "Expr.variable.name")
        value_type = TypeNode.from_wire(node["value_type"])
        if variables.get(name) != value_type:
            raise ExpressionError(f"variable type mismatch: {name}")
        return value_type, 1
    if kind == "collection":
        require_exact_keys(
            node,
            {"node", "collection_type", "element_type", "elements", "value_type"},
            "Expr.collection",
        )
        collection_type = node["collection_type"]
        if collection_type not in {"list", "set"} or not isinstance(
            node["elements"], list
        ):
            raise ExpressionError("invalid expression collection")
        element_type = TypeNode.from_wire(node["element_type"])
        expected = TypeNode(collection_type, item=element_type)
        if TypeNode.from_wire(node["value_type"]) != expected:
            raise ExpressionError("collection value_type mismatch")
        count = 1
        encodings: list[str] = []
        for child in node["elements"]:
            child_type, nodes = _validate_node(
                child, variables, function_resolver, depth + 1
            )
            count += nodes
            if child_type != element_type:
                raise ExpressionError("collection element type mismatch")
            encodings.append(canonical_json(child))
        if collection_type == "set" and (
            encodings != sorted(encodings) or len(encodings) != len(set(encodings))
        ):
            raise ExpressionError("expression set elements must be sorted-unique")
        return expected, count
    if kind == "operator":
        require_exact_keys(node, {"node", "op", "args", "value_type"}, "Expr.operator")
        if not isinstance(node["args"], list) or not node["args"]:
            raise ExpressionError("operator needs arguments")
        arg_types: list[TypeNode] = []
        count = 1
        for child in node["args"]:
            child_type, nodes = _validate_node(
                child, variables, function_resolver, depth + 1
            )
            arg_types.append(child_type)
            count += nodes
        result_type = _operator_type(str(node["op"]), arg_types)
        if TypeNode.from_wire(node["value_type"]) != result_type:
            raise ExpressionError("operator value_type mismatch")
        return result_type, count
    if kind == "quantifier":
        require_exact_keys(
            node,
            {"node", "quantifier", "variable", "domain", "body", "value_type"},
            "Expr.quantifier",
        )
        if node["quantifier"] not in {"forall", "exists"}:
            raise ExpressionError("unknown quantifier")
        binding = require_exact_keys(
            node["variable"], {"name", "value_type"}, "Expr.quantifier.variable"
        )
        name = require_ref(binding["name"])
        bound_type = TypeNode.from_wire(binding["value_type"])
        domain_type, domain_nodes = _validate_node(
            node["domain"], variables, function_resolver, depth + 1
        )
        if domain_type.kind not in {"list", "set"} or domain_type.item != bound_type:
            raise ExpressionError("quantifier domain/binding mismatch")
        nested = dict(variables)
        nested[name] = bound_type
        body_type, body_nodes = _validate_node(
            node["body"], nested, function_resolver, depth + 1
        )
        if body_type != BOOLEAN or TypeNode.from_wire(node["value_type"]) != BOOLEAN:
            raise ExpressionError("quantifier body/output must be Boolean")
        return BOOLEAN, 1 + domain_nodes + body_nodes
    if kind == "call":
        require_exact_keys(
            node, {"node", "function", "args", "value_type"}, "Expr.call"
        )
        if function_resolver is None or not isinstance(node["args"], list):
            raise ExpressionError("Call requires a pinned function resolver")
        binding = function_resolver(node["function"])
        arg_types: list[TypeNode] = []
        count = 1
        for child in node["args"]:
            child_type, nodes = _validate_node(
                child, variables, function_resolver, depth + 1
            )
            arg_types.append(child_type)
            count += nodes
        if (
            tuple(arg_types) != binding.input_types
            or TypeNode.from_wire(node["value_type"]) != binding.output_type
        ):
            raise ExpressionError("Call signature mismatch")
        return binding.output_type, count
    if kind == "field":
        raise ExpressionError("Field requires a registered record-schema resolver")
    raise ExpressionError(f"unknown expression node: {kind}")


def _operator_type(op: str, args: list[TypeNode]) -> TypeNode:
    if op == "not" and args == [BOOLEAN]:
        return BOOLEAN
    if op in {"and", "or"} and len(args) >= 1 and all(item == BOOLEAN for item in args):
        return BOOLEAN
    if op in {"eq", "neq"} and len(args) == 2 and args[0] == args[1]:
        return BOOLEAN
    if (
        op in {"lt", "lte", "gt", "gte"}
        and len(args) == 2
        and args[0] == args[1]
        and args[0] in {INTEGER, STRING}
    ):
        return BOOLEAN
    if (
        op == "in"
        and len(args) == 2
        and args[1].kind in {"list", "set"}
        and args[1].item == args[0]
    ):
        return BOOLEAN
    if (
        op == "contains"
        and len(args) == 2
        and args[0].kind in {"list", "set"}
        and args[0].item == args[1]
    ):
        return BOOLEAN
    if op == "is_null" and len(args) == 1 and args[0].kind == "optional":
        return BOOLEAN
    if (
        op == "coalesce"
        and len(args) == 2
        and args[0].kind == "optional"
        and args[0].item == args[1]
    ):
        return args[1]
    if (
        op == "if_then_else"
        and len(args) == 3
        and args[0] == BOOLEAN
        and args[1] == args[2]
    ):
        return args[1]
    if op in {"add", "sub", "mul"} and len(args) == 2 and args == [INTEGER, INTEGER]:
        return INTEGER
    if op == "count" and len(args) == 1 and args[0].kind in {"list", "set"}:
        return INTEGER
    if (
        op in {"sum", "min", "max"}
        and len(args) == 1
        and args[0].kind in {"list", "set"}
        and args[0].item == INTEGER
    ):
        return INTEGER
    if op == "all_equal" and len(args) == 1 and args[0].kind in {"list", "set"}:
        return BOOLEAN
    raise ExpressionError(f"operator signature is invalid: {op}")


def _evaluate_node(
    node: dict[str, Any],
    values: Mapping[str, Any],
    function_resolver: FunctionResolver | None,
) -> Any:
    kind = node["node"]
    if kind == "literal":
        return decode_canonical_value(
            node["value"], TypeNode.from_wire(node["value_type"])
        )
    if kind == "variable":
        name = node["name"]
        if name not in values:
            raise ExpressionError(f"missing expression variable: {name}")
        return values[name]
    if kind == "collection":
        items = [
            _evaluate_node(item, values, function_resolver) for item in node["elements"]
        ]
        return items if node["collection_type"] == "list" else frozenset(items)
    if kind == "operator":
        args = [
            _evaluate_node(item, values, function_resolver) for item in node["args"]
        ]
        op = node["op"]
        operations: dict[str, Callable[..., Any]] = {
            "not": lambda a: not a,
            "and": lambda *a: all(a),
            "or": lambda *a: any(a),
            "eq": lambda a, b: a == b,
            "neq": lambda a, b: a != b,
            "lt": lambda a, b: a < b,
            "lte": lambda a, b: a <= b,
            "gt": lambda a, b: a > b,
            "gte": lambda a, b: a >= b,
            "in": lambda a, b: a in b,
            "contains": lambda a, b: b in a,
            "is_null": lambda a: a is None,
            "coalesce": lambda a, b: b if a is None else a,
            "if_then_else": lambda condition, yes, no: yes if condition else no,
            "add": lambda a, b: a + b,
            "sub": lambda a, b: a - b,
            "mul": lambda a, b: a * b,
            "count": len,
            "sum": sum,
            "min": min,
            "max": max,
            "all_equal": lambda a: len(set(a)) <= 1,
        }
        return operations[op](*args)
    if kind == "quantifier":
        domain = _evaluate_node(node["domain"], values, function_resolver)
        name = node["variable"]["name"]
        answers = []
        for item in domain:
            nested = dict(values)
            nested[name] = item
            answers.append(
                bool(_evaluate_node(node["body"], nested, function_resolver))
            )
        return all(answers) if node["quantifier"] == "forall" else any(answers)
    if kind == "call":
        if function_resolver is None:
            raise ExpressionError("Call requires a pinned function resolver")
        binding = function_resolver(node["function"])
        return binding.implementation(
            *[_evaluate_node(item, values, function_resolver) for item in node["args"]]
        )
    raise ExpressionError(f"expression node is not executable: {kind}")
