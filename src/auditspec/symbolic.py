from __future__ import annotations

import ast
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from .expr import UnsafeExpression, evaluate
from .model import AuditSpec


@dataclass(frozen=True)
class SymbolicDomain:
    kind: str
    lower: int | None = None
    upper: int | None = None
    values: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"bool", "int", "enum"}:
            raise ValueError(f"Unsupported symbolic domain kind: {self.kind}")
        if self.kind == "int" and self.values:
            if any(isinstance(value, bool) or not isinstance(value, int) for value in self.values):
                raise ValueError("Finite integer domains require integer values")
        if self.kind == "int" and not self.values:
            if self.lower is None or self.upper is None or self.lower > self.upper:
                raise ValueError("Interval integer domains require lower <= upper")
        if self.kind == "enum" and not self.values:
            raise ValueError("Enum domains require at least one value")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SymbolicProblem:
    name: str
    variables: Mapping[str, SymbolicDomain]
    constraints: tuple[str, ...]
    query: str
    observations: tuple[str, ...]
    assumptions: tuple[str, ...] = ()

    def digest(self) -> str:
        payload = {
            "name": self.name,
            "variables": {
                name: domain.as_dict() for name, domain in sorted(self.variables.items())
            },
            "constraints": list(self.constraints),
            "query": self.query,
            "observations": list(self.observations),
            "assumptions": list(self.assumptions),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class SymbolicTwinCertificate:
    schema: str
    problem_digest: str
    world_a: Mapping[str, Any]
    world_b: Mapping[str, Any]
    answer_a: Any
    answer_b: Any
    observations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SymbolicCheckResult:
    status: str
    determinate: bool | None
    elapsed_seconds: float
    solver: str
    assertions: int
    certificate: SymbolicTwinCertificate | None = None
    reason_unknown: str | None = None
    assumptions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["certificate"] = self.certificate.as_dict() if self.certificate else None
        return value


class SymbolicDeterminacyChecker:
    """SAT/SMT determinacy checker for two copies of an AuditSpec state.

    SAT returns an observation-equivalent twin with different query answers.
    UNSAT proves determinacy for the declared symbolic domains and constraints.
    This backend checks the D layer only; structural R/M/V gates remain separate.
    """

    def __init__(self, problem: SymbolicProblem):
        self.problem = problem

    def check(self, *, timeout_ms: int = 30_000) -> SymbolicCheckResult:
        z3 = _z3()
        solver = z3.Solver()
        solver.set(timeout=timeout_ms)
        worlds: dict[str, dict[str, Any]] = {}
        for side in ("a", "b"):
            env: dict[str, Any] = {}
            for name, domain in self.problem.variables.items():
                symbol = _symbol(z3, f"{side}__{name}", domain)
                env[name] = symbol
                solver.add(*_domain_constraints(z3, symbol, domain))
            worlds[side] = env
            for expression in self.problem.constraints:
                solver.add(_translate(z3, ast.parse(expression, mode="eval").body, env))

        for expression in self.problem.observations:
            parsed = ast.parse(expression, mode="eval").body
            solver.add(
                _translate(z3, parsed, worlds["a"])
                == _translate(z3, parsed, worlds["b"])
            )
        query_node = ast.parse(self.problem.query, mode="eval").body
        solver.add(
            _translate(z3, query_node, worlds["a"])
            != _translate(z3, query_node, worlds["b"])
        )
        started = time.perf_counter()
        outcome = solver.check()
        elapsed = time.perf_counter() - started
        solver_name = f"Z3 {z3.get_version_string()}"
        if outcome == z3.unsat:
            return SymbolicCheckResult(
                status="UNSAT_DETERMINATE",
                determinate=True,
                elapsed_seconds=elapsed,
                solver=solver_name,
                assertions=len(solver.assertions()),
                assumptions=self.problem.assumptions,
            )
        if outcome == z3.unknown:
            return SymbolicCheckResult(
                status="UNKNOWN",
                determinate=None,
                elapsed_seconds=elapsed,
                solver=solver_name,
                assertions=len(solver.assertions()),
                reason_unknown=solver.reason_unknown(),
                assumptions=self.problem.assumptions,
            )
        model = solver.model()
        world_a = _concrete_world(z3, model, worlds["a"], self.problem.variables)
        world_b = _concrete_world(z3, model, worlds["b"], self.problem.variables)
        certificate = SymbolicTwinCertificate(
            schema="AuditSpec-symbolic-twin-v1",
            problem_digest=self.problem.digest(),
            world_a=world_a,
            world_b=world_b,
            answer_a=evaluate(self.problem.query, world_a),
            answer_b=evaluate(self.problem.query, world_b),
            observations=self.problem.observations,
        )
        if not self.verify_certificate(certificate):
            raise RuntimeError("Z3 returned a twin that failed independent expression evaluation")
        return SymbolicCheckResult(
            status="SAT_TWIN",
            determinate=False,
            elapsed_seconds=elapsed,
            solver=solver_name,
            assertions=len(solver.assertions()),
            certificate=certificate,
            assumptions=self.problem.assumptions,
        )

    def verify_certificate(self, certificate: SymbolicTwinCertificate) -> bool:
        if certificate.schema != "AuditSpec-symbolic-twin-v1":
            return False
        if certificate.problem_digest != self.problem.digest():
            return False
        for world in (certificate.world_a, certificate.world_b):
            if set(world) != set(self.problem.variables):
                return False
            if not all(_value_in_domain(world[name], domain) for name, domain in self.problem.variables.items()):
                return False
            try:
                if not all(bool(evaluate(expression, world)) for expression in self.problem.constraints):
                    return False
            except (UnsafeExpression, KeyError, TypeError, ValueError):
                return False
        try:
            observations_a = tuple(evaluate(item, certificate.world_a) for item in self.problem.observations)
            observations_b = tuple(evaluate(item, certificate.world_b) for item in self.problem.observations)
            answer_a = evaluate(self.problem.query, certificate.world_a)
            answer_b = evaluate(self.problem.query, certificate.world_b)
        except (UnsafeExpression, KeyError, TypeError, ValueError):
            return False
        return (
            observations_a == observations_b
            and answer_a != answer_b
            and answer_a == certificate.answer_a
            and answer_b == certificate.answer_b
        )


def problem_from_spec(
    spec: AuditSpec, query_name: str, contract: Sequence[str]
) -> SymbolicProblem:
    """Translate the expression-bearing subset of AuditSpec into SMT.

    Exact, predicate, relation, aggregate, and bucket observations are exact.
    Digest observations are translated as source equality under an explicit
    collision-free abstraction. Bucket observations are rejected rather than
    silently strengthened.
    """

    observations: list[str] = []
    assumptions: set[str] = set()
    for mechanism_name in sorted(set(contract)):
        mechanism = spec.mechanisms[mechanism_name]
        if not mechanism.observations:
            observations.extend(mechanism.facts)
            continue
        for observation in mechanism.observations:
            if observation.kind == "exact":
                observations.extend(observation.sources)
            elif observation.kind in {"predicate", "relation", "aggregate"}:
                if not observation.expression:
                    raise ValueError(f"Missing symbolic expression: {observation.name}")
                observations.append(observation.expression)
            elif observation.kind == "presence":
                source = observation.sources[0]
                domain = spec.variables[source]
                if None in domain:
                    raise ValueError(
                        f"Nullable presence observation {observation.name!r} is not supported"
                    )
                # A non-null finite domain makes presence a constant channel.
            elif observation.kind == "bucket":
                source = observation.sources[0]
                boundaries = tuple(observation.parameters.get("boundaries", ()))
                labels = tuple(observation.parameters.get("labels", ()))
                if labels and len(set(labels)) != len(labels):
                    raise ValueError(
                        f"Bucket observation {observation.name!r} has duplicate labels"
                    )
                # With unique labels, equality of the threshold truth vector is
                # exactly equality of the bucket index. No boundaries means a
                # constant observation and therefore adds no constraint.
                observations.extend(f"{source} > {boundary!r}" for boundary in boundaries)
            elif observation.kind == "digest":
                observations.extend(observation.sources)
                assumptions.add(f"collision_free_digest:{observation.name}")
            else:
                raise ValueError(
                    f"Observation {observation.name!r} kind {observation.kind!r} is not supported by the symbolic adapter"
                )
    return SymbolicProblem(
        name=f"{spec.name}:{query_name}",
        variables={name: _infer_domain(values) for name, values in spec.variables.items()},
        constraints=tuple(spec.constraints),
        query=spec.queries[query_name].expression,
        observations=tuple(dict.fromkeys(observations)),
        assumptions=tuple(sorted(assumptions)),
    )


def _z3():
    try:
        import z3
    except ImportError as exc:
        raise RuntimeError(
            "The symbolic backend requires: pip install 'auditability-compiler[symbolic]'"
        ) from exc
    return z3


def _infer_domain(values: Sequence[Any]) -> SymbolicDomain:
    values = tuple(values)
    if values and all(isinstance(value, bool) for value in values):
        return SymbolicDomain("bool")
    if values and all(isinstance(value, int) and not isinstance(value, bool) for value in values):
        return SymbolicDomain("int", values=values)
    if values and all(isinstance(value, str) for value in values):
        return SymbolicDomain("enum", values=values)
    raise ValueError(f"Unsupported finite domain for symbolic translation: {values!r}")


def _symbol(z3: Any, name: str, domain: SymbolicDomain) -> Any:
    if domain.kind == "bool":
        return z3.Bool(name)
    if domain.kind == "int":
        return z3.Int(name)
    return z3.String(name)


def _domain_constraints(z3: Any, symbol: Any, domain: SymbolicDomain) -> tuple[Any, ...]:
    if domain.kind == "bool":
        return ()
    if domain.values:
        return (z3.Or(*[symbol == _literal(z3, value) for value in domain.values]),)
    return (symbol >= domain.lower, symbol <= domain.upper)


def _literal(z3: Any, value: Any) -> Any:
    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, int):
        return z3.IntVal(value)
    if isinstance(value, float):
        return z3.RealVal(str(value))
    if isinstance(value, str):
        return z3.StringVal(value)
    raise UnsafeExpression(f"Unsupported symbolic literal: {value!r}")


def _translate(z3: Any, node: ast.AST, env: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return _literal(z3, node.value)
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise UnsafeExpression(f"Unknown variable: {node.id}")
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return tuple(_translate(z3, item, env) for item in node.elts)
    if isinstance(node, ast.BoolOp):
        values = [_translate(z3, value, env) for value in node.values]
        if isinstance(node.op, ast.And):
            return z3.And(*values)
        if isinstance(node.op, ast.Or):
            return z3.Or(*values)
    if isinstance(node, ast.UnaryOp):
        value = _translate(z3, node.operand, env)
        if isinstance(node.op, ast.Not):
            return z3.Not(value)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return value
    if isinstance(node, ast.BinOp):
        left = _translate(z3, node.left, env)
        right = _translate(z3, node.right, env)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
    if isinstance(node, ast.Compare):
        left = _translate(z3, node.left, env)
        comparisons: list[Any] = []
        for operator, comparator in zip(node.ops, node.comparators):
            right = _translate(z3, comparator, env)
            if isinstance(operator, ast.Eq):
                comparison = left == right
            elif isinstance(operator, ast.NotEq):
                comparison = left != right
            elif isinstance(operator, ast.Lt):
                comparison = left < right
            elif isinstance(operator, ast.LtE):
                comparison = left <= right
            elif isinstance(operator, ast.Gt):
                comparison = left > right
            elif isinstance(operator, ast.GtE):
                comparison = left >= right
            elif isinstance(operator, ast.In):
                if not isinstance(right, tuple):
                    raise UnsafeExpression("Symbolic membership requires a literal collection")
                comparison = z3.Or(*[left == item for item in right])
            elif isinstance(operator, ast.NotIn):
                if not isinstance(right, tuple):
                    raise UnsafeExpression("Symbolic membership requires a literal collection")
                comparison = z3.Not(z3.Or(*[left == item for item in right]))
            else:
                raise UnsafeExpression(f"Unsupported symbolic comparison: {type(operator).__name__}")
            comparisons.append(comparison)
            left = right
        return z3.And(*comparisons)
    if isinstance(node, ast.IfExp):
        return z3.If(
            _translate(z3, node.test, env),
            _translate(z3, node.body, env),
            _translate(z3, node.orelse, env),
        )
    raise UnsafeExpression(f"Unsupported symbolic syntax: {ast.dump(node, include_attributes=False)}")


def _concrete_world(
    z3: Any,
    model: Any,
    symbols: Mapping[str, Any],
    domains: Mapping[str, SymbolicDomain],
) -> dict[str, Any]:
    world: dict[str, Any] = {}
    for name, symbol in symbols.items():
        value = model.eval(symbol, model_completion=True)
        domain = domains[name]
        if domain.kind == "bool":
            world[name] = z3.is_true(value)
        elif domain.kind == "int":
            world[name] = value.as_long()
        else:
            world[name] = value.as_string()
    return world


def _value_in_domain(value: Any, domain: SymbolicDomain) -> bool:
    if domain.kind == "bool":
        return isinstance(value, bool)
    if domain.values:
        return value in domain.values
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and domain.lower <= value <= domain.upper
    )
