"""Design-time Mechanism Specs and a pinned candidate catalog."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import canonical_json, digest
from .expression import Expr
from .refs import RootedRef
from .wire import ExactDecimal, TypeNode, require_ref

COST_DIMENSIONS = ("bytes", "privacy", "latency_ms", "fragility")


@dataclass(frozen=True)
class CostVector:
    bytes: ExactDecimal
    privacy: ExactDecimal
    latency_ms: ExactDecimal
    fragility: ExactDecimal

    @classmethod
    def zero(cls) -> "CostVector":
        zero = ExactDecimal(0, 0)
        return cls(zero, zero, zero, zero)

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "CostVector":
        if set(value) != set(COST_DIMENSIONS):
            raise ValueError("cost vector key set mismatch")
        result = cls(*(ExactDecimal.from_wire(value[name]) for name in COST_DIMENSIONS))
        if any(getattr(result, name).coefficient < 0 for name in COST_DIMENSIONS):
            raise ValueError("cost components must be non-negative")
        return result

    def to_wire(self) -> dict[str, Any]:
        return {name: getattr(self, name).to_wire() for name in COST_DIMENSIONS}

    def __add__(self, other: "CostVector") -> "CostVector":
        return CostVector(
            *(getattr(self, name) + getattr(other, name) for name in COST_DIMENSIONS)
        )

    def scalar(self, weights: "CostVector") -> Any:
        return sum(
            getattr(self, name).as_fraction() * getattr(weights, name).as_fraction()
            for name in COST_DIMENSIONS
        )


@dataclass(frozen=True)
class PrincipalPattern:
    id: str | None
    key_domain: str | None
    key_id: str | None

    def __post_init__(self) -> None:
        if self.id is None and self.key_domain is None and self.key_id is None:
            raise ValueError("principal pattern cannot be all-wildcard")
        if self.id is not None:
            require_ref(self.id, "principal_pattern.id")
        if self.key_id is not None:
            require_ref(self.key_id, "principal_pattern.key_id")

    def to_wire(self) -> dict[str, str | None]:
        return {"id": self.id, "key_domain": self.key_domain, "key_id": self.key_id}


@dataclass(frozen=True)
class Principal:
    id: str
    key_domain: str
    key_id: str

    def __post_init__(self) -> None:
        require_ref(self.id, "principal.id")
        require_ref(self.key_id, "principal.key_id")
        if not self.key_domain:
            raise ValueError("principal key domain is empty")

    def to_wire(self) -> dict[str, str]:
        return {"id": self.id, "key_domain": self.key_domain, "key_id": self.key_id}


@dataclass(frozen=True)
class MechanismSpec:
    mechanism_id: str
    observation_kind: str
    sources: tuple[str, ...]
    output_type: TypeNode
    producer_requirement: PrincipalPattern
    capture_requirement: PrincipalPattern
    binding_requirement: tuple[tuple[str, str], ...]
    coverage_channel: str | None
    coverage_mandatory: bool
    coverage_complete_mediation: bool
    identity_expression: Expr
    expected_population_expression: Expr
    cardinality: str
    verifier_ref: str
    verification_computation: Expr
    declared_cost: CostVector
    lifecycle_policy_template: RootedRef
    observation_expression: Expr | None = None
    observation_parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_ref(self.mechanism_id, "mechanism_id")
        if self.observation_kind not in {
            "exact",
            "predicate",
            "relation",
            "aggregate",
            "bucket",
            "digest",
            "presence",
        }:
            raise ValueError("unknown observation kind")
        if len(self.sources) != len(set(self.sources)):
            raise ValueError("observation sources must be duplicate-free")
        for source in self.sources:
            require_ref(source, "observation source")
        expression_kinds = {"predicate", "relation", "aggregate"}
        if (self.observation_expression is not None) != (
            self.observation_kind in expression_kinds
        ):
            raise ValueError("observation expression branch mismatch")
        if self.observation_kind in {"exact", "digest"} and not self.sources:
            raise ValueError("exact/digest observation requires sources")
        if self.observation_kind in {"bucket", "presence"} and len(self.sources) != 1:
            raise ValueError("bucket/presence observation requires one source")
        if self.observation_kind == "relation" and len(self.sources) < 2:
            raise ValueError("relation observation requires at least two sources")
        if self.observation_kind in {"predicate", "aggregate"} and not self.sources:
            raise ValueError("predicate/aggregate observation requires sources")
        parameters = dict(self.observation_parameters)
        if self.observation_kind == "bucket":
            if set(parameters) != {"boundaries"}:
                raise ValueError("bucket parameters must contain boundaries only")
            boundaries = [
                ExactDecimal.from_wire(item) for item in parameters["boundaries"]
            ]
            if not boundaries or [item.as_fraction() for item in boundaries] != sorted(
                {item.as_fraction() for item in boundaries}
            ):
                raise ValueError("bucket boundaries must be non-empty sorted-unique")
        elif self.observation_kind == "digest":
            if (
                set(parameters) != {"namespace"}
                or not isinstance(parameters["namespace"], str)
                or not parameters["namespace"]
            ):
                raise ValueError("digest parameters require a non-empty namespace")
        elif parameters:
            raise ValueError("observation branch requires empty parameters")
        canonical_json(parameters)
        if self.identity_expression.output_type != TypeNode.scalar("ref"):
            raise ValueError("identity expression must produce ref")
        if self.expected_population_expression.output_type != TypeNode(
            "set", item=TypeNode.scalar("ref")
        ):
            raise ValueError("expected population expression must produce set<ref>")
        if self.verification_computation.output_type != self.output_type:
            raise ValueError("verification computation/output type mismatch")
        if len(self.binding_requirement) != len(set(self.binding_requirement)):
            raise ValueError("binding requirements must be duplicate-free")
        if self.coverage_complete_mediation and self.coverage_channel is None:
            raise ValueError("complete mediation requires a channel")
        if self.coverage_mandatory and self.coverage_channel is None:
            raise ValueError("mandatory coverage requires a channel")
        if self.cardinality not in {
            "exactly_one_per_identity",
            "at_least_one_per_identity",
        }:
            raise ValueError("unknown mechanism cardinality")
        require_ref(self.verifier_ref, "verifier_ref")

    def observe(self, world: Mapping[str, Any]) -> Any:
        if self.observation_kind == "exact":
            values = tuple(world[name] for name in self.sources)
            return values[0] if len(values) == 1 else list(values)
        if self.observation_kind in {"predicate", "relation", "aggregate"}:
            assert self.observation_expression is not None
            return self.observation_expression.evaluate(world)
        if self.observation_kind == "bucket":
            raw = ExactDecimal.parse(str(world[self.sources[0]])).as_fraction()
            boundaries = [
                ExactDecimal.from_wire(item).as_fraction()
                for item in self.observation_parameters["boundaries"]
            ]
            return sum(raw > boundary for boundary in boundaries)
        if self.observation_kind == "digest":
            payload = {
                "namespace": self.observation_parameters["namespace"],
                "values": [world[name] for name in self.sources],
            }
            return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        if self.observation_kind == "presence":
            return world.get(self.sources[0]) is not None
        raise AssertionError("unreachable observation kind")

    def to_wire(self) -> dict[str, Any]:
        observation = {
            "kind": self.observation_kind,
            "sources": list(self.sources),
            "parameters": dict(self.observation_parameters),
        }
        if self.observation_expression is not None:
            observation["expression"] = self.observation_expression.to_wire()
        return {
            "schema": "AuditSpec-mechanism-spec-v1",
            "mechanism_id": self.mechanism_id,
            "observation_function": observation,
            "producer_requirement": self.producer_requirement.to_wire(),
            "capture_requirement": self.capture_requirement.to_wire(),
            "binding_requirement": [list(item) for item in self.binding_requirement],
            "coverage_requirement": {
                "channel": self.coverage_channel,
                "mandatory": self.coverage_mandatory,
                "complete_mediation": self.coverage_complete_mediation,
            },
            "closure_requirement": {
                "identity_expression": self.identity_expression.to_wire(),
                "expected_population_expression": self.expected_population_expression.to_wire(),
                "cardinality": self.cardinality,
            },
            "verification_spec": {
                "verifier_ref": self.verifier_ref,
                "computation": self.verification_computation.to_wire(),
                "output_type": self.output_type.to_wire(),
            },
            "declared_cost": self.declared_cost.to_wire(),
            "lifecycle_policy_template": self.lifecycle_policy_template.to_wire(),
        }


@dataclass(frozen=True)
class AdapterCandidate:
    adapter_id: str
    mechanism_id: str
    ledger: str
    hook_point: RootedRef
    capture_point: Principal
    implementation_status: str
    legacy_manifest_digest: str
    legacy_registry_source_sha256: str

    def __post_init__(self) -> None:
        require_ref(self.adapter_id, "adapter_id")
        require_ref(self.mechanism_id, "adapter mechanism_id")
        if self.ledger not in {
            "interaction",
            "effect",
            "config",
            "lifecycle",
            "authority",
        }:
            raise ValueError("adapter candidate has an unknown ledger")
        if self.implementation_status != "candidate_pending_conformance":
            raise ValueError("Phase 1 adapter cannot claim conformance")
        from .wire import require_digest

        require_digest(self.legacy_manifest_digest, "legacy adapter manifest digest")
        require_digest(
            self.legacy_registry_source_sha256, "legacy adapter registry source SHA"
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "auditspec.impl.adapter-candidate.v1",
            "id": f"adapter_candidate.{self.mechanism_id}",
            "adapter_id": self.adapter_id,
            "mechanism_id": self.mechanism_id,
            "ledger": self.ledger,
            "hook_point": self.hook_point.to_wire(),
            "capture_point": self.capture_point.to_wire(),
            "implementation_status": self.implementation_status,
            "legacy_manifest_digest": self.legacy_manifest_digest,
            "legacy_registry_source_sha256": self.legacy_registry_source_sha256,
        }


@dataclass(frozen=True)
class MechanismCatalog:
    mechanisms: Mapping[str, MechanismSpec]
    dependencies: Mapping[str, tuple[str, ...]]
    adapters: Mapping[str, AdapterCandidate]
    mechanism_registry_root: str
    adapter_registry_root: str
    dependency_witness_digest: str

    @classmethod
    def build(
        cls,
        mechanisms: Mapping[str, MechanismSpec],
        dependencies: Mapping[str, tuple[str, ...]],
        adapters: Mapping[str, AdapterCandidate],
    ) -> "MechanismCatalog":
        ids = set(mechanisms)
        if set(dependencies) != ids:
            raise ValueError("dependency map must cover every mechanism exactly")
        for name, required in dependencies.items():
            if (
                len(required) != len(set(required))
                or set(required) - ids
                or name in required
            ):
                raise ValueError("invalid mechanism dependency relation")
        _assert_acyclic(dependencies)
        mechanism_rows = [mechanisms[name].to_wire() for name in sorted(mechanisms)]
        dependency_rows = [
            {"mechanism_id": name, "requires": list(dependencies[name])}
            for name in sorted(dependencies)
        ]
        adapter_rows = [
            item.to_wire()
            for item in sorted(adapters.values(), key=lambda row: row.mechanism_id)
        ]
        return cls(
            dict(mechanisms),
            dict(dependencies),
            dict(adapters),
            digest("AuditSpec-core-phase1-mechanism-registry-v1", mechanism_rows),
            digest("AuditSpec-core-phase1-adapter-registry-v1", adapter_rows),
            digest(
                "AuditSpec-core-phase1-mechanism-dependency-witness-v1", dependency_rows
            ),
        )

    def dependency_closure(self, selected: tuple[str, ...]) -> tuple[str, ...]:
        closure: set[str] = set()
        pending = list(selected)
        while pending:
            name = pending.pop()
            for dependency in self.dependencies[name]:
                if dependency not in closure:
                    closure.add(dependency)
                    pending.append(dependency)
        return tuple(sorted(closure))

    def contract_is_dependency_closed(self, selected: tuple[str, ...]) -> bool:
        chosen = set(selected)
        return all(set(self.dependencies[name]) <= chosen for name in selected)


def source_file_digest(path: str, data: bytes) -> str:
    return hashlib.sha256(path.encode("utf-8") + b"\x00" + data).hexdigest()


def _assert_acyclic(dependencies: Mapping[str, tuple[str, ...]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ValueError("mechanism dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for child in dependencies[name]:
            visit(child)
        visiting.remove(name)
        visited.add(name)

    for mechanism_id in dependencies:
        visit(mechanism_id)
