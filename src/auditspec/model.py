from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

World = dict[str, Any]


@dataclass(frozen=True)
class CostVector:
    """Declared or measured mechanism cost.

    `bytes` and `latency_ms` can be populated from runtime measurements. Privacy
    and fragility remain ordinal scores and are always reported as such.
    """

    bytes: float = 0.0
    privacy: float = 0.0
    latency_ms: float = 0.0
    fragility: float = 0.0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "CostVector":
        value = value or {}
        result = cls(
            bytes=float(value.get("bytes", value.get("storage", 0.0))),
            privacy=float(value.get("privacy", 0.0)),
            latency_ms=float(value.get("latency_ms", value.get("latency", 0.0))),
            fragility=float(value.get("fragility", 0.0)),
        )
        result.validate()
        return result

    def validate(self) -> "CostVector":
        for name, value in asdict(self).items():
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"Cost component {name!r} must be finite and non-negative; got {value!r}"
                )
        return self

    def weighted(self, weights: Mapping[str, float]) -> float:
        self.validate()
        return sum(
            float(weights.get(name, 0.0)) * float(getattr(self, name))
            for name in asdict(self)
        )

    def __add__(self, other: "CostVector") -> "CostVector":
        return CostVector(
            bytes=self.bytes + other.bytes,
            privacy=self.privacy + other.privacy,
            latency_ms=self.latency_ms + other.latency_ms,
            fragility=self.fragility + other.fragility,
        )

    def as_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True)
class FactSpec:
    name: str
    domain: str = "execution"
    entity: str = "action"
    sensitivity: int = 0
    negative_evidence_channel: str | None = None
    description: str = ""


@dataclass(frozen=True)
class ObservationSpec:
    """A typed information channel from a world to an observable value."""

    name: str
    kind: str
    sources: tuple[str, ...] = ()
    expression: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    output_type: str = "any"
    entity: str = "action"
    description: str = ""

    def evaluate(self, world: Mapping[str, Any]) -> Any:
        from .expr import evaluate
        from .runtime.events import canonical_json
        import hashlib

        if self.kind == "exact":
            if not self.sources:
                raise ValueError(f"Exact observation {self.name!r} has no source")
            value: Any = (
                world[self.sources[0]]
                if len(self.sources) == 1
                else tuple(world[name] for name in self.sources)
            )
        elif self.kind in {"predicate", "relation", "aggregate"}:
            if not self.expression:
                raise ValueError(
                    f"Observation {self.name!r} of kind {self.kind!r} needs an expression"
                )
            value = evaluate(self.expression, world)
        elif self.kind == "bucket":
            if len(self.sources) != 1:
                raise ValueError(f"Bucket observation {self.name!r} needs one source")
            boundaries = tuple(float(x) for x in self.parameters.get("boundaries", ()))
            if tuple(sorted(boundaries)) != boundaries:
                raise ValueError(f"Bucket boundaries for {self.name!r} must be sorted")
            raw = float(world[self.sources[0]])
            index = sum(raw > boundary for boundary in boundaries)
            labels = tuple(self.parameters.get("labels", ()))
            value = labels[index] if labels else index
        elif self.kind == "digest":
            payload = {
                "namespace": str(self.parameters.get("namespace", self.name)),
                "values": [world[name] for name in self.sources],
            }
            value = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        elif self.kind == "presence":
            if len(self.sources) != 1:
                raise ValueError(f"Presence observation {self.name!r} needs one source")
            value = world.get(self.sources[0]) is not None
        else:
            raise ValueError(
                f"Unsupported observation kind {self.kind!r} for {self.name!r}"
            )
        return _freeze_observation_value(value)

    @property
    def exactly_revealed_facts(self) -> tuple[str, ...]:
        return self.sources if self.kind == "exact" else ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "sources": list(self.sources),
            "expression": self.expression,
            "parameters": dict(self.parameters),
            "output_type": self.output_type,
            "entity": self.entity,
            "description": self.description,
        }


def _freeze_observation_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(
            (str(key), _freeze_observation_value(item))
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_observation_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(_freeze_observation_value(item) for item in value))
    try:
        hash(value)
    except TypeError as exc:
        raise ValueError(f"Observation value is not canonicalizable: {value!r}") from exc
    return value


@dataclass(frozen=True)
class MediationChannel:
    name: str
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    mediator: str
    description: str = ""


@dataclass(frozen=True)
class DeploymentTopology:
    nodes: frozenset[str] = frozenset()
    edges: tuple[tuple[str, str], ...] = ()
    channels: Mapping[str, MediationChannel] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": sorted(self.nodes),
            "edges": [list(edge) for edge in self.edges],
            "channels": {
                name: {
                    "sources": list(channel.sources),
                    "sinks": list(channel.sinks),
                    "mediator": channel.mediator,
                    "description": channel.description,
                }
                for name, channel in sorted(self.channels.items())
            },
        }


@dataclass(frozen=True)
class ReplayContract:
    target: str
    prefix_checkpoint: str
    snapshot: str
    nondeterminism: tuple[str, ...]
    isolation: str
    side_effect_mode: str
    verifier: str
    compensation: str | None = None
    min_trials: int = 1

    def validate(self, *, adapter: str | None = None) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        required_strings = {
            "target": self.target,
            "prefix_checkpoint": self.prefix_checkpoint,
            "snapshot": self.snapshot,
            "isolation": self.isolation,
            "side_effect_mode": self.side_effect_mode,
            "verifier": self.verifier,
        }
        for field_name, value in required_strings.items():
            if not value or value.lower() in {"none", "unknown", "unavailable"}:
                reasons.append(f"missing_or_unknown:{field_name}")
        if not self.nondeterminism:
            reasons.append("missing:nondeterminism")
        if any(
            not source or source.lower() in {"none", "unknown", "unavailable"}
            for source in self.nondeterminism
        ):
            reasons.append("missing_or_unknown:nondeterminism_source")
        if len(set(self.nondeterminism)) != len(self.nondeterminism):
            reasons.append("invalid:duplicate_nondeterminism_source")
        if self.min_trials < 1:
            reasons.append("invalid:min_trials")
        if self.side_effect_mode == "irreversible":
            reasons.append("unsafe:irreversible_side_effect")
        if self.side_effect_mode == "compensated":
            if not self.compensation:
                reasons.append("missing:compensation")
            # No compensation implementation is registered in this artifact.
            # Fail closed instead of accepting a descriptive string as proof.
            reasons.append("unsupported:compensated_side_effect")
        if self.side_effect_mode not in {
            "read_only",
            "virtualized",
            "compensated",
            "irreversible",
        }:
            reasons.append("invalid:side_effect_mode")
        if adapter is None:
            reasons.append("missing:registered_adapter")
        else:
            from .adapter_registry import validate_replay_adapter

            reasons.extend(validate_replay_adapter(adapter, self))
        return not reasons, tuple(reasons)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Mechanism:
    name: str
    facts: tuple[str, ...] = ()
    observations: tuple[ObservationSpec, ...] = ()
    mode: str = "passive"  # passive | active
    producer: str = "agent"
    capture_point: str = "agent"
    trust_class: str = "agent_asserted"
    capabilities: tuple[str, ...] = ()
    binding_edges: tuple[tuple[str, str], ...] = ()
    requires: tuple[str, ...] = ()
    coverage_channel: str | None = None
    integrity: str = "none"
    adapter: str = "generic"
    capture: str = ""
    cost: CostVector = field(default_factory=CostVector)
    description: str = ""
    replay: ReplayContract | None = None
    tags: tuple[str, ...] = ()

    def observe(self, world: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
        if self.observations:
            return tuple(
                (observation.name, observation.evaluate(world))
                for observation in self.observations
            )
        return tuple((fact, world.get(fact)) for fact in self.facts)

    @property
    def exactly_revealed_facts(self) -> tuple[str, ...]:
        if not self.observations:
            return self.facts
        return tuple(
            dict.fromkeys(
                fact
                for observation in self.observations
                for fact in observation.exactly_revealed_facts
            )
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "facts": list(self.facts),
            "observations": [item.as_dict() for item in self.observations],
            "mode": self.mode,
            "producer": self.producer,
            "capture_point": self.capture_point,
            "trust_class": self.trust_class,
            "capabilities": list(self.capabilities),
            "binding_edges": [list(edge) for edge in self.binding_edges],
            "requires": list(self.requires),
            "coverage_channel": self.coverage_channel,
            "integrity": self.integrity,
            "adapter": self.adapter,
            "capture": self.capture,
            "cost": self.cost.as_dict(),
            "description": self.description,
            "replay": self.replay.as_dict() if self.replay else None,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class Query:
    name: str
    expression: str
    description: str = ""
    kind: str = "fact"
    assurance: str = "exact"
    anchor_domain: str = "execution"
    anchor_entity: str = "action"
    intervention_target: str | None = None
    required_capabilities: tuple[str, ...] = ()
    split: str = "development"  # development | held_out


@dataclass(frozen=True)
class ThreatModel:
    name: str
    compromised_producers: frozenset[str] = frozenset()
    trusted_capture_points: frozenset[str] = frozenset()
    accepted_integrity: frozenset[str] = frozenset({"none", "hash_chain", "hmac-sha256"})
    available_mechanisms: frozenset[str] | None = None
    mandatory_channels: frozenset[str] = frozenset()
    bypass_edges: tuple[tuple[str, str], ...] = ()
    description: str = ""

    def mechanism_allowed(self, mechanism: Mechanism) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if self.available_mechanisms is not None and mechanism.name not in self.available_mechanisms:
            reasons.append("unavailable")
        if mechanism.integrity not in self.accepted_integrity:
            reasons.append(f"integrity_not_accepted:{mechanism.integrity}")
        producer_compromised = mechanism.producer in self.compromised_producers
        capture_trusted = mechanism.capture_point in self.trusted_capture_points
        if producer_compromised and not capture_trusted:
            reasons.append("compromised_producer_without_trusted_capture")
        if producer_compromised and mechanism.trust_class == "agent_asserted":
            reasons.append("agent_assertion_not_authoritative")
        return not reasons, tuple(reasons)


@dataclass
class AuditSpec:
    name: str
    description: str
    variables: dict[str, list[Any]]
    constraints: list[str]
    facts: dict[str, FactSpec]
    queries: dict[str, Query]
    mechanisms: dict[str, Mechanism]
    threat_models: dict[str, ThreatModel]
    topology: DeploymentTopology = field(default_factory=DeploymentTopology)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TwinCertificate:
    schema_version: str
    spec_digest: str
    spec_name: str
    query: str
    contract: tuple[str, ...]
    world_a: World
    world_b: World
    answer_a: Any
    answer_b: Any
    shared_observation: dict[str, tuple[tuple[str, Any], ...]]
    separating_candidates: tuple[str, ...]
    derived_requirements: tuple[str, ...]
    threat_model: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TwinCertificate":
        if value.get("certificate_type") not in {None, "non-auditability"}:
            raise ValueError("Unsupported certificate type")
        return cls(
            schema_version=str(value.get("schema_version", "")),
            spec_digest=str(value.get("spec_digest", "")),
            spec_name=str(value["spec"]),
            query=str(value["query"]),
            contract=tuple(str(x) for x in value.get("contract", [])),
            world_a=dict(value["world_a"]),
            world_b=dict(value["world_b"]),
            answer_a=value["answer_a"],
            answer_b=value["answer_b"],
            shared_observation={
                str(name): tuple((str(k), v) for k, v in observations)
                for name, observations in value.get("shared_observation", {}).items()
            },
            separating_candidates=tuple(str(x) for x in value.get("separating_candidates", [])),
            derived_requirements=tuple(str(x) for x in value.get("derived_requirements", [])),
            threat_model=str(value.get("threat_model", "cooperative")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "certificate_type": "non-auditability",
            "schema_version": self.schema_version,
            "spec_digest": self.spec_digest,
            "spec": self.spec_name,
            "query": self.query,
            "contract": list(self.contract),
            "world_a": self.world_a,
            "world_b": self.world_b,
            "answer_a": self.answer_a,
            "answer_b": self.answer_b,
            "shared_observation": {
                name: [list(item) for item in observations]
                for name, observations in self.shared_observation.items()
            },
            "separating_candidates": list(self.separating_candidates),
            "derived_requirements": list(self.derived_requirements),
            "threat_model": self.threat_model,
        }


@dataclass
class SynthesisResult:
    status: str
    query: str
    threat_model: str
    contract: list[str]
    cost: CostVector
    scalar_cost: float
    iterations: int
    worlds: int
    certificates_seen: int
    derived_requirements: list[str] = field(default_factory=list)
    rejected_mechanisms: dict[str, list[str]] = field(default_factory=dict)
    minimality_witnesses: dict[str, dict[str, Any]] = field(default_factory=dict)
    unresolved_certificate: TwinCertificate | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "query": self.query,
            "threat_model": self.threat_model,
            "contract": self.contract,
            "cost": self.cost.as_dict(),
            "scalar_cost": self.scalar_cost,
            "iterations": self.iterations,
            "worlds": self.worlds,
            "certificates_seen": self.certificates_seen,
            "derived_requirements": self.derived_requirements,
            "rejected_mechanisms": self.rejected_mechanisms,
            "minimality_witnesses": self.minimality_witnesses,
            "unresolved_certificate": (
                self.unresolved_certificate.as_dict() if self.unresolved_certificate else None
            ),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class InstrumentationItem:
    mechanism: str
    mode: str
    producer: str
    capture_point: str
    adapter: str
    capture: str
    facts: tuple[str, ...]
    observations: tuple[ObservationSpec, ...]
    binding_edges: tuple[tuple[str, str], ...]
    capabilities: tuple[str, ...]
    requires: tuple[str, ...]
    integrity: str
    replay: ReplayContract | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "mode": self.mode,
            "producer": self.producer,
            "capture_point": self.capture_point,
            "adapter": self.adapter,
            "capture": self.capture,
            "facts": list(self.facts),
            "observations": [item.as_dict() for item in self.observations],
            "binding_edges": [list(edge) for edge in self.binding_edges],
            "capabilities": list(self.capabilities),
            "requires": list(self.requires),
            "integrity": self.integrity,
            "replay": self.replay.as_dict() if self.replay else None,
        }
