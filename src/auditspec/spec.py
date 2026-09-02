from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .expr import evaluate, referenced_names
from .model import (
    AuditSpec,
    CostVector,
    DeploymentTopology,
    FactSpec,
    MediationChannel,
    Mechanism,
    ObservationSpec,
    Query,
    ReplayContract,
    ThreatModel,
    World,
)


def load_spec(path: str | Path) -> AuditSpec:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Spec root must be a mapping")

    variables = _load_variables(raw.get("variables", {}))
    facts = _load_facts(raw.get("facts", {}), variables)
    metadata = dict(raw.get("metadata", {}))
    queries = _load_queries(
        raw.get("queries", {}),
        facts,
        default_anchor_entity=str(metadata.get("anchor_entity", "action")),
    )
    mechanisms = _load_mechanisms(raw, variables)
    threat_models = _load_threat_models(raw.get("threat_models", {}), mechanisms)
    topology = _load_topology(raw.get("topology", {}))

    unknown_mechanism_facts = {
        fact
        for mechanism in mechanisms.values()
        for fact in mechanism.facts
        if fact not in facts
    }
    if unknown_mechanism_facts:
        raise ValueError(f"Mechanisms expose undeclared facts: {sorted(unknown_mechanism_facts)}")
    unknown_dependencies = {
        dependency
        for mechanism in mechanisms.values()
        for dependency in mechanism.requires
        if dependency not in mechanisms
    }
    if unknown_dependencies:
        raise ValueError(f"Unknown mechanism dependencies: {sorted(unknown_dependencies)}")

    return AuditSpec(
        name=str(raw.get("name", path.stem)),
        description=str(raw.get("description", "")),
        variables=variables,
        constraints=[str(x) for x in raw.get("constraints", [])],
        facts=facts,
        queries=queries,
        mechanisms=mechanisms,
        threat_models=threat_models,
        topology=topology,
        metadata=metadata,
    )


def _load_variables(raw_variables: Any) -> dict[str, list[Any]]:
    if not isinstance(raw_variables, dict) or not raw_variables:
        raise ValueError("Spec must declare at least one variable")
    variables: dict[str, list[Any]] = {}
    for name, domain in raw_variables.items():
        if not isinstance(domain, list) or not domain:
            raise ValueError(f"Variable {name!r} needs a non-empty list domain")
        variables[str(name)] = domain
    return variables


def _load_facts(raw_facts: Any, variables: dict[str, list[Any]]) -> dict[str, FactSpec]:
    raw_facts = raw_facts or {}
    if not isinstance(raw_facts, dict):
        raise ValueError("facts must be a mapping")
    facts: dict[str, FactSpec] = {}
    for name in variables:
        cfg = raw_facts.get(name, {})
        if isinstance(cfg, str):
            cfg = {"domain": cfg}
        facts[name] = FactSpec(
            name=name,
            domain=str(cfg.get("domain", "execution")),
            entity=str(cfg.get("entity", "action")),
            sensitivity=int(cfg.get("sensitivity", 0)),
            negative_evidence_channel=(
                str(cfg["negative_evidence_channel"])
                if cfg.get("negative_evidence_channel") is not None
                else None
            ),
            description=str(cfg.get("description", "")),
        )
    extra = set(raw_facts) - set(variables)
    if extra:
        raise ValueError(f"Facts without variable domains: {sorted(extra)}")
    return facts


def _load_queries(
    raw_queries: Any,
    facts: dict[str, FactSpec],
    *,
    default_anchor_entity: str,
) -> dict[str, Query]:
    if not isinstance(raw_queries, dict) or not raw_queries:
        raise ValueError("Spec must declare at least one query")
    queries: dict[str, Query] = {}
    for name, cfg in raw_queries.items():
        if isinstance(cfg, str):
            cfg = {"expression": cfg}
        query = Query(
            name=str(name),
            expression=str(cfg["expression"]),
            description=str(cfg.get("description", "")),
            kind=str(cfg.get("kind", "fact")),
            assurance=str(cfg.get("assurance", "exact")),
            anchor_domain=str(cfg.get("anchor_domain", "execution")),
            anchor_entity=str(cfg.get("anchor_entity", default_anchor_entity)),
            intervention_target=(
                str(cfg["intervention_target"])
                if cfg.get("intervention_target") is not None
                else None
            ),
            required_capabilities=tuple(str(x) for x in cfg.get("required_capabilities", [])),
            split=str(cfg.get("split", "development")),
        )
        unknown = referenced_names(query.expression) - facts.keys()
        if unknown:
            raise ValueError(f"Query {name!r} references undeclared facts: {sorted(unknown)}")
        if query.assurance != "exact":
            raise ValueError(
                f"Query {name!r} requests unsupported assurance {query.assurance!r}; "
                "AuditSpec v0.3 implements exact finite-world assurance only"
            )
        if query.kind == "causality" and not query.intervention_target:
            raise ValueError(f"Causal query {name!r} needs intervention_target")
        queries[str(name)] = query
    return queries


def _load_mechanisms(raw: dict[str, Any], variables: dict[str, list[Any]]) -> dict[str, Mechanism]:
    raw_mechanisms = raw.get("mechanisms")
    legacy = False
    if raw_mechanisms is None:
        raw_mechanisms = raw.get("sensors", {})
        legacy = True
    if not isinstance(raw_mechanisms, dict) or not raw_mechanisms:
        raise ValueError("Spec must declare at least one mechanism")

    mechanisms: dict[str, Mechanism] = {}
    for name, cfg in raw_mechanisms.items():
        observations = _load_observations(str(name), cfg, variables)
        declared_facts = tuple(str(x) for x in cfg.get("facts", cfg.get("fields", [])))
        if not declared_facts:
            declared_facts = tuple(
                dict.fromkeys(
                    source
                    for observation in observations
                    for source in observation.sources
                )
            )
        replay_cfg = cfg.get("replay")
        replay = None
        if replay_cfg:
            replay = ReplayContract(
                target=str(replay_cfg.get("target", "")),
                prefix_checkpoint=str(replay_cfg.get("prefix_checkpoint", "")),
                snapshot=str(replay_cfg.get("snapshot", "")),
                nondeterminism=tuple(str(x) for x in replay_cfg.get("nondeterminism", [])),
                isolation=str(replay_cfg.get("isolation", "")),
                side_effect_mode=str(replay_cfg.get("side_effect_mode", "")),
                verifier=str(replay_cfg.get("verifier", "")),
                compensation=(
                    str(replay_cfg["compensation"])
                    if replay_cfg.get("compensation") is not None
                    else None
                ),
                min_trials=int(replay_cfg.get("min_trials", 1)),
            )
        mechanisms[str(name)] = Mechanism(
            name=str(name),
            facts=declared_facts,
            observations=observations,
            mode=str(cfg.get("mode", "passive")),
            producer=str(cfg.get("producer", cfg.get("boundary", "agent"))),
            capture_point=str(cfg.get("capture_point", cfg.get("boundary", "agent"))),
            trust_class=str(cfg.get("trust_class", "legacy_boundary" if legacy else "agent_asserted")),
            capabilities=tuple(str(x) for x in cfg.get("capabilities", [])),
            binding_edges=_load_binding_edges(cfg.get("binding_edges", [])),
            requires=tuple(str(x) for x in cfg.get("requires", [])),
            coverage_channel=(
                str(cfg["coverage_channel"]) if cfg.get("coverage_channel") is not None else None
            ),
            integrity=str(cfg.get("integrity", "none")),
            adapter=str(cfg.get("adapter", "generic")),
            capture=str(cfg.get("capture", "")),
            cost=CostVector.from_mapping(cfg.get("cost")),
            description=str(cfg.get("description", "")),
            replay=replay,
            tags=tuple(str(x) for x in cfg.get("tags", [])),
        )
    return mechanisms


def _load_observations(
    mechanism_name: str,
    cfg: dict[str, Any],
    variables: dict[str, list[Any]],
) -> tuple[ObservationSpec, ...]:
    raw_observations = cfg.get("observations")
    if raw_observations is None:
        legacy_facts = tuple(str(x) for x in cfg.get("facts", cfg.get("fields", [])))
        return tuple(
            ObservationSpec(
                name=fact,
                kind="exact",
                sources=(fact,),
                output_type="world_value",
            )
            for fact in legacy_facts
        )
    if not isinstance(raw_observations, list) or not raw_observations:
        raise ValueError(
            f"Mechanism {mechanism_name!r} observations must be a non-empty list"
        )
    observations: list[ObservationSpec] = []
    names: set[str] = set()
    for index, raw in enumerate(raw_observations):
        if isinstance(raw, str):
            raw = {"name": raw, "kind": "exact", "sources": [raw]}
        if not isinstance(raw, dict):
            raise ValueError(
                f"Mechanism {mechanism_name!r} observation {index} must be a mapping"
            )
        observation_name = str(raw.get("name", f"observation_{index}"))
        if observation_name in names:
            raise ValueError(
                f"Mechanism {mechanism_name!r} repeats observation {observation_name!r}"
            )
        names.add(observation_name)
        expression = (
            str(raw["expression"]) if raw.get("expression") is not None else None
        )
        sources = tuple(str(x) for x in raw.get("sources", []))
        if expression:
            expression_sources = referenced_names(expression)
            if not sources:
                sources = tuple(sorted(expression_sources))
            elif not expression_sources <= set(sources):
                raise ValueError(
                    f"Observation {mechanism_name}.{observation_name} expression uses "
                    f"sources absent from its declaration: {sorted(expression_sources - set(sources))}"
                )
        unknown = set(sources) - set(variables)
        if unknown:
            raise ValueError(
                f"Observation {mechanism_name}.{observation_name} uses undeclared facts: {sorted(unknown)}"
            )
        observations.append(
            ObservationSpec(
                name=observation_name,
                kind=str(raw.get("kind", "exact")),
                sources=sources,
                expression=expression,
                parameters=dict(raw.get("parameters", {})),
                output_type=str(raw.get("output_type", "any")),
                entity=str(raw.get("entity", "action")),
                description=str(raw.get("description", "")),
            )
        )
    return tuple(observations)


def _load_binding_edges(raw: Any) -> tuple[tuple[str, str], ...]:
    edges: list[tuple[str, str]] = []
    for item in raw or []:
        if isinstance(item, str) and "->" in item:
            source, target = item.split("->", 1)
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            source, target = item
        elif isinstance(item, dict):
            source, target = item.get("from"), item.get("to")
        else:
            raise ValueError(f"Invalid binding edge: {item!r}")
        source, target = str(source).strip(), str(target).strip()
        if not source or not target or source == target:
            raise ValueError(f"Invalid binding edge: {item!r}")
        edges.append((source, target))
    return tuple(dict.fromkeys(edges))


def _load_topology(raw: Any) -> DeploymentTopology:
    if not raw:
        return DeploymentTopology()
    if not isinstance(raw, dict):
        raise ValueError("topology must be a mapping")
    nodes = frozenset(str(x) for x in raw.get("nodes", []))
    edges = _load_binding_edges(raw.get("edges", []))
    channels: dict[str, MediationChannel] = {}
    for name, cfg in (raw.get("channels", {}) or {}).items():
        channel = MediationChannel(
            name=str(name),
            sources=tuple(str(x) for x in cfg.get("sources", [])),
            sinks=tuple(str(x) for x in cfg.get("sinks", [])),
            mediator=str(cfg.get("mediator", "")),
            description=str(cfg.get("description", "")),
        )
        mentioned = set(channel.sources) | set(channel.sinks) | {channel.mediator}
        if not channel.sources or not channel.sinks or not channel.mediator:
            raise ValueError(f"Topology channel {name!r} is incomplete")
        if nodes and not mentioned <= nodes:
            raise ValueError(
                f"Topology channel {name!r} references unknown nodes: {sorted(mentioned - nodes)}"
            )
        channels[str(name)] = channel
    edge_nodes = {node for edge in edges for node in edge}
    if nodes and not edge_nodes <= nodes:
        raise ValueError(f"Topology edges reference unknown nodes: {sorted(edge_nodes - nodes)}")
    return DeploymentTopology(nodes=nodes, edges=edges, channels=channels)


def _load_threat_models(
    raw_tms: Any, mechanisms: dict[str, Mechanism]
) -> dict[str, ThreatModel]:
    if not raw_tms:
        raw_tms = {
            "cooperative": {
                "trusted_capture_points": sorted({m.capture_point for m in mechanisms.values()}),
                "accepted_integrity": ["none", "hash_chain", "hmac-sha256"],
            }
        }
    threat_models: dict[str, ThreatModel] = {}
    for name, cfg in raw_tms.items():
        available = cfg.get("available_mechanisms")
        threat_models[str(name)] = ThreatModel(
            name=str(name),
            compromised_producers=frozenset(str(x) for x in cfg.get("compromised_producers", [])),
            trusted_capture_points=frozenset(
                str(x)
                for x in cfg.get(
                    "trusted_capture_points", cfg.get("trusted_boundaries", [])
                )
            ),
            accepted_integrity=frozenset(
                str(x)
                for x in cfg.get(
                    "accepted_integrity", ["none", "hash_chain", "hmac-sha256"]
                )
            ),
            available_mechanisms=(
                frozenset(str(x) for x in available) if available is not None else None
            ),
            mandatory_channels=frozenset(str(x) for x in cfg.get("mandatory_channels", [])),
            bypass_edges=_load_binding_edges(cfg.get("bypass_edges", [])),
            description=str(cfg.get("description", "")),
        )
    return threat_models


def enumerate_worlds(spec: AuditSpec) -> list[World]:
    names = list(spec.variables)
    worlds: list[World] = []

    def visit(index: int, current: dict[str, Any]) -> None:
        if index == len(names):
            if all(bool(evaluate(expr, current)) for expr in spec.constraints):
                worlds.append(dict(current))
            return
        name = names[index]
        for value in spec.variables[name]:
            current[name] = value
            visit(index + 1, current)
        current.pop(name, None)

    visit(0, {})
    return worlds
