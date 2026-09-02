from __future__ import annotations

import hashlib
from typing import Any, Mapping

from ..adapter_registry import ADAPTER_MANIFESTS, registry_digest
from ..model import AuditSpec
from .events import AuditEvent, EventSink, canonical_json


def entity_identifier(spec: AuditSpec, world: Mapping[str, Any], entity: str) -> str:
    payload = {
        name: world[name]
        for name, fact in sorted(spec.facts.items())
        if fact.entity == entity and name in world
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{entity}:{digest[:24]}"


def root_digest(spec: AuditSpec, world: Mapping[str, Any]) -> str:
    entity = str(spec.metadata.get("anchor_entity", "action"))
    identity_facts = tuple(str(x) for x in spec.metadata.get("identity_facts", ()))
    if identity_facts:
        payload = {name: world[name] for name in identity_facts}
    else:
        payload = {
            name: world[name]
            for name, fact in sorted(spec.facts.items())
            if fact.entity == entity and name in world
        }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def binding_proof(
    spec: AuditSpec,
    world: Mapping[str, Any],
    action_id: str,
    binding_edges: tuple[tuple[str, str], ...],
) -> dict[str, Any] | None:
    if not binding_edges:
        return None
    root = str(spec.metadata.get("anchor_entity", "action"))
    ids: dict[str, str] = {root: action_id}
    for source, target in binding_edges:
        ids.setdefault(
            source,
            action_id if source == root else entity_identifier(spec, world, source),
        )
        ids.setdefault(target, entity_identifier(spec, world, target))
    payload = {
        "edges": [list(edge) for edge in binding_edges],
        "entity_ids": ids,
    }
    payload["digest"] = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload


def emit_mechanism_event(
    sink: EventSink,
    spec: AuditSpec,
    mechanism_name: str,
    world: Mapping[str, Any],
    *,
    run_id: str,
    action_id: str,
    attributes: Mapping[str, Any] | None = None,
    observation_names: set[str] | None = None,
) -> AuditEvent | None:
    mechanism = spec.mechanisms[mechanism_name]
    manifest = ADAPTER_MANIFESTS[mechanism.adapter]
    observation_values = dict(mechanism.observe(world))
    if observation_names is not None:
        observation_values = {
            name: value
            for name, value in observation_values.items()
            if name in observation_names
        }
    reserved: dict[str, Any] = {
        "observation_values": observation_values,
        "root_digest": root_digest(spec, world),
    }
    binding = binding_proof(
        spec, world, action_id, mechanism.binding_edges
    )
    if binding is not None:
        reserved["binding_proof"] = binding
    if any(target == "policy_version" for _, target in mechanism.binding_edges):
        reserved["policy_version_id"] = entity_identifier(
            spec, world, "policy_version"
        )
    if mechanism.coverage_channel:
        channel = spec.topology.channels.get(mechanism.coverage_channel)
        reserved["mediation_channel"] = mechanism.coverage_channel
        reserved["declared_mediator"] = channel.mediator if channel else None
    merged = dict(attributes or {})
    merged.update(reserved)
    return sink.emit(
        mechanism=mechanism_name,
        adapter_id=mechanism.adapter,
        adapter_version=manifest.version,
        registry_sha256=registry_digest(),
        producer=mechanism.producer,
        capture_point=mechanism.capture_point,
        run_id=run_id,
        action_id=action_id,
        attributes=merged,
    )
