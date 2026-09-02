from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from ..adapter_registry import (
    ADAPTER_MANIFESTS,
    REPLAY_ADAPTERS,
    registry_attestation_status,
    registry_digest,
)
from ..model import AuditSpec
from ..topology import verify_mediation
from .evidence import entity_identifier, root_digest
from .events import EventSink, canonical_json
from .replay_proof import REPLAY_PROOF_SCHEMA


@dataclass(frozen=True)
class ConformanceResult:
    valid: bool
    errors: tuple[str, ...]
    checked_mechanisms: tuple[str, ...]
    event_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def certify_adapter_run(
    spec: AuditSpec,
    world: Mapping[str, Any],
    sink: EventSink,
    contract: Sequence[str],
    *,
    threat_model: str = "cooperative",
    expected_action_id: str | None = None,
    expected_run_id: str | None = None,
) -> ConformanceResult:
    """Certify an adapter against a development-time semantic oracle.

    This procedure deliberately receives the hidden model ``world`` so that it
    can compare emitted values with ground truth.  It is an adapter/test-fixture
    certification step, not a deployment-time audit verifier.  Deployment-time
    verification is implemented by :func:`verify_run_evidence` and has no world
    parameter.
    """
    errors: list[str] = []
    chain_valid, chain_errors = sink.verify()
    if not chain_valid:
        errors.extend(f"chain:{item}" for item in chain_errors)
    attested, attestation_errors = registry_attestation_status()
    if not attested:
        errors.extend(attestation_errors)

    selected = tuple(sorted(set(contract)))
    unexpected = sorted({event.mechanism for event in sink.events} - set(selected))
    if unexpected:
        errors.append(f"unexpected_mechanisms:{','.join(unexpected)}")
    action_ids = {event.action_id for event in sink.events}
    run_ids = {event.run_id for event in sink.events}
    if expected_action_id is not None and action_ids != {expected_action_id}:
        errors.append("action_identity:mismatch")
    if len(action_ids) > 1:
        errors.append("action_identity:inconsistent")
    if expected_run_id is not None and run_ids != {expected_run_id}:
        errors.append("run_identity:mismatch")
    if len(run_ids) > 1:
        errors.append("run_identity:inconsistent")

    threat = spec.threat_models[threat_model]
    for name in selected:
        mechanism = spec.mechanisms.get(name)
        if mechanism is None:
            errors.append(f"unknown_mechanism:{name}")
            continue
        events = [event for event in sink.events if event.mechanism == name]
        if not events:
            errors.append(f"missing_mechanism:{name}")
            continue
        manifest = ADAPTER_MANIFESTS.get(mechanism.adapter)
        if manifest is None:
            errors.append(f"unregistered_adapter:{name}:{mechanism.adapter}")
            continue
        observations: dict[str, Any] = {}
        for event in events:
            if event.adapter_id != mechanism.adapter:
                errors.append(f"adapter_id:{name}")
            if event.adapter_version != manifest.version:
                errors.append(f"adapter_version:{name}")
            if event.registry_sha256 != registry_digest():
                errors.append(f"registry_digest:{name}")
            if event.producer != mechanism.producer:
                errors.append(f"producer:{name}")
            if event.capture_point != mechanism.capture_point:
                errors.append(f"capture_point:{name}")
            if event.attributes.get("root_digest") != root_digest(spec, world):
                errors.append(f"root_digest:{name}")
            values = event.attributes.get("observation_values")
            if not isinstance(values, Mapping):
                errors.append(f"observation_envelope:{name}")
            else:
                for key, value in values.items():
                    if key in observations and observations[key] != value:
                        errors.append(f"observation_conflict:{name}:{key}")
                    observations[str(key)] = value

        expected_observations = dict(mechanism.observe(world))
        for key, expected in expected_observations.items():
            if key not in observations:
                errors.append(f"observation_missing:{name}:{key}")
            elif observations[key] != expected:
                errors.append(f"observation_value:{name}:{key}")

        if mechanism.binding_edges:
            if not any(
                _binding_valid(spec, world, event.attributes.get("binding_proof"), event.action_id, mechanism.binding_edges)
                for event in events
            ):
                errors.append(f"binding:{name}")
        if any(target == "policy_version" for _, target in mechanism.binding_edges):
            expected_policy = entity_identifier(spec, world, "policy_version")
            if not any(
                event.attributes.get("policy_version_id") == expected_policy
                for event in events
            ):
                errors.append(f"policy_version:{name}")
        if mechanism.coverage_channel:
            proof = verify_mediation(
                spec.topology,
                mechanism.coverage_channel,
                bypass_edges=threat.bypass_edges,
            )
            if not proof.valid:
                errors.append(f"mediation:{name}:{proof.reason}")
            if not any(
                event.attributes.get("mediation_channel")
                == mechanism.coverage_channel
                and event.attributes.get("declared_mediator") == proof.mediator
                and event.capture_point == proof.mediator
                for event in events
            ):
                errors.append(f"mediation_evidence:{name}")
        if mechanism.mode == "active" and mechanism.replay is not None:
            if not any(
                _replay_proof_valid(
                    event.attributes,
                    mechanism.replay,
                    adapter_id=mechanism.adapter,
                    world=world,
                )
                for event in events
            ):
                errors.append(f"replay_proof:{name}")

    return ConformanceResult(
        valid=not errors,
        errors=tuple(sorted(set(errors))),
        checked_mechanisms=selected,
        event_count=len(sink.events),
    )


def verify_runtime_conformance(
    spec: AuditSpec,
    world: Mapping[str, Any],
    sink: EventSink,
    contract: Sequence[str],
    *,
    threat_model: str = "cooperative",
    expected_action_id: str | None = None,
    expected_run_id: str | None = None,
) -> ConformanceResult:
    """Compatibility alias for the development-time certification procedure.

    The name is retained for the v0.3 public API.  New code should use
    :func:`certify_adapter_run` for oracle-based certification and
    :func:`auditspec.runtime.run_verification.verify_run_evidence` for
    deployment-time evidence verification.
    """

    return certify_adapter_run(
        spec,
        world,
        sink,
        contract,
        threat_model=threat_model,
        expected_action_id=expected_action_id,
        expected_run_id=expected_run_id,
    )

def _binding_valid(
    spec: AuditSpec,
    world: Mapping[str, Any],
    raw: Any,
    action_id: str,
    edges: tuple[tuple[str, str], ...],
) -> bool:
    if not isinstance(raw, Mapping):
        return False
    expected_edges = [list(edge) for edge in edges]
    if raw.get("edges") != expected_edges:
        return False
    ids = raw.get("entity_ids")
    if not isinstance(ids, Mapping):
        return False
    root = str(spec.metadata.get("anchor_entity", "action"))
    if ids.get(root) != action_id:
        return False
    for source, target in edges:
        expected_source = (
            action_id if source == root else entity_identifier(spec, world, source)
        )
        if ids.get(source) != expected_source:
            return False
        if ids.get(target) != entity_identifier(spec, world, target):
            return False
    payload = {"edges": expected_edges, "entity_ids": dict(ids)}
    expected_digest = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return raw.get("digest") == expected_digest


def _replay_proof_valid(
    attributes: Mapping[str, Any],
    replay: Any,
    *,
    adapter_id: str,
    world: Mapping[str, Any] | None,
) -> bool:
    proof = attributes.get("replay_proof")
    if not isinstance(proof, Mapping):
        return False
    manifest = REPLAY_ADAPTERS.get(adapter_id)
    if manifest is None or manifest.assurance_level != "executable":
        return False
    try:
        trials = int(proof.get("trials", 0))
    except (TypeError, ValueError):
        return False
    exact = {
        "schema": REPLAY_PROOF_SCHEMA,
        "adapter_id": adapter_id,
        "implementation_ref": manifest.implementation_ref,
        "target": replay.target,
        "prefix_checkpoint": replay.prefix_checkpoint,
        "snapshot": replay.snapshot,
        "isolation": replay.isolation,
        "side_effect_mode": replay.side_effect_mode,
        "verifier": replay.verifier,
    }
    if any(proof.get(name) != expected for name, expected in exact.items()):
        return False
    if tuple(proof.get("nondeterminism", ())) != replay.nondeterminism:
        return False
    captures = proof.get("nondeterminism_capture")
    if not isinstance(captures, Mapping) or set(captures) != set(replay.nondeterminism):
        return False
    expected_capture_digest = hashlib.sha256(
        canonical_json({name: captures[name] for name in sorted(captures)}).encode(
            "utf-8"
        )
    ).hexdigest()
    if proof.get("nondeterminism_capture_digest") != expected_capture_digest:
        return False
    for source in replay.nondeterminism:
        item = captures.get(source)
        if not isinstance(item, Mapping) or item.get("source") != source:
            return False
        if item.get("mode") not in {
            "captured",
            "intervened",
            "frozen",
            "proved_unused",
        }:
            return False
        replay_values = item.get("replay_values")
        if not isinstance(replay_values, list) or len(replay_values) < trials:
            return False
        unsigned = {
            "source": source,
            "mode": item.get("mode"),
            "original_value": item.get("original_value"),
            "replay_values": replay_values,
        }
        if item.get("value_digest") != hashlib.sha256(
            canonical_json(unsigned).encode("utf-8")
        ).hexdigest():
            return False
        if (
            world is not None
            and source == "tool_response"
            and item.get("original_value") != world.get("tool_response")
        ):
            return False
        if (
            world is not None
            and source == "model_output"
            and item.get("original_value") != world.get("model_decision")
        ):
            return False
    return bool(
        trials >= replay.min_trials
        and proof.get("prefix_equal") is True
        and proof.get("verifier_passed") is True
    )
