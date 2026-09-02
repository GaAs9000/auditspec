from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from ..adapter_registry import (
    ADAPTER_MANIFESTS,
    registry_attestation_status,
    registry_digest,
    validate_mechanism_adapter,
)
from ..model import AuditSpec, Mechanism
from ..spec import enumerate_worlds
from ..topology import verify_mediation
from .conformance import _replay_proof_valid
from .events import AuditEvent, EventSink, canonical_json
from .evidence import entity_identifier


_ENTITY_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:[0-9a-f]{24}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_NS = (1 << 63) - 1


@dataclass(frozen=True)
class PolicyRoot:
    """An authoritative, frozen policy version known before a run is audited."""

    version_id: str
    mechanism_observations: Mapping[str, Mapping[str, Any]]
    valid_from_ns: int = 0
    valid_to_ns: int = _MAX_NS

    def __post_init__(self) -> None:
        if self.valid_from_ns < 0 or self.valid_to_ns < self.valid_from_ns:
            raise ValueError("Invalid policy-root validity interval")


@dataclass(frozen=True)
class RunTrustContext:
    """Deployment trust roots supplied independently of the evidence stream.

    The context is intentionally a closed, non-oracular schema: it contains
    pre-established producer/policy roots and optional run selectors, never a
    hidden execution world, expected audit answer, or unconstrained semantic
    fact.  A per-run policy selector is accepted only when retained evidence
    binds it to a root already present in ``policy_roots``.
    """

    producer_keys: Mapping[str, bytes]
    policy_roots: Mapping[str, PolicyRoot] = field(default_factory=dict)
    expected_action_id: str | None = None
    expected_run_id: str | None = None
    required_event_counts: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RunEvidenceVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    checked_mechanisms: tuple[str, ...]
    event_count: int
    action_ids: tuple[str, ...]
    run_ids: tuple[str, ...]
    root_digests: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def fixture_producer_key(producer: str) -> bytes:
    """Return the deterministic key used only by the bundled local fixtures."""

    return hashlib.sha256(f"auditspec-fixture:{producer}".encode("utf-8")).digest()


def build_fixture_trust_context(
    spec: AuditSpec,
    *,
    expected_action_id: str | None = None,
    expected_run_id: str | None = None,
    required_event_counts: Mapping[str, int] | None = None,
) -> RunTrustContext:
    """Build explicit trust roots for deterministic examples and tests.

    This helper makes the fixture assumptions visible.  Production callers must
    construct :class:`RunTrustContext` from their own key management and frozen
    policy registry rather than use these deterministic keys.
    """

    producers = {mechanism.producer for mechanism in spec.mechanisms.values()}
    return RunTrustContext(
        producer_keys={name: fixture_producer_key(name) for name in producers},
        policy_roots=_fixture_policy_roots(spec),
        expected_action_id=expected_action_id,
        expected_run_id=expected_run_id,
        required_event_counts=dict(required_event_counts or {}),
    )


def verify_run_evidence(
    spec: AuditSpec,
    sink: EventSink,
    contract: Sequence[str],
    trust_context: RunTrustContext,
    *,
    threat_model: str = "cooperative",
) -> RunEvidenceVerificationResult:
    """Verify retained run evidence without access to a hidden execution world.

    Semantic truth is inherited only from separately certified adapters and
    authoritative producer/policy roots.  This verifier checks the evidence
    envelope, identities, bindings, topology, receipts, and replay proof.  It
    intentionally cannot compare observed values with an unavailable world.
    """

    errors: list[str] = []
    errors.extend(_verify_trusted_chain(sink.events, trust_context.producer_keys))
    attested, attestation_errors = registry_attestation_status()
    if not attested:
        errors.extend(attestation_errors)

    selected = tuple(sorted(set(contract)))
    unexpected = sorted({event.mechanism for event in sink.events} - set(selected))
    if unexpected:
        errors.append(f"unexpected_mechanisms:{','.join(unexpected)}")

    action_ids = {event.action_id for event in sink.events}
    run_ids = {event.run_id for event in sink.events}
    root_digests = {
        str(event.attributes.get("root_digest"))
        for event in sink.events
        if event.attributes.get("root_digest") is not None
    }
    if trust_context.expected_action_id is not None and action_ids != {
        trust_context.expected_action_id
    }:
        errors.append("action_identity:mismatch")
    if len(action_ids) > 1:
        errors.append("action_identity:inconsistent")
    if trust_context.expected_run_id is not None and run_ids != {
        trust_context.expected_run_id
    }:
        errors.append("run_identity:mismatch")
    if len(run_ids) > 1:
        errors.append("run_identity:inconsistent")
    if not root_digests or any(not _DIGEST.fullmatch(item) for item in root_digests):
        errors.append("root_digest:invalid")
    if len(root_digests) > 1:
        errors.append("root_digest:inconsistent")

    threat = spec.threat_models[threat_model]
    global_entity_ids: dict[str, str] = {}
    for name in selected:
        mechanism = spec.mechanisms.get(name)
        if mechanism is None:
            errors.append(f"unknown_mechanism:{name}")
            continue
        events = [event for event in sink.events if event.mechanism == name]
        required_count = max(1, int(trust_context.required_event_counts.get(name, 1)))
        if len(events) < required_count:
            errors.append(f"missing_mechanism:{name}")
            continue
        allowed, reasons = threat.mechanism_allowed(mechanism)
        adapter_reasons = validate_mechanism_adapter(mechanism)
        if not allowed or adapter_reasons:
            detail = ",".join(sorted(set(reasons + adapter_reasons)))
            errors.append(f"ineligible_mechanism:{name}:{detail}")

        manifest = ADAPTER_MANIFESTS.get(mechanism.adapter)
        if manifest is None:
            errors.append(f"unregistered_adapter:{name}:{mechanism.adapter}")
            continue
        observations: dict[str, Any] = {}
        for event in events:
            _verify_event_manifest(event, mechanism, manifest.version, name, errors)
            values = event.attributes.get("observation_values")
            if not isinstance(values, Mapping):
                errors.append(f"observation_envelope:{name}")
                continue
            for key, value in values.items():
                key = str(key)
                if key in observations and observations[key] != value:
                    errors.append(f"observation_conflict:{name}:{key}")
                observations[key] = value
                if key in event.attributes and event.attributes[key] != value:
                    errors.append(f"observation_attribute_binding:{name}:{key}")
            _verify_adapter_relations(event, values, errors)

        expected_names = {
            observation.name for observation in mechanism.observations
        } or set(mechanism.facts)
        missing_names = expected_names - observations.keys()
        extra_names = observations.keys() - expected_names
        for key in sorted(missing_names):
            errors.append(f"observation_missing:{name}:{key}")
        for key in sorted(extra_names):
            errors.append(f"observation_unexpected:{name}:{key}")

        if mechanism.binding_edges:
            valid_binding = False
            for event in events:
                ok, ids = _binding_valid_without_world(
                    spec,
                    event.attributes.get("binding_proof"),
                    event.action_id,
                    mechanism.binding_edges,
                )
                if ok:
                    valid_binding = True
                    for entity, entity_id in ids.items():
                        prior = global_entity_ids.setdefault(entity, entity_id)
                        if prior != entity_id:
                            errors.append(f"binding_identity_conflict:{entity}")
            if not valid_binding:
                errors.append(f"binding:{name}")

        if any(target == "policy_version" for _, target in mechanism.binding_edges):
            if not any(
                _policy_event_valid(event, name, observations, trust_context.policy_roots)
                for event in events
            ):
                errors.append(f"policy_root:{name}")

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
                    world=None,
                )
                for event in events
            ):
                errors.append(f"replay_proof:{name}")

        for dependency in sorted(set(mechanism.requires) - set(selected)):
            errors.append(f"missing_dependency:{name}:{dependency}")

    _verify_cross_receipts(sink.events, errors)
    return RunEvidenceVerificationResult(
        valid=not errors,
        errors=tuple(sorted(set(errors))),
        checked_mechanisms=selected,
        event_count=len(sink.events),
        action_ids=tuple(sorted(action_ids)),
        run_ids=tuple(sorted(run_ids)),
        root_digests=tuple(sorted(root_digests)),
    )


def _fixture_policy_roots(spec: AuditSpec) -> dict[str, PolicyRoot]:
    policy_mechanisms = {
        name: mechanism
        for name, mechanism in spec.mechanisms.items()
        if any(target == "policy_version" for _, target in mechanism.binding_edges)
    }
    roots: dict[str, dict[str, dict[str, Any]]] = {}
    for world in enumerate_worlds(spec):
        version_id = entity_identifier(spec, world, "policy_version")
        observations = roots.setdefault(version_id, {})
        for name, mechanism in policy_mechanisms.items():
            value = dict(mechanism.observe(world))
            prior = observations.setdefault(name, value)
            if prior != value:
                raise ValueError(
                    f"Policy version {version_id!r} does not uniquely determine {name!r}"
                )
    return {
        version_id: PolicyRoot(version_id, observations)
        for version_id, observations in roots.items()
    }


def _verify_trusted_chain(
    events: Sequence[AuditEvent], producer_keys: Mapping[str, bytes]
) -> list[str]:
    errors: list[str] = []
    prior: dict[str, str] = {}
    expected_sequence: dict[str, int] = {}
    for event in events:
        sequence = expected_sequence.get(event.run_id, 0) + 1
        previous_hash = prior.get(event.run_id, "0" * 64)
        if event.sequence != sequence:
            errors.append(f"chain:sequence:{event.event_id}")
        if event.previous_hash != previous_hash:
            errors.append(f"chain:previous_hash:{event.event_id}")
        body = {
            "run_id": event.run_id,
            "sequence": event.sequence,
            "mechanism": event.mechanism,
            "adapter_id": event.adapter_id,
            "adapter_version": event.adapter_version,
            "registry_sha256": event.registry_sha256,
            "producer": event.producer,
            "capture_point": event.capture_point,
            "action_id": event.action_id,
            "attributes": event.attributes,
            "captured_ns": event.captured_ns,
            "previous_hash": event.previous_hash,
        }
        event_hash = hashlib.sha256(
            (event.previous_hash + canonical_json(body)).encode("utf-8")
        ).hexdigest()
        if event_hash != event.event_hash:
            errors.append(f"chain:hash:{event.event_id}")
        key = producer_keys.get(event.producer)
        if key is None:
            errors.append(f"trust_root:unknown_producer:{event.producer}")
        else:
            signature = hmac.new(
                key, event_hash.encode("ascii"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, event.signature):
                errors.append(f"trust_root:signature:{event.event_id}")
        prior[event.run_id] = event.event_hash
        expected_sequence[event.run_id] = event.sequence
    return errors


def _verify_event_manifest(
    event: AuditEvent,
    mechanism: Mechanism,
    manifest_version: str,
    name: str,
    errors: list[str],
) -> None:
    if event.adapter_id != mechanism.adapter:
        errors.append(f"adapter_id:{name}")
    if event.adapter_version != manifest_version:
        errors.append(f"adapter_version:{name}")
    if event.registry_sha256 != registry_digest():
        errors.append(f"registry_digest:{name}")
    if event.producer != mechanism.producer:
        errors.append(f"producer:{name}")
    if event.capture_point != mechanism.capture_point:
        errors.append(f"capture_point:{name}")
    digest = event.attributes.get("root_digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        errors.append(f"root_digest:{name}")


def _verify_adapter_relations(
    event: AuditEvent, values: Mapping[str, Any], errors: list[str]
) -> None:
    """Check relations fully determined by the signed evidence itself."""

    if event.adapter_id == "canonical-action" and "amount" in values:
        payload = {"kind": "transfer", "amount": values["amount"], "currency": "USD"}
        expected = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        if event.attributes.get("action_digest") != expected:
            errors.append(f"adapter_relation:{event.mechanism}:action_digest")
    if event.adapter_id == "canonical-application" and "score" in values:
        payload = {"kind": "credit_application", "score": values["score"]}
        expected = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        if event.attributes.get("application_digest") != expected:
            errors.append(f"adapter_relation:{event.mechanism}:application_digest")


def _binding_valid_without_world(
    spec: AuditSpec,
    raw: Any,
    action_id: str,
    edges: tuple[tuple[str, str], ...],
) -> tuple[bool, dict[str, str]]:
    if not isinstance(raw, Mapping) or raw.get("edges") != [list(edge) for edge in edges]:
        return False, {}
    ids = raw.get("entity_ids")
    if not isinstance(ids, Mapping):
        return False, {}
    entity_ids = {str(name): str(value) for name, value in ids.items()}
    root = str(spec.metadata.get("anchor_entity", "action"))
    expected_entities = {root} | {item for edge in edges for item in edge}
    if set(entity_ids) != expected_entities or entity_ids.get(root) != action_id:
        return False, {}
    for entity, value in entity_ids.items():
        if entity != root and not _ENTITY_ID.fullmatch(value):
            return False, {}
        if entity != root and not value.startswith(f"{entity}:"):
            return False, {}
    payload = {"edges": [list(edge) for edge in edges], "entity_ids": entity_ids}
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return raw.get("digest") == digest, entity_ids


def _policy_event_valid(
    event: AuditEvent,
    mechanism_name: str,
    observations: Mapping[str, Any],
    roots: Mapping[str, PolicyRoot],
) -> bool:
    version_id = event.attributes.get("policy_version_id")
    root = roots.get(str(version_id))
    if root is None or root.version_id != version_id:
        return False
    if not (root.valid_from_ns <= event.captured_ns <= root.valid_to_ns):
        return False
    binding = event.attributes.get("binding_proof")
    if not isinstance(binding, Mapping):
        return False
    ids = binding.get("entity_ids")
    if not isinstance(ids, Mapping) or ids.get("policy_version") != version_id:
        return False
    expected = root.mechanism_observations.get(mechanism_name)
    return expected is not None and dict(expected) == dict(observations)


def _verify_cross_receipts(events: Sequence[AuditEvent], errors: list[str]) -> None:
    canonical_adapters = {
        "canonical-action": "action_digest",
        "canonical-application": "application_digest",
        "canonical-case-action": "case_action_digest",
    }
    for adapter_id, digest_name in canonical_adapters.items():
        canonical = {
            event.attributes.get(digest_name)
            for event in events
            if event.adapter_id == adapter_id and event.attributes.get(digest_name) is not None
        }
        if len(canonical) > 1:
            errors.append(f"receipt_binding:canonical_conflict:{digest_name}")
            continue
        if not canonical:
            continue
        expected = next(iter(canonical))
        for event in events:
            actual = event.attributes.get(digest_name)
            if actual is not None and actual != expected:
                errors.append(f"receipt_binding:{event.mechanism}:{digest_name}")
    for event in events:
        values = event.attributes.get("observation_values")
        if not isinstance(values, Mapping):
            continue
        if values.get("decision_record_bound") is True and event.attributes.get(
            "stored_application_id"
        ) != event.action_id:
            errors.append(f"receipt_binding:{event.mechanism}:stored_application_id")
