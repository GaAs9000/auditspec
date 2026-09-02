from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from ..model import AuditSpec
from .events import AuditEvent, EventSink


@dataclass(frozen=True)
class RuntimeAttack:
    name: str
    sink: EventSink
    threat_model: str
    description: str
    attack_class: str = "semantic_forgery"


EventMutation = Callable[[dict[str, Any]], None]


def resign_with_mutation(
    source: EventSink,
    *,
    mechanism: str,
    mutate: EventMutation,
) -> EventSink:
    """Create a validly re-signed chain containing one semantic forgery."""

    result = EventSink({event.mechanism for event in source.events})
    changed = False
    for event in source.events:
        envelope = _event_envelope(event)
        if event.mechanism == mechanism and not changed:
            before = copy.deepcopy(envelope)
            mutate(envelope)
            if envelope == before:
                raise ValueError(
                    f"Attack mutation did not change target mechanism: {mechanism}"
                )
            changed = True
        result.emit(**envelope)
    if not changed:
        raise ValueError(f"Attack target mechanism was not emitted: {mechanism}")
    valid, errors = result.verify()
    if not valid:
        raise RuntimeError(f"Attack forge failed to produce a valid chain: {errors}")
    return result


def resign_with_filter(
    source: EventSink,
    *,
    keep: Callable[[AuditEvent], bool],
) -> EventSink:
    """Re-sign a filtered event stream so omission is not a trivial hash error."""

    result = EventSink({event.mechanism for event in source.events})
    for event in source.events:
        if keep(event):
            result.emit(**_event_envelope(event))
    valid, errors = result.verify()
    if not valid:
        raise RuntimeError(f"Filtered attack chain is invalid: {errors}")
    return result


def legacy_label_conformance(
    spec: AuditSpec, sink: EventSink, contract: Sequence[str]
) -> bool:
    """Reproduce the v0.2 name/key/chain realization criterion."""

    if not sink.verify()[0]:
        return False
    for name in contract:
        events = [event for event in sink.events if event.mechanism == name]
        if not events:
            return False
        observed_names = {
            str(key)
            for event in events
            for key in (
                event.attributes.get("observation_values", {})
                if isinstance(event.attributes.get("observation_values"), Mapping)
                else {}
            )
        }
        expected_names = {
            observation.name for observation in spec.mechanisms[name].observations
        } or set(spec.mechanisms[name].facts)
        if not expected_names <= observed_names:
            return False
    return True


def payment_runtime_attacks(source: EventSink) -> tuple[RuntimeAttack, ...]:
    def observation_value(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["observation_values"]["amount"] = 999999

    def producer(envelope: dict[str, Any]) -> None:
        envelope["producer"] = "agent"

    def capture(envelope: dict[str, Any]) -> None:
        envelope["capture_point"] = "agent"

    def adapter(envelope: dict[str, Any]) -> None:
        envelope["adapter_id"] = "invented-adapter"

    def registry(envelope: dict[str, Any]) -> None:
        envelope["registry_sha256"] = "0" * 64

    def binding(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["binding_proof"]["entity_ids"]["approval"] = (
            "approval:other"
        )

    def executor_identity(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["binding_proof"]["entity_ids"]["delegation"] = (
            "delegation:wrong-executor"
        )

    def policy_version(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["policy_version_id"] = "policy_version:stale"

    def action_identity(envelope: dict[str, Any]) -> None:
        envelope["action_id"] = "other-action"

    def run_identity(envelope: dict[str, Any]) -> None:
        envelope["run_id"] = "cross-run-splice"

    def root(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["root_digest"] = "0" * 64

    def coverage_value(envelope: dict[str, Any]) -> None:
        values = envelope["attributes"]["observation_values"]
        values["gateway_coverage_complete"] = not bool(
            values["gateway_coverage_complete"]
        )

    def effect_value(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["observation_values"]["ledger_commit_count"] = 999

    def adapter_version(envelope: dict[str, Any]) -> None:
        envelope["adapter_version"] = "99.0.0"

    cases = (
        ("wrong_value", "canonical_action", observation_value),
        ("wrong_producer", "approval_bound_receipt", producer),
        ("wrong_capture_point", "approval_bound_receipt", capture),
        ("wrong_adapter_identity", "approval_bound_receipt", adapter),
        ("wrong_registry_digest", "approval_bound_receipt", registry),
        ("action_misbinding", "approval_bound_receipt", binding),
        ("wrong_executor_identity", "delegation_context", executor_identity),
        ("stale_policy_version", "policy_snapshot", policy_version),
        ("cross_action_splice", "durable_effect_receipt", action_identity),
        ("cross_run_replay", "durable_effect_receipt", run_identity),
        ("wrong_root_digest", "canonical_action", root),
        ("false_coverage_value", "gateway_coverage", coverage_value),
        ("wrong_effect_receipt", "durable_effect_receipt", effect_value),
        ("lying_manifest", "approval_bound_receipt", adapter_version),
    )
    attacks = [
        RuntimeAttack(
            name=name,
            sink=resign_with_mutation(source, mechanism=mechanism, mutate=mutation),
            threat_model="cooperative",
            description=f"Validly re-signed {name.replace('_', ' ')} attack",
        )
        for name, mechanism, mutation in cases
    ]
    attacks.append(
        RuntimeAttack(
            name="gateway_bypass",
            sink=source,
            threat_model="best_effort_gateway",
            description="Same events evaluated under a deployment graph with a concrete gateway bypass edge",
            attack_class="topology_bypass",
        )
    )
    attacks.extend(
        (
            RuntimeAttack(
                name="mechanism_omission",
                sink=resign_with_filter(
                    source,
                    keep=lambda event: event.mechanism != "approval_bound_receipt",
                ),
                threat_model="cooperative",
                description="A required approval event is omitted and the remaining stream is re-signed",
                attack_class="availability_integrity",
            ),
            RuntimeAttack(
                name="event_stream_truncation",
                sink=resign_with_filter(
                    source,
                    keep=lambda event: event is not source.events[-1],
                ),
                threat_model="cooperative",
                description="The final event is truncated and the retained prefix is re-signed",
                attack_class="availability_integrity",
            ),
        )
    )
    return tuple(attacks)


def forge_replay_trial_count(
    source: EventSink, mechanism: str, trials: int
) -> EventSink:
    def mutate(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["replay_proof"]["trials"] = trials

    return resign_with_mutation(source, mechanism=mechanism, mutate=mutate)


def replay_runtime_attacks(
    source: EventSink, mechanism: str
) -> tuple[RuntimeAttack, ...]:
    """Forge replay semantics while retaining a valid chain and mechanism keys."""

    def verifier(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["replay_proof"]["verifier"] = (
            "unregistered_verifier"
        )

    def incomplete_nondeterminism(envelope: dict[str, Any]) -> None:
        proof = envelope["attributes"]["replay_proof"]
        proof["nondeterminism"] = list(proof["nondeterminism"][:-1])
        proof["nondeterminism_capture"].pop(
            next(reversed(proof["nondeterminism_capture"]))
        )

    def unsafe_compensation(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["replay_proof"]["side_effect_mode"] = "compensated"

    def runtime_replacement(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["replay_proof"]["implementation_ref"] = (
            "attacker.runtime:ReplacementHarness"
        )

    def false_verifier(envelope: dict[str, Any]) -> None:
        envelope["attributes"]["replay_proof"]["verifier_passed"] = False

    cases = (
        ("unregistered_verifier", verifier),
        ("incomplete_nondeterminism_capture", incomplete_nondeterminism),
        ("unsafe_compensated_replay", unsafe_compensation),
        ("runtime_implementation_replacement", runtime_replacement),
        ("verifier_false", false_verifier),
    )
    return tuple(
        RuntimeAttack(
            name=name,
            sink=resign_with_mutation(
                source, mechanism=mechanism, mutate=mutation
            ),
            threat_model="adversarial_agent",
            description=f"Validly re-signed replay attack: {name.replace('_', ' ')}",
            attack_class="replay_semantics",
        )
        for name, mutation in cases
    )


def _event_envelope(event: AuditEvent) -> dict[str, Any]:
    return {
        "mechanism": event.mechanism,
        "adapter_id": event.adapter_id,
        "adapter_version": event.adapter_version,
        "registry_sha256": event.registry_sha256,
        "producer": event.producer,
        "capture_point": event.capture_point,
        "run_id": event.run_id,
        "action_id": event.action_id,
        "attributes": copy.deepcopy(event.attributes),
    }
