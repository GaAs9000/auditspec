"""Frozen structural attacks for external evidence packages."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .evidence import (
    EvidenceAttestation,
    ExternalEvidenceSource,
    IndependentVerifierWitness,
    sign_evidence_attestation,
)


@dataclass(frozen=True)
class ExternalAttackDefinition:
    name: str
    target_layer: str
    description: str
    needs_donor: bool = False


EXTERNAL_STRUCTURAL_ATTACKS = {
    item.name: item
    for item in (
        ExternalAttackDefinition(
            "cross_run_witness_splice",
            "R",
            "Copy a valid witness and attestation from another run.",
            needs_donor=True,
        ),
        ExternalAttackDefinition(
            "cross_task_binding",
            "R",
            "Bind the witness to a different task and validly re-sign it.",
        ),
        ExternalAttackDefinition(
            "missing_claim_binding",
            "R",
            "Remove the run-to-claim edge and validly re-sign the package.",
        ),
        ExternalAttackDefinition(
            "stale_benchmark_revision",
            "R",
            "Replace the benchmark revision and validly re-sign the package.",
        ),
        ExternalAttackDefinition(
            "untrusted_producer",
            "M",
            "Replace the evaluator with an untrusted producer.",
        ),
        ExternalAttackDefinition(
            "capture_point_downgrade",
            "M",
            "Move capture from the benchmark harness to the agent.",
        ),
        ExternalAttackDefinition(
            "coverage_omission",
            "M",
            "Declare incomplete mandatory-path capture.",
        ),
        ExternalAttackDefinition(
            "verifier_substitution",
            "V",
            "Substitute an unregistered verifier in witness and attestation.",
        ),
        ExternalAttackDefinition(
            "witness_value_corruption",
            "M",
            "Modify the witness value without a trusted re-signature.",
        ),
    )
}


def _resign(
    attestation: EvidenceAttestation,
    witness: IndependentVerifierWitness,
    key: bytes,
) -> EvidenceAttestation:
    return sign_evidence_attestation(
        replace(attestation, signature=""), witness, key
    )


def apply_external_structural_attack(
    source: ExternalEvidenceSource,
    claim_id: str,
    attack_name: str,
    *,
    trusted_resign_key: bytes,
    donor: ExternalEvidenceSource | None = None,
    attacker_key: bytes = b"untrusted-external-evidence-producer",
) -> ExternalEvidenceSource:
    """Apply one predeclared attack without consulting benchmark truth."""

    if attack_name not in EXTERNAL_STRUCTURAL_ATTACKS:
        raise KeyError(f"unknown external structural attack: {attack_name}")
    if claim_id not in source.witnesses or claim_id not in source.attestations:
        raise ValueError(f"source has no complete evidence for {claim_id}")
    if attack_name == "cross_run_witness_splice":
        if donor is None:
            raise ValueError("cross-run splice requires a donor source")
        if claim_id not in donor.witnesses or claim_id not in donor.attestations:
            raise ValueError(f"donor has no complete evidence for {claim_id}")
        return replace(
            source,
            witnesses={**source.witnesses, claim_id: donor.witnesses[claim_id]},
            attestations={
                **source.attestations,
                claim_id: donor.attestations[claim_id],
            },
        )

    witness = source.witnesses[claim_id]
    attestation = source.attestations[claim_id]
    signing_key = trusted_resign_key
    if attack_name == "cross_task_binding":
        attestation = replace(attestation, task_id="other-task")
    elif attack_name == "missing_claim_binding":
        edges = tuple(
            edge for edge in attestation.binding_edges if edge != ("run", "claim")
        )
        attestation = replace(attestation, binding_edges=edges)
    elif attack_name == "stale_benchmark_revision":
        attestation = replace(attestation, benchmark_revision="stale-revision")
    elif attack_name == "untrusted_producer":
        attestation = replace(attestation, producer="agent")
        signing_key = attacker_key
    elif attack_name == "capture_point_downgrade":
        attestation = replace(attestation, capture_point="agent")
    elif attack_name == "coverage_omission":
        attestation = replace(attestation, coverage_complete=False)
    elif attack_name == "verifier_substitution":
        witness = replace(witness, verifier_id="invented-verifier")
        attestation = replace(attestation, verifier_id="invented-verifier")
    elif attack_name == "witness_value_corruption":
        witness = replace(witness, declared_value=not witness.declared_value)
        return replace(source, witnesses={**source.witnesses, claim_id: witness})
    else:  # pragma: no cover - exhaustive registry guard above
        raise AssertionError(attack_name)

    attestation = _resign(attestation, witness, signing_key)
    return replace(
        source,
        witnesses={**source.witnesses, claim_id: witness},
        attestations={**source.attestations, claim_id: attestation},
    )
