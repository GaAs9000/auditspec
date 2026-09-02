from dataclasses import replace

import pytest

from auditspec.external.attacks import (
    EXTERNAL_STRUCTURAL_ATTACKS,
    apply_external_structural_attack,
)
from auditspec.external.evidence import (
    AuditorEvidenceCase,
    EvidenceAttestation,
    ExternalEvidenceSource,
    ExternalTrustContext,
    IndependentVerifierWitness,
    certify_ambiguous_pair,
    project_external_evidence,
    sign_evidence_attestation,
    verify_external_evidence,
)
from auditspec.external.learned import verify_planner_mechanisms
from auditspec.model_adequacy import AssuranceVerdict


REVISION = "official-revision"
PRODUCER_KEY = b"independent-benchmark-harness-key"


def witness(value: bool = True) -> IndependentVerifierWitness:
    return IndependentVerifierWitness(
        witness_id="witness-1",
        claim_id="T01",
        statement="The official aggregate task reward is successful.",
        declared_value=value,
        verifier_id="tau2-official-evaluator-replay-v1",
        replay_id="replay-2",
        computation="official evaluator replay over captured trajectory",
        evidence_components={"reward_basis": ["DB"]},
    )


def attestation(**changes) -> EvidenceAttestation:
    values = {
        "run_id": "run-1",
        "task_id": "task-1",
        "claim_id": "T01",
        "benchmark_revision": REVISION,
        "witness_id": "witness-1",
        "producer": "benchmark-evaluator",
        "capture_point": "benchmark-harness",
        "verifier_id": "tau2-official-evaluator-replay-v1",
        "binding_edges": (
            ("run", "task"),
            ("run", "claim"),
            ("run", "verifier_witness"),
            ("task", "benchmark_revision"),
        ),
        "coverage_channel": "tau2-tool-dispatch",
        "coverage_complete": True,
    }
    values.update(changes)
    return sign_evidence_attestation(
        EvidenceAttestation(**values), witness(), PRODUCER_KEY
    )


def source() -> ExternalEvidenceSource:
    item = witness()
    return ExternalEvidenceSource(
        environment="tau2",
        run_id="run-1",
        task_id="task-1",
        benchmark_revision=REVISION,
        final_answer="Done.",
        normalized_trace=({"tool": "update", "status": "ok"},),
        native_trace=({"role": "assistant", "tool_call_id": "call-1"},),
        witnesses={"T01": item},
        attestations={"T01": attestation()},
    )


def test_evidence_source_round_trip_preserves_complete_bound_witness() -> None:
    original = source()

    restored = ExternalEvidenceSource.from_mapping(original.as_dict())

    assert restored == original
    assert restored.as_dict() == original.as_dict()


def trust() -> ExternalTrustContext:
    return ExternalTrustContext(
        environment="tau2",
        benchmark_revision=REVISION,
        expected_run_id="run-1",
        expected_task_id="task-1",
        producer_keys={"benchmark-evaluator": PRODUCER_KEY},
        accepted_capture_points=frozenset({"benchmark-harness"}),
        accepted_verifiers=frozenset({"tau2-official-evaluator-replay-v1"}),
        mandatory_coverage_channel="tau2-tool-dispatch",
    )


def test_projections_are_oracle_free_and_have_measured_bytes() -> None:
    item = source()
    for regime in (
        "final_answer_only",
        "generic_normalized_trace",
        "full_native_trajectory",
        "state_effect_receipt",
        "static_exact_dependency_cover",
        "auditspec_compiled_contract",
    ):
        projected = project_external_evidence(item, "T01", regime)
        assert projected.byte_count > 0
        lowered = projected.serialized.lower()
        assert "oracle_checks" not in lowered
        assert "reward_info" not in lowered
        assert "test_tracker" not in lowered


def test_only_compiled_contract_passes_structural_verification() -> None:
    item = source()
    compiled = verify_external_evidence(
        project_external_evidence(item, "T01", "auditspec_compiled_contract"),
        trust(),
    )
    assert compiled.valid is True
    assert compiled.answer is True

    receipt = verify_external_evidence(
        project_external_evidence(item, "T01", "state_effect_receipt"),
        trust(),
    )
    assert receipt.primary_verdict == AssuranceVerdict.TCB_GAP
    assert receipt.semantic_determinate is True
    assert receipt.structural_assurance is False
    assert receipt.answer is None


def test_learned_planner_mechanism_set_is_checked_by_real_verifier() -> None:
    required = {
        "independent_verifier_witness",
        "run_task_binding",
        "run_claim_binding",
        "run_witness_binding",
        "task_revision_binding",
        "trusted_producer",
        "trusted_capture_point",
        "mandatory_path_coverage",
        "accepted_verifier",
    }

    valid = verify_planner_mechanisms(
        source=source(),
        claim_id="T01",
        selected_mechanisms=required,
        producer_key=PRODUCER_KEY,
        trust_context=trust(),
    )
    invalid = verify_planner_mechanisms(
        source=source(),
        claim_id="T01",
        selected_mechanisms=required - {"run_claim_binding"},
        producer_key=PRODUCER_KEY,
        trust_context=trust(),
    )

    assert valid.valid is True
    assert invalid.valid is False
    assert "claim_id:mismatch" in invalid.errors


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"run_id": "other-run"}, "run_id:mismatch"),
        ({"task_id": "other-task"}, "task_id:mismatch"),
        ({"witness_id": "other-witness"}, "witness_id:mismatch"),
        ({"benchmark_revision": "stale"}, "benchmark_revision:mismatch"),
        ({"producer": "agent"}, "producer:untrusted"),
        ({"capture_point": "agent"}, "capture_point:untrusted"),
        ({"coverage_channel": "best-effort"}, "coverage_channel:mismatch"),
        ({"coverage_complete": False}, "coverage:incomplete"),
        ({"verifier_id": "invented"}, "verifier_id:mismatch"),
    ],
)
def test_compiled_contract_rejects_structural_attacks(changes, error) -> None:
    item = source()
    attacked = replace(item, attestations={"T01": attestation(**changes)})
    result = verify_external_evidence(
        project_external_evidence(
            attacked, "T01", "auditspec_compiled_contract"
        ),
        trust(),
    )
    assert result.valid is False
    assert error in result.errors


def test_primary_verdict_is_ordered_and_additional_failures_are_retained() -> None:
    item = source()
    attacked_attestation = attestation(
        run_id="other-run",
        capture_point="agent",
        verifier_id="invented",
    )
    attacked_witness = replace(witness(), verifier_id="invented")
    attacked = replace(
        item,
        witnesses={"T01": attacked_witness},
        attestations={"T01": attacked_attestation},
    )
    result = verify_external_evidence(
        project_external_evidence(
            attacked, "T01", "auditspec_compiled_contract"
        ),
        trust(),
    )
    assert result.primary_verdict == AssuranceVerdict.TCB_GAP
    assert "run_id:mismatch" in result.errors
    assert any(item.startswith("M:") for item in result.additional_detected_failures)
    assert any(item.startswith("V:") for item in result.additional_detected_failures)


def test_missing_binding_is_rejected() -> None:
    item = source()
    attacked = replace(
        item,
        attestations={
            "T01": attestation(binding_edges=(("run", "task"),))
        },
    )
    result = verify_external_evidence(
        project_external_evidence(
            attacked, "T01", "auditspec_compiled_contract"
        ),
        trust(),
    )
    assert result.primary_verdict == AssuranceVerdict.TCB_GAP
    assert "missing_binding:run->claim" in result.errors


def test_witness_value_mutation_without_trusted_resigning_is_rejected() -> None:
    item = source()
    attacked = replace(item, witnesses={"T01": witness(False)})
    result = verify_external_evidence(
        project_external_evidence(
            attacked, "T01", "auditspec_compiled_contract"
        ),
        trust(),
    )
    assert result.valid is False
    assert "attestation_signature:invalid" in result.errors
    assert result.answer is None


@pytest.mark.parametrize(
    ("attack_name", "expected_error"),
    [
        ("cross_run_witness_splice", "run_id:mismatch"),
        ("cross_task_binding", "task_id:mismatch"),
        ("missing_claim_binding", "missing_binding:run->claim"),
        ("stale_benchmark_revision", "benchmark_revision:mismatch"),
        ("untrusted_producer", "producer:untrusted"),
        ("capture_point_downgrade", "capture_point:untrusted"),
        ("coverage_omission", "coverage:incomplete"),
        ("verifier_substitution", "verifier:untrusted"),
        ("witness_value_corruption", "attestation_signature:invalid"),
    ],
)
def test_frozen_external_attack_set_is_executable(
    attack_name: str, expected_error: str
) -> None:
    item = source()
    donor_witness = witness()
    donor_attestation = sign_evidence_attestation(
        replace(attestation(), run_id="donor-run", signature=""),
        donor_witness,
        PRODUCER_KEY,
    )
    donor = replace(
        item,
        run_id="donor-run",
        witnesses={"T01": donor_witness},
        attestations={"T01": donor_attestation},
    )
    attacked = apply_external_structural_attack(
        item,
        "T01",
        attack_name,
        trusted_resign_key=PRODUCER_KEY,
        donor=donor if EXTERNAL_STRUCTURAL_ATTACKS[attack_name].needs_donor else None,
    )
    result = verify_external_evidence(
        project_external_evidence(
            attacked, "T01", "auditspec_compiled_contract"
        ),
        trust(),
    )
    assert result.valid is False
    assert expected_error in result.errors


def test_exact_visible_pair_with_different_truth_is_machine_checkable() -> None:
    evidence = project_external_evidence(
        source(), "T01", "static_exact_dependency_cover"
    )
    first = AuditorEvidenceCase(
        case_id="true-run",
        claim_id="T01",
        truth=True,
        applicable=True,
        evidence=evidence,
    )
    second = AuditorEvidenceCase(
        case_id="false-run-with-cross-run-splice",
        claim_id="T01",
        truth=False,
        applicable=True,
        evidence=evidence,
        attack="cross_run_witness_splice",
    )
    certificate = certify_ambiguous_pair(first, second)
    assert certificate.verify() == (True, ())
    assert certificate.truth_a != certificate.truth_b


def test_pair_rejects_nonidentical_visible_evidence() -> None:
    true_evidence = project_external_evidence(
        source(), "T01", "static_exact_dependency_cover"
    )
    false_source = replace(source(), witnesses={"T01": witness(False)})
    false_evidence = project_external_evidence(
        false_source, "T01", "static_exact_dependency_cover"
    )
    with pytest.raises(ValueError, match="not exactly equal"):
        certify_ambiguous_pair(
            AuditorEvidenceCase("a", "T01", True, True, true_evidence),
            AuditorEvidenceCase("b", "T01", False, True, false_evidence),
        )


def test_source_rejects_raw_oracle_objects_in_witness_components() -> None:
    with pytest.raises(ValueError, match="raw oracle"):
        replace(
            witness(),
            evidence_components={"nested": {"reward_info": {"reward": 1}}},
        )
