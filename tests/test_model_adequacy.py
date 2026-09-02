from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from auditspec.model_adequacy import (
    ASSURANCE_CHECKING_ORDER,
    AssuranceVerdict,
    AuditAssuranceCompiler,
    ModelAdequacyChecker,
    ModelTwinCertificate,
    load_adequacy_cases,
)
from auditspec.spec import load_spec


ROOT = Path(__file__).resolve().parents[1]
SPECS = {
    name: load_spec(ROOT / "examples" / f"{name}.yaml")
    for name in ("payment", "credit", "aml")
}
CASES = load_adequacy_cases(ROOT / "challenges" / "model_adequacy_cases.yaml")


def test_external_cases_separate_model_gaps_from_adequate_models() -> None:
    results = {
        case_id: ModelAdequacyChecker(SPECS[case.pack], case).check()
        for case_id, case in CASES.items()
    }
    adequate = {case_id for case_id, result in results.items() if result.adequate}
    model_gaps = {
        case_id
        for case_id, result in results.items()
        if result.verdict == AssuranceVerdict.MODEL_GAP
    }
    assert len(adequate) == 6
    assert model_gaps == {
        "external_payment_six_month_log_retention",
        "external_credit_all_principal_factors_disclosed",
        "external_aml_supporting_records_five_years",
    }
    assert all(results[case_id].certificate is not None for case_id in model_gaps)


def test_model_twin_certificate_recomputes_and_rejects_tampering() -> None:
    case = CASES["external_payment_six_month_log_retention"]
    checker = ModelAdequacyChecker(SPECS[case.pack], case)
    result = checker.check()
    assert result.certificate is not None
    assert checker.verify_certificate(result.certificate)
    serialized = result.certificate.as_dict()
    assert checker.verify_certificate(ModelTwinCertificate.from_dict(serialized))

    wrong_domain = dict(serialized)
    wrong_domain["execution_a"] = dict(serialized["execution_a"])
    wrong_domain["execution_a"]["retention_days"] = 999
    assert not checker.verify_certificate(ModelTwinCertificate.from_dict(wrong_domain))

    wrong_semantics = dict(serialized)
    wrong_semantics["missing_semantics"] = ["something_else"]
    assert not checker.verify_certificate(
        ModelTwinCertificate.from_dict(wrong_semantics)
    )


def test_query_mismatch_is_not_misclassified_as_model_gap() -> None:
    case = CASES["external_payment_effect_governance_chain"]
    mismatched = replace(case, abstract_query="ledger_commit_count == 99")
    result = ModelAdequacyChecker(SPECS[case.pack], mismatched).check()
    assert not result.adequate
    assert result.verdict == AssuranceVerdict.QUERY_GAP
    assert result.certificate is None
    assert result.witness is not None


def test_two_layer_compiler_stops_before_evidence_on_model_gap() -> None:
    case = CASES["external_credit_all_principal_factors_disclosed"]
    result = AuditAssuranceCompiler(SPECS[case.pack], case).compile()
    assert result.verdict == AssuranceVerdict.MODEL_GAP
    assert result.failed_layer == "A"
    assert result.synthesis is None
    serialized = result.as_dict()
    assert serialized["primary_verdict"] == "MODEL_GAP"
    assert serialized["checking_order"] == list(ASSURANCE_CHECKING_ORDER)
    assert serialized["additional_detected_failures"] == []


def test_primary_verdict_is_ordered_not_a_unique_root_cause() -> None:
    case = CASES["external_credit_all_principal_factors_disclosed"]
    result = AuditAssuranceCompiler(SPECS[case.pack], case).compile()
    diagnosed = replace(
        result,
        additional_detected_failures=(
            "receipt_binding_failure",
            "verifier_registry_mismatch",
        ),
    )
    assert diagnosed.primary_verdict == AssuranceVerdict.MODEL_GAP
    assert diagnosed.as_dict()["additional_detected_failures"] == [
        "receipt_binding_failure",
        "verifier_registry_mismatch",
    ]


def test_two_layer_compiler_enters_evidence_loop_only_after_adequacy() -> None:
    case = CASES["external_payment_effect_governance_chain"]
    result = AuditAssuranceCompiler(SPECS[case.pack], case).compile(
        threat_model="cooperative"
    )
    assert result.adequacy.adequate
    assert result.synthesis is not None
    assert result.verdict in {
        AssuranceVerdict.CONTRACT_READY,
        AssuranceVerdict.EVIDENCE_GAP,
        AssuranceVerdict.TCB_GAP,
    }
