from __future__ import annotations

from pathlib import Path

import pytest

from auditspec.compiler import AuditCompiler
from auditspec.information import information_leakage, query_sensitive_facts
from auditspec.spec import load_spec


ROOT = Path(__file__).resolve().parents[1]


def test_bounded_digest_leaks_the_same_amount_as_raw_value() -> None:
    compiler = AuditCompiler(load_spec(ROOT / "examples" / "payment.yaml"))
    raw = information_leakage(
        compiler,
        "policy_compliant",
        ["canonical_action"],
        sensitive_facts=["amount"],
    )
    digest = information_leakage(
        compiler,
        "policy_compliant",
        ["amount_token"],
        sensitive_facts=["amount"],
    )
    redacted = information_leakage(
        compiler,
        "policy_compliant",
        ["coarse_amount_channel"],
        sensitive_facts=["amount"],
    )
    assert raw.mutual_information_bits == pytest.approx(1.0)
    assert digest.mutual_information_bits == pytest.approx(1.0)
    assert digest.evidence_bayes_accuracy == pytest.approx(1.0)
    assert raw.as_dict()["normalized_mutual_information"] == pytest.approx(
        digest.normalized_mutual_information
    )
    assert redacted.mutual_information_bits == pytest.approx(0.0)
    assert redacted.evidence_bayes_accuracy == pytest.approx(0.5)


def test_auditable_contract_reports_disclosure_beyond_answer() -> None:
    compiler = AuditCompiler(load_spec(ROOT / "examples" / "payment.yaml"))
    synthesis = compiler.synthesize("policy_compliant", "adversarial_agent")
    metrics = information_leakage(
        compiler,
        "policy_compliant",
        synthesis.contract,
        sensitive_facts=["amount"],
    )
    assert compiler.check_contract(
        "policy_compliant", synthesis.contract, "adversarial_agent"
    ).auditable
    assert metrics.mutual_information_bits == pytest.approx(1.0)
    assert metrics.conditional_mutual_information_given_answer_bits > 0
    assert metrics.bayes_gain_over_answer > 0


def test_query_sensitive_scope_excludes_public_policy_state() -> None:
    compiler = AuditCompiler(load_spec(ROOT / "examples" / "credit.yaml"))
    assert query_sensitive_facts(compiler, "threshold_breach") == ("score",)
