from __future__ import annotations

from pathlib import Path

import pytest

from auditspec.compiler import AuditCompiler
from auditspec.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]


def compiler_for(name: str = "payment") -> AuditCompiler:
    return AuditCompiler(load_spec(ROOT / "examples" / f"{name}.yaml"))


def test_three_packs_have_frozen_query_splits_and_expected_worlds() -> None:
    expected = {
        "payment": (8192, 6, 4, 16),
        "credit": (3072, 5, 3, 14),
        "aml": (3072, 5, 3, 12),
    }
    for name, (worlds, development, held_out, mechanisms) in expected.items():
        compiler = compiler_for(name)
        splits = [query.split for query in compiler.spec.queries.values()]
        assert len(compiler.worlds) == worlds
        assert splits.count("development") == development
        assert splits.count("held_out") == held_out
        assert len(compiler.spec.mechanisms) == mechanisms


def test_terminal_output_is_not_authorization_evidence() -> None:
    compiler = compiler_for()
    checked = compiler.check_contract("transfer_authorized", ["final_output"])
    assert not checked.auditable
    assert checked.certificate is not None
    assert checked.certificate.answer_a != checked.certificate.answer_b
    assert compiler.verify_certificate(checked.certificate)


def test_authorization_contract_closes_dependencies_and_is_locally_minimal() -> None:
    compiler = compiler_for()
    result = compiler.synthesize(
        "transfer_authorized", threat_model="adversarial_agent"
    )
    assert result.status == "PASSIVE_AUDITABLE"
    assert set(result.contract) == {
        "canonical_action",
        "approval_bound_receipt",
        "delegation_context",
    }
    assert set(result.minimality_witnesses) == set(result.contract)
    assert set(result.derived_requirements) == {
        "bind:action:approval",
        "bind:action:delegation",
    }


def test_compromised_agent_assertion_is_rejected() -> None:
    compiler = compiler_for()
    with pytest.raises(ValueError, match="unavailable or untrusted"):
        compiler.check_contract(
            "report_matches_ledger",
            ["final_output", "canonical_action", "durable_effect_receipt"],
            threat_model="adversarial_agent",
        )


def test_determinacy_does_not_substitute_for_mandatory_channel_coverage() -> None:
    compiler = compiler_for()
    checked = compiler.check_contract(
        "no_out_of_band_effect",
        ["canonical_action", "gateway_coverage"],
        threat_model="best_effort_gateway",
    )
    assert not checked.auditable
    assert checked.certificate is None
    assert checked.unmet_requirements == ("coverage:tool_dispatch:mandatory",)
    result = compiler.synthesize(
        "no_out_of_band_effect", threat_model="best_effort_gateway"
    )
    assert result.status == "NOT_AUDITABLE_UNDER_CURRENT_TCB"


@pytest.mark.parametrize(
    ("pack", "query", "mechanism"),
    [
        ("payment", "tool_response_necessary_for_duplicate", "virtualized_tool_omission_replay"),
        ("credit", "income_feature_necessary_for_denial", "virtualized_income_ablation"),
    ],
)
def test_validated_causal_queries_require_active_mechanisms(
    pack: str, query: str, mechanism: str
) -> None:
    compiler = compiler_for(pack)
    result = compiler.synthesize(query, threat_model="adversarial_agent")
    assert result.status == "ACTIVE_AUDIT_REQUIRED"
    assert mechanism in result.contract
    assert any(item.startswith("replay:") for item in result.derived_requirements)


@pytest.mark.parametrize(
    ("pack", "query", "mechanism"),
    [
        ("aml", "vendor_signal_necessary_for_release", "virtualized_vendor_ablation"),
    ],
)
def test_schema_only_replay_adapter_is_not_called_verified(
    pack: str, query: str, mechanism: str
) -> None:
    compiler = compiler_for(pack)
    result = compiler.synthesize(query, threat_model="adversarial_agent")
    assert result.status == "UNREALIZABLE_INTERVENTION"
    assert not result.contract
    assert any(
        "adapter_refinement_unproven:schema_only" in reasons
        for name, reasons in result.rejected_mechanisms.items()
        if name == mechanism
    )


@pytest.mark.parametrize("threat_model", ["no_replay", "irreversible_only"])
def test_unavailable_or_irreversible_replay_is_safely_rejected(
    threat_model: str,
) -> None:
    compiler = compiler_for()
    result = compiler.synthesize(
        "tool_response_necessary_for_duplicate", threat_model=threat_model
    )
    assert result.status == "UNREALIZABLE_INTERVENTION"
    assert not result.contract


def test_compiled_contract_eliminates_semantic_ambiguity() -> None:
    compiler = compiler_for()
    result = compiler.synthesize("policy_compliant", threat_model="adversarial_agent")
    metrics = compiler.ambiguity_metrics(
        "policy_compliant", result.contract, threat_model="adversarial_agent"
    )
    assert metrics["ambiguous_world_fraction"] == 0
    assert metrics["bayes_error_lower_bound"] == 0
    assert metrics["structural_assurance_valid"] is True
