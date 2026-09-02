from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from auditspec.compiler import AuditCompiler
from auditspec.model import CostVector, ReplayContract, TwinCertificate
from auditspec.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]


def payment_compiler() -> AuditCompiler:
    return AuditCompiler(load_spec(ROOT / "examples" / "payment.yaml"))


def cloned_certificate(certificate: TwinCertificate) -> TwinCertificate:
    return TwinCertificate.from_dict(certificate.as_dict())


def test_certificate_rejects_noncanonical_world_and_extra_variable() -> None:
    compiler = payment_compiler()
    certificate = compiler.check_contract(
        "settled_exactly_once", ["final_output"]
    ).certificate
    assert certificate is not None

    out_of_domain = cloned_certificate(certificate)
    out_of_domain.world_a["amount"] = 999999
    out_of_domain.world_b["amount"] = 999999
    assert compiler.verify_certificate(out_of_domain) is False

    extra_variable = cloned_certificate(certificate)
    extra_variable.world_a["undeclared"] = True
    extra_variable.world_b["undeclared"] = True
    assert compiler.verify_certificate(extra_variable) is False


@pytest.mark.parametrize(
    "field,mutated",
    [
        ("shared_observation", {"final_output": (("tool_response", "forged"),)}),
        ("separating_candidates", ("final_output",)),
        ("derived_requirements", ("invented:capability",)),
        ("spec_digest", "0" * 64),
        ("schema_version", "AuditSpec-certificate-v999"),
    ],
)
def test_certificate_rejects_tampered_serialized_claims(
    field: str, mutated: object
) -> None:
    compiler = payment_compiler()
    certificate = compiler.check_contract(
        "transfer_authorized", ["final_output"]
    ).certificate
    assert certificate is not None
    tampered = replace(cloned_certificate(certificate), **{field: mutated})
    assert compiler.verify_certificate(tampered) is False


def test_replay_contract_rejects_unregistered_implementation() -> None:
    bogus = ReplayContract(
        target="nonsense",
        prefix_checkpoint="bogus",
        snapshot="magic",
        nondeterminism=("pixie_dust",),
        isolation="nowhere",
        side_effect_mode="virtualized",
        verifier="trust_me",
    )
    valid, reasons = bogus.validate(adapter="invented-adapter")
    assert valid is False
    assert "unregistered:adapter:invented-adapter" in reasons


def test_compensated_replay_fails_closed_without_registered_compensation() -> None:
    replay = ReplayContract(
        target="omit_tool_response",
        prefix_checkpoint="before_effect",
        snapshot="sqlite_backup",
        nondeterminism=("agent_decision", "tool_response", "clock"),
        isolation="offline_temp_database",
        side_effect_mode="compensated",
        verifier="ledger_loss_predicate",
        compensation="descriptive-string-is-not-an-implementation",
    )
    valid, reasons = replay.validate(adapter="sqlite-counterfactual-replay")
    assert valid is False
    assert "unsupported:compensated_side_effect" in reasons


def test_replay_contract_rejects_duplicate_nondeterminism_sources() -> None:
    replay = ReplayContract(
        target="omit_tool_response",
        prefix_checkpoint="before_effect",
        snapshot="sqlite_backup",
        nondeterminism=("tool_response", "tool_response"),
        isolation="offline_temp_database",
        side_effect_mode="virtualized",
        verifier="ledger_loss_predicate",
    )
    valid, reasons = replay.validate(adapter="sqlite-counterfactual-replay")
    assert valid is False
    assert "invalid:duplicate_nondeterminism_source" in reasons


def test_active_mechanism_with_unknown_adapter_is_ineligible() -> None:
    compiler = payment_compiler()
    name = "virtualized_tool_omission_replay"
    compiler.spec.mechanisms[name] = replace(
        compiler.spec.mechanisms[name], adapter="invented-adapter"
    )
    eligible, rejected = compiler.eligible_mechanisms(
        "adversarial_agent", {"active"}
    )
    assert name not in eligible
    assert "unregistered:adapter:invented-adapter" in rejected[name]


@pytest.mark.parametrize(
    "cost",
    [
        CostVector(bytes=-1),
        CostVector(privacy=float("nan")),
        CostVector(latency_ms=float("inf")),
    ],
)
def test_cost_vector_rejects_negative_or_nonfinite_values(cost: CostVector) -> None:
    with pytest.raises(ValueError):
        cost.validate()


def test_compiler_rejects_negative_or_nonfinite_weights() -> None:
    compiler = payment_compiler()
    with pytest.raises(ValueError, match="weights"):
        compiler.synthesize("settled_exactly_once", weights={"bytes": -1})
    with pytest.raises(ValueError, match="weights"):
        compiler.synthesize(
            "settled_exactly_once", weights={"privacy": float("nan")}
        )


def test_unsupported_query_assurance_is_rejected(tmp_path: Path) -> None:
    raw = yaml.safe_load(
        (ROOT / "examples" / "payment.yaml").read_text(encoding="utf-8")
    )
    raw["queries"]["transfer_authorized"]["assurance"] = "probabilistic"
    path = tmp_path / "unsupported-assurance.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="implements exact finite-world assurance only"):
        load_spec(path)
