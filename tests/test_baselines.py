from __future__ import annotations

from pathlib import Path

from auditspec.baselines import determinacy_only, static_dependency_cover
from auditspec.compiler import AuditCompiler
from auditspec.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]


def compiler_for(pack: str) -> AuditCompiler:
    return AuditCompiler(load_spec(ROOT / "examples" / f"{pack}.yaml"))


def test_source_cover_claims_false_assurance_for_lossy_channels() -> None:
    result = static_dependency_cover(
        compiler_for("payment"),
        "policy_compliant",
        "adversarial_agent",
        provider_semantics="source",
    )
    assert result.contract == (
        "coarse_amount_channel",
        "coarse_policy_channel",
    )
    assert result.claimed_auditable is True
    assert result.semantic_determinate is False
    assert result.false_assurance is True


def test_exact_cover_is_sound_but_over_retains_raw_values() -> None:
    compiler = compiler_for("payment")
    exact = static_dependency_cover(
        compiler,
        "policy_compliant",
        "adversarial_agent",
        provider_semantics="exact",
    )
    compiled = compiler.synthesize(
        "policy_compliant", threat_model="adversarial_agent"
    )
    assert exact.sound_auditable is True
    assert exact.contract == ("canonical_action", "policy_snapshot")
    assert tuple(compiled.contract) == ("amount_token", "policy_state_token")
    assert exact.contract != tuple(compiled.contract)


def test_determinacy_only_exposes_structural_false_assurance() -> None:
    compiler = compiler_for("payment")
    result = determinacy_only(
        compiler, "no_out_of_band_effect", "best_effort_gateway"
    )
    assert result.semantic_determinate is True
    assert result.structural_assurance is False
    assert result.false_assurance is True
