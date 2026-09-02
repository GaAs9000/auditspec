from __future__ import annotations

from dataclasses import replace
from copy import deepcopy

import pytest

from auditspec.assurance import (
    contract_digest,
    declared_adapter_manifest_digest,
)
from auditspec.minimality import (
    ATOM_SIGNATURES,
    CanonicalPremiseSet,
    PMinimalityCertificate,
    PremiseAtom,
    PremiseEvaluationStatus,
    evaluate_premise,
    make_minimality_certificate,
    verify_p_minimality_certificate,
)
from test_assurance_gate import CLAIM_ID, VERIFIER_ID, configurations, make_config


def atoms():
    base = configurations()["base"]
    return {
        "Q": PremiseAtom.build(
            "Q",
            "formal_claim",
            claim_id=CLAIM_ID,
            semantics_digest=base.claim_semantics_commitment,
        ),
        "A": PremiseAtom.build("A", "abstraction_adequate", claim_id=CLAIM_ID),
        "D": PremiseAtom.build(
            "D",
            "evidence_determinate",
            claim_id=CLAIM_ID,
            contract_digest=contract_digest(base.contract),
        ),
        "R": PremiseAtom.build(
            "R",
            "declared_adapter_conformance",
            mechanism_id="truth_receipt",
            manifest_digest=declared_adapter_manifest_digest(base, "truth_receipt"),
        ),
        "M": PremiseAtom.build(
            "M",
            "declared_scope_covered",
            claim_id=CLAIM_ID,
            channel=base.inventory_scope.channel,
            inventory_scope_digest=base.inventory_scope.inventory_scope_digest,
        ),
        "V": PremiseAtom.build(
            "V",
            "audit_verifier_packet_accepted",
            claim_id=CLAIM_ID,
            verifier_id=VERIFIER_ID,
        ),
    }


def test_all_six_atom_signatures_parse_and_round_trip() -> None:
    assert {layer for layer, _ in ATOM_SIGNATURES} == set("QADRMV")
    for atom in atoms().values():
        assert PremiseAtom.from_dict(atom.as_dict()).as_dict() == atom.as_dict()
        assert len(atom.atom_digest) == 64


def test_pi_builder_orders_layers_but_strict_parser_rejects_wire_reorder() -> None:
    all_atoms = atoms()
    pi = CanonicalPremiseSet.build(
        [all_atoms[layer] for layer in reversed("QADRMV")]
    )
    assert [atom.layer for atom in pi.atoms] == list("QADRMV")
    assert CanonicalPremiseSet.from_dict(pi.as_dict()) == pi
    raw = pi.as_dict()
    raw["atoms"] = list(reversed(raw["atoms"]))
    with pytest.raises(ValueError, match="canonical order"):
        CanonicalPremiseSet.from_dict(raw)


def test_atom_rejects_bad_signatures_compounds_reordering_and_duplicates() -> None:
    with pytest.raises(ValueError):
        PremiseAtom.build("A", "abstraction_adequate_AND_complete_coverage", claim_id=CLAIM_ID)
    with pytest.raises(ValueError):
        PremiseAtom.build("M", "domain_closed", claim_id=CLAIM_ID)
    with pytest.raises(ValueError):
        PremiseAtom.build("V", "verifier_recomputes", claim_id=CLAIM_ID, verifier_id=VERIFIER_ID)
    raw = atoms()["M"].as_dict()
    raw["args"][0], raw["args"][1] = raw["args"][1], raw["args"][0]
    with pytest.raises(ValueError, match="wire order"):
        PremiseAtom.from_dict(raw)
    with pytest.raises(ValueError, match="duplicate"):
        CanonicalPremiseSet((atoms()["A"], atoms()["A"]))
    with pytest.raises(ValueError, match="non-empty"):
        CanonicalPremiseSet(())


def test_base_satisfies_all_canonical_atoms() -> None:
    base = configurations()["base"]
    assert all(
        evaluate_premise(atom, base).status is PremiseEvaluationStatus.SATISFIED
        for atom in atoms().values()
    )


@pytest.mark.parametrize(
    ("layer", "config_name", "variant"),
    [
        ("Q", "Q", "Q:query-formation-failure"),
        ("A", "A", "A:model-twin"),
        ("D", "D", "D:finite-evidence-twin"),
        ("R", "R", "R:declared-adapter-conformance-failure"),
        ("M", "M", "M:declared-mediation-failure"),
        ("M", "M_coverage", "M:declared-coverage-failure"),
        ("V", "V", "V:audit-verifier-packet-failure"),
    ],
)
def test_each_layer_uses_a_strict_native_deletion_credential(
    layer: str, config_name: str, variant: str
) -> None:
    configs = configurations()
    atom = atoms()[layer]
    pi = CanonicalPremiseSet((atom,))
    certificate = make_minimality_certificate(pi, atom, configs["base"], configs[config_name])
    assert certificate.variant == variant
    verified = verify_p_minimality_certificate(
        certificate, pi, atom, configs["base"], configs[config_name]
    )
    assert verified.valid, verified.errors
    restored = PMinimalityCertificate.from_dict(certificate.as_dict())
    assert restored.as_dict() == certificate.as_dict()
    assert restored.certificate_digest == certificate.certificate_digest
    assert restored.as_dict()["extension_admissibility_checked"] is False
    assert restored.as_dict()["open_world"] is False
    assert restored.as_dict()["inventory_completeness_proven"] is False


def test_closed_schema_rejects_unknown_fields_at_every_outer_boundary() -> None:
    atom_raw = atoms()["A"].as_dict()
    atom_raw["extra"] = 1
    with pytest.raises(ValueError, match="closed schema"):
        PremiseAtom.from_dict(atom_raw)
    pi_raw = CanonicalPremiseSet((atoms()["A"],)).as_dict()
    pi_raw["extra"] = 1
    with pytest.raises(ValueError, match="closed schema"):
        CanonicalPremiseSet.from_dict(pi_raw)
    configs = configurations()
    atom = atoms()["A"]
    pi = CanonicalPremiseSet((atom,))
    cert = make_minimality_certificate(pi, atom, configs["base"], configs["A"])
    cert_raw = cert.as_dict()
    cert_raw["extra"] = 1
    with pytest.raises(ValueError, match="closed schema"):
        PMinimalityCertificate.from_dict(cert_raw)
    cert_raw = cert.as_dict()
    cert_raw["native"]["extra"] = 1
    with pytest.raises(ValueError, match="closed schema"):
        PMinimalityCertificate.from_dict(cert_raw)


@pytest.mark.parametrize(
    "field",
    [
        "premise_set_digest",
        "removed_atom_digest",
        "base_configuration_digest",
        "extension_configuration_digest",
        "base_primary_verdict",
        "extension_primary_verdict",
        "first_failed_layer",
    ],
)
def test_common_envelope_tampering_is_rejected(field: str) -> None:
    configs = configurations()
    atom = atoms()["A"]
    pi = CanonicalPremiseSet((atom,))
    cert = make_minimality_certificate(pi, atom, configs["base"], configs["A"])
    replacement = (
        "V"
        if field == "first_failed_layer"
        else ("0" * 64 if field.endswith("digest") else "tampered")
    )
    tampered = replace(cert, **{field: replacement})
    result = verify_p_minimality_certificate(
        tampered, pi, atom, configs["base"], configs["A"]
    )
    assert not result.valid


def test_removed_atom_must_be_a_member_of_pi() -> None:
    configs = configurations()
    pi = CanonicalPremiseSet((atoms()["A"],))
    with pytest.raises(ValueError, match="not a member"):
        make_minimality_certificate(pi, atoms()["M"], configs["base"], configs["M"])


def test_remaining_premise_false_rejects_otherwise_valid_a_twin() -> None:
    configs = configurations()
    combined = make_config(
        "a-and-m-gap",
        case=configs["A"].adequacy_case,
        coverage_complete=False,
    )
    pi = CanonicalPremiseSet.build([atoms()["A"], atoms()["M"]])
    with pytest.raises(ValueError, match="does not verify"):
        make_minimality_certificate(pi, atoms()["A"], configs["base"], combined)


def test_two_atom_a_m_deletions_keep_the_other_premise_true() -> None:
    configs = configurations()
    pi = CanonicalPremiseSet.build([atoms()["A"], atoms()["M"]])
    for removed, extension_name in (
        (atoms()["A"], "A"),
        (atoms()["M"], "M_coverage"),
    ):
        certificate = make_minimality_certificate(
            pi, removed, configs["base"], configs[extension_name]
        )
        result = verify_p_minimality_certificate(
            certificate, pi, removed, configs["base"], configs[extension_name]
        )
        assert result.valid, result.errors


def test_wrong_bound_configuration_and_branch_substitution_are_rejected() -> None:
    configs = configurations()
    a_atom = atoms()["A"]
    a_pi = CanonicalPremiseSet((a_atom,))
    a_cert = make_minimality_certificate(a_pi, a_atom, configs["base"], configs["A"])
    wrong_base = replace(configs["base"], configuration_id="other-base")
    assert not verify_p_minimality_certificate(
        a_cert, a_pi, a_atom, wrong_base, configs["A"]
    ).valid
    with pytest.raises(ValueError, match="closed schema"):
        replace(a_cert, variant="M:declared-coverage-failure")


def test_native_payload_tampering_is_rejected() -> None:
    configs = configurations()
    for layer, config_name in (("A", "A"), ("D", "D"), ("M", "M_coverage"), ("V", "V")):
        atom = atoms()[layer]
        pi = CanonicalPremiseSet((atom,))
        cert = make_minimality_certificate(pi, atom, configs["base"], configs[config_name])
        native = deepcopy(dict(cert.native))
        key = next(iter(native))
        native[key] = "tampered"
        try:
            tampered = replace(cert, native=native)
        except (TypeError, ValueError):
            continue
        assert not verify_p_minimality_certificate(
            tampered, pi, atom, configs["base"], configs[config_name]
        ).valid


def test_native_top_level_mapping_is_immutable_for_every_branch() -> None:
    configs = configurations()
    for layer, config_name in (
        ("Q", "Q"),
        ("A", "A"),
        ("D", "D"),
        ("R", "R"),
        ("M", "M"),
        ("M", "M_coverage"),
        ("V", "V"),
    ):
        atom = atoms()[layer]
        pi = CanonicalPremiseSet((atom,))
        certificate = make_minimality_certificate(
            pi, atom, configs["base"], configs[config_name]
        )
        with pytest.raises(TypeError):
            certificate.native["unexpected_after_parse"] = "bypass"


def test_noncoverage_m_packet_failure_cannot_be_issued_as_coverage() -> None:
    configs = configurations()
    base = configs["base"]
    payload = deepcopy(dict(base.evidence.payload))
    payload["attestation"]["signature"] = "0" * 64
    attacked = replace(
        base,
        configuration_id="signature-only-m-failure",
        evidence=replace(base.evidence, payload=payload),
    )
    atom = atoms()["M"]
    pi = CanonicalPremiseSet((atom,))
    with pytest.raises(ValueError, match="singleton declared coverage failure"):
        make_minimality_certificate(pi, atom, base, attacked)


def test_m_premise_sees_additional_m_failure_after_r_failure() -> None:
    configs = configurations()
    coverage = configs["M_coverage"]
    attacked = replace(
        coverage,
        configuration_id="r-first-m-additional",
        evidence=replace(coverage.evidence, regime="state_effect_receipt"),
    )
    result = evaluate_premise(atoms()["M"], attacked)
    assert result.status is PremiseEvaluationStatus.UNSATISFIED
    assert "coverage:incomplete" in result.details
