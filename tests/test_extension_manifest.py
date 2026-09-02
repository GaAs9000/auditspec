from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from types import MappingProxyType

import auditspec.verifier_registry as verifier_registry_module
import pytest

from auditspec.assurance import (
    REGISTERED_REEXECUTION_PROFILE,
    canonical_digest,
    run_exact_assurance_gate,
)
from auditspec.extension_manifest import (
    ExtensionMode,
    FullAssuranceExtensionManifest,
    StrongVDeletionCertificate,
    StrongVerifierPremise,
    actual_structural_delta,
    make_strong_v_deletion_certificate,
    strong_verifier_premise_satisfied,
    verify_full_assurance_extension,
    verify_strong_v_deletion_certificate,
)
from auditspec.model import FactSpec, Mechanism
from auditspec.verifier_registry import (
    make_registered_verifier_invocation,
    verifier_registry_digest,
)
from test_assurance_gate import (
    CLAIM_ID,
    base_case,
    configurations,
    make_config,
    make_spec,
)


def domain_extension(*, truth: str = "claim_truth", observes_new: bool = False):
    spec = deepcopy(make_spec())
    spec.variables = {"claim_truth": [False, True], "context": [False, True]}
    spec.facts = {**spec.facts, "context": FactSpec(name="context")}
    if observes_new:
        spec.mechanisms = {
            "truth_receipt": replace(
                spec.mechanisms["truth_receipt"],
                facts=("claim_truth", "context"),
            )
        }
    case = replace(base_case(spec), external_predicate=truth)
    return replace(
        make_config("base", spec=spec, case=case), configuration_id="domain-extension"
    )


def manifest(base, extension, *, mode=ExtensionMode.DOMAIN_ONLY_FREEZE, delta=()):
    return FullAssuranceExtensionManifest.build(
        "extension-1",
        mode,
        base,
        extension,
        section_defaults={"context": False}
        if "context" in extension.spec.variables
        and "context" not in base.spec.variables
        else {},
        declared_delta=tuple(delta),
    )


def strong_config(
    name: str,
    *,
    checks=(True, True),
    witness_value: bool = True,
    verifier_id: str = "auditspec-all-boolean-checks-v1",
    replay_id: str = "strong-replay",
    invocation_replay_id: str | None = None,
    fuel: int | None = None,
    manifest_digest: str | None = None,
):
    invocation = make_registered_verifier_invocation(
        verifier_id=verifier_id,
        claim_id=CLAIM_ID,
        replay_id=invocation_replay_id or replay_id,
        input_payload={"checks": list(checks)},
        fuel=fuel if fuel is not None else len(checks),
    )
    if manifest_digest is not None:
        invocation = replace(invocation, verifier_manifest_digest=manifest_digest)
    return make_config(
        name,
        verifier_id=verifier_id,
        replay_id=replay_id,
        declared_value=witness_value,
        evidence_components={"checks": list(checks)},
        registered_verifier_invocation=invocation,
        external_verifier_profile=REGISTERED_REEXECUTION_PROFILE,
    )


def test_domain_only_strict_extension_is_admitted_and_supported() -> None:
    base = configurations()["base"]
    extension = domain_extension()
    result = verify_full_assurance_extension(manifest(base, extension), base, extension)
    assert result.manifest_valid
    assert result.extension_supported
    assert result.new_variables == ("context",)
    assert result.as_dict()["inventory_completeness_is_axiom"] is True
    assert result.as_dict()["inventory_completeness_proven"] is False
    assert result.as_dict()["open_world"] is False
    restored = FullAssuranceExtensionManifest.from_dict(
        manifest(base, extension).as_dict()
    )
    assert restored.as_dict() == manifest(base, extension).as_dict()


def test_domain_only_hidden_topology_change_is_rejected() -> None:
    base = configurations()["base"]
    extension = deepcopy(domain_extension())
    extension.spec.topology = replace(
        extension.spec.topology,
        nodes=frozenset((*extension.spec.topology.nodes, "extra")),
    )
    result = verify_full_assurance_extension(manifest(base, extension), base, extension)
    assert not result.manifest_valid
    assert "frame_violation:topology" in result.errors


def test_declared_safe_topology_and_bypass_deltas_are_separated() -> None:
    base = configurations()["base"]
    safe_spec = deepcopy(make_spec())
    safe_spec.topology = replace(
        safe_spec.topology,
        nodes=frozenset((*safe_spec.topology.nodes, "observer")),
        edges=(*safe_spec.topology.edges, ("sink", "observer")),
    )
    safe = replace(
        make_config("base", spec=safe_spec, case=base_case(safe_spec)),
        configuration_id="safe-topology",
    )
    safe_manifest = FullAssuranceExtensionManifest.build(
        "safe",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        safe,
        section_defaults={},
        declared_delta=("topology",),
    )
    safe_result = verify_full_assurance_extension(safe_manifest, base, safe)
    assert safe_result.manifest_valid and safe_result.extension_supported

    bypass_spec = make_spec(bypass=(("source", "sink"),))
    bypass = replace(
        make_config("base", spec=bypass_spec, case=base_case(bypass_spec)),
        configuration_id="bypass",
    )
    bypass_manifest = FullAssuranceExtensionManifest.build(
        "bypass",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        bypass,
        section_defaults={},
        declared_delta=("bypass",),
    )
    bypass_result = verify_full_assurance_extension(bypass_manifest, base, bypass)
    assert bypass_result.manifest_valid
    assert not bypass_result.extension_supported
    assert bypass_result.first_failed_layer == "M"


def test_extension_rejects_truth_evidence_and_delta_mismatches() -> None:
    base = configurations()["base"]
    truth = domain_extension(truth="claim_truth != context")
    assert (
        "truth:projection_inconsistent"
        in verify_full_assurance_extension(manifest(base, truth), base, truth).errors
    )
    observed = domain_extension(observes_new=True)
    assert (
        "evidence:projection_inconsistent"
        in verify_full_assurance_extension(
            manifest(base, observed), base, observed
        ).errors
    )
    safe_spec = deepcopy(make_spec())
    safe_spec.topology = replace(
        safe_spec.topology, nodes=frozenset((*safe_spec.topology.nodes, "extra"))
    )
    safe = replace(
        make_config("base", spec=safe_spec, case=base_case(safe_spec)),
        configuration_id="undeclared",
    )
    wrong = FullAssuranceExtensionManifest.build(
        "wrong",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        safe,
        section_defaults={},
        declared_delta=(),
    )
    assert (
        "declared_delta:mismatch"
        in verify_full_assurance_extension(wrong, base, safe).errors
    )


def test_extension_rejects_abstraction_and_section_inconsistency() -> None:
    base = configurations()["base"]
    abstracted = domain_extension()
    abstracted_case = replace(
        abstracted.adequacy_case,
        abstraction={"claim_truth": "not claim_truth", "context": "context"},
    )
    abstracted = replace(
        make_config("base", spec=abstracted.spec, case=abstracted_case),
        configuration_id="abstracted-extension",
    )
    abstracted_result = verify_full_assurance_extension(
        manifest(base, abstracted), base, abstracted
    )
    assert "abstraction:projection_inconsistent" in abstracted_result.errors

    extension = domain_extension()
    invalid_section = FullAssuranceExtensionManifest.build(
        "invalid-section",
        ExtensionMode.DOMAIN_ONLY_FREEZE,
        base,
        extension,
        section_defaults={"context": "outside-domain"},
    )
    section_result = verify_full_assurance_extension(invalid_section, base, extension)
    assert "section:not_in_extension_worlds" in section_result.errors


def test_extension_rejects_projection_outside_base_and_digest_tamper() -> None:
    base_spec = make_spec()
    base_spec.variables = {"claim_truth": [False]}
    base = make_config("base", spec=base_spec, case=base_case(base_spec))
    extension = replace(make_config("base"), configuration_id="wider-domain")
    ext_manifest = FullAssuranceExtensionManifest.build(
        "projection",
        ExtensionMode.DOMAIN_ONLY_FREEZE,
        base,
        extension,
        section_defaults={},
        declared_delta=(),
    )
    result = verify_full_assurance_extension(ext_manifest, base, extension)
    assert "projection:outside_base_worlds" in result.errors
    tampered = replace(ext_manifest, base_configuration_digest="0" * 64)
    assert (
        "base_configuration_digest:mismatch"
        in verify_full_assurance_extension(tampered, base, extension).errors
    )


def test_declared_trust_delta_is_valid_manifest_but_fails_v() -> None:
    base = configurations()["base"]
    extension = replace(
        make_config("base", accepted_verifiers=frozenset({"different-verifier"})),
        configuration_id="trust-delta",
    )
    ext_manifest = FullAssuranceExtensionManifest.build(
        "trust",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=("trust_roots",),
    )
    result = verify_full_assurance_extension(ext_manifest, base, extension)
    assert result.manifest_valid
    assert result.first_failed_layer == "V"


def test_registered_verifier_reexecution_controls_v_layer() -> None:
    positive = strong_config("strong-base")
    gate = run_exact_assurance_gate(positive)
    assert gate.supported_within_declared_tcb
    assert gate.registered_verifier_result["executed"] is True
    mismatch = strong_config(
        "strong-mismatch", checks=(True, False), witness_value=True
    )
    failed = run_exact_assurance_gate(mismatch)
    assert failed.first_failed_layer == "V"
    assert "registered_verifier_answer:mismatch" in failed.trace[-1].details


def test_registered_verifier_digest_replay_and_unknown_fail_closed() -> None:
    digest = strong_config("digest", manifest_digest="0" * 64)
    assert run_exact_assurance_gate(digest).first_failed_layer == "V"
    replay = strong_config("replay", invocation_replay_id="different-replay")
    replay_gate = run_exact_assurance_gate(replay)
    assert replay_gate.first_failed_layer == "Q"
    assert "registered_verifier_replay:mismatch" in replay_gate.trace[0].details
    unknown = replace(
        make_registered_verifier_invocation(
            verifier_id="auditspec-all-boolean-checks-v1",
            claim_id=CLAIM_ID,
            replay_id="strong-replay",
            input_payload={"checks": [True]},
            fuel=1,
        ),
        verifier_id="unknown-verifier",
        verifier_manifest_digest="0" * 64,
        input_schema="unknown",
    )
    config = make_config(
        "unknown",
        verifier_id="unknown-verifier",
        replay_id="strong-replay",
        evidence_components={"checks": [True]},
        registered_verifier_invocation=unknown,
        external_verifier_profile=REGISTERED_REEXECUTION_PROFILE,
    )
    assert run_exact_assurance_gate(config).first_failed_layer == "V"


def test_registered_verifier_exception_and_fuel_exhaustion_fail_at_v() -> None:
    raising_invocation = make_registered_verifier_invocation(
        verifier_id="auditspec-raising-verifier-v1",
        claim_id=CLAIM_ID,
        replay_id="strong-replay",
        input_payload={"checks": []},
        fuel=1,
    )
    raising = make_config(
        "raising",
        verifier_id="auditspec-raising-verifier-v1",
        replay_id="strong-replay",
        evidence_components={"checks": []},
        registered_verifier_invocation=raising_invocation,
        external_verifier_profile=REGISTERED_REEXECUTION_PROFILE,
    )
    assert run_exact_assurance_gate(raising).first_failed_layer == "V"
    exhausted = strong_config("exhausted", checks=(True, True, True), fuel=2)
    assert run_exact_assurance_gate(exhausted).first_failed_layer == "V"


def test_strong_v_deletion_certificate_binds_valid_extension_manifest() -> None:
    base = strong_config("strong-shared", checks=(True, True))
    extension = strong_config("strong-shared", checks=(True, False))
    extension = replace(extension, configuration_id="strong-extension")
    delta = actual_structural_delta(base, extension)
    assert delta == ("retained_evidence", "registered_verifier")
    ext_manifest = FullAssuranceExtensionManifest.build(
        "strong-v",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=delta,
    )
    premise = StrongVerifierPremise(
        CLAIM_ID, "auditspec-all-boolean-checks-v1", verifier_registry_digest()
    )
    assert StrongVerifierPremise.from_dict(premise.as_dict()) == premise
    assert strong_verifier_premise_satisfied(premise, base)
    assert not strong_verifier_premise_satisfied(premise, extension)
    certificate = make_strong_v_deletion_certificate(
        premise, ext_manifest, base, extension
    )
    assert verify_strong_v_deletion_certificate(
        certificate, premise, ext_manifest, base, extension
    )
    restored = StrongVDeletionCertificate.from_dict(certificate.as_dict())
    assert restored == certificate
    raw = certificate.as_dict()
    raw["extra"] = True
    with pytest.raises(ValueError, match="closed schema"):
        StrongVDeletionCertificate.from_dict(raw)
    wrong_variant = certificate.as_dict()
    wrong_variant["variant"] = "A:model-twin"
    with pytest.raises(ValueError, match="schema/variant"):
        StrongVDeletionCertificate.from_dict(wrong_variant)


def test_domain_only_frame_binds_signature_trust_threat_inventory_and_contract() -> (
    None
):
    base = configurations()["base"]

    signature = domain_extension()
    evidence_payload = signature.evidence.as_dict()["payload"]
    evidence_payload["attestation"]["signature"] = "0" * 64
    signature = replace(
        signature,
        evidence=replace(signature.evidence, payload=evidence_payload),
    )
    assert actual_structural_delta(base, signature) == ("retained_evidence",)
    assert (
        "frame_violation:retained_evidence"
        in verify_full_assurance_extension(
            manifest(base, signature), base, signature
        ).errors
    )

    trust = domain_extension()
    trust = replace(
        trust,
        trust_context=replace(
            trust.trust_context,
            expected_claim_semantics_commitments={CLAIM_ID: "0" * 64},
        ),
    )
    assert actual_structural_delta(base, trust) == ("trust_roots",)
    assert (
        "frame_violation:trust_roots"
        in verify_full_assurance_extension(manifest(base, trust), base, trust).errors
    )

    threat = deepcopy(domain_extension())
    selected = threat.spec.threat_models[threat.threat_model]
    threat.spec.threat_models[threat.threat_model] = replace(
        selected, compromised_producers=frozenset({"benchmark-evaluator"})
    )
    threat_delta = actual_structural_delta(base, threat)
    assert "threat_model" in threat_delta
    threat_errors = verify_full_assurance_extension(
        manifest(base, threat), base, threat
    ).errors
    assert "frame_violation:threat_model" in threat_errors

    inventory = domain_extension()
    inventory = replace(
        inventory,
        inventory_scope=replace(inventory.inventory_scope, scope_id="other-scope"),
    )
    assert actual_structural_delta(base, inventory) == ("inventory_scope",)
    assert (
        "frame_violation:inventory_scope"
        in verify_full_assurance_extension(
            manifest(base, inventory), base, inventory
        ).errors
    )

    contract = deepcopy(domain_extension())
    selected_mechanism = contract.spec.mechanisms["truth_receipt"]
    contract.spec.mechanisms["truth_receipt"] = replace(
        selected_mechanism, requires=("missing_dependency",)
    )
    contract_delta = actual_structural_delta(base, contract)
    assert "contract" in contract_delta
    contract_errors = verify_full_assurance_extension(
        manifest(base, contract), base, contract
    ).errors
    assert "frame_violation:contract" in contract_errors


def test_manifest_rejects_equal_but_nonderived_inventory_pair() -> None:
    base = configurations()["base"]
    extension = domain_extension()
    bogus = {"bogus": True}
    base = replace(
        base,
        inventory_scope=replace(base.inventory_scope, inventory_manifest=bogus),
    )
    extension = replace(
        extension,
        inventory_scope=replace(extension.inventory_scope, inventory_manifest=bogus),
    )
    assert actual_structural_delta(base, extension) == ()
    result = verify_full_assurance_extension(manifest(base, extension), base, extension)
    assert not result.manifest_valid
    assert "base_inventory_manifest:derived_relation_mismatch" in result.errors
    assert "extension_inventory_manifest:derived_relation_mismatch" in result.errors


@pytest.mark.parametrize("dependency_exists", [False, True])
def test_manifest_and_gate_reject_pair_equal_invalid_dependency_closure(
    dependency_exists: bool,
) -> None:
    spec = make_spec()
    spec.mechanisms["truth_receipt"] = replace(
        spec.mechanisms["truth_receipt"], requires=("required_receipt",)
    )
    if dependency_exists:
        spec.mechanisms["required_receipt"] = Mechanism(
            name="required_receipt",
            facts=("claim_truth",),
            adapter="agent-final",
        )
    base = make_config("invalid-contract", spec=spec, case=base_case(spec))
    extension = replace(base, configuration_id="invalid-contract-extension")
    assert actual_structural_delta(base, extension) == ()
    gate = run_exact_assurance_gate(base)
    assert gate.first_failed_layer == "R"
    relation = verify_full_assurance_extension(
        FullAssuranceExtensionManifest.build(
            "invalid-contract",
            ExtensionMode.DOMAIN_ONLY_FREEZE,
            base,
            extension,
            section_defaults={},
        ),
        base,
        extension,
    )
    assert not relation.manifest_valid
    expected = (
        "unselected_dependencies" if dependency_exists else "missing_dependencies"
    )
    assert f"base_contract:{expected}" in relation.errors
    assert f"extension_contract:{expected}" in relation.errors


def test_exact_gate_requires_complete_multihop_dependency_selection() -> None:
    spec = make_spec()
    spec.mechanisms["truth_receipt"] = replace(
        spec.mechanisms["truth_receipt"], requires=("middle_receipt",)
    )
    spec.mechanisms["middle_receipt"] = Mechanism(
        name="middle_receipt",
        facts=("claim_truth",),
        adapter="agent-final",
        requires=("leaf_receipt",),
    )
    spec.mechanisms["leaf_receipt"] = Mechanism(
        name="leaf_receipt",
        facts=("claim_truth",),
        adapter="agent-final",
    )
    complete = make_config(
        "complete-closure",
        spec=spec,
        case=base_case(spec),
        contract=("leaf_receipt", "middle_receipt", "truth_receipt"),
    )
    assert run_exact_assurance_gate(complete).supported_within_declared_tcb
    incomplete = make_config(
        "incomplete-closure",
        spec=spec,
        case=base_case(spec),
        contract=("middle_receipt", "truth_receipt"),
    )
    gate = run_exact_assurance_gate(incomplete)
    assert gate.first_failed_layer == "R"
    details = tuple(detail for item in gate.trace for detail in item.details)
    assert "middle_receipt:missing:selected_dependency:leaf_receipt" in details


def test_profile_cannot_be_silently_downgraded_or_declared_admissible() -> None:
    base = strong_config("strong-profile")
    extension = replace(
        base,
        configuration_id="weak-profile",
        external_verifier_profile="v06_fixed_envelope",
    )
    assert actual_structural_delta(base, extension) == ("external_verifier_profile",)
    frozen = FullAssuranceExtensionManifest.build(
        "profile-freeze",
        ExtensionMode.DOMAIN_ONLY_FREEZE,
        base,
        extension,
        section_defaults={},
    )
    assert (
        "frame_violation:external_verifier_profile"
        in verify_full_assurance_extension(frozen, base, extension).errors
    )
    declared = FullAssuranceExtensionManifest.build(
        "profile-declared",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=("external_verifier_profile",),
    )
    assert (
        "declared_delta:unsupported_coordinate"
        in verify_full_assurance_extension(declared, base, extension).errors
    )
    premise = StrongVerifierPremise(
        CLAIM_ID, "auditspec-all-boolean-checks-v1", verifier_registry_digest()
    )
    assert not strong_verifier_premise_satisfied(premise, extension)


def test_registered_input_is_derived_from_signed_retained_evidence() -> None:
    invocation = make_registered_verifier_invocation(
        verifier_id="auditspec-all-boolean-checks-v1",
        claim_id=CLAIM_ID,
        replay_id="strong-replay",
        input_payload={"checks": [True]},
        fuel=1,
    )
    config = make_config(
        "derived-input-mismatch",
        verifier_id="auditspec-all-boolean-checks-v1",
        replay_id="strong-replay",
        evidence_components={"checks": [False]},
        registered_verifier_invocation=invocation,
        external_verifier_profile=REGISTERED_REEXECUTION_PROFILE,
    )
    gate = run_exact_assurance_gate(config)
    assert gate.first_failed_layer == "V"
    assert gate.registered_verifier_result is None
    assert gate.external_result is not None and gate.external_result["valid"] is True
    assert (
        "registered verifier derived input digest mismatch" in gate.trace[-1].details[0]
    )


def test_registered_execution_rejects_in_process_function_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = strong_config(
        "implementation-rebound",
        checks=(True, False),
        witness_value=True,
    )
    rebound = dict(verifier_registry_module._FUNCTIONS)
    rebound["auditspec-all-boolean-checks-v1"] = lambda payload, fuel: (True, 1)
    monkeypatch.setattr(
        verifier_registry_module,
        "_FUNCTIONS",
        MappingProxyType(rebound),
    )
    gate = run_exact_assurance_gate(config)
    assert gate.first_failed_layer == "V"
    assert gate.registered_verifier_result is not None
    assert gate.registered_verifier_result["executed"] is False
    assert "verifier_implementation_digest:mismatch" in gate.trace[-1].details


def test_gate_rejects_serialized_vacuous_empty_check_invocation() -> None:
    seeded = make_registered_verifier_invocation(
        verifier_id="auditspec-all-boolean-checks-v1",
        claim_id=CLAIM_ID,
        replay_id="strong-replay",
        input_payload={"checks": [True]},
        fuel=1,
    )
    empty = replace(
        seeded,
        input_payload_digest=canonical_digest({"checks": []}),
        fuel=0,
    )
    config = make_config(
        "serialized-empty",
        verifier_id="auditspec-all-boolean-checks-v1",
        replay_id="strong-replay",
        evidence_components={"checks": []},
        registered_verifier_invocation=empty,
        external_verifier_profile=REGISTERED_REEXECUTION_PROFILE,
    )
    gate = run_exact_assurance_gate(config)
    assert gate.first_failed_layer == "V"
    assert gate.registered_verifier_result is None
    assert "below the input item minimum" in gate.trace[-1].details[0]


def test_strong_v_certificate_rejects_external_packet_v_failure() -> None:
    base = strong_config("packet-source")
    extension = replace(
        base,
        configuration_id="packet-invalid",
        trust_context=replace(
            base.trust_context,
            accepted_verifiers=frozenset({"different-verifier"}),
        ),
    )
    ext_manifest = FullAssuranceExtensionManifest.build(
        "packet-invalid",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=("trust_roots",),
    )
    result = verify_full_assurance_extension(ext_manifest, base, extension)
    assert result.manifest_valid and result.first_failed_layer == "V"
    assert run_exact_assurance_gate(extension).registered_verifier_result is None
    premise = StrongVerifierPremise(
        CLAIM_ID, "auditspec-all-boolean-checks-v1", verifier_registry_digest()
    )
    with pytest.raises(ValueError, match="requires registered invocations"):
        make_strong_v_deletion_certificate(premise, ext_manifest, base, extension)


def test_manifest_wire_schema_order_digests_and_defaults_are_closed() -> None:
    base = strong_config("wire-shared", checks=(True, True))
    extension = replace(
        strong_config("wire-shared", checks=(True, False)),
        configuration_id="wire-extension",
    )
    delta = actual_structural_delta(base, extension)
    value = FullAssuranceExtensionManifest.build(
        "wire",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=delta,
    )
    raw = value.as_dict()
    raw["extra"] = True
    with pytest.raises(ValueError, match="closed schema"):
        FullAssuranceExtensionManifest.from_dict(raw)
    reordered = value.as_dict()
    reordered["declared_delta"] = list(reversed(reordered["declared_delta"]))
    with pytest.raises(ValueError, match="canonical coordinate order"):
        FullAssuranceExtensionManifest.from_dict(reordered)
    uppercase = value.as_dict()
    uppercase["inventory_scope_pair_digest"] = "A" * 64
    with pytest.raises(TypeError, match="must be a digest"):
        FullAssuranceExtensionManifest.from_dict(uppercase)

    nested = replace(value, section_defaults={"nested": {"items": [1, 2]}})
    with pytest.raises(TypeError):
        nested.section_defaults["nested"]["items"] = (3,)


@pytest.mark.parametrize(
    "field",
    [
        "premise_digest",
        "extension_manifest_digest",
        "base_configuration_digest",
        "extension_configuration_digest",
        "base_execution_digest",
        "extension_execution_digest",
    ],
)
def test_strong_v_certificate_rejects_each_digest_tamper(field: str) -> None:
    base = strong_config("digest-shared", checks=(True, True))
    extension = replace(
        strong_config("digest-shared", checks=(True, False)),
        configuration_id="digest-extension",
    )
    ext_manifest = FullAssuranceExtensionManifest.build(
        "digest-strong-v",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=actual_structural_delta(base, extension),
    )
    premise = StrongVerifierPremise(
        CLAIM_ID, "auditspec-all-boolean-checks-v1", verifier_registry_digest()
    )
    certificate = make_strong_v_deletion_certificate(
        premise, ext_manifest, base, extension
    )
    tampered = replace(certificate, **{field: "0" * 64})
    assert not verify_strong_v_deletion_certificate(
        tampered, premise, ext_manifest, base, extension
    )
