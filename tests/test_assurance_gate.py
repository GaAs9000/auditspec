from __future__ import annotations

from dataclasses import replace

import pytest

from auditspec.assurance import (
    EXTERNAL_VERIFIER_PROFILE,
    AssuranceConfiguration,
    DeclaredInventoryScope,
    claim_semantics_commitment_for,
    declared_inventory_manifest,
    external_packet_result,
    run_exact_assurance_gate,
)
from auditspec.external.evidence import (
    EvidenceAttestation,
    ExternalEvidenceSource,
    ExternalTrustContext,
    IndependentVerifierWitness,
    project_external_evidence,
    sign_evidence_attestation,
)
from auditspec.isolated_verifier import IsolatedVerifierInvocation, IsolationPolicy
from auditspec.model import (
    AuditSpec,
    DeploymentTopology,
    FactSpec,
    Mechanism,
    MediationChannel,
    Query,
    ThreatModel,
)
from auditspec.model_adequacy import AdequacyCase, AssuranceVerdict
from auditspec.verifier_registry import RegisteredVerifierInvocation

CLAIM_ID = "T01"
PRODUCER_KEY = b"v11-minimality-test-key"
VERIFIER_ID = "v11-packet-verifier"
REVISION = "v11-test-revision"


def make_spec(
    *, adapter: str = "agent-final", bypass: tuple[tuple[str, str], ...] = ()
) -> AuditSpec:
    channel = "tau2-tool-dispatch"
    return AuditSpec(
        name="v11-minimality-test",
        description="Declared finite exact-gate fixture",
        variables={"claim_truth": [False, True]},
        constraints=[],
        facts={"claim_truth": FactSpec(name="claim_truth")},
        queries={CLAIM_ID: Query(name=CLAIM_ID, expression="claim_truth")},
        mechanisms={
            "truth_receipt": Mechanism(
                name="truth_receipt",
                facts=("claim_truth",),
                adapter=adapter,
            )
        },
        threat_models={
            "cooperative": ThreatModel(name="cooperative", bypass_edges=bypass)
        },
        topology=DeploymentTopology(
            nodes=frozenset({"source", "mediator", "sink"}),
            edges=(("source", "mediator"), ("mediator", "sink")),
            channels={
                channel: MediationChannel(
                    name=channel,
                    sources=("source",),
                    sinks=("sink",),
                    mediator="mediator",
                )
            },
        ),
        metadata={"domain": "v11-minimality-test"},
    )


def base_case(spec: AuditSpec) -> AdequacyCase:
    return AdequacyCase(
        obligation_id=CLAIM_ID,
        pack=spec.name,
        external_predicate="claim_truth",
        abstract_query="claim_truth",
        external_variables={},
    )


def make_config(
    name: str,
    *,
    spec: AuditSpec | None = None,
    case: AdequacyCase | None = None,
    contract: tuple[str, ...] = ("truth_receipt",),
    coverage_complete: bool = True,
    accepted_verifiers: frozenset[str] | None = None,
    verifier_id: str = VERIFIER_ID,
    replay_id: str = "v11-replay",
    declared_value: bool = True,
    evidence_components: dict[str, object] | None = None,
    registered_verifier_invocation: RegisteredVerifierInvocation | None = None,
    isolated_verifier_invocation: IsolatedVerifierInvocation | None = None,
    isolation_policy: IsolationPolicy | None = None,
    external_verifier_profile: str = EXTERNAL_VERIFIER_PROFILE,
) -> AssuranceConfiguration:
    spec = spec or make_spec()
    case = case or base_case(spec)
    commitment = claim_semantics_commitment_for(
        spec, case, claim_id=CLAIM_ID, query_name=CLAIM_ID
    )
    witness = IndependentVerifierWitness(
        witness_id=f"{name}-witness",
        claim_id=CLAIM_ID,
        statement="The declared finite claim is true.",
        declared_value=declared_value,
        verifier_id=verifier_id,
        replay_id=replay_id,
        computation="declared finite packet verification",
        evidence_components=(
            {"scope": "v11-test"}
            if evidence_components is None
            else evidence_components
        ),
        claim_semantics_commitment=commitment,
    )
    unsigned = EvidenceAttestation(
        run_id="v11-run",
        task_id="v11-task",
        claim_id=CLAIM_ID,
        benchmark_revision=REVISION,
        witness_id=witness.witness_id,
        producer="benchmark-evaluator",
        capture_point="benchmark-harness",
        verifier_id=verifier_id,
        binding_edges=(
            ("run", "task"),
            ("run", "claim"),
            ("run", "verifier_witness"),
            ("task", "benchmark_revision"),
        ),
        coverage_channel="tau2-tool-dispatch",
        coverage_complete=coverage_complete,
        claim_semantics_commitment=commitment,
    )
    attestation = sign_evidence_attestation(unsigned, witness, PRODUCER_KEY)
    source = ExternalEvidenceSource(
        environment="tau2",
        run_id="v11-run",
        task_id="v11-task",
        benchmark_revision=REVISION,
        witnesses={CLAIM_ID: witness},
        attestations={CLAIM_ID: attestation},
    )
    evidence = project_external_evidence(
        source, CLAIM_ID, "auditspec_compiled_contract"
    )
    trust = ExternalTrustContext(
        environment="tau2",
        benchmark_revision=REVISION,
        expected_run_id="v11-run",
        expected_task_id="v11-task",
        producer_keys={"benchmark-evaluator": PRODUCER_KEY},
        accepted_capture_points=frozenset({"benchmark-harness"}),
        accepted_verifiers=accepted_verifiers or frozenset({verifier_id}),
        mandatory_coverage_channel="tau2-tool-dispatch",
        expected_claim_semantics_commitments={CLAIM_ID: commitment},
    )
    inventory = DeclaredInventoryScope(
        scope_id="v11-declared-scope",
        channel="tau2-tool-dispatch",
        inventory_manifest=declared_inventory_manifest(
            spec, threat_model="cooperative", channel="tau2-tool-dispatch"
        ),
    )
    return AssuranceConfiguration(
        configuration_id=name,
        spec=spec,
        adequacy_case=case,
        claim_id=CLAIM_ID,
        query_name=CLAIM_ID,
        contract=contract,
        threat_model="cooperative",
        claim_semantics_commitment=commitment,
        evidence=evidence,
        trust_context=trust,
        inventory_scope=inventory,
        external_verifier_profile=external_verifier_profile,
        registered_verifier_invocation=registered_verifier_invocation,
        isolated_verifier_invocation=isolated_verifier_invocation,
        isolation_policy=isolation_policy,
    )


def configurations() -> dict[str, AssuranceConfiguration]:
    base = make_config("base")
    q_case = replace(base.adequacy_case, external_predicate="not claim_truth")
    q = make_config("q-gap", case=q_case)
    a_case = replace(
        base.adequacy_case,
        external_predicate="claim_truth != hidden_dependency",
        external_variables={"hidden_dependency": (False, True)},
        missing_semantics=("hidden_dependency",),
    )
    a = make_config("a-gap", case=a_case)
    d = make_config("d-gap", contract=())
    r_spec = make_spec(adapter="unregistered-v11-adapter")
    r = make_config("r-gap", spec=r_spec, case=base_case(r_spec))
    m_spec = make_spec(bypass=(("source", "sink"),))
    m = make_config("m-gap", spec=m_spec, case=base_case(m_spec))
    m_coverage = make_config("m-coverage-gap", coverage_complete=False)
    v = make_config("v-gap", accepted_verifiers=frozenset({"different-verifier"}))
    return {
        "base": base,
        "Q": q,
        "A": a,
        "D": d,
        "R": r,
        "M": m,
        "M_coverage": m_coverage,
        "V": v,
    }


def test_exact_gate_supported_base_is_literal_external_positive() -> None:
    result = run_exact_assurance_gate(configurations()["base"])
    assert result.primary_verdict is AssuranceVerdict.VERIFIED_AUDITABLE
    assert result.first_failed_layer is None
    assert result.supported_within_declared_tcb is True
    assert [str(item.status) for item in result.trace] == ["PASS"] * 6
    assert result.external_result is not None
    assert result.external_result["valid"] is True
    assert result.as_dict()["open_world"] is False
    assert result.as_dict()["inventory_completeness_proven"] is False


@pytest.mark.parametrize(
    ("name", "layer", "verdict"),
    [
        ("Q", "Q", AssuranceVerdict.QUERY_GAP),
        ("A", "A", AssuranceVerdict.MODEL_GAP),
        ("D", "D", AssuranceVerdict.EVIDENCE_GAP),
        ("R", "R", AssuranceVerdict.TCB_GAP),
        ("M", "M", AssuranceVerdict.TCB_GAP),
        ("M_coverage", "M", AssuranceVerdict.TCB_GAP),
        ("V", "V", AssuranceVerdict.VERIFICATION_FAILURE),
    ],
)
def test_exact_gate_locates_each_declared_layer(
    name: str, layer: str, verdict: AssuranceVerdict
) -> None:
    result = run_exact_assurance_gate(configurations()[name])
    assert result.first_failed_layer == layer
    assert result.primary_verdict is verdict
    assert result.supported_within_declared_tcb is False
    failed = [item for item in result.trace if str(item.status) == "TYPED_FAIL"]
    assert [item.layer for item in failed] == [layer]


def test_external_result_default_serialization_stays_backward_compatible() -> None:
    result = external_packet_result(configurations()["base"])
    assert "first_failed_layer" not in result.as_dict()
    assert result.as_dict(include_layer=True)["first_failed_layer"] is None


def test_external_q_failure_has_one_ordered_q_trace() -> None:
    base = configurations()["base"]
    attacked = replace(
        base,
        configuration_id="bad-evidence-schema",
        evidence=replace(base.evidence, schema="bogus"),
    )
    result = run_exact_assurance_gate(attacked)
    assert result.first_failed_layer == "Q"
    assert [item.layer for item in result.trace] == list("QADRMV")
    assert [str(item.status) for item in result.trace] == [
        "TYPED_FAIL",
        "SKIPPED",
        "SKIPPED",
        "SKIPPED",
        "SKIPPED",
        "SKIPPED",
    ]


def test_malformed_adequacy_expression_fails_closed_instead_of_raising() -> None:
    base = configurations()["base"]
    malformed = replace(base.adequacy_case, external_predicate="unknown_name")
    config = make_config("malformed-adequacy", case=malformed)
    result = run_exact_assurance_gate(config)
    assert result.supported_within_declared_tcb is False
    assert result.first_failed_layer == "A"
    assert result.primary_verdict is AssuranceVerdict.VERIFICATION_FAILURE


def test_global_registry_snapshots_are_bound_to_configuration_digest() -> None:
    base = configurations()["base"]
    bad_claim_registry = replace(base, external_claim_registry_snapshot="0" * 64)
    assert run_exact_assurance_gate(bad_claim_registry).first_failed_layer == "Q"
    bad_adapter_registry = replace(base, adapter_registry_snapshot="0" * 64)
    assert run_exact_assurance_gate(bad_adapter_registry).first_failed_layer == "R"
