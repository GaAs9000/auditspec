from __future__ import annotations

import inspect
from dataclasses import fields, replace
from pathlib import Path

from auditspec.compiler import AuditCompiler
from auditspec.runtime.attacks import (
    payment_runtime_attacks,
    replay_runtime_attacks,
    resign_with_mutation,
)
from auditspec.runtime.conformance import certify_adapter_run
from auditspec.runtime.credit_replay import CreditReplayHarness
from auditspec.runtime.payment_graph import run_payment_fixture, runtime_world
from auditspec.runtime.run_verification import (
    PolicyRoot,
    RunTrustContext,
    build_fixture_trust_context,
    verify_run_evidence,
)
from auditspec.spec import load_spec


ROOT = Path(__file__).resolve().parents[1]


def _all_passive(spec):
    return [name for name, item in spec.mechanisms.items() if item.mode == "passive"]


def test_deployment_verifier_has_no_hidden_world_parameter() -> None:
    verifier_parameters = set(inspect.signature(verify_run_evidence).parameters)
    assert verifier_parameters.isdisjoint(
        {"world", "truth", "answer", "query_result", "external_predicate"}
    )
    trust_fields = {item.name for item in fields(RunTrustContext)}
    assert trust_fields.isdisjoint(
        {"world", "truth", "answer", "query_result", "external_predicate"}
    )
    assert "world" in inspect.signature(certify_adapter_run).parameters


def test_payment_run_evidence_verifies_without_world(tmp_path: Path) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = _all_passive(spec)
    result, sink = run_payment_fixture(
        {"run_id": "oracle-free-payment"},
        db_path=tmp_path / "payment.sqlite",
        enabled_mechanisms=set(contract),
    )
    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    verified = verify_run_evidence(spec, sink, contract, context)
    assert verified.valid is True
    assert verified.errors == ()

    certified = certify_adapter_run(
        spec,
        runtime_world(result, False),
        sink,
        contract,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    assert certified.valid is True


def test_deployment_verifier_rejects_untrusted_producer_key(tmp_path: Path) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = ["canonical_action"]
    result, sink = run_payment_fixture(
        {"run_id": "wrong-key"},
        db_path=tmp_path / "wrong-key.sqlite",
        enabled_mechanisms=set(contract),
    )
    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    bad_keys = dict(context.producer_keys)
    bad_keys["action_gateway"] = b"not-the-authoritative-key"
    verified = verify_run_evidence(
        spec, sink, contract, replace(context, producer_keys=bad_keys)
    )
    assert verified.valid is False
    assert any(error.startswith("trust_root:signature:") for error in verified.errors)


def test_deployment_verifier_rejects_expired_policy_root(tmp_path: Path) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = ["canonical_action", "policy_snapshot"]
    result, sink = run_payment_fixture(
        {"run_id": "expired-policy"},
        db_path=tmp_path / "expired.sqlite",
        enabled_mechanisms=set(contract),
    )
    context = build_fixture_trust_context(spec)
    policy_event = next(event for event in sink.events if event.mechanism == "policy_snapshot")
    version_id = policy_event.attributes["policy_version_id"]
    roots = dict(context.policy_roots)
    original = roots[version_id]
    roots[version_id] = PolicyRoot(
        original.version_id,
        original.mechanism_observations,
        valid_from_ns=0,
        valid_to_ns=policy_event.captured_ns - 1,
    )
    verified = verify_run_evidence(
        spec, sink, contract, replace(context, policy_roots=roots)
    )
    assert verified.valid is False
    assert "policy_root:policy_snapshot" in verified.errors


def test_deployment_verifier_rejects_resigned_receipt_misbinding(
    tmp_path: Path,
) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = ["canonical_action", "approval_bound_receipt"]
    result, sink = run_payment_fixture(
        {"run_id": "receipt-binding"},
        db_path=tmp_path / "receipt.sqlite",
        enabled_mechanisms=set(contract),
    )

    def mutate(envelope):
        envelope["attributes"]["action_digest"] = "0" * 64

    forged = resign_with_mutation(
        sink, mechanism="approval_bound_receipt", mutate=mutate
    )
    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    verified = verify_run_evidence(spec, forged, contract, context)
    assert forged.verify() == (True, [])
    assert verified.valid is False
    assert "receipt_binding:approval_bound_receipt:action_digest" in verified.errors


def test_oracle_free_verifier_rejects_resigned_payment_attack_suite(
    tmp_path: Path,
) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = _all_passive(spec)
    result, sink = run_payment_fixture(
        {"run_id": "oracle-free-attacks"},
        db_path=tmp_path / "attacks.sqlite",
        enabled_mechanisms=set(contract),
    )
    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    for attack in payment_runtime_attacks(sink):
        verified = verify_run_evidence(
            spec,
            attack.sink,
            contract,
            context,
            threat_model=attack.threat_model,
        )
        assert verified.valid is False, attack.name
        assert verified.errors, attack.name


def test_payment_coverage_attack_is_non_noop_for_incomplete_gateway(
    tmp_path: Path,
) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = _all_passive(spec)
    result, sink = run_payment_fixture(
        {
            "run_id": "incomplete-gateway-coverage-attack",
            "gateway_coverage_complete": False,
            "tool_response": "timeout",
            "commit_policy": "commit_on_timeout",
        },
        db_path=tmp_path / "incomplete-gateway.sqlite",
        enabled_mechanisms=set(contract),
    )
    source_event = next(
        event for event in sink.events if event.mechanism == "gateway_coverage"
    )
    assert source_event.attributes["observation_values"][
        "gateway_coverage_complete"
    ] is False

    attack = next(
        item for item in payment_runtime_attacks(sink)
        if item.name == "false_coverage_value"
    )
    forged_event = next(
        event for event in attack.sink.events
        if event.mechanism == "gateway_coverage"
    )
    assert forged_event.attributes["observation_values"][
        "gateway_coverage_complete"
    ] is True

    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    verified = verify_run_evidence(
        spec,
        attack.sink,
        contract,
        context,
        threat_model=attack.threat_model,
    )
    assert verified.valid is False
    assert (
        "observation_attribute_binding:gateway_coverage:gateway_coverage_complete"
        in verified.errors
    )


def test_resigned_mutation_rejects_noop(tmp_path: Path) -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    contract = _all_passive(spec)
    _, sink = run_payment_fixture(
        {"run_id": "noop-attack"},
        db_path=tmp_path / "noop.sqlite",
        enabled_mechanisms=set(contract),
    )
    try:
        resign_with_mutation(
            sink,
            mechanism="gateway_coverage",
            mutate=lambda envelope: None,
        )
    except ValueError as exc:
        assert "did not change target mechanism" in str(exc)
    else:
        raise AssertionError("a no-op mutation must not be emitted as an attack")


def test_credit_replay_evidence_and_attacks_verify_without_world() -> None:
    spec = load_spec(ROOT / "examples" / "credit.yaml")
    synthesis = AuditCompiler(spec).synthesize(
        "income_feature_necessary_for_denial", "adversarial_agent"
    )
    _, result, sink, _ = CreditReplayHarness(set(synthesis.contract)).run(
        {"run_id": "oracle-free-credit-replay"}
    )
    context = build_fixture_trust_context(
        spec,
        expected_action_id=result["application_id"],
        expected_run_id=result["run_id"],
    )
    positive = verify_run_evidence(
        spec,
        sink,
        synthesis.contract,
        context,
        threat_model="adversarial_agent",
    )
    assert positive.valid is True
    for attack in replay_runtime_attacks(sink, "virtualized_income_ablation"):
        verified = verify_run_evidence(
            spec,
            attack.sink,
            synthesis.contract,
            context,
            threat_model="adversarial_agent",
        )
        assert verified.valid is False, attack.name
        assert "replay_proof:virtualized_income_ablation" in verified.errors
