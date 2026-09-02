from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from auditspec.compiler import AuditCompiler
from auditspec.runtime.conformance import verify_runtime_conformance
from auditspec.runtime import PaymentReplayHarness, run_payment_fixture
from auditspec.runtime.payment_graph import runtime_world
from auditspec.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
PAYMENT = ROOT / "examples" / "payment.yaml"

ALL_RUNTIME_MECHANISMS = {
    "canonical_action",
    "generic_agent_trace",
    "model_advice",
    "human_decision_record",
    "approval_bound_receipt",
    "delegation_context",
    "policy_snapshot",
    "gateway_coverage",
    "durable_effect_receipt",
    "final_output",
    "virtualized_tool_omission_replay",
    "coarse_amount_channel",
    "coarse_policy_channel",
    "amount_token",
    "policy_state_token",
}


def test_langgraph_fixture_commits_durable_state_and_emits_valid_chain(
    tmp_path: Path,
) -> None:
    result, sink = run_payment_fixture(
        {
            "run_id": "runtime-test",
            "commit_policy": "single_on_success",
            "tool_response": "success",
        },
        db_path=tmp_path / "ledger.sqlite",
        enabled_mechanisms=ALL_RUNTIME_MECHANISMS,
    )
    assert result["ledger_commit_count"] == 1
    assert result["phase"] == "reported"
    assert sink.verify() == (True, [])
    assert sink.serialized_bytes() > 0
    assert {event.mechanism for event in sink.events} >= {
        "canonical_action",
        "durable_effect_receipt",
        "gateway_coverage",
    }


def test_chained_event_tampering_is_detected(tmp_path: Path) -> None:
    _, sink = run_payment_fixture(
        {"run_id": "tamper-test"},
        db_path=tmp_path / "ledger.sqlite",
        enabled_mechanisms=ALL_RUNTIME_MECHANISMS,
    )
    first = sink.events[0]
    sink.events[0] = replace(first, attributes={**first.attributes, "amount": 999999})
    valid, errors = sink.verify()
    assert valid is False
    assert any(error.startswith("hash:") for error in errors)


def test_compiled_plan_is_realized_by_fixture(tmp_path: Path) -> None:
    compiler = AuditCompiler(load_spec(PAYMENT))
    result = compiler.synthesize(
        "transfer_authorized", threat_model="adversarial_agent"
    )
    _, sink = run_payment_fixture(
        {"run_id": "plan-realization"},
        db_path=tmp_path / "ledger.sqlite",
        enabled_mechanisms=set(result.contract),
    )
    assert {event.mechanism for event in sink.events} == set(result.contract)


def test_payment_runtime_conformance_checks_values_bindings_and_registry(
    tmp_path: Path,
) -> None:
    spec = load_spec(PAYMENT)
    contract = [name for name, item in spec.mechanisms.items() if item.mode == "passive"]
    result, sink = run_payment_fixture(
        {"run_id": "semantic-conformance"},
        db_path=tmp_path / "semantic.sqlite",
        enabled_mechanisms=set(contract),
    )
    checked = verify_runtime_conformance(
        spec,
        runtime_world(result, False),
        sink,
        contract,
        threat_model="cooperative",
        expected_action_id=result["action_id"],
        expected_run_id=result["run_id"],
    )
    assert checked.valid is True
    assert checked.errors == ()


def test_virtualized_replay_uses_same_prefix_and_flips_duplicate_outcome() -> None:
    outcome, original, original_sink, replay_sink = PaymentReplayHarness(
        ALL_RUNTIME_MECHANISMS
    ).run(
        {
            "run_id": "replay-test",
            "commit_policy": "duplicate_on_success",
            "tool_response": "success",
        }
    )
    assert outcome.feasible is True
    assert outcome.prefix_equal is True
    assert outcome.original_commit_count == 2
    assert outcome.replay_commit_count == 0
    assert outcome.outcome_flip is True
    assert outcome.verifier_passed is True
    assert original["ledger_commit_count"] == 2
    assert original_sink.verify() == (True, [])
    assert replay_sink is not None and replay_sink.verify() == (True, [])


def test_payment_replay_proof_conforms_to_active_contract() -> None:
    spec = load_spec(PAYMENT)
    compiler = AuditCompiler(spec)
    synthesis = compiler.synthesize(
        "tool_response_necessary_for_duplicate", threat_model="adversarial_agent"
    )
    outcome, original, sink, _ = PaymentReplayHarness(
        set(synthesis.contract)
    ).run(
        {
            "run_id": "replay-conformance",
            "commit_policy": "duplicate_on_success",
            "tool_response": "success",
        }
    )
    checked = verify_runtime_conformance(
        spec,
        runtime_world(original, bool(outcome.duplicate_without_tool_response)),
        sink,
        synthesis.contract,
        threat_model="adversarial_agent",
        expected_action_id=original["action_id"],
        expected_run_id=original["run_id"],
    )
    assert checked.valid is True


def test_seeded_planner_is_reproducible_and_branches(tmp_path: Path) -> None:
    outputs: list[str] = []
    digests: list[str] = []
    for seed in range(12):
        result, _ = run_payment_fixture(
            {"run_id": f"planner-{seed}", "planner_seed": seed},
            db_path=tmp_path / f"planner-{seed}.sqlite",
            enabled_mechanisms={"model_advice"},
        )
        outputs.append(result["model_recommendation"])
        digests.append(result["planner_trace_digest"])
    repeated, _ = run_payment_fixture(
        {"run_id": "planner-repeat", "planner_seed": 0},
        db_path=tmp_path / "planner-repeat.sqlite",
        enabled_mechanisms={"model_advice"},
    )
    assert repeated["model_recommendation"] == outputs[0]
    assert repeated["planner_trace_digest"] == digests[0]
    assert set(outputs) == {"approve", "deny"}


def test_irreversible_replay_is_rejected_before_any_side_effect() -> None:
    outcome, result, sink, replay_sink = PaymentReplayHarness(
        ALL_RUNTIME_MECHANISMS
    ).run(
        {"run_id": "unsafe-replay"}, side_effect_mode="irreversible"
    )
    assert outcome.feasible is False
    assert outcome.reason == "irreversible_side_effect"
    assert result == {}
    assert sink.events == []
    assert replay_sink is None
