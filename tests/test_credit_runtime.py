from __future__ import annotations

from pathlib import Path

from auditspec.compiler import AuditCompiler
from auditspec.runtime.conformance import verify_runtime_conformance
from auditspec.runtime.credit_graph import run_credit_fixture, runtime_world
from auditspec.runtime.credit_replay import CreditReplayHarness
from auditspec.spec import load_spec

ROOT = Path(__file__).resolve().parents[1]
CREDIT = ROOT / "examples" / "credit.yaml"


def test_credit_workflow_emits_semantically_conformant_passive_evidence(
    tmp_path: Path,
) -> None:
    spec = load_spec(CREDIT)
    contract = [name for name, item in spec.mechanisms.items() if item.mode == "passive"]
    result, sink = run_credit_fixture(
        {"run_id": "credit-runtime"},
        db_path=tmp_path / "decisions.sqlite",
        enabled_mechanisms=set(contract),
    )
    conformance = verify_runtime_conformance(
        spec,
        runtime_world(result, False),
        sink,
        contract,
        threat_model="adversarial_agent",
        expected_action_id=result["application_id"],
        expected_run_id=result["run_id"],
    )
    assert result["phase"] == "reported"
    assert sink.verify() == (True, [])
    assert conformance.valid is True
    assert conformance.errors == ()


def test_credit_replay_executes_declared_min_trials_and_conforms() -> None:
    spec = load_spec(CREDIT)
    compiler = AuditCompiler(spec)
    synthesis = compiler.synthesize(
        "income_feature_necessary_for_denial",
        threat_model="adversarial_agent",
    )
    assert synthesis.status == "ACTIVE_AUDIT_REQUIRED"
    outcome, original, sink, replay_sinks = CreditReplayHarness(
        set(synthesis.contract)
    ).run({"run_id": "credit-ablation"})
    conformance = verify_runtime_conformance(
        spec,
        runtime_world(original, bool(outcome.denial_without_income_feature)),
        sink,
        synthesis.contract,
        threat_model="adversarial_agent",
        expected_action_id=original["application_id"],
        expected_run_id=original["run_id"],
    )
    replay = spec.mechanisms["virtualized_income_ablation"].replay
    assert replay is not None
    assert outcome.trials == replay.min_trials == 3
    assert len(replay_sinks) == 3
    assert outcome.prefix_equal is True
    assert outcome.outcome_flip is True
    assert outcome.verifier_passed is True
    assert all(item.verify() == (True, []) for item in replay_sinks)
    assert conformance.valid is True
