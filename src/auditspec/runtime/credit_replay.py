from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .credit_graph import (
    _credit_spec,
    build_credit_graph,
    run_credit_fixture,
    runtime_world,
)
from .evidence import emit_mechanism_event
from .events import AuditEvent, EventSink, canonical_json
from .replay_proof import build_replay_proof, nondeterminism_capture


@dataclass(frozen=True)
class CreditReplayOutcome:
    feasible: bool
    target: str
    trials: int
    original_decision: str | None
    replay_decisions: tuple[str, ...]
    denial_without_income_feature: bool | None
    outcome_flip: bool | None
    prefix_equal: bool | None
    verifier_passed: bool
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _initialize(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, application_id TEXT NOT NULL, decision TEXT NOT NULL, record_bound INTEGER NOT NULL)"
        )
        connection.commit()


def _prefix_digest(sink: EventSink) -> str:
    prefix_mechanisms = {
        "canonical_application",
        "coarse_score_channel",
        "score_token",
        "feature_provenance",
        "feature_coverage",
        "policy_snapshot",
        "coarse_credit_policy_channel",
        "credit_policy_state_token",
    }
    normalized: list[dict[str, Any]] = []
    for event in sink.events:
        if event.mechanism not in prefix_mechanisms:
            continue
        item = event.as_dict()
        for volatile in {
            "event_id",
            "captured_ns",
            "previous_hash",
            "event_hash",
            "signature",
            "capture_latency_ms",
        }:
            item.pop(volatile, None)
        item["run_id"] = "<normalized-run>"
        normalized.append(item)
    return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()


class CreditReplayHarness:
    def __init__(self, enabled_mechanisms: set[str]) -> None:
        self.enabled_mechanisms = set(enabled_mechanisms)
        self.graph = build_credit_graph()

    def run(
        self,
        scenario: dict[str, Any],
        *,
        target: str = "remove_income_feature",
    ) -> tuple[CreditReplayOutcome, dict[str, Any], EventSink, tuple[EventSink, ...]]:
        mechanism = _credit_spec().mechanisms["virtualized_income_ablation"]
        replay = mechanism.replay
        assert replay is not None
        if target != replay.target:
            return (
                CreditReplayOutcome(
                    feasible=False,
                    target=target,
                    trials=0,
                    original_decision=None,
                    replay_decisions=(),
                    denial_without_income_feature=None,
                    outcome_flip=None,
                    prefix_equal=None,
                    verifier_passed=False,
                    reason="unsupported_intervention_target",
                ),
                {},
                EventSink(set()),
                (),
            )

        with tempfile.TemporaryDirectory(prefix="auditspec-credit-replay-") as temporary:
            root = Path(temporary)
            original_db = root / "original.sqlite"
            _initialize(original_db)
            original_scenario = dict(scenario)
            original_scenario.setdefault("run_id", "credit-original")
            original, original_sink = run_credit_fixture(
                original_scenario,
                db_path=original_db,
                enabled_mechanisms=self.enabled_mechanisms,
                graph=self.graph,
            )

            replay_decisions: list[str] = []
            replay_sinks: list[EventSink] = []
            prefix_equal = True
            original_prefix = _prefix_digest(original_sink)
            for trial in range(replay.min_trials):
                trial_db = root / f"trial-{trial}.sqlite"
                _initialize(trial_db)
                replay_scenario = dict(original_scenario)
                replay_scenario.update(
                    {
                        "run_id": f"{original_scenario['run_id']}-ablation-{trial}",
                        "ablation_mode": True,
                    }
                )
                replay_result, replay_sink = run_credit_fixture(
                    replay_scenario,
                    db_path=trial_db,
                    enabled_mechanisms=self.enabled_mechanisms,
                    graph=self.graph,
                )
                replay_decisions.append(str(replay_result["human_decision"]))
                replay_sinks.append(replay_sink)
                prefix_equal = prefix_equal and _prefix_digest(replay_sink) == original_prefix

            denial_without = all(decision == "deny" for decision in replay_decisions)
            outcome_flip = original["human_decision"] == "deny" and not denial_without
            consistent = len(set(replay_decisions)) == 1
            verifier_passed = bool(prefix_equal and consistent and len(replay_decisions) >= replay.min_trials)
            outcome = CreditReplayOutcome(
                feasible=True,
                target=target,
                trials=len(replay_decisions),
                original_decision=str(original["human_decision"]),
                replay_decisions=tuple(replay_decisions),
                denial_without_income_feature=denial_without,
                outcome_flip=outcome_flip,
                prefix_equal=prefix_equal,
                verifier_passed=verifier_passed,
            )
            policy_version = {
                "threshold": original["policy_threshold"],
                "effective": original["policy_effective"],
            }
            replay_captures = {
                "model_output": nondeterminism_capture(
                    "model_output",
                    original["model_decision"],
                    replay_decisions,
                    mode="intervened",
                ),
                "policy_version": nondeterminism_capture(
                    "policy_version",
                    policy_version,
                    [policy_version for _ in replay_decisions],
                    mode="frozen",
                ),
            }
            emit_mechanism_event(
                original_sink,
                _credit_spec(),
                "virtualized_income_ablation",
                runtime_world(original, denial_without),
                run_id=original["run_id"],
                action_id=original["application_id"],
                attributes={
                    **outcome.as_dict(),
                    "replay_proof": build_replay_proof(
                        replay,
                        adapter_id="feature-ablation",
                        captures=replay_captures,
                        trials=len(replay_decisions),
                        prefix_equal=prefix_equal,
                        verifier_passed=verifier_passed,
                    ),
                },
            )
            valid, errors = original_sink.verify()
            if not valid:
                raise RuntimeError(f"Credit replay evidence chain invalid: {errors}")
            return outcome, original, original_sink, tuple(replay_sinks)
