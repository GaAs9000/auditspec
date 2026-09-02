from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import emit_mechanism_event
from .events import EventSink, canonical_json
from .payment_graph import (
    _payment_spec,
    build_payment_graph,
    run_payment_fixture,
    runtime_world,
)
from .replay_proof import build_replay_proof, nondeterminism_capture


@dataclass(frozen=True)
class ReplayOutcome:
    feasible: bool
    target: str
    side_effect_mode: str
    original_commit_count: int | None
    replay_commit_count: int | None
    duplicate_without_tool_response: bool | None
    outcome_flip: bool | None
    prefix_equal: bool | None
    verifier_passed: bool
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _empty_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, action_id TEXT NOT NULL, amount INTEGER NOT NULL, route TEXT NOT NULL)"
        )
        connection.commit()


def _snapshot_database(source: Path, destination: Path) -> None:
    with sqlite3.connect(source) as src, sqlite3.connect(destination) as dst:
        src.backup(dst)


def _prefix_digest(sink: EventSink) -> str:
    prefix = [
        event.as_dict()
        for event in sink.events
        if event.mechanism not in {
            "gateway_coverage",
            "durable_effect_receipt",
            "final_output",
        }
        and not (
            event.mechanism == "generic_agent_trace"
            and event.attributes.get("node") == "report"
        )
    ]
    normalized = []
    for event in prefix:
        event = dict(event)
        for volatile in {
            "event_id",
            "captured_ns",
            "previous_hash",
            "event_hash",
            "signature",
            "capture_latency_ms",
        }:
            event.pop(volatile, None)
        # A replay is a distinct run of the same canonical action. Sequence,
        # mechanism, producer, capture point, action_id and attributes must
        # remain equal; only the envelope's run label may change.
        event["run_id"] = "<normalized-run>"
        normalized.append(event)
    return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()


class PaymentReplayHarness:
    def __init__(self, enabled_mechanisms: set[str]) -> None:
        self.enabled_mechanisms = set(enabled_mechanisms)
        self.graph = build_payment_graph()

    def run(
        self,
        scenario: dict[str, Any],
        *,
        target: str = "omit_tool_response",
        side_effect_mode: str = "virtualized",
    ) -> tuple[ReplayOutcome, dict[str, Any], EventSink, EventSink | None]:
        if target != "omit_tool_response":
            outcome = ReplayOutcome(
                feasible=False,
                target=target,
                side_effect_mode=side_effect_mode,
                original_commit_count=None,
                replay_commit_count=None,
                duplicate_without_tool_response=None,
                outcome_flip=None,
                prefix_equal=None,
                verifier_passed=False,
                reason="unsupported_intervention_target",
            )
            return outcome, {}, EventSink(set()), None
        if side_effect_mode == "irreversible":
            outcome = ReplayOutcome(
                feasible=False,
                target=target,
                side_effect_mode=side_effect_mode,
                original_commit_count=None,
                replay_commit_count=None,
                duplicate_without_tool_response=None,
                outcome_flip=None,
                prefix_equal=None,
                verifier_passed=False,
                reason="irreversible_side_effect",
            )
            return outcome, {}, EventSink(set()), None
        if side_effect_mode not in {"virtualized", "read_only"}:
            outcome = ReplayOutcome(
                feasible=False,
                target=target,
                side_effect_mode=side_effect_mode,
                original_commit_count=None,
                replay_commit_count=None,
                duplicate_without_tool_response=None,
                outcome_flip=None,
                prefix_equal=None,
                verifier_passed=False,
                reason="unsupported_side_effect_mode",
            )
            return outcome, {}, EventSink(set()), None

        with tempfile.TemporaryDirectory(prefix="auditspec-replay-") as temporary:
            root = Path(temporary)
            baseline = root / "baseline.sqlite"
            original_db = root / "original.sqlite"
            replay_db = root / "replay.sqlite"
            _empty_database(baseline)
            _snapshot_database(baseline, original_db)
            _snapshot_database(baseline, replay_db)

            original_scenario = dict(scenario)
            original_scenario.setdefault("run_id", "original")
            original_result, original_sink = run_payment_fixture(
                original_scenario,
                db_path=original_db,
                enabled_mechanisms=self.enabled_mechanisms,
                graph=self.graph,
            )

            replay_scenario = dict(original_scenario)
            replay_scenario["run_id"] = f"{original_scenario['run_id']}-replay"
            replay_scenario["tool_response"] = "timeout"
            replay_result, replay_sink = run_payment_fixture(
                replay_scenario,
                db_path=replay_db,
                enabled_mechanisms=self.enabled_mechanisms,
                graph=self.graph,
            )

            original_count = int(original_result["ledger_commit_count"])
            replay_count = int(replay_result["ledger_commit_count"])
            duplicate_without = replay_count == 2
            outcome_flip = (original_count == 2) and (replay_count != 2)
            prefix_equal = _prefix_digest(original_sink) == _prefix_digest(replay_sink)
            verifier_passed = bool(prefix_equal and original_count == 2)
            outcome = ReplayOutcome(
                feasible=True,
                target=target,
                side_effect_mode=side_effect_mode,
                original_commit_count=original_count,
                replay_commit_count=replay_count,
                duplicate_without_tool_response=duplicate_without,
                outcome_flip=outcome_flip,
                prefix_equal=prefix_equal,
                verifier_passed=verifier_passed,
            )
            replay_contract = _payment_spec().mechanisms[
                "virtualized_tool_omission_replay"
            ].replay
            assert replay_contract is not None
            replay_captures = {
                "agent_decision": nondeterminism_capture(
                    "agent_decision",
                    {
                        "model_recommendation": original_result["model_recommendation"],
                        "human_decision": original_result["human_decision"],
                        "planner_seed": original_result["planner_seed"],
                    },
                    [
                        {
                            "model_recommendation": replay_result["model_recommendation"],
                            "human_decision": replay_result["human_decision"],
                            "planner_seed": replay_result["planner_seed"],
                        }
                    ],
                    mode="frozen",
                ),
                "tool_response": nondeterminism_capture(
                    "tool_response",
                    original_result["tool_response"],
                    [replay_result["tool_response"]],
                    mode="intervened",
                ),
                "clock": nondeterminism_capture(
                    "clock", None, [None], mode="proved_unused"
                ),
            }
            emit_mechanism_event(
                original_sink,
                _payment_spec(),
                "virtualized_tool_omission_replay",
                runtime_world(original_result, duplicate_without),
                run_id=original_result["run_id"],
                action_id=original_result["action_id"],
                attributes={
                    **outcome.as_dict(),
                    "replay_proof": build_replay_proof(
                        replay_contract,
                        adapter_id="sqlite-counterfactual-replay",
                        captures=replay_captures,
                        trials=1,
                        prefix_equal=bool(prefix_equal),
                        verifier_passed=verifier_passed,
                    ),
                },
            )
            valid, errors = original_sink.verify()
            if not valid:
                raise RuntimeError(f"Replay evidence chain invalid: {errors}")
            return outcome, original_result, original_sink, replay_sink
