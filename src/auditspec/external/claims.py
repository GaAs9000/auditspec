"""Benchmark-native Boolean oracle registry for the v0.6 evaluation.

The registry does not reinterpret a benchmark policy or task. Each entry is
bound to one check produced by a pinned official evaluator, or to a closed
integrity predicate over the official native trajectory. Adapters are the only
components allowed to create these oracle checks.
"""

from __future__ import annotations

from dataclasses import dataclass

from .record import NormalizedRunRecord


@dataclass(frozen=True)
class ClaimEvaluation:
    claim_id: str
    applicable: bool
    value: bool
    statement: str
    source: str
    violating_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "claim_id": self.claim_id,
            "applicable": self.applicable,
            "value": self.value,
            "statement": self.statement,
            "source": self.source,
            "violating_ids": list(self.violating_ids),
        }


@dataclass(frozen=True)
class ClaimDefinition:
    claim_id: str
    environment: str
    statement_template: str
    oracle_check_id: str
    oracle_source: str

    def evaluate(self, record: NormalizedRunRecord) -> ClaimEvaluation:
        record.validate()
        if record.environment != self.environment:
            raise ValueError(
                f"claim {self.claim_id} expects {self.environment}, got {record.environment}"
            )
        try:
            check = record.oracle_check_by_id()[self.oracle_check_id]
        except KeyError as exc:
            raise ValueError(
                f"record {record.run_id} is missing oracle check {self.oracle_check_id}"
            ) from exc
        if check.source != self.oracle_source:
            raise ValueError(
                f"claim {self.claim_id} expects source {self.oracle_source}, "
                f"got {check.source}"
            )
        return ClaimEvaluation(
            claim_id=self.claim_id,
            applicable=check.applicable,
            value=check.value,
            statement=check.statement,
            source=check.source,
            violating_ids=tuple(sorted(set(check.violating_ids))),
        )


def _definition(
    claim_id: str,
    environment: str,
    statement: str,
    check_id: str,
    source: str,
) -> ClaimDefinition:
    return ClaimDefinition(claim_id, environment, statement, check_id, source)


TAU_EVALUATOR = "tau2-official-evaluator"
TAU_TRAJECTORY = "tau2-native-trajectory"
APPWORLD_EVALUATOR = "appworld-official-evaluator"


CLAIM_REGISTRY = {
    item.claim_id: item
    for item in (
        _definition(
            "T01",
            "tau2",
            "The official aggregate task reward is successful.",
            "official_task_success",
            TAU_EVALUATOR,
        ),
        _definition(
            "T02",
            "tau2",
            "The official target database end state matches.",
            "official_db_match",
            TAU_EVALUATOR,
        ),
        _definition(
            "T03",
            "tau2",
            "Every declared official environment assertion is met.",
            "all_env_assertions",
            TAU_EVALUATOR,
        ),
        _definition(
            "T04",
            "tau2",
            "Official environment-assertion slot 1 is met.",
            "env_assertion_slot_1",
            TAU_EVALUATOR,
        ),
        _definition(
            "T05",
            "tau2",
            "Official environment-assertion slot 2 is met.",
            "env_assertion_slot_2",
            TAU_EVALUATOR,
        ),
        _definition(
            "T06",
            "tau2",
            "Official environment-assertion slot 3 is met.",
            "env_assertion_slot_3",
            TAU_EVALUATOR,
        ),
        _definition(
            "T07",
            "tau2",
            "No agent-requested tool result is marked as an error.",
            "no_agent_tool_errors",
            TAU_TRAJECTORY,
        ),
        _definition(
            "T08",
            "tau2",
            "Agent tool calls and results form a one-to-one ID binding.",
            "agent_call_result_bijection",
            TAU_TRAJECTORY,
        ),
        _definition(
            "T09",
            "tau2",
            "Agent tool-call identifiers are non-empty and unique.",
            "unique_nonempty_agent_call_ids",
            TAU_TRAJECTORY,
        ),
        _definition(
            "T10",
            "tau2",
            "The simulation ended by an explicit agent or user stop.",
            "explicit_stop_termination",
            TAU_TRAJECTORY,
        ),
        _definition(
            "A01",
            "appworld",
            "Every official state-based task requirement is met.",
            "official_task_success",
            APPWORLD_EVALUATOR,
        ),
        _definition(
            "A02",
            "appworld",
            "Every official goal requirement is met.",
            "all_no_op_fail_requirements",
            APPWORLD_EVALUATOR,
        ),
        _definition(
            "A03",
            "appworld",
            "Every official state-preservation requirement is met.",
            "all_no_op_pass_requirements",
            APPWORLD_EVALUATOR,
        ),
        *(
            _definition(
                f"A{slot + 3:02d}",
                "appworld",
                f"Official task-specific requirement slot {slot} is met.",
                f"requirement_slot_{slot}",
                APPWORLD_EVALUATOR,
            )
            for slot in range(1, 8)
        ),
    )
}


def evaluate_claim(claim_id: str, record: NormalizedRunRecord) -> ClaimEvaluation:
    """Evaluate one registered claim against its benchmark-native oracle check."""

    try:
        definition = CLAIM_REGISTRY[claim_id]
    except KeyError as exc:
        raise KeyError(f"unknown external claim: {claim_id}") from exc
    return definition.evaluate(record)
