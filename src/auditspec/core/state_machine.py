"""Pure claim-lifecycle transition engine for the design-time slice."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LifecycleState(StrEnum):
    DECLARED = "DECLARED"
    SCOPED = "SCOPED"
    MODEL_VALIDATED = "MODEL_VALIDATED"
    SYNTHESIZED = "SYNTHESIZED"
    PLANNED = "PLANNED"
    CERTIFIED = "CERTIFIED"
    INSTALLED = "INSTALLED"
    PREFLIGHT_PASSED = "PREFLIGHT_PASSED"
    CAPTURING = "CAPTURING"
    RUN_CLOSED = "RUN_CLOSED"
    VERIFIED_AT_CAPTURE = "VERIFIED_AT_CAPTURE"
    ARCHIVED = "ARCHIVED"
    REVERIFIED_AT_AUDIT_TIME = "REVERIFIED_AT_AUDIT_TIME"
    INTERVENTION_REQUIRED = "INTERVENTION_REQUIRED"
    INTERVENTION_PLANNED = "INTERVENTION_PLANNED"
    INTERVENTION_EXECUTED = "INTERVENTION_EXECUTED"


class TransitionOutcome(StrEnum):
    PASS = "PASS"
    TYPED_FAIL = "TYPED_FAIL"
    LIMIT_REACHED = "LIMIT_REACHED"


PASSIVE_EDGES = {
    (LifecycleState.DECLARED, LifecycleState.SCOPED),
    (LifecycleState.SCOPED, LifecycleState.MODEL_VALIDATED),
    (LifecycleState.MODEL_VALIDATED, LifecycleState.SYNTHESIZED),
    (LifecycleState.SYNTHESIZED, LifecycleState.PLANNED),
    (LifecycleState.PLANNED, LifecycleState.CERTIFIED),
    (LifecycleState.CERTIFIED, LifecycleState.INSTALLED),
    (LifecycleState.INSTALLED, LifecycleState.PREFLIGHT_PASSED),
    (LifecycleState.PREFLIGHT_PASSED, LifecycleState.CAPTURING),
    (LifecycleState.CAPTURING, LifecycleState.RUN_CLOSED),
    (LifecycleState.RUN_CLOSED, LifecycleState.VERIFIED_AT_CAPTURE),
    (LifecycleState.VERIFIED_AT_CAPTURE, LifecycleState.ARCHIVED),
    (LifecycleState.ARCHIVED, LifecycleState.REVERIFIED_AT_AUDIT_TIME),
    (LifecycleState.REVERIFIED_AT_AUDIT_TIME, LifecycleState.REVERIFIED_AT_AUDIT_TIME),
}
CAUSAL_EDGES = {
    (LifecycleState.SYNTHESIZED, LifecycleState.INTERVENTION_REQUIRED),
    (LifecycleState.INTERVENTION_REQUIRED, LifecycleState.INTERVENTION_PLANNED),
    (LifecycleState.INTERVENTION_PLANNED, LifecycleState.PLANNED),
    (LifecycleState.CAPTURING, LifecycleState.INTERVENTION_EXECUTED),
    (LifecycleState.INTERVENTION_EXECUTED, LifecycleState.RUN_CLOSED),
}
ALLOWED_EDGES = PASSIVE_EDGES | CAUSAL_EDGES


@dataclass(frozen=True)
class DesignTransition:
    sequence: int
    from_state: LifecycleState
    attempted_to_state: LifecycleState
    resulting_state: LifecycleState
    obligation_checked: str | None
    outcome: TransitionOutcome
    verdict_on_fail: str | None = None
    failure_subtype: str | None = None

    def to_wire(self) -> dict[str, object]:
        return {
            "schema": "AuditSpec-core-phase1-design-transition-v1",
            "sequence": self.sequence,
            "from_state": str(self.from_state),
            "attempted_to_state": str(self.attempted_to_state),
            "resulting_state": str(self.resulting_state),
            "obligation_checked": self.obligation_checked,
            "outcome": str(self.outcome),
            "verdict_on_fail": self.verdict_on_fail,
            "failure_subtype": self.failure_subtype,
            "authenticated_state_transition_record": False,
        }


class DesignLifecycle:
    """Checks Core edges without pretending to issue authenticated records."""

    def __init__(self) -> None:
        self.state = LifecycleState.DECLARED
        self.transitions: list[DesignTransition] = []

    def attempt(
        self,
        target: LifecycleState,
        *,
        obligation: str | None,
        outcome: TransitionOutcome,
        verdict_on_fail: str | None = None,
        failure_subtype: str | None = None,
    ) -> DesignTransition:
        edge = (self.state, target)
        if edge not in ALLOWED_EDGES:
            raise ValueError(f"illegal lifecycle edge: {self.state}->{target}")
        if outcome == TransitionOutcome.PASS:
            if verdict_on_fail is not None or failure_subtype is not None:
                raise ValueError("passing transition cannot carry a failure")
            resulting = target
        else:
            if verdict_on_fail is None:
                raise ValueError("failed/limited transition needs a verdict")
            resulting = self.state
        record = DesignTransition(
            len(self.transitions),
            self.state,
            target,
            resulting,
            obligation,
            outcome,
            verdict_on_fail,
            failure_subtype,
        )
        self.transitions.append(record)
        self.state = resulting
        return record
