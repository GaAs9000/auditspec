"""Runtime fixtures and evidence adapters used by the AuditSpec artifact."""

from .events import AuditEvent, EventSink

__all__ = [
    "AuditEvent",
    "EventSink",
    "PolicyRoot",
    "RunEvidenceVerificationResult",
    "RunTrustContext",
    "build_fixture_trust_context",
    "verify_run_evidence",
    "PaymentReplayHarness",
    "ReplayOutcome",
    "build_payment_graph",
    "run_payment_fixture",
    "CreditReplayHarness",
    "CreditReplayOutcome",
    "build_credit_graph",
    "run_credit_fixture",
]


def __getattr__(name: str):
    if name in {
        "PolicyRoot",
        "RunEvidenceVerificationResult",
        "RunTrustContext",
        "build_fixture_trust_context",
        "verify_run_evidence",
    }:
        from .run_verification import (
            PolicyRoot,
            RunEvidenceVerificationResult,
            RunTrustContext,
            build_fixture_trust_context,
            verify_run_evidence,
        )

        return {
            "PolicyRoot": PolicyRoot,
            "RunEvidenceVerificationResult": RunEvidenceVerificationResult,
            "RunTrustContext": RunTrustContext,
            "build_fixture_trust_context": build_fixture_trust_context,
            "verify_run_evidence": verify_run_evidence,
        }[name]
    if name in {"build_payment_graph", "run_payment_fixture"}:
        from .payment_graph import build_payment_graph, run_payment_fixture

        return {
            "build_payment_graph": build_payment_graph,
            "run_payment_fixture": run_payment_fixture,
        }[name]
    if name in {"PaymentReplayHarness", "ReplayOutcome"}:
        from .replay import PaymentReplayHarness, ReplayOutcome

        return {
            "PaymentReplayHarness": PaymentReplayHarness,
            "ReplayOutcome": ReplayOutcome,
        }[name]
    if name in {"build_credit_graph", "run_credit_fixture"}:
        from .credit_graph import build_credit_graph, run_credit_fixture

        return {
            "build_credit_graph": build_credit_graph,
            "run_credit_fixture": run_credit_fixture,
        }[name]
    if name in {"CreditReplayHarness", "CreditReplayOutcome"}:
        from .credit_replay import CreditReplayHarness, CreditReplayOutcome

        return {
            "CreditReplayHarness": CreditReplayHarness,
            "CreditReplayOutcome": CreditReplayOutcome,
        }[name]
    raise AttributeError(name)
