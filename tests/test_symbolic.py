from __future__ import annotations

from pathlib import Path

from auditspec.compiler import AuditCompiler
from auditspec.spec import load_spec
from auditspec.symbolic import (
    SymbolicDeterminacyChecker,
    SymbolicDomain,
    SymbolicProblem,
    problem_from_spec,
)


ROOT = Path(__file__).resolve().parents[1]


def test_symbolic_backend_proves_large_interval_determinacy() -> None:
    problem = SymbolicProblem(
        name="large-payment",
        variables={
            "amount": SymbolicDomain("int", lower=0, upper=1_000_000_000),
            "policy_limit": SymbolicDomain("int", lower=0, upper=1_000_000_000),
            "approval_valid": SymbolicDomain("bool"),
            "event_time": SymbolicDomain("int", lower=0, upper=1_000_000_000_000),
            "valid_from": SymbolicDomain("int", lower=0, upper=1_000_000_000_000),
            "valid_to": SymbolicDomain("int", lower=0, upper=1_000_000_000_000),
        },
        constraints=("valid_from <= valid_to",),
        query=(
            "approval_valid and amount <= policy_limit and "
            "valid_from <= event_time and event_time <= valid_to"
        ),
        observations=(
            "amount",
            "policy_limit",
            "approval_valid",
            "event_time",
            "valid_from",
            "valid_to",
        ),
    )
    result = SymbolicDeterminacyChecker(problem).check()
    assert result.status == "UNSAT_DETERMINATE"
    assert result.determinate is True


def test_symbolic_backend_returns_independently_verifiable_twin() -> None:
    problem = SymbolicProblem(
        name="missing-policy-limit",
        variables={
            "amount": SymbolicDomain("int", lower=0, upper=1_000_000_000),
            "policy_limit": SymbolicDomain("int", lower=0, upper=1_000_000_000),
            "approval_valid": SymbolicDomain("bool"),
        },
        constraints=(),
        query="approval_valid and amount <= policy_limit",
        observations=("amount", "approval_valid"),
    )
    checker = SymbolicDeterminacyChecker(problem)
    result = checker.check()
    assert result.status == "SAT_TWIN"
    assert result.certificate is not None
    assert checker.verify_certificate(result.certificate) is True


def test_symbolic_adapter_matches_enumerator_on_payment_contracts() -> None:
    spec = load_spec(ROOT / "examples" / "payment.yaml")
    compiler = AuditCompiler(spec)
    sufficient = ["canonical_action", "approval_bound_receipt", "delegation_context"]
    insufficient = ["canonical_action"]
    for contract in (sufficient, insufficient):
        finite = compiler.check_contract("transfer_authorized", contract)
        symbolic = SymbolicDeterminacyChecker(
            problem_from_spec(spec, "transfer_authorized", contract)
        ).check()
        assert symbolic.determinate is (finite.certificate is None)
