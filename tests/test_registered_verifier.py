from __future__ import annotations

from dataclasses import replace

import pytest

from auditspec.verifier_registry import (
    RegisteredVerifierInvocation,
    VerifierExecutionStatus,
    execute_registered_verifier,
    make_registered_verifier_invocation,
)


def invocation(**changes):
    payload = changes.pop("payload", {"checks": [True, True, True]})
    value = make_registered_verifier_invocation(
        verifier_id="auditspec-all-boolean-checks-v1",
        claim_id="T01",
        replay_id="replay-1",
        input_payload=payload,
        fuel=3,
    )
    return replace(value, **changes)


def test_registered_verifier_really_executes() -> None:
    value = invocation()
    assert (
        RegisteredVerifierInvocation.from_dict(value.as_dict()).as_dict()
        == value.as_dict()
    )
    result = execute_registered_verifier(value, {"checks": [True, True, True]})
    assert result.status is VerifierExecutionStatus.EXECUTED
    assert result.executed and result.accepted
    assert result.answer is True
    assert result.steps == 3
    assert not hasattr(value, "input_payload")
    raw = value.as_dict()
    raw["extra"] = True
    with pytest.raises(ValueError, match="closed schema"):
        RegisteredVerifierInvocation.from_dict(raw)


def test_registered_verifier_recomputes_false_answer() -> None:
    payload = {"checks": [True, False]}
    result = execute_registered_verifier(invocation(payload=payload), payload)
    assert result.executed
    assert result.answer is False


def test_registered_verifier_rejects_digest_and_unknown_registry_entries() -> None:
    assert not execute_registered_verifier(
        invocation(verifier_manifest_digest="0" * 64),
        {"checks": [True, True, True]},
    ).executed
    unknown = RegisteredVerifierInvocation(
        verifier_id="unknown-verifier",
        verifier_version="1.0.0",
        verifier_manifest_digest="0" * 64,
        registry_digest=invocation().registry_digest,
        claim_id="T01",
        replay_id="replay-1",
        input_schema="unknown",
        input_extractor_id="retained-witness-checks-v1",
        input_payload_digest="0" * 64,
        fuel=1,
    )
    result = execute_registered_verifier(unknown, {"checks": []})
    assert result.status is VerifierExecutionStatus.REJECTED
    assert "verifier:unregistered" in result.errors


def test_registered_verifier_fuel_exhaustion_and_exception_fail_closed() -> None:
    payload = {"checks": [True, True, True]}
    exhausted = execute_registered_verifier(
        invocation(payload=payload, fuel=2), payload
    )
    assert exhausted.status is VerifierExecutionStatus.FUEL_EXHAUSTED
    raising = make_registered_verifier_invocation(
        verifier_id="auditspec-raising-verifier-v1",
        claim_id="T01",
        replay_id="replay-1",
        input_payload={"checks": []},
        fuel=1,
    )
    errored = execute_registered_verifier(raising, {"checks": []})
    assert errored.status is VerifierExecutionStatus.ERROR
    assert not errored.accepted


def test_registered_verifier_rejects_input_above_registry_bound() -> None:
    oversized = {"checks": [True] * 4097}
    with pytest.raises(ValueError, match="input exceeds the registered item bound"):
        make_registered_verifier_invocation(
            verifier_id="auditspec-all-boolean-checks-v1",
            claim_id="T01",
            replay_id="replay-1",
            input_payload=oversized,
            fuel=0,
        )
    result = execute_registered_verifier(invocation(fuel=0), oversized)
    assert result.status is VerifierExecutionStatus.REJECTED
    assert result.steps == 0
    assert "input exceeds the registered item bound" in result.errors[0]


def test_boolean_verifier_rejects_vacuous_empty_check_set() -> None:
    with pytest.raises(ValueError, match="below the registered item minimum"):
        make_registered_verifier_invocation(
            verifier_id="auditspec-all-boolean-checks-v1",
            claim_id="T01",
            replay_id="replay-1",
            input_payload={"checks": []},
            fuel=0,
        )
