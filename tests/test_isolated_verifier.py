from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_assurance_gate import CLAIM_ID, make_config

from auditspec.assurance import ISOLATED_REEXECUTION_PROFILE, run_exact_assurance_gate
from auditspec.isolated_verifier import (
    ISOLATED_VERIFIERS,
    IsolatedExecutionStatus,
    IsolationLimits,
    execute_isolated_verifier,
    extract_isolated_input,
    make_isolated_invocation,
    make_isolation_policy,
    verify_isolated_execution_receipt,
)


def _limits(**changes) -> IsolationLimits:
    values = {
        "cpu_seconds": 2,
        "address_space_bytes": 512 * 1024 * 1024,
        "file_size_bytes": 1024 * 1024,
        "open_files": 64,
        "process_count": 16,
        "wall_clock_seconds": 4.0,
        "stderr_bytes": 65536,
    }
    values.update(changes)
    return IsolationLimits(**values)


def _policy(*, limits: IsolationLimits | None = None):
    return make_isolation_policy(
        backend="subprocess",
        python_path=Path(sys.executable),
        limits=limits or _limits(),
    )


def _invocation(verifier_id: str, payload: dict, *, fuel: int = 4):
    return make_isolated_invocation(
        verifier_id=verifier_id,
        claim_id="T01",
        replay_id="isolated-replay",
        input_payload=payload,
        fuel=fuel,
    )


def test_isolated_boolean_verifier_executes_in_subprocess() -> None:
    payload = {"checks": [True, True, True]}
    invocation = _invocation(
        "auditspec-all-boolean-checks-isolated-v1", payload, fuel=3
    )
    policy = _policy()
    receipt = execute_isolated_verifier(invocation, payload, policy)
    assert receipt.status is IsolatedExecutionStatus.EXECUTED
    assert receipt.executed and receipt.answer is True and receipt.steps == 3
    assert verify_isolated_execution_receipt(
        receipt, invocation=invocation, policy=policy
    )


def test_isolated_boolean_input_is_derived_from_retained_witness() -> None:
    payload = {"checks": [True, False]}
    invocation = _invocation(
        "auditspec-all-boolean-checks-isolated-v1", payload, fuel=2
    )
    evidence = {
        "verification_witness": {"evidence_components": {"checks": [True, False]}}
    }
    assert extract_isolated_input(invocation, evidence) == payload
    with pytest.raises(ValueError, match="derived input digest mismatch"):
        extract_isolated_input(
            invocation,
            {"verification_witness": {"evidence_components": {"checks": [True, True]}}},
        )


def test_isolated_worker_and_request_digests_are_load_bearing() -> None:
    payload = {"checks": [True]}
    invocation = _invocation(
        "auditspec-all-boolean-checks-isolated-v1", payload, fuel=1
    )
    policy = _policy()
    bad_policy = replace(policy, worker_sha256="0" * 64)
    receipt = execute_isolated_verifier(invocation, payload, bad_policy)
    assert receipt.status is IsolatedExecutionStatus.REJECTED
    assert "isolated_worker_source_digest:mismatch" in receipt.errors
    bad_payload = {"checks": [False]}
    receipt = execute_isolated_verifier(invocation, bad_payload, policy)
    assert receipt.status is IsolatedExecutionStatus.REJECTED
    assert "isolated_input_payload_digest:mismatch" in receipt.errors


def test_isolation_policy_preserves_lexical_and_resolved_mount_paths(
    tmp_path: Path,
) -> None:
    target = tmp_path / "runtime-target"
    target.mkdir()
    lexical = tmp_path / "runtime-link"
    lexical.symlink_to(target, target_is_directory=True)
    policy = make_isolation_policy(
        backend="subprocess",
        python_path=Path(sys.executable),
        readonly_paths=(lexical,),
        limits=_limits(),
    )
    assert str(lexical.absolute()) in policy.readonly_paths
    assert str(target.resolve()) in policy.readonly_paths


def test_isolation_policy_removes_redundant_descendant_mounts(tmp_path: Path) -> None:
    parent = tmp_path / "runtime"
    parent.mkdir()
    child = parent / "worker-data.json"
    child.write_text("{}\n", encoding="utf-8")
    policy = make_isolation_policy(
        backend="subprocess",
        python_path=Path(sys.executable),
        readonly_paths=(parent, child),
        limits=_limits(),
    )
    assert str(parent.resolve()) in policy.readonly_paths
    assert str(child.resolve()) not in policy.readonly_paths


def test_isolation_policy_retains_explicit_intermediate_python_alias(
    tmp_path: Path,
) -> None:
    versioned = tmp_path / "cpython-3.12.14" / "bin"
    versioned.mkdir(parents=True)
    binary = versioned / "python3.12"
    binary.write_bytes(b"fixture-python")
    alias_root = tmp_path / "cpython-3.12"
    alias_root.symlink_to(versioned.parent, target_is_directory=True)
    explicit_target = alias_root / "bin/python3.12"
    venv_bin = tmp_path / "venv/bin"
    venv_bin.mkdir(parents=True)
    python_ref = venv_bin / "python"
    python_ref.symlink_to(explicit_target)
    policy = make_isolation_policy(
        backend="subprocess",
        python_path=python_ref,
        readonly_paths=(venv_bin.parent,),
        limits=_limits(),
    )
    assert str(alias_root.absolute()) in policy.readonly_paths
    assert str(versioned.parent.resolve()) in policy.readonly_paths
    assert str(explicit_target.absolute()) not in policy.readonly_paths
    assert str(binary.resolve()) not in policy.readonly_paths


def test_isolated_timeout_and_cpu_limit_fail_closed() -> None:
    sleep_payload = {"seconds": 2}
    sleep = _invocation("auditspec-isolation-sleep-test-v1", sleep_payload, fuel=1)
    receipt = execute_isolated_verifier(
        sleep,
        sleep_payload,
        _policy(limits=_limits(wall_clock_seconds=0.1)),
    )
    assert receipt.status is IsolatedExecutionStatus.TIMEOUT

    cpu = _invocation("auditspec-isolation-cpu-test-v1", {}, fuel=1)
    receipt = execute_isolated_verifier(
        cpu,
        {},
        _policy(limits=_limits(cpu_seconds=1, wall_clock_seconds=3.0)),
    )
    assert receipt.status in {
        IsolatedExecutionStatus.RESOURCE_LIMIT,
        IsolatedExecutionStatus.ERROR,
        IsolatedExecutionStatus.TIMEOUT,
    }
    assert not receipt.executed


def test_isolated_memory_and_output_limits_fail_closed() -> None:
    memory = _invocation("auditspec-isolation-memory-test-v1", {}, fuel=1)
    receipt = execute_isolated_verifier(
        memory,
        {},
        _policy(
            limits=_limits(
                address_space_bytes=192 * 1024 * 1024,
                wall_clock_seconds=3.0,
            )
        ),
    )
    assert receipt.status in {
        IsolatedExecutionStatus.RESOURCE_LIMIT,
        IsolatedExecutionStatus.ERROR,
        IsolatedExecutionStatus.TIMEOUT,
    }
    assert not receipt.executed

    output_payload = {"bytes": 1024 * 1024}
    output = _invocation("auditspec-isolation-output-test-v1", output_payload, fuel=1)
    receipt = execute_isolated_verifier(
        output,
        output_payload,
        _policy(limits=_limits(file_size_bytes=4096)),
    )
    assert receipt.status in {
        IsolatedExecutionStatus.RESOURCE_LIMIT,
        IsolatedExecutionStatus.ERROR,
    }
    assert not receipt.executed


def test_isolated_invalid_json_and_nonzero_exit_fail_closed() -> None:
    invalid = _invocation("auditspec-isolation-invalid-json-test-v1", {}, fuel=1)
    receipt = execute_isolated_verifier(invalid, {}, _policy())
    assert receipt.status is IsolatedExecutionStatus.ERROR
    assert receipt.errors[0].startswith("isolated_process:invalid_result")

    nonzero = _invocation("auditspec-isolation-nonzero-test-v1", {}, fuel=1)
    receipt = execute_isolated_verifier(nonzero, {}, _policy())
    assert receipt.status is IsolatedExecutionStatus.ERROR
    assert "isolated_process:return_code:17" in receipt.errors


def test_isolated_receipt_tamper_and_registry_shape_are_rejected() -> None:
    payload = {"checks": [True]}
    invocation = _invocation(
        "auditspec-all-boolean-checks-isolated-v1", payload, fuel=1
    )
    policy = _policy()
    receipt = execute_isolated_verifier(invocation, payload, policy)
    assert receipt.executed
    assert not verify_isolated_execution_receipt(
        replace(receipt, invocation_digest="0" * 64),
        invocation=invocation,
        policy=policy,
    )
    for manifest in ISOLATED_VERIFIERS.values():
        raw = manifest.as_dict()
        assert "callback" not in raw
        assert "import_path" not in raw
        assert set(raw) == {
            "verifier_id",
            "version",
            "input_schema",
            "min_items",
            "max_items",
            "max_fuel",
            "input_extractor_id",
            "worker_behavior",
            "worker_source_digest",
        }


def test_exact_gate_uses_evidence_derived_isolated_reexecution() -> None:
    payload = {"checks": [True, True]}
    invocation = make_isolated_invocation(
        verifier_id="auditspec-all-boolean-checks-isolated-v1",
        claim_id=CLAIM_ID,
        replay_id="isolated-gate-replay",
        input_payload=payload,
        fuel=2,
    )
    config = make_config(
        "isolated-gate",
        verifier_id="auditspec-all-boolean-checks-isolated-v1",
        replay_id="isolated-gate-replay",
        declared_value=True,
        evidence_components=payload,
        isolated_verifier_invocation=invocation,
        isolation_policy=_policy(),
        external_verifier_profile=ISOLATED_REEXECUTION_PROFILE,
    )
    gate = run_exact_assurance_gate(config)
    assert gate.supported_within_declared_tcb
    assert gate.isolated_verifier_result is not None
    assert gate.isolated_verifier_result["executed"] is True
    assert gate.isolated_verifier_result["answer"] is True

    false_payload = {"checks": [True, False]}
    false_invocation = make_isolated_invocation(
        verifier_id="auditspec-all-boolean-checks-isolated-v1",
        claim_id=CLAIM_ID,
        replay_id="isolated-gate-replay",
        input_payload=false_payload,
        fuel=2,
    )
    failed = make_config(
        "isolated-gate-false",
        verifier_id="auditspec-all-boolean-checks-isolated-v1",
        replay_id="isolated-gate-replay",
        declared_value=True,
        evidence_components=false_payload,
        isolated_verifier_invocation=false_invocation,
        isolation_policy=_policy(),
        external_verifier_profile=ISOLATED_REEXECUTION_PROFILE,
    )
    gate = run_exact_assurance_gate(failed)
    assert gate.first_failed_layer == "V"
    details = next(item.details for item in gate.trace if item.layer == "V")
    assert "isolated_verifier_answer:mismatch" in details
