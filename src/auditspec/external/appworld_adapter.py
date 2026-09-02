"""Adapter from AppWorld's official TestTracker to the v0.6 oracle IR."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .claims import APPWORLD_EVALUATOR
from .evidence import ExternalEvidenceSource, materialize_independent_witnesses
from .record import ActionRecord, NormalizedRunRecord, OracleCheckRecord


def _tracker_mapping(tracker: Any) -> Mapping[str, Any]:
    if isinstance(tracker, Mapping):
        return tracker
    if hasattr(tracker, "to_dict"):
        return tracker.to_dict(stats_only=False)
    raise TypeError("tracker must be an AppWorld TestTracker or its serialized mapping")


def _check(
    check_id: str,
    statement: str,
    *,
    applicable: bool,
    value: bool,
    violating_ids: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> OracleCheckRecord:
    return OracleCheckRecord(
        check_id=check_id,
        statement=statement,
        source=APPWORLD_EVALUATOR,
        applicable=applicable,
        value=value,
        violating_ids=tuple(str(item) for item in violating_ids),
        metadata=dict(metadata or {}),
    )


def adapt_appworld_run(
    *,
    run_id: str,
    task_id: str,
    tracker: Any,
    test_data: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]] = (),
    benchmark_commit: str,
    task_spec_revision: str,
) -> NormalizedRunRecord:
    """Normalize official state-based evaluation results.

    Test order and labels come from the pinned task's ground-truth test data.
    A slot's statement is display text; its truth is the official TestTracker
    pass/fail result for the corresponding executable state assertion.
    """

    raw_tracker = _tracker_mapping(tracker)
    passes = list(raw_tracker.get("passes", ()))
    failures = list(raw_tracker.get("failures", ()))
    passed_requirements = {str(item["requirement"]) for item in passes}
    failed_requirements = {str(item["requirement"]) for item in failures}
    declared = [str(item["requirement"]) for item in test_data]
    if len(set(declared)) != len(declared):
        raise ValueError("AppWorld test requirement strings must be unique")
    observed = passed_requirements | failed_requirements
    unexpected = observed - set(declared)
    if unexpected:
        raise ValueError(f"tracker returned undeclared requirements: {sorted(unexpected)}")

    missing = [
        f"requirement:{index}"
        for index, text in enumerate(declared, start=1)
        if text not in observed
    ]
    complete = not missing and len(observed) == len(declared)
    success = bool(raw_tracker.get("success", False)) and complete
    overall_violations = [
        f"requirement:{index}"
        for index, text in enumerate(declared, start=1)
        if text not in passed_requirements
    ]
    if not success and not overall_violations:
        overall_violations = ["official_task_success"]
    oracle_checks: list[OracleCheckRecord] = [
        _check(
            "official_task_success",
            "Every official state-based task requirement is met.",
            applicable=True,
            value=success,
            violating_ids=overall_violations,
            metadata={"num_tests": len(declared), "complete": complete},
        )
    ]

    for label, check_id, statement in (
        (
            "no_op_fail",
            "all_no_op_fail_requirements",
            "Every official goal requirement is met.",
        ),
        (
            "no_op_pass",
            "all_no_op_pass_requirements",
            "Every official state-preservation requirement is met.",
        ),
    ):
        indexes = [
            index
            for index, item in enumerate(test_data, start=1)
            if str(item.get("label")) == label
        ]
        violations = [
            f"requirement:{index}"
            for index in indexes
            if declared[index - 1] not in passed_requirements
        ]
        oracle_checks.append(
            _check(
                check_id,
                statement,
                applicable=bool(indexes),
                value=not violations,
                violating_ids=violations,
                metadata={"label": label, "slots": indexes},
            )
        )

    for slot in range(1, 8):
        applicable = len(declared) >= slot
        statement = (
            declared[slot - 1]
            if applicable
            else f"Official task-specific requirement slot {slot} is not declared."
        )
        value = statement in passed_requirements if applicable else True
        oracle_checks.append(
            _check(
                f"requirement_slot_{slot}",
                statement,
                applicable=applicable,
                value=value,
                violating_ids=() if value else (f"requirement:{slot}",),
                metadata={
                    "slot": slot,
                    "label": (
                        str(test_data[slot - 1].get("label"))
                        if applicable
                        else None
                    ),
                },
            )
        )

    actions: list[ActionRecord] = []
    for index, request in enumerate(requests, start=1):
        method = str(request.get("method", "")).lower()
        url = str(request.get("url", ""))
        path = url.split("://", 1)[-1].split("/", 1)[-1].lstrip("/")
        app = path.split("/", 1)[0] if path else None
        actions.append(
            ActionRecord(
                call_id=f"request-event:{index}",
                native_call_id=f"{method}:{url}",
                sequence=index,
                tool=f"{method.upper()} {path}",
                app=app,
                effectful=method in {"post", "put", "patch", "delete"},
            )
        )

    record = NormalizedRunRecord(
        schema="AuditSpec-external-run-record-v1",
        environment="appworld",
        run_id=run_id,
        task_id=task_id,
        policy_version=task_spec_revision,
        actions=tuple(actions),
        official_task_success=success,
        oracle_checks=tuple(oracle_checks),
        adapter_metadata={
            "adapter": "appworld-v06",
            "benchmark_commit": benchmark_commit,
            "task_spec_revision": task_spec_revision,
            "num_declared_tests": len(declared),
            "num_observed_tests": len(observed),
        },
    )
    record.validate()
    return record


def extract_appworld_evidence_source(
    *,
    run_id: str,
    task_id: str,
    requests: Sequence[Mapping[str, Any]],
    verification_record: NormalizedRunRecord,
    benchmark_commit: str,
    replay_id: str,
    producer_key: bytes,
    final_answer: str | None = None,
) -> ExternalEvidenceSource:
    """Build evidence from AppWorld requests and an independent state-test replay."""

    if verification_record.environment != "appworld":
        raise ValueError("AppWorld evidence requires an AppWorld verification record")
    if (
        verification_record.run_id != run_id
        or verification_record.task_id != task_id
        or verification_record.adapter_metadata.get("benchmark_commit")
        != benchmark_commit
    ):
        raise ValueError("AppWorld verification record is not bound to the source run")

    normalized: list[dict[str, Any]] = []
    for sequence, request in enumerate(requests, start=1):
        method = str(request.get("method", "")).upper()
        url = str(request.get("url", ""))
        path = url.split("://", 1)[-1].split("/", 1)[-1].lstrip("/")
        normalized.append(
            {
                "sequence": sequence,
                "method": method,
                "app": path.split("/", 1)[0] if path else None,
                "endpoint": path,
                "effectful": method.lower() in {"post", "put", "patch", "delete"},
            }
        )

    witnesses, attestations = materialize_independent_witnesses(
        verification_record,
        replay_id=replay_id,
        verifier_id="appworld-official-evaluator-replay-v1",
        producer="benchmark-evaluator",
        capture_point="benchmark-harness",
        coverage_channel="appworld-api-dispatch",
        benchmark_revision=benchmark_commit,
        producer_key=producer_key,
    )
    return ExternalEvidenceSource(
        environment="appworld",
        run_id=run_id,
        task_id=task_id,
        benchmark_revision=benchmark_commit,
        final_answer=final_answer,
        normalized_trace=tuple(normalized),
        native_trace=tuple(dict(request) for request in requests),
        witnesses=witnesses,
        attestations=attestations,
    )
