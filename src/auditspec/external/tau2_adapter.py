"""Adapter from pinned τ² SimulationRun records to the v0.6 oracle IR."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .claims import TAU_EVALUATOR, TAU_TRAJECTORY
from .evidence import ExternalEvidenceSource, materialize_independent_witnesses
from .record import ActionRecord, NormalizedRunRecord, OracleCheckRecord


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _scalar(value: Any) -> Any:
    return getattr(value, "value", value)


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return {"value": str(value)}


def _statement(value: Any) -> str:
    mapping = _mapping(value)
    message = mapping.get("message")
    if message:
        return str(message)
    return json.dumps(mapping, sort_keys=True, separators=(",", ":"), default=str)


def _check(
    check_id: str,
    statement: str,
    source: str,
    *,
    applicable: bool,
    value: bool,
    violating_ids: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> OracleCheckRecord:
    return OracleCheckRecord(
        check_id=check_id,
        statement=statement,
        source=source,
        applicable=applicable,
        value=value,
        violating_ids=tuple(str(item) for item in violating_ids),
        metadata=dict(metadata or {}),
    )


def _messages(simulation: Any) -> list[Any]:
    if not isinstance(simulation, Mapping) and hasattr(simulation, "get_messages"):
        return list(simulation.get_messages())
    return list(_field(simulation, "messages", ()) or ())


def adapt_tau2_run(
    simulation: Any,
    *,
    domain: str,
    benchmark_commit: str,
) -> NormalizedRunRecord:
    """Normalize one official τ² run without reinterpreting domain policy."""

    reward_info = _field(simulation, "reward_info")
    if reward_info is None:
        raise ValueError("τ² run has no official reward_info")
    env_assertions = list(_field(reward_info, "env_assertions", ()) or ())
    db_check = _field(reward_info, "db_check")

    oracle_checks: list[OracleCheckRecord] = []
    reward = float(_field(reward_info, "reward", 0.0))
    oracle_checks.append(
        _check(
            "official_task_success",
            "The official aggregate task reward equals 1.",
            TAU_EVALUATOR,
            applicable=True,
            value=reward == 1.0,
            violating_ids=() if reward == 1.0 else ("official_reward",),
            metadata={"reward": reward},
        )
    )

    db_applicable = db_check is not None
    db_match = bool(_field(db_check, "db_match", False)) if db_applicable else True
    oracle_checks.append(
        _check(
            "official_db_match",
            "The official target database end state matches.",
            TAU_EVALUATOR,
            applicable=db_applicable,
            value=db_match,
            violating_ids=() if db_match else ("db_check",),
        )
    )

    failed_env = [
        f"env_assertion:{index}"
        for index, assertion in enumerate(env_assertions, start=1)
        if not bool(_field(assertion, "met", False))
    ]
    oracle_checks.append(
        _check(
            "all_env_assertions",
            "Every declared official environment assertion is met.",
            TAU_EVALUATOR,
            applicable=bool(env_assertions),
            value=not failed_env,
            violating_ids=failed_env,
            metadata={"count": len(env_assertions)},
        )
    )
    for slot in range(1, 4):
        applicable = len(env_assertions) >= slot
        assertion = env_assertions[slot - 1] if applicable else None
        met = bool(_field(assertion, "met", False)) if applicable else True
        statement = (
            _statement(_field(assertion, "env_assertion"))
            if applicable
            else f"Official environment-assertion slot {slot} is not declared."
        )
        oracle_checks.append(
            _check(
                f"env_assertion_slot_{slot}",
                statement,
                TAU_EVALUATOR,
                applicable=applicable,
                value=met,
                violating_ids=() if met else (f"env_assertion:{slot}",),
                metadata={"slot": slot},
            )
        )

    messages = _messages(simulation)
    calls: list[tuple[int, Any]] = []
    results: list[tuple[int, Any]] = []
    for sequence, message in enumerate(messages):
        role = str(_scalar(_field(message, "role", "")))
        if role == "assistant":
            for tool_call in list(_field(message, "tool_calls", ()) or ()):
                calls.append((sequence, tool_call))
        elif role == "tool" and str(_scalar(_field(message, "requestor", ""))) == "assistant":
            results.append((sequence, message))

    call_ids = [str(_field(call, "id", "")) for _, call in calls]
    result_ids = [str(_field(result, "id", "")) for _, result in results]
    result_counts = Counter(result_ids)
    call_counts = Counter(call_ids)
    result_by_id = {
        str(_field(result, "id", "")): result
        for _, result in results
        if str(_field(result, "id", ""))
    }

    actions = tuple(
        ActionRecord(
            call_id=f"agent-call-event:{index}",
            native_call_id=call_id,
            sequence=sequence,
            tool=str(_field(call, "name", "")),
            app=domain,
            status=(
                "failed"
                if bool(_field(result_by_id.get(call_id), "error", False))
                else "succeeded"
            ),
        )
        for index, ((sequence, call), call_id) in enumerate(
            zip(calls, call_ids, strict=True), start=1
        )
    )

    error_ids = sorted(
        {
            str(_field(result, "id", ""))
            for _, result in results
            if bool(_field(result, "error", False))
        }
    )
    tool_applicable = bool(calls or results)
    oracle_checks.append(
        _check(
            "no_agent_tool_errors",
            "No agent-requested tool result is marked as an error.",
            TAU_TRAJECTORY,
            applicable=tool_applicable,
            value=not error_ids,
            violating_ids=error_ids,
        )
    )

    missing = [
        call_id or "<empty-call-id>"
        for call_id in call_ids
        if result_counts[call_id] != 1
    ]
    orphaned = [
        result_id or "<empty-result-id>"
        for result_id in result_ids
        if call_counts[result_id] != 1
    ]
    binding_violations = sorted(set(missing + orphaned))
    oracle_checks.append(
        _check(
            "agent_call_result_bijection",
            "Agent tool calls and results form a one-to-one ID binding.",
            TAU_TRAJECTORY,
            applicable=tool_applicable,
            value=not binding_violations,
            violating_ids=binding_violations,
        )
    )

    duplicate_or_empty = sorted(
        {
            call_id or "<empty-call-id>"
            for call_id in call_ids
            if not call_id or call_counts[call_id] != 1
        }
    )
    oracle_checks.append(
        _check(
            "unique_nonempty_agent_call_ids",
            "Agent tool-call identifiers are non-empty and unique.",
            TAU_TRAJECTORY,
            applicable=bool(calls),
            value=not duplicate_or_empty,
            violating_ids=duplicate_or_empty,
        )
    )

    termination = str(_scalar(_field(simulation, "termination_reason", "")))
    explicit_stop = termination in {"agent_stop", "user_stop"}
    oracle_checks.append(
        _check(
            "explicit_stop_termination",
            "The simulation ended by an explicit agent or user stop.",
            TAU_TRAJECTORY,
            applicable=True,
            value=explicit_stop,
            violating_ids=() if explicit_stop else (termination or "<missing>",),
            metadata={"termination_reason": termination},
        )
    )

    record = NormalizedRunRecord(
        schema="AuditSpec-external-run-record-v1",
        environment="tau2",
        run_id=str(_field(simulation, "id")),
        task_id=str(_field(simulation, "task_id")),
        policy_version=benchmark_commit,
        actions=actions,
        official_task_success=reward == 1.0,
        oracle_checks=tuple(oracle_checks),
        adapter_metadata={
            "adapter": "tau2-v06",
            "benchmark_commit": benchmark_commit,
            "domain": domain,
            "reward_basis": [
                str(_scalar(item))
                for item in list(_field(reward_info, "reward_basis", ()) or ())
            ],
        },
    )
    record.validate()
    return record


def extract_tau2_evidence_source(
    simulation: Any,
    *,
    verification_record: NormalizedRunRecord,
    benchmark_commit: str,
    replay_id: str,
    producer_key: bytes,
) -> ExternalEvidenceSource:
    """Build evidence from a second official evaluator replay and native messages."""

    run_id = str(_field(simulation, "id"))
    task_id = str(_field(simulation, "task_id"))
    if verification_record.environment != "tau2":
        raise ValueError("τ² evidence requires a τ² verification record")
    if (
        verification_record.run_id != run_id
        or verification_record.task_id != task_id
        or verification_record.policy_version != benchmark_commit
    ):
        raise ValueError("τ² verification record is not bound to the source run")

    messages = _messages(simulation)
    final_answer: str | None = None
    results: dict[str, Any] = {}
    for message in messages:
        role = str(_scalar(_field(message, "role", "")))
        if role == "assistant" and _field(message, "content") is not None:
            final_answer = str(_field(message, "content"))
        if role == "tool" and str(_scalar(_field(message, "requestor", ""))) == "assistant":
            results[str(_field(message, "id", ""))] = message

    normalized: list[dict[str, Any]] = []
    for sequence, message in enumerate(messages):
        if str(_scalar(_field(message, "role", ""))) != "assistant":
            continue
        for call in list(_field(message, "tool_calls", ()) or ()):
            call_id = str(_field(call, "id", ""))
            result = results.get(call_id)
            normalized.append(
                {
                    "sequence": sequence,
                    "tool": str(_field(call, "name", "")),
                    "arguments": dict(_field(call, "arguments", {}) or {}),
                    "result": _field(result, "content"),
                    "status": (
                        "error" if bool(_field(result, "error", False)) else "ok"
                    ),
                }
            )

    witnesses, attestations = materialize_independent_witnesses(
        verification_record,
        replay_id=replay_id,
        verifier_id="tau2-official-evaluator-replay-v1",
        producer="benchmark-evaluator",
        capture_point="benchmark-harness",
        coverage_channel="tau2-tool-dispatch",
        benchmark_revision=benchmark_commit,
        producer_key=producer_key,
    )
    return ExternalEvidenceSource(
        environment="tau2",
        run_id=run_id,
        task_id=task_id,
        benchmark_revision=benchmark_commit,
        final_answer=final_answer,
        normalized_trace=tuple(normalized),
        native_trace=tuple(_mapping(message) for message in messages),
        witnesses=witnesses,
        attestations=attestations,
    )
