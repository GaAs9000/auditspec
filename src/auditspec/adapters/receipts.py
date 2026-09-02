"""Generic runtime evidence receipts for the v0.8 instrumented runtime.

These receipts are the runtime realization of the contract mechanisms the
AuditSpec compiler selects (``state_diff_receipt``, ``mandatory_path_coverage``,
``policy_text_hash_binding``, trusted capture). They are environment-agnostic:
the τ² binding lives in ``experiments/v08_tau2_instrumented.py``, and the same
receipt families are meant to be reused by other adapters (AppWorld DB
mutations, payment ledgers, file writes, API state mutations).

Every builder returns a plain mapping so receipts can be embedded in a
producer-signed ``EvidenceAttestation`` (the signature covers the complete
attestation payload).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

RECEIPT_SCHEMA = "AuditSpec-v08-runtime-receipts-v1"


def canonical_json_bytes(value: Any) -> bytes:
    """Stable serialization used for every receipt hash."""

    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def ledger_root(entries: Sequence[Mapping[str, Any]]) -> str:
    """Ordered commitment to a sequence of receipt entries."""

    return sha256_value([sha256_value(entry) for entry in entries])


def interaction_ledger_entry(
    *,
    sequence: int,
    call_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    requestor: str,
    result_content: Any,
    error: bool,
) -> dict[str, Any]:
    """One captured tool request/result pair (Complete Interaction Ledger)."""

    _require(bool(call_id), "interaction ledger entry requires a call id")
    _require(sequence >= 0, "interaction ledger entry requires a sequence")
    return {
        "sequence": sequence,
        "call_id": call_id,
        "tool_name": tool_name,
        "requestor": requestor,
        "arguments_digest": sha256_value(dict(arguments)),
        "request_digest": sha256_value(
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "arguments": dict(arguments),
                "requestor": requestor,
            }
        ),
        "result_digest": sha256_text(
            result_content if isinstance(result_content, str) else str(result_content)
        ),
        "error": bool(error),
    }


def interaction_request_entry(
    *,
    sequence: int,
    call_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    requestor: str,
    mutating: bool,
) -> dict[str, Any]:
    """Request captured before dispatch at the trusted orchestrator boundary."""

    _require(bool(call_id), "interaction request requires a call id")
    _require(sequence >= 0, "interaction request requires a sequence")
    return {
        "sequence": sequence,
        "call_id": call_id,
        "tool_name": tool_name,
        "requestor": requestor,
        "arguments_digest": sha256_value(dict(arguments)),
        "request_digest": sha256_value(
            {
                "call_id": call_id,
                "tool_name": tool_name,
                "arguments": dict(arguments),
                "requestor": requestor,
            }
        ),
        "mutating": bool(mutating),
    }


def request_disposition_entry(
    *, request: Mapping[str, Any], termination_reason: str
) -> dict[str, Any]:
    """Trusted terminal disposition for a request that was never dispatched."""

    _require(bool(termination_reason), "terminal disposition requires a reason")
    return {
        "sequence": int(request["sequence"]),
        "call_id": str(request["call_id"]),
        "tool_name": str(request["tool_name"]),
        "requestor": str(request["requestor"]),
        "request_digest": str(request["request_digest"]),
        "mutating": bool(request.get("mutating")),
        "disposition": "not_dispatched",
        "termination_reason": termination_reason,
    }


def tool_result_coverage_receipt(
    *,
    run_id: str,
    task_id: str,
    agent_requested_call_count: int,
    entries: Sequence[Mapping[str, Any]],
    requested_not_dispatched: int = 0,
    request_entries: Sequence[Mapping[str, Any]] | None = None,
    terminal_dispositions: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Run-level closure proving complete tool-result capture (T06 family).

    With ``request_entries`` supplied, closure is over the complete request
    domain captured before dispatch: every request must have exactly one
    captured result or one signed terminal non-dispatch disposition. This
    preserves the difference between "no result existed" and "a result was
    omitted" without fabricating a tool response.

    The legacy count-only path remains for pre-v0.8-live artifacts.
    """

    captured = len(entries)
    if request_entries is None:
        request_count = agent_requested_call_count
        complete = agent_requested_call_count == captured
        request_root = None
        disposition_root = None
        disposition_count = requested_not_dispatched
    else:
        request_ids = [str(entry["call_id"]) for entry in request_entries]
        result_ids = [str(entry["call_id"]) for entry in entries]
        disposition_ids = [str(entry["call_id"]) for entry in terminal_dispositions]
        request_count = len(request_entries)
        complete = bool(
            len(set(request_ids)) == len(request_ids)
            and len(set(result_ids)) == len(result_ids)
            and len(set(disposition_ids)) == len(disposition_ids)
            and not (set(result_ids) & set(disposition_ids))
            and set(request_ids) == set(result_ids) | set(disposition_ids)
        )
        request_root = ledger_root(request_entries)
        disposition_root = ledger_root(terminal_dispositions)
        disposition_count = len(terminal_dispositions)
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "tool_result_coverage",
        "run_id": run_id,
        "task_id": task_id,
        "agent_requested_call_count": request_count,
        "captured_result_count": captured,
        "requested_not_dispatched": disposition_count,
        "terminal_disposition_count": disposition_count,
        "request_ledger_root": request_root,
        "terminal_disposition_root": disposition_root,
        "result_ledger_root": ledger_root(entries),
        "all_results_non_error": all(not entry["error"] for entry in entries),
        "coverage_complete": complete,
    }


def write_effect_entry(
    *,
    sequence: int,
    call_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    pre_state_root: str,
    post_state_root: str,
) -> dict[str, Any]:
    """Per-WRITE state-transition receipt (Write-Effect Ledger, T04 family)."""

    _require(bool(pre_state_root) and bool(post_state_root), "state roots required")
    return {
        "sequence": sequence,
        "call_id": call_id,
        "tool_name": tool_name,
        "arguments_digest": sha256_value(dict(arguments)),
        "pre_state_root": pre_state_root,
        "post_state_root": post_state_root,
        "effect_occurred": pre_state_root != post_state_root,
    }


def write_coverage_receipt(
    *,
    run_id: str,
    task_id: str,
    agent_requested_write_count: int,
    entries: Sequence[Mapping[str, Any]],
    request_entries: Sequence[Mapping[str, Any]] | None = None,
    terminal_dispositions: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Run-level closure over the write-effect ledger."""

    if request_entries is None:
        requested = agent_requested_write_count
        dispositions = 0
        complete = requested == len(entries)
        request_root = None
        disposition_root = None
    else:
        write_requests = [entry for entry in request_entries if entry.get("mutating")]
        write_dispositions = [
            entry for entry in terminal_dispositions if entry.get("mutating")
        ]
        request_ids = {str(entry["call_id"]) for entry in write_requests}
        result_ids = {str(entry["call_id"]) for entry in entries}
        disposition_ids = {str(entry["call_id"]) for entry in write_dispositions}
        requested = len(write_requests)
        dispositions = len(write_dispositions)
        complete = bool(
            len(request_ids) == len(write_requests)
            and len(result_ids) == len(entries)
            and len(disposition_ids) == len(write_dispositions)
            and not (result_ids & disposition_ids)
            and request_ids == result_ids | disposition_ids
        )
        request_root = ledger_root(write_requests)
        disposition_root = ledger_root(write_dispositions)
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "write_effect_coverage",
        "run_id": run_id,
        "task_id": task_id,
        "agent_requested_write_count": requested,
        "captured_write_count": len(entries),
        "terminal_disposition_count": dispositions,
        "write_request_ledger_root": request_root,
        "write_terminal_disposition_root": disposition_root,
        "ordered_call_root": ledger_root(entries),
        "any_effect_occurred": any(entry["effect_occurred"] for entry in entries),
        "coverage_complete": complete,
    }


def termination_receipt(
    *,
    run_id: str,
    task_id: str,
    termination_reason: str,
    terminal_event_id: str,
    last_agent_action_id: str | None,
    runner_revision: str,
) -> dict[str, Any]:
    """Lifecycle closure receipt (T05 family).

    Emitted for *every* run termination, whatever the reason: a false claim
    value must be as auditable as a true one.
    """

    _require(bool(termination_reason), "termination reason required")
    _require(bool(runner_revision), "runner revision required")
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "termination",
        "run_id": run_id,
        "task_id": task_id,
        "termination_reason": termination_reason,
        "terminal_event_id": terminal_event_id,
        "last_agent_action_id": last_agent_action_id,
        "runner_revision": runner_revision,
    }


def policy_delivery_receipt(
    *,
    run_id: str,
    task_id: str,
    domain: str,
    served_policy_text: str,
    pinned_policy_digest: str | None,
    policy_source_revision: str,
    delivery_point: str = "agent_prompt_assembly",
) -> dict[str, Any]:
    """Configuration-delivery binding (T07 family).

    Binds the policy bytes actually served to the agent — captured at the
    prompt-assembly boundary — to the pinned digest from the frozen registry.
    """

    _require(bool(served_policy_text), "served policy text required")
    served = sha256_text(served_policy_text)
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "policy_delivery",
        "run_id": run_id,
        "task_id": task_id,
        "domain": domain,
        "served_policy_digest": served,
        "pinned_policy_digest": pinned_policy_digest,
        "policy_matches_pin": (
            pinned_policy_digest is not None and served == pinned_policy_digest
        ),
        "policy_source_revision": policy_source_revision,
        "delivery_point": delivery_point,
    }


def run_closure_receipt(
    *,
    run_id: str,
    task_id: str,
    environment_revision: str,
    ledgers: Mapping[str, str],
    evidence_count: int,
    final_sequence: int,
) -> dict[str, Any]:
    """Final commitment over every ledger produced during the run."""

    _require(evidence_count >= 0 and final_sequence >= 0, "invalid closure counts")
    return {
        "schema": RECEIPT_SCHEMA,
        "kind": "run_closure",
        "run_id": run_id,
        "task_id": task_id,
        "ledger_roots": dict(ledgers),
        "evidence_count": evidence_count,
        "final_sequence": final_sequence,
        "environment_revision": environment_revision,
    }
