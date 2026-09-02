from __future__ import annotations

import hashlib
import json
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any, TypedDict

from ..model import AuditSpec
from ..spec import load_spec
from .evidence import emit_mechanism_event
from .events import EventSink, canonical_json
from .planner import SeededPlanner


class PaymentState(TypedDict, total=False):
    run_id: str
    action_id: str
    action_digest: str
    amount: int
    approval_limit: int
    approval_signature_valid: bool
    approval_action_bound: bool
    delegation_scope_payment: bool
    delegation_executor_bound: bool
    policy_limit: int
    policy_effective: bool
    model_recommendation: str
    planner_seed: int
    planner_id: str
    planner_version: str
    planner_trace_digest: str
    human_decision: str
    tool_response: str
    gateway_coverage_complete: bool
    commit_policy: str
    ledger_commit_count: int
    db_path: str
    sink: EventSink
    phase: str


def _action_identity(state: PaymentState) -> tuple[str, str]:
    payload = {"kind": "transfer", "amount": state["amount"], "currency": "USD"}
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    # Canonical action identity must survive a replay run-id change.  The run
    # identifier is carried separately by the event envelope.
    action_id = hashlib.sha256(f"transfer:{digest}".encode("utf-8")).hexdigest()[:24]
    return action_id, digest


def _initialize_ledger(path: str | Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, action_id TEXT NOT NULL, amount INTEGER NOT NULL, route TEXT NOT NULL)"
        )
        connection.commit()


def _commit_count(policy: str, tool_response: str) -> int:
    if policy == "single_on_success":
        return 1 if tool_response == "success" else 0
    if policy == "duplicate_on_success":
        return 2 if tool_response == "success" else 0
    if policy == "always_duplicate":
        return 2
    if policy == "commit_on_timeout":
        return 1
    if policy == "never_commit":
        return 0
    raise ValueError(f"Unknown commit_policy: {policy}")


@lru_cache(maxsize=1)
def _payment_spec() -> AuditSpec:
    source_path = Path(__file__).resolve().parents[3] / "examples" / "payment.yaml"
    package_path = Path(__file__).resolve().parents[1] / "data" / "examples" / "payment.yaml"
    return load_spec(source_path if source_path.is_file() else package_path)


def build_payment_graph(spec: AuditSpec | None = None):
    """Build a deterministic tool-using workflow on the real LangGraph runtime."""

    spec = spec or _payment_spec()

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover - exercised by optional-dependency check
        raise RuntimeError(
            "The payment fixture needs the optional runtime dependency: pip install 'auditability-compiler[runtime]'"
        ) from exc

    def emit(
        state: PaymentState,
        mechanism: str,
        attributes: dict[str, Any],
        *,
        action_id: str | None = None,
        world: dict[str, Any] | None = None,
        observation_names: set[str] | None = None,
    ) -> None:
        emit_mechanism_event(
            state["sink"],
            spec,
            mechanism,
            world or state,
            run_id=state["run_id"],
            action_id=action_id or state["action_id"],
            attributes=attributes,
            observation_names=observation_names,
        )

    def canonicalize(state: PaymentState) -> dict[str, Any]:
        action_id, digest = _action_identity(state)
        emit(
            state,
            "canonical_action",
            {"amount": state["amount"], "action_digest": digest},
            action_id=action_id,
        )
        emit(state, "coarse_amount_channel", {}, action_id=action_id)
        emit(state, "amount_token", {}, action_id=action_id)
        return {"action_id": action_id, "action_digest": digest, "phase": "canonicalized"}

    def review(state: PaymentState) -> dict[str, Any]:
        common = {
            "model_recommendation": state["model_recommendation"],
            "human_decision": state["human_decision"],
        }
        emit(
            state,
            "generic_agent_trace",
            {"node": "review", **common},
            observation_names={"model_recommendation", "human_decision"},
        )
        emit(
            state,
            "model_advice",
            {
                "model_recommendation": state["model_recommendation"],
                "planner_seed": state["planner_seed"],
                "planner_id": state["planner_id"],
                "planner_version": state["planner_version"],
                "planner_trace_digest": state["planner_trace_digest"],
            },
        )
        emit(
            state,
            "human_decision_record",
            {"human_decision": state["human_decision"]},
        )
        return {"phase": "reviewed"}

    def approval(state: PaymentState) -> dict[str, Any]:
        emit(
            state,
            "approval_bound_receipt",
            {
                "approval_limit": state["approval_limit"],
                "approval_signature_valid": state["approval_signature_valid"],
                "approval_action_bound": state["approval_action_bound"],
                "action_digest": state["action_digest"] if state["approval_action_bound"] else "other-action",
            },
        )
        return {"phase": "approval_captured"}

    def authority(state: PaymentState) -> dict[str, Any]:
        emit(
            state,
            "delegation_context",
            {
                "delegation_scope_payment": state["delegation_scope_payment"],
                "delegation_executor_bound": state["delegation_executor_bound"],
                "delegation_id": f"dlg-{state['action_id']}",
            },
        )
        return {"phase": "authority_captured"}

    def policy(state: PaymentState) -> dict[str, Any]:
        policy_payload = {
            "limit": state["policy_limit"],
            "effective": state["policy_effective"],
        }
        emit(
            state,
            "policy_snapshot",
            {
                "policy_limit": state["policy_limit"],
                "policy_effective": state["policy_effective"],
                "policy_hash": hashlib.sha256(
                    canonical_json(policy_payload).encode("utf-8")
                ).hexdigest(),
            },
        )
        emit(state, "coarse_policy_channel", {})
        emit(state, "policy_state_token", {})
        return {"phase": "policy_captured"}

    def execute(state: PaymentState) -> dict[str, Any]:
        path = Path(state["db_path"])
        _initialize_ledger(path)
        commits = _commit_count(state["commit_policy"], state["tool_response"])
        route = "gateway" if state["gateway_coverage_complete"] else "out_of_band"
        with sqlite3.connect(path) as connection:
            for _ in range(commits):
                connection.execute(
                    "INSERT INTO ledger(run_id, action_id, amount, route) VALUES (?, ?, ?, ?)",
                    (state["run_id"], state["action_id"], state["amount"], route),
                )
            connection.commit()
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM ledger WHERE action_id = ?", (state["action_id"],)
                ).fetchone()[0]
            )
        event_world = dict(state)
        event_world["ledger_commit_count"] = count
        emit(
            state,
            "gateway_coverage",
            {
                "gateway_coverage_complete": state["gateway_coverage_complete"],
                "declared_channel": "tool_dispatch",
                "bypass_count": 0 if state["gateway_coverage_complete"] else count,
            },
            world=event_world,
        )
        emit(
            state,
            "durable_effect_receipt",
            {"ledger_commit_count": count, "action_digest": state["action_digest"]},
            world=event_world,
        )
        return {"ledger_commit_count": count, "phase": "effect_committed"}

    def report(state: PaymentState) -> dict[str, Any]:
        emit(
            state,
            "generic_agent_trace",
            {"node": "report", "tool_response": state["tool_response"]},
            observation_names={"tool_response"},
        )
        emit(state, "final_output", {"tool_response": state["tool_response"]})
        return {"phase": "reported"}

    graph = StateGraph(PaymentState)
    graph.add_node("canonicalize", canonicalize)
    graph.add_node("review", review)
    graph.add_node("approval", approval)
    graph.add_node("authority", authority)
    graph.add_node("policy", policy)
    graph.add_node("execute", execute)
    graph.add_node("report", report)
    graph.add_edge(START, "canonicalize")
    graph.add_edge("canonicalize", "review")
    graph.add_edge("review", "approval")
    graph.add_edge("approval", "authority")
    graph.add_edge("authority", "policy")
    graph.add_edge("policy", "execute")
    graph.add_edge("execute", "report")
    graph.add_edge("report", END)
    return graph.compile()


def run_payment_fixture(
    scenario: dict[str, Any],
    *,
    db_path: str | Path,
    enabled_mechanisms: set[str],
    graph: Any | None = None,
    planner: Any | None = None,
) -> tuple[dict[str, Any], EventSink]:
    graph = graph or build_payment_graph()
    sink = EventSink(enabled_mechanisms)
    planner_seed = int(scenario.get("planner_seed", 0))
    planner = planner or SeededPlanner(planner_seed)
    planned = planner.payment(
        amount=int(scenario.get("amount", 150)),
        policy_limit=int(scenario.get("policy_limit", 100)),
        context=scenario,
    )
    model_recommendation = str(
        scenario.get("model_recommendation", planned.output)
    )
    initial: PaymentState = {
        "run_id": str(scenario["run_id"]),
        "amount": int(scenario.get("amount", 150)),
        "approval_limit": int(scenario.get("approval_limit", 100)),
        "approval_signature_valid": bool(scenario.get("approval_signature_valid", True)),
        "approval_action_bound": bool(scenario.get("approval_action_bound", True)),
        "delegation_scope_payment": bool(scenario.get("delegation_scope_payment", True)),
        "delegation_executor_bound": bool(scenario.get("delegation_executor_bound", True)),
        "policy_limit": int(scenario.get("policy_limit", 100)),
        "policy_effective": bool(scenario.get("policy_effective", True)),
        "model_recommendation": model_recommendation,
        "planner_seed": planner_seed,
        "planner_id": planned.planner_id,
        "planner_version": planned.planner_version,
        "planner_trace_digest": planned.trace_digest,
        "human_decision": str(scenario.get("human_decision", "approve")),
        "tool_response": str(scenario.get("tool_response", "success")),
        "gateway_coverage_complete": bool(scenario.get("gateway_coverage_complete", True)),
        "commit_policy": str(scenario.get("commit_policy", "single_on_success")),
        "ledger_commit_count": 0,
        "db_path": str(db_path),
        "sink": sink,
        "phase": "start",
    }
    result = dict(graph.invoke(initial))
    valid, errors = sink.verify()
    if not valid:
        raise RuntimeError(f"Fixture emitted an invalid evidence chain: {errors}")
    return result, sink


def runtime_world(result: dict[str, Any], duplicate_without_tool_response: bool) -> dict[str, Any]:
    return {
        "amount": result["amount"],
        "approval_limit": result["approval_limit"],
        "approval_signature_valid": result["approval_signature_valid"],
        "approval_action_bound": result["approval_action_bound"],
        "delegation_scope_payment": result["delegation_scope_payment"],
        "delegation_executor_bound": result["delegation_executor_bound"],
        "policy_limit": result["policy_limit"],
        "policy_effective": result["policy_effective"],
        "model_recommendation": result["model_recommendation"],
        "human_decision": result["human_decision"],
        "tool_response": result["tool_response"],
        "ledger_commit_count": result["ledger_commit_count"],
        "gateway_coverage_complete": result["gateway_coverage_complete"],
        "duplicate_without_tool_response": duplicate_without_tool_response,
    }
