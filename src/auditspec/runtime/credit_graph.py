from __future__ import annotations

import hashlib
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any, TypedDict

from ..model import AuditSpec
from ..spec import load_spec
from .evidence import emit_mechanism_event
from .events import EventSink, canonical_json
from .planner import SeededPlanner


class CreditState(TypedDict, total=False):
    run_id: str
    application_id: str
    application_digest: str
    score: int
    model_decision: str
    planner_seed: int
    planner_id: str
    planner_version: str
    planner_trace_digest: str
    human_decision: str
    policy_threshold: int
    policy_effective: bool
    income_source_verified: bool
    feature_source_bound: bool
    model_reason_code: str
    notice_reason_code: str
    decision_record_bound: bool
    feature_channel_complete: bool
    denial_without_income_feature: bool
    ablation_mode: bool
    ablation_model_decision: str
    ablation_human_decision: str
    db_path: str
    sink: EventSink
    phase: str


@lru_cache(maxsize=1)
def _credit_spec() -> AuditSpec:
    return load_spec(Path(__file__).resolve().parents[3] / "examples" / "credit.yaml")


def _application_identity(state: CreditState) -> tuple[str, str]:
    payload = {"kind": "credit_application", "score": state["score"]}
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    application_id = hashlib.sha256(
        f"application:{digest}".encode("utf-8")
    ).hexdigest()[:24]
    return application_id, digest


def _initialize_decisions(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, application_id TEXT NOT NULL, decision TEXT NOT NULL, record_bound INTEGER NOT NULL)"
        )
        connection.commit()


def build_credit_graph(spec: AuditSpec | None = None):
    spec = spec or _credit_spec()
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The credit fixture needs the optional runtime dependency: pip install 'auditability-compiler[runtime]'"
        ) from exc

    def emit(
        state: CreditState,
        mechanism: str,
        attributes: dict[str, Any],
        *,
        application_id: str | None = None,
        world: dict[str, Any] | None = None,
        observation_names: set[str] | None = None,
    ) -> None:
        emit_mechanism_event(
            state["sink"],
            spec,
            mechanism,
            world or state,
            run_id=state["run_id"],
            action_id=application_id or state["application_id"],
            attributes=attributes,
            observation_names=observation_names,
        )

    def canonicalize(state: CreditState) -> dict[str, Any]:
        application_id, digest = _application_identity(state)
        emit(
            state,
            "canonical_application",
            {"score": state["score"], "application_digest": digest},
            application_id=application_id,
        )
        emit(state, "coarse_score_channel", {}, application_id=application_id)
        emit(state, "score_token", {}, application_id=application_id)
        return {
            "application_id": application_id,
            "application_digest": digest,
            "phase": "canonicalized",
        }

    def features(state: CreditState) -> dict[str, Any]:
        emit(
            state,
            "feature_provenance",
            {
                "income_source_verified": state["income_source_verified"],
                "feature_source_bound": state["feature_source_bound"],
            },
        )
        emit(
            state,
            "feature_coverage",
            {
                "feature_channel_complete": state["feature_channel_complete"],
                "bypass_count": 0 if state["feature_channel_complete"] else 1,
            },
        )
        return {"phase": "features_captured"}

    def policy(state: CreditState) -> dict[str, Any]:
        emit(
            state,
            "policy_snapshot",
            {
                "policy_threshold": state["policy_threshold"],
                "policy_effective": state["policy_effective"],
            },
        )
        emit(state, "coarse_credit_policy_channel", {})
        emit(state, "credit_policy_state_token", {})
        return {"phase": "policy_captured"}

    def decide(state: CreditState) -> dict[str, Any]:
        model_decision = (
            state["ablation_model_decision"]
            if state["ablation_mode"]
            else state["model_decision"]
        )
        human_decision = (
            state["ablation_human_decision"]
            if state["ablation_mode"]
            else state["human_decision"]
        )
        reason = "other" if state["ablation_mode"] else state["model_reason_code"]
        decision_world = dict(state)
        decision_world.update(
            {
                "model_decision": model_decision,
                "human_decision": human_decision,
                "model_reason_code": reason,
            }
        )
        emit(
            state,
            "generic_decision_trace",
            {
                "node": "decision",
                "model_decision": model_decision,
                "human_decision": human_decision,
                "model_reason_code": reason,
            },
            world=decision_world,
        )
        emit(
            state,
            "model_reason_record",
            {
                "model_decision": model_decision,
                "model_reason_code": reason,
                "planner_seed": state["planner_seed"],
                "planner_id": state["planner_id"],
                "planner_version": state["planner_version"],
                "planner_trace_digest": state["planner_trace_digest"],
            },
            world=decision_world,
        )
        path = Path(state["db_path"])
        _initialize_decisions(path)
        stored_application = (
            state["application_id"] if state["decision_record_bound"] else "other-application"
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                "INSERT INTO decisions(run_id, application_id, decision, record_bound) VALUES (?, ?, ?, ?)",
                (
                    state["run_id"],
                    stored_application,
                    human_decision,
                    int(state["decision_record_bound"]),
                ),
            )
            connection.commit()
        emit(
            state,
            "decision_receipt",
            {
                "human_decision": human_decision,
                "decision_record_bound": state["decision_record_bound"],
                "stored_application_id": stored_application,
            },
            world=decision_world,
        )
        return {
            "model_decision": model_decision,
            "human_decision": human_decision,
            "model_reason_code": reason,
            "phase": "decided",
        }

    def notice(state: CreditState) -> dict[str, Any]:
        emit(
            state,
            "notice_receipt",
            {"notice_reason_code": state["notice_reason_code"]},
        )
        emit(
            state,
            "final_decision",
            {"human_decision": state["human_decision"]},
        )
        return {"phase": "reported"}

    graph = StateGraph(CreditState)
    graph.add_node("canonicalize", canonicalize)
    graph.add_node("features", features)
    graph.add_node("policy", policy)
    graph.add_node("decide", decide)
    graph.add_node("notice", notice)
    graph.add_edge(START, "canonicalize")
    graph.add_edge("canonicalize", "features")
    graph.add_edge("features", "policy")
    graph.add_edge("policy", "decide")
    graph.add_edge("decide", "notice")
    graph.add_edge("notice", END)
    return graph.compile()


def run_credit_fixture(
    scenario: dict[str, Any],
    *,
    db_path: str | Path,
    enabled_mechanisms: set[str],
    graph: Any | None = None,
    planner: Any | None = None,
) -> tuple[dict[str, Any], EventSink]:
    graph = graph or build_credit_graph()
    sink = EventSink(enabled_mechanisms)
    planner_seed = int(scenario.get("planner_seed", 0))
    planner = planner or SeededPlanner(planner_seed)
    planned = planner.credit(
        score=int(scenario.get("score", 580)),
        policy_threshold=int(scenario.get("policy_threshold", 600)),
        context=scenario,
    )
    model_decision = str(scenario.get("model_decision", planned.output))
    normalized_reason_code = (
        "low_score"
        if planned.reason_code == "below_threshold"
        else "other"
        if planned.reason_code != "unspecified"
        else "low_score"
    )
    initial: CreditState = {
        "run_id": str(scenario["run_id"]),
        "score": int(scenario.get("score", 580)),
        "model_decision": model_decision,
        "planner_seed": planner_seed,
        "planner_id": planned.planner_id,
        "planner_version": planned.planner_version,
        "planner_trace_digest": planned.trace_digest,
        "human_decision": str(scenario.get("human_decision", "deny")),
        "policy_threshold": int(scenario.get("policy_threshold", 600)),
        "policy_effective": bool(scenario.get("policy_effective", True)),
        "income_source_verified": bool(
            scenario.get("income_source_verified", True)
        ),
        "feature_source_bound": bool(scenario.get("feature_source_bound", True)),
        "model_reason_code": str(
            scenario.get("model_reason_code", normalized_reason_code)
        ),
        "notice_reason_code": str(scenario.get("notice_reason_code", "low_score")),
        "decision_record_bound": bool(scenario.get("decision_record_bound", True)),
        "feature_channel_complete": bool(
            scenario.get("feature_channel_complete", True)
        ),
        "denial_without_income_feature": bool(
            scenario.get("denial_without_income_feature", False)
        ),
        "ablation_mode": bool(scenario.get("ablation_mode", False)),
        "ablation_model_decision": str(
            scenario.get("ablation_model_decision", "approve")
        ),
        "ablation_human_decision": str(
            scenario.get("ablation_human_decision", "approve")
        ),
        "db_path": str(db_path),
        "sink": sink,
        "phase": "start",
    }
    result = dict(graph.invoke(initial))
    valid, errors = sink.verify()
    if not valid:
        raise RuntimeError(f"Credit fixture emitted an invalid evidence chain: {errors}")
    return result, sink


def runtime_world(
    result: dict[str, Any], denial_without_income_feature: bool
) -> dict[str, Any]:
    return {
        "score": result["score"],
        "model_decision": result["model_decision"],
        "human_decision": result["human_decision"],
        "policy_threshold": result["policy_threshold"],
        "policy_effective": result["policy_effective"],
        "income_source_verified": result["income_source_verified"],
        "feature_source_bound": result["feature_source_bound"],
        "model_reason_code": result["model_reason_code"],
        "notice_reason_code": result["notice_reason_code"],
        "decision_record_bound": result["decision_record_bound"],
        "feature_channel_complete": result["feature_channel_complete"],
        "denial_without_income_feature": denial_without_income_feature,
    }
