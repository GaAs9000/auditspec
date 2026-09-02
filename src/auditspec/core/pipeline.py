"""First Core 1.0 vertical slice: semantic migration through design PLANNED."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import digest, strict_json_loads
from .claim_ir import FormationFailure, ScopedClaim, validate_and_scope
from .contract import VerifiedContract, build_verified_contract, derive_open_premises
from .finite_backend import SynthesisGap, SynthesisIncomplete, SynthesisPass, synthesize
from .finite_model import AdequacyGap, AdequacyPass, check_sqlite_count_adequacy
from .legacy_crosswalk import ROOT, CrosswalkBundle, build_crosswalk
from .plan import CoreInstallationPlan, RealizationGap, build_plan
from .refs import RegistryStore, RootedRef
from .state_machine import DesignLifecycle, LifecycleState, TransitionOutcome


@dataclass(frozen=True)
class CompileFailure:
    verdict: str
    obligation: str
    subtype: str | None
    witness: Any
    last_state: str
    transitions: tuple[dict[str, Any], ...]
    scoped_claim: ScopedClaim | None = None
    contract: VerifiedContract | None = None

    def to_wire(self) -> dict[str, Any]:
        witness = _wire_value(self.witness)
        analysis_limit = witness if self.verdict == "ANALYSIS_INCOMPLETE" else None
        if self.verdict == "ANALYSIS_INCOMPLETE" and (
            not isinstance(analysis_limit, dict)
            or analysis_limit.get("schema") != "AuditSpec-analysis-limit-v1"
        ):
            raise ValueError("ANALYSIS_INCOMPLETE requires AnalysisLimit wire block")
        return {
            "schema": "AuditSpec-core-compilation-terminal-v1",
            "status": "TYPED_FAIL",
            "verdict": self.verdict,
            "obligation": self.obligation,
            "subtype": self.subtype,
            "witness": witness,
            "analysis_limit": analysis_limit,
            "last_state": self.last_state,
            "transitions": list(self.transitions),
            "scoped_claim": (
                self.scoped_claim.to_wire() if self.scoped_claim is not None else None
            ),
            "contract": self.contract.to_wire() if self.contract is not None else None,
        }


@dataclass(frozen=True)
class PlannedCompilation:
    claim_ref: RootedRef
    scoped_claim: ScopedClaim
    scoped_claim_ref: RootedRef
    adequacy: AdequacyPass
    synthesis: SynthesisPass
    contract: VerifiedContract
    contract_ref: RootedRef
    plan: CoreInstallationPlan
    plan_ref: RootedRef
    crosswalk_report: dict[str, Any]
    last_state: str
    transitions: tuple[dict[str, Any], ...]
    boundaries: dict[str, Any]
    registries: RegistryStore

    def summary(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-core-phase1-planning-artifact-preview-v1",
            "status": "PASS",
            "claim_ref": self.claim_ref.to_wire(),
            "scoped_claim_ref": self.scoped_claim_ref.to_wire(),
            "scoped_claim": self.scoped_claim.to_wire(),
            "contract_ref": self.contract_ref.to_wire(),
            "contract": self.contract.to_wire(),
            "plan_ref": self.plan_ref.to_wire(),
            "plan": self.plan.to_wire(),
            "crosswalk_report": self.crosswalk_report,
            "last_state": self.last_state,
            "transitions": list(self.transitions),
            "boundaries": self.boundaries,
            "registry_snapshot": self.registries.export(),
        }


def _wire_value(value: Any) -> Any:
    to_wire = getattr(value, "to_wire", None)
    if callable(to_wire):
        return to_wire()
    if isinstance(value, tuple):
        return [_wire_value(item) for item in value]
    if isinstance(value, list):
        return [_wire_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _wire_value(item) for key, item in value.items()}
    return value


def load_overlay(path: str | Path) -> dict[str, Any]:
    value = strict_json_loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Core overlay root must be an object")
    return value


def compile_overlay(
    path: str | Path,
    *,
    root: Path = ROOT,
    state_cap: int | None = None,
    abstraction_mode: str | None = None,
    missing_adapters: frozenset[str] = frozenset(),
) -> PlannedCompilation | CompileFailure:
    return compile_overlay_data(
        load_overlay(path),
        root=root,
        state_cap=state_cap,
        abstraction_mode=abstraction_mode,
        missing_adapters=missing_adapters,
    )


def compile_overlay_data(
    overlay: Mapping[str, Any],
    *,
    root: Path = ROOT,
    state_cap: int | None = None,
    abstraction_mode: str | None = None,
    missing_adapters: frozenset[str] = frozenset(),
) -> PlannedCompilation | CompileFailure:
    bundle = build_crosswalk(copy.deepcopy(dict(overlay)), root=root)
    lifecycle = DesignLifecycle()
    scoped = validate_and_scope(bundle.claim, bundle.claim_ref, bundle.registries)
    if isinstance(scoped, FormationFailure):
        lifecycle.attempt(
            LifecycleState.SCOPED,
            obligation=scoped.obligation,
            outcome=TransitionOutcome.TYPED_FAIL,
            verdict_on_fail=scoped.verdict,
        )
        return _failure(scoped.verdict, scoped.obligation, None, scoped, lifecycle)
    lifecycle.attempt(
        LifecycleState.SCOPED, obligation="Q+WorldScope", outcome=TransitionOutcome.PASS
    )
    scoped_ref = bundle.registries.register(
        "core_phase1_scoped_claim_registry", "claim", [scoped.to_wire()]
    )[scoped.scoped_claim_id]

    mode = abstraction_mode or bundle.overlay["concrete_model"]["abstraction"]
    adequacy = check_sqlite_count_adequacy(
        bundle.domain,
        bundle.claim.predicate,
        action_id=bundle.overlay["concrete_model"]["action_id"],
        abstraction_mode=mode,
    )
    if isinstance(adequacy, AdequacyGap):
        lifecycle.attempt(
            LifecycleState.MODEL_VALIDATED,
            obligation="A",
            outcome=TransitionOutcome.TYPED_FAIL,
            verdict_on_fail="MODEL_GAP",
        )
        return _failure("MODEL_GAP", "A", None, adequacy.twin, lifecycle, scoped=scoped)
    lifecycle.attempt(
        LifecycleState.MODEL_VALIDATED, obligation="A", outcome=TransitionOutcome.PASS
    )

    limit = bundle.overlay["analysis_state_cap"] if state_cap is None else state_cap
    synthesis = synthesize(
        bundle.domain,
        bundle.claim.predicate,
        bundle.catalog,
        bundle.weights,
        state_cap=limit,
    )
    if isinstance(synthesis, SynthesisIncomplete):
        lifecycle.attempt(
            LifecycleState.SYNTHESIZED,
            obligation="D",
            outcome=TransitionOutcome.LIMIT_REACHED,
            verdict_on_fail="ANALYSIS_INCOMPLETE",
        )
        return _failure(
            "ANALYSIS_INCOMPLETE",
            "D",
            None,
            synthesis.analysis_limit,
            lifecycle,
            scoped=scoped,
        )
    if isinstance(synthesis, SynthesisGap):
        lifecycle.attempt(
            LifecycleState.SYNTHESIZED,
            obligation="D",
            outcome=TransitionOutcome.TYPED_FAIL,
            verdict_on_fail="EVIDENCE_GAP",
        )
        return _failure(
            "EVIDENCE_GAP", "D", None, synthesis.twin, lifecycle, scoped=scoped
        )

    contract, contract_ref = _contract(
        bundle, scoped, scoped_ref, adequacy, synthesis, root
    )
    lifecycle.attempt(
        LifecycleState.SYNTHESIZED, obligation="D", outcome=TransitionOutcome.PASS
    )
    available = {
        name: candidate
        for name, candidate in bundle.catalog.adapters.items()
        if name not in missing_adapters
    }
    plan = build_plan(
        contract,
        contract_ref,
        bundle.catalog,
        bundle.registries,
        adapter_candidates=available,
    )
    if isinstance(plan, RealizationGap):
        lifecycle.attempt(
            LifecycleState.PLANNED,
            obligation="R",
            outcome=TransitionOutcome.TYPED_FAIL,
            verdict_on_fail=plan.verdict,
            failure_subtype=plan.subtype,
        )
        return _failure(
            plan.verdict,
            "R",
            plan.subtype,
            plan,
            lifecycle,
            scoped=scoped,
            contract=contract,
        )
    lifecycle.attempt(
        LifecycleState.PLANNED,
        obligation="adapter_resolution",
        outcome=TransitionOutcome.PASS,
    )
    plan_ref = bundle.registries.register(
        "core_phase1_plan_registry", "other", [plan.to_wire()]
    )[plan.wire_without_digest["plan_id"]]
    boundaries = dict(bundle.overlay["boundaries"])
    boundaries.update(
        {
            "last_state": "PLANNED",
            "authenticated_core_state_transition_records_emitted": False,
            "planning_artifact_preview_only": True,
            "formal_model_calls": 0,
            "official_evaluator_executions": 0,
        }
    )
    return PlannedCompilation(
        bundle.claim_ref,
        scoped,
        scoped_ref,
        adequacy,
        synthesis,
        contract,
        contract_ref,
        plan,
        plan_ref,
        bundle.crosswalk_report,
        str(lifecycle.state),
        _transitions(lifecycle),
        boundaries,
        bundle.registries,
    )


def _contract(
    bundle: CrosswalkBundle,
    scoped: ScopedClaim,
    scoped_ref: RootedRef,
    adequacy: AdequacyPass,
    synthesis: SynthesisPass,
    root: Path,
) -> tuple[VerifiedContract, RootedRef]:
    registry = bundle.registries
    optimization_record = dict(synthesis.witness)
    optimization_record["id"] = "witness.global_optimization"
    optimization_ref = registry.register(
        "core_phase1_optimization_registry", "witness", [optimization_record]
    )[optimization_record["id"]]
    trace_records = [
        {
            "schema": "auditspec.impl.obligation-witness.v1",
            "id": f"witness.{obligation}",
            "obligation": obligation,
            "status": "PASS",
            "input": {
                "Q": scoped.claim_ir_digest,
                "WorldScope": scoped.scope_commitment,
                "A": bundle.domain.domain_root,
                "D": bundle.catalog.mechanism_registry_root,
            }[obligation],
            "witness": {
                "Q": list(scoped.q_check_trace),
                "WorldScope": list(scoped.world_scope_check_trace),
                "A": adequacy.to_wire(),
                "D": synthesis.witness,
            }[obligation],
        }
        for obligation in ("Q", "WorldScope", "A", "D")
    ]
    trace_refs = registry.register(
        "core_phase1_trace_registry", "witness", trace_records
    )
    minimality_records: list[dict[str, Any]] = []
    for name, witness in sorted(synthesis.minimality_twins.items()):
        wire = witness.to_wire() if hasattr(witness, "to_wire") else dict(witness)
        minimality_records.append(
            {
                "schema": "auditspec.impl.minimality-witness.v1",
                "id": f"witness.minimality.{name}",
                "mechanism_id": name,
                "witness": wire,
            }
        )
    minimality_refs_map = registry.register(
        "core_phase1_minimality_registry", "witness", minimality_records
    )
    lifecycle_policy = bundle.bootstrap_refs["policy.lifecycle.synthetic_slice"]
    premises = derive_open_premises(bundle.claim, bundle.catalog, lifecycle_policy)
    premise_root = digest("AuditSpec-open-premise-set-v1", premises)
    premise_record = {
        "schema": "auditspec.impl.open-premise-derivation-witness.v1",
        "id": "witness.open_premises",
        "open_premise_set_root": premise_root,
        "premises": premises,
    }
    premise_ref = registry.register(
        "core_phase1_premise_registry", "witness", [premise_record]
    )[premise_record["id"]]
    contract = build_verified_contract(
        claim=bundle.claim,
        scoped=scoped,
        scoped_ref=scoped_ref,
        domain=bundle.domain,
        adequacy=adequacy,
        synthesis=synthesis,
        catalog=bundle.catalog,
        compiler_root=_core_source_root(root),
        threat_model_root=bundle.bootstrap_refs[
            "threat.synthetic_payment_slice"
        ].payload_digest,
        schema_registry_root=bundle.schema_registry_root,
        verifier_ref=bundle.bootstrap_refs["verifier.exact_observation"],
        optimization_witness_ref=optimization_ref,
        optimization_witness_digest=synthesis.witness_digest,
        premise_witness_ref=premise_ref,
        policy_witness_ref=bundle.bootstrap_refs[
            "witness.lifecycle_policy_covers_horizon"
        ],
        lifecycle_policy_ref=lifecycle_policy,
        trace_witness_refs={
            name: trace_refs[f"witness.{name}"]
            for name in ("Q", "WorldScope", "A", "D")
        },
        minimality_witness_refs=tuple(
            minimality_refs_map[name] for name in sorted(minimality_refs_map)
        ),
        registries=registry,
    )
    contract_ref = registry.register(
        "core_phase1_contract_registry", "other", [contract.to_wire()]
    )[contract.contract_id]
    return contract, contract_ref


def _core_source_root(root: Path) -> str:
    directory = root / "src/auditspec/core"
    rows = []
    for path in sorted(directory.glob("*.py")):
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return digest("AuditSpec-core-phase1-compiler-source-v1", rows)


def _failure(
    verdict: str,
    obligation: str,
    subtype: str | None,
    witness: Any,
    lifecycle: DesignLifecycle,
    *,
    scoped: ScopedClaim | None = None,
    contract: VerifiedContract | None = None,
) -> CompileFailure:
    return CompileFailure(
        verdict,
        obligation,
        subtype,
        witness,
        str(lifecycle.state),
        _transitions(lifecycle),
        scoped,
        contract,
    )


def _transitions(lifecycle: DesignLifecycle) -> tuple[dict[str, Any], ...]:
    return tuple(item.to_wire() for item in lifecycle.transitions)
