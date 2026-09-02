from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from .compiler import DEFAULT_WEIGHTS, AuditCompiler, _minimum_weight_contract


@dataclass(frozen=True)
class BaselineResult:
    method: str
    query: str
    threat_model: str
    contract: tuple[str, ...]
    claimed_auditable: bool
    sound_auditable: bool
    semantic_determinate: bool
    structural_assurance: bool
    false_assurance: bool
    scalar_cost: float
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def static_dependency_cover(
    compiler: AuditCompiler,
    query_name: str,
    threat_model: str,
    *,
    provider_semantics: str = "source",
    weights: Mapping[str, float] | None = None,
) -> BaselineResult:
    """AST dependency cover without world-pair or determinacy reasoning.

    `source` treats every channel source as if it were revealed and can therefore
    produce false assurance for lossy observations. `exact` only credits exact
    projections and is sounder but cannot exploit predicates, digests, logical
    redundancy, or bounded-domain equivalence.
    """

    if provider_semantics not in {"source", "exact"}:
        raise ValueError("provider_semantics must be source or exact")
    method = f"static_{provider_semantics}_dependency_cover"
    eligible, _ = compiler.eligible_mechanisms(
        threat_model, {"passive", "active"}
    )
    threat = compiler.spec.threat_models[threat_model]
    merged_weights = dict(DEFAULT_WEIGHTS | dict(weights or {}))
    costs = {
        name: mechanism.cost.weighted(merged_weights)
        for name, mechanism in eligible.items()
    }
    dependencies = {name: mechanism.requires for name, mechanism in eligible.items()}
    constraints: list[frozenset[str]] = []
    missing: list[str] = []
    for fact in compiler.query_dependencies(query_name):
        providers = frozenset(
            name
            for name, mechanism in eligible.items()
            if fact
            in (
                mechanism.facts
                if provider_semantics == "source"
                else mechanism.exactly_revealed_facts
            )
        )
        if providers:
            constraints.append(providers)
        else:
            missing.append(f"fact:{fact}")
    for requirement in compiler.derived_requirements(query_name):
        providers = frozenset(
            name
            for name, mechanism in eligible.items()
            if requirement in compiler.effective_capabilities(mechanism, threat)
        )
        if providers:
            constraints.append(providers)
        else:
            missing.append(f"requirement:{requirement}")
    selected = (
        None
        if missing
        else _minimum_weight_contract(constraints, costs, dependencies)
    )
    if selected is None:
        return _result(
            compiler,
            method,
            query_name,
            threat_model,
            (),
            claimed=False,
            reason="missing_static_provider:" + ",".join(sorted(missing)),
        )
    contract = tuple(sorted(selected))
    return _result(
        compiler,
        method,
        query_name,
        threat_model,
        contract,
        claimed=True,
    )

def determinacy_only(
    compiler: AuditCompiler,
    query_name: str,
    threat_model: str,
    *,
    weights: Mapping[str, float] | None = None,
    max_iterations: int = 512,
) -> BaselineResult:
    """Counterexample-guided semantic selection with all structural gates off."""

    eligible, _ = compiler.eligible_mechanisms(
        threat_model, {"passive", "active"}
    )
    merged_weights = dict(DEFAULT_WEIGHTS | dict(weights or {}))
    costs = {
        name: mechanism.cost.weighted(merged_weights)
        for name, mechanism in eligible.items()
    }
    dependencies = {name: mechanism.requires for name, mechanism in eligible.items()}
    constraints: list[frozenset[str]] = []
    selected = _minimum_weight_contract(constraints, costs, dependencies)
    assert selected is not None
    for _ in range(max_iterations):
        checked = compiler.check_contract(
            query_name,
            sorted(selected),
            threat_model=threat_model,
        )
        if checked.certificate is None:
            return _result(
                compiler,
                "determinacy_only",
                query_name,
                threat_model,
                tuple(sorted(selected)),
                claimed=True,
            )
        separators = frozenset(
            name
            for name in checked.certificate.separating_candidates
            if name in eligible
        )
        if not separators:
            return _result(
                compiler,
                "determinacy_only",
                query_name,
                threat_model,
                tuple(sorted(selected)),
                claimed=False,
                reason="unseparable_critical_pair",
            )
        constraints.append(separators)
        selected = _minimum_weight_contract(constraints, costs, dependencies)
        if selected is None:
            break
    return _result(
        compiler,
        "determinacy_only",
        query_name,
        threat_model,
        (),
        claimed=False,
        reason="inconclusive_or_unsatisfiable",
    )


def fixed_bundle(
    compiler: AuditCompiler,
    query_name: str,
    threat_model: str,
    names: Sequence[str],
    *,
    method: str,
) -> BaselineResult:
    eligible, _ = compiler.eligible_mechanisms(
        threat_model, {"passive", "active"}
    )
    selected = _dependency_closure(
        {name for name in names if name in eligible}, compiler, set(eligible)
    )
    contract = tuple(sorted(selected or ()))
    checked = compiler.check_contract(query_name, contract, threat_model=threat_model)
    return _result(
        compiler,
        method,
        query_name,
        threat_model,
        contract,
        claimed=checked.auditable,
        reason=None if selected is not None else "dependency_unavailable",
    )


def retain_all_admissible(
    compiler: AuditCompiler, query_name: str, threat_model: str
) -> BaselineResult:
    eligible, _ = compiler.eligible_mechanisms(
        threat_model, {"passive", "active"}
    )
    return fixed_bundle(
        compiler,
        query_name,
        threat_model,
        sorted(eligible),
        method="retain_all_admissible_passive_and_active",
    )


def _dependency_closure(
    chosen: set[str], compiler: AuditCompiler, allowed: set[str]
) -> set[str] | None:
    closure = set(chosen)
    pending = list(chosen)
    while pending:
        current = pending.pop()
        for dependency in compiler.spec.mechanisms[current].requires:
            if dependency not in allowed:
                return None
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)
    return closure


def _result(
    compiler: AuditCompiler,
    method: str,
    query_name: str,
    threat_model: str,
    contract: tuple[str, ...],
    *,
    claimed: bool,
    reason: str | None = None,
) -> BaselineResult:
    checked = compiler.check_contract(
        query_name, contract, threat_model=threat_model
    )
    semantic = checked.certificate is None
    structural = not checked.unmet_requirements and not checked.missing_dependencies
    sound = checked.auditable
    weights = DEFAULT_WEIGHTS
    scalar_cost = sum(
        compiler.spec.mechanisms[name].cost.weighted(weights) for name in contract
    )
    return BaselineResult(
        method=method,
        query=query_name,
        threat_model=threat_model,
        contract=contract,
        claimed_auditable=claimed,
        sound_auditable=sound,
        semantic_determinate=semantic,
        structural_assurance=structural,
        false_assurance=bool(claimed and not sound),
        scalar_cost=scalar_cost,
        reason=reason,
    )
