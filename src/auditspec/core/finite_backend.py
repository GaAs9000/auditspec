"""Pure finite-world D/optimization backend with typed limit outcomes."""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json, digest
from .expression import Expr
from .finite_model import FiniteDomain
from .mechanism_ir import CostVector, MechanismCatalog


@dataclass(frozen=True)
class EvidenceTwin:
    contract: tuple[str, ...]
    world_a: dict[str, Any]
    world_b: dict[str, Any]
    answer_a: bool
    answer_b: bool
    shared_observation: dict[str, Any]
    witness_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-non-auditability-certificate-v2",
            "contract": list(self.contract),
            "world_a": self.world_a,
            "world_b": self.world_b,
            "answer_a": self.answer_a,
            "answer_b": self.answer_b,
            "shared_observation": self.shared_observation,
            "witness_digest": self.witness_digest,
        }


@dataclass(frozen=True)
class AnalysisLimit:
    backend: str
    unresolved_obligation: str
    bound_kind: str
    bound_value: int
    explored_states: int
    reproduces: bool = True

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-analysis-limit-v1",
            "backend": self.backend,
            "backend_ref": None,
            "unresolved_obligation": self.unresolved_obligation,
            "bound_kind": self.bound_kind,
            "bound_value": self.bound_value,
            "explored": {"states": self.explored_states, "wall_ms": 0},
            "lower_bound": None,
            "upper_bound": None,
            "reproduces": self.reproduces,
        }


@dataclass(frozen=True)
class SynthesisPass:
    selected: tuple[str, ...]
    dependency_closure: tuple[str, ...]
    cost: CostVector
    witness: dict[str, Any]
    witness_digest: str
    minimality_twins: Mapping[str, EvidenceTwin | dict[str, Any]]
    states_explored: int


@dataclass(frozen=True)
class SynthesisGap:
    verdict: str
    twin: EvidenceTwin
    states_explored: int


@dataclass(frozen=True)
class SynthesisIncomplete:
    verdict: str
    analysis_limit: AnalysisLimit


def synthesize(
    domain: FiniteDomain,
    predicate: Expr,
    catalog: MechanismCatalog,
    weights: CostVector,
    *,
    state_cap: int,
) -> SynthesisPass | SynthesisGap | SynthesisIncomplete:
    if state_cap < 0:
        raise ValueError("state cap must be non-negative")
    mechanism_ids = tuple(sorted(catalog.mechanisms))
    candidates: list[tuple[tuple[str, ...], CostVector, EvidenceTwin | None]] = []
    explored = 0
    last_twin: EvidenceTwin | None = None
    for size in range(len(mechanism_ids) + 1):
        for subset in itertools.combinations(mechanism_ids, size):
            if not catalog.contract_is_dependency_closed(subset):
                continue
            determinate, twin, used = _check_determinacy(
                domain,
                predicate,
                catalog,
                subset,
                state_cap - explored,
            )
            explored += used
            if determinate is None:
                return SynthesisIncomplete(
                    "ANALYSIS_INCOMPLETE",
                    AnalysisLimit("finite-enum", "D", "state_cap", state_cap, explored),
                )
            cost = CostVector.zero()
            for mechanism_id in subset:
                cost = cost + catalog.mechanisms[mechanism_id].declared_cost
            candidates.append((subset, cost, twin))
            if twin is not None:
                last_twin = twin
    feasible = [(subset, cost) for subset, cost, twin in candidates if twin is None]
    if not feasible:
        assert last_twin is not None
        return SynthesisGap("EVIDENCE_GAP", last_twin, explored)
    selected, selected_cost = min(
        feasible,
        key=lambda item: (item[1].scalar(weights), len(item[0]), item[0]),
    )
    rows: list[dict[str, Any]] = []
    for subset, cost, twin in candidates:
        rows.append(
            {
                "contract": list(subset),
                "dependency_closed": True,
                "determinate": twin is None,
                "cost": cost.to_wire(),
                "scalar_cost": {
                    "numerator": cost.scalar(weights).numerator,
                    "denominator": cost.scalar(weights).denominator,
                },
                "twin_digest": twin.witness_digest if twin else None,
            }
        )
    witness = {
        "schema": "auditspec.impl.global-finite-optimization-witness.v1",
        "domain_root": domain.domain_root,
        "universe_root": domain.universe_root,
        "predicate_digest": predicate.ast_digest,
        "mechanism_registry_root": catalog.mechanism_registry_root,
        "dependency_witness_digest": catalog.dependency_witness_digest,
        "weights": weights.to_wire(),
        "candidate_contracts": rows,
        "selected": list(selected),
        "tie_break": "scalar_cost_then_cardinality_then_utf8_id_tuple",
    }
    minimality: dict[str, EvidenceTwin | dict[str, Any]] = {}
    for mechanism_id in selected:
        reduced = tuple(name for name in selected if name != mechanism_id)
        if not catalog.contract_is_dependency_closed(reduced):
            minimality[mechanism_id] = {
                "type": "dependency_nonclosure",
                "removed": mechanism_id,
                "required_by": sorted(
                    name
                    for name in selected
                    if mechanism_id in catalog.dependencies[name]
                ),
            }
            continue
        checked, twin, _ = _check_determinacy(
            domain, predicate, catalog, reduced, len(domain.worlds) + 1
        )
        if checked is True and twin is not None:
            minimality[mechanism_id] = twin
        else:
            minimality[mechanism_id] = {
                "type": "global_cost_witness",
                "removed": mechanism_id,
            }
    return SynthesisPass(
        selected,
        catalog.dependency_closure(selected),
        selected_cost,
        witness,
        digest("auditspec.impl.global-finite-optimization-witness.v1", witness),
        minimality,
        explored,
    )


def check_contract(
    domain: FiniteDomain,
    predicate: Expr,
    catalog: MechanismCatalog,
    contract: tuple[str, ...],
) -> EvidenceTwin | None:
    determinate, twin, _ = _check_determinacy(
        domain, predicate, catalog, contract, len(domain.worlds) + 1
    )
    if determinate is None:
        raise AssertionError("unbounded contract check unexpectedly hit a limit")
    return twin


def _check_determinacy(
    domain: FiniteDomain,
    predicate: Expr,
    catalog: MechanismCatalog,
    contract: tuple[str, ...],
    remaining: int,
) -> tuple[bool | None, EvidenceTwin | None, int]:
    buckets: dict[str, tuple[bool, dict[str, Any], dict[str, Any]]] = {}
    used = 0
    for world in domain.worlds:
        if used >= remaining:
            return None, None, used
        used += 1
        observation = {
            name: catalog.mechanisms[name].observe(world) for name in contract
        }
        key = canonical_json(observation)
        answer = bool(predicate.evaluate(world))
        prior = buckets.get(key)
        if prior is not None and prior[0] != answer:
            body = {
                "contract": list(contract),
                "world_a": prior[1],
                "world_b": world,
                "answer_a": prior[0],
                "answer_b": answer,
                "shared_observation": observation,
            }
            return (
                True,
                EvidenceTwin(
                    contract,
                    prior[1],
                    dict(world),
                    prior[0],
                    answer,
                    observation,
                    digest("AuditSpec-non-auditability-certificate-v2", body),
                ),
                used,
            )
        buckets.setdefault(key, (answer, dict(world), observation))
    return True, None, used
