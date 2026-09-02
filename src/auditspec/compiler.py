from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
from typing import Any, Mapping, Sequence

from .adapter_registry import validate_mechanism_adapter
from .catalog import spec_digest
from .expr import evaluate, referenced_names
from .model import (
    AuditSpec,
    CostVector,
    InstrumentationItem,
    Mechanism,
    SynthesisResult,
    ThreatModel,
    TwinCertificate,
    World,
)
from .spec import enumerate_worlds
from .topology import verify_mediation

DEFAULT_WEIGHTS = {
    "bytes": 0.001,
    "privacy": 1.0,
    "latency_ms": 1.0,
    "fragility": 1.0,
}


@dataclass(frozen=True)
class ContractCheck:
    auditable: bool
    certificate: TwinCertificate | None
    unmet_requirements: tuple[str, ...] = ()
    missing_dependencies: tuple[str, ...] = ()


class AuditCompiler:
    """Bounded compiler for trusted evidence and replay-mechanism contracts.

    The counterexample loop is an explicit domain adaptation of established
    critical-pair / minimum-observation synthesis. Guarantees are exact only for
    the supplied finite worlds, candidate catalog, threat model and cost weights.
    """

    def __init__(self, spec: AuditSpec, worlds: Sequence[World] | None = None):
        self.spec = spec
        self.worlds: list[World] = list(worlds) if worlds is not None else enumerate_worlds(spec)
        if not self.worlds:
            raise ValueError("The specification has no satisfying worlds")
        for mechanism in self.spec.mechanisms.values():
            mechanism.cost.validate()
        self._answer_cache: dict[str, list[Any]] = {}
        self._world_keys = {
            self._canonical_world(world) for world in self.worlds
        }

    def _canonical_world(self, world: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
        return tuple((name, world[name]) for name in self.spec.variables)

    def _world_is_canonical_member(self, world: Mapping[str, Any]) -> bool:
        if set(world) != set(self.spec.variables):
            return False
        try:
            if any(world[name] not in domain for name, domain in self.spec.variables.items()):
                return False
            return self._canonical_world(world) in self._world_keys
        except (KeyError, TypeError, ValueError):
            return False

    def query_answer(self, query_name: str, world: Mapping[str, Any]) -> Any:
        return evaluate(self.spec.queries[query_name].expression, world)

    def query_answers(self, query_name: str) -> list[Any]:
        if query_name not in self._answer_cache:
            expression = self.spec.queries[query_name].expression
            self._answer_cache[query_name] = [evaluate(expression, world) for world in self.worlds]
        return self._answer_cache[query_name]

    def query_dependencies(self, query_name: str) -> tuple[str, ...]:
        return tuple(sorted(referenced_names(self.spec.queries[query_name].expression)))

    def derived_requirements(self, query_name: str) -> tuple[str, ...]:
        query = self.spec.queries[query_name]
        requirements = set(query.required_capabilities)
        for fact_name in self.query_dependencies(query_name):
            fact = self.spec.facts[fact_name]
            if fact.entity != query.anchor_entity:
                requirements.add(f"bind:{query.anchor_entity}:{fact.entity}")
            if fact.negative_evidence_channel:
                requirements.add(f"coverage:{fact.negative_evidence_channel}:mandatory")
        if query.kind == "causality":
            assert query.intervention_target is not None
            requirements.add(f"replay:{query.intervention_target}:verified")
        return tuple(sorted(requirements))

    def effective_capabilities(
        self, mechanism: Mechanism, threat_model: ThreatModel
    ) -> frozenset[str]:
        capabilities = {
            capability
            for capability in mechanism.capabilities
            if not capability.startswith(("coverage:", "bind:", "replay:"))
        }
        adapter_reasons = validate_mechanism_adapter(mechanism)
        if not adapter_reasons:
            capabilities.update(
                f"bind:{source}:{target}"
                for source, target in mechanism.binding_edges
            )
        if mechanism.coverage_channel and not adapter_reasons:
            proof = verify_mediation(
                self.spec.topology,
                mechanism.coverage_channel,
                bypass_edges=threat_model.bypass_edges,
            )
            if proof.valid and mechanism.capture_point == proof.mediator:
                capabilities.add(
                    f"coverage:{mechanism.coverage_channel}:mandatory"
                )
        if mechanism.mode == "active" and mechanism.replay is not None:
            valid, _ = mechanism.replay.validate(adapter=mechanism.adapter)
            if valid:
                capabilities.add(f"replay:{mechanism.replay.target}:verified")
        return frozenset(capabilities)

    def eligible_mechanisms(
        self,
        threat_model: str,
        modes: set[str] | None = None,
    ) -> tuple[dict[str, Mechanism], dict[str, list[str]]]:
        tm = self.spec.threat_models[threat_model]
        modes = modes or {"passive", "active"}
        eligible: dict[str, Mechanism] = {}
        rejected: dict[str, list[str]] = {}
        for name, mechanism in self.spec.mechanisms.items():
            if mechanism.mode not in modes:
                continue
            allowed, reasons = tm.mechanism_allowed(mechanism)
            rejection_reasons = list(reasons)
            rejection_reasons.extend(validate_mechanism_adapter(mechanism))
            if mechanism.mode == "active":
                if mechanism.replay is None:
                    rejection_reasons.append("missing:replay_contract")
                else:
                    replay_valid, replay_reasons = mechanism.replay.validate(
                        adapter=mechanism.adapter
                    )
                    if not replay_valid:
                        rejection_reasons.extend(replay_reasons)
            if allowed and not rejection_reasons:
                eligible[name] = mechanism
            else:
                rejected[name] = sorted(set(rejection_reasons))
        return eligible, rejected

    def observation(
        self, world: Mapping[str, Any], contract: Sequence[str]
    ) -> tuple[tuple[str, tuple[tuple[str, Any], ...]], ...]:
        return tuple(
            (name, self.spec.mechanisms[name].observe(world))
            for name in sorted(set(contract))
        )

    def _contract_assurance(
        self,
        query_name: str,
        contract: Sequence[str],
        threat_model: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        tm = self.spec.threat_models[threat_model]
        selected = set(contract)
        capabilities = set()
        missing_dependencies: set[str] = set()
        for name in selected:
            mechanism = self.spec.mechanisms[name]
            capabilities.update(self.effective_capabilities(mechanism, tm))
            missing_dependencies.update(set(mechanism.requires) - selected)
        unmet = set(self.derived_requirements(query_name)) - capabilities
        return tuple(sorted(unmet)), tuple(sorted(missing_dependencies))

    def check_contract(
        self,
        query_name: str,
        contract: Sequence[str],
        threat_model: str = "cooperative",
        candidate_modes: set[str] | None = None,
    ) -> ContractCheck:
        if query_name not in self.spec.queries:
            raise KeyError(f"Unknown query: {query_name}")
        eligible, _ = self.eligible_mechanisms(
            threat_model, candidate_modes or {"passive", "active"}
        )
        contract = tuple(sorted(set(contract)))
        unavailable = sorted(set(contract) - set(eligible))
        if unavailable:
            raise ValueError(
                f"Contract mechanisms are unavailable or untrusted under {threat_model!r}: {unavailable}"
            )
        unmet, missing_dependencies = self._contract_assurance(
            query_name, contract, threat_model
        )

        buckets: dict[tuple[Any, ...], tuple[Any, World]] = {}
        for world, answer in zip(self.worlds, self.query_answers(query_name)):
            obs = self.observation(world, contract)
            if obs in buckets:
                prior_answer, prior_world = buckets[obs]
                if prior_answer != answer:
                    separators = tuple(
                        sorted(
                            name
                            for name, mechanism in eligible.items()
                            if mechanism.observe(prior_world) != mechanism.observe(world)
                        )
                    )
                    shared = {
                        name: self.spec.mechanisms[name].observe(world) for name in contract
                    }
                    certificate = TwinCertificate(
                        schema_version="AuditSpec-non-auditability-certificate-v2",
                        spec_digest=spec_digest(self.spec),
                        spec_name=self.spec.name,
                        query=query_name,
                        contract=contract,
                        world_a=dict(prior_world),
                        world_b=dict(world),
                        answer_a=prior_answer,
                        answer_b=answer,
                        shared_observation=shared,
                        separating_candidates=separators,
                        derived_requirements=self.derived_requirements(query_name),
                        threat_model=threat_model,
                    )
                    return ContractCheck(
                        False,
                        certificate,
                        unmet_requirements=unmet,
                        missing_dependencies=missing_dependencies,
                    )
            else:
                buckets[obs] = (answer, world)
        return ContractCheck(
            not (unmet or missing_dependencies),
            None,
            unmet_requirements=unmet,
            missing_dependencies=missing_dependencies,
        )

    def synthesize(
        self,
        query_name: str,
        threat_model: str = "cooperative",
        mode: str = "auto",
        weights: Mapping[str, float] | None = None,
        max_iterations: int = 512,
    ) -> SynthesisResult:
        weights = dict(DEFAULT_WEIGHTS | dict(weights or {}))
        unknown_weights = set(weights) - set(DEFAULT_WEIGHTS)
        invalid_weights = {
            name: value
            for name, value in weights.items()
            if not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        }
        if unknown_weights or invalid_weights:
            raise ValueError(
                "weights must use known cost dimensions with finite, non-negative values; "
                f"unknown={sorted(unknown_weights)}, invalid={invalid_weights}"
            )
        if mode not in {"passive", "all", "auto"}:
            raise ValueError("mode must be passive, all, or auto")

        if mode == "auto":
            passive = self._synthesize_with_modes(
                query_name, threat_model, {"passive"}, weights, max_iterations
            )
            if passive.status == "PASSIVE_AUDITABLE":
                return passive
            complete = self._synthesize_with_modes(
                query_name, threat_model, {"passive", "active"}, weights, max_iterations
            )
            if complete.status == "AUDITABLE":
                complete.status = "ACTIVE_AUDIT_REQUIRED"
                complete.notes.insert(
                    0,
                    "No trusted passive contract satisfied both determinacy and structural assurance; at least one validated replay mechanism is selected.",
                )
            return complete

        modes = {"passive"} if mode == "passive" else {"passive", "active"}
        return self._synthesize_with_modes(
            query_name, threat_model, modes, weights, max_iterations
        )

    def _synthesize_with_modes(
        self,
        query_name: str,
        threat_model: str,
        modes: set[str],
        weights: Mapping[str, float],
        max_iterations: int,
    ) -> SynthesisResult:
        eligible, rejected = self.eligible_mechanisms(threat_model, modes)
        tm = self.spec.threat_models[threat_model]
        requirements = self.derived_requirements(query_name)
        costs = {name: mechanism.cost.weighted(weights) for name, mechanism in eligible.items()}
        dependencies = {name: mechanism.requires for name, mechanism in eligible.items()}

        constraints: list[frozenset[str]] = []
        unsatisfied_requirements: list[str] = []
        for requirement in requirements:
            providers = frozenset(
                name
                for name, mechanism in eligible.items()
                if requirement in self.effective_capabilities(mechanism, tm)
            )
            if not providers:
                unsatisfied_requirements.append(requirement)
            else:
                constraints.append(providers)
        if unsatisfied_requirements:
            status = self._blocked_status(query_name, unsatisfied_requirements, rejected)
            return SynthesisResult(
                status=status,
                query=query_name,
                threat_model=threat_model,
                contract=[],
                cost=CostVector(),
                scalar_cost=0.0,
                iterations=0,
                worlds=len(self.worlds),
                certificates_seen=0,
                derived_requirements=list(requirements),
                rejected_mechanisms=rejected,
                notes=[
                    "No admissible mechanism provides every derived structural requirement.",
                    f"Unsatisfied requirements: {sorted(unsatisfied_requirements)}",
                ],
            )

        selected = _minimum_weight_contract(constraints, costs, dependencies)
        if selected is None:
            return self._unsatisfiable_result(
                query_name, threat_model, requirements, rejected, "Dependency closure is unsatisfiable."
            )

        certificates_seen = 0
        for iteration in range(1, max_iterations + 1):
            check = self.check_contract(
                query_name,
                sorted(selected),
                threat_model=threat_model,
                candidate_modes=modes,
            )
            if check.auditable:
                active_selected = any(
                    self.spec.mechanisms[name].mode == "active" for name in selected
                )
                status = "AUDITABLE" if active_selected else "PASSIVE_AUDITABLE"
                minimality = self._minimality_witnesses(
                    query_name, selected, threat_model, modes
                )
                return SynthesisResult(
                    status=status,
                    query=query_name,
                    threat_model=threat_model,
                    contract=sorted(selected),
                    cost=self.contract_cost(sorted(selected)),
                    scalar_cost=sum(costs[name] for name in selected),
                    iterations=iteration,
                    worlds=len(self.worlds),
                    certificates_seen=certificates_seen,
                    derived_requirements=list(requirements),
                    rejected_mechanisms=rejected,
                    minimality_witnesses=minimality,
                    notes=[
                        "Exact only for the declared finite worlds and threat model.",
                        "Cost minimality is conditional on the frozen candidate catalog, dependency graph and scalar weights.",
                        "The backend adapts established critical-pair / counterexample-guided minimum-observation synthesis.",
                    ],
                )

            if check.certificate is None:
                return self._unsatisfiable_result(
                    query_name,
                    threat_model,
                    requirements,
                    rejected,
                    f"Structural assurance failed: unmet={check.unmet_requirements}, dependencies={check.missing_dependencies}",
                )

            certificate = check.certificate
            certificates_seen += 1
            separators = frozenset(
                name for name in certificate.separating_candidates if name in eligible
            )
            if not separators:
                status = self._blocked_status(query_name, [], rejected)
                return SynthesisResult(
                    status=status,
                    query=query_name,
                    threat_model=threat_model,
                    contract=sorted(selected),
                    cost=self.contract_cost(sorted(selected)),
                    scalar_cost=sum(costs[name] for name in selected),
                    iterations=iteration,
                    worlds=len(self.worlds),
                    certificates_seen=certificates_seen,
                    derived_requirements=list(requirements),
                    rejected_mechanisms=rejected,
                    unresolved_certificate=certificate,
                    notes=[
                        "The critical pair is not separable by any admissible mechanism.",
                        "Expand the trusted capture surface, mechanism catalog, or validated replay capability.",
                    ],
                )
            if separators not in constraints:
                constraints.append(separators)
            selected = _minimum_weight_contract(constraints, costs, dependencies)
            if selected is None:
                return self._unsatisfiable_result(
                    query_name,
                    threat_model,
                    requirements,
                    rejected,
                    "Accumulated counterexample and dependency constraints are unsatisfiable.",
                )

        return SynthesisResult(
            status="INCONCLUSIVE",
            query=query_name,
            threat_model=threat_model,
            contract=sorted(selected),
            cost=self.contract_cost(sorted(selected)),
            scalar_cost=sum(costs[name] for name in selected),
            iterations=max_iterations,
            worlds=len(self.worlds),
            certificates_seen=certificates_seen,
            derived_requirements=list(requirements),
            rejected_mechanisms=rejected,
            notes=["Counterexample iteration limit reached."],
        )

    def _blocked_status(
        self,
        query_name: str,
        unsatisfied_requirements: Sequence[str],
        rejected: Mapping[str, Sequence[str]],
    ) -> str:
        query = self.spec.queries[query_name]
        if query.kind != "causality":
            return "NOT_AUDITABLE_UNDER_CURRENT_TCB"
        target = query.intervention_target
        replay_requirement = f"replay:{target}:verified"
        rejected_target = [
            name
            for name, mechanism in self.spec.mechanisms.items()
            if mechanism.mode == "active"
            and mechanism.replay is not None
            and mechanism.replay.target == target
            and name in rejected
        ]
        if replay_requirement in unsatisfied_requirements or rejected_target:
            return "UNREALIZABLE_INTERVENTION"
        return "NOT_AUDITABLE_UNDER_CURRENT_TCB"

    def _unsatisfiable_result(
        self,
        query_name: str,
        threat_model: str,
        requirements: Sequence[str],
        rejected: dict[str, list[str]],
        reason: str,
    ) -> SynthesisResult:
        return SynthesisResult(
            status=self._blocked_status(query_name, requirements, rejected),
            query=query_name,
            threat_model=threat_model,
            contract=[],
            cost=CostVector(),
            scalar_cost=0.0,
            iterations=0,
            worlds=len(self.worlds),
            certificates_seen=0,
            derived_requirements=list(requirements),
            rejected_mechanisms=rejected,
            notes=[reason],
        )

    def _minimality_witnesses(
        self,
        query_name: str,
        selected: set[str],
        threat_model: str,
        modes: set[str],
    ) -> dict[str, dict[str, Any]]:
        witnesses: dict[str, dict[str, Any]] = {}
        for mechanism_name in sorted(selected):
            reduced = sorted(selected - {mechanism_name})
            check = self.check_contract(
                query_name,
                reduced,
                threat_model=threat_model,
                candidate_modes=modes,
            )
            if check.certificate is not None:
                witnesses[mechanism_name] = {
                    "type": "critical_pair",
                    "certificate": check.certificate.as_dict(),
                }
            elif check.unmet_requirements or check.missing_dependencies:
                witnesses[mechanism_name] = {
                    "type": "structural_assurance",
                    "unmet_requirements": list(check.unmet_requirements),
                    "missing_dependencies": list(check.missing_dependencies),
                }
        return witnesses

    def contract_cost(self, contract: Sequence[str]) -> CostVector:
        total = CostVector()
        for name in sorted(set(contract)):
            total = total + self.spec.mechanisms[name].cost
        return total

    def compile_instrumentation(
        self, contract: Sequence[str]
    ) -> list[InstrumentationItem]:
        items: list[InstrumentationItem] = []
        for name in sorted(set(contract)):
            mechanism = self.spec.mechanisms[name]
            items.append(
                InstrumentationItem(
                    mechanism=name,
                    mode=mechanism.mode,
                    producer=mechanism.producer,
                    capture_point=mechanism.capture_point,
                    adapter=mechanism.adapter,
                    capture=mechanism.capture,
                    facts=mechanism.facts,
                    observations=mechanism.observations,
                    binding_edges=mechanism.binding_edges,
                    capabilities=mechanism.capabilities,
                    requires=mechanism.requires,
                    integrity=mechanism.integrity,
                    replay=mechanism.replay,
                )
            )
        return items

    def verify_certificate(self, certificate: TwinCertificate) -> bool:
        if certificate.schema_version != "AuditSpec-non-auditability-certificate-v2":
            return False
        if certificate.spec_digest != spec_digest(self.spec):
            return False
        if certificate.spec_name != self.spec.name:
            return False
        if certificate.query not in self.spec.queries:
            return False
        if certificate.threat_model not in self.spec.threat_models:
            return False
        if tuple(sorted(set(certificate.contract))) != certificate.contract:
            return False
        if not self._world_is_canonical_member(certificate.world_a):
            return False
        if not self._world_is_canonical_member(certificate.world_b):
            return False
        try:
            if not all(
                bool(evaluate(expr, certificate.world_a))
                and bool(evaluate(expr, certificate.world_b))
                for expr in self.spec.constraints
            ):
                return False
            eligible, _ = self.eligible_mechanisms(
                certificate.threat_model, {"passive", "active"}
            )
        except (KeyError, ValueError):
            return False
        if set(certificate.contract) - set(eligible):
            return False
        if self.query_answer(certificate.query, certificate.world_a) != certificate.answer_a:
            return False
        if self.query_answer(certificate.query, certificate.world_b) != certificate.answer_b:
            return False
        if certificate.answer_a == certificate.answer_b:
            return False
        observation_a = self.observation(certificate.world_a, certificate.contract)
        observation_b = self.observation(certificate.world_b, certificate.contract)
        if observation_a != observation_b:
            return False
        expected_shared = {name: observations for name, observations in observation_a}
        if certificate.shared_observation != expected_shared:
            return False
        expected_separators = tuple(
            sorted(
                name
                for name, mechanism in eligible.items()
                if mechanism.observe(certificate.world_a)
                != mechanism.observe(certificate.world_b)
            )
        )
        if certificate.separating_candidates != expected_separators:
            return False
        return certificate.derived_requirements == self.derived_requirements(
            certificate.query
        )

    def ambiguity_metrics(
        self,
        query_name: str,
        contract: Sequence[str],
        threat_model: str = "cooperative",
    ) -> dict[str, float | int | bool | list[str]]:
        check = self.check_contract(query_name, contract, threat_model=threat_model)
        buckets: dict[tuple[Any, ...], dict[Any, int]] = defaultdict(lambda: defaultdict(int))
        for world, answer in zip(self.worlds, self.query_answers(query_name)):
            buckets[self.observation(world, contract)][answer] += 1
        ambiguous_worlds = 0
        errors = 0
        ambiguous_buckets = 0
        for counts in buckets.values():
            size = sum(counts.values())
            if len(counts) > 1:
                ambiguous_buckets += 1
                ambiguous_worlds += size
            errors += size - max(counts.values())
        total = len(self.worlds)
        return {
            "worlds": total,
            "observation_buckets": len(buckets),
            "ambiguous_buckets": ambiguous_buckets,
            "ambiguous_world_fraction": ambiguous_worlds / total,
            "bayes_error_lower_bound": errors / total,
            "structural_assurance_valid": not (
                check.unmet_requirements or check.missing_dependencies
            ),
            "unmet_requirements": list(check.unmet_requirements),
            "missing_dependencies": list(check.missing_dependencies),
        }

    def sampled_weight_solutions(
        self,
        query_name: str,
        threat_model: str = "cooperative",
        weight_grid: Sequence[Mapping[str, float]] | None = None,
    ) -> list[SynthesisResult]:
        weight_grid = weight_grid or [
            {"bytes": 1, "privacy": 0, "latency_ms": 0, "fragility": 0},
            {"bytes": 0, "privacy": 1, "latency_ms": 0, "fragility": 0},
            {"bytes": 0, "privacy": 0, "latency_ms": 1, "fragility": 0},
            {"bytes": 0, "privacy": 0, "latency_ms": 0, "fragility": 1},
            DEFAULT_WEIGHTS,
            {"bytes": 0.001, "privacy": 3, "latency_ms": 1, "fragility": 2},
        ]
        unique: dict[tuple[str, ...], SynthesisResult] = {}
        for weights in weight_grid:
            result = self.synthesize(
                query_name,
                threat_model=threat_model,
                mode="auto",
                weights=weights,
            )
            unique.setdefault(tuple(result.contract), result)
        values = list(unique.values())
        pareto: list[SynthesisResult] = []
        for candidate in values:
            c = candidate.cost
            dominated = False
            for other in values:
                if other is candidate:
                    continue
                o = other.cost
                no_worse = (
                    o.bytes <= c.bytes
                    and o.privacy <= c.privacy
                    and o.latency_ms <= c.latency_ms
                    and o.fragility <= c.fragility
                )
                strictly_better = (
                    o.bytes < c.bytes
                    or o.privacy < c.privacy
                    or o.latency_ms < c.latency_ms
                    or o.fragility < c.fragility
                )
                if no_worse and strictly_better:
                    dominated = True
                    break
            if not dominated:
                pareto.append(candidate)
        return sorted(
            pareto,
            key=lambda result: (
                result.cost.bytes,
                result.cost.privacy,
                result.cost.latency_ms,
                result.cost.fragility,
            ),
        )

    def weighted_frontier(
        self,
        query_name: str,
        threat_model: str = "cooperative",
        weight_grid: Sequence[Mapping[str, float]] | None = None,
    ) -> list[SynthesisResult]:
        """Deprecated compatibility alias; this is not an exhaustive frontier."""

        import warnings

        warnings.warn(
            "weighted_frontier() samples weighted solutions and is not a complete Pareto frontier; use sampled_weight_solutions()",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.sampled_weight_solutions(
            query_name, threat_model=threat_model, weight_grid=weight_grid
        )


def _dependency_closure(
    chosen: set[str],
    dependencies: Mapping[str, Sequence[str]],
    allowed: set[str],
) -> set[str] | None:
    closure = set(chosen)
    pending = list(chosen)
    while pending:
        current = pending.pop()
        for dependency in dependencies.get(current, ()):
            if dependency not in allowed:
                return None
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)
    return closure


def _minimum_weight_contract(
    constraints: Sequence[frozenset[str]],
    costs: Mapping[str, float],
    dependencies: Mapping[str, Sequence[str]],
) -> set[str] | None:
    """Exact weighted hitting set with transitive mechanism dependency closure."""

    reduced: list[frozenset[str]] = []
    for constraint in sorted(set(constraints), key=lambda item: (len(item), sorted(item))):
        filtered = frozenset(name for name in constraint if name in costs)
        if not filtered:
            return None
        if any(existing <= filtered for existing in reduced):
            continue
        reduced = [existing for existing in reduced if not filtered < existing]
        reduced.append(filtered)

    allowed = set(costs)
    best_set: set[str] | None = None
    best_cost = float("inf")

    def recurse(selected: set[str], remaining: list[frozenset[str]]) -> None:
        nonlocal best_set, best_cost
        current_cost = sum(costs[name] for name in selected)
        if current_cost > best_cost:
            return
        if not remaining:
            candidate_key = tuple(sorted(selected))
            best_key = tuple(sorted(best_set)) if best_set is not None else None
            if current_cost < best_cost or (
                current_cost == best_cost and (best_key is None or candidate_key < best_key)
            ):
                best_set = set(selected)
                best_cost = current_cost
            return

        pivot = min(
            remaining,
            key=lambda constraint: (
                len(constraint),
                sum(costs[name] for name in constraint),
                tuple(sorted(constraint)),
            ),
        )
        coverage = {
            name: sum(1 for constraint in remaining if name in constraint) for name in pivot
        }
        choices = sorted(
            pivot,
            key=lambda name: (
                costs[name] / max(coverage[name], 1),
                costs[name],
                name,
            ),
        )
        for name in choices:
            closed = _dependency_closure(selected | {name}, dependencies, allowed)
            if closed is None:
                continue
            if sum(costs[item] for item in closed) > best_cost:
                continue
            new_remaining = [
                constraint for constraint in remaining if not (constraint & closed)
            ]
            recurse(closed, new_remaining)

    recurse(set(), reduced)
    return best_set
