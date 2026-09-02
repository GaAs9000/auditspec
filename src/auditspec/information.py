from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Hashable, Mapping, Sequence

from .compiler import AuditCompiler


@dataclass(frozen=True)
class InformationLeakage:
    """Uniform finite-world information and Bayes-reconstruction metrics."""

    sensitive_facts: tuple[str, ...]
    worlds: int
    sensitive_states: int
    evidence_states: int
    sensitive_entropy_bits: float
    evidence_entropy_bits: float
    mutual_information_bits: float
    normalized_mutual_information: float
    conditional_mutual_information_given_answer_bits: float
    prior_bayes_accuracy: float
    answer_only_bayes_accuracy: float
    evidence_bayes_accuracy: float
    evidence_and_answer_bayes_accuracy: float
    bayes_gain_over_prior: float
    bayes_gain_over_answer: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def information_leakage(
    compiler: AuditCompiler,
    query_name: str,
    contract: Sequence[str],
    *,
    sensitive_facts: Sequence[str] | None = None,
) -> InformationLeakage:
    """Measure disclosure under the uniform distribution on satisfying worlds.

    These are exact empirical quantities for the supplied finite model, not a
    population estimate or a cryptographic privacy guarantee.  The evidence
    variable is the joint observation emitted by ``contract``.  Bayes accuracy
    is the optimal reconstruction rate for the complete sensitive tuple.
    """

    facts = tuple(
        sensitive_facts
        if sensitive_facts is not None
        else sorted(
            name for name, fact in compiler.spec.facts.items() if fact.sensitivity > 0
        )
    )
    unknown = set(facts) - compiler.spec.facts.keys()
    if unknown:
        raise ValueError(f"Unknown sensitive facts: {sorted(unknown)}")
    if not compiler.worlds:
        raise ValueError("Information leakage needs at least one world")

    states: list[Hashable] = [tuple(world[name] for name in facts) for world in compiler.worlds]
    evidence: list[Hashable] = [
        compiler.observation(world, contract) for world in compiler.worlds
    ]
    answers: list[Hashable] = [
        compiler.query_answer(query_name, world) for world in compiler.worlds
    ]

    h_sensitive = _entropy(states)
    h_evidence = _entropy(evidence)
    mi = _mutual_information(states, evidence)
    conditional_mi = _conditional_mutual_information(states, evidence, answers)
    prior = _bayes_accuracy(states, [None] * len(states))
    answer_only = _bayes_accuracy(states, answers)
    evidence_only = _bayes_accuracy(states, evidence)
    evidence_answer = _bayes_accuracy(
        states, list(zip(evidence, answers, strict=True))
    )
    normalized = mi / h_sensitive if h_sensitive > 0 else 0.0
    return InformationLeakage(
        sensitive_facts=facts,
        worlds=len(states),
        sensitive_states=len(set(states)),
        evidence_states=len(set(evidence)),
        sensitive_entropy_bits=h_sensitive,
        evidence_entropy_bits=h_evidence,
        mutual_information_bits=mi,
        normalized_mutual_information=normalized,
        conditional_mutual_information_given_answer_bits=conditional_mi,
        prior_bayes_accuracy=prior,
        answer_only_bayes_accuracy=answer_only,
        evidence_bayes_accuracy=evidence_only,
        evidence_and_answer_bayes_accuracy=evidence_answer,
        bayes_gain_over_prior=evidence_only - prior,
        bayes_gain_over_answer=evidence_answer - answer_only,
    )


def query_sensitive_facts(
    compiler: AuditCompiler, query_name: str
) -> tuple[str, ...]:
    return tuple(
        name
        for name in compiler.query_dependencies(query_name)
        if compiler.spec.facts[name].sensitivity > 0
    )


def _entropy(values: Sequence[Hashable]) -> float:
    counts = Counter(values)
    total = len(values)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def _conditional_entropy(
    targets: Sequence[Hashable], conditions: Sequence[Hashable]
) -> float:
    if len(targets) != len(conditions):
        raise ValueError("Target and condition lengths differ")
    total = len(targets)
    joint = Counter(zip(targets, conditions, strict=True))
    condition_counts = Counter(conditions)
    return sum(
        (count / total)
        * -math.log2(count / condition_counts[condition])
        for (target, condition), count in joint.items()
    )


def _mutual_information(
    left: Sequence[Hashable], right: Sequence[Hashable]
) -> float:
    value = _entropy(left) - _conditional_entropy(left, right)
    return max(0.0, value)


def _conditional_mutual_information(
    sensitive: Sequence[Hashable],
    evidence: Sequence[Hashable],
    answer: Sequence[Hashable],
) -> float:
    h_sensitive_given_answer = _conditional_entropy(sensitive, answer)
    evidence_answer = list(zip(evidence, answer, strict=True))
    h_sensitive_given_both = _conditional_entropy(sensitive, evidence_answer)
    return max(0.0, h_sensitive_given_answer - h_sensitive_given_both)


def _bayes_accuracy(
    targets: Sequence[Hashable], observations: Sequence[Hashable]
) -> float:
    if len(targets) != len(observations):
        raise ValueError("Target and observation lengths differ")
    buckets: dict[Hashable, Counter[Hashable]] = {}
    for target, observation in zip(targets, observations, strict=True):
        buckets.setdefault(observation, Counter())[target] += 1
    return sum(max(counts.values()) for counts in buckets.values()) / len(targets)
