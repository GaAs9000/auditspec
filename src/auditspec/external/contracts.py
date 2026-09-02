"""v0.7 per-claim contract synthesis over the candidate mechanism catalog.

Each provable v0.7 claim carries derived requirements obtained from its
oracle semantics (design document section 4, "oracle source" column): a
requirement names a set of candidate mechanisms, at least one of which must
be installed to satisfy it. The minimum sufficient contract is the
minimum-cost hitting set over those requirements, computed with the same
weighted hitting-set solver the compiler uses
(:func:`auditspec.compiler._minimum_weight_contract`).

In the v0.7 draft every derived requirement is a singleton — the benchmark
oracle inventory admits exactly one mechanism per requirement — so the
solver certifies minimality of the union rather than choosing between
alternatives. The constraint form is kept general so a requirement with
alternative realizations needs no code change at freeze time.

Typed negatives have no derived requirements; synthesis returns their
declared gap verdict instead of a mechanism set. The frozen registry's
first freeze blocker ("solver recomputation of every minimal_contract must
reproduce this registry exactly") is discharged by
:func:`registry_contract_mismatches`.
"""

from __future__ import annotations

from typing import Mapping

from ..compiler import _minimum_weight_contract
from ..model_adequacy import AssuranceVerdict
from .claims_v07 import V07ClaimDefinition, V07ClaimRegistry


# Derived requirements shared by every provable claim: the evidence must be
# bound to the run/task and the claim, and it must be produced and captured
# inside the trusted boundary.
_BASE_REQUIREMENTS: Mapping[str, frozenset[str]] = {
    "bind_run_to_task": frozenset({"run_task_binding"}),
    "bind_run_to_claim": frozenset({"run_claim_binding"}),
    "authenticated_producer": frozenset({"trusted_producer"}),
    "trusted_capture": frozenset({"trusted_capture_point"}),
}

# Additional requirements for claims answered by an independent evaluator
# replay witness (the v0.6 envelope minus the base requirements).
_EVALUATOR_REPLAY_REQUIREMENTS: Mapping[str, frozenset[str]] = {
    "independent_answer": frozenset({"independent_verifier_witness"}),
    "bind_run_to_witness": frozenset({"run_witness_binding"}),
    "pin_benchmark_revision": frozenset({"task_revision_binding"}),
    "cover_effect_paths": frozenset({"mandatory_path_coverage"}),
    "accepted_verifier_identity": frozenset({"accepted_verifier"}),
}

_ITEM_COMPONENTS_REQUIREMENT: Mapping[str, frozenset[str]] = {
    "item_level_components": frozenset({"witness_components"}),
}


def _requirements(
    *blocks: Mapping[str, frozenset[str]],
) -> dict[str, frozenset[str]]:
    merged: dict[str, frozenset[str]] = {}
    for block in blocks:
        merged.update(block)
    return merged


# Per-claim derived requirements, the machine-readable form of the design
# document section 4 oracle-source column. Typed negatives (T09-T12,
# A10-A12) are absent: no mechanism set can satisfy them.
DERIVED_REQUIREMENTS: Mapping[str, Mapping[str, frozenset[str]]] = {
    "T01": _requirements(_BASE_REQUIREMENTS, _EVALUATOR_REPLAY_REQUIREMENTS),
    "T02": _requirements(_BASE_REQUIREMENTS, _EVALUATOR_REPLAY_REQUIREMENTS),
    "T03": _requirements(
        _BASE_REQUIREMENTS,
        _EVALUATOR_REPLAY_REQUIREMENTS,
        _ITEM_COMPONENTS_REQUIREMENT,
    ),
    "T04": _requirements(
        _BASE_REQUIREMENTS,
        {"cover_effect_paths": frozenset({"mandatory_path_coverage"})},
        {"pre_post_state_diff": frozenset({"state_diff_receipt"})},
    ),
    "T05": _requirements(_BASE_REQUIREMENTS),
    "T06": _requirements(
        _BASE_REQUIREMENTS,
        {"cover_effect_paths": frozenset({"mandatory_path_coverage"})},
    ),
    "T07": _requirements(
        _BASE_REQUIREMENTS,
        {"served_policy_hash": frozenset({"policy_text_hash_binding"})},
    ),
    "T08": _requirements(
        _BASE_REQUIREMENTS,
        {"pin_benchmark_revision": frozenset({"task_revision_binding"})},
        {"replay_intervention": frozenset({"replay_intervention_witness"})},
    ),
    "A01": _requirements(_BASE_REQUIREMENTS, _EVALUATOR_REPLAY_REQUIREMENTS),
    "A02": _requirements(
        _BASE_REQUIREMENTS,
        _EVALUATOR_REPLAY_REQUIREMENTS,
        _ITEM_COMPONENTS_REQUIREMENT,
    ),
    "A03": _requirements(
        _BASE_REQUIREMENTS,
        {"pin_benchmark_revision": frozenset({"task_revision_binding"})},
        {"cover_effect_paths": frozenset({"mandatory_path_coverage"})},
        {"pre_post_state_diff": frozenset({"state_diff_receipt"})},
    ),
    "A04": _requirements(
        _BASE_REQUIREMENTS,
        _EVALUATOR_REPLAY_REQUIREMENTS,
        _ITEM_COMPONENTS_REQUIREMENT,
    ),
    "A05": _requirements(
        _BASE_REQUIREMENTS,
        {"cover_effect_paths": frozenset({"mandatory_path_coverage"})},
        {"full_request_log": frozenset({"api_call_log_receipt"})},
    ),
    "A06": _requirements(
        _BASE_REQUIREMENTS,
        {"cover_effect_paths": frozenset({"mandatory_path_coverage"})},
        {"full_request_log": frozenset({"api_call_log_receipt"})},
    ),
    "A07": _requirements(
        _BASE_REQUIREMENTS,
        {"full_request_log": frozenset({"api_call_log_receipt"})},
    ),
    "A08": _requirements(
        _BASE_REQUIREMENTS,
        {"pin_benchmark_revision": frozenset({"task_revision_binding"})},
        {"replay_intervention": frozenset({"replay_intervention_witness"})},
    ),
    "A09": _requirements(
        {
            name: options
            for name, options in _BASE_REQUIREMENTS.items()
            if name != "trusted_capture"
        },
        {"version_fingerprints": frozenset({"version_fingerprint_witness"})},
    ),
}


def requirements_satisfied(
    requirements: Mapping[str, frozenset[str]],
    mechanisms: frozenset[str] | set[str],
) -> bool:
    """Return whether ``mechanisms`` hits every derived requirement."""

    return all(bool(options & mechanisms) for options in requirements.values())


def synthesize_claim_contract(
    claim_def: V07ClaimDefinition,
    mechanism_costs: Mapping[str, int],
    *,
    derived_requirements: Mapping[
        str, Mapping[str, frozenset[str]]
    ] = DERIVED_REQUIREMENTS,
) -> frozenset[str] | AssuranceVerdict:
    """Compute the minimum-cost contract for one claim.

    Returns the minimum-cost mechanism set for provable claims, or the
    declared gap verdict (``MODEL_GAP`` / ``EVIDENCE_GAP``) for typed
    negatives, which have no machine-checkable contract by construction.
    """

    if claim_def.is_typed_negative:
        gap = claim_def.declared_gap
        assert gap is not None  # validated at registry load
        return gap
    requirements = derived_requirements.get(claim_def.claim_id)
    if requirements is None:
        raise ValueError(
            f"no derived requirements for provable claim {claim_def.claim_id}"
        )
    contract = _minimum_weight_contract(
        tuple(requirements.values()),
        {name: float(cost) for name, cost in mechanism_costs.items()},
        {},
    )
    if contract is None:
        raise ValueError(
            f"derived requirements for {claim_def.claim_id} are unsatisfiable "
            "over the candidate mechanism catalog"
        )
    return frozenset(contract)


def registry_contract_mismatches(
    registry: V07ClaimRegistry,
    *,
    derived_requirements: Mapping[
        str, Mapping[str, frozenset[str]]
    ] = DERIVED_REQUIREMENTS,
) -> tuple[str, ...]:
    """Claims whose frozen registry entry disagrees with synthesis.

    An empty tuple discharges the registry's solver-recomputation freeze
    blocker; any mismatch names the claim whose ``minimal_contract`` (or
    typed-negative status) must be corrected before freeze.
    """

    mismatches: list[str] = []
    for claim_id, claim in sorted(registry.claims.items()):
        synthesized = synthesize_claim_contract(
            claim,
            registry.mechanism_costs,
            derived_requirements=derived_requirements,
        )
        if isinstance(synthesized, AssuranceVerdict):
            if not claim.is_typed_negative or claim.declared_gap != synthesized:
                mismatches.append(claim_id)
        elif claim.minimal_contract != synthesized:
            mismatches.append(claim_id)
    return tuple(mismatches)
