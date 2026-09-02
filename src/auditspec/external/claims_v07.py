"""v0.7 query-specific external claim registry.

The frozen registry (``experiments/v07_external_claim_registry.json``) gives
every claim its own minimal mechanism contract and an expected verdict.
Claims whose oracle cannot be exported from the benchmark are first-class
typed negatives: their contract is ``None`` and they must always be refused
with the declared gap verdict (:class:`AssuranceVerdict.MODEL_GAP` or
``EVIDENCE_GAP``), never proved.

This module loads and types the frozen document and evaluates the frozen
applicability rules against episode metadata. Deriving the oracle inputs
themselves (state diffs, API logs, replay interventions, policy hashes) from
retained episode artifacts happens offline in
``experiments/derive_v07_oracles.py``; ``evidence.py`` materializes them into
signed receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
import functools
import json
from pathlib import Path
from typing import Any, Mapping

from ..model_adequacy import AssuranceVerdict


V07_REGISTRY_SCHEMA = "AuditSpec-v07-external-claim-registry-v1"
_DEFAULT_REGISTRY_PATH = (
    Path(__file__).resolve().parents[3]
    / "experiments"
    / "v07_external_claim_registry.json"
)


# Episode metadata keys consumed by the v0.7 applicability predicates.
# The offline oracle deriver (experiments/derive_v07_oracles.py) emits exactly
# these keys per episode so evaluation can replay eligibility decisions.
#
# Shared:
#   environment (str), slot_k (int, default 1 for slot claims T03/A02/A04)
# tau2:
#   domain (str: airline | banking_knowledge | telecom)
#   reward_basis (sequence of RewardType values, e.g. ["DB", "COMMUNICATE"])
#   num_env_assertions (int)
#   agent_write_call_count (int): trajectory tool calls by the agent whose
#       tool carries the benchmark's WRITE annotation (tau2 mutates_state)
#   task_declares_communicate_info (bool)
# AppWorld:
#   num_requirements (int), num_no_op_pass (int) from ground_truth test_data
#   has_changed_set_assertion (bool): evaluation.py asserts exact
#       changed_model_names() set equality
#   effectful_call_count (int): conservative effectful definition —
#       api_calls.jsonl entries with method in {post, put, patch, delete},
#       excluding the known non-mutating login endpoint "/<app>/auth/token"
#       (JWT signing only, no DB write)
#   authenticated_effectful_call_count (int): effectful entries carrying an
#       access_token field
#   payment_call_count (int): payment-related calls (venmo transactions /
#       payment_requests, amazon orders / payment_cards)
#   placed_order (bool): at least one POST /amazon/orders

def _require(context: Mapping[str, Any], key: str, claim_id: str) -> Any:
    if key not in context or context[key] is None:
        raise ValueError(
            f"episode context for {claim_id} is missing required key {key!r}"
        )
    return context[key]


def _slot_k(context: Mapping[str, Any]) -> int:
    return int(context.get("slot_k", 1))


_APPLICABILITY_PREDICATES: dict[str, Any] = {
    "T01": lambda c: True,
    "T02": lambda c: "DB"
    in {str(basis) for basis in _require(c, "reward_basis", "T02")},
    "T03": lambda c: _require(c, "domain", "T03") == "telecom"
    and int(_require(c, "num_env_assertions", "T03")) >= _slot_k(c),
    "T04": lambda c: True,
    "T05": lambda c: True,
    "T06": lambda c: True,
    "T07": lambda c: True,  # all tau2 domains record SimulationRun.policy
    "T08": lambda c: int(_require(c, "agent_write_call_count", "T08")) >= 1,
    "T09": lambda c: True,
    "T10": lambda c: True,
    "T11": lambda c: True,
    "T12": lambda c: _require(c, "domain", "T12") == "airline"
    and bool(_require(c, "task_declares_communicate_info", "T12")),
    "A01": lambda c: True,
    "A02": lambda c: int(_require(c, "num_requirements", "A02")) >= _slot_k(c),
    "A03": lambda c: bool(_require(c, "has_changed_set_assertion", "A03")),
    "A04": lambda c: int(_require(c, "num_no_op_pass", "A04")) >= _slot_k(c),
    "A05": lambda c: int(_require(c, "authenticated_effectful_call_count", "A05"))
    >= 1,
    "A06": lambda c: True,
    "A07": lambda c: int(_require(c, "effectful_call_count", "A07")) >= 1,
    "A08": lambda c: int(_require(c, "effectful_call_count", "A08")) >= 1,
    "A09": lambda c: True,
    "A10": lambda c: int(_require(c, "payment_call_count", "A10")) >= 1,
    "A11": lambda c: True,
    "A12": lambda c: bool(_require(c, "placed_order", "A12")),
}


@dataclass(frozen=True)
class V07ClaimDefinition:
    """One frozen v0.7 claim with its per-claim minimal contract."""

    claim_id: str
    environment: str
    claim_class: str
    statement: str
    oracle_check_id: str | None
    oracle_source: str
    applicability: str
    minimal_contract: frozenset[str] | None
    expected_verdict: str
    gap_reason: str | None = None

    @property
    def is_typed_negative(self) -> bool:
        return self.minimal_contract is None

    @property
    def declared_gap(self) -> AssuranceVerdict | None:
        """Gap verdict a typed negative must produce; ``None`` otherwise."""

        if not self.is_typed_negative:
            return None
        try:
            return AssuranceVerdict(self.expected_verdict)
        except ValueError as exc:
            raise ValueError(
                f"typed negative {self.claim_id} must declare a gap verdict, "
                f"got {self.expected_verdict!r}"
            ) from exc

    def applies_to(self, episode_context: Mapping[str, Any] | None = None) -> bool:
        """Evaluate the frozen applicability rule against episode metadata.

        With no context the claim is treated as applicable to every episode of
        its own environment (the stage-A default). A provided context must
        carry every metadata key the claim's rule reads (see the key list at
        the top of this module); a missing key is a caller bug and raises.
        """

        if episode_context is None:
            return True
        environment = episode_context.get("environment")
        if environment is not None and environment != self.environment:
            return False
        predicate = _APPLICABILITY_PREDICATES.get(self.claim_id)
        if predicate is None:
            raise ValueError(f"no applicability predicate for {self.claim_id}")
        return bool(predicate(episode_context))


@dataclass(frozen=True)
class EvidenceStack:
    """One honestly specified installation of evidence mechanisms."""

    stack_id: str
    installed: frozenset[str]

    def covers(self, claim: V07ClaimDefinition) -> bool:
        """Contract-subset half of the frozen ``stack_support_rule``."""

        return (
            claim.minimal_contract is not None
            and claim.minimal_contract <= self.installed
        )


@dataclass(frozen=True)
class V07ClaimRegistry:
    claims: Mapping[str, V07ClaimDefinition]
    stacks: Mapping[str, EvidenceStack]
    mechanism_costs: Mapping[str, int]
    stack_support_rule: str

    @property
    def provable_claims(self) -> tuple[V07ClaimDefinition, ...]:
        return tuple(
            claim for claim in self.claims.values() if not claim.is_typed_negative
        )

    @property
    def typed_negatives(self) -> tuple[V07ClaimDefinition, ...]:
        return tuple(
            claim for claim in self.claims.values() if claim.is_typed_negative
        )


def load_v07_claim_registry(
    path: str | Path | None = None,
) -> V07ClaimRegistry:
    """Load the frozen per-claim registry document."""

    registry_path = Path(path) if path is not None else _DEFAULT_REGISTRY_PATH
    document = json.loads(registry_path.read_text(encoding="utf-8"))
    if document.get("schema") != V07_REGISTRY_SCHEMA:
        raise ValueError("unsupported v07 external claim registry schema")
    claims: dict[str, V07ClaimDefinition] = {}
    for item in document["claims"]:
        contract = item["minimal_contract"]
        oracle = item.get("oracle") or {}
        claim = V07ClaimDefinition(
            claim_id=str(item["id"]),
            environment=str(item["environment"]),
            claim_class=str(item["class"]),
            statement=str(item["statement"]),
            oracle_check_id=(
                str(oracle["check_id"]) if oracle.get("check_id") is not None else None
            ),
            oracle_source=str(oracle.get("source", "")),
            applicability=str(item["applicability"]),
            minimal_contract=(
                frozenset(str(mechanism) for mechanism in contract)
                if contract is not None
                else None
            ),
            expected_verdict=str(item["expected_verdict"]),
            gap_reason=(
                str(item["gap_reason"]) if item.get("gap_reason") is not None else None
            ),
        )
        if claim.claim_id in claims:
            raise ValueError(f"duplicate v07 claim id: {claim.claim_id}")
        if claim.is_typed_negative:
            claim.declared_gap  # validate the declared gap eagerly
        claims[claim.claim_id] = claim
    stacks = {
        str(item["id"]): EvidenceStack(
            stack_id=str(item["id"]),
            installed=frozenset(str(mechanism) for mechanism in item["installed"]),
        )
        for item in document["evidence_stacks"]
    }
    mechanism_costs = {
        str(item["id"]): int(item["cost"])
        for item in document["candidate_mechanisms"]
    }
    unknown = {
        mechanism
        for claim in claims.values()
        for mechanism in (claim.minimal_contract or frozenset())
    } - set(mechanism_costs)
    if unknown:
        raise ValueError(f"v07 contracts reference unknown mechanisms: {sorted(unknown)}")
    return V07ClaimRegistry(
        claims=claims,
        stacks=stacks,
        mechanism_costs=mechanism_costs,
        stack_support_rule=str(document["stack_support_rule"]),
    )


@functools.lru_cache(maxsize=1)
def v07_claim_registry() -> V07ClaimRegistry:
    """Cached load of the default frozen registry."""

    return load_v07_claim_registry()
