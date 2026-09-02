"""VerifiedContract construction for the design-time Core slice."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import digest
from .claim_ir import ClaimIR, ScopedClaim
from .finite_backend import SynthesisPass
from .finite_model import AdequacyPass, FiniteDomain
from .mechanism_ir import MechanismCatalog
from .refs import RegistryStore, RootedRef


@dataclass(frozen=True)
class VerifiedContract:
    wire_without_digest: dict[str, Any]
    contract_digest: str

    @property
    def contract_id(self) -> str:
        return str(self.wire_without_digest["contract_id"])

    @property
    def selected_mechanisms(self) -> tuple[str, ...]:
        return tuple(self.wire_without_digest["selected_mechanisms"])

    def to_wire(self) -> dict[str, Any]:
        return {**self.wire_without_digest, "contract_digest": self.contract_digest}


def build_verified_contract(
    *,
    claim: ClaimIR,
    scoped: ScopedClaim,
    scoped_ref: RootedRef,
    domain: FiniteDomain,
    adequacy: AdequacyPass,
    synthesis: SynthesisPass,
    catalog: MechanismCatalog,
    compiler_root: str,
    threat_model_root: str,
    schema_registry_root: str,
    verifier_ref: RootedRef,
    optimization_witness_ref: RootedRef,
    optimization_witness_digest: str,
    premise_witness_ref: RootedRef,
    policy_witness_ref: RootedRef,
    lifecycle_policy_ref: RootedRef,
    trace_witness_refs: dict[str, RootedRef],
    minimality_witness_refs: tuple[RootedRef, ...],
    registries: RegistryStore,
) -> VerifiedContract:
    registries.resolve(scoped_ref, expected_schema="AuditSpec-scoped-claim-v1")
    registries.resolve(verifier_ref)
    registries.resolve(optimization_witness_ref)
    registries.resolve(premise_witness_ref)
    registries.resolve(policy_witness_ref)
    registries.resolve(lifecycle_policy_ref)
    expected_trace = ("Q", "WorldScope", "A", "D")
    if tuple(trace_witness_refs) != expected_trace:
        raise ValueError("design-time trace must be exactly Q,WorldScope,A,D")
    input_roots = {
        "Q": scoped.claim_ir_digest,
        "WorldScope": scoped.scope_commitment,
        "A": domain.domain_root,
        "D": catalog.mechanism_registry_root,
    }
    witness_digests = {
        "Q": digest("AuditSpec-core-phase1-Q-pass-v1", list(scoped.q_check_trace)),
        "WorldScope": digest(
            "AuditSpec-core-phase1-WorldScope-pass-v1",
            list(scoped.world_scope_check_trace),
        ),
        "A": adequacy.witness_digest,
        "D": synthesis.witness_digest,
    }
    trace = []
    for obligation in expected_trace:
        reference = trace_witness_refs[obligation]
        registries.resolve(reference)
        trace.append(
            {
                "obligation": obligation,
                "status": "PASS",
                "input_root": input_roots[obligation],
                "witness_ref": reference.to_wire(),
                "witness_digest": witness_digests[obligation],
                "recompute_ref": reference.to_wire(),
            }
        )
    open_premises = derive_open_premises(claim, catalog, lifecycle_policy_ref)
    premise_root = digest("AuditSpec-open-premise-set-v1", open_premises)
    premise_witness = registries.resolve(premise_witness_ref)
    if premise_witness.get("open_premise_set_root") != premise_root:
        raise ValueError("open-premise derivation witness mismatch")
    if set(synthesis.dependency_closure) - set(synthesis.selected):
        raise ValueError("dependency closure is not included in the selection")
    body = {
        "schema": "AuditSpec-verified-contract-v1",
        "contract_id": f"contract:{claim.id}",
        "scoped_claim_ref": scoped_ref.to_wire(),
        "world_scope": claim.world_scope,
        "environment_model_root": domain.domain_root,
        "threat_model_root": threat_model_root,
        "compiler_root": compiler_root,
        "mechanism_registry_root": catalog.mechanism_registry_root,
        "schema_registry_root": schema_registry_root,
        "selected_mechanisms": list(synthesis.selected),
        "dependency_closure": list(synthesis.dependency_closure),
        "bridge_requirement": None,
        "verifier_ref": verifier_ref.to_wire(),
        "adapter_registry_root": catalog.adapter_registry_root,
        "schema_version": "AuditSpec-Schema-1.0",
        "cost_vector": synthesis.cost.to_wire(),
        "design_time_trace": trace,
        "optimization_witness_ref": optimization_witness_ref.to_wire(),
        "optimization_witness_digest": optimization_witness_digest,
        "open_premises": open_premises,
        "open_premise_set_root": premise_root,
        "open_premise_derivation_witness": {
            "ref": premise_witness_ref.to_wire(),
            "digest": premise_witness_ref.payload_digest,
        },
        "minimality_witness_refs": [item.to_wire() for item in minimality_witness_refs],
        "lifecycle_policy": lifecycle_policy_ref.to_wire(),
        "audit_horizon_commitment": claim.temporal_scope["audit_horizon_commitment"],
        "audit_schedule_commitment": claim.temporal_scope["audit_schedule_commitment"],
        "policy_horizon_coverage_witness": {
            "ref": policy_witness_ref.to_wire(),
            "digest": policy_witness_ref.payload_digest,
        },
    }
    return VerifiedContract(body, digest("AuditSpec-verified-contract-v1", body))


def derive_open_premises(
    claim: ClaimIR,
    catalog: MechanismCatalog,
    lifecycle_policy_ref: RootedRef,
) -> list[dict[str, Any]]:
    rows = [
        {
            "premise_id": "legacy_normative_faithfulness",
            "kind": "normative_faithfulness",
            "source_digest": claim.semantics_commitment,
            "discharge_requirement": None,
        },
        {
            "premise_id": "declared_world_boundary",
            "kind": "world_boundary",
            "source_digest": claim.world_scope["scope_commitment"],
            "discharge_requirement": None,
        },
        {
            "premise_id": "source_pinned_registry_authentication",
            "kind": "trust_root",
            "source_digest": catalog.mechanism_registry_root,
            "discharge_requirement": "deployed_sp2_registry",
        },
        {
            "premise_id": "adapter_conformance",
            "kind": "mediation",
            "source_digest": catalog.adapter_registry_root,
            "discharge_requirement": "R",
        },
        {
            "premise_id": "future_custody",
            "kind": "custody",
            "source_digest": lifecycle_policy_ref.payload_digest,
            "discharge_requirement": "L",
        },
        {
            "premise_id": "future_availability",
            "kind": "availability",
            "source_digest": lifecycle_policy_ref.payload_digest,
            "discharge_requirement": "L",
        },
    ]
    return sorted(rows, key=lambda item: item["premise_id"])
