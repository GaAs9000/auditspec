"""Core InstallationPlan resolution; conformance is deliberately not run."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import digest
from .contract import VerifiedContract
from .mechanism_ir import MechanismCatalog
from .refs import RegistryStore, RootedRef


@dataclass(frozen=True)
class RealizationGap:
    verdict: str
    subtype: str
    missing_mechanisms: tuple[str, ...]


@dataclass(frozen=True)
class CoreInstallationPlan:
    wire_without_digest: dict[str, Any]
    installation_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            **self.wire_without_digest,
            "installation_digest": self.installation_digest,
        }


def build_plan(
    contract: VerifiedContract,
    contract_ref: RootedRef,
    catalog: MechanismCatalog,
    registries: RegistryStore,
    *,
    adapter_candidates: Mapping[str, Any] | None = None,
) -> CoreInstallationPlan | RealizationGap:
    resolved_contract = registries.resolve(
        contract_ref, expected_schema="AuditSpec-verified-contract-v1"
    )
    if resolved_contract != contract.to_wire():
        raise ValueError("plan contract_ref does not resolve the supplied contract")
    candidates = dict(
        catalog.adapters if adapter_candidates is None else adapter_candidates
    )
    selected = contract.selected_mechanisms
    missing = tuple(sorted(set(selected) - set(candidates)))
    if missing:
        return RealizationGap(
            "REALIZATION_GAP", "NO_REGISTERED_IMPLEMENTATION", missing
        )
    if set(candidates) - set(catalog.mechanisms):
        raise ValueError("adapter map names an unknown mechanism")
    adapter_refs: dict[str, str] = {}
    hooks: list[dict[str, Any]] = []
    capture_points: list[dict[str, Any]] = []
    for mechanism_id in selected:
        candidate = candidates[mechanism_id]
        if candidate.mechanism_id != mechanism_id:
            raise ValueError("adapter candidate mechanism binding mismatch")
        registries.resolve(candidate.hook_point)
        mechanism = catalog.mechanisms[mechanism_id]
        pattern = mechanism.capture_requirement
        if (
            (pattern.id is not None and pattern.id != candidate.capture_point.id)
            or (
                pattern.key_domain is not None
                and pattern.key_domain != candidate.capture_point.key_domain
            )
            or (
                pattern.key_id is not None
                and pattern.key_id != candidate.capture_point.key_id
            )
        ):
            raise ValueError("adapter capture point does not match Mechanism Spec")
        adapter_refs[mechanism_id] = candidate.adapter_id
        hooks.append(
            {
                "mechanism_ref": mechanism_id,
                "ledger": candidate.ledger,
                "hook_point": candidate.hook_point.to_wire(),
            }
        )
        capture_points.append(
            {
                "mechanism_ref": mechanism_id,
                "capture_point": candidate.capture_point.to_wire(),
            }
        )
    hooks.sort(key=lambda item: (item["mechanism_ref"], item["ledger"]))
    capture_points.sort(key=lambda item: item["mechanism_ref"])
    body = {
        "schema": "AuditSpec-core-installation-plan-v1",
        "plan_id": f"plan:{contract.contract_id}",
        "contract_ref": contract_ref.to_wire(),
        "adapter_refs": {name: adapter_refs[name] for name in sorted(adapter_refs)},
        "runtime_hooks": hooks,
        "credential_requirements": [],
        "capture_points": capture_points,
        "preflight_checks": ["M", "key_validity", "topology", "version_match"],
        "noninterference_requirements": [],
    }
    return CoreInstallationPlan(
        body, digest("AuditSpec-core-installation-plan-v1", body)
    )
