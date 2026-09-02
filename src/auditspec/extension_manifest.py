from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .assurance import (
    OFFICIAL_LIVE_PROFILE,
    OFFICIAL_RECEIPT_PROFILE,
    REGISTERED_REEXECUTION_PROFILE,
    AssuranceConfiguration,
    ExactGateResult,
    canonical_digest,
    declared_inventory_manifest,
    inventory_authority_result,
    run_exact_assurance_gate,
    trust_context_commitment_payload,
)
from .compiler import AuditCompiler
from .expr import evaluate
from .model_adequacy import ModelAdequacyChecker
from .spec import enumerate_worlds
from .verifier_registry import verifier_registry_digest

EXTENSION_MANIFEST_SCHEMA = "AuditSpec-full-assurance-extension-manifest-v1"
EXTENSION_RESULT_SCHEMA = "AuditSpec-full-assurance-extension-result-v1"
STRONG_V_CERTIFICATE_SCHEMA = "AuditSpec-strong-v-deletion-certificate-v1"
INVENTORY_TCB_BASIS = "declared-manifest-tcb-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
STRUCTURAL_COORDINATES = (
    "spec_identity",
    "query",
    "claim_semantics",
    "contract",
    "mechanism_catalog",
    "threat_model",
    "adapter_registry",
    "topology",
    "bypass",
    "trust_roots",
    "retained_evidence",
    "inventory_scope",
    "inventory_authority",
    "external_verifier_profile",
    "registered_verifier",
    "isolated_verifier",
    "official_gate",
)
ADMISSIBLE_STRUCTURAL_DELTAS = frozenset(
    {
        "topology",
        "bypass",
        "trust_roots",
        "retained_evidence",
        "inventory_scope",
        "inventory_authority",
        "registered_verifier",
        "isolated_verifier",
        "official_gate",
    }
)
_COORDINATE_RANK = {name: index for index, name in enumerate(STRUCTURAL_COORDINATES)}
_OFFICIAL_GATE_PROFILES = frozenset({OFFICIAL_RECEIPT_PROFILE, OFFICIAL_LIVE_PROFILE})


class ExtensionMode(StrEnum):
    DOMAIN_ONLY_FREEZE = "domain_only_freeze"
    ADMITTED_STRUCTURAL_DELTA = "admitted_structural_delta"


def _threat_payload(threat: Any, *, include_bypass: bool) -> dict[str, Any] | None:
    if threat is None:
        return None
    payload = {
        "name": threat.name,
        "compromised_producers": sorted(threat.compromised_producers),
        "trusted_capture_points": sorted(threat.trusted_capture_points),
        "accepted_integrity": sorted(threat.accepted_integrity),
        "available_mechanisms": (
            sorted(threat.available_mechanisms)
            if threat.available_mechanisms is not None
            else None
        ),
        "mandatory_channels": sorted(threat.mandatory_channels),
        "description": threat.description,
    }
    if include_bypass:
        payload["bypass_edges"] = [list(edge) for edge in threat.bypass_edges]
    return payload


def _contract_payload(config: AssuranceConfiguration) -> dict[str, Any]:
    pending = list(config.contract)
    closure: set[str] = set()
    missing: set[str] = set()
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        mechanism = config.spec.mechanisms.get(name)
        if mechanism is None:
            missing.add(name)
            continue
        closure.add(name)
        pending.extend(mechanism.requires)
    return {
        "selection": list(config.contract),
        "dependency_closure": {
            name: config.spec.mechanisms[name].as_dict() for name in sorted(closure)
        },
        "missing_dependencies": sorted(missing),
        "unselected_dependencies": sorted(closure - set(config.contract)),
    }


def _inventory_scope_payload(config: AssuranceConfiguration) -> dict[str, Any]:
    raw = config.inventory_scope.as_dict()
    expected = declared_inventory_manifest(
        config.spec,
        threat_model=config.threat_model,
        channel=config.inventory_scope.channel,
    )
    return {
        "schema": raw["schema"],
        "scope_id": raw["scope_id"],
        "channel": raw["channel"],
        "basis": raw["basis"],
        "open_world": raw["open_world"],
        "inventory_completeness_proven": raw["inventory_completeness_proven"],
        "derived_inventory_manifest": {
            "law": "declared_inventory_manifest(spec,threat_model,channel)-v1",
            "satisfied": dict(config.inventory_scope.inventory_manifest) == expected,
        },
    }


def _config_coordinate_payload(config: AssuranceConfiguration) -> dict[str, Any]:
    query = config.spec.queries.get(config.query_name)
    threat = config.spec.threat_models.get(config.threat_model)
    closure = set(_contract_payload(config)["dependency_closure"])
    return {
        "spec_identity": {
            "name": config.spec.name,
            "description": config.spec.description,
            "metadata": config.spec.metadata,
        },
        "query": {
            "query_name": config.query_name,
            "selected": asdict(query) if query is not None else None,
            "unselected_catalog": {
                name: asdict(value)
                for name, value in sorted(config.spec.queries.items())
                if name != config.query_name
            },
        },
        "claim_semantics": {
            "claim_id": config.claim_id,
            "adequacy_case": config.adequacy_case.as_dict(),
            "claim_semantics_commitment": config.claim_semantics_commitment,
        },
        "contract": _contract_payload(config),
        "mechanism_catalog": {
            name: mechanism.as_dict()
            for name, mechanism in sorted(config.spec.mechanisms.items())
            if name not in closure
        },
        "threat_model": {
            "selected_name": config.threat_model,
            "selected": _threat_payload(threat, include_bypass=False),
            "unselected_catalog": {
                name: _threat_payload(value, include_bypass=True)
                for name, value in sorted(config.spec.threat_models.items())
                if name != config.threat_model
            },
        },
        "adapter_registry": {
            "adapter_registry": config.adapter_registry_snapshot,
            "adapter_registry_attestation": config.adapter_registry_attestation_snapshot,
            "external_claim_registry": config.external_claim_registry_snapshot,
            "assurance_implementation": config.implementation_snapshot,
        },
        "topology": config.spec.topology.as_dict(),
        "bypass": [
            list(edge) for edge in (threat.bypass_edges if threat is not None else ())
        ],
        "trust_roots": trust_context_commitment_payload(config.trust_context),
        "retained_evidence": config.evidence.as_dict(),
        "inventory_scope": _inventory_scope_payload(config),
        "inventory_authority": {
            "required": config.inventory_authority_required,
            "statement": (
                dict(config.inventory_scope.authority_statement)
                if config.inventory_scope.authority_statement is not None
                else None
            ),
            "trust": (
                config.inventory_authority_trust.as_dict()
                if config.inventory_authority_trust is not None
                else None
            ),
        },
        "external_verifier_profile": config.external_verifier_profile,
        "registered_verifier": (
            config.registered_verifier_invocation.as_dict()
            if config.registered_verifier_invocation is not None
            else None
        ),
        "isolated_verifier": {
            "invocation": (
                config.isolated_verifier_invocation.as_dict()
                if config.isolated_verifier_invocation is not None
                else None
            ),
            "policy": (
                config.isolation_policy.as_dict()
                if config.isolation_policy is not None
                else None
            ),
        },
        "official_gate": {
            "invocation": (
                config.official_gate_invocation.as_dict()
                if config.official_gate_invocation is not None
                else None
            ),
            "context": (
                config.official_gate_context.as_dict()
                if config.official_gate_context is not None
                else None
            ),
        },
    }


def actual_structural_delta(
    base: AssuranceConfiguration, extension: AssuranceConfiguration
) -> tuple[str, ...]:
    before = _config_coordinate_payload(base)
    after = _config_coordinate_payload(extension)
    return tuple(name for name in STRUCTURAL_COORDINATES if before[name] != after[name])


def _canonical_delta(values: tuple[str, ...]) -> tuple[str, ...]:
    if len(set(values)) != len(values):
        raise ValueError("declared delta must be duplicate-free")
    unknown = set(values) - set(STRUCTURAL_COORDINATES)
    if unknown:
        raise ValueError("declared delta names an unknown coordinate")
    return tuple(sorted(values, key=_COORDINATE_RANK.__getitem__))


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True)
class FullAssuranceExtensionManifest:
    manifest_id: str
    mode: ExtensionMode
    base_configuration_digest: str
    extension_configuration_digest: str
    inventory_scope_pair_digest: str
    section_defaults: Mapping[str, Any]
    declared_delta: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.manifest_id, str) or not self.manifest_id:
            raise ValueError("extension manifest_id must be non-empty")
        if not isinstance(self.mode, ExtensionMode):
            raise TypeError("extension mode must be ExtensionMode")
        for label, value in (
            ("base_configuration_digest", self.base_configuration_digest),
            ("extension_configuration_digest", self.extension_configuration_digest),
            ("inventory_scope_pair_digest", self.inventory_scope_pair_digest),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"extension manifest {label} must be a digest")
        if _canonical_delta(self.declared_delta) != self.declared_delta:
            raise ValueError("declared delta is not in canonical coordinate order")
        if not isinstance(self.section_defaults, Mapping):
            raise TypeError("section defaults must be a mapping")
        if any(not isinstance(name, str) or not name for name in self.section_defaults):
            raise TypeError("section default names must be non-empty strings")
        detached = json.loads(
            json.dumps(
                dict(self.section_defaults),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
        object.__setattr__(self, "section_defaults", _freeze_json(detached))

    @classmethod
    def build(
        cls,
        manifest_id: str,
        mode: ExtensionMode,
        base: AssuranceConfiguration,
        extension: AssuranceConfiguration,
        *,
        section_defaults: Mapping[str, Any],
        declared_delta: tuple[str, ...] = (),
    ) -> FullAssuranceExtensionManifest:
        return cls(
            manifest_id,
            mode,
            base.configuration_digest,
            extension.configuration_digest,
            canonical_digest(
                {
                    "base": base.inventory_scope.as_dict(),
                    "extension": extension.inventory_scope.as_dict(),
                }
            ),
            section_defaults,
            _canonical_delta(declared_delta),
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> FullAssuranceExtensionManifest:
        expected = {
            "schema",
            "manifest_id",
            "mode",
            "base_configuration_digest",
            "extension_configuration_digest",
            "inventory_scope_pair_digest",
            "section_defaults",
            "declared_delta",
            "inventory_tcb_basis",
            "inventory_completeness_is_axiom",
            "inventory_completeness_proven",
            "open_world",
        }
        if set(raw) != expected:
            raise ValueError("extension manifest fields differ from closed schema")
        if (
            raw["schema"] != EXTENSION_MANIFEST_SCHEMA
            or raw["inventory_tcb_basis"] != INVENTORY_TCB_BASIS
        ):
            raise ValueError("extension manifest schema/TCB basis mismatch")
        if not (
            raw["inventory_completeness_is_axiom"] is True
            and raw["inventory_completeness_proven"] is False
            and raw["open_world"] is False
        ):
            raise ValueError("extension manifest boundary changed")
        for key in (
            "base_configuration_digest",
            "extension_configuration_digest",
            "inventory_scope_pair_digest",
        ):
            if not isinstance(raw[key], str) or not _DIGEST.fullmatch(raw[key]):
                raise TypeError(f"extension manifest {key} must be a digest")
        if not isinstance(raw["manifest_id"], str) or not raw["manifest_id"]:
            raise TypeError("extension manifest_id must be non-empty")
        if not isinstance(raw["section_defaults"], Mapping):
            raise TypeError("extension section defaults must be a mapping")
        delta = raw["declared_delta"]
        if not isinstance(delta, list) or any(
            not isinstance(item, str) for item in delta
        ):
            raise TypeError("extension declared delta must be a string list")
        return cls(
            raw["manifest_id"],
            ExtensionMode(raw["mode"]),
            raw["base_configuration_digest"],
            raw["extension_configuration_digest"],
            raw["inventory_scope_pair_digest"],
            dict(raw["section_defaults"]),
            tuple(delta),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": EXTENSION_MANIFEST_SCHEMA,
            "manifest_id": self.manifest_id,
            "mode": str(self.mode),
            "base_configuration_digest": self.base_configuration_digest,
            "extension_configuration_digest": self.extension_configuration_digest,
            "inventory_scope_pair_digest": self.inventory_scope_pair_digest,
            "section_defaults": _thaw_json(self.section_defaults),
            "declared_delta": list(self.declared_delta),
            "inventory_tcb_basis": INVENTORY_TCB_BASIS,
            "inventory_completeness_is_axiom": True,
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    @property
    def manifest_digest(self) -> str:
        return canonical_digest(self.as_dict())


@dataclass(frozen=True)
class FullAssuranceExtensionResult:
    manifest_digest: str
    manifest_valid: bool
    extension_supported: bool
    primary_verdict: str | None
    first_failed_layer: str | None
    actual_delta: tuple[str, ...]
    new_variables: tuple[str, ...]
    errors: tuple[str, ...]
    extension_gate: Mapping[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": EXTENSION_RESULT_SCHEMA,
            "manifest_digest": self.manifest_digest,
            "manifest_valid": self.manifest_valid,
            "extension_supported": self.extension_supported,
            "primary_verdict": self.primary_verdict,
            "first_failed_layer": self.first_failed_layer,
            "actual_delta": list(self.actual_delta),
            "new_variables": list(self.new_variables),
            "errors": list(self.errors),
            "extension_gate": dict(self.extension_gate)
            if self.extension_gate is not None
            else None,
            "extension_admissibility_checked": self.manifest_valid,
            "assurance_scope": "declared_finite_assurance_configuration",
            "inventory_tcb_basis": INVENTORY_TCB_BASIS,
            "inventory_completeness_is_axiom": True,
            "inventory_completeness_proven": False,
            "open_world": False,
        }


def _world_key(world: Mapping[str, Any], variables: Mapping[str, Any]) -> tuple:
    return tuple((name, world[name]) for name in variables)


def verify_full_assurance_extension(
    manifest: FullAssuranceExtensionManifest,
    base: AssuranceConfiguration,
    extension: AssuranceConfiguration,
) -> FullAssuranceExtensionResult:
    errors: list[str] = []
    if manifest.base_configuration_digest != base.configuration_digest:
        errors.append("base_configuration_digest:mismatch")
    if manifest.extension_configuration_digest != extension.configuration_digest:
        errors.append("extension_configuration_digest:mismatch")
    expected_inventory_pair_digest = canonical_digest(
        {
            "base": base.inventory_scope.as_dict(),
            "extension": extension.inventory_scope.as_dict(),
        }
    )
    if manifest.inventory_scope_pair_digest != expected_inventory_pair_digest:
        errors.append("inventory_scope_pair_digest:mismatch")
    for label, config in (("base", base), ("extension", extension)):
        inventory_relation = _inventory_scope_payload(config)[
            "derived_inventory_manifest"
        ]
        if inventory_relation["satisfied"] is not True:
            errors.append(f"{label}_inventory_manifest:derived_relation_mismatch")
        contract_relation = _contract_payload(config)
        if contract_relation["missing_dependencies"]:
            errors.append(f"{label}_contract:missing_dependencies")
        if contract_relation["unselected_dependencies"]:
            errors.append(f"{label}_contract:unselected_dependencies")
        try:
            authority = inventory_authority_result(config)
        except (OSError, TypeError, ValueError) as exc:
            errors.append(
                f"{label}_inventory_authority:exception:{type(exc).__name__}:{exc}"
            )
        else:
            if config.inventory_authority_required and (
                authority is None or not authority.valid
            ):
                errors.append(f"{label}_inventory_authority:invalid")
    actual_delta = actual_structural_delta(base, extension)
    if manifest.mode is ExtensionMode.DOMAIN_ONLY_FREEZE:
        if manifest.declared_delta:
            errors.append("domain_only:declared_delta_nonempty")
        if actual_delta:
            errors.extend(f"frame_violation:{name}" for name in actual_delta)
    else:
        if tuple(manifest.declared_delta) != actual_delta:
            errors.append("declared_delta:mismatch")
        if set(actual_delta) - ADMISSIBLE_STRUCTURAL_DELTAS:
            errors.append("declared_delta:unsupported_coordinate")

    base_names = tuple(base.spec.variables)
    extension_names = tuple(extension.spec.variables)
    new_variables = tuple(
        name for name in extension_names if name not in base.spec.variables
    )
    if not set(base_names) <= set(extension_names):
        errors.append("variables:not_included")
    if set(manifest.section_defaults) != set(new_variables):
        errors.append("section_defaults:mismatch")
    if set(base.spec.facts) != set(base.spec.variables):
        errors.append("base_facts:variables_mismatch")
    if set(extension.spec.facts) != set(extension.spec.variables):
        errors.append("extension_facts:variables_mismatch")
    for name in base_names:
        if extension.spec.facts.get(name) != base.spec.facts.get(name):
            errors.append(f"fact_definition:changed:{name}")
    if set(extension.spec.facts) - set(base.spec.facts) != set(new_variables):
        errors.append("new_fact_definitions:variables_mismatch")
    if (
        base.adequacy_case.external_variables
        or extension.adequacy_case.external_variables
        or base.adequacy_case.concrete_constraints
        or extension.adequacy_case.concrete_constraints
    ):
        errors.append("external_variables:unsupported_by_manifest_v1")

    try:
        base_worlds = enumerate_worlds(base.spec)
        extension_worlds = enumerate_worlds(extension.spec)
        base_keys = {_world_key(world, base.spec.variables) for world in base_worlds}
        extension_keys = {
            _world_key(world, extension.spec.variables) for world in extension_worlds
        }
        base_checker = ModelAdequacyChecker(base.spec, base.adequacy_case)
        extension_checker = ModelAdequacyChecker(
            extension.spec, extension.adequacy_case
        )
        base_compiler = AuditCompiler(base.spec)
        extension_compiler = AuditCompiler(extension.spec)
        for world in extension_worlds:
            projected = {name: world[name] for name in base_names}
            if _world_key(projected, base.spec.variables) not in base_keys:
                errors.append("projection:outside_base_worlds")
                break
            base_truth = bool(
                evaluate(base.adequacy_case.external_predicate, projected)
            )
            extension_truth = bool(
                evaluate(extension.adequacy_case.external_predicate, world)
            )
            if base_truth != extension_truth:
                errors.append("truth:projection_inconsistent")
                break
            base_abstract = base_checker.abstract(projected)
            extension_abstract = extension_checker.abstract(world)
            if any(
                extension_abstract[name] != base_abstract[name] for name in base_names
            ):
                errors.append("abstraction:projection_inconsistent")
                break
            if base.contract != extension.contract:
                errors.append("contract:changed_in_manifest_v1")
                break
            if extension_compiler.observation(
                world, extension.contract
            ) != base_compiler.observation(projected, base.contract):
                errors.append("evidence:projection_inconsistent")
                break
        for world in base_worlds:
            lifted = {**world, **dict(manifest.section_defaults)}
            if _world_key(lifted, extension.spec.variables) not in extension_keys:
                errors.append("section:not_in_extension_worlds")
                break
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"manifest_exception:{type(exc).__name__}:{exc}")

    gate: ExactGateResult | None = None
    if not errors:
        gate = run_exact_assurance_gate(extension)
    return FullAssuranceExtensionResult(
        manifest.manifest_digest,
        not errors,
        bool(gate and gate.supported_within_declared_tcb),
        str(gate.primary_verdict) if gate is not None else None,
        gate.first_failed_layer if gate is not None else None,
        actual_delta,
        new_variables,
        tuple(errors),
        gate.as_dict() if gate is not None else None,
    )


@dataclass(frozen=True)
class StrongVerifierPremise:
    claim_id: str
    verifier_id: str
    registry_digest: str

    def __post_init__(self) -> None:
        for label, value in (
            ("claim_id", self.claim_id),
            ("verifier_id", self.verifier_id),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"strong verifier {label} must be non-empty")
        if not isinstance(self.registry_digest, str) or not _DIGEST.fullmatch(
            self.registry_digest
        ):
            raise ValueError("strong verifier registry digest is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-strong-verifier-premise-v1",
            "claim_id": self.claim_id,
            "verifier_id": self.verifier_id,
            "registry_digest": self.registry_digest,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StrongVerifierPremise:
        if set(raw) != {"schema", "claim_id", "verifier_id", "registry_digest"}:
            raise ValueError("strong verifier premise fields differ from closed schema")
        if raw["schema"] != "AuditSpec-strong-verifier-premise-v1":
            raise ValueError("strong verifier premise schema mismatch")
        if not isinstance(raw["registry_digest"], str) or not _DIGEST.fullmatch(
            raw["registry_digest"]
        ):
            raise TypeError("strong verifier registry digest is invalid")
        for key in ("claim_id", "verifier_id"):
            if not isinstance(raw[key], str) or not raw[key]:
                raise TypeError(f"strong verifier {key} must be non-empty")
        return cls(raw["claim_id"], raw["verifier_id"], raw["registry_digest"])

    @property
    def premise_digest(self) -> str:
        return canonical_digest(self.as_dict())


def strong_verifier_premise_satisfied(
    premise: StrongVerifierPremise, config: AssuranceConfiguration
) -> bool:
    gate = run_exact_assurance_gate(config)
    witness = config.evidence.payload.get("verification_witness")
    declared = witness.get("declared_value") if isinstance(witness, Mapping) else None
    if config.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE:
        invocation = config.registered_verifier_invocation
        result = gate.registered_verifier_result
        return bool(
            invocation is not None
            and premise.claim_id == config.claim_id == invocation.claim_id
            and premise.verifier_id == invocation.verifier_id
            and premise.registry_digest
            == invocation.registry_digest
            == verifier_registry_digest()
            and gate.supported_within_declared_tcb
            and result is not None
            and result.get("executed") is True
            and result.get("accepted") is True
            and result.get("answer") == declared
        )
    if config.external_verifier_profile in _OFFICIAL_GATE_PROFILES:
        invocation = config.official_gate_invocation
        result = gate.official_gate_result
        return bool(
            invocation is not None
            and premise.claim_id == config.claim_id == invocation.claim_id
            and premise.verifier_id == invocation.verifier_id
            and premise.registry_digest == invocation.official_evaluator_registry_digest
            and gate.supported_within_declared_tcb
            and result is not None
            and result.get("official_evaluator_actual_execution") is True
            and result.get("accepted") is True
            and result.get("answer") == declared
        )
    return False


@dataclass(frozen=True)
class StrongVDeletionCertificate:
    premise_digest: str
    extension_manifest_digest: str
    base_configuration_digest: str
    extension_configuration_digest: str
    base_execution_digest: str
    extension_execution_digest: str
    variant: str = "V:registered-verifier-reexecution-failure"

    def __post_init__(self) -> None:
        for label, value in (
            ("premise_digest", self.premise_digest),
            ("extension_manifest_digest", self.extension_manifest_digest),
            ("base_configuration_digest", self.base_configuration_digest),
            ("extension_configuration_digest", self.extension_configuration_digest),
            ("base_execution_digest", self.base_execution_digest),
            ("extension_execution_digest", self.extension_execution_digest),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"strong V {label} must be a digest")
        if self.variant not in {
            "V:registered-verifier-reexecution-failure",
            "V:official-gate-receipt-failure",
        }:
            raise ValueError("strong V certificate variant is invalid")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StrongVDeletionCertificate:
        expected = {
            "schema",
            "variant",
            "premise_digest",
            "extension_manifest_digest",
            "base_configuration_digest",
            "extension_configuration_digest",
            "base_execution_digest",
            "extension_execution_digest",
            "first_failed_layer",
            "extension_admissibility_checked",
            "inventory_completeness_proven",
            "open_world",
        }
        if set(raw) != expected:
            raise ValueError("strong V certificate fields differ from closed schema")
        if raw["schema"] != STRONG_V_CERTIFICATE_SCHEMA or raw["variant"] not in {
            "V:registered-verifier-reexecution-failure",
            "V:official-gate-receipt-failure",
        }:
            raise ValueError("strong V certificate schema/variant mismatch")
        if not (
            raw["first_failed_layer"] == "V"
            and raw["extension_admissibility_checked"] is True
            and raw["inventory_completeness_proven"] is False
            and raw["open_world"] is False
        ):
            raise ValueError("strong V certificate boundary changed")
        values = []
        for key in (
            "premise_digest",
            "extension_manifest_digest",
            "base_configuration_digest",
            "extension_configuration_digest",
            "base_execution_digest",
            "extension_execution_digest",
        ):
            value = raw[key]
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise TypeError(f"strong V {key} must be a digest")
            values.append(value)
        return cls(*values, variant=raw["variant"])

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": STRONG_V_CERTIFICATE_SCHEMA,
            "variant": self.variant,
            "premise_digest": self.premise_digest,
            "extension_manifest_digest": self.extension_manifest_digest,
            "base_configuration_digest": self.base_configuration_digest,
            "extension_configuration_digest": self.extension_configuration_digest,
            "base_execution_digest": self.base_execution_digest,
            "extension_execution_digest": self.extension_execution_digest,
            "first_failed_layer": "V",
            "extension_admissibility_checked": True,
            "inventory_completeness_proven": False,
            "open_world": False,
        }


def make_strong_v_deletion_certificate(
    premise: StrongVerifierPremise,
    manifest: FullAssuranceExtensionManifest,
    base: AssuranceConfiguration,
    extension: AssuranceConfiguration,
) -> StrongVDeletionCertificate:
    base_gate = run_exact_assurance_gate(base)
    extension_gate = run_exact_assurance_gate(extension)
    if (
        base.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE
        and extension.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE
    ):
        base_execution = base_gate.registered_verifier_result
        extension_execution = extension_gate.registered_verifier_result
        variant = "V:registered-verifier-reexecution-failure"
    elif (
        base.external_verifier_profile in _OFFICIAL_GATE_PROFILES
        and extension.external_verifier_profile in _OFFICIAL_GATE_PROFILES
    ):
        base_execution = base_gate.official_gate_result
        extension_execution = extension_gate.official_gate_result
        variant = "V:official-gate-receipt-failure"
    else:
        raise ValueError("strong V certificate profiles do not match")
    if base_execution is None or extension_execution is None:
        if base.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE:
            raise ValueError("strong V certificate requires registered invocations")
        raise ValueError("strong V certificate requires official gate executions")
    certificate = StrongVDeletionCertificate(
        premise.premise_digest,
        manifest.manifest_digest,
        base.configuration_digest,
        extension.configuration_digest,
        canonical_digest(base_execution),
        canonical_digest(extension_execution),
        variant,
    )
    if not verify_strong_v_deletion_certificate(
        certificate, premise, manifest, base, extension
    ):
        raise ValueError("generated strong V deletion certificate does not verify")
    return certificate


def verify_strong_v_deletion_certificate(
    certificate: StrongVDeletionCertificate,
    premise: StrongVerifierPremise,
    manifest: FullAssuranceExtensionManifest,
    base: AssuranceConfiguration,
    extension: AssuranceConfiguration,
) -> bool:
    result = verify_full_assurance_extension(manifest, base, extension)
    base_gate = run_exact_assurance_gate(base)
    extension_gate = run_exact_assurance_gate(extension)
    if (
        base.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE
        and extension.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE
        and base.registered_verifier_invocation is not None
        and extension.registered_verifier_invocation is not None
        and base_gate.registered_verifier_result is not None
        and extension_gate.registered_verifier_result is not None
    ):
        base_execution = base_gate.registered_verifier_result
        extension_execution = extension_gate.registered_verifier_result
        expected_variant = "V:registered-verifier-reexecution-failure"
        execution_conditions = bool(
            extension_gate.trace
            and extension_gate.trace[-1].details
            == ("registered_verifier_answer:mismatch",)
            and base_execution.get("executed") is True
            and base_execution.get("accepted") is True
            and extension_execution.get("executed") is True
            and extension_execution.get("accepted") is True
        )
    elif (
        base.external_verifier_profile in _OFFICIAL_GATE_PROFILES
        and extension.external_verifier_profile in _OFFICIAL_GATE_PROFILES
        and base.official_gate_invocation is not None
        and extension.official_gate_invocation is not None
        and base_gate.official_gate_result is not None
        and extension_gate.official_gate_result is not None
    ):
        base_execution = base_gate.official_gate_result
        extension_execution = extension_gate.official_gate_result
        expected_variant = "V:official-gate-receipt-failure"
        extension_details = (
            extension_gate.trace[-1].details
            if extension_gate.trace and extension_gate.trace[-1].layer == "V"
            else ()
        )
        execution_conditions = bool(
            any(detail.startswith("official_gate:") for detail in extension_details)
            and "official_gate:not_accepted" in extension_details
            and base_execution.get("official_evaluator_actual_execution") is True
            and base_execution.get("accepted") is True
            and extension_execution.get("official_evaluator_actual_execution") is True
            and extension_execution.get("accepted") is False
        )
    else:
        return False
    base_witness = base.evidence.payload.get("verification_witness")
    extension_witness = extension.evidence.payload.get("verification_witness")
    base_declared = (
        base_witness.get("declared_value")
        if isinstance(base_witness, Mapping)
        else None
    )
    extension_declared = (
        extension_witness.get("declared_value")
        if isinstance(extension_witness, Mapping)
        else None
    )
    return bool(
        certificate.variant == expected_variant
        and certificate.premise_digest == premise.premise_digest
        and certificate.extension_manifest_digest == manifest.manifest_digest
        and certificate.base_configuration_digest == base.configuration_digest
        and certificate.extension_configuration_digest == extension.configuration_digest
        and certificate.base_execution_digest == canonical_digest(base_execution)
        and certificate.extension_execution_digest
        == canonical_digest(extension_execution)
        and result.manifest_valid
        and not result.extension_supported
        and result.first_failed_layer == "V"
        and result.extension_gate == extension_gate.as_dict()
        and base_gate.supported_within_declared_tcb
        and base_gate.external_result is not None
        and base_gate.external_result.get("valid") is True
        and extension_gate.external_result is not None
        and extension_gate.external_result.get("valid") is True
        and extension_gate.first_failed_layer == "V"
        and execution_conditions
        and base_execution.get("answer") == base_declared
        and extension_execution.get("answer") != extension_declared
        and strong_verifier_premise_satisfied(premise, base)
        and not strong_verifier_premise_satisfied(premise, extension)
    )
