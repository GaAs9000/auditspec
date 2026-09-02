from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, TypeAlias

from .adapter_registry import registry_digest
from .assurance import (
    AssuranceConfiguration,
    ExactGateResult,
    canonical_digest,
    contract_digest,
    declared_adapter_failures,
    declared_adapter_manifest_digest,
    declared_mediation_proof,
    declared_scope_errors,
    evidence_determinate,
    external_packet_result,
    finite_evidence_twin_certificate,
    query_formation_errors,
    run_exact_assurance_gate,
    trust_context_digest,
)
from .compiler import AuditCompiler
from .model import TwinCertificate
from .model_adequacy import ModelAdequacyChecker, ModelTwinCertificate


PREMISE_GRAMMAR = "AuditSpec-premise-grammar-v1"
PREMISE_SET_SCHEMA = "AuditSpec-premise-set-v1"
CERTIFICATE_SCHEMA = "AuditSpec-p-minimality-certificate-v1"
CERTIFICATE_SCOPE = "declared_configuration_pair"
LAYER_ORDER = ("Q", "A", "D", "R", "M", "V")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")

ATOM_SIGNATURES: dict[tuple[str, str], tuple[str, ...]] = {
    ("Q", "formal_claim"): ("claim_id", "semantics_digest"),
    ("A", "abstraction_adequate"): ("claim_id",),
    ("D", "evidence_determinate"): ("claim_id", "contract_digest"),
    ("R", "declared_adapter_conformance"): ("mechanism_id", "manifest_digest"),
    ("M", "declared_scope_covered"): (
        "claim_id",
        "channel",
        "inventory_scope_digest",
    ),
    ("V", "audit_verifier_packet_accepted"): ("claim_id", "verifier_id"),
}

VARIANT_BY_LAYER = {
    "Q": "Q:query-formation-failure",
    "A": "A:model-twin",
    "D": "D:finite-evidence-twin",
    "R": "R:declared-adapter-conformance-failure",
    "V": "V:audit-verifier-packet-failure",
}
M_VARIANTS = {"M:declared-mediation-failure", "M:declared-coverage-failure"}
ALL_VARIANTS = frozenset((*VARIANT_BY_LAYER.values(), *M_VARIANTS))


def _strict_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields differ from closed schema")


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{label} must be a non-empty string")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise TypeError(f"{label} must be a list of strings")
    return value


def _atom_sort_key(atom: "PremiseAtom") -> tuple[Any, ...]:
    return (LAYER_ORDER.index(atom.layer), atom.kind, atom.args)


@dataclass(frozen=True)
class PremiseAtom:
    layer: str
    kind: str
    args: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        signature = ATOM_SIGNATURES.get((self.layer, self.kind))
        if signature is None:
            raise ValueError("premise is not in the canonical atomic grammar")
        if tuple(name for name, _ in self.args) != signature:
            raise ValueError("premise arguments are not in canonical wire order")
        if any(
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name
            or not value
            for name, value in self.args
        ):
            raise TypeError("premise arguments must be non-empty string pairs")

    @classmethod
    def build(cls, layer: str, kind: str, **args: str) -> "PremiseAtom":
        signature = ATOM_SIGNATURES.get((layer, kind))
        if signature is None or set(args) != set(signature):
            raise ValueError("premise arguments do not match canonical signature")
        return cls(layer, kind, tuple((name, args[name]) for name in signature))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PremiseAtom":
        if not isinstance(raw, Mapping):
            raise TypeError("premise atom must be a mapping")
        _strict_keys(raw, {"layer", "kind", "args"}, "premise atom")
        layer = _nonempty_string(raw["layer"], "premise layer")
        kind = _nonempty_string(raw["kind"], "premise kind")
        pairs = raw["args"]
        if not isinstance(pairs, list):
            raise TypeError("premise args must be an ordered pair list")
        parsed: list[tuple[str, str]] = []
        for pair in pairs:
            if not isinstance(pair, list) or len(pair) != 2:
                raise TypeError("premise args entries must be two-item lists")
            parsed.append(
                (
                    _nonempty_string(pair[0], "premise argument name"),
                    _nonempty_string(pair[1], "premise argument value"),
                )
            )
        return cls(layer, kind, tuple(parsed))

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "kind": self.kind,
            "args": [[name, value] for name, value in self.args],
        }

    @property
    def atom_digest(self) -> str:
        return canonical_digest(self.as_dict())

    @property
    def arg_map(self) -> dict[str, str]:
        return dict(self.args)


@dataclass(frozen=True)
class CanonicalPremiseSet:
    atoms: tuple[PremiseAtom, ...]

    def __post_init__(self) -> None:
        if not self.atoms:
            raise ValueError("canonical premise set must be non-empty")
        if tuple(sorted(self.atoms, key=_atom_sort_key)) != self.atoms:
            raise ValueError("premise atoms are not in canonical order")
        digests = [atom.atom_digest for atom in self.atoms]
        if len(set(digests)) != len(digests):
            raise ValueError("duplicate canonical premise atom")

    @classmethod
    def build(cls, atoms: tuple[PremiseAtom, ...] | list[PremiseAtom]) -> "CanonicalPremiseSet":
        return cls(tuple(sorted(tuple(atoms), key=_atom_sort_key)))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CanonicalPremiseSet":
        if not isinstance(raw, Mapping):
            raise TypeError("premise set must be a mapping")
        _strict_keys(raw, {"schema", "grammar", "atoms"}, "premise set")
        if raw["schema"] != PREMISE_SET_SCHEMA or raw["grammar"] != PREMISE_GRAMMAR:
            raise ValueError("unsupported premise-set schema/grammar")
        atoms = raw["atoms"]
        if not isinstance(atoms, list):
            raise TypeError("premise-set atoms must be a list")
        return cls(tuple(PremiseAtom.from_dict(item) for item in atoms))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": PREMISE_SET_SCHEMA,
            "grammar": PREMISE_GRAMMAR,
            "atoms": [atom.as_dict() for atom in self.atoms],
        }

    @property
    def premise_set_digest(self) -> str:
        return canonical_digest(self.as_dict())


class PremiseEvaluationStatus(StrEnum):
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class PremiseEvaluation:
    status: PremiseEvaluationStatus
    details: tuple[str, ...] = ()


def evaluate_premise(
    atom: PremiseAtom, config: AssuranceConfiguration
) -> PremiseEvaluation:
    args = atom.arg_map
    if atom.layer in {"Q", "A", "D", "M", "V"} and args.get("claim_id") != config.claim_id:
        return PremiseEvaluation(PremiseEvaluationStatus.UNSATISFIED, ("claim_id:mismatch",))
    if atom.layer == "Q":
        if args["semantics_digest"] != config.claim_semantics_commitment:
            return PremiseEvaluation(
                PremiseEvaluationStatus.UNSATISFIED,
                ("claim_semantics_commitment:mismatch",),
            )
        errors = query_formation_errors(config)
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if not errors else PremiseEvaluationStatus.UNSATISFIED,
            errors,
        )
    if atom.layer == "A":
        result = ModelAdequacyChecker(config.spec, config.adequacy_case).check()
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if result.adequate else PremiseEvaluationStatus.UNSATISFIED,
            tuple(result.notes),
        )
    if atom.layer == "D":
        if args["contract_digest"] != contract_digest(config.contract):
            return PremiseEvaluation(PremiseEvaluationStatus.UNSATISFIED, ("contract_digest:mismatch",))
        value = evidence_determinate(config)
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if value else PremiseEvaluationStatus.UNSATISFIED,
            () if value else ("evidence_twin",),
        )
    if atom.layer == "R":
        mechanism_id = args["mechanism_id"]
        actual = declared_adapter_manifest_digest(config, mechanism_id)
        all_failures = declared_adapter_failures(config)
        failures = (
            *all_failures.get("__registry_snapshot__", ()),
            *all_failures.get("__registry__", ()),
            *all_failures.get(mechanism_id, ()),
        )
        if actual != args["manifest_digest"]:
            failures = (*failures, "manifest_digest:mismatch")
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if not failures else PremiseEvaluationStatus.UNSATISFIED,
            tuple(failures),
        )
    if atom.layer == "M":
        failures: list[str] = []
        if args["channel"] != config.inventory_scope.channel:
            failures.append("channel:mismatch")
        if args["inventory_scope_digest"] != config.inventory_scope.inventory_scope_digest:
            failures.append("inventory_scope_digest:mismatch")
        failures.extend(declared_scope_errors(config))
        exact = external_packet_result(config)
        if exact.first_failed_layer == "M":
            failures.extend(exact.errors)
        failures.extend(
            item.split(":", 1)[1]
            for item in exact.additional_detected_failures
            if item.startswith("M:")
        )
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if not failures else PremiseEvaluationStatus.UNSATISFIED,
            tuple(failures),
        )
    if atom.layer == "V":
        witness = config.evidence.payload.get("verification_witness")
        failures: list[str] = []
        if not isinstance(witness, Mapping):
            failures.append("verification_witness:missing")
        else:
            if witness.get("verifier_id") != args["verifier_id"]:
                failures.append("verifier_id:mismatch")
            if not witness.get("replay_id"):
                failures.append("verifier_replay:missing")
        exact = external_packet_result(config)
        if exact.first_failed_layer == "V":
            failures.extend(exact.errors)
        failures.extend(
            item for item in exact.additional_detected_failures if item.startswith("V:")
        )
        return PremiseEvaluation(
            PremiseEvaluationStatus.SATISFIED if not failures else PremiseEvaluationStatus.UNSATISFIED,
            tuple(failures),
        )
    return PremiseEvaluation(PremiseEvaluationStatus.UNSUPPORTED, ("unsupported premise",))


_CERT_KEYS = {
    "schema",
    "variant",
    "premise_set_digest",
    "removed_atom_digest",
    "base_configuration_digest",
    "extension_configuration_digest",
    "base_primary_verdict",
    "extension_primary_verdict",
    "first_failed_layer",
    "scope",
    "extension_admissibility_checked",
    "open_world",
    "inventory_completeness_proven",
    "native",
}

_NATIVE_KEYS = {
    "Q:query-formation-failure": {"schema_version", "gate_input_digest", "gate_result_digest", "details"},
    "A:model-twin": {
        "certificate_type",
        "schema_version",
        "case_digest",
        "spec_digest",
        "obligation_id",
        "pack",
        "execution_a",
        "execution_b",
        "abstract_world",
        "external_truth_a",
        "external_truth_b",
        "missing_semantics",
    },
    "D:finite-evidence-twin": {
        "certificate_type",
        "schema_version",
        "spec_digest",
        "spec",
        "query",
        "contract",
        "world_a",
        "world_b",
        "answer_a",
        "answer_b",
        "shared_observation",
        "separating_candidates",
        "derived_requirements",
        "threat_model",
    },
    "R:declared-adapter-conformance-failure": {
        "schema_version",
        "mechanism_id",
        "registry_digest",
        "manifest_digest",
        "errors",
        "gate_result_digest",
    },
    "M:declared-mediation-failure": {
        "schema_version",
        "inventory_scope_digest",
        "channel",
        "reason",
        "mediator",
        "checked_pairs",
        "bypass_witnesses",
        "gate_result_digest",
    },
    "M:declared-coverage-failure": {
        "schema_version",
        "inventory_scope_digest",
        "evidence_digest",
        "trust_context_digest",
        "verifier_result_digest",
        "errors",
        "gate_result_digest",
    },
    "V:audit-verifier-packet-failure": {
        "schema_version",
        "evidence_digest",
        "trust_context_digest",
        "verifier_result_digest",
        "errors",
        "gate_result_digest",
    },
}


def _validate_native(variant: str, native: Mapping[str, Any]) -> None:
    expected = _NATIVE_KEYS.get(variant)
    if expected is None:
        raise ValueError("unsupported minimality certificate variant")
    _strict_keys(native, expected, f"native {variant}")
    _nonempty_string(native["schema_version"], "native schema_version")
    for key, value in native.items():
        if key.endswith("digest") and value is not None:
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise TypeError(f"native {key} must be a SHA-256 digest")
    if variant == "A:model-twin":
        if not isinstance(native["external_truth_a"], bool) or not isinstance(native["external_truth_b"], bool):
            raise TypeError("model-twin truth fields must be booleans")
        for key in ("execution_a", "execution_b", "abstract_world"):
            if not isinstance(native[key], Mapping):
                raise TypeError(f"model-twin {key} must be a mapping")
        _string_list(native["missing_semantics"], "model-twin missing_semantics")
    if variant == "D:finite-evidence-twin":
        for key in ("world_a", "world_b", "shared_observation"):
            if not isinstance(native[key], Mapping):
                raise TypeError(f"evidence-twin {key} must be a mapping")
        for key in ("contract", "separating_candidates", "derived_requirements"):
            _string_list(native[key], f"evidence-twin {key}")
    if variant == "M:declared-mediation-failure":
        for key in ("checked_pairs", "bypass_witnesses"):
            rows = native[key]
            if not isinstance(rows, list) or any(
                not isinstance(row, list)
                or any(not isinstance(item, str) for item in row)
                for row in rows
            ):
                raise TypeError(f"mediation {key} must be a string-list matrix")
        if native["reason"] is not None and not isinstance(native["reason"], str):
            raise TypeError("mediation reason must be a string or null")
        if native["mediator"] is not None and not isinstance(native["mediator"], str):
            raise TypeError("mediation mediator must be a string or null")
    if "errors" in native:
        _string_list(native["errors"], "native errors")
    if "details" in native:
        _string_list(native["details"], "native details")


@dataclass(frozen=True)
class PMinimalityCertificate:
    variant: str
    premise_set_digest: str
    removed_atom_digest: str
    base_configuration_digest: str
    extension_configuration_digest: str
    base_primary_verdict: str
    extension_primary_verdict: str
    first_failed_layer: str
    native: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.variant not in ALL_VARIANTS:
            raise ValueError("unsupported minimality certificate variant")
        for label, value in (
            ("premise_set_digest", self.premise_set_digest),
            ("removed_atom_digest", self.removed_atom_digest),
            ("base_configuration_digest", self.base_configuration_digest),
            ("extension_configuration_digest", self.extension_configuration_digest),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"{label} must be a digest")
        for label, value in (
            ("base_primary_verdict", self.base_primary_verdict),
            ("extension_primary_verdict", self.extension_primary_verdict),
        ):
            if not isinstance(value, str) or not value:
                raise TypeError(f"{label} must be a non-empty string")
        if self.first_failed_layer not in LAYER_ORDER:
            raise ValueError("invalid first failed layer")
        if not isinstance(self.native, Mapping):
            raise TypeError("native credential must be a mapping")
        _validate_native(self.variant, self.native)
        detached = json.loads(json.dumps(dict(self.native), sort_keys=True))
        object.__setattr__(self, "native", MappingProxyType(detached))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PMinimalityCertificate":
        if not isinstance(raw, Mapping):
            raise TypeError("minimality certificate must be a mapping")
        _strict_keys(raw, _CERT_KEYS, "minimality certificate")
        if raw["schema"] != CERTIFICATE_SCHEMA or raw["scope"] != CERTIFICATE_SCOPE:
            raise ValueError("unsupported minimality certificate schema/scope")
        for key in (
            "extension_admissibility_checked",
            "open_world",
            "inventory_completeness_proven",
        ):
            if raw[key] is not False:
                raise ValueError(f"certificate boundary field must be false: {key}")
        native = raw["native"]
        if not isinstance(native, Mapping):
            raise TypeError("native credential must be a mapping")
        return cls(
            variant=_nonempty_string(raw["variant"], "certificate variant"),
            premise_set_digest=_nonempty_string(raw["premise_set_digest"], "premise-set digest"),
            removed_atom_digest=_nonempty_string(raw["removed_atom_digest"], "removed-atom digest"),
            base_configuration_digest=_nonempty_string(raw["base_configuration_digest"], "base configuration digest"),
            extension_configuration_digest=_nonempty_string(raw["extension_configuration_digest"], "extension configuration digest"),
            base_primary_verdict=_nonempty_string(raw["base_primary_verdict"], "base primary verdict"),
            extension_primary_verdict=_nonempty_string(raw["extension_primary_verdict"], "extension primary verdict"),
            first_failed_layer=_nonempty_string(raw["first_failed_layer"], "first failed layer"),
            native=dict(native),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CERTIFICATE_SCHEMA,
            "variant": self.variant,
            "premise_set_digest": self.premise_set_digest,
            "removed_atom_digest": self.removed_atom_digest,
            "base_configuration_digest": self.base_configuration_digest,
            "extension_configuration_digest": self.extension_configuration_digest,
            "base_primary_verdict": self.base_primary_verdict,
            "extension_primary_verdict": self.extension_primary_verdict,
            "first_failed_layer": self.first_failed_layer,
            "scope": CERTIFICATE_SCOPE,
            "extension_admissibility_checked": False,
            "open_world": False,
            "inventory_completeness_proven": False,
            "native": dict(self.native),
        }

    @property
    def certificate_digest(self) -> str:
        return canonical_digest(self.as_dict())


def _failure_details(gate: ExactGateResult, layer: str) -> list[str]:
    for item in gate.trace:
        if item.layer == layer:
            return list(item.details)
    return []


def make_minimality_certificate(
    premise_set: CanonicalPremiseSet,
    removed: PremiseAtom,
    base: AssuranceConfiguration,
    extension: AssuranceConfiguration,
) -> PMinimalityCertificate:
    if removed not in premise_set.atoms:
        raise ValueError("removed atom is not a member of Pi")
    base_gate = run_exact_assurance_gate(base)
    extension_gate = run_exact_assurance_gate(extension)
    layer = removed.layer
    if extension_gate.first_failed_layer != layer:
        raise ValueError("extension first failure does not match removed premise")
    variant = VARIANT_BY_LAYER.get(layer)
    if layer == "Q":
        native = {
            "schema_version": "AuditSpec-query-formation-failure-v1",
            "gate_input_digest": extension.configuration_digest,
            "gate_result_digest": canonical_digest(extension_gate.as_dict()),
            "details": _failure_details(extension_gate, "Q"),
        }
    elif layer == "A":
        result = ModelAdequacyChecker(extension.spec, extension.adequacy_case).check()
        if result.certificate is None:
            raise ValueError("A deletion did not produce a model twin")
        native = result.certificate.as_dict()
    elif layer == "D":
        twin = finite_evidence_twin_certificate(extension)
        if twin is None:
            raise ValueError("D deletion did not produce a finite evidence twin")
        native = twin.as_dict()
    elif layer == "R":
        mechanism_id = removed.arg_map["mechanism_id"]
        all_failures = declared_adapter_failures(extension)
        failures = (
            *all_failures.get("__registry_snapshot__", ()),
            *all_failures.get("__registry__", ()),
            *all_failures.get(mechanism_id, ()),
        )
        native = {
            "schema_version": "AuditSpec-declared-adapter-failure-v1",
            "mechanism_id": mechanism_id,
            "registry_digest": registry_digest(),
            "manifest_digest": declared_adapter_manifest_digest(extension, mechanism_id),
            "errors": list(failures),
            "gate_result_digest": canonical_digest(extension_gate.as_dict()),
        }
    elif layer == "M":
        proof = declared_mediation_proof(extension)
        if not proof.valid:
            variant = "M:declared-mediation-failure"
            native = {
                "schema_version": "AuditSpec-declared-mediation-failure-v1",
                "inventory_scope_digest": extension.inventory_scope.inventory_scope_digest,
                "channel": proof.channel,
                "reason": proof.reason,
                "mediator": proof.mediator,
                "checked_pairs": [list(pair) for pair in proof.checked_pairs],
                "bypass_witnesses": [list(path) for path in proof.bypass_witnesses],
                "gate_result_digest": canonical_digest(extension_gate.as_dict()),
            }
        else:
            variant = "M:declared-coverage-failure"
            exact = external_packet_result(extension)
            if not (
                exact.primary_verdict.value == "TCB_GAP"
                and exact.first_failed_layer == "M"
                and exact.semantic_determinate
                and not exact.structural_assurance
                and exact.errors == ("coverage:incomplete",)
            ):
                raise ValueError(
                    "M coverage credential requires the singleton declared coverage failure"
                )
            native = {
                "schema_version": "AuditSpec-declared-coverage-failure-v1",
                "inventory_scope_digest": extension.inventory_scope.inventory_scope_digest,
                "evidence_digest": canonical_digest(extension.evidence.as_dict()),
                "trust_context_digest": trust_context_digest(extension.trust_context),
                "verifier_result_digest": canonical_digest(exact.as_dict(include_layer=True)),
                "errors": list(exact.errors),
                "gate_result_digest": canonical_digest(extension_gate.as_dict()),
            }
    elif layer == "V":
        exact = external_packet_result(extension)
        native = {
            "schema_version": "AuditSpec-audit-verifier-packet-failure-v1",
            "evidence_digest": canonical_digest(extension.evidence.as_dict()),
            "trust_context_digest": trust_context_digest(extension.trust_context),
            "verifier_result_digest": canonical_digest(exact.as_dict(include_layer=True)),
            "errors": list(exact.errors),
            "gate_result_digest": canonical_digest(extension_gate.as_dict()),
        }
    else:
        raise ValueError("unsupported certificate layer")
    assert variant is not None
    certificate = PMinimalityCertificate(
        variant=variant,
        premise_set_digest=premise_set.premise_set_digest,
        removed_atom_digest=removed.atom_digest,
        base_configuration_digest=base.configuration_digest,
        extension_configuration_digest=extension.configuration_digest,
        base_primary_verdict=str(base_gate.primary_verdict),
        extension_primary_verdict=str(extension_gate.primary_verdict),
        first_failed_layer=layer,
        native=native,
    )
    verification = verify_p_minimality_certificate(
        certificate, premise_set, removed, base, extension
    )
    if not verification.valid:
        raise ValueError(
            "generated minimality certificate does not verify: "
            + ",".join(verification.errors)
        )
    return certificate


@dataclass(frozen=True)
class PMinimalityVerificationResult:
    valid: bool
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "scope": CERTIFICATE_SCOPE,
            "extension_admissibility_checked": False,
            "open_world": False,
            "inventory_completeness_proven": False,
        }


def _native_valid_unchecked(
    certificate: PMinimalityCertificate,
    removed: PremiseAtom,
    extension: AssuranceConfiguration,
    extension_gate: ExactGateResult,
) -> bool:
    native = certificate.native
    variant = certificate.variant
    if variant == "Q:query-formation-failure":
        return bool(
            native["schema_version"] == "AuditSpec-query-formation-failure-v1"
            and native["gate_input_digest"] == extension.configuration_digest
            and native["gate_result_digest"] == canonical_digest(extension_gate.as_dict())
            and native["details"] == _failure_details(extension_gate, "Q")
        )
    if variant == "A:model-twin":
        twin = ModelTwinCertificate.from_dict(native)
        return ModelAdequacyChecker(extension.spec, extension.adequacy_case).verify_certificate(twin)
    if variant == "D:finite-evidence-twin":
        twin = TwinCertificate.from_dict(native)
        return AuditCompiler(extension.spec).verify_certificate(twin)
    if variant == "R:declared-adapter-conformance-failure":
        mechanism_id = removed.arg_map["mechanism_id"]
        all_failures = declared_adapter_failures(extension)
        failures = (
            *all_failures.get("__registry_snapshot__", ()),
            *all_failures.get("__registry__", ()),
            *all_failures.get(mechanism_id, ()),
        )
        return bool(
            native["schema_version"] == "AuditSpec-declared-adapter-failure-v1"
            and native["mechanism_id"] == mechanism_id
            and native["registry_digest"] == registry_digest()
            and native["manifest_digest"] == declared_adapter_manifest_digest(extension, mechanism_id)
            and native["errors"] == list(failures)
            and bool(failures)
            and native["gate_result_digest"] == canonical_digest(extension_gate.as_dict())
        )
    if variant == "M:declared-mediation-failure":
        proof = declared_mediation_proof(extension)
        return bool(
            native["schema_version"] == "AuditSpec-declared-mediation-failure-v1"
            and not proof.valid
            and native["inventory_scope_digest"] == extension.inventory_scope.inventory_scope_digest
            and native["channel"] == proof.channel
            and native["reason"] == proof.reason
            and native["mediator"] == proof.mediator
            and native["checked_pairs"] == [list(pair) for pair in proof.checked_pairs]
            and native["bypass_witnesses"] == [list(path) for path in proof.bypass_witnesses]
            and native["gate_result_digest"] == canonical_digest(extension_gate.as_dict())
        )
    if variant == "M:declared-coverage-failure":
        exact = external_packet_result(extension)
        return bool(
            native["schema_version"] == "AuditSpec-declared-coverage-failure-v1"
            and native["inventory_scope_digest"] == extension.inventory_scope.inventory_scope_digest
            and native["evidence_digest"] == canonical_digest(extension.evidence.as_dict())
            and native["trust_context_digest"] == trust_context_digest(extension.trust_context)
            and native["verifier_result_digest"] == canonical_digest(exact.as_dict(include_layer=True))
            and native["errors"] == list(exact.errors)
            and exact.primary_verdict.value == "TCB_GAP"
            and exact.first_failed_layer == "M"
            and exact.semantic_determinate
            and not exact.structural_assurance
            and exact.errors == ("coverage:incomplete",)
            and native["gate_result_digest"] == canonical_digest(extension_gate.as_dict())
        )
    if variant == "V:audit-verifier-packet-failure":
        exact = external_packet_result(extension)
        return bool(
            native["schema_version"] == "AuditSpec-audit-verifier-packet-failure-v1"
            and native["evidence_digest"] == canonical_digest(extension.evidence.as_dict())
            and native["trust_context_digest"] == trust_context_digest(extension.trust_context)
            and native["verifier_result_digest"] == canonical_digest(exact.as_dict(include_layer=True))
            and native["errors"] == list(exact.errors)
            and exact.first_failed_layer == "V"
            and native["gate_result_digest"] == canonical_digest(extension_gate.as_dict())
        )
    return False


def _native_valid(
    certificate: PMinimalityCertificate,
    removed: PremiseAtom,
    extension: AssuranceConfiguration,
    extension_gate: ExactGateResult,
) -> bool:
    try:
        return _native_valid_unchecked(
            certificate, removed, extension, extension_gate
        )
    except (KeyError, TypeError, ValueError):
        return False


def verify_p_minimality_certificate(
    certificate: PMinimalityCertificate,
    premise_set: CanonicalPremiseSet,
    removed: PremiseAtom,
    base: AssuranceConfiguration,
    extension: AssuranceConfiguration,
) -> PMinimalityVerificationResult:
    errors: list[str] = []
    try:
        _validate_native(certificate.variant, certificate.native)
    except (KeyError, TypeError, ValueError):
        errors.append("native_credential:closed_schema_violation")
    if removed not in premise_set.atoms:
        errors.append("removed_atom:not_in_premise_set")
    if certificate.premise_set_digest != premise_set.premise_set_digest:
        errors.append("premise_set_digest:mismatch")
    if certificate.removed_atom_digest != removed.atom_digest:
        errors.append("removed_atom_digest:mismatch")
    if certificate.base_configuration_digest != base.configuration_digest:
        errors.append("base_configuration_digest:mismatch")
    if certificate.extension_configuration_digest != extension.configuration_digest:
        errors.append("extension_configuration_digest:mismatch")
    for atom in premise_set.atoms:
        evaluation = evaluate_premise(atom, base)
        if evaluation.status is not PremiseEvaluationStatus.SATISFIED:
            errors.append(f"base_premise:{atom.atom_digest}:{evaluation.status}")
    removed_evaluation = evaluate_premise(removed, extension)
    if removed_evaluation.status is not PremiseEvaluationStatus.UNSATISFIED:
        errors.append(f"removed_premise:{removed_evaluation.status}")
    for atom in premise_set.atoms:
        if atom == removed:
            continue
        evaluation = evaluate_premise(atom, extension)
        if evaluation.status is not PremiseEvaluationStatus.SATISFIED:
            errors.append(f"remaining_premise:{atom.atom_digest}:{evaluation.status}")
    base_gate = run_exact_assurance_gate(base)
    extension_gate = run_exact_assurance_gate(extension)
    if not base_gate.supported_within_declared_tcb:
        errors.append("base_gate:not_supported")
    if extension_gate.supported_within_declared_tcb:
        errors.append("extension_gate:still_supported")
    if extension_gate.first_failed_layer != removed.layer:
        errors.append("first_failed_layer:mismatch")
    if certificate.base_primary_verdict != str(base_gate.primary_verdict):
        errors.append("base_primary_verdict:mismatch")
    if certificate.extension_primary_verdict != str(extension_gate.primary_verdict):
        errors.append("extension_primary_verdict:mismatch")
    if certificate.first_failed_layer != extension_gate.first_failed_layer:
        errors.append("certificate_first_failed_layer:mismatch")
    expected_variants = {VARIANT_BY_LAYER.get(removed.layer)}
    if removed.layer == "M":
        expected_variants = M_VARIANTS
    if certificate.variant not in expected_variants:
        errors.append("certificate_variant:wrong_layer")
    if not errors and not _native_valid(certificate, removed, extension, extension_gate):
        errors.append("native_credential:invalid")
    return PMinimalityVerificationResult(not errors, tuple(errors))


PMinimalityCertificateType: TypeAlias = PMinimalityCertificate
