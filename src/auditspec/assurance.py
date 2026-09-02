from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any

from .adapter_registry import (
    ADAPTER_MANIFESTS,
    REGISTRY_ATTESTATION_PATH,
    registry_attestation_status,
    registry_digest,
    validate_mechanism_adapter,
)
from .catalog import spec_digest
from .compiler import AuditCompiler
from .expr import referenced_names
from .external.claims import CLAIM_REGISTRY
from .external.evidence import (
    EVIDENCE_SCHEMA,
    ExternalEvidenceVerificationResult,
    ExternalTrustContext,
    ProjectedEvidence,
    verify_external_evidence,
)
from .inventory_authority import (
    InventoryAuthorityStatement,
    InventoryAuthorityTrustContext,
    InventoryAuthorityVerificationResult,
    ScheduleClosureTrustContext,
    ScheduleClosureVerificationResult,
    verify_inventory_authority_statement,
    verify_declared_schedule_closure_certificate,
)
from .isolated_verifier import (
    IsolatedExecutionReceipt,
    IsolatedVerifierInvocation,
    IsolationPolicy,
    execute_isolated_verifier,
    extract_isolated_input,
)
from .model import AuditSpec, TwinCertificate
from .model_adequacy import (
    AdequacyCase,
    AdequacyResult,
    AssuranceVerdict,
    ModelAdequacyChecker,
)
from .official_gate import (
    OFFICIAL_LIVE_PROFILE,
    OFFICIAL_RECEIPT_PROFILE,
    OfficialGateContext,
    OfficialGateExecutionReceipt,
    OfficialGateInvocation,
    execute_official_gate,
    official_gate_context_errors,
    official_gate_trust_errors,
)
from .runtime.events import canonical_json
from .topology import MediationProof, verify_mediation
from .verifier_registry import (
    RegisteredVerifierExecutionResult,
    RegisteredVerifierInvocation,
    execute_registered_verifier,
    extract_registered_verifier_input,
)

ASSURANCE_INPUT_SCHEMA = "AuditSpec-exact-assurance-input-v1"
ASSURANCE_GATE_SCHEMA = "AuditSpec-exact-assurance-gate-result-v1"
DECLARED_SCOPE_SCHEMA = "AuditSpec-declared-inventory-scope-v1"
ASSURANCE_SCOPE = "declared_finite_configuration"
EXTERNAL_VERIFIER_PROFILE = "v06_fixed_envelope"
REGISTERED_REEXECUTION_PROFILE = "v12_registered_reexecution"
ISOLATED_REEXECUTION_PROFILE = "v13_isolated_registered_reexecution"
LAYER_ORDER = ("Q", "A", "D", "R", "M", "V")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def contract_digest(contract: Sequence[str]) -> str:
    return canonical_digest(
        {"schema": "AuditSpec-contract-selection-v1", "contract": list(contract)}
    )


def adapter_manifest_digest(manifest_id: str) -> str | None:
    manifest = ADAPTER_MANIFESTS.get(manifest_id)
    return canonical_digest(manifest.as_dict()) if manifest is not None else None


def adapter_registry_attestation_digest() -> str:
    try:
        return hashlib.sha256(REGISTRY_ATTESTATION_PATH.read_bytes()).hexdigest()
    except OSError:
        return canonical_digest({"missing": REGISTRY_ATTESTATION_PATH.name})


def external_claim_registry_digest() -> str:
    return canonical_digest(
        {
            claim_id: asdict(definition)
            for claim_id, definition in sorted(CLAIM_REGISTRY.items())
        }
    )


@lru_cache(maxsize=1)
def assurance_implementation_digest() -> str:
    package = Path(__file__).resolve().parent
    paths = tuple(sorted(package.rglob("*.py")))
    return canonical_digest(
        {
            path.relative_to(package).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in paths
        }
    )


def trust_context_commitment_payload(trust: ExternalTrustContext) -> dict[str, Any]:
    return {
        "schema": "AuditSpec-external-trust-context-commitment-v1",
        "environment": trust.environment,
        "benchmark_revision": trust.benchmark_revision,
        "expected_run_id": trust.expected_run_id,
        "expected_task_id": trust.expected_task_id,
        "producer_key_digests": {
            name: hashlib.sha256(key).hexdigest()
            for name, key in sorted(trust.producer_keys.items())
        },
        "accepted_capture_points": sorted(trust.accepted_capture_points),
        "accepted_verifiers": sorted(trust.accepted_verifiers),
        "mandatory_coverage_channel": trust.mandatory_coverage_channel,
        "expected_claim_semantics_commitments": dict(
            sorted(trust.expected_claim_semantics_commitments.items())
        ),
    }


def trust_context_digest(trust: ExternalTrustContext) -> str:
    return canonical_digest(trust_context_commitment_payload(trust))


def claim_semantics_commitment_for(
    spec: AuditSpec,
    case: AdequacyCase,
    *,
    claim_id: str,
    query_name: str,
) -> str:
    query = spec.queries.get(query_name)
    expressions = [case.external_predicate, *case.concrete_constraints]
    if case.abstract_query is not None:
        expressions.append(case.abstract_query)
    if query is not None:
        expressions.append(query.expression)
    if case.abstraction is not None:
        expressions.extend(case.abstraction.values())
    referenced = set()
    for expression in expressions:
        referenced.update(referenced_names(expression))
    referenced &= set(spec.variables)
    relevant_constraints = []
    for constraint in spec.constraints:
        if referenced_names(constraint) & referenced:
            relevant_constraints.append(constraint)
    return canonical_digest(
        {
            "schema": "AuditSpec-claim-semantics-commitment-v2",
            "claim_id": claim_id,
            "adequacy_case": case.as_dict(),
            "query_name": query_name,
            "query_definition": asdict(query) if query is not None else None,
            "referenced_spec_variables": {
                name: list(spec.variables[name]) for name in sorted(referenced)
            },
            "referenced_fact_definitions": {
                name: asdict(spec.facts[name])
                for name in sorted(referenced & set(spec.facts))
            },
            "relevant_constraints": relevant_constraints,
            "output_schema": "boolean",
        }
    )


def declared_inventory_manifest(
    spec: AuditSpec, *, threat_model: str, channel: str
) -> dict[str, Any]:
    threat = spec.threat_models.get(threat_model)
    return {
        "schema": "AuditSpec-declared-inventory-manifest-v1",
        "spec_digest": spec_digest(spec),
        "threat_model": threat_model,
        "channel": channel,
        "topology": spec.topology.as_dict(),
        "bypass_edges": (
            [list(edge) for edge in threat.bypass_edges] if threat is not None else None
        ),
    }


@dataclass(frozen=True)
class DeclaredInventoryScope:
    scope_id: str
    channel: str
    inventory_manifest: Mapping[str, Any]
    authority_statement: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope_id, str) or not self.scope_id:
            raise ValueError("declared inventory scope_id must be non-empty")
        if not isinstance(self.channel, str) or not self.channel:
            raise ValueError("declared inventory channel must be non-empty")
        if not isinstance(self.inventory_manifest, Mapping):
            raise TypeError("declared inventory manifest must be a mapping")
        canonical_json(self.inventory_manifest)
        if self.authority_statement is not None:
            if not isinstance(self.authority_statement, Mapping):
                raise TypeError("inventory authority statement must be a mapping")
            InventoryAuthorityStatement.from_dict(self.authority_statement)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": DECLARED_SCOPE_SCHEMA,
            "scope_id": self.scope_id,
            "channel": self.channel,
            "basis": "declared-manifest-tcb-v1",
            "inventory_manifest": dict(self.inventory_manifest),
            "authority_statement": (
                dict(self.authority_statement)
                if self.authority_statement is not None
                else None
            ),
            "open_world": False,
            "inventory_completeness_proven": False,
        }

    @property
    def inventory_scope_digest(self) -> str:
        return canonical_digest(self.as_dict())


@dataclass(frozen=True)
class AssuranceConfiguration:
    configuration_id: str
    spec: AuditSpec
    adequacy_case: AdequacyCase
    claim_id: str
    query_name: str
    contract: tuple[str, ...]
    threat_model: str
    claim_semantics_commitment: str
    evidence: ProjectedEvidence
    trust_context: ExternalTrustContext
    inventory_scope: DeclaredInventoryScope
    external_verifier_profile: str = EXTERNAL_VERIFIER_PROFILE
    adapter_registry_snapshot: str = field(default_factory=registry_digest)
    adapter_registry_attestation_snapshot: str = field(
        default_factory=adapter_registry_attestation_digest
    )
    external_claim_registry_snapshot: str = field(
        default_factory=external_claim_registry_digest
    )
    implementation_snapshot: str = field(
        default_factory=assurance_implementation_digest
    )
    registered_verifier_invocation: RegisteredVerifierInvocation | None = None
    isolated_verifier_invocation: IsolatedVerifierInvocation | None = None
    isolation_policy: IsolationPolicy | None = None
    official_gate_invocation: OfficialGateInvocation | None = None
    official_gate_context: OfficialGateContext | None = None
    inventory_authority_required: bool = False
    inventory_authority_trust: InventoryAuthorityTrustContext | None = None
    schedule_closure_required: bool = False
    schedule_closure_certificate: Mapping[str, Any] | None = None
    schedule_closure_trust: ScheduleClosureTrustContext | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("configuration_id", self.configuration_id),
            ("claim_id", self.claim_id),
            ("query_name", self.query_name),
            ("threat_model", self.threat_model),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if tuple(sorted(set(self.contract))) != self.contract:
            raise ValueError("contract must be sorted and duplicate-free")
        if not _DIGEST.fullmatch(self.claim_semantics_commitment):
            raise ValueError("claim semantics commitment must be a SHA-256 digest")
        if self.external_verifier_profile not in {
            EXTERNAL_VERIFIER_PROFILE,
            REGISTERED_REEXECUTION_PROFILE,
            ISOLATED_REEXECUTION_PROFILE,
            OFFICIAL_RECEIPT_PROFILE,
            OFFICIAL_LIVE_PROFILE,
        }:
            raise ValueError("unsupported external verifier profile")
        if (
            self.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE
            and self.registered_verifier_invocation is None
        ):
            raise ValueError("registered reexecution profile needs an invocation")
        if self.external_verifier_profile == ISOLATED_REEXECUTION_PROFILE and (
            self.isolated_verifier_invocation is None or self.isolation_policy is None
        ):
            raise ValueError(
                "isolated reexecution profile needs an invocation and policy"
            )
        if self.external_verifier_profile in {
            OFFICIAL_RECEIPT_PROFILE,
            OFFICIAL_LIVE_PROFILE,
        } and (
            self.official_gate_invocation is None or self.official_gate_context is None
        ):
            raise ValueError("official gate profile needs an invocation and context")
        if (
            self.official_gate_invocation is not None
            and self.official_gate_invocation.profile != self.external_verifier_profile
        ):
            raise ValueError("official gate invocation/profile mismatch")
        if not isinstance(self.inventory_authority_required, bool):
            raise TypeError("inventory_authority_required must be Boolean")
        if self.inventory_authority_required and (
            self.inventory_scope.authority_statement is None
            or self.inventory_authority_trust is None
        ):
            raise ValueError(
                "required inventory authority needs a statement and trust context"
            )
        if not isinstance(self.schedule_closure_required, bool):
            raise TypeError("schedule_closure_required must be Boolean")
        if self.schedule_closure_certificate is not None:
            if not isinstance(self.schedule_closure_certificate, Mapping):
                raise TypeError("schedule closure certificate must be a mapping")
            canonical_json(self.schedule_closure_certificate)
        if self.schedule_closure_required and (
            self.schedule_closure_certificate is None
            or self.schedule_closure_trust is None
        ):
            raise ValueError("required schedule closure needs a certificate and trust")
        for label, value in (
            ("adapter_registry_snapshot", self.adapter_registry_snapshot),
            (
                "adapter_registry_attestation_snapshot",
                self.adapter_registry_attestation_snapshot,
            ),
            ("external_claim_registry_snapshot", self.external_claim_registry_snapshot),
            ("implementation_snapshot", self.implementation_snapshot),
        ):
            if not _DIGEST.fullmatch(value):
                raise ValueError(f"{label} must be a SHA-256 digest")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": ASSURANCE_INPUT_SCHEMA,
            "configuration_id": self.configuration_id,
            "spec_digest": spec_digest(self.spec),
            "adequacy_case": self.adequacy_case.as_dict(),
            "adequacy_case_digest": self.adequacy_case.digest,
            "claim_id": self.claim_id,
            "query_name": self.query_name,
            "contract": list(self.contract),
            "contract_digest": contract_digest(self.contract),
            "threat_model": self.threat_model,
            "claim_semantics_commitment": self.claim_semantics_commitment,
            "evidence": self.evidence.as_dict(),
            "trust_context": trust_context_commitment_payload(self.trust_context),
            "inventory_scope": self.inventory_scope.as_dict(),
            "external_verifier_profile": self.external_verifier_profile,
            "registered_verifier_invocation": (
                self.registered_verifier_invocation.as_dict()
                if self.registered_verifier_invocation is not None
                else None
            ),
            "isolated_verifier_invocation": (
                self.isolated_verifier_invocation.as_dict()
                if self.isolated_verifier_invocation is not None
                else None
            ),
            "isolation_policy": (
                self.isolation_policy.as_dict()
                if self.isolation_policy is not None
                else None
            ),
            "official_gate_invocation": (
                self.official_gate_invocation.as_dict()
                if self.official_gate_invocation is not None
                else None
            ),
            "official_gate_context": (
                self.official_gate_context.as_dict()
                if self.official_gate_context is not None
                else None
            ),
            "inventory_authority_required": self.inventory_authority_required,
            "inventory_authority_trust": (
                self.inventory_authority_trust.as_dict()
                if self.inventory_authority_trust is not None
                else None
            ),
            "schedule_closure_required": self.schedule_closure_required,
            "schedule_closure_certificate": (
                dict(self.schedule_closure_certificate)
                if self.schedule_closure_certificate is not None
                else None
            ),
            "schedule_closure_trust": (
                self.schedule_closure_trust.as_dict()
                if self.schedule_closure_trust is not None
                else None
            ),
            "adapter_registry_snapshot": self.adapter_registry_snapshot,
            "adapter_registry_attestation_snapshot": self.adapter_registry_attestation_snapshot,
            "external_claim_registry_snapshot": self.external_claim_registry_snapshot,
            "implementation_snapshot": self.implementation_snapshot,
            "execution_policy": "finite-enumeration-fail-closed-v1",
            "assurance_scope": ASSURANCE_SCOPE,
            "extension_admissibility_checked": False,
            "open_world": False,
            "inventory_completeness_proven": False,
        }

    @property
    def configuration_digest(self) -> str:
        return canonical_digest(self.as_dict())


class LayerStatus(StrEnum):
    PASS = "PASS"
    TYPED_FAIL = "TYPED_FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class GateLayerResult:
    layer: str
    status: LayerStatus
    details: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "status": str(self.status),
            "details": list(self.details),
        }


@dataclass(frozen=True)
class ExactGateResult:
    input_digest: str
    primary_verdict: AssuranceVerdict
    first_failed_layer: str | None
    supported_within_declared_tcb: bool
    trace: tuple[GateLayerResult, ...]
    adequacy_result: Mapping[str, Any] | None
    external_result: Mapping[str, Any] | None
    registered_verifier_result: Mapping[str, Any] | None = None
    isolated_verifier_result: Mapping[str, Any] | None = None
    official_gate_result: Mapping[str, Any] | None = None
    inventory_authority_result: Mapping[str, Any] | None = None
    schedule_closure_result: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": ASSURANCE_GATE_SCHEMA,
            "input_digest": self.input_digest,
            "primary_verdict": str(self.primary_verdict),
            "first_failed_layer": self.first_failed_layer,
            "supported_within_declared_tcb": self.supported_within_declared_tcb,
            "trace": [item.as_dict() for item in self.trace],
            "adequacy_result": dict(self.adequacy_result)
            if self.adequacy_result is not None
            else None,
            "external_result": dict(self.external_result)
            if self.external_result is not None
            else None,
            "registered_verifier_result": (
                dict(self.registered_verifier_result)
                if self.registered_verifier_result is not None
                else None
            ),
            "isolated_verifier_result": (
                dict(self.isolated_verifier_result)
                if self.isolated_verifier_result is not None
                else None
            ),
            "official_gate_result": (
                dict(self.official_gate_result)
                if self.official_gate_result is not None
                else None
            ),
            "inventory_authority_result": (
                dict(self.inventory_authority_result)
                if self.inventory_authority_result is not None
                else None
            ),
            "schedule_closure_result": (
                dict(self.schedule_closure_result)
                if self.schedule_closure_result is not None
                else None
            ),
            "assurance_scope": ASSURANCE_SCOPE,
            "extension_admissibility_checked": False,
            "open_world": False,
            "inventory_completeness_proven": False,
        }


def query_formation_errors(config: AssuranceConfiguration) -> tuple[str, ...]:
    errors: list[str] = []
    if config.claim_id != config.adequacy_case.obligation_id:
        errors.append("claim_case:mismatch")
    if config.evidence.claim_id != config.claim_id:
        errors.append("claim_evidence:mismatch")
    definition = CLAIM_REGISTRY.get(config.claim_id)
    if config.evidence.schema != EVIDENCE_SCHEMA or definition is None:
        errors.append("claim_or_schema:unregistered")
    elif definition.environment != config.evidence.environment:
        errors.append("claim_environment:mismatch")
    if config.external_claim_registry_snapshot != external_claim_registry_digest():
        errors.append("external_claim_registry_snapshot:mismatch")
    if config.implementation_snapshot != assurance_implementation_digest():
        errors.append("assurance_implementation_snapshot:mismatch")
    query = config.spec.queries.get(config.query_name)
    if query is None:
        errors.append("query:missing")
    elif config.adequacy_case.abstract_query != query.expression:
        errors.append("query_expression:mismatch")
    expected = claim_semantics_commitment_for(
        config.spec,
        config.adequacy_case,
        claim_id=config.claim_id,
        query_name=config.query_name,
    )
    if config.claim_semantics_commitment != expected:
        errors.append("claim_semantics_commitment:mismatch")
    if (
        config.trust_context.expected_claim_semantics_commitments.get(config.claim_id)
        != expected
    ):
        errors.append("trust_claim_semantics_commitment:mismatch")
    if config.threat_model not in config.spec.threat_models:
        errors.append("threat_model:missing")
    if set(config.contract) - set(config.spec.mechanisms):
        errors.append("contract:unknown_mechanism")
    if (
        config.inventory_scope.channel
        != config.trust_context.mandatory_coverage_channel
    ):
        errors.append("inventory_scope_channel:mismatch")
    if config.registered_verifier_invocation is not None:
        invocation = config.registered_verifier_invocation
        witness = config.evidence.payload.get("verification_witness")
        if invocation.claim_id != config.claim_id:
            errors.append("registered_verifier_claim:mismatch")
        if not isinstance(witness, Mapping):
            errors.append("registered_verifier_witness:missing")
        else:
            if invocation.verifier_id != witness.get("verifier_id"):
                errors.append("registered_verifier_id:mismatch")
            if invocation.replay_id != witness.get("replay_id"):
                errors.append("registered_verifier_replay:mismatch")
    if config.isolated_verifier_invocation is not None:
        invocation = config.isolated_verifier_invocation
        witness = config.evidence.payload.get("verification_witness")
        if invocation.claim_id != config.claim_id:
            errors.append("isolated_verifier_claim:mismatch")
        if not isinstance(witness, Mapping):
            errors.append("isolated_verifier_witness:missing")
        else:
            if invocation.verifier_id != witness.get("verifier_id"):
                errors.append("isolated_verifier_id:mismatch")
            if invocation.replay_id != witness.get("replay_id"):
                errors.append("isolated_verifier_replay:mismatch")
    if config.official_gate_invocation is not None:
        invocation = config.official_gate_invocation
        witness = config.evidence.payload.get("verification_witness")
        if invocation.claim_id != config.claim_id:
            errors.append("official_gate_claim:mismatch")
        if invocation.environment != config.evidence.environment:
            errors.append("official_gate_environment:mismatch")
        if invocation.run_id != config.trust_context.expected_run_id:
            errors.append("official_gate_run:mismatch")
        if invocation.task_id != config.trust_context.expected_task_id:
            errors.append("official_gate_task:mismatch")
        if invocation.claim_semantics_commitment != config.claim_semantics_commitment:
            errors.append("official_gate_claim_semantics:mismatch")
        if not isinstance(witness, Mapping):
            errors.append("official_gate_witness:missing")
        else:
            if invocation.verifier_id != witness.get("verifier_id"):
                errors.append("official_gate_verifier:mismatch")
            if witness.get("replay_id") != f"v14:{invocation.gate_row_digest}":
                errors.append("official_gate_replay:mismatch")
    return tuple(errors)


def adequacy_result(config: AssuranceConfiguration) -> AdequacyResult:
    return ModelAdequacyChecker(config.spec, config.adequacy_case).check()


def _raw_evidence_twin(
    config: AssuranceConfiguration,
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    compiler = AuditCompiler(config.spec)
    buckets: dict[Any, tuple[Any, Mapping[str, Any]]] = {}
    for world, answer in zip(
        compiler.worlds, compiler.query_answers(config.query_name)
    ):
        observation = compiler.observation(world, config.contract)
        prior = buckets.get(observation)
        if prior is not None and prior[0] != answer:
            return dict(prior[1]), dict(world)
        buckets.setdefault(observation, (answer, dict(world)))
    return None


def evidence_determinate(config: AssuranceConfiguration) -> bool:
    try:
        return _raw_evidence_twin(config) is None
    except (KeyError, TypeError, ValueError):
        return False


def finite_evidence_twin_certificate(
    config: AssuranceConfiguration,
) -> TwinCertificate | None:
    try:
        check = AuditCompiler(config.spec).check_contract(
            config.query_name,
            config.contract,
            threat_model=config.threat_model,
        )
    except (KeyError, TypeError, ValueError):
        return None
    return check.certificate


def declared_adapter_failures(
    config: AssuranceConfiguration,
) -> dict[str, tuple[str, ...]]:
    failures: dict[str, tuple[str, ...]] = {}
    snapshot_errors: list[str] = []
    if config.adapter_registry_snapshot != registry_digest():
        snapshot_errors.append("mismatch:adapter_registry_snapshot")
    if (
        config.adapter_registry_attestation_snapshot
        != adapter_registry_attestation_digest()
    ):
        snapshot_errors.append("mismatch:adapter_registry_attestation_snapshot")
    if snapshot_errors:
        failures["__registry_snapshot__"] = tuple(snapshot_errors)
    attested, attestation_errors = registry_attestation_status()
    if not attested:
        failures["__registry__"] = attestation_errors
    for name in config.contract:
        mechanism = config.spec.mechanisms.get(name)
        if mechanism is None:
            failures[name] = ("unknown:mechanism",)
            continue
        reasons = list(validate_mechanism_adapter(mechanism))
        for dependency in mechanism.requires:
            if dependency not in config.spec.mechanisms:
                reasons.append(f"missing:mechanism_dependency:{dependency}")
            elif dependency not in config.contract:
                reasons.append(f"missing:selected_dependency:{dependency}")
        if reasons:
            failures[name] = tuple(sorted(set(reasons)))
    return failures


def declared_mediation_proof(config: AssuranceConfiguration) -> MediationProof:
    threat = config.spec.threat_models[config.threat_model]
    return verify_mediation(
        config.spec.topology,
        config.inventory_scope.channel,
        bypass_edges=threat.bypass_edges,
    )


def inventory_authority_result(
    config: AssuranceConfiguration,
) -> InventoryAuthorityVerificationResult | None:
    if not config.inventory_authority_required:
        return None
    if (
        config.inventory_scope.authority_statement is None
        or config.inventory_authority_trust is None
    ):
        raise ValueError("required inventory authority inputs are missing")
    statement = InventoryAuthorityStatement.from_dict(
        config.inventory_scope.authority_statement
    )
    return verify_inventory_authority_statement(
        statement,
        scope_id=config.inventory_scope.scope_id,
        channel=config.inventory_scope.channel,
        inventory_manifest=config.inventory_scope.inventory_manifest,
        trust=config.inventory_authority_trust,
    )


def schedule_closure_result(
    config: AssuranceConfiguration,
) -> ScheduleClosureVerificationResult | None:
    if config.schedule_closure_certificate is None:
        return None
    return verify_declared_schedule_closure_certificate(
        config.schedule_closure_certificate,
        config.schedule_closure_trust,
    )


def declared_scope_check(
    config: AssuranceConfiguration,
) -> tuple[
    tuple[str, ...],
    InventoryAuthorityVerificationResult | None,
    ScheduleClosureVerificationResult | None,
]:
    errors: list[str] = []
    expected = declared_inventory_manifest(
        config.spec,
        threat_model=config.threat_model,
        channel=config.inventory_scope.channel,
    )
    if dict(config.inventory_scope.inventory_manifest) != expected:
        errors.append("inventory_manifest:mismatch")
    proof = declared_mediation_proof(config)
    if not proof.valid:
        errors.append(f"mediation:{proof.reason or 'invalid'}")
    authority = inventory_authority_result(config)
    if authority is not None and not authority.valid:
        errors.extend(f"inventory_authority:{error}" for error in authority.errors)
    closure = schedule_closure_result(config)
    if config.schedule_closure_required and (
        closure is None or config.schedule_closure_trust is None
    ):
        errors.append("schedule_closure:missing_or_untrusted")
    if closure is not None and not closure.valid:
        errors.extend(f"schedule_closure:{error}" for error in closure.errors)
    if config.external_verifier_profile in {
        OFFICIAL_RECEIPT_PROFILE,
        OFFICIAL_LIVE_PROFILE,
    }:
        if (
            config.official_gate_invocation is None
            or config.official_gate_context is None
        ):
            errors.append("official_gate:configuration_missing")
        else:
            errors.extend(
                f"official_gate_context:{error}"
                for error in official_gate_context_errors(config.official_gate_context)
            )
            errors.extend(
                f"official_gate_trust:{error}"
                for error in official_gate_trust_errors(
                    config.official_gate_invocation,
                    config.official_gate_context,
                    config.trust_context,
                )
            )
    return tuple(errors), authority, closure


def declared_scope_errors(config: AssuranceConfiguration) -> tuple[str, ...]:
    return declared_scope_check(config)[0]


def external_packet_result(
    config: AssuranceConfiguration,
) -> ExternalEvidenceVerificationResult:
    return verify_external_evidence(config.evidence, config.trust_context)


def _trace_with_failure(
    passed: Sequence[GateLayerResult], layer: str, details: Sequence[str]
) -> tuple[GateLayerResult, ...]:
    trace = list(passed)
    trace.append(GateLayerResult(layer, LayerStatus.TYPED_FAIL, tuple(details)))
    start = LAYER_ORDER.index(layer) + 1
    trace.extend(
        GateLayerResult(item, LayerStatus.SKIPPED) for item in LAYER_ORDER[start:]
    )
    return tuple(trace)


def _failure(
    config: AssuranceConfiguration,
    passed: Sequence[GateLayerResult],
    *,
    layer: str,
    verdict: AssuranceVerdict,
    details: Sequence[str],
    adequacy: AdequacyResult | None = None,
    external: ExternalEvidenceVerificationResult | None = None,
    registered: RegisteredVerifierExecutionResult | None = None,
    isolated: IsolatedExecutionReceipt | None = None,
    official_gate: OfficialGateExecutionReceipt | None = None,
    inventory_authority: InventoryAuthorityVerificationResult | None = None,
    schedule_closure: ScheduleClosureVerificationResult | None = None,
) -> ExactGateResult:
    return ExactGateResult(
        input_digest=config.configuration_digest,
        primary_verdict=verdict,
        first_failed_layer=layer,
        supported_within_declared_tcb=False,
        trace=_trace_with_failure(passed, layer, details),
        adequacy_result=adequacy.as_dict() if adequacy is not None else None,
        external_result=(
            external.as_dict(include_layer=True) if external is not None else None
        ),
        registered_verifier_result=(
            registered.as_dict() if registered is not None else None
        ),
        isolated_verifier_result=(isolated.as_dict() if isolated is not None else None),
        official_gate_result=(
            official_gate.as_dict() if official_gate is not None else None
        ),
        inventory_authority_result=(
            inventory_authority.as_dict() if inventory_authority is not None else None
        ),
        schedule_closure_result=(
            schedule_closure.as_dict() if schedule_closure is not None else None
        ),
    )


def run_exact_assurance_gate(config: AssuranceConfiguration) -> ExactGateResult:
    passed: list[GateLayerResult] = []
    try:
        q_errors = query_formation_errors(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        q_errors = (f"exception:{type(exc).__name__}:{exc}",)
    if q_errors:
        return _failure(
            config,
            passed,
            layer="Q",
            verdict=AssuranceVerdict.QUERY_GAP,
            details=q_errors,
        )
    passed.append(GateLayerResult("Q", LayerStatus.PASS))

    try:
        adequate = adequacy_result(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _failure(
            config,
            passed,
            layer="A",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=(f"exception:{type(exc).__name__}:{exc}",),
        )
    if not adequate.adequate:
        layer = "A" if adequate.verdict is AssuranceVerdict.MODEL_GAP else "Q"
        return _failure(
            config,
            passed[:-1] if layer == "Q" else passed,
            layer=layer,
            verdict=adequate.verdict or AssuranceVerdict.QUERY_GAP,
            details=adequate.notes,
            adequacy=adequate,
        )
    passed.append(GateLayerResult("A", LayerStatus.PASS))

    try:
        exact = external_packet_result(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _failure(
            config,
            passed,
            layer="V",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=(f"exception:{type(exc).__name__}:{exc}",),
            adequacy=adequate,
        )
    if exact.first_failed_layer == "Q":
        return _failure(
            config,
            (),
            layer="Q",
            verdict=AssuranceVerdict.QUERY_GAP,
            details=exact.errors,
            adequacy=adequate,
            external=exact,
        )
    try:
        determinate = evidence_determinate(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _failure(
            config,
            passed,
            layer="D",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=(f"exception:{type(exc).__name__}:{exc}",),
            adequacy=adequate,
            external=exact,
        )
    if not determinate or exact.first_failed_layer == "D":
        details = (
            exact.errors if exact.first_failed_layer == "D" else ("evidence_twin",)
        )
        return _failure(
            config,
            passed,
            layer="D",
            verdict=AssuranceVerdict.EVIDENCE_GAP,
            details=details,
            adequacy=adequate,
            external=exact,
        )
    passed.append(GateLayerResult("D", LayerStatus.PASS))

    try:
        adapter_errors = declared_adapter_failures(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _failure(
            config,
            passed,
            layer="R",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=(f"exception:{type(exc).__name__}:{exc}",),
            adequacy=adequate,
            external=exact,
        )
    if adapter_errors or exact.first_failed_layer == "R":
        details = (
            tuple(
                f"{name}:{reason}"
                for name, reasons in sorted(adapter_errors.items())
                for reason in reasons
            )
            or exact.errors
        )
        return _failure(
            config,
            passed,
            layer="R",
            verdict=AssuranceVerdict.TCB_GAP,
            details=details,
            adequacy=adequate,
            external=exact,
        )
    passed.append(GateLayerResult("R", LayerStatus.PASS))

    authority: InventoryAuthorityVerificationResult | None = None
    closure: ScheduleClosureVerificationResult | None = None
    try:
        scope_errors, authority, closure = declared_scope_check(config)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return _failure(
            config,
            passed,
            layer="M",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=(f"exception:{type(exc).__name__}:{exc}",),
            adequacy=adequate,
            external=exact,
        )
    if scope_errors or exact.first_failed_layer == "M":
        return _failure(
            config,
            passed,
            layer="M",
            verdict=AssuranceVerdict.TCB_GAP,
            details=scope_errors or exact.errors,
            adequacy=adequate,
            external=exact,
            inventory_authority=authority,
            schedule_closure=closure,
        )
    passed.append(GateLayerResult("M", LayerStatus.PASS))

    if (
        exact.first_failed_layer == "V"
        or exact.primary_verdict is AssuranceVerdict.VERIFICATION_FAILURE
    ):
        return _failure(
            config,
            passed,
            layer="V",
            verdict=AssuranceVerdict.VERIFICATION_FAILURE,
            details=exact.errors,
            adequacy=adequate,
            external=exact,
            inventory_authority=authority,
        )
    registered: RegisteredVerifierExecutionResult | None = None
    isolated: IsolatedExecutionReceipt | None = None
    official_gate: OfficialGateExecutionReceipt | None = None
    if config.external_verifier_profile == REGISTERED_REEXECUTION_PROFILE:
        assert config.registered_verifier_invocation is not None
        witness = config.evidence.payload.get("verification_witness")
        declared_value = (
            witness.get("declared_value") if isinstance(witness, Mapping) else None
        )
        try:
            derived_input = extract_registered_verifier_input(
                config.registered_verifier_invocation,
                config.evidence.payload,
            )
        except (KeyError, TypeError, ValueError) as exc:
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=(f"registered_verifier_input:{type(exc).__name__}:{exc}",),
                adequacy=adequate,
                external=exact,
                inventory_authority=authority,
            )
        registered = execute_registered_verifier(
            config.registered_verifier_invocation,
            derived_input,
        )
        errors = list(registered.errors)
        if not registered.executed:
            errors.append("registered_verifier:not_executed")
        elif registered.answer != declared_value:
            errors.append("registered_verifier_answer:mismatch")
        if errors:
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=tuple(errors),
                adequacy=adequate,
                external=exact,
                registered=registered,
                inventory_authority=authority,
            )
    if config.external_verifier_profile == ISOLATED_REEXECUTION_PROFILE:
        if (
            config.isolated_verifier_invocation is None
            or config.isolation_policy is None
        ):
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=("isolated_verifier:configuration_missing",),
                adequacy=adequate,
                external=exact,
                inventory_authority=authority,
            )
        witness = config.evidence.payload.get("verification_witness")
        declared_value = (
            witness.get("declared_value") if isinstance(witness, Mapping) else None
        )
        try:
            derived_input = extract_isolated_input(
                config.isolated_verifier_invocation,
                config.evidence.payload,
            )
        except (KeyError, TypeError, ValueError) as exc:
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=(f"isolated_verifier_input:{type(exc).__name__}:{exc}",),
                adequacy=adequate,
                external=exact,
                inventory_authority=authority,
            )
        isolated = execute_isolated_verifier(
            config.isolated_verifier_invocation,
            derived_input,
            config.isolation_policy,
        )
        isolated_errors = list(isolated.errors)
        if not isolated.executed:
            isolated_errors.append("isolated_verifier:not_executed")
        elif isolated.answer != declared_value:
            isolated_errors.append("isolated_verifier_answer:mismatch")
        if isolated_errors:
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=tuple(isolated_errors),
                adequacy=adequate,
                external=exact,
                isolated=isolated,
                inventory_authority=authority,
            )
    if config.external_verifier_profile in {
        OFFICIAL_RECEIPT_PROFILE,
        OFFICIAL_LIVE_PROFILE,
    }:
        if (
            config.official_gate_invocation is None
            or config.official_gate_context is None
        ):
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=("official_gate:configuration_missing",),
                adequacy=adequate,
                external=exact,
                inventory_authority=authority,
            )
        witness = config.evidence.payload.get("verification_witness")
        declared_value = (
            witness.get("declared_value") if isinstance(witness, Mapping) else None
        )
        official_gate = execute_official_gate(
            config.official_gate_invocation,
            config.official_gate_context,
            config.evidence.payload,
        )
        gate_errors = list(official_gate.errors)
        if not official_gate.accepted:
            gate_errors.append("official_gate:not_accepted")
        elif official_gate.answer != declared_value:
            gate_errors.append("official_gate_answer:mismatch")
        if gate_errors:
            return _failure(
                config,
                passed,
                layer="V",
                verdict=AssuranceVerdict.VERIFICATION_FAILURE,
                details=tuple(gate_errors),
                adequacy=adequate,
                external=exact,
                official_gate=official_gate,
                inventory_authority=authority,
            )
    if exact.primary_verdict is not AssuranceVerdict.VERIFIED_AUDITABLE:
        layer = exact.first_failed_layer or "V"
        return _failure(
            config,
            passed,
            layer=layer if layer in LAYER_ORDER else "V",
            verdict=exact.primary_verdict,
            details=exact.errors,
            adequacy=adequate,
            external=exact,
            isolated=isolated,
            official_gate=official_gate,
            inventory_authority=authority,
        )
    passed.append(GateLayerResult("V", LayerStatus.PASS))
    return ExactGateResult(
        input_digest=config.configuration_digest,
        primary_verdict=AssuranceVerdict.VERIFIED_AUDITABLE,
        first_failed_layer=None,
        supported_within_declared_tcb=True,
        trace=tuple(passed),
        adequacy_result=adequate.as_dict(),
        external_result=exact.as_dict(include_layer=True),
        registered_verifier_result=(
            registered.as_dict() if registered is not None else None
        ),
        isolated_verifier_result=(isolated.as_dict() if isolated is not None else None),
        official_gate_result=(
            official_gate.as_dict() if official_gate is not None else None
        ),
        inventory_authority_result=(
            authority.as_dict() if authority is not None else None
        ),
        schedule_closure_result=(
            closure.as_dict() if closure is not None else None
        ),
    )


def declared_adapter_manifest_digest(
    config: AssuranceConfiguration, mechanism_id: str
) -> str | None:
    mechanism = config.spec.mechanisms.get(mechanism_id)
    return adapter_manifest_digest(mechanism.adapter) if mechanism is not None else None


def current_registry_digest() -> str:
    return registry_digest()
