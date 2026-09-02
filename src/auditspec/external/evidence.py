"""Evidence projections for executable external-agent evaluations.

The benchmark oracle and the auditor-visible evidence are deliberately separate.
An :class:`ExternalEvidenceSource` may contain a witness produced by an
independent evaluator replay, but it never contains the original oracle record.
Projection and verification code therefore cannot read hidden benchmark truth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import hashlib
import hmac
from typing import Any, Mapping, Sequence

from ..model_adequacy import AssuranceVerdict
from ..runtime.events import canonical_json
from .claims import CLAIM_REGISTRY
from .claims_v07 import EvidenceStack, V07ClaimDefinition
from .record import NormalizedRunRecord
from .semantic_freshness import valid_claim_semantics_commitment


EVIDENCE_SCHEMA = "AuditSpec-external-evidence-v1"
PAIR_SCHEMA = "AuditSpec-external-ambiguous-pair-v1"
_FORBIDDEN_RAW_ORACLE_KEYS = frozenset(
    {"oracle_checks", "reward_info", "test_tracker"}
)


def _json_copy(value: Any) -> Any:
    """Return a detached JSON value and reject opaque runtime objects."""

    import json

    return json.loads(canonical_json(value))


def _contains_forbidden_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return bool(_FORBIDDEN_RAW_ORACLE_KEYS & {str(key) for key in value}) or any(
            _contains_forbidden_key(item) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_key(item) for item in value)
    return False


@dataclass(frozen=True)
class IndependentVerifierWitness:
    """Output of a second evaluator execution, distinct from the truth oracle."""

    witness_id: str
    claim_id: str
    statement: str
    declared_value: bool
    verifier_id: str
    replay_id: str
    computation: str
    evidence_components: Mapping[str, Any] = field(default_factory=dict)
    claim_semantics_commitment: str | None = None

    def __post_init__(self) -> None:
        required = (
            self.witness_id,
            self.claim_id,
            self.statement,
            self.verifier_id,
            self.replay_id,
            self.computation,
        )
        if any(not value for value in required):
            raise ValueError("independent verifier witness fields must be non-empty")
        if _contains_forbidden_key(self.evidence_components):
            raise ValueError("raw oracle objects cannot be embedded in evidence")
        if self.claim_semantics_commitment is not None and not (
            valid_claim_semantics_commitment(self.claim_semantics_commitment)
        ):
            raise ValueError("claim semantics commitment must be a SHA-256 digest")

    def as_dict(self, *, include_components: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "witness_id": self.witness_id,
            "claim_id": self.claim_id,
            "statement": self.statement,
            "declared_value": self.declared_value,
            "verifier_id": self.verifier_id,
            "replay_id": self.replay_id,
            "computation": self.computation,
        }
        if include_components:
            result["evidence_components"] = _json_copy(self.evidence_components)
        if self.claim_semantics_commitment is not None:
            result["claim_semantics_commitment"] = self.claim_semantics_commitment
        return result

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "IndependentVerifierWitness":
        return cls(
            witness_id=str(value["witness_id"]),
            claim_id=str(value["claim_id"]),
            statement=str(value["statement"]),
            declared_value=bool(value["declared_value"]),
            verifier_id=str(value["verifier_id"]),
            replay_id=str(value["replay_id"]),
            computation=str(value["computation"]),
            evidence_components=dict(value.get("evidence_components", {})),
            claim_semantics_commitment=(
                str(value["claim_semantics_commitment"])
                if value.get("claim_semantics_commitment") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class EvidenceAttestation:
    """Run/claim binding and capture assertions retained with a witness.

    The trailing optional fields carry the v0.7 query-specific receipts and
    the producer-signed derivation result for claims whose contract has no
    independent verifier witness. They are part of the signed payload, so a
    producer signature authenticates them exactly like the v0.6 fields.
    """

    run_id: str
    task_id: str
    claim_id: str
    benchmark_revision: str
    witness_id: str
    producer: str
    capture_point: str
    verifier_id: str
    binding_edges: tuple[tuple[str, str], ...]
    coverage_channel: str
    coverage_complete: bool
    signature: str = ""
    claim_result: bool | None = None
    state_diff_receipt: Mapping[str, Any] | None = None
    api_call_log_receipt: Mapping[str, Any] | None = None
    replay_intervention_witness: Mapping[str, Any] | None = None
    version_fingerprint_witness: Mapping[str, Any] | None = None
    policy_text_hash: str | None = None
    # v0.8 instrumented-runtime receipts. These are signed exactly like the
    # fields above, but ``None``-valued entries are omitted from the signed
    # payload so attestations minted before v0.8 keep their signatures.
    write_effect_ledger: Mapping[str, Any] | None = None
    termination_receipt: Mapping[str, Any] | None = None
    tool_result_coverage: Mapping[str, Any] | None = None
    policy_delivery_receipt: Mapping[str, Any] | None = None
    # Optional so historical evidence remains byte-compatible.  When present,
    # it is signed and must match the independently supplied trust expectation.
    claim_semantics_commitment: str | None = None
    # A parsed historical attestation must retain exactly which optional v0.7
    # fields were present in its signed JSON payload.  ``None`` means a newly
    # constructed/current attestation and preserves the established behavior
    # of serializing every v0.7 field (including explicit nulls).
    _signed_optional_fields: frozenset[str] | None = field(
        default=None, repr=False, compare=False
    )

    _V08_RECEIPT_FIELDS = (
        "write_effect_ledger",
        "termination_receipt",
        "tool_result_coverage",
        "policy_delivery_receipt",
    )
    _V07_OPTIONAL_FIELDS = (
        "claim_result",
        "state_diff_receipt",
        "api_call_log_receipt",
        "replay_intervention_witness",
        "version_fingerprint_witness",
        "policy_text_hash",
    )

    def __post_init__(self) -> None:
        if self.claim_semantics_commitment is not None and not (
            valid_claim_semantics_commitment(self.claim_semantics_commitment)
        ):
            raise ValueError("claim semantics commitment must be a SHA-256 digest")

    def unsigned_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("signature")
        signed_optional_fields = result.pop("_signed_optional_fields")
        result["binding_edges"] = [list(edge) for edge in self.binding_edges]
        if signed_optional_fields is not None:
            for name in self._V07_OPTIONAL_FIELDS:
                if name not in signed_optional_fields:
                    result.pop(name)
        for name in self._V08_RECEIPT_FIELDS:
            if result.get(name) is None:
                result.pop(name)
        if result.get("claim_semantics_commitment") is None:
            result.pop("claim_semantics_commitment")
        return result

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EvidenceAttestation":
        def _receipt(name: str) -> dict[str, Any] | None:
            receipt = value.get(name)
            return dict(receipt) if isinstance(receipt, Mapping) else None

        policy_text_hash = value.get("policy_text_hash")
        claim_result = value.get("claim_result")
        return cls(
            run_id=str(value["run_id"]),
            task_id=str(value["task_id"]),
            claim_id=str(value["claim_id"]),
            benchmark_revision=str(value["benchmark_revision"]),
            witness_id=str(value["witness_id"]),
            producer=str(value["producer"]),
            capture_point=str(value["capture_point"]),
            verifier_id=str(value["verifier_id"]),
            binding_edges=tuple(
                (str(edge[0]), str(edge[1])) for edge in value["binding_edges"]
            ),
            coverage_channel=str(value["coverage_channel"]),
            coverage_complete=bool(value["coverage_complete"]),
            signature=str(value.get("signature", "")),
            claim_result=(
                bool(claim_result) if isinstance(claim_result, bool) else None
            ),
            state_diff_receipt=_receipt("state_diff_receipt"),
            api_call_log_receipt=_receipt("api_call_log_receipt"),
            replay_intervention_witness=_receipt("replay_intervention_witness"),
            version_fingerprint_witness=_receipt("version_fingerprint_witness"),
            policy_text_hash=(
                str(policy_text_hash) if policy_text_hash is not None else None
            ),
            write_effect_ledger=_receipt("write_effect_ledger"),
            termination_receipt=_receipt("termination_receipt"),
            tool_result_coverage=_receipt("tool_result_coverage"),
            policy_delivery_receipt=_receipt("policy_delivery_receipt"),
            claim_semantics_commitment=(
                str(value["claim_semantics_commitment"])
                if value.get("claim_semantics_commitment") is not None
                else None
            ),
            _signed_optional_fields=frozenset(
                name for name in cls._V07_OPTIONAL_FIELDS if name in value
            ),
        )


def sign_evidence_attestation(
    attestation: EvidenceAttestation,
    witness: IndependentVerifierWitness | None,
    producer_key: bytes,
) -> EvidenceAttestation:
    """Bind the complete witness and attestation to a pre-established key.

    ``witness`` may be ``None`` for v0.7 claims whose answer is carried by the
    signed attestation (``claim_result`` and receipts) instead of an
    independent verifier witness.
    """

    if not producer_key:
        raise ValueError("producer key must be non-empty")
    if witness is not None and (
        witness.claim_semantics_commitment
        != attestation.claim_semantics_commitment
    ):
        raise ValueError(
            "witness and attestation claim semantics commitments must match"
        )
    message = canonical_json(
        {
            "attestation": attestation.unsigned_dict(),
            "witness": (
                witness.as_dict(include_components=True)
                if witness is not None
                else None
            ),
        }
    ).encode("utf-8")
    signature = hmac.new(producer_key, message, hashlib.sha256).hexdigest()
    return replace(attestation, signature=signature)


def bind_claim_semantics(
    source: "ExternalEvidenceSource",
    claim_id: str,
    commitment: str,
    *,
    producer_key: bytes,
) -> "ExternalEvidenceSource":
    """Re-mint one evidence entry with a signed executable-claim commitment.

    This operation does not change the witness answer, receipts, or run
    identity.  It binds the existing evidence to the descriptor selected by
    the caller and signs the new witness/attestation pair.
    """

    if not valid_claim_semantics_commitment(commitment):
        raise ValueError("claim semantics commitment must be a SHA-256 digest")
    witness = source.witnesses.get(claim_id)
    attestation = source.attestations.get(claim_id)
    if witness is None or attestation is None:
        raise ValueError(f"source has no complete evidence for {claim_id}")
    bound_witness = replace(witness, claim_semantics_commitment=commitment)
    bound_attestation = sign_evidence_attestation(
        replace(
            attestation,
            claim_semantics_commitment=commitment,
            signature="",
        ),
        bound_witness,
        producer_key,
    )
    return replace(
        source,
        witnesses={**source.witnesses, claim_id: bound_witness},
        attestations={**source.attestations, claim_id: bound_attestation},
    )


@dataclass(frozen=True)
class ExternalTrustContext:
    """Closed, answer-free roots established outside the evidence package."""

    environment: str
    benchmark_revision: str
    expected_run_id: str
    expected_task_id: str
    producer_keys: Mapping[str, bytes]
    accepted_capture_points: frozenset[str]
    accepted_verifiers: frozenset[str]
    mandatory_coverage_channel: str
    expected_claim_semantics_commitments: Mapping[str, str] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if self.environment not in {"tau2", "appworld"}:
            raise ValueError(f"unsupported external environment: {self.environment}")
        required = (
            self.benchmark_revision,
            self.expected_run_id,
            self.expected_task_id,
            self.mandatory_coverage_channel,
        )
        if any(not value for value in required):
            raise ValueError("external trust roots and selectors must be non-empty")
        if not (
            self.producer_keys
            and self.accepted_capture_points
            and self.accepted_verifiers
        ):
            raise ValueError("external trust roots must be pre-established")
        if any(not key for key in self.producer_keys.values()):
            raise ValueError("external producer keys must be non-empty")
        if any(
            not claim_id or not valid_claim_semantics_commitment(commitment)
            for claim_id, commitment in self.expected_claim_semantics_commitments.items()
        ):
            raise ValueError(
                "expected claim semantics commitments must map non-empty claim ids "
                "to SHA-256 digests"
            )


@dataclass(frozen=True)
class ExternalEvidenceSource:
    """Evidence-side material captured for one benchmark run.

    The type intentionally has no oracle/truth field. Formal runners construct
    the hidden :class:`NormalizedRunRecord` and this source on separate paths.
    """

    environment: str
    run_id: str
    task_id: str
    benchmark_revision: str
    final_answer: str | None = None
    normalized_trace: tuple[Mapping[str, Any], ...] = ()
    native_trace: tuple[Mapping[str, Any], ...] = ()
    witnesses: Mapping[str, IndependentVerifierWitness] = field(default_factory=dict)
    attestations: Mapping[str, EvidenceAttestation] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.environment not in {"tau2", "appworld"}:
            raise ValueError(f"unsupported external environment: {self.environment}")
        if any(not value for value in (self.run_id, self.task_id, self.benchmark_revision)):
            raise ValueError("external evidence identity fields must be non-empty")
        if set(self.attestations) - set(self.witnesses):
            raise ValueError("an attestation cannot exist without its witness")
        for claim_id, witness in self.witnesses.items():
            if claim_id != witness.claim_id:
                raise ValueError("witness registry key does not match claim_id")
        for claim_id, attestation in self.attestations.items():
            if claim_id != attestation.claim_id:
                raise ValueError("attestation registry key does not match claim_id")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": EVIDENCE_SCHEMA,
            "environment": self.environment,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "benchmark_revision": self.benchmark_revision,
            "final_answer": self.final_answer,
            "normalized_trace": _json_copy(self.normalized_trace),
            "native_trace": _json_copy(self.native_trace),
            "witnesses": {
                claim_id: witness.as_dict(include_components=True)
                for claim_id, witness in sorted(self.witnesses.items())
            },
            "attestations": {
                claim_id: attestation.as_dict()
                for claim_id, attestation in sorted(self.attestations.items())
            },
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExternalEvidenceSource":
        if value.get("schema") != EVIDENCE_SCHEMA:
            raise ValueError("unsupported external evidence source schema")
        return cls(
            environment=str(value["environment"]),
            run_id=str(value["run_id"]),
            task_id=str(value["task_id"]),
            benchmark_revision=str(value["benchmark_revision"]),
            final_answer=(
                str(value["final_answer"])
                if value.get("final_answer") is not None
                else None
            ),
            normalized_trace=tuple(
                dict(item) for item in value.get("normalized_trace", ())
            ),
            native_trace=tuple(dict(item) for item in value.get("native_trace", ())),
            witnesses={
                str(claim_id): IndependentVerifierWitness.from_mapping(item)
                for claim_id, item in dict(value.get("witnesses", {})).items()
            },
            attestations={
                str(claim_id): EvidenceAttestation.from_mapping(item)
                for claim_id, item in dict(value.get("attestations", {})).items()
            },
        )


@dataclass(frozen=True)
class ProjectedEvidence:
    schema: str
    regime: str
    environment: str
    claim_id: str
    statement: str
    payload: Mapping[str, Any]

    @property
    def serialized(self) -> str:
        return canonical_json(self.as_dict())

    @property
    def byte_count(self) -> int:
        return len(self.serialized.encode("utf-8"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "regime": self.regime,
            "environment": self.environment,
            "claim_id": self.claim_id,
            "statement": self.statement,
            "payload": _json_copy(self.payload),
        }


EVIDENCE_REGIMES = (
    "final_answer_only",
    "generic_normalized_trace",
    "full_native_trajectory",
    "state_effect_receipt",
    "static_exact_dependency_cover",
    "auditspec_compiled_contract",
)


def materialize_independent_witnesses(
    verification_record: NormalizedRunRecord,
    *,
    replay_id: str,
    verifier_id: str,
    producer: str,
    capture_point: str,
    coverage_channel: str,
    benchmark_revision: str,
    producer_key: bytes,
) -> tuple[
    dict[str, IndependentVerifierWitness],
    dict[str, EvidenceAttestation],
]:
    """Transform a second official evaluation into bound evidence witnesses.

    ``verification_record`` must come from a separately executed evaluator
    replay. The hidden truth record is intentionally not accepted by this API.
    """

    if not replay_id or not verifier_id or not benchmark_revision:
        raise ValueError(
            "independent replay, verifier and benchmark revision are required"
        )
    witnesses: dict[str, IndependentVerifierWitness] = {}
    attestations: dict[str, EvidenceAttestation] = {}
    for claim_id, definition in CLAIM_REGISTRY.items():
        if definition.environment != verification_record.environment:
            continue
        evaluation = definition.evaluate(verification_record)
        if not evaluation.applicable:
            continue
        witness_id = f"{verification_record.run_id}:{claim_id}:{replay_id}"
        witnesses[claim_id] = IndependentVerifierWitness(
            witness_id=witness_id,
            claim_id=claim_id,
            statement=evaluation.statement,
            declared_value=evaluation.value,
            verifier_id=verifier_id,
            replay_id=replay_id,
            computation=evaluation.source,
            evidence_components={
                "check_id": definition.oracle_check_id,
                "violating_ids": list(evaluation.violating_ids),
            },
        )
        unsigned = EvidenceAttestation(
            run_id=verification_record.run_id,
            task_id=verification_record.task_id,
            claim_id=claim_id,
            benchmark_revision=benchmark_revision,
            witness_id=witness_id,
            producer=producer,
            capture_point=capture_point,
            verifier_id=verifier_id,
            binding_edges=tuple(sorted(_REQUIRED_BINDINGS)),
            coverage_channel=coverage_channel,
            coverage_complete=True,
        )
        attestations[claim_id] = sign_evidence_attestation(
            unsigned, witnesses[claim_id], producer_key
        )
    return witnesses, attestations


def project_external_evidence(
    source: ExternalEvidenceSource,
    claim_id: str,
    regime: str,
) -> ProjectedEvidence:
    """Apply one frozen auditor-visible projection without reading truth."""

    if regime not in EVIDENCE_REGIMES:
        raise ValueError(f"unknown external evidence regime: {regime}")
    definition = CLAIM_REGISTRY.get(claim_id)
    if definition is None or definition.environment != source.environment:
        raise ValueError(f"claim {claim_id!r} is not registered for {source.environment}")
    witness = source.witnesses.get(claim_id)
    statement = witness.statement if witness is not None else claim_id
    if regime == "final_answer_only":
        payload: Mapping[str, Any] = {"final_answer": source.final_answer}
    elif regime == "generic_normalized_trace":
        payload = {
            "final_answer": source.final_answer,
            "events": _json_copy(source.normalized_trace),
        }
    elif regime == "full_native_trajectory":
        payload = {
            "final_answer": source.final_answer,
            "events": _json_copy(source.native_trace),
        }
    elif witness is None:
        payload = {"verification_witness": None}
    elif regime == "state_effect_receipt":
        payload = {"verification_witness": witness.as_dict(include_components=True)}
    elif regime == "static_exact_dependency_cover":
        payload = {
            "verification_witness": witness.as_dict(include_components=False)
        }
    else:
        attestation = source.attestations.get(claim_id)
        payload = {
            "verification_witness": witness.as_dict(include_components=True),
            "attestation": attestation.as_dict() if attestation is not None else None,
        }
    return ProjectedEvidence(
        schema=EVIDENCE_SCHEMA,
        regime=regime,
        environment=source.environment,
        claim_id=claim_id,
        statement=statement,
        payload=_json_copy(payload),
    )


@dataclass(frozen=True)
class ExternalEvidenceVerificationResult:
    primary_verdict: AssuranceVerdict
    answer: bool | None
    semantic_determinate: bool
    structural_assurance: bool
    errors: tuple[str, ...]
    additional_detected_failures: tuple[str, ...]
    first_failed_layer: str | None = None

    @property
    def valid(self) -> bool:
        return self.primary_verdict == AssuranceVerdict.VERIFIED_AUDITABLE

    def as_dict(self, *, include_layer: bool = False) -> dict[str, Any]:
        result = asdict(self)
        layer = result.pop("first_failed_layer")
        result["primary_verdict"] = str(self.primary_verdict)
        result["valid"] = self.valid
        if include_layer:
            result["first_failed_layer"] = layer
        return result


_REQUIRED_BINDINGS = frozenset(
    {
        ("run", "task"),
        ("run", "claim"),
        ("run", "verifier_witness"),
        ("task", "benchmark_revision"),
    }
)

# Binding mechanism -> attestation binding edge, shared by the v0.6 planner
# realization and the v0.7 stack projection.
_BINDING_EDGE_REQUIREMENTS = {
    "run_task_binding": ("run", "task"),
    "run_claim_binding": ("run", "claim"),
    "run_witness_binding": ("run", "verifier_witness"),
    "task_revision_binding": ("task", "benchmark_revision"),
}

# v0.7 receipt mechanisms and their attestation fields.
_RECEIPT_FIELDS = {
    "state_diff_receipt": "state_diff_receipt",
    "api_call_log_receipt": "api_call_log_receipt",
    "replay_intervention_witness": "replay_intervention_witness",
    "version_fingerprint_witness": "version_fingerprint_witness",
    "policy_text_hash_binding": "policy_text_hash",
}

# v0.8 instrumented-runtime receipt payloads and the contract mechanism whose
# installation licenses each payload in an honest stack projection.
_V08_RECEIPT_GATING = {
    "state_diff_receipt": "write_effect_ledger",
    "trusted_capture_point": "termination_receipt",
    "mandatory_path_coverage": "tool_result_coverage",
    "policy_text_hash_binding": "policy_delivery_receipt",
}


def realize_mechanism_evidence(
    source: ExternalEvidenceSource,
    claim_id: str,
    mechanisms: frozenset[str] | set[str],
    *,
    producer_key: bytes,
    untrusted_key: bytes = b"untrusted-producer-key",
) -> tuple[IndependentVerifierWitness | None, EvidenceAttestation | None]:
    """Realize the evidence an installation of ``mechanisms`` would produce.

    Components whose mechanism is not installed are dropped or replaced by
    their unbound/untrusted stand-ins, and the attestation is re-signed with
    the trusted producer key only when ``trusted_producer`` is installed.
    This is the shared degradation path behind the v0.6 planner realization
    and the v0.7 stack projections.
    """

    witness = source.witnesses.get(claim_id)
    attestation = source.attestations.get(claim_id)
    if witness is None or attestation is None:
        return None, None
    if "independent_verifier_witness" not in mechanisms:
        witness = None
    if witness is not None and "witness_components" not in mechanisms:
        witness = replace(witness, evidence_components={})
    if witness is not None and "run_claim_binding" not in mechanisms:
        witness = replace(witness, claim_semantics_commitment=None)
    attestation = replace(
        attestation,
        binding_edges=tuple(
            edge
            for mechanism, edge in _BINDING_EDGE_REQUIREMENTS.items()
            if mechanism in mechanisms
        ),
        task_id=(
            attestation.task_id
            if "run_task_binding" in mechanisms
            else "unbound-task"
        ),
        claim_id=(
            attestation.claim_id
            if "run_claim_binding" in mechanisms
            else "unbound-claim"
        ),
        claim_semantics_commitment=(
            attestation.claim_semantics_commitment
            if "run_claim_binding" in mechanisms
            else None
        ),
        witness_id=(
            witness.witness_id
            if witness is not None and "run_witness_binding" in mechanisms
            else "unbound-witness"
        ),
        benchmark_revision=(
            attestation.benchmark_revision
            if "task_revision_binding" in mechanisms
            else "unbound-revision"
        ),
        producer=(
            attestation.producer if "trusted_producer" in mechanisms else "agent"
        ),
        capture_point=(
            attestation.capture_point
            if "trusted_capture_point" in mechanisms
            else "agent"
        ),
        coverage_complete="mandatory_path_coverage" in mechanisms,
        **{
            field: (
                getattr(attestation, field) if mechanism in mechanisms else None
            )
            for mechanism, field in _RECEIPT_FIELDS.items()
        },
        **{
            field: (
                getattr(attestation, field) if mechanism in mechanisms else None
            )
            for mechanism, field in _V08_RECEIPT_GATING.items()
        },
    )
    if "accepted_verifier" not in mechanisms:
        if witness is not None:
            witness = replace(witness, verifier_id="invented-verifier")
        attestation = replace(attestation, verifier_id="invented-verifier")
    signing_key = (
        producer_key if "trusted_producer" in mechanisms else untrusted_key
    )
    attestation = sign_evidence_attestation(
        replace(attestation, signature=""), witness, signing_key
    )
    return witness, attestation


def verify_external_evidence(
    evidence: ProjectedEvidence,
    trust_context: ExternalTrustContext,
    *,
    required_mechanisms: frozenset[str] | None = None,
    v07_claim: V07ClaimDefinition | None = None,
    v07_oracle: Mapping[str, Any] | None = None,
) -> ExternalEvidenceVerificationResult:
    """Verify a projected package without consulting benchmark truth.

    With no optional arguments this is exactly the v0.6 fixed-envelope
    verifier (``v07_oracle`` is never consulted on that path). Passing
    ``required_mechanisms`` (and usually the frozen ``v07_claim``) switches to
    the v0.7 query-specific path: only the contract-required mechanisms are
    checked, and typed negatives are always refused with their declared gap
    verdict. ``v07_oracle`` is the parsed offline ``v07-oracles.json`` record
    for the run; when given, receipts and ``claim_result`` are additionally
    compared against the derived values, so a producer that signs values
    contradicting the derivation is rejected even with a valid key.
    """

    if required_mechanisms is None and v07_claim is None:
        return _verify_external_evidence_v06(evidence, trust_context)
    return _verify_external_evidence_v07(
        evidence,
        trust_context,
        required_mechanisms=required_mechanisms,
        v07_claim=v07_claim,
        v07_oracle=v07_oracle,
    )


def _claim_semantics_binding_errors(
    evidence: ProjectedEvidence,
    witness: Any,
    attestation: Any,
    trust_context: ExternalTrustContext,
) -> list[str]:
    """Check the evidence-side commitment against an independent expectation."""

    expected = trust_context.expected_claim_semantics_commitments.get(
        evidence.claim_id
    )
    if expected is None:
        return []
    errors: list[str] = []
    if isinstance(witness, Mapping):
        actual = witness.get("claim_semantics_commitment")
        if actual is None:
            errors.append("claim_semantics_commitment:witness_missing")
        elif not valid_claim_semantics_commitment(actual):
            errors.append("claim_semantics_commitment:witness_malformed")
        elif actual != expected:
            errors.append("claim_semantics_commitment:witness_mismatch")
    if isinstance(attestation, Mapping):
        actual = attestation.get("claim_semantics_commitment")
        if actual is None:
            errors.append("claim_semantics_commitment:attestation_missing")
        elif not valid_claim_semantics_commitment(actual):
            errors.append("claim_semantics_commitment:attestation_malformed")
        elif actual != expected:
            errors.append("claim_semantics_commitment:attestation_mismatch")
    return errors


def _verify_external_evidence_v06(
    evidence: ProjectedEvidence,
    trust_context: ExternalTrustContext,
) -> ExternalEvidenceVerificationResult:
    definition = CLAIM_REGISTRY.get(evidence.claim_id)
    if (
        evidence.schema != EVIDENCE_SCHEMA
        or definition is None
        or definition.environment != evidence.environment
    ):
        return ExternalEvidenceVerificationResult(
            primary_verdict=AssuranceVerdict.QUERY_GAP,
            answer=None,
            semantic_determinate=False,
            structural_assurance=False,
            errors=("claim_or_schema:unregistered",),
            additional_detected_failures=(),
            first_failed_layer="Q",
        )
    witness = evidence.payload.get("verification_witness")
    if not isinstance(witness, Mapping) or not isinstance(
        witness.get("declared_value"), bool
    ):
        return ExternalEvidenceVerificationResult(
            primary_verdict=AssuranceVerdict.EVIDENCE_GAP,
            answer=None,
            semantic_determinate=False,
            structural_assurance=False,
            errors=("missing:independent_verifier_witness",),
            additional_detected_failures=(),
            first_failed_layer="D",
        )

    errors_by_layer: dict[str, list[str]] = {"R": [], "M": [], "V": []}
    if evidence.regime != "auditspec_compiled_contract":
        errors_by_layer["R"].append("contract_projection:mismatch")
    if evidence.environment != trust_context.environment:
        errors_by_layer["R"].append("environment:mismatch")
    if witness.get("claim_id") != evidence.claim_id:
        errors_by_layer["R"].append("claim_binding:mismatch")

    attestation = evidence.payload.get("attestation")
    if not isinstance(attestation, Mapping):
        errors_by_layer["R"].append("missing:attestation")
    else:
        expected = {
            "run_id": trust_context.expected_run_id,
            "task_id": trust_context.expected_task_id,
            "claim_id": evidence.claim_id,
            "benchmark_revision": trust_context.benchmark_revision,
            "witness_id": witness.get("witness_id"),
            "verifier_id": witness.get("verifier_id"),
        }
        for name, value in expected.items():
            if attestation.get(name) != value:
                layer = "V" if name == "verifier_id" else "R"
                errors_by_layer[layer].append(f"{name}:mismatch")
        raw_edges = attestation.get("binding_edges", ())
        edges = {
            (str(item[0]), str(item[1]))
            for item in raw_edges
            if not isinstance(item, (str, bytes))
            and isinstance(item, Sequence)
            and len(item) == 2
        }
        for source, target in sorted(_REQUIRED_BINDINGS - edges):
            errors_by_layer["R"].append(f"missing_binding:{source}->{target}")
        producer = str(attestation.get("producer", ""))
        producer_key = trust_context.producer_keys.get(producer)
        if producer_key is None:
            errors_by_layer["M"].append("producer:untrusted")
        else:
            unsigned = dict(attestation)
            signature = str(unsigned.pop("signature", ""))
            message = canonical_json(
                {"attestation": unsigned, "witness": _json_copy(witness)}
            ).encode("utf-8")
            expected_signature = hmac.new(
                producer_key, message, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                errors_by_layer["M"].append("attestation_signature:invalid")
        if (
            attestation.get("capture_point")
            not in trust_context.accepted_capture_points
        ):
            errors_by_layer["M"].append("capture_point:untrusted")
        if (
            attestation.get("coverage_channel")
            != trust_context.mandatory_coverage_channel
        ):
            errors_by_layer["M"].append("coverage_channel:mismatch")
        if attestation.get("coverage_complete") is not True:
            errors_by_layer["M"].append("coverage:incomplete")

    if witness.get("verifier_id") not in trust_context.accepted_verifiers:
        errors_by_layer["V"].append("verifier:untrusted")
    if not witness.get("replay_id"):
        errors_by_layer["V"].append("verifier_replay:missing")
    errors_by_layer["V"].extend(
        _claim_semantics_binding_errors(
            evidence, witness, attestation, trust_context
        )
    )

    ordered_errors = tuple(
        error for layer in ("R", "M", "V") for error in errors_by_layer[layer]
    )
    failed_layers = [layer for layer in ("R", "M", "V") if errors_by_layer[layer]]
    if not failed_layers:
        return ExternalEvidenceVerificationResult(
            primary_verdict=AssuranceVerdict.VERIFIED_AUDITABLE,
            answer=bool(witness["declared_value"]),
            semantic_determinate=True,
            structural_assurance=True,
            errors=(),
            additional_detected_failures=(),
            first_failed_layer=None,
        )
    primary_layer = failed_layers[0]
    primary = (
        AssuranceVerdict.VERIFICATION_FAILURE
        if primary_layer == "V"
        else AssuranceVerdict.TCB_GAP
    )
    additions = tuple(
        f"{layer}:{error}"
        for layer in failed_layers[1:]
        for error in errors_by_layer[layer]
    )
    return ExternalEvidenceVerificationResult(
        primary_verdict=primary,
        answer=None,
        semantic_determinate=True,
        structural_assurance=False,
        errors=ordered_errors,
        additional_detected_failures=additions,
        first_failed_layer=primary_layer,
    )


def _gap_result(
    verdict: AssuranceVerdict, error: str
) -> ExternalEvidenceVerificationResult:
    layer = {
        AssuranceVerdict.QUERY_GAP: "Q",
        AssuranceVerdict.MODEL_GAP: "A",
        AssuranceVerdict.EVIDENCE_GAP: "D",
        AssuranceVerdict.TCB_GAP: "M",
        AssuranceVerdict.INTERVENTION_GAP: "R",
        AssuranceVerdict.VERIFICATION_FAILURE: "V",
    }.get(verdict)
    return ExternalEvidenceVerificationResult(
        primary_verdict=verdict,
        answer=None,
        semantic_determinate=False,
        structural_assurance=False,
        errors=(error,),
        additional_detected_failures=(),
        first_failed_layer=layer,
    )


def _verify_external_evidence_v07(
    evidence: ProjectedEvidence,
    trust_context: ExternalTrustContext,
    *,
    required_mechanisms: frozenset[str] | None,
    v07_claim: V07ClaimDefinition | None,
    v07_oracle: Mapping[str, Any] | None = None,
) -> ExternalEvidenceVerificationResult:
    """Query-specific verification against one frozen minimal contract."""

    oracle_entry: Mapping[str, Any] | None = None
    if v07_claim is not None:
        claim_environment: str | None = v07_claim.environment
        if required_mechanisms is None:
            required_mechanisms = v07_claim.minimal_contract
        if v07_oracle is not None and v07_claim.oracle_check_id is not None:
            candidate = dict(v07_oracle.get("oracles", {})).get(
                v07_claim.oracle_check_id
            )
            if isinstance(candidate, Mapping):
                oracle_entry = candidate
    else:
        definition = CLAIM_REGISTRY.get(evidence.claim_id)
        claim_environment = (
            definition.environment if definition is not None else None
        )
    if (
        evidence.schema != EVIDENCE_SCHEMA
        or claim_environment is None
        or claim_environment != evidence.environment
    ):
        return _gap_result(
            AssuranceVerdict.QUERY_GAP, "claim_or_schema:unregistered"
        )
    if required_mechanisms is None:
        # Typed negative: no machine-checkable contract exists, so the claim
        # must be refused with its declared gap verdict under every stack.
        assert v07_claim is not None and v07_claim.declared_gap is not None
        return _gap_result(
            v07_claim.declared_gap, "typed_negative:no_machine_checkable_contract"
        )
    required = frozenset(required_mechanisms)

    witness = evidence.payload.get("verification_witness")
    witness_required = "independent_verifier_witness" in required
    if witness_required and (
        not isinstance(witness, Mapping)
        or not isinstance(witness.get("declared_value"), bool)
    ):
        return _gap_result(
            AssuranceVerdict.EVIDENCE_GAP, "missing:independent_verifier_witness"
        )

    errors_by_layer: dict[str, list[str]] = {"R": [], "M": [], "V": []}
    if evidence.environment != trust_context.environment:
        errors_by_layer["R"].append("environment:mismatch")

    attestation = evidence.payload.get("attestation")
    attestation_required = bool(
        required - {"independent_verifier_witness", "witness_components"}
    )
    if attestation_required and not isinstance(attestation, Mapping):
        errors_by_layer["R"].append("missing:attestation")
    if isinstance(witness, Mapping) and "run_claim_binding" in required:
        if witness.get("claim_id") != evidence.claim_id:
            errors_by_layer["R"].append("claim_binding:mismatch")
    if "witness_components" in required:
        if not isinstance(witness, Mapping) or not witness.get(
            "evidence_components"
        ):
            errors_by_layer["R"].append("missing:witness_components")

    if isinstance(attestation, Mapping):
        expected_by_mechanism = {
            "run_task_binding": (
                ("run_id", trust_context.expected_run_id),
                ("task_id", trust_context.expected_task_id),
            ),
            "run_claim_binding": (("claim_id", evidence.claim_id),),
            "run_witness_binding": (
                ("witness_id", witness.get("witness_id"))
                if isinstance(witness, Mapping)
                else ("witness_id", None),
            ),
            "task_revision_binding": (
                ("benchmark_revision", trust_context.benchmark_revision),
            ),
        }
        for mechanism, pairs in expected_by_mechanism.items():
            if mechanism not in required:
                continue
            for name, value in pairs:
                if attestation.get(name) != value:
                    errors_by_layer["R"].append(f"{name}:mismatch")
        raw_edges = attestation.get("binding_edges", ())
        edges = {
            (str(item[0]), str(item[1]))
            for item in raw_edges
            if not isinstance(item, (str, bytes))
            and isinstance(item, Sequence)
            and len(item) == 2
        }
        for mechanism, edge in _BINDING_EDGE_REQUIREMENTS.items():
            if mechanism in required and edge not in edges:
                errors_by_layer["R"].append(
                    f"missing_binding:{edge[0]}->{edge[1]}"
                )

        if "trusted_producer" in required:
            producer = str(attestation.get("producer", ""))
            producer_key = trust_context.producer_keys.get(producer)
            if producer_key is None:
                errors_by_layer["M"].append("producer:untrusted")
            else:
                unsigned = dict(attestation)
                signature = str(unsigned.pop("signature", ""))
                message = canonical_json(
                    {"attestation": unsigned, "witness": _json_copy(witness)}
                ).encode("utf-8")
                expected_signature = hmac.new(
                    producer_key, message, hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(signature, expected_signature):
                    errors_by_layer["M"].append("attestation_signature:invalid")
        if "trusted_capture_point" in required and (
            attestation.get("capture_point")
            not in trust_context.accepted_capture_points
        ):
            errors_by_layer["M"].append("capture_point:untrusted")
        if "mandatory_path_coverage" in required:
            if (
                attestation.get("coverage_channel")
                != trust_context.mandatory_coverage_channel
            ):
                errors_by_layer["M"].append("coverage_channel:mismatch")
            if attestation.get("coverage_complete") is not True:
                errors_by_layer["M"].append("coverage:incomplete")

        for mechanism, field in _RECEIPT_FIELDS.items():
            if mechanism not in required:
                continue
            receipt_error = _check_receipt(
                mechanism, attestation.get(field), oracle_entry
            )
            if receipt_error is not None:
                errors_by_layer["R"].append(receipt_error)

        if oracle_entry is not None:
            oracle_value = oracle_entry.get("value")
            claim_result = attestation.get("claim_result")
            if (
                isinstance(oracle_value, bool)
                and isinstance(claim_result, bool)
                and claim_result != oracle_value
            ):
                errors_by_layer["R"].append("claim_result:oracle_mismatch")

        if "accepted_verifier" in required:
            witness_verifier = (
                witness.get("verifier_id")
                if isinstance(witness, Mapping)
                else None
            )
            if attestation.get("verifier_id") != witness_verifier:
                errors_by_layer["V"].append("verifier_id:mismatch")

    if "accepted_verifier" in required and isinstance(witness, Mapping):
        if witness.get("verifier_id") not in trust_context.accepted_verifiers:
            errors_by_layer["V"].append("verifier:untrusted")
        if not witness.get("replay_id"):
            errors_by_layer["V"].append("verifier_replay:missing")

    errors_by_layer["V"].extend(
        _claim_semantics_binding_errors(
            evidence, witness, attestation, trust_context
        )
    )

    ordered_errors = tuple(
        error for layer in ("R", "M", "V") for error in errors_by_layer[layer]
    )
    failed_layers = [layer for layer in ("R", "M", "V") if errors_by_layer[layer]]
    if failed_layers:
        primary_layer = failed_layers[0]
        primary = (
            AssuranceVerdict.VERIFICATION_FAILURE
            if primary_layer == "V"
            else AssuranceVerdict.TCB_GAP
        )
        additions = tuple(
            f"{layer}:{error}"
            for layer in failed_layers[1:]
            for error in errors_by_layer[layer]
        )
        return ExternalEvidenceVerificationResult(
            primary_verdict=primary,
            answer=None,
            semantic_determinate=True,
            structural_assurance=False,
            errors=ordered_errors,
            additional_detected_failures=additions,
            first_failed_layer=primary_layer,
        )

    if witness_required:
        answer = bool(witness["declared_value"])
    else:
        # Without an independent verifier witness the answer is the
        # producer-signed derivation result carried by the attestation.
        claim_result = (
            attestation.get("claim_result")
            if isinstance(attestation, Mapping)
            else None
        )
        if not isinstance(claim_result, bool):
            return _gap_result(
                AssuranceVerdict.EVIDENCE_GAP, "missing:claim_result"
            )
        answer = claim_result
    return ExternalEvidenceVerificationResult(
        primary_verdict=AssuranceVerdict.VERIFIED_AUDITABLE,
        answer=answer,
        semantic_determinate=True,
        structural_assurance=True,
        errors=(),
        additional_detected_failures=(),
        first_failed_layer=None,
    )


def _check_receipt(
    mechanism: str,
    receipt: Any,
    oracle_entry: Mapping[str, Any] | None = None,
) -> str | None:
    """Structural and (when available) derivation check for one receipt field.

    Structure: the signed receipt must be present and well-formed. When the
    offline oracle entry for the claim's check is supplied, the receipt is
    additionally compared field-by-field against the derived values, so a
    receipt that contradicts the deterministic derivation is rejected even
    under a valid producer signature. An oracle entry whose value is ``null``
    marks a legitimate data gap (e.g. no recorded policy text): the receipt
    is then allowed to be absent, and the missing ``claim_result`` produces
    the declared EVIDENCE_GAP downstream.
    """

    oracle_receipts = (
        oracle_entry.get("receipts") if isinstance(oracle_entry, Mapping) else None
    )
    if (
        oracle_entry is not None
        and oracle_entry.get("value") is None
        and isinstance(oracle_receipts, Mapping)
        and oracle_receipts.get(_RECEIPT_FIELDS[mechanism]) is None
    ):
        return None
    if mechanism == "policy_text_hash_binding":
        if not isinstance(receipt, str) or not receipt:
            return "missing:policy_text_hash"
    else:
        if not isinstance(receipt, Mapping):
            return f"missing:{mechanism}"
        requirements: dict[str, tuple[str, ...]] = {
            "state_diff_receipt": ("pre_state_hash", "post_state_hash"),
            "api_call_log_receipt": ("log_hash",),
            "replay_intervention_witness": (
                "intervention_id",
                "baseline_end_hash",
                "intervened_end_hash",
            ),
            "version_fingerprint_witness": ("code_revision", "data_version"),
        }
        for key in requirements[mechanism]:
            if not receipt.get(key):
                return f"{mechanism}:malformed"
    if isinstance(oracle_receipts, Mapping):
        expected = oracle_receipts.get(_RECEIPT_FIELDS[mechanism])
        if expected is not None and canonical_json(receipt) != canonical_json(
            expected
        ):
            return f"{mechanism}:oracle_mismatch"
    return None


def project_external_evidence_v07(
    source: ExternalEvidenceSource,
    claim: V07ClaimDefinition,
    stack: EvidenceStack,
    *,
    producer_key: bytes,
) -> ProjectedEvidence:
    """Project the evidence one honestly specified stack would produce.

    Only components whose mechanism is installed in ``stack`` survive; the
    attestation is re-signed by the trusted producer key only when the stack
    installs ``trusted_producer``. Typed negatives project to an empty
    package and are refused by the verifier with their declared gap verdict.
    """

    if claim.environment != source.environment:
        raise ValueError(
            f"claim {claim.claim_id!r} is not registered for {source.environment}"
        )
    if claim.is_typed_negative:
        payload: dict[str, Any] = {
            "verification_witness": None,
            "attestation": None,
        }
    else:
        witness, attestation = realize_mechanism_evidence(
            source, claim.claim_id, stack.installed, producer_key=producer_key
        )
        payload = {
            "verification_witness": (
                witness.as_dict(include_components=True)
                if witness is not None
                else None
            ),
            "attestation": (
                attestation.as_dict() if attestation is not None else None
            ),
        }
        if "final_answer" in stack.installed:
            payload["final_answer"] = source.final_answer
        if "generic_trace" in stack.installed:
            payload["events"] = _json_copy(source.normalized_trace)
        if "native_trace" in stack.installed:
            payload["events"] = _json_copy(source.native_trace)
    return ProjectedEvidence(
        schema=EVIDENCE_SCHEMA,
        regime=stack.stack_id,
        environment=source.environment,
        claim_id=claim.claim_id,
        statement=claim.statement,
        payload=_json_copy(payload),
    )


def verify_stack_support(
    source: ExternalEvidenceSource,
    claim: V07ClaimDefinition,
    stack: EvidenceStack,
    trust_context: ExternalTrustContext,
    *,
    producer_key: bytes,
) -> ExternalEvidenceVerificationResult:
    """Verify the evidence one stack realizes for one claim."""

    projected = project_external_evidence_v07(
        source, claim, stack, producer_key=producer_key
    )
    return verify_external_evidence(projected, trust_context, v07_claim=claim)


def stack_supports_claim(
    source: ExternalEvidenceSource,
    claim: V07ClaimDefinition,
    stack: EvidenceStack,
    trust_context: ExternalTrustContext,
    *,
    producer_key: bytes,
) -> bool:
    """Frozen ``stack_support_rule``: contract subset plus realized proof.

    Typed negatives are never supported; every stack must refuse them.
    """

    if not stack.covers(claim):
        return False
    return verify_stack_support(
        source, claim, stack, trust_context, producer_key=producer_key
    ).valid


@dataclass(frozen=True)
class AuditorEvidenceCase:
    case_id: str
    claim_id: str
    truth: bool
    applicable: bool
    evidence: ProjectedEvidence
    attack: str | None = None


@dataclass(frozen=True)
class AmbiguousPairCertificate:
    schema: str
    claim_id: str
    case_a: str
    case_b: str
    truth_a: bool
    truth_b: bool
    shared_evidence: Mapping[str, Any]
    attack: str | None = None

    def verify(self) -> tuple[bool, tuple[str, ...]]:
        errors: list[str] = []
        if self.schema != PAIR_SCHEMA:
            errors.append("schema:mismatch")
        if self.case_a == self.case_b:
            errors.append("cases:not_distinct")
        if self.truth_a == self.truth_b:
            errors.append("truth:not_distinct")
        if self.shared_evidence.get("claim_id") != self.claim_id:
            errors.append("claim:mismatch")
        return not errors, tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "case_a": self.case_a,
            "case_b": self.case_b,
            "truth_a": self.truth_a,
            "truth_b": self.truth_b,
            "shared_evidence": _json_copy(self.shared_evidence),
            "attack": self.attack,
        }


def certify_ambiguous_pair(
    case_a: AuditorEvidenceCase,
    case_b: AuditorEvidenceCase,
) -> AmbiguousPairCertificate:
    """Create a machine-checkable exact-evidence/different-truth certificate."""

    if not case_a.applicable or not case_b.applicable:
        raise ValueError("ambiguous-pair cases must both be applicable")
    if case_a.claim_id != case_b.claim_id:
        raise ValueError("ambiguous-pair claim IDs differ")
    if case_a.truth == case_b.truth:
        raise ValueError("ambiguous-pair truths must differ")
    left = case_a.evidence.as_dict()
    right = case_b.evidence.as_dict()
    if canonical_json(left) != canonical_json(right):
        raise ValueError("auditor-visible evidence is not exactly equal")
    certificate = AmbiguousPairCertificate(
        schema=PAIR_SCHEMA,
        claim_id=case_a.claim_id,
        case_a=case_a.case_id,
        case_b=case_b.case_id,
        truth_a=case_a.truth,
        truth_b=case_b.truth,
        shared_evidence=left,
        attack=case_b.attack or case_a.attack,
    )
    valid, errors = certificate.verify()
    if not valid:
        raise ValueError(f"invalid ambiguous-pair certificate: {errors}")
    return certificate
