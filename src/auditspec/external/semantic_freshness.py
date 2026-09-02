"""Executable-claim identity commitments for cross-version evidence binding.

The commitment is deliberately conservative.  It binds a witness to a
canonical executable descriptor; it does not attempt to decide semantic
equivalence between arbitrary programs, nor does it certify oracle correctness.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from ..runtime.events import canonical_json
from .claims_v07 import V07ClaimDefinition


EXECUTABLE_CLAIM_DESCRIPTOR_SCHEMA = "AuditSpec-executable-claim-descriptor-v1"
_COMMITMENT = re.compile(r"^[0-9a-f]{64}$")


def executable_claim_descriptor(
    *,
    claim_id: str,
    environment: str,
    oracle_check_id: str,
    oracle_source: str,
    applicability_predicate_id: str,
    output_schema: str = "boolean",
    threat_model_id: str = "external-benchmark-evidence-v1",
) -> dict[str, str]:
    """Build the closed canonical descriptor committed by retained evidence."""

    values = {
        "claim_id": claim_id,
        "environment": environment,
        "oracle_check_id": oracle_check_id,
        "oracle_source": oracle_source,
        "applicability_predicate_id": applicability_predicate_id,
        "output_schema": output_schema,
        "threat_model_id": threat_model_id,
    }
    if any(not isinstance(value, str) or not value for value in values.values()):
        raise ValueError("executable claim descriptor fields must be non-empty strings")
    return {"schema": EXECUTABLE_CLAIM_DESCRIPTOR_SCHEMA, **values}


def v07_executable_claim_descriptor(
    claim: V07ClaimDefinition,
    *,
    threat_model_id: str = "external-benchmark-evidence-v1",
) -> dict[str, str]:
    """Build the frozen v0.7 executable descriptor for a positive claim."""

    if claim.oracle_check_id is None:
        raise ValueError(f"claim {claim.claim_id} has no executable oracle check")
    return executable_claim_descriptor(
        claim_id=claim.claim_id,
        environment=claim.environment,
        oracle_check_id=claim.oracle_check_id,
        oracle_source=claim.oracle_source,
        applicability_predicate_id=(
            f"v07:{claim.claim_id}:{claim.oracle_check_id}:applicability-v1"
        ),
        threat_model_id=threat_model_id,
    )


def claim_semantics_commitment(descriptor: Mapping[str, Any]) -> str:
    """Commit to one complete canonical descriptor."""

    expected = {
        "schema",
        "claim_id",
        "environment",
        "oracle_check_id",
        "oracle_source",
        "applicability_predicate_id",
        "output_schema",
        "threat_model_id",
    }
    if set(descriptor) != expected:
        raise ValueError(
            "executable claim descriptor fields differ from the closed schema"
        )
    if descriptor.get("schema") != EXECUTABLE_CLAIM_DESCRIPTOR_SCHEMA:
        raise ValueError("unsupported executable claim descriptor schema")
    if any(
        not isinstance(value, str) or not value for value in descriptor.values()
    ):
        raise ValueError("executable claim descriptor values must be non-empty strings")
    return hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()


def valid_claim_semantics_commitment(value: object) -> bool:
    return isinstance(value, str) and bool(_COMMITMENT.fullmatch(value))
