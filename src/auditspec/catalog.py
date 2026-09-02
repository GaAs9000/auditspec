from __future__ import annotations

import hashlib
from dataclasses import asdict
from typing import Iterable

from .adapter_registry import registry_digest
from .model import AuditSpec
from .runtime.events import canonical_json


def catalog_payload(spec: AuditSpec) -> dict[str, object]:
    """Return the query-independent mechanism catalog representation.

    Query text and development/held-out labels are intentionally excluded.  A
    matching digest therefore checks that evaluation did not alter the
    candidate mechanisms after seeing a held-out query.
    """

    return {
        "spec": spec.name,
        "catalog_version": spec.metadata.get("catalog_version"),
        "adapter_registry_sha256": registry_digest(),
        "topology": spec.topology.as_dict(),
        "mechanisms": {
            name: spec.mechanisms[name].as_dict() for name in sorted(spec.mechanisms)
        },
    }


def catalog_digest(spec: AuditSpec) -> str:
    return hashlib.sha256(
        canonical_json(catalog_payload(spec)).encode("utf-8")
    ).hexdigest()


def combined_catalog_digest(specs: Iterable[AuditSpec]) -> str:
    payload = [catalog_payload(spec) for spec in sorted(specs, key=lambda item: item.name)]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def spec_payload(spec: AuditSpec) -> dict[str, object]:
    """Canonical payload binding certificates to all audit semantics."""

    return {
        "schema": "AuditSpec-bounded-spec-v2",
        "name": spec.name,
        "description": spec.description,
        "variables": spec.variables,
        "constraints": spec.constraints,
        "facts": {name: asdict(spec.facts[name]) for name in sorted(spec.facts)},
        "queries": {name: asdict(spec.queries[name]) for name in sorted(spec.queries)},
        "mechanisms": {
            name: spec.mechanisms[name].as_dict() for name in sorted(spec.mechanisms)
        },
        "threat_models": {
            name: {
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
                "bypass_edges": [list(edge) for edge in threat.bypass_edges],
                "description": threat.description,
            }
            for name, threat in sorted(spec.threat_models.items())
        },
        "metadata": spec.metadata,
        "topology": spec.topology.as_dict(),
        "adapter_registry_sha256": registry_digest(),
    }


def spec_digest(spec: AuditSpec) -> str:
    return hashlib.sha256(
        canonical_json(spec_payload(spec)).encode("utf-8")
    ).hexdigest()
