"""Finite exact auditability calculus over information channels.

The module implements the deterministic special case used by AuditSpec:

* auditability is factorization through a finite evidence channel;
* sufficient contracts are dependency-closed hitting sets of claim-critical
  pairs; and
* a lifecycle transformation is claim-safe exactly when the claim decoder is
  constant on each transformation fiber.

All certificates contain the finite tables needed for independent replay.  They
establish results only for those declared tables and never prove that the table
exhausts an open world.
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .canonical import canonical_bytes, canonical_json, digest


QUOTIENT_SCHEMA = "AuditSpec-auditability-quotient-certificate-v1"
CONTRACT_SCHEMA = "AuditSpec-evidence-contract-duality-certificate-v1"
LIFECYCLE_SCHEMA = "AuditSpec-claim-relative-lifecycle-certificate-v1"
MIGRATION_BUNDLE_SCHEMA = "AuditSpec-claim-relative-migration-bundle-v1"
HORIZON_SCHEMA = "AuditSpec-semantic-audit-horizon-v1"


class InformationOrderError(ValueError):
    """A finite channel, transformation, or certificate is malformed."""


@dataclass(frozen=True)
class DeterministicProcessor:
    processor_id: str
    function: Callable[[Any], Any]


def analyze_auditability(
    *,
    claim_id: str,
    evidence_id: str,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return a factorization certificate or a canonical audit twin."""

    normalized = _channel_rows(rows)
    evidence_groups = _partition(normalized, "evidence_value")
    claim_groups = _partition(normalized, "claim_value")
    twin = _first_twin(normalized, value_field="evidence_value")
    decoder = []
    if twin is None:
        for group in evidence_groups:
            row = normalized[group["row_indexes"][0]]
            decoder.append(
                {
                    "evidence_value": row["evidence_value"],
                    "claim_value": row["claim_value"],
                }
            )
        decoder.sort(key=lambda item: canonical_json(item["evidence_value"]))
    body = {
        "schema": QUOTIENT_SCHEMA,
        "claim_id": _identifier(claim_id, "claim_id"),
        "evidence_id": _identifier(evidence_id, "evidence_id"),
        "rows": normalized,
        "world_count": len(normalized),
        "world_table_root": digest(
            "AuditSpec-finite-information-world-table-v1",
            [
                {"world_id": row["world_id"], "world": row["world"]}
                for row in normalized
            ],
        ),
        "claim_partition": claim_groups,
        "evidence_partition": evidence_groups,
        "claim_partition_root": digest(
            "AuditSpec-claim-partition-v1", claim_groups
        ),
        "evidence_partition_root": digest(
            "AuditSpec-evidence-partition-v1", evidence_groups
        ),
        "kernel_inclusion": twin is None,
        "factorization_exists": twin is None,
        "status": "FACTORIZATION" if twin is None else "TWIN_OBSTRUCTION",
        "decoder_table": decoder,
        "twin": twin,
        "boundaries": {
            "finite_declared_table_only": True,
            "open_world_completeness_proven": False,
            "claim_semantics_supplied": True,
        },
    }
    return {**body, "certificate_root": digest(QUOTIENT_SCHEMA, body)}


def verify_auditability_certificate(certificate: Mapping[str, Any]) -> bool:
    if not isinstance(certificate, Mapping) or certificate.get("schema") != QUOTIENT_SCHEMA:
        return False
    try:
        rebuilt = analyze_auditability(
            claim_id=certificate["claim_id"],
            evidence_id=certificate["evidence_id"],
            rows=certificate["rows"],
        )
    except (KeyError, TypeError, InformationOrderError, ValueError):
        return False
    return dict(certificate) == rebuilt


def compile_minimum_contract(
    *,
    claim_id: str,
    rows: Sequence[Mapping[str, Any]],
    mechanisms: Mapping[str, Mapping[str, Any]],
    state_cap: int | None = None,
) -> dict[str, Any]:
    """Compile an exact dependency-closed weighted hitting set.

    ``rows`` carry one observation per mechanism.  Positive integer costs and
    a deterministic cost/cardinality/identifier tie break make the optimum and
    deletion witnesses reproducible.
    """

    normalized_rows = _contract_rows(rows, mechanisms)
    normalized_mechanisms = _mechanisms(mechanisms)
    admissible = {
        mechanism_id
        for mechanism_id, row in normalized_mechanisms.items()
        if row["admissible"] is True
    }
    feasible_mechanisms = {
        mechanism_id
        for mechanism_id in admissible
        if _dependency_closure(
            (mechanism_id,), normalized_mechanisms, admissible
        )
        is not None
    }
    critical_pairs = _critical_pairs(normalized_rows)
    for pair in critical_pairs:
        pair["separators"] = sorted(
            mechanism_id
            for mechanism_id in feasible_mechanisms
            if normalized_rows[pair["left_index"]]["observations"][mechanism_id]
            != normalized_rows[pair["right_index"]]["observations"][mechanism_id]
        )
    mechanism_ids = tuple(sorted(feasible_mechanisms))
    candidate_rows = []
    explored = 0
    limit = state_cap if state_cap is not None else 1 << len(mechanism_ids)
    for size in range(len(mechanism_ids) + 1):
        for subset in itertools.combinations(mechanism_ids, size):
            if explored >= limit:
                return _analysis_incomplete(
                    claim_id=claim_id,
                    rows=normalized_rows,
                    mechanisms=normalized_mechanisms,
                    critical_pairs=critical_pairs,
                    state_cap=limit,
                    explored=explored,
                )
            explored += 1
            if _dependency_closure(subset, normalized_mechanisms, admissible) != set(
                subset
            ):
                continue
            missing = [
                pair["pair_id"]
                for pair in critical_pairs
                if not set(subset) & set(pair["separators"])
            ]
            candidate_rows.append(
                {
                    "contract": list(subset),
                    "dependency_closed": True,
                    "sufficient": not missing,
                    "missing_pair_ids": missing,
                    "cost": sum(
                        normalized_mechanisms[item]["cost"] for item in subset
                    ),
                }
            )
    feasible = [row for row in candidate_rows if row["sufficient"]]
    common = {
        "schema": CONTRACT_SCHEMA,
        "claim_id": _identifier(claim_id, "claim_id"),
        "rows": normalized_rows,
        "mechanisms": normalized_mechanisms,
        "critical_pairs": critical_pairs,
        "critical_pair_count": len(critical_pairs),
        "critical_pair_root": digest(
            "AuditSpec-claim-critical-pair-hypergraph-v1", critical_pairs
        ),
        "candidate_contracts": candidate_rows,
        "states_explored": explored,
        "tie_break": "cost_then_cardinality_then_utf8_mechanism_tuple",
        "boundaries": {
            "finite_declared_table_only": True,
            "catalog_relative": True,
            "open_world_completeness_proven": False,
        },
    }
    if not feasible:
        unseparated = next(
            (pair for pair in critical_pairs if not pair["separators"]), None
        )
        body = {
            **common,
            "status": "EVIDENCE_GAP",
            "selected": [],
            "selected_cost": None,
            "separation_certificate": [],
            "minimality_certificate": [],
            "optimality_certificate": None,
            "obstruction": {
                "type": "unseparated_critical_pair",
                "pair": unseparated,
            },
            "full_contract": list(mechanism_ids),
            "full_contract_sufficient": False,
        }
    else:
        selected_row = min(
            feasible,
            key=lambda row: (
                row["cost"],
                len(row["contract"]),
                tuple(row["contract"]),
            ),
        )
        selected = tuple(selected_row["contract"])
        separation = [
            {
                "pair_id": pair["pair_id"],
                "separator": min(set(selected) & set(pair["separators"])),
            }
            for pair in critical_pairs
        ]
        minimality = []
        for removed in selected:
            reduced = tuple(item for item in selected if item != removed)
            closure = _dependency_closure(
                reduced, normalized_mechanisms, admissible
            )
            if closure != set(reduced):
                minimality.append(
                    {
                        "removed": removed,
                        "witness_type": "dependency_nonclosure",
                        "pair_id": None,
                    }
                )
                continue
            pair = next(
                pair
                for pair in critical_pairs
                if not set(reduced) & set(pair["separators"])
            )
            minimality.append(
                {
                    "removed": removed,
                    "witness_type": "critical_pair",
                    "pair_id": pair["pair_id"],
                }
            )
        lower = [
            row for row in candidate_rows if row["cost"] < selected_row["cost"]
        ]
        body = {
            **common,
            "status": "CONTRACT",
            "selected": list(selected),
            "selected_cost": selected_row["cost"],
            "separation_certificate": separation,
            "minimality_certificate": minimality,
            "optimality_certificate": {
                "type": "exhaustive_lower_cost_infeasibility",
                "lower_cost_candidate_count": len(lower),
                "all_lower_cost_candidates_infeasible": all(
                    not row["sufficient"] for row in lower
                ),
                "candidate_table_root": digest(
                    "AuditSpec-contract-candidate-table-v1", candidate_rows
                ),
            },
            "obstruction": None,
            "full_contract": list(mechanism_ids),
            "full_contract_sufficient": all(
                set(mechanism_ids) & set(pair["separators"])
                for pair in critical_pairs
            ),
        }
    return {**body, "certificate_root": digest(CONTRACT_SCHEMA, body)}


def verify_contract_certificate(certificate: Mapping[str, Any]) -> bool:
    if not isinstance(certificate, Mapping) or certificate.get("schema") != CONTRACT_SCHEMA:
        return False
    if certificate.get("status") == "ANALYSIS_INCOMPLETE":
        body = {key: certificate[key] for key in certificate if key != "certificate_root"}
        return certificate.get("certificate_root") == digest(CONTRACT_SCHEMA, body)
    try:
        rebuilt = compile_minimum_contract(
            claim_id=certificate["claim_id"],
            rows=certificate["rows"],
            mechanisms=certificate["mechanisms"],
        )
    except (KeyError, TypeError, InformationOrderError, ValueError):
        return False
    return dict(certificate) == rebuilt


def analyze_lifecycle_transformation(
    *,
    claim_id: str,
    transformation_id: str,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Check decoder descent through one finite lifecycle transformation."""

    normalized = _lifecycle_rows(rows)
    source_rows = [
        {
            "world_id": row["state_id"],
            "world": {"source_evidence": row["source_evidence"]},
            "claim_value": row["claim_value"],
            "evidence_value": row["source_evidence"],
        }
        for row in normalized
    ]
    source = analyze_auditability(
        claim_id=claim_id,
        evidence_id=f"{transformation_id}:source",
        rows=source_rows,
    )
    if source["factorization_exists"] is not True:
        raise InformationOrderError(
            "capture-time evidence does not support the supplied claim"
        )
    twin = _first_twin(normalized, value_field="transformed_evidence")
    decoder = []
    if twin is None:
        for group in _partition_lifecycle(normalized, "transformed_evidence"):
            row = normalized[group["row_indexes"][0]]
            decoder.append(
                {
                    "transformed_evidence": row["transformed_evidence"],
                    "claim_value": row["claim_value"],
                }
            )
        decoder.sort(
            key=lambda item: canonical_json(item["transformed_evidence"])
        )
    transformation_table = [
        {
            "source_evidence": row["source_evidence"],
            "transformed_evidence": row["transformed_evidence"],
        }
        for row in normalized
    ]
    body = {
        "schema": LIFECYCLE_SCHEMA,
        "claim_id": _identifier(claim_id, "claim_id"),
        "transformation_id": _identifier(
            transformation_id, "transformation_id"
        ),
        "rows": normalized,
        "source_factorization_root": source["certificate_root"],
        "source_image_root": digest(
            "AuditSpec-lifecycle-source-image-v1",
            [row["source_evidence"] for row in normalized],
        ),
        "transformation_table_root": digest(
            "AuditSpec-lifecycle-transformation-table-v1", transformation_table
        ),
        "transformed_image_root": digest(
            "AuditSpec-lifecycle-transformed-image-v1",
            [row["transformed_evidence"] for row in normalized],
        ),
        "status": "PRESERVED" if twin is None else "HARD_SEMANTIC_GAP",
        "kernel_inclusion": twin is None,
        "induced_decoder": decoder,
        "lifecycle_twin": twin,
        "boundaries": {
            "finite_declared_image_only": True,
            "transformation_semantics_supplied": True,
            "open_world_completeness_proven": False,
        },
    }
    return {**body, "certificate_root": digest(LIFECYCLE_SCHEMA, body)}


def verify_lifecycle_certificate(certificate: Mapping[str, Any]) -> bool:
    if not isinstance(certificate, Mapping) or certificate.get("schema") != LIFECYCLE_SCHEMA:
        return False
    try:
        rebuilt = analyze_lifecycle_transformation(
            claim_id=certificate["claim_id"],
            transformation_id=certificate["transformation_id"],
            rows=certificate["rows"],
        )
    except (KeyError, TypeError, InformationOrderError, ValueError):
        return False
    return dict(certificate) == rebuilt


def make_migration_bundle(
    *, transformation_id: str, certificates: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    if not certificates:
        raise InformationOrderError("migration bundle has no claim certificates")
    normalized = {}
    for claim_id, certificate in sorted(certificates.items()):
        if (
            claim_id != certificate.get("claim_id")
            or certificate.get("transformation_id") != transformation_id
            or not verify_lifecycle_certificate(certificate)
        ):
            raise InformationOrderError("migration claim certificate is invalid")
        normalized[claim_id] = dict(certificate)
    body = {
        "schema": MIGRATION_BUNDLE_SCHEMA,
        "transformation_id": _identifier(
            transformation_id, "transformation_id"
        ),
        "certificates": normalized,
        "claim_ids": sorted(normalized),
    }
    return {**body, "bundle_root": digest(MIGRATION_BUNDLE_SCHEMA, body)}


def verify_migration_bundle(
    bundle: Mapping[str, Any], *, claim_id: str
) -> dict[str, Any]:
    if not isinstance(bundle, Mapping) or set(bundle) != {
        "schema",
        "transformation_id",
        "certificates",
        "claim_ids",
        "bundle_root",
    }:
        raise InformationOrderError("migration bundle keys mismatch")
    if bundle["schema"] != MIGRATION_BUNDLE_SCHEMA:
        raise InformationOrderError("migration bundle schema mismatch")
    body = {key: bundle[key] for key in bundle if key != "bundle_root"}
    if bundle["bundle_root"] != digest(MIGRATION_BUNDLE_SCHEMA, body):
        raise InformationOrderError("migration bundle root mismatch")
    if bundle["claim_ids"] != sorted(bundle["certificates"]):
        raise InformationOrderError("migration bundle claim population mismatch")
    certificate = bundle["certificates"].get(claim_id)
    if certificate is None or not verify_lifecycle_certificate(certificate):
        raise InformationOrderError("claim-relative migration certificate is absent")
    if certificate["transformation_id"] != bundle["transformation_id"]:
        raise InformationOrderError("migration transformation binding mismatch")
    return dict(certificate)


def no_posthoc_repair_certificate(
    lifecycle_certificate: Mapping[str, Any],
    processors: Sequence[DeterministicProcessor],
) -> dict[str, Any]:
    if not verify_lifecycle_certificate(lifecycle_certificate):
        raise InformationOrderError("lifecycle certificate is invalid")
    if lifecycle_certificate["status"] != "HARD_SEMANTIC_GAP":
        raise InformationOrderError("no-posthoc repair requires a lifecycle twin")
    twin = lifecycle_certificate["lifecycle_twin"]
    shared = twin["shared_value"]
    rows = []
    for processor in processors:
        left = processor.function(shared)
        right = processor.function(shared)
        canonical_bytes(left)
        canonical_bytes(right)
        rows.append(
            {
                "processor_id": _identifier(
                    processor.processor_id, "processor_id"
                ),
                "left_output": left,
                "right_output": right,
                "outputs_equal": left == right,
            }
        )
    body = {
        "schema": "AuditSpec-no-posthoc-repair-certificate-v1",
        "lifecycle_certificate_root": lifecycle_certificate["certificate_root"],
        "twin": twin,
        "processors": rows,
        "all_postprocessors_preserve_collision": all(
            row["outputs_equal"] for row in rows
        ),
        "repair_requirement": "new_trusted_execution_specific_separator",
    }
    return {
        **body,
        "certificate_root": digest(
            "AuditSpec-no-posthoc-repair-certificate-v1", body
        ),
    }


def classify_obstruction(
    *, lifecycle_certificate: Mapping[str, Any], operationally_usable: bool,
    missing_dependencies: Sequence[str] = (),
) -> dict[str, Any]:
    if not verify_lifecycle_certificate(lifecycle_certificate):
        raise InformationOrderError("lifecycle certificate is invalid")
    if lifecycle_certificate["status"] == "HARD_SEMANTIC_GAP":
        classification = "HARD_SEMANTIC_OBSTRUCTION"
        repairable_without_new_evidence = False
    elif not operationally_usable:
        classification = "SOFT_TRUST_INTERPRETABILITY_OBSTRUCTION"
        repairable_without_new_evidence = True
    else:
        classification = "AUDITABLE"
        repairable_without_new_evidence = True
    return {
        "schema": "AuditSpec-lifecycle-obstruction-classification-v1",
        "claim_id": lifecycle_certificate["claim_id"],
        "lifecycle_certificate_root": lifecycle_certificate["certificate_root"],
        "classification": classification,
        "operationally_usable": operationally_usable,
        "missing_dependencies": sorted(set(missing_dependencies)),
        "repairable_without_new_execution_specific_evidence": (
            repairable_without_new_evidence
        ),
    }


def semantic_audit_horizon(
    *, claim_id: str, timeline: Sequence[Mapping[str, Any]],
    no_new_evidence: bool,
) -> dict[str, Any]:
    if not timeline:
        raise InformationOrderError("audit horizon timeline is empty")
    rows = []
    seen_hard = False
    prefix_closed = True
    for index, point in enumerate(timeline):
        certificate = analyze_auditability(
            claim_id=claim_id,
            evidence_id=str(point["evidence_id"]),
            rows=point["rows"],
        )
        semantically_sufficient = certificate["factorization_exists"]
        if seen_hard and semantically_sufficient:
            prefix_closed = False
        seen_hard = seen_hard or not semantically_sufficient
        rows.append(
            {
                "index": index,
                "time": str(point["time"]),
                "evidence_id": str(point["evidence_id"]),
                "semantically_sufficient": semantically_sufficient,
                "certificate_root": certificate["certificate_root"],
            }
        )
    if no_new_evidence and not prefix_closed:
        raise InformationOrderError(
            "semantic horizon regained without a declared new evidence channel"
        )
    body = {
        "schema": HORIZON_SCHEMA,
        "claim_id": claim_id,
        "timeline": rows,
        "no_new_execution_specific_evidence": no_new_evidence,
        "semantic_horizon_prefix_closed": prefix_closed,
        "last_semantically_auditable_index": max(
            (row["index"] for row in rows if row["semantically_sufficient"]),
            default=None,
        ),
    }
    return {**body, "horizon_root": digest(HORIZON_SCHEMA, body)}


def _channel_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    required = {"world_id", "world", "claim_value", "evidence_value"}
    normalized = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != required:
            raise InformationOrderError("finite channel row keys mismatch")
        world_id = _identifier(row["world_id"], "world_id")
        normalized.append(
            {
                "world_id": world_id,
                "world": _json(row["world"], "world"),
                "claim_value": _json(row["claim_value"], "claim_value"),
                "evidence_value": _json(
                    row["evidence_value"], "evidence_value"
                ),
            }
        )
    if not normalized or len({row["world_id"] for row in normalized}) != len(
        normalized
    ):
        raise InformationOrderError("finite channel worlds are empty or duplicated")
    normalized.sort(key=lambda row: row["world_id"])
    return normalized


def _contract_rows(
    rows: Sequence[Mapping[str, Any]], mechanisms: Mapping[str, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    mechanism_ids = set(mechanisms)
    normalized = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "world_id",
            "world",
            "claim_value",
            "observations",
        }:
            raise InformationOrderError("contract row keys mismatch")
        observations = row["observations"]
        if not isinstance(observations, Mapping) or set(observations) != mechanism_ids:
            raise InformationOrderError("contract observation population mismatch")
        normalized.append(
            {
                "world_id": _identifier(row["world_id"], "world_id"),
                "world": _json(row["world"], "world"),
                "claim_value": _json(row["claim_value"], "claim_value"),
                "observations": {
                    key: _json(value, f"observation:{key}")
                    for key, value in sorted(observations.items())
                },
            }
        )
    if not normalized or len({row["world_id"] for row in normalized}) != len(
        normalized
    ):
        raise InformationOrderError("contract worlds are empty or duplicated")
    normalized.sort(key=lambda row: row["world_id"])
    return normalized


def _mechanisms(
    mechanisms: Mapping[str, Mapping[str, Any]]
) -> dict[str, dict[str, Any]]:
    if not mechanisms:
        raise InformationOrderError("mechanism catalog is empty")
    normalized = {}
    for mechanism_id, row in sorted(mechanisms.items()):
        _identifier(mechanism_id, "mechanism_id")
        if not isinstance(row, Mapping) or set(row) != {
            "cost",
            "requires",
            "admissible",
        }:
            raise InformationOrderError("mechanism row keys mismatch")
        cost = row["cost"]
        if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
            raise InformationOrderError("mechanism cost must be a positive integer")
        requires = sorted(set(row["requires"]))
        for dependency in requires:
            _identifier(dependency, "mechanism dependency")
        normalized[mechanism_id] = {
            "cost": cost,
            "requires": requires,
            "admissible": bool(row["admissible"]),
        }
    return normalized


def _lifecycle_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    required = {
        "state_id",
        "source_evidence",
        "transformed_evidence",
        "claim_value",
    }
    normalized = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != required:
            raise InformationOrderError("lifecycle row keys mismatch")
        normalized.append(
            {
                "state_id": _identifier(row["state_id"], "state_id"),
                "source_evidence": _json(
                    row["source_evidence"], "source_evidence"
                ),
                "transformed_evidence": _json(
                    row["transformed_evidence"], "transformed_evidence"
                ),
                "claim_value": _json(row["claim_value"], "claim_value"),
            }
        )
    if not normalized or len({row["state_id"] for row in normalized}) != len(
        normalized
    ):
        raise InformationOrderError("lifecycle states are empty or duplicated")
    normalized.sort(key=lambda row: row["state_id"])
    source_map = {}
    for row in normalized:
        key = canonical_json(row["source_evidence"])
        transformed = canonical_json(row["transformed_evidence"])
        prior = source_map.setdefault(key, transformed)
        if prior != transformed:
            raise InformationOrderError("lifecycle transformation is not deterministic")
    return normalized


def _partition(rows: Sequence[Mapping[str, Any]], field: str) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    values = {}
    for index, row in enumerate(rows):
        key = canonical_json(row[field])
        groups[key].append(index)
        values[key] = row[field]
    return [
        {
            "value": values[key],
            "world_ids": [rows[index]["world_id"] for index in groups[key]],
            "row_indexes": groups[key],
        }
        for key in sorted(groups)
    ]


def _partition_lifecycle(
    rows: Sequence[Mapping[str, Any]], field: str
) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    values = {}
    for index, row in enumerate(rows):
        key = canonical_json(row[field])
        groups[key].append(index)
        values[key] = row[field]
    return [
        {
            "value": values[key],
            "state_ids": [rows[index]["state_id"] for index in groups[key]],
            "row_indexes": groups[key],
        }
        for key in sorted(groups)
    ]


def _first_twin(
    rows: Sequence[Mapping[str, Any]], *, value_field: str
) -> dict[str, Any] | None:
    buckets: dict[str, tuple[int, str]] = {}
    for index, row in enumerate(rows):
        key = canonical_json(row[value_field])
        claim_key = canonical_json(row["claim_value"])
        prior = buckets.get(key)
        if prior is not None and prior[1] != claim_key:
            left = rows[prior[0]]
            id_field = "world_id" if "world_id" in left else "state_id"
            body = {
                "left_id": left[id_field],
                "right_id": row[id_field],
                "shared_value": row[value_field],
                "left_claim_value": left["claim_value"],
                "right_claim_value": row["claim_value"],
            }
            return {
                **body,
                "witness_root": digest(
                    "AuditSpec-information-order-twin-v1", body
                ),
            }
        buckets.setdefault(key, (index, claim_key))
    return None


def _critical_pairs(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for left, right in itertools.combinations(range(len(rows)), 2):
        if rows[left]["claim_value"] == rows[right]["claim_value"]:
            continue
        body = {
            "left_index": left,
            "right_index": right,
            "left_world_id": rows[left]["world_id"],
            "right_world_id": rows[right]["world_id"],
            "left_claim_value": rows[left]["claim_value"],
            "right_claim_value": rows[right]["claim_value"],
        }
        result.append(
            {
                **body,
                "pair_id": digest("AuditSpec-claim-critical-pair-v1", body),
                "separators": [],
            }
        )
    return result


def _dependency_closure(
    selected: Sequence[str],
    mechanisms: Mapping[str, Mapping[str, Any]],
    admissible: set[str],
) -> set[str] | None:
    closure = set(selected)
    pending = list(selected)
    while pending:
        mechanism_id = pending.pop()
        if mechanism_id not in mechanisms or mechanism_id not in admissible:
            return None
        for dependency in mechanisms[mechanism_id]["requires"]:
            if dependency not in mechanisms or dependency not in admissible:
                return None
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)
        if len(closure) > len(mechanisms):
            return None
    return closure


def _analysis_incomplete(
    *,
    claim_id: str,
    rows: list[dict[str, Any]],
    mechanisms: dict[str, dict[str, Any]],
    critical_pairs: list[dict[str, Any]],
    state_cap: int,
    explored: int,
) -> dict[str, Any]:
    body = {
        "schema": CONTRACT_SCHEMA,
        "claim_id": claim_id,
        "rows": rows,
        "mechanisms": mechanisms,
        "critical_pairs": critical_pairs,
        "status": "ANALYSIS_INCOMPLETE",
        "analysis_limit": {
            "bound_kind": "candidate_state_cap",
            "bound_value": state_cap,
            "states_explored": explored,
        },
        "selected": [],
        "selected_cost": None,
    }
    return {**body, "certificate_root": digest(CONTRACT_SCHEMA, body)}


def _json(value: Any, label: str) -> Any:
    try:
        canonical_bytes(value)
    except (TypeError, ValueError) as exc:
        raise InformationOrderError(f"{label} is not canonical JSON") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise InformationOrderError(f"{label} is invalid")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for character in value):
        raise InformationOrderError(f"{label} is invalid")
    return value
