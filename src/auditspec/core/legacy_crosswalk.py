"""Data-driven legacy payment-to-Core crosswalk for the first vertical slice."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml
from auditspec.adapter_registry import ADAPTER_MANIFESTS

from .canonical import digest, legacy_json_value
from .claim_ir import ClaimIR
from .expression import Expr, collection, literal, parse_legacy_expression, variable
from .finite_model import FiniteDomain
from .mechanism_ir import (
    AdapterCandidate,
    CostVector,
    MechanismCatalog,
    MechanismSpec,
    Principal,
    PrincipalPattern,
)
from .refs import RegistryStore, RootedRef
from .wire import (
    BOOLEAN,
    REF,
    ExactDecimal,
    TypeNode,
    infer_scalar_type,
    require_digest,
    require_ref,
)

ROOT = Path(__file__).resolve().parents[3]


class CrosswalkError(ValueError):
    pass


@dataclass(frozen=True)
class CrosswalkBundle:
    overlay: dict[str, Any]
    claim: ClaimIR
    claim_ref: RootedRef
    domain: FiniteDomain
    catalog: MechanismCatalog
    weights: CostVector
    registries: RegistryStore
    bootstrap_refs: Mapping[str, RootedRef]
    schema_registry_root: str
    crosswalk_report: dict[str, Any]


def build_crosswalk(
    overlay: Mapping[str, Any], *, root: Path = ROOT
) -> CrosswalkBundle:
    raw_overlay = copy.deepcopy(dict(overlay))
    _validate_overlay(raw_overlay)
    source = raw_overlay["legacy_source"]
    source_path = _safe_path(root, source["path"])
    source_bytes = source_path.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != source["sha256"]:
        raise CrosswalkError("legacy source SHA-256 mismatch")
    for record in raw_overlay["pinned_implementation_sources"]:
        path = _safe_path(root, record["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise CrosswalkError(
                f"pinned implementation source changed: {record['path']}"
            )
    loaded = yaml.safe_load(source_bytes)
    lexical = yaml.load(source_bytes, Loader=yaml.BaseLoader)
    if not isinstance(loaded, dict) or not isinstance(lexical, dict):
        raise CrosswalkError("legacy source root must be a mapping")
    query_id = source["query_id"]
    try:
        query = loaded["queries"][query_id]
        variables_raw = loaded["variables"]
    except (KeyError, TypeError) as exc:
        raise CrosswalkError("legacy query/domain is missing") from exc
    variable_domains = {name: tuple(values) for name, values in variables_raw.items()}
    variable_types = {
        name: infer_scalar_type(list(values))
        for name, values in variable_domains.items()
    }
    constraints = tuple(
        parse_legacy_expression(str(text), variable_types)
        for text in loaded.get("constraints", [])
    )
    domain = FiniteDomain.build(
        "payment_finite_domain_core_slice",
        variable_types,
        variable_domains,
        constraints,
    )
    if len(domain.worlds) != raw_overlay["concrete_model"]["expected_world_count"]:
        raise CrosswalkError("legacy payment universe count changed")
    predicate = parse_legacy_expression(str(query["expression"]), variable_types)
    if predicate.output_type != BOOLEAN:
        raise CrosswalkError("slice query is not Boolean")

    registries = RegistryStore()
    bootstrap_records = _bootstrap_records(raw_overlay)
    bootstrap_refs = registries.register(
        "core_phase1_bootstrap_registry",
        "other",
        bootstrap_records,
    )
    schema_refs = registries.register(
        "core_phase1_schema_registry",
        "schema",
        _schema_descriptor_records(),
    )
    schema_registry_root = next(iter(schema_refs.values())).registry.package_root
    domain_refs = registries.register(
        "core_phase1_domain_registry", "other", [domain.record()]
    )
    domain_ref = domain_refs[domain.domain_id]
    selector = Expr.build(literal(True, BOOLEAN), variable_types, display="true")
    scope_expr = Expr.build(
        literal(True, BOOLEAN), {"carrier": BOOLEAN}, display="true"
    )
    claim_cfg = raw_overlay["claim"]
    carrier_ref = bootstrap_refs["carrier.sqlite_payment_ledger"]
    scope_semantics_ref = bootstrap_refs["scope.synthetic_declared_carriers"]
    world_scope = {
        "type": "declared_closed_world",
        "carrier_type_ref": carrier_ref.to_wire(),
        "scope_semantics_version": scope_semantics_ref.to_wire(),
        "scope_predicate_ref": scope_expr.to_wire(),
        "scope_commitment": "",
        "universe_ref": domain.universe_root,
    }
    world_scope["scope_commitment"] = digest(
        "AuditSpec-WorldScope-1.0",
        {
            "type": world_scope["type"],
            "carrier_type_ref": world_scope["carrier_type_ref"],
            "scope_semantics_version": world_scope["scope_semantics_version"],
            "scope_predicate_digest": scope_expr.ast_digest,
            "universe_ref": domain.universe_root,
        },
    )
    temporal = _temporal_scope(claim_cfg["temporal_scope"], bootstrap_refs)
    dependencies = tuple(
        sorted((domain_ref, carrier_ref, scope_semantics_ref), key=lambda item: item.id)
    )
    semantics = ClaimIR.compute_semantics_commitment(
        predicate,
        tuple(claim_cfg["entities"]),
        claim_cfg["anchor_entity"],
        domain_ref,
        claim_cfg["applicability_quantifier"],
        selector,
        dependencies,
    )
    claim = ClaimIR(
        claim_cfg["id"],
        claim_cfg["domain"],
        domain_ref,
        claim_cfg["kind"],
        predicate,
        tuple(claim_cfg["entities"]),
        claim_cfg["anchor_entity"],
        domain_ref,
        claim_cfg["applicability_quantifier"],
        selector,
        world_scope,
        temporal,
        None,
        claim_cfg["required_assurance"],
        dependencies,
        semantics,
    )
    claim_refs = registries.register(
        "core_phase1_claim_registry", "claim", [claim.to_wire()]
    )
    claim_ref = claim_refs[claim.id]
    catalog = _mechanism_catalog(
        raw_overlay, loaded, lexical, variable_types, bootstrap_refs
    )
    mechanism_refs = registries.register(
        "core_phase1_mechanism_registry",
        "mechanism",
        [catalog.mechanisms[name].to_wire() for name in sorted(catalog.mechanisms)],
    )
    adapter_refs = registries.register(
        "core_phase1_adapter_registry",
        "adapter",
        [catalog.adapters[name].to_wire() for name in sorted(catalog.adapters)],
    )
    weights = CostVector.from_wire(raw_overlay["cost_objective"])
    report = {
        "schema": "AuditSpec-core-phase1-crosswalk-report-v1",
        "id": "crosswalk.payment_settled_exactly_once",
        "provenance": raw_overlay["provenance"],
        "legacy_source_path": source["path"],
        "legacy_source_sha256": source["sha256"],
        "pinned_implementation_sources": raw_overlay["pinned_implementation_sources"],
        "legacy_query_expression_sha256": hashlib.sha256(
            str(query["expression"]).encode("utf-8")
        ).hexdigest(),
        "core_predicate_digest": predicate.ast_digest,
        "core_claim_payload_digest": claim_ref.payload_digest,
        "finite_domain_root": domain.domain_root,
        "universe_root": domain.universe_root,
        "world_count": len(domain.worlds),
        "concrete_model": raw_overlay["concrete_model"],
        "candidate_mechanisms": list(raw_overlay["candidate_mechanisms"]),
        "mechanism_refs": [
            mechanism_refs[name].to_wire() for name in sorted(mechanism_refs)
        ],
        "adapter_refs": [adapter_refs[name].to_wire() for name in sorted(adapter_refs)],
        "schema_refs": [schema_refs[name].to_wire() for name in sorted(schema_refs)],
        "threat_model_ref": bootstrap_refs["threat.synthetic_payment_slice"].to_wire(),
        "mechanism_dependencies": [
            {
                "mechanism_id": name,
                "requires": list(catalog.dependencies[name]),
            }
            for name in sorted(catalog.dependencies)
        ],
        "cost_objective": weights.to_wire(),
        "new_semantics_not_inherited_from_legacy": [
            "world_scope",
            "temporal_scope",
            "lifecycle_policy",
            "closure_expressions",
            "principal_patterns",
            "adapter_hook_records",
        ],
        "historical_result_migrated": False,
    }
    return CrosswalkBundle(
        raw_overlay,
        claim,
        claim_ref,
        domain,
        catalog,
        weights,
        registries,
        bootstrap_refs,
        schema_registry_root,
        report,
    )


def _schema_descriptor_records() -> list[dict[str, Any]]:
    schemas = (
        "AuditSpec-Expr-1.0",
        "AuditSpec-analysis-limit-v1",
        "AuditSpec-claim-ir-v1",
        "AuditSpec-core-installation-plan-v1",
        "AuditSpec-mechanism-spec-v1",
        "AuditSpec-scoped-claim-v1",
        "AuditSpec-verified-contract-v1",
        "auditspec.impl.adapter-candidate.v1",
        "auditspec.impl.finite-domain.v1",
        "auditspec.impl.lifecycle-policy-template.v1",
        "auditspec.impl.obligation-witness.v1",
        "auditspec.impl.runtime-hook.v1",
    )
    return [
        {
            "schema": "auditspec.impl.schema-descriptor.v1",
            "id": f"schema_descriptor.{index}",
            "target_schema": target,
            "schema_version": "AuditSpec-Schema-1.0",
            "validator_profile": "auditspec.core.validation:phase1_subset",
            "record_identity_pointer": {
                "AuditSpec-scoped-claim-v1": "/scoped_claim_id",
                "AuditSpec-verified-contract-v1": "/contract_id",
                "AuditSpec-core-installation-plan-v1": "/plan_id",
                "AuditSpec-mechanism-spec-v1": "/mechanism_id",
            }.get(target, "/id"),
        }
        for index, target in enumerate(schemas)
    ]


def _bootstrap_records(overlay: dict[str, Any]) -> list[dict[str, Any]]:
    temporal = overlay["claim"]["temporal_scope"]
    paths = overlay["pinned_implementation_sources"]
    return [
        {
            "schema": "auditspec.impl.calendar.v1",
            "id": temporal["audit_grace"]["calendar_id"],
            "calendar": "proleptic_gregorian",
            "timezone": "UTC",
            "tzdb": "synthetic-fixed-utc",
            "end_of_month": "clamp",
        },
        {
            "schema": "auditspec.impl.audit-horizon-policy.v1",
            "id": temporal["audit_horizon"]["policy_id"],
            "scope": "synthetic_core_phase1_slice_only",
        },
        {
            "schema": "auditspec.impl.lifecycle-policy-template.v1",
            "id": "policy.lifecycle.synthetic_slice",
            "minimum_retain_through_audit_horizon": True,
            "deletion_required_by": None,
            "custody_sla_proven": False,
        },
        {
            "schema": "auditspec.impl.carrier-type.v1",
            "id": "carrier.sqlite_payment_ledger",
            "carrier": "sqlite_committed_row",
            "binding": ["action_id", "execution_window"],
        },
        {
            "schema": "auditspec.impl.scope-semantics.v1",
            "id": "scope.synthetic_declared_carriers",
            "statement": overlay["claim"]["scope_statement"],
            "open_world": False,
        },
        {
            "schema": "auditspec.impl.verifier.v1",
            "id": "verifier.exact_observation",
            "computation": "identity_over_typed_realized_value",
            "independence_proven": False,
        },
        {
            "schema": "auditspec.impl.runtime-hook.v1",
            "id": "hook.emit_mechanism_event",
            "implementation": "auditspec.runtime.evidence:emit_mechanism_event",
            "source": next(
                item for item in paths if item["path"].endswith("runtime/evidence.py")
            ),
            "core_ledger_conformance_proven": False,
        },
        {
            "schema": "auditspec.impl.threat-model.v1",
            "id": "threat.synthetic_payment_slice",
            "scope": "declared finite fixture",
            "runtime_mediation_proven": False,
        },
        {
            "schema": "auditspec.impl.schema-profile.v1",
            "id": "schema.core_1_0_phase1_subset",
            "core_schema": "AuditSpec-Schema-1.0",
            "subset_only": True,
        },
        {
            "schema": "auditspec.impl.policy-coverage-witness.v1",
            "id": "witness.lifecycle_policy_covers_horizon",
            "policy_id": "policy.lifecycle.synthetic_slice",
            "horizon_policy_id": temporal["audit_horizon"]["policy_id"],
            "result": "design_time_policy_relation_only",
        },
    ]


def _temporal_scope(
    config: dict[str, Any], refs: Mapping[str, RootedRef]
) -> dict[str, Any]:
    horizon_cfg = config["audit_horizon"]
    horizon = {
        "mode": "absolute",
        "policy": refs[horizon_cfg["policy_id"]].to_wire(),
        "absolute_deadline": horizon_cfg["absolute_deadline"],
    }
    grace_cfg = config["audit_grace"]
    grace = {
        "years": grace_cfg["years"],
        "months": grace_cfg["months"],
        "days": grace_cfg["days"],
        "seconds": grace_cfg["seconds"],
        "nanoseconds": grace_cfg["nanoseconds"],
        "calendar": refs[grace_cfg["calendar_id"]].to_wire(),
        "timezone_id": grace_cfg["timezone_id"],
    }
    schedule = dict(config["audit_schedule"])
    return {
        "execution_window": config["execution_window"],
        "audit_horizon": horizon,
        "audit_horizon_commitment": digest("AuditSpec-audit-horizon-v1", horizon),
        "audit_schedule": schedule,
        "audit_grace": grace,
        "audit_schedule_commitment": digest(
            "AuditSpec-audit-schedule-v1", {"schedule": schedule, "audit_grace": grace}
        ),
    }


def _mechanism_catalog(
    overlay: dict[str, Any],
    loaded: dict[str, Any],
    lexical: dict[str, Any],
    variable_types: Mapping[str, TypeNode],
    refs: Mapping[str, RootedRef],
) -> MechanismCatalog:
    candidates = tuple(overlay["candidate_mechanisms"])
    if len(candidates) != len(set(candidates)) or set(candidates) != set(
        overlay["mechanism_overlays"]
    ):
        raise CrosswalkError("candidate mechanism set/overlay mismatch")
    mechanisms: dict[str, MechanismSpec] = {}
    dependencies: dict[str, tuple[str, ...]] = {}
    adapters: dict[str, AdapterCandidate] = {}
    adapter_source_sha = next(
        row["sha256"]
        for row in overlay["pinned_implementation_sources"]
        if row["path"].endswith("adapter_registry.py")
    )
    for name in candidates:
        try:
            legacy = loaded["mechanisms"][name]
            lexical_cost = lexical["mechanisms"][name]["cost"]
            config = overlay["mechanism_overlays"][name]
        except (KeyError, TypeError) as exc:
            raise CrosswalkError(f"mechanism crosswalk source missing: {name}") from exc
        sources = tuple(config["sources"])
        if any(source not in variable_types for source in sources):
            raise CrosswalkError(f"mechanism source is not in the finite model: {name}")
        if set(sources) != set(legacy.get("facts", sources)):
            raise CrosswalkError(
                f"mechanism source crosswalk changed legacy facts: {name}"
            )
        source_types = tuple(variable_types[source] for source in sources)
        if len(source_types) == 1:
            output_type = source_types[0]
        elif len(set(source_types)) == 1:
            output_type = TypeNode("list", item=source_types[0])
        else:
            raise CrosswalkError(
                "multi-source exact observation needs one homogeneous list type"
            )
        identity = Expr.build(
            variable(config["identity_variable"], REF),
            {config["identity_variable"]: REF},
        )
        expected_population = Expr.build(
            collection("set", REF, [variable(config["identity_variable"], REF)]),
            {config["identity_variable"]: REF},
        )
        verification = Expr.build(
            variable("observed_value", output_type), {"observed_value": output_type}
        )
        declared_cost = CostVector.from_wire(
            {
                dimension: ExactDecimal.parse(str(lexical_cost[dimension])).to_wire()
                for dimension in ("bytes", "privacy", "latency_ms", "fragility")
            }
        )
        if config["adapter_id"] != legacy.get("adapter"):
            raise CrosswalkError(f"adapter id differs from legacy mechanism: {name}")
        manifest = ADAPTER_MANIFESTS.get(config["adapter_id"])
        if manifest is None:
            raise CrosswalkError(f"adapter is absent from the pinned registry: {name}")
        producer_config = config["producer"]
        capture_config = config["capture_point"]
        binding_edges = _legacy_binding_edges(legacy.get("binding_edges", []))
        if (
            producer_config["id"] != legacy.get("producer")
            or capture_config["id"] != legacy.get("capture_point")
            or producer_config["id"] not in manifest.producers
            or capture_config["id"] not in manifest.capture_points
            or legacy.get("integrity") not in manifest.integrity
            or "exact" not in manifest.observation_kinds
            or set(binding_edges) - set(manifest.binding_edges)
            or (
                legacy.get("coverage_channel") is not None
                and legacy["coverage_channel"] not in manifest.coverage_channels
            )
        ):
            raise CrosswalkError(f"adapter manifest does not cover mechanism: {name}")
        capture_point = Principal(**config["capture_point"])
        mechanisms[name] = MechanismSpec(
            name,
            "exact",
            sources,
            output_type,
            PrincipalPattern(**config["producer"]),
            PrincipalPattern(**config["capture_point"]),
            binding_edges,
            legacy.get("coverage_channel"),
            bool(legacy.get("coverage_channel")),
            bool(legacy.get("coverage_channel")),
            identity,
            expected_population,
            config["cardinality"],
            config["verifier_ref"],
            verification,
            declared_cost,
            refs[config["lifecycle_policy_id"]],
        )
        requires = tuple(config["requires"])
        if tuple(legacy.get("requires", [])) != requires:
            raise CrosswalkError(f"mechanism dependency crosswalk mismatch: {name}")
        dependencies[name] = requires
        adapters[name] = AdapterCandidate(
            config["adapter_id"],
            name,
            config["ledger"],
            refs[config["hook_point_id"]],
            capture_point,
            "candidate_pending_conformance",
            digest(
                "auditspec.legacy.adapter-manifest.v1",
                legacy_json_value(manifest.as_dict()),
            ),
            adapter_source_sha,
        )
    return MechanismCatalog.build(mechanisms, dependencies, adapters)


def _legacy_binding_edges(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise CrosswalkError("legacy binding_edges must be a list")
    edges: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, str) and item.count("->") == 1:
            source, target = item.split("->", 1)
        elif isinstance(item, list) and len(item) == 2:
            source, target = item
        else:
            raise CrosswalkError("legacy binding edge is malformed")
        edge = (str(source).strip(), str(target).strip())
        if not all(edge) or edge[0] == edge[1]:
            raise CrosswalkError("legacy binding edge is invalid")
        edges.append(edge)
    if len(edges) != len(set(edges)):
        raise CrosswalkError("legacy binding edges contain duplicates")
    return tuple(edges)


def _validate_overlay(value: dict[str, Any]) -> None:
    expected = {
        "schema",
        "overlay_id",
        "provenance",
        "legacy_source",
        "pinned_implementation_sources",
        "claim",
        "concrete_model",
        "candidate_mechanisms",
        "mechanism_overlays",
        "cost_objective",
        "analysis_state_cap",
        "boundaries",
    }
    if (
        set(value) != expected
        or value.get("schema") != "AuditSpec-core-phase1-overlay-v1"
    ):
        raise CrosswalkError("overlay top-level schema/key mismatch")
    if value.get("provenance") != "semantic_migration":
        raise CrosswalkError(
            "legacy missing semantics cannot be a structural crosswalk"
        )
    _exact_keys(value["legacy_source"], {"path", "sha256", "query_id"}, "legacy_source")
    require_digest(value["legacy_source"]["sha256"], "legacy source sha256")
    require_ref(value["legacy_source"]["query_id"], "legacy query id")
    pinned = value["pinned_implementation_sources"]
    if not isinstance(pinned, list) or not pinned:
        raise CrosswalkError("pinned implementation sources must be non-empty")
    for index, row in enumerate(pinned):
        _exact_keys(row, {"path", "sha256"}, f"pinned source {index}")
        require_digest(row["sha256"], f"pinned source {index} sha256")
    claim = value["claim"]
    _exact_keys(
        claim,
        {
            "id",
            "domain",
            "kind",
            "entities",
            "anchor_entity",
            "applicability_quantifier",
            "required_assurance",
            "world_scope",
            "scope_statement",
            "temporal_scope",
        },
        "claim overlay",
    )
    temporal = claim["temporal_scope"]
    _exact_keys(
        temporal,
        {"execution_window", "audit_horizon", "audit_schedule", "audit_grace"},
        "claim temporal scope",
    )
    _exact_keys(temporal["execution_window"], {"from", "to"}, "execution window")
    _exact_keys(
        temporal["audit_horizon"],
        {"mode", "policy_id", "absolute_deadline"},
        "audit horizon",
    )
    _exact_keys(temporal["audit_schedule"], {"mode"}, "audit schedule")
    _exact_keys(
        temporal["audit_grace"],
        {
            "years",
            "months",
            "days",
            "seconds",
            "nanoseconds",
            "calendar_id",
            "timezone_id",
        },
        "audit grace",
    )
    concrete = value["concrete_model"]
    _exact_keys(
        concrete,
        {
            "kind",
            "action_id",
            "row_count_variable",
            "abstraction",
            "negative_control_abstraction",
            "expected_world_count",
        },
        "concrete model",
    )
    if (
        concrete["kind"] != "sqlite_committed_rows_by_action_in_isolated_database"
        or concrete["abstraction"] != "exact_row_count"
        or concrete["negative_control_abstraction"] != "cap_at_one"
        or isinstance(concrete["expected_world_count"], bool)
        or not isinstance(concrete["expected_world_count"], int)
        or concrete["expected_world_count"] <= 0
    ):
        raise CrosswalkError("concrete model profile is invalid")
    require_ref(concrete["action_id"], "concrete model action id")
    require_ref(concrete["row_count_variable"], "concrete row-count variable")
    candidates = value["candidate_mechanisms"]
    if (
        not isinstance(candidates, list)
        or not candidates
        or candidates != sorted(set(candidates))
    ):
        raise CrosswalkError("candidate mechanism ids must be sorted-unique")
    mechanism_overlays = value["mechanism_overlays"]
    if not isinstance(mechanism_overlays, dict) or set(mechanism_overlays) != set(
        candidates
    ):
        raise CrosswalkError("mechanism overlay population mismatch")
    mechanism_keys = {
        "sources",
        "ledger",
        "adapter_id",
        "requires",
        "producer",
        "capture_point",
        "hook_point_id",
        "identity_variable",
        "cardinality",
        "verifier_ref",
        "lifecycle_policy_id",
    }
    for name in candidates:
        config = mechanism_overlays[name]
        _exact_keys(config, mechanism_keys, f"mechanism overlay {name}")
        for principal_field in ("producer", "capture_point"):
            _exact_keys(
                config[principal_field],
                {"id", "key_domain", "key_id"},
                f"{name}.{principal_field}",
            )
        if not isinstance(config["sources"], list) or not all(
            isinstance(item, str) for item in config["sources"]
        ):
            raise CrosswalkError(f"{name}.sources must be a string list")
        if not isinstance(config["requires"], list) or not all(
            isinstance(item, str) for item in config["requires"]
        ):
            raise CrosswalkError(f"{name}.requires must be a string list")
        for ref_field in (
            "adapter_id",
            "hook_point_id",
            "identity_variable",
            "verifier_ref",
            "lifecycle_policy_id",
        ):
            require_ref(config[ref_field], f"{name}.{ref_field}")
    _exact_keys(
        value["cost_objective"],
        {"bytes", "privacy", "latency_ms", "fragility"},
        "cost objective",
    )
    CostVector.from_wire(value["cost_objective"])
    boundaries = value["boundaries"]
    required_false = {
        "core_assurance_result_emitted",
        "verified_auditable_proven",
        "adapter_conformance_proven",
        "registry_authentication_proven",
        "runtime_installation_proven",
        "capture_and_verification_proven",
        "audit_time_lifecycle_proven",
        "core_c1_complete",
        "core_c3_complete",
        "inventory_completeness_proven",
        "candidate_registry_exhausts_legacy_catalog",
    }
    if not isinstance(boundaries, dict) or set(boundaries) != {
        "maximum_lifecycle_state",
        *required_false,
    }:
        raise CrosswalkError("overlay boundary key set mismatch")
    if boundaries.get("maximum_lifecycle_state") != "PLANNED" or any(
        boundaries.get(name) is not False for name in required_false
    ):
        raise CrosswalkError("overlay overclaims the Phase 1 boundary")
    if (
        isinstance(value["analysis_state_cap"], bool)
        or not isinstance(value["analysis_state_cap"], int)
        or value["analysis_state_cap"] < 0
    ):
        raise CrosswalkError("analysis state cap must be a non-negative integer")


def _exact_keys(value: Any, keys: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise CrosswalkError(f"{where} key mismatch")


def _safe_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise CrosswalkError("overlay path escapes repository root") from exc
    if not path.is_file() or path.is_symlink():
        raise CrosswalkError(f"overlay source is not a regular file: {relative}")
    return path
