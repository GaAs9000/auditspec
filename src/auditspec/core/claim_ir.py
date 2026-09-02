"""Core Claim IR formation, world scoping, and ScopedClaim construction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import digest
from .expression import Expr
from .refs import RegistryStore, RootedRef
from .wire import BOOLEAN, require_digest, require_instant, require_ref


VERDICTS = {
    "VERIFIED_AUDITABLE",
    "QUERY_GAP",
    "MODEL_GAP",
    "EVIDENCE_GAP",
    "ANALYSIS_INCOMPLETE",
    "REALIZATION_GAP",
    "TCB_GAP",
    "INVENTORY_GAP",
    "VERIFICATION_FAILURE",
    "LIFECYCLE_GAP",
    "UNREALIZABLE_INTERVENTION",
}


@dataclass(frozen=True)
class FormationFailure:
    verdict: str
    obligation: str
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.verdict != "QUERY_GAP" or self.obligation not in {"Q", "WorldScope"}:
            raise ValueError("formation failure must be a Q/WorldScope QUERY_GAP")


@dataclass(frozen=True)
class ClaimIR:
    id: str
    domain: str
    environment: RootedRef
    kind: str
    predicate: Expr
    entities: tuple[str, ...]
    anchor_entity: str
    concrete_domain_ref: RootedRef
    quantifier: str
    selector: Expr
    world_scope: dict[str, Any]
    temporal_scope: dict[str, Any]
    intervention_target: str | None
    required_assurance: str
    semantics_dependencies: tuple[RootedRef, ...]
    semantics_commitment: str

    def to_wire(self) -> dict[str, Any]:
        result = {
            "schema": "AuditSpec-claim-ir-v1",
            "id": self.id,
            "domain": self.domain,
            "environment": self.environment.to_wire(),
            "kind": self.kind,
            "predicate": {
                "expression": self.predicate.to_wire(),
                "output_type": "boolean",
                "entities": list(self.entities),
                "anchor_entity": self.anchor_entity,
            },
            "applicability": {
                "concrete_domain_ref": self.concrete_domain_ref.to_wire(),
                "quantifier": self.quantifier,
                "selector": self.selector.to_wire(),
            },
            "world_scope": self.world_scope,
            "temporal_scope": self.temporal_scope,
            "causal_scope": {"intervention_target": self.intervention_target},
            "required_assurance": {"level": self.required_assurance},
            "semantics_commitment": self.semantics_commitment,
        }
        return result

    @staticmethod
    def compute_semantics_commitment(
        predicate: Expr,
        entities: tuple[str, ...],
        anchor_entity: str,
        concrete_domain_ref: RootedRef,
        quantifier: str,
        selector: Expr,
        dependencies: tuple[RootedRef, ...],
    ) -> str:
        dependency_rows = [
            {"kind": "rooted_ref", "record": item.to_wire()}
            for item in sorted(
                dependencies, key=lambda ref: (ref.id, ref.payload_digest)
            )
        ]
        return digest(
            "AuditSpec-claim-semantics-commitment-v3",
            {
                "predicate": {
                    "expression_digest": predicate.ast_digest,
                    "output_type": "boolean",
                    "entities": list(entities),
                    "anchor_entity": anchor_entity,
                },
                "applicability": {
                    "concrete_domain_ref": concrete_domain_ref.to_wire(),
                    "quantifier": quantifier,
                    "selector_digest": selector.ast_digest,
                },
                "dependencies": dependency_rows,
            },
        )


@dataclass(frozen=True)
class ScopedClaim:
    scoped_claim_id: str
    claim_ref: RootedRef
    claim_ir_digest: str
    scope_commitment: str
    resolved_universe_ref: str | None
    q_check_trace: tuple[dict[str, str], ...]
    world_scope_check_trace: tuple[dict[str, str], ...]
    scoped_claim_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-scoped-claim-v1",
            "scoped_claim_id": self.scoped_claim_id,
            "claim_ref": self.claim_ref.to_wire(),
            "claim_ir_digest": self.claim_ir_digest,
            "scope_commitment": self.scope_commitment,
            "resolved_universe_ref": self.resolved_universe_ref,
            "q_check_trace": list(self.q_check_trace),
            "world_scope_check_trace": list(self.world_scope_check_trace),
            "scoped_claim_digest": self.scoped_claim_digest,
        }


def validate_and_scope(
    claim: ClaimIR,
    claim_ref: RootedRef,
    registries: RegistryStore,
) -> ScopedClaim | FormationFailure:
    q_errors: list[str] = []
    scope_errors: list[str] = []
    try:
        require_ref(claim.id, "claim.id")
    except ValueError as exc:
        q_errors.append(str(exc))
    if claim.domain not in {
        "interaction",
        "effect",
        "config",
        "lifecycle",
        "authority",
    }:
        q_errors.append("claim.domain is outside the closed enum")
    if claim.kind not in {
        "fact",
        "authorization",
        "compliance",
        "attribution",
        "coverage",
        "causality",
    }:
        q_errors.append("claim.kind is outside the closed enum")
    if claim.predicate.output_type != BOOLEAN or claim.selector.output_type != BOOLEAN:
        q_errors.append("predicate and selector must be Boolean")
    if not claim.entities or claim.anchor_entity not in claim.entities:
        q_errors.append("anchor entity must occur in the non-empty entity set")
    is_causal = claim.kind == "causality"
    if (claim.quantifier == "counterfactual") != is_causal:
        q_errors.append("counterfactual quantifier and causal kind disagree")
    if (claim.intervention_target is not None) != is_causal:
        q_errors.append("intervention target and causal kind disagree")
    if (claim.required_assurance == "active") != is_causal:
        q_errors.append("active assurance and causal kind disagree")
    if claim.quantifier not in {"forall", "exists", "counterfactual"}:
        q_errors.append("unknown applicability quantifier")
    if claim.required_assurance not in {"passive", "active"}:
        q_errors.append("unknown assurance level")
    try:
        registries.resolve(claim.environment)
        registries.resolve(claim.concrete_domain_ref)
        for dependency in claim.semantics_dependencies:
            registries.resolve(dependency)
    except ValueError as exc:
        q_errors.append(str(exc))
    expected_semantics = ClaimIR.compute_semantics_commitment(
        claim.predicate,
        claim.entities,
        claim.anchor_entity,
        claim.concrete_domain_ref,
        claim.quantifier,
        claim.selector,
        claim.semantics_dependencies,
    )
    if claim.semantics_commitment != expected_semantics:
        q_errors.append("semantics commitment mismatch")
    q_errors.extend(_validate_temporal_scope(claim.temporal_scope, registries))
    if q_errors:
        return FormationFailure("QUERY_GAP", "Q", tuple(sorted(set(q_errors))))

    scope = claim.world_scope
    if scope.get("type") not in {"declared_closed_world", "externally_bridged_world"}:
        scope_errors.append("unknown world scope type")
    required = {
        "type",
        "carrier_type_ref",
        "scope_semantics_version",
        "scope_predicate_ref",
        "scope_commitment",
        "universe_ref",
    }
    if set(scope) != required:
        scope_errors.append("world scope key set mismatch")
    else:
        try:
            carrier = _rooted_from_wire(scope["carrier_type_ref"])
            semantics = _rooted_from_wire(scope["scope_semantics_version"])
            registries.resolve(carrier)
            registries.resolve(semantics)
            scope_expr = Expr.from_wire(
                scope["scope_predicate_ref"], {"carrier": claim.selector.output_type}
            )
            if scope_expr.output_type != BOOLEAN:
                scope_errors.append("scope predicate must be Boolean")
            expected_scope = digest(
                "AuditSpec-WorldScope-1.0",
                {
                    "type": scope["type"],
                    "carrier_type_ref": carrier.to_wire(),
                    "scope_semantics_version": semantics.to_wire(),
                    "scope_predicate_digest": scope_expr.ast_digest,
                    "universe_ref": scope["universe_ref"],
                },
            )
            if scope["scope_commitment"] != expected_scope:
                scope_errors.append("scope commitment mismatch")
            require_digest(scope["scope_commitment"], "scope commitment")
            if scope["type"] == "declared_closed_world":
                require_digest(scope["universe_ref"], "closed-world universe")
            elif scope["universe_ref"] is not None:
                scope_errors.append("bridged world forbids universe_ref")
        except (ValueError, TypeError) as exc:
            scope_errors.append(str(exc))
    if scope_errors:
        return FormationFailure(
            "QUERY_GAP", "WorldScope", tuple(sorted(set(scope_errors)))
        )

    claim_object = registries.resolve(
        claim_ref, expected_schema="AuditSpec-claim-ir-v1"
    )
    if claim_object != claim.to_wire():
        return FormationFailure("QUERY_GAP", "Q", ("claim rooted bytes mismatch",))

    q_trace = tuple(
        {
            "check_id": check_id,
            "outcome": "PASS",
            "witness_digest": digest(
                "AuditSpec-Q-check-v1",
                {"claim": claim_ref.to_wire(), "check": check_id},
            ),
        }
        for check_id in (
            "C-1",
            "C-2",
            "C-4",
            "C-5",
            "C-7",
            "C-8",
            "C-9",
            "expr_totality",
        )
    )
    scope_trace = tuple(
        {
            "check_id": check_id,
            "outcome": "PASS",
            "witness_digest": digest(
                "AuditSpec-WorldScope-check-v1",
                {"claim": claim_ref.to_wire(), "check": check_id},
            ),
        }
        for check_id in ("C-3", "C-6", "SC-1")
    )
    body = {
        "schema": "AuditSpec-scoped-claim-v1",
        "scoped_claim_id": f"scoped:{claim.id}",
        "claim_ref": claim_ref.to_wire(),
        "claim_ir_digest": claim_ref.payload_digest,
        "scope_commitment": scope["scope_commitment"],
        "resolved_universe_ref": scope["universe_ref"],
        "q_check_trace": list(q_trace),
        "world_scope_check_trace": list(scope_trace),
    }
    return ScopedClaim(
        body["scoped_claim_id"],
        claim_ref,
        claim_ref.payload_digest,
        scope["scope_commitment"],
        scope["universe_ref"],
        q_trace,
        scope_trace,
        digest("AuditSpec-scoped-claim-v1", body),
    )


def _validate_temporal_scope(
    value: dict[str, Any], registries: RegistryStore
) -> list[str]:
    errors: list[str] = []
    required = {
        "execution_window",
        "audit_horizon",
        "audit_horizon_commitment",
        "audit_schedule",
        "audit_grace",
        "audit_schedule_commitment",
    }
    if not isinstance(value, dict) or set(value) != required:
        return ["temporal scope key set mismatch"]
    try:
        window = value["execution_window"]
        if not isinstance(window, dict) or set(window) != {"from", "to"}:
            raise ValueError("execution window key mismatch")
        require_instant(window["from"], "execution_window.from")
        require_instant(window["to"], "execution_window.to")
        if window["from"]["rfc3339_utc"] > window["to"]["rfc3339_utc"]:
            raise ValueError("execution window is reversed")
        horizon = value["audit_horizon"]
        if (
            not isinstance(horizon, dict)
            or horizon.get("mode") != "absolute"
            or set(horizon) != {"mode", "policy", "absolute_deadline"}
        ):
            raise ValueError("slice requires the closed absolute audit-horizon variant")
        require_instant(horizon["absolute_deadline"], "audit_horizon.absolute_deadline")
        registries.resolve(_rooted_from_wire(horizon["policy"]))
        if horizon["absolute_deadline"]["rfc3339_utc"] < window["to"]["rfc3339_utc"]:
            raise ValueError("audit horizon ends before the execution window")
        if value["audit_horizon_commitment"] != digest(
            "AuditSpec-audit-horizon-v1", horizon
        ):
            errors.append("audit horizon commitment mismatch")
        schedule = value["audit_schedule"]
        if schedule != {"mode": "on_demand"}:
            raise ValueError("slice requires the on-demand schedule variant")
        grace = value["audit_grace"]
        _validate_duration(grace)
        registries.resolve(_rooted_from_wire(grace["calendar"]))
        if value["audit_schedule_commitment"] != digest(
            "AuditSpec-audit-schedule-v1", {"schedule": schedule, "audit_grace": grace}
        ):
            errors.append("audit schedule commitment mismatch")
    except (ValueError, TypeError) as exc:
        errors.append(str(exc))
    return errors


def _validate_duration(value: Any) -> None:
    keys = {
        "years",
        "months",
        "days",
        "seconds",
        "nanoseconds",
        "calendar",
        "timezone_id",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("duration key set mismatch")
    integers = [
        value[name] for name in ("years", "months", "days", "seconds", "nanoseconds")
    ]
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in integers
    ):
        raise ValueError("duration components must be non-negative integers")
    if (
        value["months"] >= 12
        or value["nanoseconds"] >= 1_000_000_000
        or not any(integers)
    ):
        raise ValueError("duration is not normalized and positive")
    _rooted_from_wire(value["calendar"])
    require_ref(value["timezone_id"], "duration.timezone_id")


def _rooted_from_wire(value: Any) -> RootedRef:
    from .refs import AuthenticatedPackageRef

    if not isinstance(value, dict) or set(value) != {
        "id",
        "payload_digest",
        "registry",
    }:
        raise ValueError("invalid rooted_ref wire object")
    registry = value["registry"]
    if not isinstance(registry, dict) or set(registry) != {
        "id",
        "object_payload_digest",
        "package_root",
    }:
        raise ValueError("invalid rooted_ref registry locator")
    return RootedRef(
        value["id"],
        value["payload_digest"],
        AuthenticatedPackageRef(
            registry["id"], registry["object_payload_digest"], registry["package_root"]
        ),
    )
