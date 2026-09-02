"""Closed normalized oracle record for external executable environments.

The record is an audit oracle input, not an evidence bundle. Evidence regimes
must be derived separately and may expose only a declared projection of it.
Adapters are responsible for deriving every field from official benchmark
state, trajectories, policies, or evaluators without consulting an auditor's
answer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(str(item) for item in (value or ()))


@dataclass(frozen=True)
class MarkerRecord:
    kind: str
    token: str
    sequence: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MarkerRecord":
        return cls(
            kind=str(value["kind"]),
            token=str(value["token"]),
            sequence=int(value["sequence"]),
        )


@dataclass(frozen=True)
class ActionRecord:
    call_id: str
    sequence: int
    tool: str
    native_call_id: str | None = None
    app: str | None = None
    object_ids: tuple[str, ...] = ()
    effectful: bool = False
    registered_gateway: bool = True
    policy_allowed: bool = True
    tool_prohibited: bool = False
    confirmation_required: bool = False
    confirmation_token: str | None = None
    intent_token: str | None = None
    verification_required: bool = False
    verification_token: str | None = None
    policy_version_valid_at_execution: bool = True
    status: str = "succeeded"  # succeeded | failed | rolled_back

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ActionRecord":
        optional_strings = {
            name: (str(value[name]) if value.get(name) is not None else None)
            for name in (
                "native_call_id",
                "app",
                "confirmation_token",
                "intent_token",
                "verification_token",
            )
        }
        return cls(
            call_id=str(value["call_id"]),
            sequence=int(value["sequence"]),
            tool=str(value["tool"]),
            object_ids=_strings(value.get("object_ids")),
            effectful=bool(value.get("effectful", False)),
            registered_gateway=bool(value.get("registered_gateway", True)),
            policy_allowed=bool(value.get("policy_allowed", True)),
            tool_prohibited=bool(value.get("tool_prohibited", False)),
            confirmation_required=bool(value.get("confirmation_required", False)),
            verification_required=bool(value.get("verification_required", False)),
            policy_version_valid_at_execution=bool(
                value.get("policy_version_valid_at_execution", True)
            ),
            status=str(value.get("status", "succeeded")),
            **optional_strings,
        )


@dataclass(frozen=True)
class DurableEffectRecord:
    effect_id: str
    sequence: int
    app: str
    object_id: str
    operation: str
    source_call_id: str | None
    declared_residual: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DurableEffectRecord":
        source = value.get("source_call_id")
        return cls(
            effect_id=str(value["effect_id"]),
            sequence=int(value["sequence"]),
            app=str(value["app"]),
            object_id=str(value["object_id"]),
            operation=str(value["operation"]),
            source_call_id=str(source) if source is not None else None,
            declared_residual=bool(value.get("declared_residual", False)),
        )


@dataclass(frozen=True)
class CitationRecord:
    citation_id: str
    source_app: str
    source_object_id: str | None
    declared_source: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CitationRecord":
        source_object = value.get("source_object_id")
        return cls(
            citation_id=str(value["citation_id"]),
            source_app=str(value["source_app"]),
            source_object_id=str(source_object) if source_object is not None else None,
            declared_source=bool(value.get("declared_source", False)),
        )


@dataclass(frozen=True)
class CrossAppCopyRecord:
    copy_id: str
    source_subject_id: str
    destination_subject_id: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CrossAppCopyRecord":
        return cls(
            copy_id=str(value["copy_id"]),
            source_subject_id=str(value["source_subject_id"]),
            destination_subject_id=str(value["destination_subject_id"]),
        )


@dataclass(frozen=True)
class OracleCheckRecord:
    """One benchmark-native executable check.

    ``statement`` is display text only.  ``value`` and ``applicable`` must be
    extracted from the pinned benchmark evaluator or from a closed structural
    check over its native trajectory.  They are oracle-side fields and must
    never be copied into a tested evidence projection.
    """

    check_id: str
    statement: str
    source: str
    applicable: bool
    value: bool
    violating_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OracleCheckRecord":
        return cls(
            check_id=str(value["check_id"]),
            statement=str(value["statement"]),
            source=str(value["source"]),
            applicable=bool(value.get("applicable", True)),
            value=bool(value["value"]),
            violating_ids=_strings(value.get("violating_ids")),
            metadata=dict(value.get("metadata", {})),
        )


@dataclass(frozen=True)
class NormalizedRunRecord:
    schema: str
    environment: str
    run_id: str
    task_id: str
    policy_version: str
    actions: tuple[ActionRecord, ...] = ()
    effects: tuple[DurableEffectRecord, ...] = ()
    markers: tuple[MarkerRecord, ...] = ()
    allowed_apps: frozenset[str] = frozenset()
    authorized_object_ids: frozenset[str] = frozenset()
    requested_object_ids: frozenset[str] = frozenset()
    claimed_effect_ids: frozenset[str] = frozenset()
    collateral_effect_ids: frozenset[str] = frozenset()
    cancellation_sequences: tuple[int, ...] = ()
    final_success_claim: bool | None = None
    official_task_success: bool = False
    citations: tuple[CitationRecord, ...] = ()
    cross_app_copies: tuple[CrossAppCopyRecord, ...] = ()
    oracle_checks: tuple[OracleCheckRecord, ...] = ()
    adapter_metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "NormalizedRunRecord":
        final_claim = value.get("final_success_claim")
        record = cls(
            schema=str(value.get("schema", "AuditSpec-external-run-record-v1")),
            environment=str(value["environment"]),
            run_id=str(value["run_id"]),
            task_id=str(value["task_id"]),
            policy_version=str(value["policy_version"]),
            actions=tuple(ActionRecord.from_mapping(item) for item in value.get("actions", ())),
            effects=tuple(
                DurableEffectRecord.from_mapping(item) for item in value.get("effects", ())
            ),
            markers=tuple(MarkerRecord.from_mapping(item) for item in value.get("markers", ())),
            allowed_apps=frozenset(_strings(value.get("allowed_apps"))),
            authorized_object_ids=frozenset(
                _strings(value.get("authorized_object_ids"))
            ),
            requested_object_ids=frozenset(_strings(value.get("requested_object_ids"))),
            claimed_effect_ids=frozenset(_strings(value.get("claimed_effect_ids"))),
            collateral_effect_ids=frozenset(
                _strings(value.get("collateral_effect_ids"))
            ),
            cancellation_sequences=tuple(
                int(item) for item in value.get("cancellation_sequences", ())
            ),
            final_success_claim=(bool(final_claim) if final_claim is not None else None),
            official_task_success=bool(value.get("official_task_success", False)),
            citations=tuple(
                CitationRecord.from_mapping(item) for item in value.get("citations", ())
            ),
            cross_app_copies=tuple(
                CrossAppCopyRecord.from_mapping(item)
                for item in value.get("cross_app_copies", ())
            ),
            oracle_checks=tuple(
                OracleCheckRecord.from_mapping(item)
                for item in value.get("oracle_checks", ())
            ),
            adapter_metadata=dict(value.get("adapter_metadata", {})),
        )
        record.validate()
        return record

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for name in (
            "allowed_apps",
            "authorized_object_ids",
            "requested_object_ids",
            "claimed_effect_ids",
            "collateral_effect_ids",
        ):
            value[name] = sorted(value[name])
        return value

    def validate(self) -> None:
        if self.schema != "AuditSpec-external-run-record-v1":
            raise ValueError(f"unsupported external run schema: {self.schema}")
        if self.environment not in {"tau2", "appworld"}:
            raise ValueError(f"unsupported external environment: {self.environment}")
        action_ids = [action.call_id for action in self.actions]
        effect_ids = [effect.effect_id for effect in self.effects]
        check_ids = [check.check_id for check in self.oracle_checks]
        if len(set(action_ids)) != len(action_ids):
            raise ValueError("action call_id values must be unique")
        if len(set(effect_ids)) != len(effect_ids):
            raise ValueError("effect_id values must be unique")
        if len(set(check_ids)) != len(check_ids):
            raise ValueError("oracle check_id values must be unique")
        if any(action.sequence < 0 for action in self.actions):
            raise ValueError("action sequences must be non-negative")
        if any(effect.sequence < 0 for effect in self.effects):
            raise ValueError("effect sequences must be non-negative")
        if any(marker.sequence < 0 for marker in self.markers):
            raise ValueError("marker sequences must be non-negative")
        known_actions = set(action_ids)
        unknown_sources = {
            effect.source_call_id
            for effect in self.effects
            if effect.source_call_id is not None
            and effect.source_call_id not in known_actions
        }
        if unknown_sources:
            raise ValueError(f"effects reference unknown actions: {sorted(unknown_sources)}")
        if any(
            action.status not in {"succeeded", "failed", "rolled_back"}
            for action in self.actions
        ):
            raise ValueError("unsupported action status")

    def action_by_id(self) -> dict[str, ActionRecord]:
        return {action.call_id: action for action in self.actions}

    def oracle_check_by_id(self) -> dict[str, OracleCheckRecord]:
        return {check.check_id: check for check in self.oracle_checks}

    def marker_precedes(self, *, kind: str, token: str | None, sequence: int) -> bool:
        if token is None:
            return False
        return any(
            marker.kind == kind
            and marker.token == token
            and marker.sequence < sequence
            for marker in self.markers
        )
