"""Small independent state model for Evidence Vault composition tests.

This module deliberately imports no AuditSpec implementation code.  It models
only the public semantic state needed by the composition-correctness campaign;
cryptographic encoding, filesystem durability, and journal parsing remain
properties of the system under test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Mapping


class ModelError(ValueError):
    """An operation is outside the reference model's valid transition relation."""


@dataclass(frozen=True)
class Component:
    reference: str
    kind: str
    object_sha256: str
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    claim_id: str
    run_id: str
    object_sha256: str
    schema_ref: str
    key_ref: str
    verifier_ref: str
    policy_ref: str
    bridge_ref: str | None
    captured_at: str
    minimum_retain_until: str
    deletion_required_by: str


@dataclass
class Hold:
    evidence_ids: frozenset[str]
    released: bool = False


@dataclass(frozen=True)
class DeletionIntent:
    evidence_id: str
    deletion_basis: str
    object_sha256: str
    physical_delete_required: bool
    retained_by_evidence_ids: tuple[str, ...]
    retained_by_component_refs: tuple[str, ...]


@dataclass
class VaultStateModel:
    """Executable transition system independent from EvidenceVault internals."""

    objects: dict[str, bytes] = field(default_factory=dict)
    components: dict[str, Component] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)
    bundles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    holds: dict[str, Hold] = field(default_factory=dict)
    pending_deletions: dict[str, DeletionIntent] = field(default_factory=dict)
    deletions: dict[str, str] = field(default_factory=dict)

    @property
    def keys(self) -> dict[str, Component]:
        return {
            reference: component
            for reference, component in self.components.items()
            if component.kind == "key"
        }

    @property
    def dependencies(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for evidence_id, record in self.evidence.items():
            refs = [
                record.schema_ref,
                record.key_ref,
                record.verifier_ref,
                record.policy_ref,
            ]
            if record.bridge_ref is not None:
                refs.append(record.bridge_ref)
            result[evidence_id] = tuple(refs)
        return result

    def archive_component(
        self,
        *,
        reference: str,
        kind: str,
        content: bytes,
        metadata: Mapping[str, Any],
    ) -> None:
        if reference in self.components:
            raise ModelError("component reference already exists")
        object_sha = self._put_object(content)
        self.components[reference] = Component(
            reference=reference,
            kind=kind,
            object_sha256=object_sha,
            metadata=dict(metadata),
        )

    def append_evidence(
        self,
        *,
        evidence_id: str,
        claim_id: str,
        run_id: str,
        content: bytes,
        schema_ref: str,
        key_ref: str,
        verifier_ref: str,
        policy_ref: str,
        bridge_ref: str | None,
        captured_at: str,
        minimum_retain_until: str,
        deletion_required_by: str,
    ) -> None:
        if evidence_id in self.evidence:
            raise ModelError("evidence id already exists")
        required = {
            schema_ref: "schema",
            key_ref: "key",
            verifier_ref: "verifier",
            policy_ref: "policy",
        }
        if bridge_ref is not None:
            required[bridge_ref] = "bridge"
        for reference, kind in required.items():
            component = self.components.get(reference)
            if component is None or component.kind != kind:
                raise ModelError("evidence dependency is unresolved or has the wrong kind")
        if not (
            _instant(captured_at)
            <= _instant(minimum_retain_until)
            <= _instant(deletion_required_by)
        ):
            raise ModelError("evidence retention interval is invalid")
        self.evidence[evidence_id] = Evidence(
            evidence_id=evidence_id,
            claim_id=claim_id,
            run_id=run_id,
            object_sha256=self._put_object(content),
            schema_ref=schema_ref,
            key_ref=key_ref,
            verifier_ref=verifier_ref,
            policy_ref=policy_ref,
            bridge_ref=bridge_ref,
            captured_at=captured_at,
            minimum_retain_until=minimum_retain_until,
            deletion_required_by=deletion_required_by,
        )

    def seal_bundle(self, *, bundle_id: str, evidence_ids: tuple[str, ...]) -> None:
        if bundle_id in self.bundles:
            raise ModelError("bundle id already exists")
        if not evidence_ids or len(set(evidence_ids)) != len(evidence_ids):
            raise ModelError("bundle evidence ids must be non-empty and unique")
        if any(
            evidence_id not in self.evidence
            or evidence_id in self.deletions
            or evidence_id in self.pending_deletions
            for evidence_id in evidence_ids
        ):
            raise ModelError("bundle references unavailable evidence")
        self.bundles[bundle_id] = tuple(sorted(evidence_ids))

    def place_hold(self, *, hold_id: str, evidence_ids: tuple[str, ...]) -> None:
        if hold_id in self.holds:
            raise ModelError("legal hold id already exists")
        if not evidence_ids or len(set(evidence_ids)) != len(evidence_ids):
            raise ModelError("legal hold evidence ids must be non-empty and unique")
        if any(
            evidence_id not in self.evidence
            or evidence_id in self.deletions
            or evidence_id in self.pending_deletions
            for evidence_id in evidence_ids
        ):
            raise ModelError("legal hold references unavailable evidence")
        self.holds[hold_id] = Hold(frozenset(evidence_ids))

    def release_hold(self, *, hold_id: str) -> None:
        hold = self.holds.get(hold_id)
        if hold is None or hold.released:
            raise ModelError("legal hold is absent or already released")
        hold.released = True

    def retention_status(self, evidence_id: str, *, evaluated_at: str) -> str:
        record = self.evidence.get(evidence_id)
        if record is None:
            raise ModelError("evidence id is unknown")
        if evidence_id in self.deletions:
            return "DELETED"
        if evidence_id in self.pending_deletions:
            return "DELETION_IN_PROGRESS"
        if any(
            not hold.released and evidence_id in hold.evidence_ids
            for hold in self.holds.values()
        ):
            return "LEGAL_HOLD"
        at = _instant(evaluated_at)
        if at < _instant(record.minimum_retain_until):
            return "RETAIN_REQUIRED"
        if at >= _instant(record.deletion_required_by):
            return "DELETION_REQUIRED"
        return "DELETION_ELIGIBLE"

    def object_references(
        self, object_sha256: str, *, excluding_evidence_id: str | None = None
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        evidence_ids = tuple(
            sorted(
                evidence_id
                for evidence_id, record in self.evidence.items()
                if evidence_id != excluding_evidence_id
                and evidence_id not in self.deletions
                and evidence_id not in self.pending_deletions
                and record.object_sha256 == object_sha256
            )
        )
        component_refs = tuple(
            sorted(
                reference
                for reference, component in self.components.items()
                if component.object_sha256 == object_sha256
            )
        )
        return evidence_ids, component_refs

    def begin_delete(
        self, *, evidence_id: str, deleted_at: str, deletion_basis: str
    ) -> DeletionIntent:
        expected = {
            "permitted_disposal": "DELETION_ELIGIBLE",
            "policy_deadline": "DELETION_REQUIRED",
        }
        if deletion_basis not in expected:
            raise ModelError("deletion basis is invalid")
        if self.retention_status(evidence_id, evaluated_at=deleted_at) != expected[
            deletion_basis
        ]:
            raise ModelError("retention or legal hold prevents deletion")
        record = self.evidence[evidence_id]
        evidence_refs, component_refs = self.object_references(
            record.object_sha256, excluding_evidence_id=evidence_id
        )
        intent = DeletionIntent(
            evidence_id=evidence_id,
            deletion_basis=deletion_basis,
            object_sha256=record.object_sha256,
            physical_delete_required=not evidence_refs and not component_refs,
            retained_by_evidence_ids=evidence_refs,
            retained_by_component_refs=component_refs,
        )
        self.pending_deletions[evidence_id] = intent
        return intent

    def apply_pending_physical_transition(self, evidence_id: str) -> None:
        intent = self.pending_deletions[evidence_id]
        evidence_refs, component_refs = self.object_references(
            intent.object_sha256, excluding_evidence_id=evidence_id
        )
        if intent.physical_delete_required and (evidence_refs or component_refs):
            raise ModelError("pending deletion conflicts with live object references")
        if intent.physical_delete_required:
            self.objects.pop(intent.object_sha256, None)

    def recover(self) -> None:
        for evidence_id in sorted(tuple(self.pending_deletions)):
            intent = self.pending_deletions[evidence_id]
            self.apply_pending_physical_transition(evidence_id)
            self.deletions[evidence_id] = intent.deletion_basis
            del self.pending_deletions[evidence_id]
        self.collect_unreferenced_objects()

    def delete(self, *, evidence_id: str, deleted_at: str, deletion_basis: str) -> DeletionIntent:
        intent = self.begin_delete(
            evidence_id=evidence_id,
            deleted_at=deleted_at,
            deletion_basis=deletion_basis,
        )
        self.recover()
        return intent

    def collect_unreferenced_objects(self) -> None:
        for object_sha in tuple(self.objects):
            evidence_refs, component_refs = self.object_references(object_sha)
            if not evidence_refs and not component_refs:
                del self.objects[object_sha]

    def retrieve(self, *, bundle_id: str, audited_at: str) -> dict[str, Any]:
        evidence_ids = self.bundles.get(bundle_id)
        if evidence_ids is None:
            raise ModelError("bundle id is unknown")
        gaps: list[tuple[str, str]] = []
        retrieved: list[str] = []
        for evidence_id in evidence_ids:
            record = self.evidence[evidence_id]
            if evidence_id in self.deletions:
                subtype = (
                    "LEGAL_DELETION_PREVENTS_REVERIFY"
                    if self.deletions[evidence_id] == "policy_deadline"
                    else "EVIDENCE_UNAVAILABLE"
                )
                gaps.append((subtype, evidence_id))
                continue
            if evidence_id in self.pending_deletions:
                gaps.append(("DELETION_TRANSITION_INCOMPLETE", evidence_id))
                continue
            data = self.objects.get(record.object_sha256)
            if data is None:
                gaps.append(("RETENTION_NONCOMPLIANCE", evidence_id))
                continue
            if _digest(data) != record.object_sha256:
                gaps.append(("EVIDENCE_INTEGRITY_FAILURE", evidence_id))
                continue
            if self.retention_status(evidence_id, evaluated_at=audited_at) == (
                "DELETION_REQUIRED"
            ):
                gaps.append(("RETENTION_NONCOMPLIANCE", evidence_id))
            gaps.extend(self._dependency_gaps(record, audited_at=audited_at))
            retrieved.append(evidence_id)
        ordered = _ordered_gaps(gaps)
        return {
            "status": "READY_FOR_REVERIFICATION" if not ordered else "LIFECYCLE_GAP",
            "primary_failure": ordered[0] if ordered else None,
            "additional_detected_failures": ordered[1:],
            "retrieved_evidence_ids": tuple(sorted(retrieved)),
        }

    def invariant_violations(self) -> tuple[str, ...]:
        violations: list[str] = []
        for reference, component in self.components.items():
            if component.object_sha256 not in self.objects:
                violations.append(f"component object absent: {reference}")
        for evidence_id, record in self.evidence.items():
            if (
                evidence_id not in self.deletions
                and evidence_id not in self.pending_deletions
                and record.object_sha256 not in self.objects
            ):
                violations.append(f"live evidence object absent: {evidence_id}")
            for reference in self.dependencies[evidence_id]:
                if reference not in self.components:
                    violations.append(f"dependency absent: {evidence_id}:{reference}")
        for bundle_id, evidence_ids in self.bundles.items():
            if any(evidence_id not in self.evidence for evidence_id in evidence_ids):
                violations.append(f"bundle binding absent: {bundle_id}")
        for hold_id, hold in self.holds.items():
            if not hold.released and any(
                evidence_id in self.deletions or evidence_id in self.pending_deletions
                for evidence_id in hold.evidence_ids
            ):
                violations.append(f"active hold covers deletion: {hold_id}")
        return tuple(sorted(violations))

    def _dependency_gaps(
        self, record: Evidence, *, audited_at: str
    ) -> list[tuple[str, str]]:
        gaps: list[tuple[str, str]] = []
        for reference, subtype in (
            (record.schema_ref, "UNREADABLE_SCHEMA"),
            (record.key_ref, "HISTORIC_KEY_UNRESOLVED"),
            (record.verifier_ref, "VERIFIER_UNAVAILABLE"),
            (record.policy_ref, "VERSION_ROOT_UNRESOLVED"),
        ):
            component = self.components.get(reference)
            if component is None or component.object_sha256 not in self.objects:
                gaps.append((subtype, record.evidence_id))
                continue
            metadata = component.metadata
            if component.kind == "schema" and (
                metadata.get("readable") is not True
                or metadata.get("migration_mode") == "lossy"
            ):
                gaps.append(
                    (
                        "LOSSY_SCHEMA_MIGRATION"
                        if metadata.get("migration_mode") == "lossy"
                        else subtype,
                        record.evidence_id,
                    )
                )
            elif component.kind == "key" and not _historic_key_valid(
                metadata, captured_at=record.captured_at
            ):
                gaps.append((subtype, record.evidence_id))
            elif component.kind == "verifier" and (
                metadata.get("archive_executable") is not True
            ):
                gaps.append((subtype, record.evidence_id))
        if record.bridge_ref is not None:
            bridge = self.components.get(record.bridge_ref)
            if bridge is None or bridge.object_sha256 not in self.objects:
                gaps.append(("BRIDGE_UNRESOLVED", record.evidence_id))
            elif not _bridge_valid(bridge.metadata, audited_at=audited_at):
                gaps.append(("BRIDGE_EXPIRED_OR_REVOKED", record.evidence_id))
        return gaps

    def _put_object(self, content: bytes) -> str:
        object_sha = _digest(content)
        existing = self.objects.get(object_sha)
        if existing is not None and existing != content:
            raise ModelError("content-address collision")
        self.objects[object_sha] = content
        return object_sha


def _digest(content: bytes) -> str:
    return sha256(content).hexdigest()


def _instant(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ModelError("timestamp is not RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ModelError("timestamp is not UTC")
    return parsed


def _historic_key_valid(metadata: Mapping[str, Any], *, captured_at: str) -> bool:
    required = {
        "valid_from",
        "valid_until",
        "revoked_at",
        "revocation_kind",
        "compromise_effective_from",
    }
    if set(metadata) != required:
        return False
    captured = _instant(captured_at)
    if captured < _instant(metadata["valid_from"]):
        return False
    if metadata["valid_until"] is not None and captured > _instant(
        metadata["valid_until"]
    ):
        return False
    kind = metadata["revocation_kind"]
    revoked_at = metadata["revoked_at"]
    if kind is None:
        return revoked_at is None and metadata["compromise_effective_from"] is None
    if revoked_at is None:
        return False
    revoked = _instant(revoked_at)
    if kind == "routine":
        return metadata["compromise_effective_from"] is None and captured < revoked
    if kind == "retroactive_compromise":
        effective = metadata["compromise_effective_from"]
        return (
            effective is not None
            and _instant(effective) <= revoked
            and captured < _instant(effective)
        )
    return False


def _bridge_valid(metadata: Mapping[str, Any], *, audited_at: str) -> bool:
    if set(metadata) != {"valid_from", "valid_until", "revoked_at", "mode"}:
        return False
    if metadata["mode"] not in {"complete_mediation", "external_inventory"}:
        return False
    audited = _instant(audited_at)
    if audited < _instant(metadata["valid_from"]):
        return False
    if metadata["valid_until"] is not None and audited > _instant(
        metadata["valid_until"]
    ):
        return False
    return metadata["revoked_at"] is None or audited < _instant(metadata["revoked_at"])


def _ordered_gaps(gaps: list[tuple[str, str]]) -> list[dict[str, str]]:
    priority = {
        "EVIDENCE_INTEGRITY_FAILURE": 0,
        "HISTORIC_KEY_UNRESOLVED": 1,
        "UNREADABLE_SCHEMA": 2,
        "LOSSY_SCHEMA_MIGRATION": 3,
        "VERIFIER_UNAVAILABLE": 4,
        "VERSION_ROOT_UNRESOLVED": 5,
        "BRIDGE_UNRESOLVED": 6,
        "BRIDGE_EXPIRED_OR_REVOKED": 7,
        "RETENTION_NONCOMPLIANCE": 8,
        "LEGAL_DELETION_PREVENTS_REVERIFY": 9,
        "EVIDENCE_UNAVAILABLE": 10,
        "DELETION_TRANSITION_INCOMPLETE": 11,
    }
    unique = set(gaps)
    return [
        {"subtype": subtype, "evidence_id": evidence_id}
        for subtype, evidence_id in sorted(
            unique, key=lambda row: (priority.get(row[0], 99), row[1], row[0])
        )
    ]
