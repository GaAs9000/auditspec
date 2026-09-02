"""Standalone, append-only Evidence Vault for audit-time re-verification.

The vault is deliberately independent from a runtime adapter.  It stores opaque
evidence bytes in a content-addressed object store and records every semantic
operation in a signed, hash-chained journal.  The read path needs only the vault
public key; the signing key is never persisted by this module.
"""

from __future__ import annotations

import fcntl
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes, canonical_json, digest, raw_sha256, strict_json_loads
from .information_order import InformationOrderError, verify_migration_bundle
from .predicate import evaluate_predicate


VAULT_SCHEMA = "AuditSpec-evidence-vault-v1"
EVENT_SCHEMA = "AuditSpec-evidence-vault-event-v1"
OBJECT_SCHEMA = "AuditSpec-evidence-vault-object-ref-v1"
COMPONENT_SCHEMA = "AuditSpec-evidence-vault-component-v1"
EVIDENCE_SCHEMA = "AuditSpec-evidence-vault-evidence-record-v1"
BUNDLE_SCHEMA = "AuditSpec-evidence-vault-bundle-v1"
RETRIEVAL_SCHEMA = "AuditSpec-evidence-vault-audit-retrieval-v1"
REVERIFY_SCHEMA = "AuditSpec-evidence-vault-reverification-v1"
DELETION_INTENT_SCHEMA_V1 = "AuditSpec-evidence-vault-deletion-intent-v1"
DELETION_INTENT_SCHEMA_V2 = "AuditSpec-evidence-vault-deletion-intent-v2"
DELETION_INTENT_SCHEMA_V3 = "AuditSpec-evidence-vault-deletion-intent-v3"
DELETION_TOMBSTONE_SCHEMA_V1 = "AuditSpec-evidence-vault-deletion-tombstone-v1"
DELETION_TOMBSTONE_SCHEMA_V2 = "AuditSpec-evidence-vault-deletion-tombstone-v2"
DELETION_TOMBSTONE_SCHEMA_V3 = "AuditSpec-evidence-vault-deletion-tombstone-v3"
JOURNAL_AUTHORITY_ROTATION_SCHEMA = (
    "AuditSpec-evidence-vault-journal-authority-rotation-v1"
)
LEGAL_HOLD_SCHEMA_V2 = "AuditSpec-evidence-vault-legal-hold-v2"
LEGAL_HOLD_RELEASE_SCHEMA_V2 = "AuditSpec-evidence-vault-legal-hold-release-v2"
RETIREMENT_SCHEMA_V2 = "AuditSpec-evidence-vault-retirement-certificate-v2"
AUTHORITY_ATTRIBUTION_SEMANTICS = (
    "attribution_metadata_asserted_by_vault_authority"
)

COMPONENT_KINDS = {"bridge", "key", "policy", "schema", "verifier"}
WORLD_SCOPES = {"declared_closed_world", "externally_bridged_world"}
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}\Z")


class EvidenceVaultError(ValueError):
    """A vault command, journal entry, or archived object is invalid."""


@dataclass(frozen=True)
class VaultTrustPins:
    """Caller-owned expectations used to authenticate a Vault directory.

    A vault id is descriptive, not cryptographic. At least one digest or key
    expectation is therefore required whenever any external expectation is
    supplied.
    """

    expected_vault_id: str | None = None
    expected_manifest_root: str | None = None
    expected_public_key_hex: str | None = None
    expected_vault_root: str | None = None

    def __post_init__(self) -> None:
        if self.expected_vault_id is not None:
            _identifier(self.expected_vault_id, "expected_vault_id")
        for value, label in (
            (self.expected_manifest_root, "expected_manifest_root"),
            (self.expected_vault_root, "expected_vault_root"),
        ):
            if value is not None:
                _sha256(value, label)
        if self.expected_public_key_hex is not None:
            _public_key(self.expected_public_key_hex, "expected_public_key_hex")
        if self.expected_vault_id is not None and not self.has_cryptographic_pin:
            raise EvidenceVaultError(
                "expected_vault_id requires a manifest, public-key, or vault-root pin"
            )

    @property
    def has_cryptographic_pin(self) -> bool:
        return any(
            value is not None
            for value in (
                self.expected_manifest_root,
                self.expected_public_key_hex,
                self.expected_vault_root,
            )
        )

    @property
    def names(self) -> list[str]:
        return [
            name
            for name, value in (
                ("vault_id", self.expected_vault_id),
                ("manifest_root", self.expected_manifest_root),
                ("public_key", self.expected_public_key_hex),
                ("vault_root", self.expected_vault_root),
            )
            if value is not None
        ]

    @property
    def authentication_status(self) -> str:
        if self.expected_vault_root is not None or self.expected_manifest_root is not None:
            return "EXTERNALLY_AUTHENTICATED"
        if self.expected_public_key_hex is not None:
            return "AUTHORITY_PINNED"
        return "SELF_CONSISTENT"

    @property
    def authentication_scope(self) -> str:
        if self.expected_vault_root is not None:
            return "SNAPSHOT"
        if self.expected_manifest_root is not None:
            return "GENESIS"
        if self.expected_public_key_hex is not None:
            return "SIGNING_AUTHORITY"
        return "INTERNAL_ONLY"


def _locked_mutation(method: Any) -> Any:
    """Serialize one complete state-dependent Vault mutation."""

    @wraps(method)
    def wrapped(self: "EvidenceVault", *args: Any, **kwargs: Any) -> Any:
        if self.signer is None:
            raise EvidenceVaultError("read-only vault cannot mutate")
        with self._locked():
            self._recover_locked()
            return method(self, *args, **kwargs)

    return wrapped


@dataclass(frozen=True)
class VaultSigner:
    """In-memory Ed25519 signer; private key bytes are never written by the vault."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "VaultSigner":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_hex(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()

    def sign(self, event_root: str) -> str:
        return self.private_key.sign(_signature_message(event_root)).hex()


@dataclass(frozen=True)
class AuditRetrieval:
    record: dict[str, Any]
    evidence_bytes: dict[str, bytes]


class EvidenceVault:
    """Signed append-only evidence archive with deterministic state replay."""

    def __init__(
        self,
        root: str | Path,
        *,
        signer: VaultSigner | None = None,
        expected_vault_id: str | None = None,
        expected_manifest_root: str | None = None,
        expected_public_key_hex: str | None = None,
        expected_vault_root: str | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.signer = signer
        self._trust_pins = VaultTrustPins(
            expected_vault_id=expected_vault_id,
            expected_manifest_root=expected_manifest_root,
            expected_public_key_hex=expected_public_key_hex,
            expected_vault_root=expected_vault_root,
        )
        self._manifest = self._load_manifest()
        self._verify_manifest_pins()
        if signer is not None:
            with self._locked():
                state = self.replay()
                self._verify_vault_root_pin(state)
                if signer.public_key_hex != state["journal_authority"][
                    "active_public_key_hex"
                ]:
                    raise EvidenceVaultError(
                        "vault signer does not match active journal authority"
                    )
                self._recover_locked()
        elif self._trust_pins.has_cryptographic_pin:
            self._verify_vault_root_pin(self.replay())

    @classmethod
    def create(
        cls,
        root: str | Path,
        *,
        vault_id: str,
        created_at: str,
        signer: VaultSigner,
    ) -> "EvidenceVault":
        _identifier(vault_id, "vault_id")
        _instant(created_at)
        target = Path(root).resolve()
        if target.exists() and any(target.iterdir()):
            raise EvidenceVaultError("vault root already exists and is not empty")
        target.mkdir(parents=True, exist_ok=True)
        for relative in ("events", "objects/sha256", "tmp"):
            (target / relative).mkdir(parents=True, exist_ok=False)
        manifest_body = {
            "schema": VAULT_SCHEMA,
            "vault_id": vault_id,
            "created_at": created_at,
            "hash_algorithm": "sha256",
            "signature_algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex,
            "event_schema": EVENT_SCHEMA,
            "object_addressing": "sha256_raw_bytes",
            "private_key_persisted": False,
        }
        manifest = {
            **manifest_body,
            "manifest_root": digest(VAULT_SCHEMA, manifest_body),
        }
        _exclusive_write(target / "vault.json", _json_bytes(manifest))
        _exclusive_write(target / ".lock", b"")
        return cls(target, signer=signer)

    @classmethod
    def open_read_only(
        cls,
        root: str | Path,
        *,
        expected_vault_id: str | None = None,
        expected_manifest_root: str | None = None,
        expected_public_key_hex: str | None = None,
        expected_vault_root: str | None = None,
    ) -> "EvidenceVault":
        return cls(
            root,
            signer=None,
            expected_vault_id=expected_vault_id,
            expected_manifest_root=expected_manifest_root,
            expected_public_key_hex=expected_public_key_hex,
            expected_vault_root=expected_vault_root,
        )

    @property
    def vault_id(self) -> str:
        return str(self._manifest["vault_id"])

    @property
    def manifest_root(self) -> str:
        return str(self._manifest["manifest_root"])

    @property
    def initial_public_key_hex(self) -> str:
        return str(self._manifest["public_key_hex"])

    def assurance(self, state: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return the exact trust level established by this open operation."""

        current = self.replay() if state is None else state
        self._verify_vault_root_pin(current)
        return {
            "schema": "AuditSpec-evidence-vault-assurance-v1",
            "status": self._trust_pins.authentication_status,
            "authentication_scope": self._trust_pins.authentication_scope,
            "rollback_protection": (
                self._trust_pins.expected_vault_root is not None
            ),
            "integrity_status": "VALID",
            "external_pin_names": self._trust_pins.names,
            "vault_id": self.vault_id,
            "manifest_root": self.manifest_root,
            "vault_root": current["vault_root"],
            "initial_public_key_hex": self.initial_public_key_hex,
            "active_public_key_hex": current["journal_authority"][
                "active_public_key_hex"
            ],
            "journal_authority_rotation_count": current["journal_authority"][
                "rotation_count"
            ],
            "time_assurance": "DECLARED_BY_VAULT_AUTHORITY",
        }

    @_locked_mutation
    def rotate_journal_authority(
        self,
        *,
        successor_public_key_hex: str,
        reason_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        """Authorize the key that signs every event after this rotation event."""

        successor = _public_key(
            successor_public_key_hex, "successor_public_key_hex"
        )
        _sha256(reason_digest, "reason_digest")
        _instant(recorded_at)
        state = self.replay()
        authority = state["journal_authority"]
        if successor in authority["public_key_history"]:
            raise EvidenceVaultError("journal authority key was already used")
        body = {
            "schema": JOURNAL_AUTHORITY_ROTATION_SCHEMA,
            "predecessor_public_key_hex": authority["active_public_key_hex"],
            "successor_public_key_hex": successor,
            "reason_digest": reason_digest,
        }
        return self._append_event(
            "JOURNAL_AUTHORITY_ROTATED", body, recorded_at=recorded_at
        )

    @_locked_mutation
    def archive_component(
        self,
        *,
        kind: str,
        component_id: str,
        version: str,
        content: bytes,
        media_type: str,
        metadata: Mapping[str, Any],
        recorded_at: str,
    ) -> dict[str, Any]:
        if kind not in COMPONENT_KINDS:
            raise EvidenceVaultError("component kind is invalid")
        _identifier(component_id, "component_id")
        _identifier(version, "component version")
        _instant(recorded_at)
        if not isinstance(content, bytes) or not content:
            raise EvidenceVaultError("component content must be non-empty bytes")
        _media_type(media_type)
        component_ref = f"{kind}:{component_id}:{version}"
        state = self.replay()
        if component_ref in state["components"]:
            raise EvidenceVaultError("component reference already exists")
        object_ref = self._put_object(content, media_type=media_type)
        body = {
            "schema": COMPONENT_SCHEMA,
            "component_ref": component_ref,
            "kind": kind,
            "component_id": component_id,
            "version": version,
            "object_ref": object_ref,
            "metadata": _json_mapping(metadata, "component metadata"),
        }
        return self._append_event("COMPONENT_ARCHIVED", body, recorded_at=recorded_at)

    @_locked_mutation
    def append_evidence(
        self,
        *,
        evidence_id: str,
        claim_id: str,
        run_id: str,
        content: bytes,
        media_type: str,
        schema_ref: str,
        key_ref: str,
        verifier_ref: str,
        policy_ref: str,
        world_scope: Mapping[str, Any],
        captured_at: str,
        minimum_retain_until: str,
        deletion_required_by: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        for value, label in (
            (evidence_id, "evidence_id"),
            (claim_id, "claim_id"),
            (run_id, "run_id"),
        ):
            _identifier(value, label)
        captured = _instant(captured_at)
        minimum = _instant(minimum_retain_until)
        deletion = _instant(deletion_required_by)
        _instant(recorded_at)
        if not captured <= minimum <= deletion:
            raise EvidenceVaultError("evidence retention interval is invalid")
        state = self.replay()
        if evidence_id in state["evidence"]:
            raise EvidenceVaultError("evidence id already exists")
        references = {
            "schema_ref": schema_ref,
            "key_ref": key_ref,
            "verifier_ref": verifier_ref,
            "policy_ref": policy_ref,
        }
        expected_kinds = {
            "schema_ref": "schema",
            "key_ref": "key",
            "verifier_ref": "verifier",
            "policy_ref": "policy",
        }
        for name, reference in references.items():
            component = state["components"].get(reference)
            if (
                component is None
                or component["body"]["kind"] != expected_kinds[name]
            ):
                raise EvidenceVaultError(f"{name} is unresolved or has wrong kind")
            self._require_capture_eligible_component(
                state,
                component_ref=reference,
                claim_id=claim_id,
                field_name=name,
            )
        scope = _world_scope(world_scope, components=state["components"])
        if scope["type"] == "externally_bridged_world":
            self._require_capture_eligible_component(
                state,
                component_ref=scope["bridge_ref"],
                claim_id=claim_id,
                field_name="bridge_ref",
            )
        object_ref = self._put_object(content, media_type=media_type)
        body = {
            "schema": EVIDENCE_SCHEMA,
            "evidence_id": evidence_id,
            "claim_id": claim_id,
            "run_id": run_id,
            "object_ref": object_ref,
            **references,
            "world_scope": scope,
            "captured_at": captured_at,
            "minimum_retain_until": minimum_retain_until,
            "deletion_required_by": deletion_required_by,
        }
        return self._append_event("EVIDENCE_APPENDED", body, recorded_at=recorded_at)

    @_locked_mutation
    def create_bundle(
        self,
        *,
        bundle_id: str,
        evidence_ids: Sequence[str],
        recorded_at: str,
    ) -> dict[str, Any]:
        _identifier(bundle_id, "bundle_id")
        _instant(recorded_at)
        ids = sorted(evidence_ids)
        if not ids or ids != sorted(set(ids)):
            raise EvidenceVaultError("bundle evidence ids must be non-empty and unique")
        state = self.replay()
        if bundle_id in state["bundles"]:
            raise EvidenceVaultError("bundle id already exists")
        rows = []
        for evidence_id in ids:
            record = state["evidence"].get(evidence_id)
            if (
                record is None
                or evidence_id in state["deletions"]
                or evidence_id in state["pending_deletions"]
            ):
                raise EvidenceVaultError("bundle references unknown evidence")
            rows.append(
                {
                    "evidence_id": evidence_id,
                    "evidence_event_root": record["event_root"],
                    "object_ref": record["body"]["object_ref"],
                }
            )
        body = {
            "schema": BUNDLE_SCHEMA,
            "bundle_id": bundle_id,
            "evidence": rows,
            "evidence_count": len(rows),
            "bundle_root": digest(BUNDLE_SCHEMA, rows),
        }
        return self._append_event("BUNDLE_SEALED", body, recorded_at=recorded_at)

    @_locked_mutation
    def place_legal_hold(
        self,
        *,
        hold_id: str,
        evidence_ids: Sequence[str],
        authority_ref: str,
        reason_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        _identifier(hold_id, "hold_id")
        _identifier(authority_ref, "authority_ref")
        _sha256(reason_digest, "reason_digest")
        _instant(recorded_at)
        ids = sorted(evidence_ids)
        state = self.replay()
        if not ids or ids != sorted(set(ids)):
            raise EvidenceVaultError("legal hold evidence ids must be non-empty and unique")
        if hold_id in state["holds"]:
            raise EvidenceVaultError("legal hold id already exists")
        if any(
            item not in state["evidence"]
            or item in state["deletions"]
            or item in state["pending_deletions"]
            for item in ids
        ):
            raise EvidenceVaultError("legal hold references unknown evidence")
        body = {
            "schema": LEGAL_HOLD_SCHEMA_V2,
            "hold_id": hold_id,
            "evidence_ids": ids,
            "authority_ref": authority_ref,
            "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
            "reason_digest": reason_digest,
        }
        return self._append_event("LEGAL_HOLD_PLACED", body, recorded_at=recorded_at)

    @_locked_mutation
    def release_legal_hold(
        self,
        *,
        hold_id: str,
        authority_ref: str,
        release_reason_digest: str,
        recorded_at: str,
    ) -> dict[str, Any]:
        _identifier(authority_ref, "authority_ref")
        _sha256(release_reason_digest, "release_reason_digest")
        _instant(recorded_at)
        state = self.replay()
        hold = state["holds"].get(hold_id)
        if hold is None or hold["released"]:
            raise EvidenceVaultError("legal hold is absent or already released")
        body = {
            "schema": LEGAL_HOLD_RELEASE_SCHEMA_V2,
            "hold_id": hold_id,
            "authority_ref": authority_ref,
            "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
            "release_reason_digest": release_reason_digest,
            "placed_event_root": hold["placed_event_root"],
        }
        return self._append_event("LEGAL_HOLD_RELEASED", body, recorded_at=recorded_at)

    def retention_decision(self, evidence_id: str, *, evaluated_at: str) -> dict[str, Any]:
        state = self.replay()
        return self._retention_decision_from_state(
            state, evidence_id=evidence_id, evaluated_at=evaluated_at
        )

    def _retention_decision_from_state(
        self,
        state: Mapping[str, Any],
        *,
        evidence_id: str,
        evaluated_at: str,
    ) -> dict[str, Any]:
        """Evaluate hold and deadline policy against one replayed state snapshot."""

        at = _instant(evaluated_at)
        record = state["evidence"].get(evidence_id)
        if record is None:
            raise EvidenceVaultError("evidence id is unknown")
        body = record["body"]
        active_holds = sorted(
            hold_id
            for hold_id, hold in state["holds"].items()
            if not hold["released"] and evidence_id in hold["evidence_ids"]
        )
        if evidence_id in state["deletions"]:
            status = "DELETED"
        elif evidence_id in state["pending_deletions"]:
            status = "DELETION_IN_PROGRESS"
        elif active_holds:
            status = "LEGAL_HOLD"
        elif at < _instant(body["minimum_retain_until"]):
            status = "RETAIN_REQUIRED"
        elif at >= _instant(body["deletion_required_by"]):
            status = "DELETION_REQUIRED"
        else:
            status = "DELETION_ELIGIBLE"
        return {
            "schema": "AuditSpec-evidence-vault-retention-decision-v1",
            "evidence_id": evidence_id,
            "evaluated_at": evaluated_at,
            "status": status,
            "active_hold_ids": active_holds,
            "minimum_retain_until": body["minimum_retain_until"],
            "deletion_required_by": body["deletion_required_by"],
        }

    @_locked_mutation
    def delete_evidence(
        self,
        *,
        evidence_id: str,
        deleted_at: str,
        deletion_basis: str,
        authority_ref: str,
    ) -> dict[str, Any]:
        _instant(deleted_at)
        _identifier(authority_ref, "authority_ref")
        if deletion_basis not in {"policy_deadline", "permitted_disposal"}:
            raise EvidenceVaultError("deletion basis is invalid")
        state = self.replay()
        decision = self._retention_decision_from_state(
            state, evidence_id=evidence_id, evaluated_at=deleted_at
        )
        allowed = {
            "policy_deadline": "DELETION_REQUIRED",
            "permitted_disposal": "DELETION_ELIGIBLE",
        }
        if decision["status"] != allowed[deletion_basis]:
            raise EvidenceVaultError("retention or legal hold prevents deletion")
        record = state["evidence"][evidence_id]["body"]
        object_ref = record["object_ref"]
        retained_by = self._object_retention_references_from_state(
            state,
            object_sha256=object_ref["sha256"],
            excluding_evidence_id=evidence_id,
        )
        other_live_refs = retained_by["evidence_ids"]
        component_refs = retained_by["component_refs"]
        physical_delete_required = not other_live_refs and not component_refs
        if physical_delete_required:
            path = self._object_path(object_ref["sha256"])
            if not path.is_file() or path.is_symlink():
                raise EvidenceVaultError("evidence object is already unavailable")
        intent_body = {
            "schema": DELETION_INTENT_SCHEMA_V3,
            "evidence_id": evidence_id,
            "deleted_at": deleted_at,
            "object_sha256": object_ref["sha256"],
            "deletion_basis": deletion_basis,
            "authority_ref": authority_ref,
            "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
            "retention_decision": decision,
            "physical_delete_required": physical_delete_required,
            "retained_by_live_evidence_ids": other_live_refs,
            "retained_by_component_refs": component_refs,
        }
        intent = self._append_event(
            "EVIDENCE_DELETION_INTENT", intent_body, recorded_at=deleted_at
        )
        if physical_delete_required:
            path.unlink()
            _fsync_directory(path.parent)
        body = _deletion_commit_body(intent)
        return self._append_event("EVIDENCE_DELETED", body, recorded_at=deleted_at)

    @_locked_mutation
    def retire_component(
        self,
        *,
        component_ref: str,
        replacement_ref: str | None,
        impacted_claim_ids: Sequence[str],
        future_unsupported_claim_ids: Sequence[str],
        recorded_at: str,
    ) -> dict[str, Any]:
        _instant(recorded_at)
        state = self.replay()
        if component_ref not in state["components"]:
            raise EvidenceVaultError("retired component is unknown")
        if component_ref in state["retirements"]:
            raise EvidenceVaultError("component is already retired")
        if replacement_ref is not None and replacement_ref not in state["components"]:
            raise EvidenceVaultError("replacement component is unknown")
        if replacement_ref == component_ref:
            raise EvidenceVaultError("replacement component must differ")
        if replacement_ref is not None:
            if replacement_ref in state["retirements"]:
                raise EvidenceVaultError("replacement component is retired")
            if (
                state["components"][replacement_ref]["body"]["kind"]
                != state["components"][component_ref]["body"]["kind"]
            ):
                raise EvidenceVaultError("replacement component has wrong kind")
        impacted = sorted(set(impacted_claim_ids))
        unsupported = sorted(set(future_unsupported_claim_ids))
        body = {
            "schema": RETIREMENT_SCHEMA_V2,
            "component_ref": component_ref,
            "replacement_ref": replacement_ref,
            "impacted_claim_ids": impacted,
            "future_unsupported_claim_ids": unsupported,
            "archive_object_ref": state["components"][component_ref]["body"]["object_ref"],
            "existing_contracts_reverify_before_retirement": True,
            "future_capture_policy": "reject_retired_reference",
            "retired_at": recorded_at,
        }
        return self._append_event("COMPONENT_RETIRED", body, recorded_at=recorded_at)

    def retrieve_for_audit(self, bundle_id: str, *, audited_at: str) -> AuditRetrieval:
        _instant(audited_at)
        state = self.replay()
        bundle = state["bundles"].get(bundle_id)
        if bundle is None:
            raise EvidenceVaultError("bundle id is unknown")
        body = bundle["body"]
        expected_root = digest(BUNDLE_SCHEMA, body["evidence"])
        if expected_root != body["bundle_root"]:
            raise EvidenceVaultError("bundle root does not recompute")
        gaps: list[dict[str, str]] = []
        material: dict[str, bytes] = {}
        for row in body["evidence"]:
            evidence_id = row["evidence_id"]
            record = state["evidence"].get(evidence_id)
            if record is None or record["event_root"] != row["evidence_event_root"]:
                raise EvidenceVaultError("bundle evidence binding differs")
            evidence = record["body"]
            deletion = state["deletions"].get(evidence_id)
            if deletion is not None:
                subtype = (
                    "LEGAL_DELETION_PREVENTS_REVERIFY"
                    if deletion["body"]["deletion_basis"] == "policy_deadline"
                    else "EVIDENCE_UNAVAILABLE"
                )
                gaps.append(_gap(subtype, evidence_id))
                continue
            if evidence_id in state["pending_deletions"]:
                gaps.append(_gap("DELETION_TRANSITION_INCOMPLETE", evidence_id))
                continue
            object_path = self._object_path(evidence["object_ref"]["sha256"])
            if not object_path.is_file() or object_path.is_symlink():
                gaps.append(_gap("RETENTION_NONCOMPLIANCE", evidence_id))
                continue
            data = object_path.read_bytes()
            if raw_sha256(data) != evidence["object_ref"]["sha256"]:
                gaps.append(_gap("EVIDENCE_INTEGRITY_FAILURE", evidence_id))
                continue
            retention = self._retention_decision_from_state(
                state, evidence_id=evidence_id, evaluated_at=audited_at
            )
            if retention["status"] == "DELETION_REQUIRED":
                gaps.append(_gap("RETENTION_NONCOMPLIANCE", evidence_id))
            self._check_component_dependencies(
                evidence, state=state, audited_at=audited_at, gaps=gaps
            )
            material[evidence_id] = data
        gaps = _deduplicate_gaps(gaps)
        obstructions = _obstruction_rows(gaps)
        vault_assurance = self.assurance(state)
        record = {
            "schema": RETRIEVAL_SCHEMA,
            "vault_id": self.vault_id,
            "bundle_id": bundle_id,
            "bundle_root": body["bundle_root"],
            "audited_at": audited_at,
            "status": "READY_FOR_REVERIFICATION" if not gaps else "LIFECYCLE_GAP",
            "primary_failure": gaps[0] if gaps else None,
            "additional_detected_failures": gaps[1:],
            "obstructions": obstructions,
            "retrieved_evidence_ids": sorted(material),
            "retrieved_evidence_count": len(material),
            "journal_event_count": state["event_count"],
            "vault_root": state["vault_root"],
            "vault_authentication_status": vault_assurance["status"],
            "vault_authentication_scope": vault_assurance["authentication_scope"],
            "vault_rollback_protection": vault_assurance["rollback_protection"],
            "external_pin_names": vault_assurance["external_pin_names"],
            "remaining_unproven": [
                "capture_truth",
                "open_world_inventory_completeness"
            ],
        }
        record["proof_digest"] = digest(RETRIEVAL_SCHEMA, record)
        return AuditRetrieval(record=record, evidence_bytes=material)

    def reverify_json_predicate(
        self,
        bundle_id: str,
        *,
        claim_id: str,
        audited_at: str,
    ) -> dict[str, Any]:
        retrieval = self.retrieve_for_audit(bundle_id, audited_at=audited_at)
        base = {
            "schema": REVERIFY_SCHEMA,
            "vault_id": self.vault_id,
            "bundle_id": bundle_id,
            "claim_id": claim_id,
            "audited_at": audited_at,
            "retrieval_proof_digest": retrieval.record["proof_digest"],
            "vault_authentication_status": retrieval.record[
                "vault_authentication_status"
            ],
            "vault_authentication_scope": retrieval.record[
                "vault_authentication_scope"
            ],
            "vault_rollback_protection": retrieval.record[
                "vault_rollback_protection"
            ],
            "external_pin_names": retrieval.record["external_pin_names"],
        }
        if retrieval.record["status"] != "READY_FOR_REVERIFICATION":
            body = {
                **base,
                "status": "LIFECYCLE_GAP",
                "verdict": "LIFECYCLE_GAP",
                "claim_value": None,
                "primary_failure": retrieval.record["primary_failure"],
                "additional_detected_failures": retrieval.record[
                    "additional_detected_failures"
                ],
                "obstructions": retrieval.record["obstructions"],
            }
            return {**body, "proof_digest": digest(REVERIFY_SCHEMA, body)}
        state = self.replay()
        evidence_records = [
            state["evidence"][item]["body"]
            for item in retrieval.record["retrieved_evidence_ids"]
            if state["evidence"][item]["body"]["claim_id"] == claim_id
        ]
        if not evidence_records:
            body = {
                **base,
                "status": "INVENTORY_GAP",
                "verdict": "INVENTORY_GAP",
                "claim_value": None,
                "primary_failure": {
                    "subtype": "CLAIM_EVIDENCE_ABSENT",
                    "claim_id": claim_id,
                },
                "additional_detected_failures": [],
                "obstructions": [
                    {
                        "subtype": "CLAIM_EVIDENCE_ABSENT",
                        "claim_id": claim_id,
                        "obstruction_class": "INVENTORY_OBSTRUCTION",
                    }
                ],
            }
            return {**body, "proof_digest": digest(REVERIFY_SCHEMA, body)}
        verifier_refs = {row["verifier_ref"] for row in evidence_records}
        if len(verifier_refs) != 1:
            raise EvidenceVaultError("claim evidence has multiple verifier archives")
        verifier = self._component_content(state, next(iter(verifier_refs)))
        spec = strict_json_loads(verifier.decode("utf-8"))
        if set(spec) != {"schema", "predicate"} or spec["schema"] != (
            "AuditSpec-vault-json-predicate-verifier-v1"
        ):
            raise EvidenceVaultError("archived verifier is not executable json predicate v1")
        values: dict[str, Any] = {}
        for evidence in evidence_records:
            raw = retrieval.evidence_bytes[evidence["evidence_id"]]
            value = strict_json_loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(values) & set(value):
                raise EvidenceVaultError("evidence JSON projection is invalid or ambiguous")
            values.update(value)
        claim_value = bool(evaluate_predicate(spec["predicate"], values))
        body = {
            **base,
            "status": "REVERIFIED_AT_AUDIT_TIME",
            "verdict": "SUPPORTED" if claim_value else "REFUTED",
            "claim_value": claim_value,
            "primary_failure": None,
            "additional_detected_failures": [],
            "obstructions": [],
            "verifier_ref": next(iter(verifier_refs)),
            "evidence_value_root": digest(
                "AuditSpec-evidence-vault-reverified-values-v1", values
            ),
        }
        return {**body, "proof_digest": digest(REVERIFY_SCHEMA, body)}

    def replay(self) -> dict[str, Any]:
        initial_public_key_hex = self.initial_public_key_hex
        active_public_key_hex = initial_public_key_hex
        public_key_history = [initial_public_key_hex]
        rotations: list[dict[str, Any]] = []
        events = []
        previous = None
        for sequence, path in enumerate(sorted((self.root / "events").glob("*.json")), 1):
            expected_name_prefix = f"{sequence:020d}-"
            if not path.name.startswith(expected_name_prefix) or path.is_symlink():
                raise EvidenceVaultError("vault event filename sequence is invalid")
            event = strict_json_loads(path.read_text(encoding="utf-8"))
            public = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(active_public_key_hex)
            )
            _verify_event(
                event,
                public,
                sequence=sequence,
                previous=previous,
                expected_vault_id=self.vault_id,
                expected_public_key_hex=active_public_key_hex,
            )
            if path.name != f"{sequence:020d}-{event['event_root']}.json":
                raise EvidenceVaultError("vault event filename/root mismatch")
            events.append(event)
            previous = event["event_root"]
            if event["event_type"] == "JOURNAL_AUTHORITY_ROTATED":
                successor = _validate_journal_authority_rotation(
                    event["body"],
                    predecessor_public_key_hex=active_public_key_hex,
                    public_key_history=public_key_history,
                )
                rotations.append(
                    {
                        "sequence": sequence,
                        "event_root": event["event_root"],
                        "recorded_at": event["recorded_at"],
                        "predecessor_public_key_hex": active_public_key_hex,
                        "successor_public_key_hex": successor,
                        "reason_digest": event["body"]["reason_digest"],
                    }
                )
                public_key_history.append(successor)
                active_public_key_hex = successor
        state: dict[str, Any] = {
            "components": {},
            "evidence": {},
            "bundles": {},
            "holds": {},
            "deletion_intents": {},
            "deletions": {},
            "retirements": {},
            "event_count": len(events),
            "vault_root": previous or self._manifest["manifest_root"],
            "journal_authority": {
                "initial_public_key_hex": initial_public_key_hex,
                "active_public_key_hex": active_public_key_hex,
                "rotation_count": len(rotations),
                "public_key_history": public_key_history,
                "rotations": rotations,
            },
        }
        for event in events:
            kind = event["event_type"]
            body = event["body"]
            row = {"body": body, "event_root": event["event_root"]}
            if kind == "COMPONENT_ARCHIVED":
                _insert_once(state["components"], body["component_ref"], row)
            elif kind == "EVIDENCE_APPENDED":
                _insert_once(state["evidence"], body["evidence_id"], row)
            elif kind == "BUNDLE_SEALED":
                _insert_once(state["bundles"], body["bundle_id"], row)
            elif kind == "LEGAL_HOLD_PLACED":
                _insert_once(
                    state["holds"],
                    body["hold_id"],
                    {
                        "evidence_ids": body["evidence_ids"],
                        "released": False,
                        "placed_event_root": event["event_root"],
                    },
                )
            elif kind == "LEGAL_HOLD_RELEASED":
                hold = state["holds"].get(body["hold_id"])
                if hold is None or hold["released"]:
                    raise EvidenceVaultError("legal-hold release journal transition is invalid")
                hold["released"] = True
                hold["release_event_root"] = event["event_root"]
            elif kind == "EVIDENCE_DELETION_INTENT":
                evidence_id = body["evidence_id"]
                if (
                    evidence_id not in state["evidence"]
                    or evidence_id in state["deletions"]
                ):
                    raise EvidenceVaultError(
                        "deletion-intent journal transition is invalid"
                    )
                _insert_once(state["deletion_intents"], evidence_id, row)
            elif kind == "EVIDENCE_DELETED":
                evidence_id = body["evidence_id"]
                if evidence_id not in state["evidence"]:
                    raise EvidenceVaultError("deletion journal references unknown evidence")
                intent_root = body.get("intent_event_root")
                if intent_root is not None:
                    intent = state["deletion_intents"].get(evidence_id)
                    if (
                        intent is None
                        or intent["event_root"] != intent_root
                        or body != _deletion_commit_body(intent)
                    ):
                        raise EvidenceVaultError(
                            "deletion commit does not match signed intent"
                        )
                _insert_once(state["deletions"], evidence_id, row)
            elif kind == "COMPONENT_RETIRED":
                if body["component_ref"] not in state["components"]:
                    raise EvidenceVaultError("retirement journal references unknown component")
                _validate_retirement(body, components=state["components"])
                _insert_once(state["retirements"], body["component_ref"], row)
            elif kind == "JOURNAL_AUTHORITY_ROTATED":
                continue
            else:
                raise EvidenceVaultError("vault event type is unknown")
        state["pending_deletions"] = {
            evidence_id: intent
            for evidence_id, intent in state["deletion_intents"].items()
            if evidence_id not in state["deletions"]
        }
        return state

    def _check_component_dependencies(
        self,
        evidence: Mapping[str, Any],
        *,
        state: Mapping[str, Any],
        audited_at: str,
        gaps: list[dict[str, str]],
    ) -> None:
        for field, subtype in (
            ("schema_ref", "UNREADABLE_SCHEMA"),
            ("key_ref", "HISTORIC_KEY_UNRESOLVED"),
            ("verifier_ref", "VERIFIER_UNAVAILABLE"),
            ("policy_ref", "VERSION_ROOT_UNRESOLVED"),
        ):
            component = state["components"].get(evidence[field])
            if component is None or not self._component_object_available(component["body"]):
                gaps.append(_gap(subtype, evidence["evidence_id"]))
                continue
            metadata = component["body"]["metadata"]
            if field == "schema_ref" and metadata.get("readable") is not True:
                gaps.append(_gap(subtype, evidence["evidence_id"]))
            elif field == "schema_ref" and metadata.get("migration_mode") == "lossy":
                bundle = metadata.get("claim_relative_migration")
                if bundle is None:
                    gaps.append(
                        _gap("LOSSY_SCHEMA_MIGRATION", evidence["evidence_id"])
                    )
                else:
                    try:
                        certificate = verify_migration_bundle(
                            bundle, claim_id=evidence["claim_id"]
                        )
                    except (InformationOrderError, KeyError, TypeError, ValueError):
                        gaps.append(
                            _gap(
                                "MIGRATION_CERTIFICATE_INVALID",
                                evidence["evidence_id"],
                            )
                        )
                    else:
                        if certificate["status"] == "HARD_SEMANTIC_GAP":
                            gaps.append(
                                _gap(
                                    "MIGRATION_CLAIM_INFORMATION_LOSS",
                                    evidence["evidence_id"],
                                )
                            )
                        elif certificate["status"] != "PRESERVED":
                            gaps.append(
                                _gap(
                                    "MIGRATION_CERTIFICATE_INVALID",
                                    evidence["evidence_id"],
                                )
                            )
            elif field == "verifier_ref" and metadata.get("archive_executable") is not True:
                gaps.append(_gap(subtype, evidence["evidence_id"]))
            elif field == "key_ref" and not _historic_key_valid(
                metadata, captured_at=evidence["captured_at"]
            ):
                gaps.append(_gap(subtype, evidence["evidence_id"]))
        scope = evidence["world_scope"]
        if scope["type"] == "externally_bridged_world":
            component = state["components"].get(scope["bridge_ref"])
            if component is None or not self._component_object_available(component["body"]):
                gaps.append(_gap("BRIDGE_UNRESOLVED", evidence["evidence_id"]))
            elif not _bridge_valid(component["body"]["metadata"], audited_at=audited_at):
                gaps.append(_gap("BRIDGE_EXPIRED_OR_REVOKED", evidence["evidence_id"]))

    def _component_object_available(self, component: Mapping[str, Any]) -> bool:
        reference = component["object_ref"]
        path = self._object_path(reference["sha256"])
        return (
            path.is_file()
            and not path.is_symlink()
            and raw_sha256(path.read_bytes()) == reference["sha256"]
        )

    def _require_capture_eligible_component(
        self,
        state: Mapping[str, Any],
        *,
        component_ref: str,
        claim_id: str,
        field_name: str,
    ) -> None:
        retirement = state["retirements"].get(component_ref)
        if retirement is None:
            return
        body = retirement["body"]
        replacement = body.get("replacement_ref")
        unsupported = claim_id in body.get("future_unsupported_claim_ids", [])
        detail = "future claim is explicitly unsupported" if unsupported else (
            f"use replacement {replacement}" if replacement is not None else "no replacement"
        )
        raise EvidenceVaultError(
            f"{field_name} references retired component ({detail})"
        )

    def _object_retention_references_from_state(
        self,
        state: Mapping[str, Any],
        *,
        object_sha256: str,
        excluding_evidence_id: str | None = None,
    ) -> dict[str, list[str]]:
        """Return every live component/evidence reference that requires CAS retention."""

        _sha256(object_sha256, "object sha256")
        pending = set(state["pending_deletions"])
        evidence_ids = sorted(
            evidence_id
            for evidence_id, evidence in state["evidence"].items()
            if evidence_id != excluding_evidence_id
            and evidence_id not in state["deletions"]
            and evidence_id not in pending
            and evidence["body"]["object_ref"]["sha256"] == object_sha256
        )
        component_refs = sorted(
            component_ref
            for component_ref, component in state["components"].items()
            if component["body"]["object_ref"]["sha256"] == object_sha256
        )
        return {
            "evidence_ids": evidence_ids,
            "component_refs": component_refs,
        }

    def _component_content(self, state: Mapping[str, Any], component_ref: str) -> bytes:
        component = state["components"].get(component_ref)
        if component is None or not self._component_object_available(component["body"]):
            raise EvidenceVaultError("archived component object is unavailable")
        return self._object_path(component["body"]["object_ref"]["sha256"]).read_bytes()

    def _put_object(self, content: bytes, *, media_type: str) -> dict[str, Any]:
        if self.signer is None:
            raise EvidenceVaultError("read-only vault cannot append objects")
        if not isinstance(content, bytes):
            raise EvidenceVaultError("vault object content must be bytes")
        _media_type(media_type)
        sha256 = raw_sha256(content)
        target = self._object_path(sha256)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.is_symlink() or raw_sha256(target.read_bytes()) != sha256:
                raise EvidenceVaultError("content-addressed object collision or corruption")
        else:
            with tempfile.NamedTemporaryFile(dir=self.root / "tmp", delete=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            try:
                os.link(temporary, target)
                _fsync_directory(target.parent)
            except FileExistsError:
                if raw_sha256(target.read_bytes()) != sha256:
                    raise EvidenceVaultError("content-addressed object race mismatch")
            finally:
                temporary.unlink(missing_ok=True)
        return {
            "schema": OBJECT_SCHEMA,
            "sha256": sha256,
            "size_bytes": len(content),
            "media_type": media_type,
        }

    def _append_event(
        self, event_type: str, body: Mapping[str, Any], *, recorded_at: str
    ) -> dict[str, Any]:
        if self.signer is None:
            raise EvidenceVaultError("read-only vault cannot append events")
        _instant(recorded_at)
        state = self.replay()
        active_public_key_hex = state["journal_authority"]["active_public_key_hex"]
        if self.signer.public_key_hex != active_public_key_hex:
            raise EvidenceVaultError(
                "vault signer does not match active journal authority"
            )
        sequence = state["event_count"] + 1
        payload = {
            "schema": EVENT_SCHEMA,
            "vault_id": self.vault_id,
            "sequence": sequence,
            "previous_event_root": (
                state["vault_root"] if state["event_count"] else None
            ),
            "event_type": event_type,
            "recorded_at": recorded_at,
            "body": _json_mapping(body, "event body"),
        }
        event_root = digest(EVENT_SCHEMA, payload)
        event = {
            **payload,
            "event_root": event_root,
            "signature": {
                "algorithm": "ed25519",
                "public_key_hex": active_public_key_hex,
                "signature_hex": self.signer.sign(event_root),
            },
        }
        path = self.root / "events" / f"{sequence:020d}-{event_root}.json"
        _exclusive_write(path, _json_bytes(event))
        return event

    def _recover_locked(self) -> None:
        """Finish signed deletion intents and remove unreachable crash residue."""

        if self.signer is None:
            return
        state = self.replay()
        for intent in state["pending_deletions"].values():
            body = intent["body"]
            retained_by = self._object_retention_references_from_state(
                state,
                object_sha256=body["object_sha256"],
                excluding_evidence_id=body["evidence_id"],
            )
            if body["physical_delete_required"] and (
                retained_by["evidence_ids"] or retained_by["component_refs"]
            ):
                raise EvidenceVaultError(
                    "pending deletion conflicts with live object references"
                )
            if body["physical_delete_required"]:
                path = self._object_path(body["object_sha256"])
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    metadata = None
                if metadata is not None:
                    if not path.is_file() or path.is_symlink():
                        raise EvidenceVaultError(
                            "pending deletion object path is unsafe"
                        )
                    path.unlink()
                    _fsync_directory(path.parent)
            self._append_event(
                "EVIDENCE_DELETED",
                _deletion_commit_body(intent),
                recorded_at=body["deleted_at"],
            )

        state = self.replay()
        object_root = self.root / "objects" / "sha256"
        for path in sorted(object_root.glob("*/*")):
            if path.is_symlink() or not path.is_file():
                raise EvidenceVaultError("vault object path is unsafe")
            sha256 = f"{path.parent.name}{path.name}"
            retained_by = self._object_retention_references_from_state(
                state, object_sha256=sha256
            )
            if not retained_by["evidence_ids"] and not retained_by["component_refs"]:
                path.unlink()
                _fsync_directory(path.parent)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_path = self.root / ".lock"
        with lock_path.open("rb") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _load_manifest(self) -> dict[str, Any]:
        path = self.root / "vault.json"
        if not path.is_file() or path.is_symlink():
            raise EvidenceVaultError("vault manifest is absent or unsafe")
        manifest = strict_json_loads(path.read_text(encoding="utf-8"))
        expected = {
            "schema",
            "vault_id",
            "created_at",
            "hash_algorithm",
            "signature_algorithm",
            "public_key_hex",
            "event_schema",
            "object_addressing",
            "private_key_persisted",
            "manifest_root",
        }
        if not isinstance(manifest, dict) or set(manifest) != expected:
            raise EvidenceVaultError("vault manifest keys mismatch")
        body = {key: manifest[key] for key in manifest if key != "manifest_root"}
        if (
            manifest["schema"] != VAULT_SCHEMA
            or manifest["hash_algorithm"] != "sha256"
            or manifest["signature_algorithm"] != "ed25519"
            or manifest["event_schema"] != EVENT_SCHEMA
            or manifest["object_addressing"] != "sha256_raw_bytes"
            or manifest["private_key_persisted"] is not False
            or manifest["manifest_root"] != digest(VAULT_SCHEMA, body)
        ):
            raise EvidenceVaultError("vault manifest identity/root mismatch")
        _identifier(manifest["vault_id"], "vault_id")
        _instant(manifest["created_at"])
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key_hex"]))
        except ValueError as exc:
            raise EvidenceVaultError("vault public key is invalid") from exc
        return manifest

    def _verify_manifest_pins(self) -> None:
        expected = self._trust_pins
        for actual, pinned, label in (
            (self.vault_id, expected.expected_vault_id, "vault id"),
            (self.manifest_root, expected.expected_manifest_root, "manifest root"),
            (
                self.initial_public_key_hex,
                expected.expected_public_key_hex,
                "initial public key",
            ),
        ):
            if pinned is not None and actual != pinned:
                raise EvidenceVaultError(f"external {label} pin mismatch")

    def _verify_vault_root_pin(self, state: Mapping[str, Any]) -> None:
        expected = self._trust_pins.expected_vault_root
        if expected is not None and state["vault_root"] != expected:
            raise EvidenceVaultError("external vault root pin mismatch")

    def _object_path(self, sha256: str) -> Path:
        _sha256(sha256, "object sha256")
        path = self.root / "objects" / "sha256" / sha256[:2] / sha256[2:]
        path.resolve(strict=False).relative_to(self.root)
        return path


def _verify_event(
    event: Any,
    public: Ed25519PublicKey,
    *,
    sequence: int,
    previous: str | None,
    expected_vault_id: str,
    expected_public_key_hex: str,
) -> None:
    required = {
        "schema",
        "vault_id",
        "sequence",
        "previous_event_root",
        "event_type",
        "recorded_at",
        "body",
        "event_root",
        "signature",
    }
    if not isinstance(event, dict) or set(event) != required:
        raise EvidenceVaultError("vault event keys mismatch")
    payload = {key: event[key] for key in event if key not in {"event_root", "signature"}}
    if (
        event["schema"] != EVENT_SCHEMA
        or event["sequence"] != sequence
        or event["previous_event_root"] != previous
        or event["vault_id"] != expected_vault_id
        or event["event_root"] != digest(EVENT_SCHEMA, payload)
    ):
        raise EvidenceVaultError("vault event chain/root mismatch")
    _instant(event["recorded_at"])
    signature = event["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "public_key_hex", "signature_hex"}
        or signature["algorithm"] != "ed25519"
        or signature["public_key_hex"] != expected_public_key_hex
    ):
        raise EvidenceVaultError("vault event signature record mismatch")
    try:
        public.verify(
            bytes.fromhex(signature["signature_hex"]),
            _signature_message(event["event_root"]),
        )
    except (ValueError, InvalidSignature) as exc:
        raise EvidenceVaultError("vault event signature invalid") from exc


def _signature_message(event_root: str) -> bytes:
    _sha256(event_root, "event_root")
    return b"AuditSpec-evidence-vault-event-signature-v1\x00" + bytes.fromhex(
        event_root
    )


def _validate_journal_authority_rotation(
    body: Any,
    *,
    predecessor_public_key_hex: str,
    public_key_history: Sequence[str],
) -> str:
    required = {
        "schema",
        "predecessor_public_key_hex",
        "successor_public_key_hex",
        "reason_digest",
    }
    if not isinstance(body, dict) or set(body) != required:
        raise EvidenceVaultError("journal authority rotation body mismatch")
    if (
        body["schema"] != JOURNAL_AUTHORITY_ROTATION_SCHEMA
        or body["predecessor_public_key_hex"] != predecessor_public_key_hex
    ):
        raise EvidenceVaultError("journal authority rotation predecessor mismatch")
    successor = _public_key(
        body["successor_public_key_hex"], "successor_public_key_hex"
    )
    _sha256(body["reason_digest"], "journal authority rotation reason_digest")
    if successor in public_key_history:
        raise EvidenceVaultError("journal authority rotation reuses a prior key")
    return successor


def _validate_retirement(
    body: Any, *, components: Mapping[str, Any]
) -> None:
    if not isinstance(body, Mapping):
        raise EvidenceVaultError("retirement certificate body mismatch")
    schema = body.get("schema")
    common = {
        "schema",
        "component_ref",
        "replacement_ref",
        "impacted_claim_ids",
        "future_unsupported_claim_ids",
        "archive_object_ref",
        "existing_contracts_reverify_before_retirement",
    }
    if schema == "AuditSpec-evidence-vault-retirement-certificate-v1":
        required = common
    elif schema == RETIREMENT_SCHEMA_V2:
        required = common | {"future_capture_policy", "retired_at"}
        if body.get("future_capture_policy") != "reject_retired_reference":
            raise EvidenceVaultError("retirement future-capture policy mismatch")
        _instant(body.get("retired_at"))
    else:
        raise EvidenceVaultError("retirement certificate schema mismatch")
    if set(body) != required:
        raise EvidenceVaultError("retirement certificate body mismatch")
    component_ref = body["component_ref"]
    replacement_ref = body["replacement_ref"]
    if replacement_ref is not None:
        replacement = components.get(replacement_ref)
        component = components.get(component_ref)
        if (
            replacement is None
            or component is None
            or replacement_ref == component_ref
            or replacement["body"]["kind"] != component["body"]["kind"]
        ):
            raise EvidenceVaultError("retirement replacement is invalid")
    if body["existing_contracts_reverify_before_retirement"] is not True:
        raise EvidenceVaultError("retirement historical-verification policy mismatch")
    for field in ("impacted_claim_ids", "future_unsupported_claim_ids"):
        values = body[field]
        if not isinstance(values, list) or values != sorted(set(values)):
            raise EvidenceVaultError("retirement claim ids are not canonical")
        for value in values:
            _identifier(value, field)


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
    if metadata["valid_until"] is not None and captured > _instant(metadata["valid_until"]):
        return False
    revocation_kind = metadata["revocation_kind"]
    if revocation_kind not in {None, "routine", "retroactive_compromise"}:
        return False
    revoked_at = metadata["revoked_at"]
    if revocation_kind is None:
        return revoked_at is None and metadata["compromise_effective_from"] is None
    if revoked_at is None:
        return False
    revoked = _instant(revoked_at)
    if revocation_kind == "routine":
        return (
            metadata["compromise_effective_from"] is None
            and captured < revoked
        )
    if revocation_kind == "retroactive_compromise":
        effective = metadata["compromise_effective_from"]
        if effective is None:
            return False
        effective_at = _instant(effective)
        return effective_at <= revoked and captured < effective_at
    return False


def _bridge_valid(metadata: Mapping[str, Any], *, audited_at: str) -> bool:
    if set(metadata) != {"valid_from", "valid_until", "revoked_at", "mode"}:
        return False
    if metadata["mode"] not in {"complete_mediation", "external_inventory"}:
        return False
    at = _instant(audited_at)
    if at < _instant(metadata["valid_from"]):
        return False
    if metadata["valid_until"] is not None and at > _instant(metadata["valid_until"]):
        return False
    return metadata["revoked_at"] is None or at < _instant(metadata["revoked_at"])


def _world_scope(
    value: Mapping[str, Any], *, components: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("type") not in WORLD_SCOPES:
        raise EvidenceVaultError("world scope is invalid")
    if value["type"] == "declared_closed_world":
        if set(value) != {"type", "scope_commitment", "universe_root"}:
            raise EvidenceVaultError("declared closed-world scope keys mismatch")
    else:
        if set(value) != {"type", "scope_commitment", "bridge_ref"}:
            raise EvidenceVaultError("externally bridged scope keys mismatch")
        component = components.get(value["bridge_ref"])
        if component is None or component["body"]["kind"] != "bridge":
            raise EvidenceVaultError("world scope bridge reference is unresolved")
    _sha256(value["scope_commitment"], "scope commitment")
    if "universe_root" in value:
        _sha256(value["universe_root"], "universe root")
    return dict(value)


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceVaultError("timestamp must be an RFC3339 UTC string")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceVaultError("timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvidenceVaultError("timestamp is not UTC")
    return parsed


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
        raise EvidenceVaultError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise EvidenceVaultError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _public_key(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise EvidenceVaultError(f"{label} is not a raw Ed25519 public key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
    except ValueError as exc:
        raise EvidenceVaultError(f"{label} is not a raw Ed25519 public key") from exc
    return value


def _media_type(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 127
        or re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", value) is None
    ):
        raise EvidenceVaultError("media type is invalid")
    return value


def _json_mapping(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceVaultError(f"{label} must be a mapping")
    materialized = dict(value)
    canonical_bytes(materialized)
    return materialized


def _json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _exclusive_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(dir=path.parent)
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _deletion_commit_body(intent: Mapping[str, Any]) -> dict[str, Any]:
    body = intent["body"]
    common = {
        "schema",
        "evidence_id",
        "deleted_at",
        "object_sha256",
        "deletion_basis",
        "authority_ref",
        "retention_decision",
        "physical_delete_required",
        "retained_by_live_evidence_ids",
    }
    schema = body.get("schema")
    if schema == DELETION_INTENT_SCHEMA_V1:
        required = common
        tombstone_schema = DELETION_TOMBSTONE_SCHEMA_V1
    elif schema == DELETION_INTENT_SCHEMA_V2:
        required = common | {"retained_by_component_refs"}
        tombstone_schema = DELETION_TOMBSTONE_SCHEMA_V2
    elif schema == DELETION_INTENT_SCHEMA_V3:
        required = common | {
            "authority_semantics",
            "retained_by_component_refs",
        }
        tombstone_schema = DELETION_TOMBSTONE_SCHEMA_V3
        if body["authority_semantics"] != AUTHORITY_ATTRIBUTION_SEMANTICS:
            raise EvidenceVaultError("deletion authority semantics mismatch")
    else:
        raise EvidenceVaultError("deletion intent body mismatch")
    if set(body) != required:
        raise EvidenceVaultError("deletion intent body mismatch")
    result = {
        "schema": tombstone_schema,
        "evidence_id": body["evidence_id"],
        "object_sha256": body["object_sha256"],
        "deletion_basis": body["deletion_basis"],
        "authority_ref": body["authority_ref"],
        "retention_decision": body["retention_decision"],
        "physical_deleted": body["physical_delete_required"],
        "retained_by_live_evidence_ids": body["retained_by_live_evidence_ids"],
        "intent_event_root": intent["event_root"],
    }
    if schema in {DELETION_INTENT_SCHEMA_V2, DELETION_INTENT_SCHEMA_V3}:
        result["retained_by_component_refs"] = body["retained_by_component_refs"]
    if schema == DELETION_INTENT_SCHEMA_V3:
        result["authority_semantics"] = body["authority_semantics"]
    return result


def _insert_once(target: dict[str, Any], key: str, value: Any) -> None:
    if key in target:
        raise EvidenceVaultError("append-only journal contains duplicate identity")
    target[key] = value


def _gap(subtype: str, evidence_id: str) -> dict[str, str]:
    return {"subtype": subtype, "evidence_id": evidence_id}


def _obstruction_rows(gaps: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    hard = {
        "EVIDENCE_INTEGRITY_FAILURE",
        "EVIDENCE_UNAVAILABLE",
        "LEGAL_DELETION_PREVENTS_REVERIFY",
        "LOSSY_SCHEMA_MIGRATION",
        "MIGRATION_CLAIM_INFORMATION_LOSS",
        "RETENTION_NONCOMPLIANCE",
    }
    verification = {"MIGRATION_CERTIFICATE_INVALID"}
    return [
        {
            **row,
            "obstruction_class": (
                "HARD_SEMANTIC_OBSTRUCTION"
                if row["subtype"] in hard
                else (
                    "VERIFICATION_FAILURE"
                    if row["subtype"] in verification
                    else "SOFT_TRUST_INTERPRETABILITY_OBSTRUCTION"
                )
            ),
        }
        for row in gaps
    ]


def _deduplicate_gaps(gaps: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    priority = {
        "EVIDENCE_INTEGRITY_FAILURE": 0,
        "HISTORIC_KEY_UNRESOLVED": 1,
        "UNREADABLE_SCHEMA": 2,
        "LOSSY_SCHEMA_MIGRATION": 3,
        "MIGRATION_CLAIM_INFORMATION_LOSS": 4,
        "MIGRATION_CERTIFICATE_INVALID": 5,
        "VERIFIER_UNAVAILABLE": 6,
        "VERSION_ROOT_UNRESOLVED": 7,
        "BRIDGE_UNRESOLVED": 8,
        "BRIDGE_EXPIRED_OR_REVOKED": 9,
        "RETENTION_NONCOMPLIANCE": 10,
        "LEGAL_DELETION_PREVENTS_REVERIFY": 11,
        "EVIDENCE_UNAVAILABLE": 12,
    }
    unique = {(row["subtype"], row["evidence_id"]): row for row in gaps}
    return sorted(
        unique.values(),
        key=lambda row: (priority.get(row["subtype"], 99), row["evidence_id"]),
    )
