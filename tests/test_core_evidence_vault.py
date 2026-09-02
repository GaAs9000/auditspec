from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from auditspec.core.evidence_vault import (
    EvidenceVault,
    EvidenceVaultError,
    VaultSigner,
    _deletion_commit_body,
)
from auditspec.core.vault_cli import main as vault_cli


T0 = "2026-01-01T00:00:00Z"
T1 = "2027-01-01T00:00:00Z"
T2 = "2028-01-01T00:00:00Z"
T3 = "2030-01-01T00:00:00Z"
ROOT = Path(__file__).resolve().parents[1]
PREDICATE = {
    "op": "eq",
    "left": {"op": "field", "name": "settled_count"},
    "right": {"op": "const", "value": 1},
}


def _new_vault(
    root: Path,
    *,
    schema_metadata: dict | None = None,
    key_metadata: dict | None = None,
    verifier_metadata: dict | None = None,
    bridge_metadata: dict | None = None,
) -> tuple[EvidenceVault, VaultSigner]:
    signer = VaultSigner.generate()
    vault = EvidenceVault.create(
        root, vault_id="vault.test", created_at=T0, signer=signer
    )
    vault.archive_component(
        kind="schema",
        component_id="payment-evidence",
        version="1",
        content=b'{"type":"object"}',
        media_type="application/json",
        metadata=schema_metadata or {"readable": True, "migration_mode": "lossless"},
        recorded_at=T0,
    )
    verifier = {
        "schema": "AuditSpec-vault-json-predicate-verifier-v1",
        "predicate": PREDICATE,
    }
    vault.archive_component(
        kind="verifier",
        component_id="payment-predicate",
        version="1",
        content=json.dumps(verifier, sort_keys=True, separators=(",", ":")).encode(),
        media_type="application/json",
        metadata=verifier_metadata or {"archive_executable": True},
        recorded_at=T0,
    )
    vault.archive_component(
        kind="key",
        component_id="producer-key",
        version="1",
        content=b"historical-public-key",
        media_type="application/octet-stream",
        metadata=key_metadata
        or {
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": T1,
            "revoked_at": T1,
            "revocation_kind": "routine",
            "compromise_effective_from": None,
        },
        recorded_at=T0,
    )
    vault.archive_component(
        kind="policy",
        component_id="payment-policy",
        version="1",
        content=b"policy-v1",
        media_type="text/plain",
        metadata={"archived": True},
        recorded_at=T0,
    )
    if bridge_metadata is not None:
        vault.archive_component(
            kind="bridge",
            component_id="inventory",
            version="1",
            content=b"signed-inventory-root",
            media_type="application/octet-stream",
            metadata=bridge_metadata,
            recorded_at=T0,
        )
    return vault, signer


def _append(
    vault: EvidenceVault,
    *,
    evidence_id: str = "evidence.payment.1",
    content: bytes = b'{"settled_count":1}',
    bridged: bool = False,
    minimum_retain_until: str = T1,
    deletion_required_by: str = T3,
    captured_at: str = T0,
) -> None:
    if bridged:
        scope = {
            "type": "externally_bridged_world",
            "scope_commitment": "1" * 64,
            "bridge_ref": "bridge:inventory:1",
        }
    else:
        scope = {
            "type": "declared_closed_world",
            "scope_commitment": "1" * 64,
            "universe_root": "2" * 64,
        }
    vault.append_evidence(
        evidence_id=evidence_id,
        claim_id="claim.payment.once",
        run_id="run.payment.1",
        content=content,
        media_type="application/json",
        schema_ref="schema:payment-evidence:1",
        key_ref="key:producer-key:1",
        verifier_ref="verifier:payment-predicate:1",
        policy_ref="policy:payment-policy:1",
        world_scope=scope,
        captured_at=captured_at,
        minimum_retain_until=minimum_retain_until,
        deletion_required_by=deletion_required_by,
        recorded_at=T0,
    )


def _bundle(vault: EvidenceVault, evidence_ids: list[str] | None = None) -> None:
    vault.create_bundle(
        bundle_id="bundle.payment.1",
        evidence_ids=evidence_ids or ["evidence.payment.1"],
        recorded_at=T0,
    )


def test_vault_manifest_is_public_only_and_read_only_replays(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    manifest = json.loads((vault.root / "vault.json").read_text(encoding="utf-8"))
    assert manifest["private_key_persisted"] is False
    assert "private_key_hex" not in manifest
    assert "seed" not in manifest
    read_only = EvidenceVault.open_read_only(vault.root)
    assert read_only.replay()["event_count"] == 4
    with pytest.raises(EvidenceVaultError, match="read-only"):
        read_only.archive_component(
            kind="policy",
            component_id="new",
            version="1",
            content=b"x",
            media_type="text/plain",
            metadata={},
            recorded_at=T0,
        )


def test_vault_reverifies_after_routine_key_rotation(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    _bundle(vault)
    result = EvidenceVault.open_read_only(vault.root).reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["status"] == "REVERIFIED_AT_AUDIT_TIME"
    assert result["verdict"] == "SUPPORTED"
    assert result["claim_value"] is True


def test_cross_claim_bundle_splice_is_typed_inventory_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    _bundle(vault)
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.other", audited_at=T2
    )
    assert result["verdict"] == "INVENTORY_GAP"
    assert result["primary_failure"] == {
        "subtype": "CLAIM_EVIDENCE_ABSENT",
        "claim_id": "claim.other",
    }


def test_retroactive_key_compromise_is_typed_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(
        tmp_path / "vault",
        key_metadata={
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": None,
            "revoked_at": T1,
            "revocation_kind": "retroactive_compromise",
            "compromise_effective_from": "2025-12-01T00:00:00Z",
        },
    )
    _append(vault)
    _bundle(vault)
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["verdict"] == "LIFECYCLE_GAP"
    assert result["primary_failure"]["subtype"] == "HISTORIC_KEY_UNRESOLVED"


def test_routine_revocation_bounds_capture_when_valid_until_is_null(
    tmp_path: Path,
) -> None:
    vault, _ = _new_vault(
        tmp_path / "vault",
        key_metadata={
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": None,
            "revoked_at": T1,
            "revocation_kind": "routine",
            "compromise_effective_from": None,
        },
    )
    _append(
        vault,
        captured_at=T2,
        minimum_retain_until=T2,
        deletion_required_by=T3,
    )
    _bundle(vault)
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["verdict"] == "LIFECYCLE_GAP"
    assert result["primary_failure"]["subtype"] == "HISTORIC_KEY_UNRESOLVED"


@pytest.mark.parametrize(
    "key_metadata",
    [
        {
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": None,
            "revoked_at": T1,
            "revocation_kind": None,
            "compromise_effective_from": None,
        },
        {
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": None,
            "revoked_at": None,
            "revocation_kind": "routine",
            "compromise_effective_from": None,
        },
        {
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": None,
            "revoked_at": T1,
            "revocation_kind": "retroactive_compromise",
            "compromise_effective_from": T2,
        },
    ],
)
def test_inconsistent_historic_key_revocation_metadata_fails_closed(
    tmp_path: Path, key_metadata: dict
) -> None:
    vault, _ = _new_vault(tmp_path / "vault", key_metadata=key_metadata)
    _append(vault)
    _bundle(vault)
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["verdict"] == "LIFECYCLE_GAP"
    assert result["primary_failure"]["subtype"] == "HISTORIC_KEY_UNRESOLVED"


def test_lossy_schema_migration_is_typed_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(
        tmp_path / "vault",
        schema_metadata={"readable": True, "migration_mode": "lossy"},
    )
    _append(vault)
    _bundle(vault)
    retrieval = vault.retrieve_for_audit("bundle.payment.1", audited_at=T2).record
    assert retrieval["status"] == "LIFECYCLE_GAP"
    assert retrieval["primary_failure"]["subtype"] == "LOSSY_SCHEMA_MIGRATION"


def test_unexecutable_verifier_archive_is_typed_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(
        tmp_path / "vault", verifier_metadata={"archive_executable": False}
    )
    _append(vault)
    _bundle(vault)
    retrieval = vault.retrieve_for_audit("bundle.payment.1", audited_at=T2).record
    assert retrieval["primary_failure"]["subtype"] == "VERIFIER_UNAVAILABLE"


@pytest.mark.parametrize(
    ("bridge_metadata", "audited_at", "expected"),
    [
        (
            {
                "valid_from": T0,
                "valid_until": T3,
                "revoked_at": None,
                "mode": "external_inventory",
            },
            T2,
            "READY_FOR_REVERIFICATION",
        ),
        (
            {
                "valid_from": T0,
                "valid_until": T1,
                "revoked_at": None,
                "mode": "external_inventory",
            },
            T2,
            "LIFECYCLE_GAP",
        ),
    ],
)
def test_bridge_is_evaluated_at_audit_time(
    tmp_path: Path, bridge_metadata: dict, audited_at: str, expected: str
) -> None:
    vault, _ = _new_vault(
        tmp_path / "vault", bridge_metadata=bridge_metadata
    )
    _append(vault, bridged=True)
    _bundle(vault)
    result = vault.retrieve_for_audit("bundle.payment.1", audited_at=audited_at).record
    assert result["status"] == expected
    if expected == "LIFECYCLE_GAP":
        assert result["primary_failure"]["subtype"] == "BRIDGE_EXPIRED_OR_REVOKED"


def test_legal_hold_prevents_physical_deletion(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    hold_event = vault.place_legal_hold(
        hold_id="hold.1",
        evidence_ids=["evidence.payment.1"],
        authority_ref="legal.authority.1",
        reason_digest="3" * 64,
        recorded_at=T2,
    )
    assert hold_event["body"]["authority_semantics"] == (
        "attribution_metadata_asserted_by_vault_authority"
    )
    assert vault.retention_decision("evidence.payment.1", evaluated_at=T2)[
        "status"
    ] == "LEGAL_HOLD"
    with pytest.raises(EvidenceVaultError, match="prevents deletion"):
        vault.delete_evidence(
            evidence_id="evidence.payment.1",
            deleted_at=T2,
            deletion_basis="permitted_disposal",
            authority_ref="custody.authority.1",
        )
    vault.release_legal_hold(
        hold_id="hold.1",
        authority_ref="legal.authority.1",
        release_reason_digest="4" * 64,
        recorded_at=T2,
    )
    assert vault.retention_decision("evidence.payment.1", evaluated_at=T2)[
        "status"
    ] == "DELETION_ELIGIBLE"


def test_permitted_deletion_returns_evidence_unavailable(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    _bundle(vault)
    tombstone = vault.delete_evidence(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
        authority_ref="custody.authority.1",
    )
    assert tombstone["body"]["physical_deleted"] is True
    assert tombstone["body"]["authority_semantics"] == (
        "attribution_metadata_asserted_by_vault_authority"
    )
    retrieval = vault.retrieve_for_audit("bundle.payment.1", audited_at=T2).record
    assert retrieval["primary_failure"]["subtype"] == "EVIDENCE_UNAVAILABLE"


def test_policy_deadline_deletion_is_legal_deletion_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault, minimum_retain_until=T1, deletion_required_by=T2)
    _bundle(vault)
    vault.delete_evidence(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="policy_deadline",
        authority_ref="custody.authority.1",
    )
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["primary_failure"]["subtype"] == (
        "LEGAL_DELETION_PREVENTS_REVERIFY"
    )


def test_deletion_intent_fails_closed_and_writable_reopen_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, signer = _new_vault(tmp_path / "vault")
    _append(vault)
    _bundle(vault)
    state = vault.replay()
    object_path = vault._object_path(
        state["evidence"]["evidence.payment.1"]["body"]["object_ref"]["sha256"]
    )
    original_unlink = Path.unlink

    def fail_evidence_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == object_path:
            raise OSError("injected crash after signed deletion intent")
        original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_evidence_unlink)
        with pytest.raises(OSError, match="injected crash"):
            vault.delete_evidence(
                evidence_id="evidence.payment.1",
                deleted_at=T2,
                deletion_basis="permitted_disposal",
                authority_ref="custody.authority.1",
            )

    read_only = EvidenceVault.open_read_only(vault.root)
    pending = read_only.replay()
    assert list(pending["pending_deletions"]) == ["evidence.payment.1"]
    result = read_only.retrieve_for_audit("bundle.payment.1", audited_at=T2).record
    assert result["status"] == "LIFECYCLE_GAP"
    assert result["primary_failure"]["subtype"] == (
        "DELETION_TRANSITION_INCOMPLETE"
    )

    recovered = EvidenceVault(vault.root, signer=signer)
    recovered_state = recovered.replay()
    assert recovered_state["pending_deletions"] == {}
    assert "evidence.payment.1" in recovered_state["deletions"]
    assert not object_path.exists()
    event_count = recovered_state["event_count"]
    reopened = EvidenceVault(vault.root, signer=signer)
    assert reopened.replay()["event_count"] == event_count


def test_legal_hold_delete_race_serializes_to_one_valid_outcome(
    tmp_path: Path,
) -> None:
    vault, signer = _new_vault(tmp_path / "vault")
    _append(vault)
    key = tmp_path / "authority.key"
    key.write_bytes(
        signer.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    common = [
        sys.executable,
        "-m",
        "auditspec.core.vault_cli",
    ]
    hold = [
        *common,
        "place-hold",
        "--root",
        str(vault.root),
        "--private-key",
        str(key),
        "--hold-id",
        "hold.race",
        "--evidence-id",
        "evidence.payment.1",
        "--authority-ref",
        "legal.authority.1",
        "--reason-digest",
        "3" * 64,
        "--recorded-at",
        T2,
    ]
    delete = [
        *common,
        "delete-evidence",
        "--root",
        str(vault.root),
        "--private-key",
        str(key),
        "--evidence-id",
        "evidence.payment.1",
        "--deleted-at",
        T2,
        "--deletion-basis",
        "permitted_disposal",
        "--authority-ref",
        "custody.authority.1",
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    processes = [
        subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE)
        for command in (hold, delete)
    ]
    returncodes = [process.wait(timeout=30) for process in processes]
    assert sorted(returncodes) == [0, 2]
    state = EvidenceVault.open_read_only(vault.root).replay()
    deleted = "evidence.payment.1" in state["deletions"]
    held = "hold.race" in state["holds"] and not state["holds"]["hold.race"][
        "released"
    ]
    assert deleted is not held


def test_concurrent_duplicate_mutation_identities_commit_once(tmp_path: Path) -> None:
    vault, signer = _new_vault(tmp_path / "vault")
    _append(vault)
    key = tmp_path / "authority.key"
    key.write_bytes(
        signer.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    content = tmp_path / "content.json"
    content.write_text('{"settled_count":1}\n', encoding="utf-8")
    metadata = tmp_path / "metadata.json"
    metadata.write_text('{"archived":true}\n', encoding="utf-8")
    world = tmp_path / "world.json"
    world.write_text(
        json.dumps(
            {
                "type": "declared_closed_world",
                "scope_commitment": "1" * 64,
                "universe_root": "2" * 64,
            }
        ),
        encoding="utf-8",
    )
    common = [
        sys.executable,
        "-m",
        "auditspec.core.vault_cli",
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

    def run_pair(arguments: list[str]) -> None:
        command = [
            *common,
            *arguments,
            "--root",
            str(vault.root),
            "--private-key",
            str(key),
        ]
        processes = [
            subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(2)
        ]
        assert sorted(process.wait(timeout=30) for process in processes) == [0, 2]
        EvidenceVault.open_read_only(vault.root).replay()

    run_pair(
        [
            "archive-component",
            "--kind",
            "policy",
            "--component-id",
            "race-policy",
            "--version",
            "1",
            "--content",
            str(content),
            "--media-type",
            "application/json",
            "--metadata",
            str(metadata),
            "--recorded-at",
            T2,
        ]
    )
    run_pair(
        [
            "append-evidence",
            "--evidence-id",
            "evidence.race",
            "--claim-id",
            "claim.payment.once",
            "--run-id",
            "run.race",
            "--content",
            str(content),
            "--media-type",
            "application/json",
            "--schema-ref",
            "schema:payment-evidence:1",
            "--key-ref",
            "key:producer-key:1",
            "--verifier-ref",
            "verifier:payment-predicate:1",
            "--policy-ref",
            "policy:payment-policy:1",
            "--world-scope",
            str(world),
            "--captured-at",
            T0,
            "--minimum-retain-until",
            T1,
            "--deletion-required-by",
            T3,
            "--recorded-at",
            T2,
        ]
    )
    run_pair(
        [
            "seal-bundle",
            "--bundle-id",
            "bundle.race",
            "--evidence-id",
            "evidence.payment.1",
            "--recorded-at",
            T2,
        ]
    )
    run_pair(
        [
            "place-hold",
            "--hold-id",
            "hold.duplicate",
            "--evidence-id",
            "evidence.payment.1",
            "--authority-ref",
            "legal.authority.1",
            "--reason-digest",
            "5" * 64,
            "--recorded-at",
            T2,
        ]
    )


def test_illegal_retention_after_deadline_is_typed_gap(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault, minimum_retain_until=T1, deletion_required_by=T2)
    _bundle(vault)
    result = vault.retrieve_for_audit("bundle.payment.1", audited_at=T2).record
    assert result["primary_failure"]["subtype"] == "RETENTION_NONCOMPLIANCE"


def test_shared_object_is_not_physically_deleted_until_last_reference(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    content = b'{"settled_count":1}'
    _append(vault, evidence_id="evidence.payment.1", content=content)
    _append(vault, evidence_id="evidence.payment.2", content=content)
    tombstone = vault.delete_evidence(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
        authority_ref="custody.authority.1",
    )
    assert tombstone["body"]["physical_deleted"] is False
    assert tombstone["body"]["retained_by_live_evidence_ids"] == [
        "evidence.payment.2"
    ]


def test_component_alias_prevents_physical_evidence_object_deletion(
    tmp_path: Path,
) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    shared = b'{"type":"object"}'
    _append(vault, content=shared)
    component_ref = "schema:payment-evidence:1"
    component = vault.replay()["components"][component_ref]["body"]
    object_path = vault._object_path(component["object_ref"]["sha256"])

    tombstone = vault.delete_evidence(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
        authority_ref="custody.authority.1",
    )

    assert tombstone["body"]["physical_deleted"] is False
    assert tombstone["body"]["retained_by_live_evidence_ids"] == []
    assert tombstone["body"]["retained_by_component_refs"] == [component_ref]
    assert object_path.is_file()


def test_legal_hold_and_audit_retrieval_share_deadline_semantics(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault, minimum_retain_until=T1, deletion_required_by=T2)
    _bundle(vault)
    vault.place_legal_hold(
        hold_id="hold.deadline",
        evidence_ids=["evidence.payment.1"],
        authority_ref="legal.authority.1",
        reason_digest="5" * 64,
        recorded_at=T1,
    )

    assert vault.retention_decision(
        "evidence.payment.1", evaluated_at=T2
    )["status"] == "LEGAL_HOLD"
    held = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert held["verdict"] == "SUPPORTED"

    vault.release_legal_hold(
        hold_id="hold.deadline",
        authority_ref="legal.authority.1",
        release_reason_digest="6" * 64,
        recorded_at=T2,
    )
    assert vault.retention_decision(
        "evidence.payment.1", evaluated_at=T2
    )["status"] == "DELETION_REQUIRED"
    released = vault.retrieve_for_audit(
        "bundle.payment.1", audited_at=T2
    ).record
    assert released["primary_failure"]["subtype"] == "RETENTION_NONCOMPLIANCE"


def test_v1_deletion_intent_remains_readable() -> None:
    intent = {
        "event_root": "a" * 64,
        "body": {
            "schema": "AuditSpec-evidence-vault-deletion-intent-v1",
            "evidence_id": "evidence.legacy.1",
            "deleted_at": T2,
            "object_sha256": "b" * 64,
            "deletion_basis": "permitted_disposal",
            "authority_ref": "custody.authority.1",
            "retention_decision": {"status": "DELETION_ELIGIBLE"},
            "physical_delete_required": True,
            "retained_by_live_evidence_ids": [],
        },
    }
    tombstone = _deletion_commit_body(intent)
    assert tombstone["schema"] == "AuditSpec-evidence-vault-deletion-tombstone-v1"
    assert "retained_by_component_refs" not in tombstone


def test_retired_verifier_remains_available_for_existing_contract(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    _bundle(vault)
    vault.retire_component(
        component_ref="verifier:payment-predicate:1",
        replacement_ref=None,
        impacted_claim_ids=["claim.payment.once"],
        future_unsupported_claim_ids=["claim.payment.future"],
        recorded_at=T1,
    )
    result = vault.reverify_json_predicate(
        "bundle.payment.1", claim_id="claim.payment.once", audited_at=T2
    )
    assert result["verdict"] == "SUPPORTED"


def test_retired_component_is_historical_only_for_new_capture(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    vault.archive_component(
        kind="verifier",
        component_id="payment-predicate",
        version="2",
        content=json.dumps(
            {
                "schema": "AuditSpec-vault-json-predicate-verifier-v1",
                "predicate": PREDICATE,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        media_type="application/json",
        metadata={"archive_executable": True},
        recorded_at=T1,
    )
    vault.retire_component(
        component_ref="verifier:payment-predicate:1",
        replacement_ref="verifier:payment-predicate:2",
        impacted_claim_ids=["claim.payment.once"],
        future_unsupported_claim_ids=["claim.payment.future"],
        recorded_at=T1,
    )

    with pytest.raises(EvidenceVaultError, match="retired component"):
        _append(vault, evidence_id="evidence.payment.retired")

    vault.append_evidence(
        evidence_id="evidence.payment.replacement",
        claim_id="claim.payment.once",
        run_id="run.payment.2",
        content=b'{"settled_count":1}',
        media_type="application/json",
        schema_ref="schema:payment-evidence:1",
        key_ref="key:producer-key:1",
        verifier_ref="verifier:payment-predicate:2",
        policy_ref="policy:payment-policy:1",
        world_scope={
            "type": "declared_closed_world",
            "scope_commitment": "1" * 64,
            "universe_root": "2" * 64,
        },
        captured_at=T0,
        minimum_retain_until=T1,
        deletion_required_by=T3,
        recorded_at=T1,
    )
    assert "evidence.payment.replacement" in vault.replay()["evidence"]


def test_external_pin_distinguishes_authentication_from_self_consistency(
    tmp_path: Path,
) -> None:
    source, _ = _new_vault(tmp_path / "source")
    replacement, _ = _new_vault(tmp_path / "replacement")

    assert EvidenceVault.open_read_only(replacement.root).assurance()["status"] == (
        "SELF_CONSISTENT"
    )
    authenticated = EvidenceVault.open_read_only(
        source.root,
        expected_vault_id=source.vault_id,
        expected_manifest_root=source.manifest_root,
        expected_public_key_hex=source.initial_public_key_hex,
    )
    assert authenticated.assurance()["status"] == "EXTERNALLY_AUTHENTICATED"
    authority_only = EvidenceVault.open_read_only(
        source.root,
        expected_public_key_hex=source.initial_public_key_hex,
    ).assurance()
    assert authority_only["status"] == "AUTHORITY_PINNED"
    assert authority_only["authentication_scope"] == "SIGNING_AUTHORITY"
    assert authority_only["rollback_protection"] is False
    with pytest.raises(EvidenceVaultError, match="external manifest root pin mismatch"):
        EvidenceVault.open_read_only(
            replacement.root,
            expected_vault_id=replacement.vault_id,
            expected_manifest_root=source.manifest_root,
        )
    with pytest.raises(EvidenceVaultError, match="requires a manifest"):
        EvidenceVault.open_read_only(source.root, expected_vault_id=source.vault_id)


def test_vault_root_pin_detects_snapshot_advance_or_rollback(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    pinned_root = vault.replay()["vault_root"]
    pinned = EvidenceVault.open_read_only(
        vault.root, expected_vault_root=pinned_root
    ).assurance()
    assert pinned["authentication_scope"] == "SNAPSHOT"
    assert pinned["rollback_protection"] is True
    _append(vault)
    with pytest.raises(EvidenceVaultError, match="external vault root pin mismatch"):
        EvidenceVault.open_read_only(vault.root, expected_vault_root=pinned_root)


def test_journal_authority_rotation_chains_to_successor_key(tmp_path: Path) -> None:
    vault, original = _new_vault(tmp_path / "vault")
    successor = VaultSigner.generate()
    rotation = vault.rotate_journal_authority(
        successor_public_key_hex=successor.public_key_hex,
        reason_digest="7" * 64,
        recorded_at=T1,
    )
    assert rotation["signature"]["public_key_hex"] == original.public_key_hex
    with pytest.raises(EvidenceVaultError, match="active journal authority"):
        vault.archive_component(
            kind="policy",
            component_id="stale-signer",
            version="1",
            content=b"x",
            media_type="text/plain",
            metadata={},
            recorded_at=T1,
        )

    rotated = EvidenceVault(vault.root, signer=successor)
    rotated.archive_component(
        kind="policy",
        component_id="successor-signer",
        version="1",
        content=b"x",
        media_type="text/plain",
        metadata={},
        recorded_at=T1,
    )
    authority = rotated.replay()["journal_authority"]
    assert authority["rotation_count"] == 1
    assert authority["active_public_key_hex"] == successor.public_key_hex
    with pytest.raises(EvidenceVaultError, match="active journal authority"):
        EvidenceVault(vault.root, signer=original)


def test_event_tampering_is_rejected_by_read_only_replay(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    path = sorted((vault.root / "events").glob("*.json"))[0]
    event = json.loads(path.read_text(encoding="utf-8"))
    attacked = copy.deepcopy(event)
    attacked["body"]["component_id"] = "attacked"
    path.write_text(json.dumps(attacked), encoding="utf-8")
    with pytest.raises(EvidenceVaultError, match="chain/root"):
        EvidenceVault.open_read_only(vault.root).replay()


def test_event_signature_key_substitution_is_rejected(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    path = sorted((vault.root / "events").glob("*.json"))[0]
    event = json.loads(path.read_text(encoding="utf-8"))
    event["signature"]["public_key_hex"] = "0" * 64
    path.write_text(json.dumps(event), encoding="utf-8")
    with pytest.raises(EvidenceVaultError, match="signature record"):
        EvidenceVault.open_read_only(vault.root).replay()


def test_same_key_cross_vault_event_transplant_is_rejected(tmp_path: Path) -> None:
    signer = VaultSigner.generate()
    source = EvidenceVault.create(
        tmp_path / "source", vault_id="vault.source", created_at=T0, signer=signer
    )
    target = EvidenceVault.create(
        tmp_path / "target", vault_id="vault.target", created_at=T0, signer=signer
    )
    for vault in (source, target):
        vault.archive_component(
            kind="policy",
            component_id="policy",
            version="1",
            content=b"policy",
            media_type="text/plain",
            metadata={"archived": True},
            recorded_at=T0,
        )
    for path in (target.root / "events").glob("*.json"):
        path.unlink()
    for path in (source.root / "events").glob("*.json"):
        shutil.copy2(path, target.root / "events" / path.name)
    with pytest.raises(EvidenceVaultError, match="chain/root"):
        EvidenceVault.open_read_only(target.root).replay()


def test_wrong_signer_cannot_open_append_capability(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    with pytest.raises(EvidenceVaultError, match="does not match"):
        EvidenceVault(vault.root, signer=VaultSigner.generate())


def test_duplicate_evidence_identity_is_rejected(tmp_path: Path) -> None:
    vault, _ = _new_vault(tmp_path / "vault")
    _append(vault)
    with pytest.raises(EvidenceVaultError, match="already exists"):
        _append(vault)


def test_standalone_cli_generates_external_key_and_opens_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "authority.key"
    root = tmp_path / "vault"
    assert vault_cli(["keygen", "--output", str(key)]) == 0
    key_result = json.loads(capsys.readouterr().out)
    assert key_result["status"] == "KEY_GENERATED"
    assert key.stat().st_mode & 0o777 == 0o600
    assert vault_cli(
        [
            "init",
            "--root",
            str(root),
            "--vault-id",
            "vault.cli",
            "--created-at",
            T0,
            "--private-key",
            str(key),
        ]
    ) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "VAULT_CREATED"
    assert vault_cli(["status", "--root", str(root)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "SELF_CONSISTENT"
    assert status["integrity_status"] == "VALID"
    assert status["event_count"] == 0

    manifest = json.loads((root / "vault.json").read_text(encoding="utf-8"))
    assert vault_cli(
        [
            "status",
            "--root",
            str(root),
            "--expected-vault-id",
            "vault.cli",
            "--expected-manifest-root",
            manifest["manifest_root"],
        ]
    ) == 0
    authenticated = json.loads(capsys.readouterr().out)
    assert authenticated["status"] == "EXTERNALLY_AUTHENTICATED"
    assert authenticated["external_pin_names"] == ["vault_id", "manifest_root"]


def test_cli_refuses_overexposed_private_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "authority.key"
    key.write_bytes(b"0" * 32)
    key.chmod(0o644)
    code = vault_cli(
        [
            "init",
            "--root",
            str(tmp_path / "vault"),
            "--vault-id",
            "vault.cli",
            "--created-at",
            T0,
            "--private-key",
            str(key),
        ]
    )
    assert code == 2
    assert "permissions" in json.loads(capsys.readouterr().out)["error"]
