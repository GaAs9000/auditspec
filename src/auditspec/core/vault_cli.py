"""Command-line API for the standalone AuditSpec Evidence Vault."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import strict_json_loads
from .evidence_vault import EvidenceVault, EvidenceVaultError, VaultSigner


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _dispatch(args)
    except (EvidenceVaultError, OSError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, sort_keys=True))
        return 2
    if result is not None:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditvault")
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--output", type=Path, required=True)

    init = sub.add_parser("init")
    _root(init)
    init.add_argument("--vault-id", required=True)
    init.add_argument("--created-at", required=True)
    _private_key(init)

    archive = sub.add_parser("archive-component")
    _root(archive)
    _private_key(archive)
    archive.add_argument("--kind", required=True)
    archive.add_argument("--component-id", required=True)
    archive.add_argument("--version", required=True)
    archive.add_argument("--content", type=Path, required=True)
    archive.add_argument("--media-type", required=True)
    archive.add_argument("--metadata", type=Path, required=True)
    archive.add_argument("--recorded-at", required=True)

    append = sub.add_parser("append-evidence")
    _root(append)
    _private_key(append)
    for name in ("evidence-id", "claim-id", "run-id"):
        append.add_argument(f"--{name}", required=True)
    append.add_argument("--content", type=Path, required=True)
    append.add_argument("--media-type", required=True)
    for name in ("schema-ref", "key-ref", "verifier-ref", "policy-ref"):
        append.add_argument(f"--{name}", required=True)
    append.add_argument("--world-scope", type=Path, required=True)
    append.add_argument("--captured-at", required=True)
    append.add_argument("--minimum-retain-until", required=True)
    append.add_argument("--deletion-required-by", required=True)
    append.add_argument("--recorded-at", required=True)

    bundle = sub.add_parser("seal-bundle")
    _root(bundle)
    _private_key(bundle)
    bundle.add_argument("--bundle-id", required=True)
    bundle.add_argument("--evidence-id", action="append", required=True)
    bundle.add_argument("--recorded-at", required=True)

    rotate = sub.add_parser("rotate-journal-authority")
    _root(rotate)
    _private_key(rotate)
    rotate.add_argument("--successor-public-key", required=True)
    rotate.add_argument("--reason-digest", required=True)
    rotate.add_argument("--recorded-at", required=True)

    hold = sub.add_parser("place-hold")
    _root(hold)
    _private_key(hold)
    hold.add_argument("--hold-id", required=True)
    hold.add_argument("--evidence-id", action="append", required=True)
    hold.add_argument("--authority-ref", required=True)
    hold.add_argument("--reason-digest", required=True)
    hold.add_argument("--recorded-at", required=True)

    release = sub.add_parser("release-hold")
    _root(release)
    _private_key(release)
    release.add_argument("--hold-id", required=True)
    release.add_argument("--authority-ref", required=True)
    release.add_argument("--release-reason-digest", required=True)
    release.add_argument("--recorded-at", required=True)

    retention = sub.add_parser("retention-decision")
    _root(retention)
    _external_pins(retention)
    retention.add_argument("--evidence-id", required=True)
    retention.add_argument("--evaluated-at", required=True)

    delete = sub.add_parser("delete-evidence")
    _root(delete)
    _private_key(delete)
    delete.add_argument("--evidence-id", required=True)
    delete.add_argument("--deleted-at", required=True)
    delete.add_argument(
        "--deletion-basis",
        choices=("policy_deadline", "permitted_disposal"),
        required=True,
    )
    delete.add_argument("--authority-ref", required=True)

    retrieve = sub.add_parser("retrieve")
    _root(retrieve)
    _external_pins(retrieve)
    retrieve.add_argument("--bundle-id", required=True)
    retrieve.add_argument("--audited-at", required=True)

    reverify = sub.add_parser("reverify-json")
    _root(reverify)
    _external_pins(reverify)
    reverify.add_argument("--bundle-id", required=True)
    reverify.add_argument("--claim-id", required=True)
    reverify.add_argument("--audited-at", required=True)

    status = sub.add_parser("status")
    _root(status)
    _external_pins(status)
    return parser


def _root(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, required=True)


def _private_key(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--private-key", type=Path, required=True)


def _external_pins(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-vault-id")
    parser.add_argument("--expected-manifest-root")
    parser.add_argument("--expected-public-key")
    parser.add_argument("--expected-vault-root")


def _dispatch(args: argparse.Namespace) -> dict[str, Any] | None:
    command = args.command
    if command == "keygen":
        signer = VaultSigner.generate()
        raw = signer.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        _private_write(args.output, raw)
        return {
            "status": "KEY_GENERATED",
            "path": str(args.output.resolve()),
            "public_key_hex": signer.public_key_hex,
            "file_mode": "0600",
        }
    if command == "init":
        vault = EvidenceVault.create(
            args.root,
            vault_id=args.vault_id,
            created_at=args.created_at,
            signer=_load_signer(args.private_key),
        )
        return {
            "status": "VAULT_CREATED",
            "vault_id": vault.vault_id,
            "root": str(vault.root),
        }
    vault = (
        EvidenceVault.open_read_only(
            args.root,
            expected_vault_id=getattr(args, "expected_vault_id", None),
            expected_manifest_root=getattr(args, "expected_manifest_root", None),
            expected_public_key_hex=getattr(args, "expected_public_key", None),
            expected_vault_root=getattr(args, "expected_vault_root", None),
        )
        if command in {"retention-decision", "retrieve", "reverify-json", "status"}
        else EvidenceVault(args.root, signer=_load_signer(args.private_key))
    )
    if command == "archive-component":
        return vault.archive_component(
            kind=args.kind,
            component_id=args.component_id,
            version=args.version,
            content=_regular_bytes(args.content),
            media_type=args.media_type,
            metadata=_json_object(args.metadata),
            recorded_at=args.recorded_at,
        )
    if command == "append-evidence":
        return vault.append_evidence(
            evidence_id=args.evidence_id,
            claim_id=args.claim_id,
            run_id=args.run_id,
            content=_regular_bytes(args.content),
            media_type=args.media_type,
            schema_ref=args.schema_ref,
            key_ref=args.key_ref,
            verifier_ref=args.verifier_ref,
            policy_ref=args.policy_ref,
            world_scope=_json_object(args.world_scope),
            captured_at=args.captured_at,
            minimum_retain_until=args.minimum_retain_until,
            deletion_required_by=args.deletion_required_by,
            recorded_at=args.recorded_at,
        )
    if command == "seal-bundle":
        return vault.create_bundle(
            bundle_id=args.bundle_id,
            evidence_ids=args.evidence_id,
            recorded_at=args.recorded_at,
        )
    if command == "rotate-journal-authority":
        return vault.rotate_journal_authority(
            successor_public_key_hex=args.successor_public_key,
            reason_digest=args.reason_digest,
            recorded_at=args.recorded_at,
        )
    if command == "place-hold":
        return vault.place_legal_hold(
            hold_id=args.hold_id,
            evidence_ids=args.evidence_id,
            authority_ref=args.authority_ref,
            reason_digest=args.reason_digest,
            recorded_at=args.recorded_at,
        )
    if command == "release-hold":
        return vault.release_legal_hold(
            hold_id=args.hold_id,
            authority_ref=args.authority_ref,
            release_reason_digest=args.release_reason_digest,
            recorded_at=args.recorded_at,
        )
    if command == "retention-decision":
        return vault.retention_decision(
            args.evidence_id, evaluated_at=args.evaluated_at
        )
    if command == "delete-evidence":
        return vault.delete_evidence(
            evidence_id=args.evidence_id,
            deleted_at=args.deleted_at,
            deletion_basis=args.deletion_basis,
            authority_ref=args.authority_ref,
        )
    if command == "retrieve":
        return vault.retrieve_for_audit(
            args.bundle_id, audited_at=args.audited_at
        ).record
    if command == "reverify-json":
        return vault.reverify_json_predicate(
            args.bundle_id, claim_id=args.claim_id, audited_at=args.audited_at
        )
    if command == "status":
        state = vault.replay()
        assurance = vault.assurance(state)
        return {
            "status": assurance["status"],
            "integrity_status": assurance["integrity_status"],
            "authentication_scope": assurance["authentication_scope"],
            "rollback_protection": assurance["rollback_protection"],
            "external_pin_names": assurance["external_pin_names"],
            "vault_id": vault.vault_id,
            "manifest_root": vault.manifest_root,
            "event_count": state["event_count"],
            "vault_root": state["vault_root"],
            "initial_public_key_hex": assurance["initial_public_key_hex"],
            "active_public_key_hex": assurance["active_public_key_hex"],
            "journal_authority_rotation_count": assurance[
                "journal_authority_rotation_count"
            ],
            "time_assurance": assurance["time_assurance"],
            "component_count": len(state["components"]),
            "evidence_count": len(state["evidence"]),
            "bundle_count": len(state["bundles"]),
            "active_hold_count": sum(
                not row["released"] for row in state["holds"].values()
            ),
            "deletion_count": len(state["deletions"]),
        }
    raise AssertionError("unreachable vault command")


def _load_signer(path: Path) -> VaultSigner:
    data = _regular_bytes(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise EvidenceVaultError("private-key file permissions must exclude group/other")
    try:
        return VaultSigner(Ed25519PrivateKey.from_private_bytes(data))
    except ValueError as exc:
        raise EvidenceVaultError("private-key file is not a raw Ed25519 key") from exc


def _regular_bytes(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise EvidenceVaultError("input path must be a regular non-symlink file")
    return path.read_bytes()


def _json_object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(_regular_bytes(path).decode("utf-8"))
    if not isinstance(value, dict):
        raise EvidenceVaultError("JSON input root must be an object")
    return value


def _private_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
