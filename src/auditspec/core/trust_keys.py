"""Client for isolated local Ed25519 authority processes."""

from __future__ import annotations

import json
import hashlib
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import digest

ROOT = Path(__file__).resolve().parents[3]


def signature_message(schema: str, payload_digest: str) -> bytes:
    return (
        b"AuditSpec-ed25519-integrity-v1"
        + b"\x00"
        + schema.encode("utf-8")
        + b"\x00"
        + bytes.fromhex(payload_digest)
    )


@dataclass
class LocalAuthority:
    role: str
    principal_id: str
    key_domain: str
    process: subprocess.Popen[str]
    receipt: dict[str, Any]
    public_key: Ed25519PublicKey
    pid: int
    key_id: str
    key_version: str
    run_id: str
    contract_payload_digest: str
    challenge: str
    allowed_schemas: tuple[str, ...]

    @classmethod
    def start(
        cls,
        role: str,
        principal_id: str,
        key_domain: str,
        run_id: str,
        contract_payload_digest: str,
        allowed_schemas: tuple[str, ...],
        trusted_public_keys: dict[str, Any] | None = None,
    ) -> "LocalAuthority":
        challenge = secrets.token_hex(32)
        worker_argv = [
            "auditspec.core.trust_worker",
            "--role",
            role,
            "--principal-id",
            principal_id,
            "--key-domain",
            key_domain,
            "--run-id",
            run_id,
            "--contract-payload-digest",
            contract_payload_digest,
            "--challenge",
            challenge,
            "--trusted-public-keys-json",
            json.dumps(
                trusted_public_keys or {}, sort_keys=True, separators=(",", ":")
            ),
        ]
        for schema in allowed_schemas:
            worker_argv.extend(("--allowed-schema", schema))
        bootstrap = (
            "import runpy,sys;"
            f"sys.path.insert(0,{str(ROOT / 'src')!r});"
            f"sys.argv={worker_argv!r};"
            "runpy.run_module('auditspec.core.trust_worker',run_name='__main__')"
        )
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", bootstrap],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"authority worker failed to start: {stderr}")
        hello = json.loads(line)
        if hello.get("type") != "hello":
            raise RuntimeError("authority worker returned no hello receipt")
        receipt = hello["receipt"]
        payload = receipt["payload"]
        if (
            payload["role"] != role
            or payload["principal_id"] != principal_id
            or payload["key_domain"] != key_domain
            or payload["private_key_exported"] is not False
            or payload["pid"] != process.pid
            or payload["run_id"] != run_id
            or payload["contract_payload_digest"] != contract_payload_digest
            or payload["parent_challenge"] != challenge
            or payload["allowed_schemas"] != sorted(allowed_schemas)
            or payload["trusted_public_keys_root"]
            != digest(
                "AuditSpec-local-worker-trusted-public-keys-v1",
                trusted_public_keys or {},
            )
            or payload["worker_source_sha256"]
            != hashlib.sha256(
                (ROOT / "src/auditspec/core/trust_worker.py").read_bytes()
            ).hexdigest()
            or payload["python_executable"] != sys.executable
            or payload["python_executable_sha256"]
            != hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
        ):
            raise RuntimeError("authority process receipt binding mismatch")
        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(payload["public_key"]["hex"])
        )
        _verify_envelope(receipt, public_key)
        return cls(
            role,
            principal_id,
            key_domain,
            process,
            receipt,
            public_key,
            process.pid,
            payload["key_id"],
            payload["key_version"],
            run_id,
            contract_payload_digest,
            challenge,
            tuple(sorted(allowed_schemas)),
        )

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise RuntimeError("authority process is no longer running")
        assert self.process.stdin is not None and self.process.stdout is not None
        request = {
            "command": "sign_typed",
            "payload": payload,
        }
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        schema = payload["schema"]
        payload_digest = digest(schema, payload)
        response = json.loads(self.process.stdout.readline())
        if (
            response.get("type") != "signature"
            or response.get("pid") != self.pid
            or response.get("schema") != schema
            or response.get("payload_digest") != payload_digest
        ):
            raise RuntimeError("authority signature response mismatch")
        integrity = {
            "type": "ed25519_signature",
            "payload_digest": payload_digest,
            "signature": response["signature"],
        }
        verify_integrity(integrity, schema, self.public_key)
        return integrity

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write('{"command":"shutdown"}\n')
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        if response != {"type": "shutdown", "pid": self.pid}:
            raise RuntimeError("authority worker shutdown mismatch")
        self.process.wait(timeout=10)

    def principal(self) -> dict[str, str]:
        return {
            "id": self.principal_id,
            "key_domain": self.key_domain,
            "key_id": self.key_id,
        }


class AuthoritySet:
    SCHEMAS = {
        "action_producer": ("AuditSpec-evidence-instance-v1",),
        "ledger_producer": ("AuditSpec-evidence-instance-v1",),
        "run_closure": ("AuditSpec-evidence-bundle-ed25519-preview-v1",),
        "snapshot": ("AuditSpec-trust-snapshot-preview-v1",),
    }

    def __init__(
        self,
        rows: Iterable[dict[str, str]],
        *,
        run_id: str,
        contract_payload_digest: str,
    ) -> None:
        materialized = list(rows)
        if {row.get("role") for row in materialized} != set(self.SCHEMAS):
            raise ValueError("authority role population mismatch")
        self.by_role: dict[str, LocalAuthority] = {}
        try:
            for role in ("action_producer", "ledger_producer", "snapshot"):
                row = next(item for item in materialized if item["role"] == role)
                self.by_role[role] = LocalAuthority.start(
                    role,
                    row["principal_id"],
                    row["key_domain"],
                    run_id,
                    contract_payload_digest,
                    self.SCHEMAS[role],
                )
            trusted = {
                "canonical_action": _public_record(
                    self.by_role["action_producer"]
                ),
                "durable_effect_receipt": _public_record(
                    self.by_role["ledger_producer"]
                ),
            }
            row = next(
                item for item in materialized if item["role"] == "run_closure"
            )
            self.by_role["run_closure"] = LocalAuthority.start(
                "run_closure",
                row["principal_id"],
                row["key_domain"],
                run_id,
                contract_payload_digest,
                self.SCHEMAS["run_closure"],
                trusted,
            )
        except Exception:
            self.close()
            raise
        pids = [item.pid for item in self.by_role.values()]
        domains = [item.key_domain for item in self.by_role.values()]
        public_keys = [
            item.receipt["payload"]["public_key"]["hex"]
            for item in self.by_role.values()
        ]
        if (
            len(pids) != len(set(pids))
            or len(domains) != len(set(domains))
            or len(public_keys) != len(set(public_keys))
        ):
            self.close()
            raise RuntimeError("local authority process/key domains are not distinct")

    def close(self) -> None:
        errors = []
        for authority in self.by_role.values():
            try:
                authority.close()
            except Exception as exc:  # pragma: no cover - shutdown best effort
                errors.append(exc)
        if errors:
            raise RuntimeError(f"authority shutdown failed: {errors}")

    def __enter__(self) -> "AuthoritySet":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def public_registry(self) -> dict[str, Any]:
        records = [
            {
                "role": role,
                "principal": authority.principal(),
                "key_version": authority.key_version,
                "public_key": authority.receipt["payload"]["public_key"],
                "process_receipt": authority.receipt,
            }
            for role, authority in sorted(self.by_role.items())
        ]
        return {
            "schema": "AuditSpec-local-authority-registry-preview-v1",
            "records": records,
            "registry_root": digest(
                "AuditSpec-local-authority-registry-preview-v1", records
            ),
            "bootstrap_external_authentication_proven": False,
        }


def verify_integrity(
    integrity: dict[str, Any], schema: str, public_key: Ed25519PublicKey
) -> None:
    signature = integrity["signature"]
    if (
        integrity.get("type") != "ed25519_signature"
        or signature.get("alg") != "ed25519"
        or signature.get("domain") != schema
    ):
        raise ValueError("Ed25519 integrity envelope mismatch")
    try:
        public_key.verify(
            bytes.fromhex(signature["value"]["hex"]),
            signature_message(schema, integrity["payload_digest"]),
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise ValueError("Ed25519 signature verification failed") from exc


def _verify_envelope(envelope: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    payload = envelope["payload"]
    expected = digest(payload["schema"], payload)
    if envelope["integrity"]["payload_digest"] != expected:
        raise ValueError("authority receipt payload digest mismatch")
    verify_integrity(envelope["integrity"], payload["schema"], public_key)


def _public_record(authority: LocalAuthority) -> dict[str, str]:
    return {
        "key_id": authority.key_id,
        "key_version": authority.key_version,
        "public_key_hex": authority.receipt["payload"]["public_key"]["hex"],
    }
