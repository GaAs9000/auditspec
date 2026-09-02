"""Ed25519 authentication for caller-declared finite inventory scopes.

Authentication identifies who asserted an exact finite inventory. It never
turns that assertion into a proof that the inventory exhausts reality.
"""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .runtime.events import canonical_json

INVENTORY_AUTHORITY_STATEMENT_SCHEMA = "AuditSpec-inventory-authority-statement-v1"
INVENTORY_AUTHORITY_RESULT_SCHEMA = "AuditSpec-inventory-authority-result-v1"
INVENTORY_SCOPE_BINDING_SCHEMA = "AuditSpec-inventory-authority-scope-binding-v1"
SCHEDULE_CLOSURE_CERTIFICATE_SCHEMA = (
    "AuditSpec-declared-schedule-closure-certificate-v1"
)
SCHEDULE_CLOSURE_RESULT_SCHEMA = "AuditSpec-schedule-closure-result-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FULL_POPULATION_SOURCES = ("schedule", "episodes", "v13_input")
_COMPLETED_POPULATION_SOURCES = (
    "completed",
    "v13_eligible",
    "v13_official",
    "v14_gate_input",
    "v14_formal",
)
_CLOSURE_CHECKS = (
    "full_population_equal",
    "completed_population_equal",
    "episode_hashes_match_v13_input",
    "eligibility_matches_episode_status",
)


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _population_identity(row: Mapping[str, Any]) -> tuple[str, str, str]:
    values = tuple(row.get(name) for name in ("run_id", "environment", "task_id"))
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("population identity fields must be non-empty strings")
    return values  # type: ignore[return-value]


def population_identity_root(identities: Iterable[tuple[str, str, str]]) -> str:
    unique = sorted(set(identities))
    payload = "".join("\0".join(identity) + "\n" for identity in unique)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScheduleClosureSourceSummary:
    name: str
    source_sha256: str
    record_count: int
    unique_count: int
    duplicate_count: int
    identity_root: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("schedule-closure source name must be non-empty")
        if not _DIGEST.fullmatch(self.source_sha256) or not _DIGEST.fullmatch(
            self.identity_root
        ):
            raise ValueError("schedule-closure source digests are invalid")
        for label, value in (
            ("record_count", self.record_count),
            ("unique_count", self.unique_count),
            ("duplicate_count", self.duplicate_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"schedule-closure {label} must be non-negative")
        if self.unique_count + self.duplicate_count != self.record_count:
            raise ValueError("schedule-closure source counts do not close")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_sha256": self.source_sha256,
            "record_count": self.record_count,
            "unique_count": self.unique_count,
            "duplicate_count": self.duplicate_count,
            "identity_root": self.identity_root,
        }

    @classmethod
    def from_dict(
        cls, raw: Mapping[str, Any]
    ) -> ScheduleClosureSourceSummary:
        if set(raw) != {
            "name",
            "source_sha256",
            "record_count",
            "unique_count",
            "duplicate_count",
            "identity_root",
        }:
            raise ValueError("schedule-closure source fields differ")
        return cls(**dict(raw))


def summarize_schedule_population(
    name: str,
    rows: Iterable[Mapping[str, Any]],
    *,
    source_sha256: str,
) -> ScheduleClosureSourceSummary:
    identities = [_population_identity(row) for row in rows]
    counts = Counter(identities)
    return ScheduleClosureSourceSummary(
        name=name,
        source_sha256=source_sha256,
        record_count=len(identities),
        unique_count=len(counts),
        duplicate_count=sum(count - 1 for count in counts.values()),
        identity_root=population_identity_root(counts),
    )


@dataclass(frozen=True)
class DeclaredScheduleClosureCertificate:
    certificate_id: str
    schedule_scope_id: str
    protocol_version: str
    scheduled_units: int
    completed_units: int
    noncompleted_units: int
    scheduled_identity_root: str
    completed_identity_root: str
    source_summaries: Mapping[str, ScheduleClosureSourceSummary]
    source_file_sha256: Mapping[str, str]
    equality_checks: Mapping[str, bool]

    def __post_init__(self) -> None:
        for label, value in (
            ("certificate_id", self.certificate_id),
            ("schedule_scope_id", self.schedule_scope_id),
            ("protocol_version", self.protocol_version),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"schedule-closure {label} must be non-empty")
        for label, value in (
            ("scheduled_units", self.scheduled_units),
            ("completed_units", self.completed_units),
            ("noncompleted_units", self.noncompleted_units),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"schedule-closure {label} is invalid")
        if self.scheduled_units != self.completed_units + self.noncompleted_units:
            raise ValueError("schedule-closure population counts do not close")
        if not _DIGEST.fullmatch(
            self.scheduled_identity_root
        ) or not _DIGEST.fullmatch(self.completed_identity_root):
            raise ValueError("schedule-closure population roots are invalid")
        expected_sources = set(
            _FULL_POPULATION_SOURCES + _COMPLETED_POPULATION_SOURCES
        )
        if set(self.source_summaries) != expected_sources:
            raise ValueError("schedule-closure source set differs")
        summaries: dict[str, ScheduleClosureSourceSummary] = {}
        for name, summary in self.source_summaries.items():
            if not isinstance(summary, ScheduleClosureSourceSummary):
                raise TypeError("schedule-closure source summary has wrong type")
            if summary.name != name:
                raise ValueError("schedule-closure source name mismatch")
            summaries[name] = summary
        if not self.source_file_sha256:
            raise ValueError("schedule-closure source file digests are empty")
        source_files: dict[str, str] = {}
        for path, digest in self.source_file_sha256.items():
            if not isinstance(path, str) or not path or not _DIGEST.fullmatch(digest):
                raise ValueError("schedule-closure source file binding is invalid")
            source_files[path] = digest
        if set(self.equality_checks) != set(_CLOSURE_CHECKS) or any(
            not isinstance(value, bool) for value in self.equality_checks.values()
        ):
            raise ValueError("schedule-closure equality checks differ")
        object.__setattr__(self, "source_summaries", MappingProxyType(summaries))
        object.__setattr__(self, "source_file_sha256", MappingProxyType(source_files))
        object.__setattr__(
            self, "equality_checks", MappingProxyType(dict(self.equality_checks))
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEDULE_CLOSURE_CERTIFICATE_SCHEMA,
            "certificate_id": self.certificate_id,
            "schedule_scope_id": self.schedule_scope_id,
            "protocol_version": self.protocol_version,
            "scheduled_units": self.scheduled_units,
            "completed_units": self.completed_units,
            "noncompleted_units": self.noncompleted_units,
            "scheduled_identity_root": self.scheduled_identity_root,
            "completed_identity_root": self.completed_identity_root,
            "source_summaries": {
                name: summary.as_dict()
                for name, summary in sorted(self.source_summaries.items())
            },
            "source_file_sha256": dict(sorted(self.source_file_sha256.items())),
            "equality_checks": dict(sorted(self.equality_checks.items())),
            "result_informed": True,
            "declared_schedule_completeness_proven": True,
            "inventory_completeness_proven": False,
            "schedule_selection_correctness_proven": False,
            "host_filesystem_visibility_complete_proven": False,
            "official_evaluator_executions": 0,
            "new_model_calls": 0,
            "open_world": False,
        }

    @property
    def certificate_digest(self) -> str:
        return _digest(self.unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "certificate_digest": self.certificate_digest}

    @classmethod
    def from_dict(
        cls, raw: Mapping[str, Any]
    ) -> DeclaredScheduleClosureCertificate:
        expected = {
            "schema",
            "certificate_id",
            "schedule_scope_id",
            "protocol_version",
            "scheduled_units",
            "completed_units",
            "noncompleted_units",
            "scheduled_identity_root",
            "completed_identity_root",
            "source_summaries",
            "source_file_sha256",
            "equality_checks",
            "result_informed",
            "declared_schedule_completeness_proven",
            "inventory_completeness_proven",
            "schedule_selection_correctness_proven",
            "host_filesystem_visibility_complete_proven",
            "official_evaluator_executions",
            "new_model_calls",
            "open_world",
            "certificate_digest",
        }
        if set(raw) != expected:
            raise ValueError("schedule-closure certificate fields differ")
        if raw["schema"] != SCHEDULE_CLOSURE_CERTIFICATE_SCHEMA:
            raise ValueError("schedule-closure certificate schema mismatch")
        boundaries = {
            "result_informed": True,
            "declared_schedule_completeness_proven": True,
            "inventory_completeness_proven": False,
            "schedule_selection_correctness_proven": False,
            "host_filesystem_visibility_complete_proven": False,
            "official_evaluator_executions": 0,
            "new_model_calls": 0,
            "open_world": False,
        }
        if any(raw[name] != value for name, value in boundaries.items()):
            raise ValueError("schedule-closure certificate boundary changed")
        source_summaries = raw["source_summaries"]
        if not isinstance(source_summaries, Mapping):
            raise TypeError("schedule-closure summaries must be a mapping")
        source_files = raw["source_file_sha256"]
        checks = raw["equality_checks"]
        if not isinstance(source_files, Mapping) or not isinstance(checks, Mapping):
            raise TypeError("schedule-closure bindings must be mappings")
        certificate = cls(
            certificate_id=raw["certificate_id"],
            schedule_scope_id=raw["schedule_scope_id"],
            protocol_version=raw["protocol_version"],
            scheduled_units=raw["scheduled_units"],
            completed_units=raw["completed_units"],
            noncompleted_units=raw["noncompleted_units"],
            scheduled_identity_root=raw["scheduled_identity_root"],
            completed_identity_root=raw["completed_identity_root"],
            source_summaries={
                name: ScheduleClosureSourceSummary.from_dict(summary)
                for name, summary in source_summaries.items()
            },
            source_file_sha256=dict(source_files),
            equality_checks=dict(checks),
        )
        if raw["certificate_digest"] != certificate.certificate_digest:
            raise ValueError("schedule-closure certificate digest mismatch")
        return certificate


@dataclass(frozen=True)
class ScheduleClosureTrustContext:
    expected_schedule_scope_id: str
    expected_protocol_version: str
    expected_scheduled_units: int
    expected_completed_units: int
    expected_scheduled_identity_root: str
    expected_completed_identity_root: str
    expected_source_file_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        for label, value in (
            ("expected_schedule_scope_id", self.expected_schedule_scope_id),
            ("expected_protocol_version", self.expected_protocol_version),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"schedule-closure trust {label} must be non-empty")
        for label, value in (
            ("expected_scheduled_units", self.expected_scheduled_units),
            ("expected_completed_units", self.expected_completed_units),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"schedule-closure trust {label} is invalid")
        if self.expected_completed_units > self.expected_scheduled_units:
            raise ValueError("schedule-closure trust counts do not close")
        if not _DIGEST.fullmatch(
            self.expected_scheduled_identity_root
        ) or not _DIGEST.fullmatch(self.expected_completed_identity_root):
            raise ValueError("schedule-closure trust roots are invalid")
        if not self.expected_source_file_sha256:
            raise ValueError("schedule-closure trust source bindings are empty")
        sources: dict[str, str] = {}
        for path, digest in self.expected_source_file_sha256.items():
            if not isinstance(path, str) or not path or not _DIGEST.fullmatch(digest):
                raise ValueError("schedule-closure trust source binding is invalid")
            sources[path] = digest
        object.__setattr__(
            self, "expected_source_file_sha256", MappingProxyType(sources)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-schedule-closure-trust-context-v1",
            "expected_schedule_scope_id": self.expected_schedule_scope_id,
            "expected_protocol_version": self.expected_protocol_version,
            "expected_scheduled_units": self.expected_scheduled_units,
            "expected_completed_units": self.expected_completed_units,
            "expected_scheduled_identity_root": self.expected_scheduled_identity_root,
            "expected_completed_identity_root": self.expected_completed_identity_root,
            "expected_source_file_sha256": dict(
                sorted(self.expected_source_file_sha256.items())
            ),
        }

    @property
    def trust_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class ScheduleClosureVerificationResult:
    certificate_digest: str
    trust_digest: str | None
    valid: bool
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEDULE_CLOSURE_RESULT_SCHEMA,
            "certificate_digest": self.certificate_digest,
            "trust_digest": self.trust_digest,
            "valid": self.valid,
            "errors": list(self.errors),
            "declared_schedule_completeness_proven": self.valid,
            "inventory_completeness_proven": False,
            "schedule_selection_correctness_proven": False,
            "host_filesystem_visibility_complete_proven": False,
            "open_world": False,
        }


def verify_declared_schedule_closure_certificate(
    raw: Mapping[str, Any],
    trust: ScheduleClosureTrustContext | None = None,
) -> ScheduleClosureVerificationResult:
    try:
        certificate = DeclaredScheduleClosureCertificate.from_dict(raw)
    except (KeyError, TypeError, ValueError) as exc:
        return ScheduleClosureVerificationResult(
            certificate_digest=_digest(dict(raw)),
            trust_digest=trust.trust_digest if trust is not None else None,
            valid=False,
            errors=(f"certificate:{type(exc).__name__}:{exc}",),
        )
    errors: list[str] = []
    for name in _FULL_POPULATION_SOURCES:
        summary = certificate.source_summaries[name]
        if (
            summary.record_count != certificate.scheduled_units
            or summary.unique_count != certificate.scheduled_units
            or summary.duplicate_count != 0
            or summary.identity_root != certificate.scheduled_identity_root
        ):
            errors.append(f"full_population:{name}:mismatch")
    for name in _COMPLETED_POPULATION_SOURCES:
        summary = certificate.source_summaries[name]
        if (
            summary.record_count != certificate.completed_units
            or summary.unique_count != certificate.completed_units
            or summary.duplicate_count != 0
            or summary.identity_root != certificate.completed_identity_root
        ):
            errors.append(f"completed_population:{name}:mismatch")
    errors.extend(
        f"equality_check:{name}:false"
        for name, value in certificate.equality_checks.items()
        if value is not True
    )
    if trust is not None:
        if certificate.schedule_scope_id != trust.expected_schedule_scope_id:
            errors.append("trust:schedule_scope_id:mismatch")
        if certificate.protocol_version != trust.expected_protocol_version:
            errors.append("trust:protocol_version:mismatch")
        if certificate.scheduled_units != trust.expected_scheduled_units:
            errors.append("trust:scheduled_units:mismatch")
        if certificate.completed_units != trust.expected_completed_units:
            errors.append("trust:completed_units:mismatch")
        if (
            certificate.scheduled_identity_root
            != trust.expected_scheduled_identity_root
        ):
            errors.append("trust:scheduled_identity_root:mismatch")
        if (
            certificate.completed_identity_root
            != trust.expected_completed_identity_root
        ):
            errors.append("trust:completed_identity_root:mismatch")
        if (
            dict(certificate.source_file_sha256)
            != dict(trust.expected_source_file_sha256)
        ):
            errors.append("trust:source_file_sha256:mismatch")
    return ScheduleClosureVerificationResult(
        certificate_digest=certificate.certificate_digest,
        trust_digest=trust.trust_digest if trust is not None else None,
        valid=not errors,
        errors=tuple(errors),
    )


def make_declared_schedule_closure_certificate(
    *,
    certificate_id: str,
    schedule_scope_id: str,
    protocol_version: str,
    scheduled_units: int,
    completed_units: int,
    noncompleted_units: int,
    scheduled_identity_root: str,
    completed_identity_root: str,
    source_summaries: Mapping[str, ScheduleClosureSourceSummary],
    source_file_sha256: Mapping[str, str],
    equality_checks: Mapping[str, bool],
) -> DeclaredScheduleClosureCertificate:
    certificate = DeclaredScheduleClosureCertificate(
        certificate_id=certificate_id,
        schedule_scope_id=schedule_scope_id,
        protocol_version=protocol_version,
        scheduled_units=scheduled_units,
        completed_units=completed_units,
        noncompleted_units=noncompleted_units,
        scheduled_identity_root=scheduled_identity_root,
        completed_identity_root=completed_identity_root,
        source_summaries=source_summaries,
        source_file_sha256=source_file_sha256,
        equality_checks=equality_checks,
    )
    result = verify_declared_schedule_closure_certificate(certificate.as_dict())
    if not result.valid:
        raise ValueError("schedule-closure certificate does not verify")
    return certificate


def inventory_scope_binding_payload(
    *,
    scope_id: str,
    channel: str,
    inventory_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": INVENTORY_SCOPE_BINDING_SCHEMA,
        "scope_id": scope_id,
        "channel": channel,
        "basis": "declared-manifest-tcb-v1",
        "inventory_manifest": dict(inventory_manifest),
        "inventory_manifest_digest": _digest(dict(inventory_manifest)),
        "inventory_completeness_proven": False,
        "open_world": False,
    }


def inventory_scope_binding_digest(
    *,
    scope_id: str,
    channel: str,
    inventory_manifest: Mapping[str, Any],
) -> str:
    return _digest(
        inventory_scope_binding_payload(
            scope_id=scope_id,
            channel=channel,
            inventory_manifest=inventory_manifest,
        )
    )


@dataclass(frozen=True)
class InventoryAuthorityStatement:
    authority_id: str
    key_id: str
    scope_id: str
    channel: str
    inventory_manifest_digest: str
    inventory_scope_binding_digest: str
    environment: str
    benchmark_revision: str
    issued_at: int
    expires_at: int
    completeness_asserted_for_declared_inventory: bool
    signature_base64: str

    def __post_init__(self) -> None:
        for label, value in (
            ("authority_id", self.authority_id),
            ("key_id", self.key_id),
            ("scope_id", self.scope_id),
            ("channel", self.channel),
            ("environment", self.environment),
            ("benchmark_revision", self.benchmark_revision),
            ("signature_base64", self.signature_base64),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"inventory authority {label} must be non-empty")
        if not self.key_id.startswith("sha256:") or not _DIGEST.fullmatch(
            self.key_id.removeprefix("sha256:")
        ):
            raise ValueError("inventory authority key_id must bind a SHA-256 digest")
        for label, value in (
            ("inventory_manifest_digest", self.inventory_manifest_digest),
            (
                "inventory_scope_binding_digest",
                self.inventory_scope_binding_digest,
            ),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"inventory authority {label} must be a digest")
        if (
            not isinstance(self.issued_at, int)
            or isinstance(self.issued_at, bool)
            or not isinstance(self.expires_at, int)
            or isinstance(self.expires_at, bool)
            or self.issued_at < 0
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("inventory authority validity interval is invalid")
        if self.completeness_asserted_for_declared_inventory is not True:
            raise ValueError(
                "inventory authority statement must assert declared completeness"
            )
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except ValueError as exc:
            raise ValueError(
                "inventory authority signature is not canonical base64"
            ) from exc
        if len(signature) != 64:
            raise ValueError("inventory authority Ed25519 signature must be 64 bytes")

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": INVENTORY_AUTHORITY_STATEMENT_SCHEMA,
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "scope_id": self.scope_id,
            "channel": self.channel,
            "inventory_manifest_digest": self.inventory_manifest_digest,
            "inventory_scope_binding_digest": self.inventory_scope_binding_digest,
            "environment": self.environment,
            "benchmark_revision": self.benchmark_revision,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "completeness_asserted_for_declared_inventory": self.completeness_asserted_for_declared_inventory,
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature_base64": self.signature_base64}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> InventoryAuthorityStatement:
        expected = {
            "schema",
            "authority_id",
            "key_id",
            "scope_id",
            "channel",
            "inventory_manifest_digest",
            "inventory_scope_binding_digest",
            "environment",
            "benchmark_revision",
            "issued_at",
            "expires_at",
            "completeness_asserted_for_declared_inventory",
            "inventory_completeness_proven",
            "open_world",
            "signature_base64",
        }
        if set(raw) != expected:
            raise ValueError(
                "inventory authority statement fields differ from closed schema"
            )
        if raw["schema"] != INVENTORY_AUTHORITY_STATEMENT_SCHEMA:
            raise ValueError("inventory authority statement schema mismatch")
        if (
            raw["inventory_completeness_proven"] is not False
            or raw["open_world"] is not False
        ):
            raise ValueError("inventory authority statement boundary changed")
        return cls(
            authority_id=raw["authority_id"],
            key_id=raw["key_id"],
            scope_id=raw["scope_id"],
            channel=raw["channel"],
            inventory_manifest_digest=raw["inventory_manifest_digest"],
            inventory_scope_binding_digest=raw["inventory_scope_binding_digest"],
            environment=raw["environment"],
            benchmark_revision=raw["benchmark_revision"],
            issued_at=raw["issued_at"],
            expires_at=raw["expires_at"],
            completeness_asserted_for_declared_inventory=raw[
                "completeness_asserted_for_declared_inventory"
            ],
            signature_base64=raw["signature_base64"],
        )

    @property
    def statement_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class InventoryAuthorityTrustContext:
    authority_public_keys: Mapping[str, bytes]
    accepted_authority_ids: frozenset[str]
    expected_environment: str
    expected_benchmark_revision: str
    verification_time: int
    openssl_path: str
    openssl_sha256: str

    def __post_init__(self) -> None:
        if not self.authority_public_keys or not self.accepted_authority_ids:
            raise ValueError("inventory authority trust roots must be non-empty")
        keys: dict[str, bytes] = {}
        for key_id, public_key in self.authority_public_keys.items():
            if not isinstance(key_id, str) or not key_id.startswith("sha256:"):
                raise ValueError("inventory authority trust key id is invalid")
            if not isinstance(public_key, bytes) or not public_key:
                raise ValueError("inventory authority public key must be bytes")
            digest = hashlib.sha256(public_key).hexdigest()
            if key_id != f"sha256:{digest}":
                raise ValueError("inventory authority public key digest mismatch")
            keys[key_id] = bytes(public_key)
        for label, value in (
            ("expected_environment", self.expected_environment),
            ("expected_benchmark_revision", self.expected_benchmark_revision),
            ("openssl_path", self.openssl_path),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"inventory authority trust {label} must be non-empty")
        if (
            not isinstance(self.verification_time, int)
            or isinstance(self.verification_time, bool)
            or self.verification_time < 0
        ):
            raise ValueError("inventory authority verification time is invalid")
        if not isinstance(self.openssl_sha256, str) or not _DIGEST.fullmatch(
            self.openssl_sha256
        ):
            raise ValueError("inventory authority OpenSSL digest is invalid")
        object.__setattr__(self, "authority_public_keys", MappingProxyType(keys))
        object.__setattr__(
            self, "accepted_authority_ids", frozenset(self.accepted_authority_ids)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-inventory-authority-trust-context-v1",
            "authority_public_key_sha256": {
                key_id: hashlib.sha256(value).hexdigest()
                for key_id, value in sorted(self.authority_public_keys.items())
            },
            "accepted_authority_ids": sorted(self.accepted_authority_ids),
            "expected_environment": self.expected_environment,
            "expected_benchmark_revision": self.expected_benchmark_revision,
            "verification_time": self.verification_time,
            "openssl_ref": self.openssl_path,
            "openssl_sha256": self.openssl_sha256,
        }

    @property
    def trust_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class InventoryAuthorityVerificationResult:
    statement_digest: str
    authority_id: str
    key_id: str
    valid: bool
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": INVENTORY_AUTHORITY_RESULT_SCHEMA,
            "statement_digest": self.statement_digest,
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "valid": self.valid,
            "errors": list(self.errors),
            "inventory_completeness_attested": self.valid,
            "inventory_completeness_proven": False,
            "open_world": False,
        }


def _openssl_sign(openssl: Path, private_key: Path, payload: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="auditspec-inventory-sign-") as directory:
        root = Path(directory)
        payload_path = root / "statement.json"
        signature_path = root / "signature.bin"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                str(openssl),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return base64.b64encode(signature_path.read_bytes()).decode("ascii")


def _openssl_verify(
    openssl: Path,
    public_key: bytes,
    payload: bytes,
    signature_base64: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="auditspec-inventory-verify-") as directory:
        root = Path(directory)
        key_path = root / "authority-public.pem"
        payload_path = root / "statement.json"
        signature_path = root / "signature.bin"
        key_path.write_bytes(public_key)
        payload_path.write_bytes(payload)
        signature_path.write_bytes(base64.b64decode(signature_base64, validate=True))
        subprocess.run(
            [
                str(openssl),
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(key_path),
                "-sigfile",
                str(signature_path),
                "-in",
                str(payload_path),
            ],
            check=True,
            capture_output=True,
        )


def sign_inventory_authority_statement(
    *,
    authority_id: str,
    key_id: str,
    scope_id: str,
    channel: str,
    inventory_manifest: Mapping[str, Any],
    environment: str,
    benchmark_revision: str,
    issued_at: int,
    expires_at: int,
    private_key: Path,
    openssl: Path,
) -> InventoryAuthorityStatement:
    unsigned = InventoryAuthorityStatement(
        authority_id=authority_id,
        key_id=key_id,
        scope_id=scope_id,
        channel=channel,
        inventory_manifest_digest=_digest(dict(inventory_manifest)),
        inventory_scope_binding_digest=inventory_scope_binding_digest(
            scope_id=scope_id,
            channel=channel,
            inventory_manifest=inventory_manifest,
        ),
        environment=environment,
        benchmark_revision=benchmark_revision,
        issued_at=issued_at,
        expires_at=expires_at,
        completeness_asserted_for_declared_inventory=True,
        signature_base64=base64.b64encode(b"\x00" * 64).decode("ascii"),
    )
    signature = _openssl_sign(
        openssl, private_key, _canonical_bytes(unsigned.unsigned_dict())
    )
    return InventoryAuthorityStatement(
        **{
            **{
                key: value
                for key, value in unsigned.__dict__.items()
                if key != "signature_base64"
            },
            "signature_base64": signature,
        }
    )


def verify_inventory_authority_statement(
    statement: InventoryAuthorityStatement,
    *,
    scope_id: str,
    channel: str,
    inventory_manifest: Mapping[str, Any],
    trust: InventoryAuthorityTrustContext,
) -> InventoryAuthorityVerificationResult:
    errors: list[str] = []
    if statement.authority_id not in trust.accepted_authority_ids:
        errors.append("authority_id:not_accepted")
    public_key = trust.authority_public_keys.get(statement.key_id)
    if public_key is None:
        errors.append("key_id:not_trusted")
    if statement.scope_id != scope_id:
        errors.append("scope_id:mismatch")
    if statement.channel != channel:
        errors.append("channel:mismatch")
    expected_manifest_digest = _digest(dict(inventory_manifest))
    if statement.inventory_manifest_digest != expected_manifest_digest:
        errors.append("inventory_manifest_digest:mismatch")
    expected_scope_digest = inventory_scope_binding_digest(
        scope_id=scope_id,
        channel=channel,
        inventory_manifest=inventory_manifest,
    )
    if statement.inventory_scope_binding_digest != expected_scope_digest:
        errors.append("inventory_scope_binding_digest:mismatch")
    if statement.environment != trust.expected_environment:
        errors.append("environment:mismatch")
    if statement.benchmark_revision != trust.expected_benchmark_revision:
        errors.append("benchmark_revision:mismatch")
    if trust.verification_time < statement.issued_at:
        errors.append("validity:not_yet_valid")
    if trust.verification_time >= statement.expires_at:
        errors.append("validity:expired")
    openssl = Path(trust.openssl_path)
    if not openssl.is_file() or openssl.is_symlink():
        errors.append("openssl:missing_or_symlink")
    elif _file_digest(openssl) != trust.openssl_sha256:
        errors.append("openssl:digest_mismatch")
    if not errors and public_key is not None:
        try:
            _openssl_verify(
                openssl,
                public_key,
                _canonical_bytes(statement.unsigned_dict()),
                statement.signature_base64,
            )
        except (OSError, subprocess.CalledProcessError, ValueError):
            errors.append("signature:invalid")
    return InventoryAuthorityVerificationResult(
        statement_digest=statement.statement_digest,
        authority_id=statement.authority_id,
        key_id=statement.key_id,
        valid=not errors,
        errors=tuple(errors),
    )
