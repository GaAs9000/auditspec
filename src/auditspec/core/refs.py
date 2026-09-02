"""Content-bound references and a local Phase-1 registry resolver.

The resolver enforces exact id/schema/bytes/root membership.  Its registry
container is source-pinned rather than a deployed SP-2 authority package; that
limitation is surfaced by the pipeline and is why this slice emits no Result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .canonical import digest
from .wire import require_digest, require_ref


class ReferenceError(ValueError):
    pass


@dataclass(frozen=True)
class AuthenticatedPackageRef:
    id: str
    object_payload_digest: str
    package_root: str

    def __post_init__(self) -> None:
        require_ref(self.id, "package.id")
        require_digest(self.object_payload_digest, "package.object_payload_digest")
        require_digest(self.package_root, "package.package_root")

    def to_wire(self) -> dict[str, str]:
        return {
            "id": self.id,
            "object_payload_digest": self.object_payload_digest,
            "package_root": self.package_root,
        }


@dataclass(frozen=True)
class RootedRef:
    id: str
    payload_digest: str
    registry: AuthenticatedPackageRef

    def __post_init__(self) -> None:
        require_ref(self.id, "rooted_ref.id")
        require_digest(self.payload_digest, "rooted_ref.payload_digest")

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "payload_digest": self.payload_digest,
            "registry": self.registry.to_wire(),
        }


@dataclass(frozen=True)
class RegistryRecord:
    id: str
    schema: str
    object: dict[str, Any]
    payload_digest: str


@dataclass(frozen=True)
class RegistryPackage:
    registry_id: str
    registry_kind: str
    records: tuple[RegistryRecord, ...]
    record_set_root: str
    package_ref: AuthenticatedPackageRef


class RegistryStore:
    """Exact immutable record resolver for design-time objects."""

    def __init__(self) -> None:
        self._packages: dict[str, RegistryPackage] = {}

    def register(
        self,
        registry_id: str,
        registry_kind: str,
        records: Iterable[dict[str, Any]],
    ) -> dict[str, RootedRef]:
        require_ref(registry_id, "registry_id")
        materialized: list[RegistryRecord] = []
        seen: set[str] = set()
        for raw in records:
            if not isinstance(raw, dict) or not isinstance(raw.get("schema"), str):
                raise ReferenceError("registry record requires schema")
            identity = _record_identity(raw)
            require_ref(identity, "registry record id")
            if identity in seen:
                raise ReferenceError(f"duplicate registry record id: {identity}")
            seen.add(identity)
            payload_digest = digest(
                "AuditSpec-unsigned-record-v1",
                {"schema": raw["schema"], "object": raw},
            )
            materialized.append(
                RegistryRecord(identity, raw["schema"], dict(raw), payload_digest)
            )
        materialized.sort(key=lambda item: item.id)
        rows = [
            {
                "id": item.id,
                "payload_digest": item.payload_digest,
                "schema": item.schema,
            }
            for item in materialized
        ]
        record_set_root = digest("AuditSpec-rooted-registry-record-set-v1", rows)
        payload = {
            "schema": "AuditSpec-core-phase1-source-pinned-registry-v1",
            "registry_id": registry_id,
            "registry_kind": registry_kind,
            "records": rows,
            "record_set_root": record_set_root,
            "authentication_status": "source_pinned_not_sp2_deployed",
        }
        object_payload_digest = digest(payload["schema"], payload)
        package_root = digest(
            "AuditSpec-core-phase1-source-pinned-registry-package-v1",
            {
                "registry_id": registry_id,
                "object_payload_digest": object_payload_digest,
                "records": rows,
            },
        )
        package_ref = AuthenticatedPackageRef(
            registry_id, object_payload_digest, package_root
        )
        package = RegistryPackage(
            registry_id,
            registry_kind,
            tuple(materialized),
            record_set_root,
            package_ref,
        )
        if package_root in self._packages:
            raise ReferenceError("registry package root reused")
        self._packages[package_root] = package
        return {
            item.id: RootedRef(item.id, item.payload_digest, package_ref)
            for item in materialized
        }

    def resolve(
        self, reference: RootedRef, *, expected_schema: str | None = None
    ) -> dict[str, Any]:
        package = self._packages.get(reference.registry.package_root)
        if package is None:
            raise ReferenceError("rooted_ref registry package is unknown")
        if package.package_ref != reference.registry:
            raise ReferenceError("rooted_ref registry package fields mismatch")
        matches = [item for item in package.records if item.id == reference.id]
        if len(matches) != 1:
            raise ReferenceError("rooted_ref membership is absent or ambiguous")
        record = matches[0]
        if record.payload_digest != reference.payload_digest:
            raise ReferenceError("rooted_ref payload digest mismatch")
        if _record_identity(record.object) != reference.id:
            raise ReferenceError("rooted_ref internal identity mismatch")
        recomputed = digest(
            "AuditSpec-unsigned-record-v1",
            {"schema": record.schema, "object": record.object},
        )
        if recomputed != reference.payload_digest:
            raise ReferenceError("rooted_ref record bytes changed")
        if expected_schema is not None and record.schema != expected_schema:
            raise ReferenceError("rooted_ref schema mismatch")
        return dict(record.object)

    def package(self, package_root: str) -> RegistryPackage:
        try:
            return self._packages[package_root]
        except KeyError as exc:
            raise ReferenceError("unknown registry package") from exc

    def export(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-core-phase1-registry-snapshot-v1",
            "authentication_status": "source_pinned_not_sp2_deployed",
            "registries": [
                {
                    "registry_id": package.registry_id,
                    "registry_kind": package.registry_kind,
                    "records": [dict(record.object) for record in package.records],
                    "record_set_root": package.record_set_root,
                    "package_ref": package.package_ref.to_wire(),
                }
                for package in sorted(
                    self._packages.values(), key=lambda item: item.registry_id
                )
            ],
        }

    @classmethod
    def from_export(cls, value: Any) -> "RegistryStore":
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "authentication_status",
            "registries",
        }:
            raise ReferenceError("registry snapshot key mismatch")
        if (
            value["schema"] != "AuditSpec-core-phase1-registry-snapshot-v1"
            or value["authentication_status"] != "source_pinned_not_sp2_deployed"
        ):
            raise ReferenceError("registry snapshot identity/boundary mismatch")
        if not isinstance(value["registries"], list):
            raise ReferenceError("registry snapshot registries must be a list")
        store = cls()
        seen_ids: set[str] = set()
        for row in value["registries"]:
            if not isinstance(row, dict) or set(row) != {
                "registry_id",
                "registry_kind",
                "records",
                "record_set_root",
                "package_ref",
            }:
                raise ReferenceError("registry snapshot row key mismatch")
            if row["registry_id"] in seen_ids:
                raise ReferenceError("duplicate registry id in snapshot")
            seen_ids.add(row["registry_id"])
            refs = store.register(
                row["registry_id"], row["registry_kind"], row["records"]
            )
            if refs:
                package = store.package(next(iter(refs.values())).registry.package_root)
            else:
                raise ReferenceError(
                    "empty source-pinned registries are not used by this slice"
                )
            if (
                package.record_set_root != row["record_set_root"]
                or package.package_ref.to_wire() != row["package_ref"]
            ):
                raise ReferenceError("registry snapshot root/package mismatch")
        return store


def _record_identity(record: dict[str, Any]) -> Any:
    identity_by_schema = {
        "AuditSpec-scoped-claim-v1": "scoped_claim_id",
        "AuditSpec-verified-contract-v1": "contract_id",
        "AuditSpec-core-installation-plan-v1": "plan_id",
        "AuditSpec-mechanism-spec-v1": "mechanism_id",
        "AuditSpec-trust-ir-v1": "trust_context_id",
        "AuditSpec-authority-record-v1": "authority_record_id",
        "AuditSpec-result-ledger-policy-v1": "policy_id",
    }
    field = identity_by_schema.get(str(record.get("schema")), "id")
    value = record.get(field)
    if value is None:
        raise ReferenceError(
            f"registry record lacks identity field {field!r} for its schema"
        )
    return value
