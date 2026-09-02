"""First-class exact-gate profiles for sealed and live official evaluation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .external.claims import CLAIM_REGISTRY
from .external.evidence import (
    EvidenceAttestation,
    ExternalEvidenceSource,
    ExternalTrustContext,
    IndependentVerifierWitness,
    ProjectedEvidence,
    project_external_evidence,
    sign_evidence_attestation,
)
from .isolated_verifier import (
    IsolationPolicy,
    _bubblewrap_command,
    _limit_process,
)
from .official_evaluator import (
    official_evaluator_registry_digest,
    verify_official_replay_row,
)
from .runtime.events import canonical_json

OFFICIAL_RECEIPT_PROFILE = "v14_official_execution_receipt"
OFFICIAL_LIVE_PROFILE = "v14_official_live_reexecution"
OFFICIAL_GATE_INVOCATION_SCHEMA = "AuditSpec-official-gate-invocation-v1"
OFFICIAL_GATE_CONTEXT_SCHEMA = "AuditSpec-official-gate-context-v1"
OFFICIAL_GATE_RECEIPT_SCHEMA = "AuditSpec-official-gate-execution-receipt-v1"
V14_GATE_INPUT_SCHEMA = "AuditSpec-v14-official-gate-input-manifest-v1"
V14_GATE_ROW_SCHEMA = "AuditSpec-v14-official-gate-input-row-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROFILES = frozenset({OFFICIAL_RECEIPT_PROFILE, OFFICIAL_LIVE_PROFILE})
_VERIFIER_IDS = MappingProxyType(
    {
        OFFICIAL_RECEIPT_PROFILE: "auditspec-v14-official-receipt-verifier-v1",
        OFFICIAL_LIVE_PROFILE: "auditspec-v14-official-live-verifier-v1",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_object(value: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"official gate {label} is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise TypeError(f"official gate {label} must be an object")
    return parsed


def _read_rows(value: bytes) -> tuple[dict[str, Any], ...]:
    try:
        rows = tuple(
            json.loads(line) for line in value.decode("utf-8").splitlines() if line
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("official gate sealed rows are not valid JSONL") from exc
    if any(not isinstance(row, dict) for row in rows):
        raise TypeError("official gate sealed row must be an object")
    return rows


def _claim_definition_payload(claim_id: str) -> dict[str, Any]:
    definition = CLAIM_REGISTRY[claim_id]
    return {
        "schema": "AuditSpec-v14-official-claim-definition-v1",
        "claim_id": definition.claim_id,
        "environment": definition.environment,
        "statement_template": definition.statement_template,
        "oracle_check_id": definition.oracle_check_id,
        "oracle_source": definition.oracle_source,
    }


@dataclass(frozen=True)
class OfficialGateInvocation:
    profile: str
    verifier_id: str
    environment: str
    run_id: str
    task_id: str
    claim_id: str
    gate_row_index: int
    gate_manifest_sha256: str
    gate_row_digest: str
    gate_row_bundle_root: str
    official_row_sha256: str
    source_input_manifest_sha256: str
    v13_artifact_sha256: str
    v13_result_bundle_root: str
    official_evaluator_registry_digest: str
    official_evaluator_manifest_digest: str
    claim_definition_digest: str
    claim_semantics_commitment: str
    declared_value: bool

    def __post_init__(self) -> None:
        if self.profile not in _PROFILES:
            raise ValueError("unsupported official gate profile")
        if self.verifier_id != _VERIFIER_IDS[self.profile]:
            raise ValueError("official gate verifier id/profile mismatch")
        if self.environment not in {"tau2", "appworld"}:
            raise ValueError("official gate environment is invalid")
        for label, value in (
            ("verifier_id", self.verifier_id),
            ("run_id", self.run_id),
            ("task_id", self.task_id),
            ("claim_id", self.claim_id),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"official gate {label} must be non-empty")
        if (
            not isinstance(self.gate_row_index, int)
            or isinstance(self.gate_row_index, bool)
            or self.gate_row_index < 0
        ):
            raise ValueError("official gate row index is invalid")
        for label, value in (
            ("gate_manifest_sha256", self.gate_manifest_sha256),
            ("gate_row_digest", self.gate_row_digest),
            ("gate_row_bundle_root", self.gate_row_bundle_root),
            ("official_row_sha256", self.official_row_sha256),
            ("source_input_manifest_sha256", self.source_input_manifest_sha256),
            ("v13_artifact_sha256", self.v13_artifact_sha256),
            ("v13_result_bundle_root", self.v13_result_bundle_root),
            (
                "official_evaluator_registry_digest",
                self.official_evaluator_registry_digest,
            ),
            (
                "official_evaluator_manifest_digest",
                self.official_evaluator_manifest_digest,
            ),
            ("claim_definition_digest", self.claim_definition_digest),
            ("claim_semantics_commitment", self.claim_semantics_commitment),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"official gate {label} must be a digest")
        if not isinstance(self.declared_value, bool):
            raise TypeError("official gate declared value must be Boolean")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": OFFICIAL_GATE_INVOCATION_SCHEMA,
            "profile": self.profile,
            "verifier_id": self.verifier_id,
            "environment": self.environment,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "claim_id": self.claim_id,
            "gate_row_index": self.gate_row_index,
            "gate_manifest_sha256": self.gate_manifest_sha256,
            "gate_row_digest": self.gate_row_digest,
            "gate_row_bundle_root": self.gate_row_bundle_root,
            "official_row_sha256": self.official_row_sha256,
            "source_input_manifest_sha256": self.source_input_manifest_sha256,
            "v13_artifact_sha256": self.v13_artifact_sha256,
            "v13_result_bundle_root": self.v13_result_bundle_root,
            "official_evaluator_registry_digest": self.official_evaluator_registry_digest,
            "official_evaluator_manifest_digest": self.official_evaluator_manifest_digest,
            "claim_definition_digest": self.claim_definition_digest,
            "claim_semantics_commitment": self.claim_semantics_commitment,
            "declared_value": self.declared_value,
            "evidence_migration_is_original_capture": False,
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    @property
    def invocation_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class OfficialGateContext:
    gate_manifest_bytes: bytes
    sealed_official_rows_bytes: bytes
    source_input_manifest_bytes: bytes
    v13_artifact_bytes: bytes
    authority_public_key: bytes
    openssl_path: str
    openssl_sha256: str
    official_worker_paths: Mapping[str, str]
    live_isolation_policies: Mapping[str, IsolationPolicy] | None = None
    server_root: str | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("gate_manifest_bytes", self.gate_manifest_bytes),
            ("sealed_official_rows_bytes", self.sealed_official_rows_bytes),
            ("source_input_manifest_bytes", self.source_input_manifest_bytes),
            ("v13_artifact_bytes", self.v13_artifact_bytes),
            ("authority_public_key", self.authority_public_key),
        ):
            if not isinstance(value, bytes) or not value:
                raise ValueError(f"official gate {label} must be non-empty bytes")
        openssl = Path(self.openssl_path)
        if not openssl.is_absolute() or not openssl.is_file() or openssl.is_symlink():
            raise ValueError("official gate OpenSSL path is invalid")
        if not _DIGEST.fullmatch(self.openssl_sha256):
            raise ValueError("official gate OpenSSL digest is invalid")
        workers = {
            name: str(Path(path).absolute())
            for name, path in self.official_worker_paths.items()
        }
        if set(workers) != {"tau2", "appworld"}:
            raise ValueError("official gate context needs both registered workers")
        for environment, path in workers.items():
            worker = Path(path)
            if not worker.is_file() or worker.is_symlink():
                raise ValueError(f"official gate {environment} worker is invalid")
        object.__setattr__(self, "official_worker_paths", MappingProxyType(workers))
        policies = dict(self.live_isolation_policies or {})
        if set(policies) - {"tau2", "appworld"}:
            raise ValueError("official gate live policy environment is invalid")
        object.__setattr__(self, "live_isolation_policies", MappingProxyType(policies))
        if policies and (
            self.server_root is None or not Path(self.server_root).is_absolute()
        ):
            raise ValueError("official gate live context needs an absolute server root")

    @cached_property
    def gate_manifest(self) -> dict[str, Any]:
        return _read_object(self.gate_manifest_bytes, "manifest")

    @cached_property
    def sealed_official_rows(self) -> tuple[dict[str, Any], ...]:
        return _read_rows(self.sealed_official_rows_bytes)

    @cached_property
    def source_input_manifest(self) -> dict[str, Any]:
        return _read_object(self.source_input_manifest_bytes, "source input manifest")

    @cached_property
    def v13_artifact(self) -> dict[str, Any]:
        return _read_object(self.v13_artifact_bytes, "v13 artifact")

    @cached_property
    def manifest_errors(self) -> tuple[str, ...]:
        return _official_gate_manifest_errors(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": OFFICIAL_GATE_CONTEXT_SCHEMA,
            "gate_manifest_sha256": _sha_bytes(self.gate_manifest_bytes),
            "sealed_official_rows_sha256": _sha_bytes(self.sealed_official_rows_bytes),
            "source_input_manifest_sha256": _sha_bytes(
                self.source_input_manifest_bytes
            ),
            "v13_artifact_sha256": _sha_bytes(self.v13_artifact_bytes),
            "authority_public_key_sha256": _sha_bytes(self.authority_public_key),
            "openssl_ref": self.openssl_path,
            "openssl_sha256": self.openssl_sha256,
            "official_worker_sha256": {
                environment: _file_digest(Path(path))
                for environment, path in sorted(self.official_worker_paths.items())
            },
            "live_isolation_policies": {
                environment: policy.as_dict()
                for environment, policy in sorted(
                    dict(self.live_isolation_policies).items()
                )
            },
            "server_root": self.server_root,
            "host_kernel_and_parent_orchestrator_in_tcb": True,
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    @property
    def context_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class OfficialGateExecutionReceipt:
    invocation_digest: str
    context_digest: str
    profile: str
    accepted: bool
    answer: bool | None
    errors: tuple[str, ...]
    gate_manifest_signature_valid: bool
    official_execution_receipt_valid: bool
    live_executed: bool
    live_row_sha256: str | None
    live_worker_metadata: Mapping[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": OFFICIAL_GATE_RECEIPT_SCHEMA,
            "invocation_digest": self.invocation_digest,
            "context_digest": self.context_digest,
            "profile": self.profile,
            "accepted": self.accepted,
            "answer": self.answer,
            "errors": list(self.errors),
            "gate_manifest_signature_valid": self.gate_manifest_signature_valid,
            "official_execution_receipt_valid": self.official_execution_receipt_valid,
            "official_evaluator_actual_execution": self.official_execution_receipt_valid,
            "live_executed": self.live_executed,
            "live_row_sha256": self.live_row_sha256,
            "live_worker_metadata": (
                dict(self.live_worker_metadata)
                if self.live_worker_metadata is not None
                else None
            ),
            "evidence_migration_is_original_capture": False,
            "inventory_completeness_proven": False,
            "open_world": False,
            "new_model_calls": 0,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.as_dict())


def _verify_ed25519(
    openssl: Path,
    public_key: bytes,
    payload: bytes,
    signature_base64: str,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="auditspec-official-gate-signature-"
    ) as name:
        root = Path(name)
        key_path = root / "authority.pem"
        payload_path = root / "payload.json"
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


def _official_gate_manifest_errors(context: OfficialGateContext) -> tuple[str, ...]:
    errors: list[str] = []
    manifest = context.gate_manifest
    expected_fields = {
        "schema",
        "protocol_version",
        "status",
        "source_lineage",
        "prior",
        "authority",
        "evidence_migration",
        "gate_inputs",
        "formal_result_rows",
        "new_model_calls",
        "unsigned_payload_sha256",
        "signature",
    }
    if set(manifest) != expected_fields:
        return ("gate_manifest:fields_mismatch",)
    if (
        manifest["schema"] != V14_GATE_INPUT_SCHEMA
        or manifest["status"] != "FROZEN_GATE_INPUTS_PRE_IMPLEMENTATION"
        or manifest["formal_result_rows"] != 0
        or manifest["new_model_calls"] != 0
    ):
        errors.append("gate_manifest:boundary_mismatch")
    unsigned = {
        key: manifest[key]
        for key in expected_fields - {"signature", "unsigned_payload_sha256"}
    }
    payload = _canonical_bytes(unsigned)
    if manifest["unsigned_payload_sha256"] != _sha_bytes(payload):
        errors.append("gate_manifest:unsigned_digest_mismatch")
    signature = manifest["signature"]
    authority = manifest["authority"]
    if not (
        isinstance(signature, Mapping)
        and set(signature) == {"algorithm", "key_id", "value_base64"}
        and signature["algorithm"] == "Ed25519"
        and signature["key_id"] == authority["key_id"]
        and authority["public_key_sha256"] == _sha_bytes(context.authority_public_key)
        and authority["institutionally_independent"] is False
        and authority["inventory_completeness_proven"] is False
    ):
        errors.append("gate_manifest:authority_binding_mismatch")
    if _file_digest(Path(context.openssl_path)) != context.openssl_sha256:
        errors.append("gate_manifest:openssl_digest_mismatch")
    if not errors:
        try:
            _verify_ed25519(
                Path(context.openssl_path),
                context.authority_public_key,
                payload,
                signature["value_base64"],
            )
        except (OSError, ValueError, subprocess.CalledProcessError):
            errors.append("gate_manifest:signature_invalid")
    gate = manifest["gate_inputs"]
    if not (
        isinstance(gate, Mapping)
        and gate.get("counts") == {"total": 1076, "tau2": 537, "appworld": 539}
        and isinstance(gate.get("rows"), list)
        and len(gate["rows"]) == 1076
        and gate.get("gate_row_bundle_root") == _digest(gate["rows"])
    ):
        errors.append("gate_manifest:population_mismatch")
    if manifest["prior"]["official_rows_sha256"] != _sha_bytes(
        context.sealed_official_rows_bytes
    ):
        errors.append("gate_manifest:sealed_rows_digest_mismatch")
    if manifest["prior"]["artifact_root_sha256"] != _sha_bytes(
        context.v13_artifact_bytes
    ):
        errors.append("gate_manifest:v13_artifact_digest_mismatch")
    if manifest["prior"].get("result_bundle_root") != context.v13_artifact.get(
        "result_bundle_root"
    ):
        errors.append("gate_manifest:v13_result_bundle_mismatch")
    if context.v13_artifact.get("official_input_manifest_sha256") != _sha_bytes(
        context.source_input_manifest_bytes
    ):
        errors.append("gate_manifest:source_input_manifest_digest_mismatch")
    if (
        manifest["evidence_migration"].get("presented_as_original_benchmark_capture")
        is not False
    ):
        errors.append("gate_manifest:migration_disclosure_mismatch")
    workers = {name: Path(path) for name, path in context.official_worker_paths.items()}
    try:
        registry_digest = official_evaluator_registry_digest(workers)
    except (OSError, TypeError, ValueError):
        errors.append("gate_manifest:official_registry_invalid")
    else:
        if gate.get("official_evaluator_registry_digest") != registry_digest:
            errors.append("gate_manifest:official_registry_digest_mismatch")
    for environment, policy in dict(context.live_isolation_policies).items():
        if not (
            policy.backend == "bubblewrap"
            and Path(policy.worker_path).absolute()
            == Path(context.official_worker_paths[environment]).absolute()
            and policy.worker_sha256
            == _file_digest(Path(context.official_worker_paths[environment]))
        ):
            errors.append(f"gate_manifest:{environment}_live_policy_mismatch")
    return tuple(errors)


def official_gate_context_errors(context: OfficialGateContext) -> tuple[str, ...]:
    return context.manifest_errors


def official_gate_trust_errors(
    invocation: OfficialGateInvocation,
    context: OfficialGateContext,
    trust: ExternalTrustContext,
) -> tuple[str, ...]:
    errors: list[str] = []
    migration = context.gate_manifest["evidence_migration"]
    producer = migration["producer"]
    producer_key = trust.producer_keys.get(producer)
    if producer_key is None:
        errors.append("official_gate_trust:migrator_key_missing")
    elif _sha_bytes(producer_key) != migration["hmac_key_sha256"]:
        errors.append("official_gate_trust:migrator_key_digest_mismatch")
    if migration["capture_point"] not in trust.accepted_capture_points:
        errors.append("official_gate_trust:migration_capture_point_missing")
    if invocation.verifier_id not in trust.accepted_verifiers:
        errors.append("official_gate_trust:verifier_missing")
    expected_channel = (
        "tau2-tool-dispatch"
        if invocation.environment == "tau2"
        else "appworld-api-dispatch"
    )
    if trust.mandatory_coverage_channel != expected_channel:
        errors.append("official_gate_trust:coverage_channel_mismatch")
    if (
        trust.expected_claim_semantics_commitments.get(invocation.claim_id)
        != invocation.claim_semantics_commitment
    ):
        errors.append("official_gate_trust:claim_semantics_mismatch")
    return tuple(errors)


def make_official_gate_invocation(
    context: OfficialGateContext,
    *,
    gate_row_index: int,
    claim_semantics_commitment: str,
    profile: str,
    claim_id: str | None = None,
) -> OfficialGateInvocation:
    if profile not in _PROFILES:
        raise ValueError("unsupported official gate profile")
    rows = context.gate_manifest["gate_inputs"]["rows"]
    if gate_row_index < 0 or gate_row_index >= len(rows):
        raise ValueError("official gate row index is outside the signed population")
    row = rows[gate_row_index]
    sealed_row = context.sealed_official_rows[gate_row_index]
    selected_claim = claim_id or row["claim_id"]
    definition = CLAIM_REGISTRY.get(selected_claim)
    claim = sealed_row.get("official_claims", {}).get(selected_claim)
    declared = sealed_row.get("signed_witnesses", {}).get(selected_claim)
    if not (
        definition is not None
        and definition.environment == row["environment"]
        and isinstance(claim, Mapping)
        and claim.get("applicable") is True
        and isinstance(claim.get("value"), bool)
        and claim.get("value") is declared
    ):
        raise ValueError(
            "official gate selected claim is not an applicable sealed claim"
        )
    claim_definition = _claim_definition_payload(selected_claim)
    return OfficialGateInvocation(
        profile=profile,
        verifier_id=_VERIFIER_IDS[profile],
        environment=row["environment"],
        run_id=row["run_id"],
        task_id=row["task_id"],
        claim_id=selected_claim,
        gate_row_index=gate_row_index,
        gate_manifest_sha256=_sha_bytes(context.gate_manifest_bytes),
        gate_row_digest=_digest(row),
        gate_row_bundle_root=context.gate_manifest["gate_inputs"][
            "gate_row_bundle_root"
        ],
        official_row_sha256=row["official_row_sha256"],
        source_input_manifest_sha256=_sha_bytes(context.source_input_manifest_bytes),
        v13_artifact_sha256=row["v13_artifact_sha256"],
        v13_result_bundle_root=row["v13_result_bundle_root"],
        official_evaluator_registry_digest=row["official_evaluator_registry_digest"],
        official_evaluator_manifest_digest=row["official_evaluator_manifest_digest"],
        claim_definition_digest=_digest(claim_definition),
        claim_semantics_commitment=claim_semantics_commitment,
        declared_value=declared,
    )


def _eligible_source_rows(
    context: OfficialGateContext,
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        row
        for row in context.source_input_manifest["official_inputs"]["rows"]
        if row["replay_eligible"] is True
    )


def _run_live_row(
    invocation: OfficialGateInvocation,
    context: OfficialGateContext,
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    policy = dict(context.live_isolation_policies).get(invocation.environment)
    if policy is None or context.server_root is None:
        return None, ("official_live:policy_or_server_root_missing",)
    environment_index = sum(
        1
        for row in context.gate_manifest["gate_inputs"]["rows"][
            : invocation.gate_row_index
        ]
        if row["environment"] == invocation.environment
    )
    with tempfile.TemporaryDirectory(prefix="auditspec-official-gate-live-") as name:
        root = Path(name)
        input_dir = root / "input"
        output_dir = root / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        input_path = input_dir / "manifest.json"
        output_path = output_dir / "row.json"
        input_path.write_bytes(context.source_input_manifest_bytes)
        command = _bubblewrap_command(
            policy,
            [
                policy.python_path,
                policy.worker_path,
                "--one-row",
                str(input_path),
                context.server_root,
                str(environment_index),
                str(output_path),
            ],
            input_dir=input_dir,
            output_dir=output_dir,
        )
        clean_environment = {
            "HOME": str(root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            **dict(policy.environment),
        }
        started = time.monotonic_ns()
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_environment,
            start_new_session=True,
            preexec_fn=lambda: _limit_process(  # noqa: PLW1509
                policy.limits, strict=True
            ),
        )
        try:
            stdout, stderr = process.communicate(
                timeout=policy.limits.wall_clock_seconds
            )
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.communicate()
            return None, ("official_live:wall_clock_timeout",)
        if process.returncode != 0:
            return None, (
                f"official_live:return_code:{process.returncode}",
                f"official_live:stderr_sha256:{_sha_bytes(stderr)}",
            )
        if stdout:
            return None, ("official_live:unexpected_stdout",)
        if not output_path.is_file() or output_path.is_symlink():
            return None, ("official_live:output_missing",)
        try:
            result = _read_object(output_path.read_bytes(), "live result")
        except (OSError, TypeError, ValueError) as exc:
            return None, (f"official_live:invalid_result:{type(exc).__name__}",)
    result["gate_wall_time_ms"] = (time.monotonic_ns() - started) // 1_000_000
    return result, ()


def execute_official_gate(
    invocation: OfficialGateInvocation,
    context: OfficialGateContext,
    evidence_payload: Mapping[str, Any],
) -> OfficialGateExecutionReceipt:
    errors = list(context.manifest_errors)
    manifest_signature_valid = not errors
    if invocation.gate_manifest_sha256 != _sha_bytes(context.gate_manifest_bytes):
        errors.append("official_gate:manifest_digest_mismatch")
    if invocation.source_input_manifest_sha256 != _sha_bytes(
        context.source_input_manifest_bytes
    ):
        errors.append("official_gate:source_input_manifest_digest_mismatch")
    if invocation.v13_artifact_sha256 != _sha_bytes(context.v13_artifact_bytes):
        errors.append("official_gate:v13_artifact_context_digest_mismatch")
    rows = context.gate_manifest.get("gate_inputs", {}).get("rows", [])
    if invocation.gate_row_index >= len(rows):
        errors.append("official_gate:row_index_outside_population")
        gate_row: Mapping[str, Any] | None = None
    else:
        gate_row = rows[invocation.gate_row_index]
    sealed_rows = context.sealed_official_rows
    source_rows = _eligible_source_rows(context)
    if invocation.gate_row_index >= len(
        sealed_rows
    ) or invocation.gate_row_index >= len(source_rows):
        errors.append("official_gate:sealed_or_source_row_missing")
        sealed_row = None
        source_row = None
    else:
        sealed_row = sealed_rows[invocation.gate_row_index]
        source_row = source_rows[invocation.gate_row_index]
    expected_identity = {
        "environment": invocation.environment,
        "run_id": invocation.run_id,
        "task_id": invocation.task_id,
    }
    if gate_row is not None:
        for name, expected in expected_identity.items():
            if gate_row.get(name) != expected:
                errors.append(f"official_gate:{name}_mismatch")
        bindings = {
            "gate_row_digest": _digest(gate_row),
            "gate_row_bundle_root": context.gate_manifest["gate_inputs"].get(
                "gate_row_bundle_root"
            ),
            "official_row_sha256": gate_row.get("official_row_sha256"),
            "v13_artifact_sha256": gate_row.get("v13_artifact_sha256"),
            "v13_result_bundle_root": gate_row.get("v13_result_bundle_root"),
            "official_evaluator_registry_digest": gate_row.get(
                "official_evaluator_registry_digest"
            ),
            "official_evaluator_manifest_digest": gate_row.get(
                "official_evaluator_manifest_digest"
            ),
        }
        for name, actual in bindings.items():
            if getattr(invocation, name) != actual:
                errors.append(f"official_gate:{name}_mismatch")
        if (
            gate_row.get("claim_id") == invocation.claim_id
            and gate_row.get("declared_value") is not invocation.declared_value
        ):
            errors.append("official_gate:declared_value_mismatch")
        primary_definition = _claim_definition_payload(gate_row["claim_id"])
        if gate_row.get("claim_definition") != primary_definition or gate_row.get(
            "claim_definition_digest"
        ) != _digest(primary_definition):
            errors.append("official_gate:primary_claim_definition_stale")
        current_definition = _claim_definition_payload(invocation.claim_id)
        if invocation.claim_definition_digest != _digest(current_definition):
            errors.append("official_gate:claim_definition_stale")
        if gate_row.get("evidence_migration_is_original_capture") is not False:
            errors.append("official_gate:migration_disclosure_mismatch")
    official_receipt_valid = False
    if sealed_row is not None and source_row is not None and gate_row is not None:
        if _digest(source_row) != gate_row.get("source_input_row_sha256"):
            errors.append("official_gate:source_input_row_digest_mismatch")
        sealed_digest_matches = _digest(sealed_row) == gate_row.get(
            "official_row_sha256"
        )
        if not sealed_digest_matches:
            errors.append("official_gate:sealed_row_digest_mismatch")
        row_errors = verify_official_replay_row(sealed_row, source_row)
        errors.extend(f"official_gate:sealed_row:{error}" for error in row_errors)
        official_receipt_valid = sealed_digest_matches and not row_errors
        claim = sealed_row.get("official_claims", {}).get(invocation.claim_id)
        witness_value = sealed_row.get("signed_witnesses", {}).get(invocation.claim_id)
        if not (
            isinstance(claim, Mapping)
            and claim.get("applicable") is True
            and claim.get("value") is invocation.declared_value
            and witness_value is invocation.declared_value
        ):
            errors.append("official_gate:sealed_claim_or_witness_mismatch")
    witness = evidence_payload.get("verification_witness")
    if not isinstance(witness, Mapping):
        errors.append("official_gate:migrated_witness_missing")
    else:
        expected_witness = {
            "claim_id": invocation.claim_id,
            "declared_value": invocation.declared_value,
            "verifier_id": invocation.verifier_id,
            "replay_id": f"v14:{invocation.gate_row_digest}",
            "claim_semantics_commitment": invocation.claim_semantics_commitment,
        }
        for name, expected in expected_witness.items():
            if witness.get(name) != expected:
                errors.append(f"official_gate:witness_{name}_mismatch")
        components = witness.get("evidence_components")
        if not isinstance(components, Mapping) or not (
            components.get("gate_row_digest") == invocation.gate_row_digest
            and components.get("official_row_sha256") == invocation.official_row_sha256
            and components.get("v13_artifact_sha256") == invocation.v13_artifact_sha256
            and components.get("original_evidence_sha256")
            == gate_row.get("original_evidence_sha256")
            and components.get("evidence_migration_is_original_capture") is False
        ):
            errors.append("official_gate:witness_components_mismatch")
    live_row: dict[str, Any] | None = None
    live_errors: tuple[str, ...] = ()
    if invocation.profile == OFFICIAL_LIVE_PROFILE and not errors:
        live_row, live_errors = _run_live_row(invocation, context)
        errors.extend(live_errors)
        if live_row is not None and source_row is not None and sealed_row is not None:
            live_for_verification = dict(live_row)
            live_for_verification.pop("gate_wall_time_ms", None)
            row_errors = verify_official_replay_row(live_for_verification, source_row)
            errors.extend(f"official_gate:live_row:{error}" for error in row_errors)
            for name in (
                "environment",
                "run_id",
                "task_id",
                "status",
                "official_task_success",
                "official_claims",
                "signed_witnesses",
                "new_model_calls",
            ):
                if live_for_verification.get(name) != sealed_row.get(name):
                    errors.append(f"official_gate:live_sealed_{name}_mismatch")
    accepted = not errors
    return OfficialGateExecutionReceipt(
        invocation_digest=invocation.invocation_digest,
        context_digest=context.context_digest,
        profile=invocation.profile,
        accepted=accepted,
        answer=invocation.declared_value if accepted else None,
        errors=tuple(errors),
        gate_manifest_signature_valid=manifest_signature_valid,
        official_execution_receipt_valid=official_receipt_valid,
        live_executed=live_row is not None and not live_errors,
        live_row_sha256=(_digest(live_row) if live_row is not None else None),
        live_worker_metadata=(
            live_row.get("worker_metadata") if live_row is not None else None
        ),
    )


def migrate_official_gate_evidence(
    invocation: OfficialGateInvocation,
    context: OfficialGateContext,
    *,
    producer_key: bytes,
) -> tuple[ProjectedEvidence, ExternalTrustContext]:
    if not producer_key:
        raise ValueError("official gate migration producer key is empty")
    gate_row = context.gate_manifest["gate_inputs"]["rows"][invocation.gate_row_index]
    migration = context.gate_manifest["evidence_migration"]
    if _sha_bytes(producer_key) != migration["hmac_key_sha256"]:
        raise ValueError("official gate migration producer key digest mismatch")
    benchmark_revision = context.source_input_manifest["official_inputs"][
        "environment_runtime"
    ][invocation.environment]["checkout_commit"]
    coverage_channel = (
        "tau2-tool-dispatch"
        if invocation.environment == "tau2"
        else "appworld-api-dispatch"
    )
    replay_id = f"v14:{invocation.gate_row_digest}"
    witness_id = f"{invocation.run_id}:{invocation.claim_id}:{replay_id}"
    definition = CLAIM_REGISTRY[invocation.claim_id]
    witness = IndependentVerifierWitness(
        witness_id=witness_id,
        claim_id=invocation.claim_id,
        statement=definition.statement_template,
        declared_value=invocation.declared_value,
        verifier_id=invocation.verifier_id,
        replay_id=replay_id,
        computation="sealed-official-evaluator-execution-receipt-v1",
        evidence_components={
            "gate_row_index": invocation.gate_row_index,
            "gate_row_digest": invocation.gate_row_digest,
            "official_row_sha256": invocation.official_row_sha256,
            "original_evidence_sha256": gate_row["original_evidence_sha256"],
            "claim_definition_digest": invocation.claim_definition_digest,
            "v13_artifact_sha256": invocation.v13_artifact_sha256,
            "evidence_migration_is_original_capture": False,
        },
        claim_semantics_commitment=invocation.claim_semantics_commitment,
    )
    unsigned = EvidenceAttestation(
        run_id=invocation.run_id,
        task_id=invocation.task_id,
        claim_id=invocation.claim_id,
        benchmark_revision=benchmark_revision,
        witness_id=witness_id,
        producer=migration["producer"],
        capture_point=migration["capture_point"],
        verifier_id=invocation.verifier_id,
        binding_edges=(
            ("run", "task"),
            ("run", "claim"),
            ("run", "verifier_witness"),
            ("task", "benchmark_revision"),
        ),
        coverage_channel=coverage_channel,
        coverage_complete=True,
        claim_result=invocation.declared_value,
        claim_semantics_commitment=invocation.claim_semantics_commitment,
    )
    attestation = sign_evidence_attestation(unsigned, witness, producer_key)
    source = ExternalEvidenceSource(
        environment=invocation.environment,
        run_id=invocation.run_id,
        task_id=invocation.task_id,
        benchmark_revision=benchmark_revision,
        witnesses={invocation.claim_id: witness},
        attestations={invocation.claim_id: attestation},
    )
    evidence = project_external_evidence(
        source,
        invocation.claim_id,
        "auditspec_compiled_contract",
    )
    trust = ExternalTrustContext(
        environment=invocation.environment,
        benchmark_revision=benchmark_revision,
        expected_run_id=invocation.run_id,
        expected_task_id=invocation.task_id,
        producer_keys={migration["producer"]: producer_key},
        accepted_capture_points=frozenset({migration["capture_point"]}),
        accepted_verifiers=frozenset({invocation.verifier_id}),
        mandatory_coverage_channel=coverage_channel,
        expected_claim_semantics_commitments={
            invocation.claim_id: invocation.claim_semantics_commitment
        },
    )
    return evidence, trust
