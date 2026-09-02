"""Closed registered-verifier execution in a resource-bounded subprocess."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .runtime.events import canonical_json

ISOLATED_REGISTRY_SCHEMA = "AuditSpec-isolated-verifier-registry-v1"
ISOLATED_INVOCATION_SCHEMA = "AuditSpec-isolated-verifier-invocation-v1"
ISOLATION_POLICY_SCHEMA = "AuditSpec-isolation-policy-v1"
ISOLATED_RECEIPT_SCHEMA = "AuditSpec-isolated-verifier-execution-receipt-v1"
WORKER_REQUEST_SCHEMA = "AuditSpec-isolated-verifier-worker-request-v1"
WORKER_RESULT_SCHEMA = "AuditSpec-isolated-verifier-worker-result-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_ENVIRONMENT = frozenset(
    {
        "APPWORLD_ROOT",
        "LANG",
        "LC_ALL",
        "LITELLM_LOCAL_MODEL_COST_MAP",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "TAU2_DATA_DIR",
    }
)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(canonical_json(value))


def default_worker_path() -> Path:
    return Path(__file__).with_name("verifier_worker.py").resolve()


@dataclass(frozen=True)
class IsolatedVerifierManifest:
    verifier_id: str
    version: str
    input_schema: str
    min_items: int
    max_items: int
    max_fuel: int
    input_extractor_id: str
    worker_behavior: str
    worker_source_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verifier_id": self.verifier_id,
            "version": self.version,
            "input_schema": self.input_schema,
            "min_items": self.min_items,
            "max_items": self.max_items,
            "max_fuel": self.max_fuel,
            "input_extractor_id": self.input_extractor_id,
            "worker_behavior": self.worker_behavior,
            "worker_source_digest": self.worker_source_digest,
        }


def _manifest(
    verifier_id: str,
    *,
    input_schema: str,
    min_items: int,
    max_items: int,
    max_fuel: int,
    input_extractor_id: str,
) -> IsolatedVerifierManifest:
    worker = default_worker_path()
    return IsolatedVerifierManifest(
        verifier_id=verifier_id,
        version="1.0.0",
        input_schema=input_schema,
        min_items=min_items,
        max_items=max_items,
        max_fuel=max_fuel,
        input_extractor_id=input_extractor_id,
        worker_behavior=verifier_id,
        worker_source_digest=_file_digest(worker),
    )


ISOLATED_VERIFIERS: Mapping[str, IsolatedVerifierManifest] = MappingProxyType(
    {
        verifier_id: _manifest(
            verifier_id,
            input_schema=input_schema,
            min_items=min_items,
            max_items=max_items,
            max_fuel=max_fuel,
            input_extractor_id=extractor,
        )
        for verifier_id, input_schema, min_items, max_items, max_fuel, extractor in (
            (
                "auditspec-all-boolean-checks-isolated-v1",
                "AuditSpec-all-boolean-checks-input-v1",
                1,
                4096,
                4096,
                "retained-witness-checks-v1",
            ),
            (
                "auditspec-isolation-namespace-probe-v1",
                "AuditSpec-isolation-namespace-probe-input-v1",
                1,
                1,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-sleep-test-v1",
                "AuditSpec-isolation-sleep-input-v1",
                1,
                1,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-cpu-test-v1",
                "AuditSpec-isolation-empty-input-v1",
                0,
                0,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-memory-test-v1",
                "AuditSpec-isolation-empty-input-v1",
                0,
                0,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-output-test-v1",
                "AuditSpec-isolation-output-input-v1",
                1,
                1,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-nonzero-test-v1",
                "AuditSpec-isolation-empty-input-v1",
                0,
                0,
                1,
                "closed-test-fixture-v1",
            ),
            (
                "auditspec-isolation-invalid-json-test-v1",
                "AuditSpec-isolation-empty-input-v1",
                0,
                0,
                1,
                "closed-test-fixture-v1",
            ),
        )
    }
)


def isolated_registry_digest() -> str:
    return _digest(
        {
            "schema": ISOLATED_REGISTRY_SCHEMA,
            "verifiers": {
                name: manifest.as_dict()
                for name, manifest in sorted(ISOLATED_VERIFIERS.items())
            },
        }
    )


def isolated_manifest_digest(verifier_id: str) -> str | None:
    manifest = ISOLATED_VERIFIERS.get(verifier_id)
    return _digest(manifest.as_dict()) if manifest is not None else None


def _payload_item_count(verifier_id: str, payload: object) -> int:
    if type(payload) is not dict:
        raise TypeError("isolated verifier payload must be a built-in dict")
    if verifier_id == "auditspec-all-boolean-checks-isolated-v1":
        if set(payload) != {"checks"} or type(payload["checks"]) is not list:
            raise ValueError("isolated Boolean payload differs from closed schema")
        if any(type(value) is not bool for value in payload["checks"]):
            raise TypeError("isolated Boolean checks must be Boolean")
        return len(payload["checks"])
    if verifier_id == "auditspec-isolation-namespace-probe-v1":
        if payload != {"probe": True}:
            raise ValueError("namespace probe payload differs from closed schema")
        return 1
    if verifier_id == "auditspec-isolation-sleep-test-v1":
        if set(payload) != {"seconds"} or not isinstance(payload["seconds"], int):
            raise ValueError("sleep payload differs from closed schema")
        return 1
    if verifier_id == "auditspec-isolation-output-test-v1":
        if set(payload) != {"bytes"} or not isinstance(payload["bytes"], int):
            raise ValueError("output payload differs from closed schema")
        return 1
    if payload:
        raise ValueError("isolated fixture requires an empty payload")
    return 0


@dataclass(frozen=True)
class IsolatedVerifierInvocation:
    verifier_id: str
    verifier_version: str
    verifier_manifest_digest: str
    registry_digest: str
    claim_id: str
    replay_id: str
    input_schema: str
    input_extractor_id: str
    input_payload_digest: str
    fuel: int

    def __post_init__(self) -> None:
        for label, value in (
            ("verifier_id", self.verifier_id),
            ("verifier_version", self.verifier_version),
            ("claim_id", self.claim_id),
            ("replay_id", self.replay_id),
            ("input_schema", self.input_schema),
            ("input_extractor_id", self.input_extractor_id),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"isolated invocation {label} must be non-empty")
        for label, value in (
            ("verifier_manifest_digest", self.verifier_manifest_digest),
            ("registry_digest", self.registry_digest),
            ("input_payload_digest", self.input_payload_digest),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"isolated invocation {label} must be a digest")
        if (
            not isinstance(self.fuel, int)
            or isinstance(self.fuel, bool)
            or self.fuel < 0
        ):
            raise ValueError("isolated invocation fuel is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": ISOLATED_INVOCATION_SCHEMA,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "verifier_manifest_digest": self.verifier_manifest_digest,
            "registry_digest": self.registry_digest,
            "claim_id": self.claim_id,
            "replay_id": self.replay_id,
            "input_schema": self.input_schema,
            "input_extractor_id": self.input_extractor_id,
            "input_payload_digest": self.input_payload_digest,
            "fuel": self.fuel,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> IsolatedVerifierInvocation:
        expected = {
            "schema",
            "verifier_id",
            "verifier_version",
            "verifier_manifest_digest",
            "registry_digest",
            "claim_id",
            "replay_id",
            "input_schema",
            "input_extractor_id",
            "input_payload_digest",
            "fuel",
        }
        if set(raw) != expected or raw.get("schema") != ISOLATED_INVOCATION_SCHEMA:
            raise ValueError("isolated invocation fields/schema differ")
        return cls(**{key: raw[key] for key in expected - {"schema"}})

    @property
    def invocation_digest(self) -> str:
        return _digest(self.as_dict())


def make_isolated_invocation(
    *,
    verifier_id: str,
    claim_id: str,
    replay_id: str,
    input_payload: Mapping[str, Any],
    fuel: int,
) -> IsolatedVerifierInvocation:
    manifest = ISOLATED_VERIFIERS[verifier_id]
    count = _payload_item_count(verifier_id, input_payload)
    if count < manifest.min_items or count > manifest.max_items:
        raise ValueError("isolated input item count is outside registered bounds")
    return IsolatedVerifierInvocation(
        verifier_id=verifier_id,
        verifier_version=manifest.version,
        verifier_manifest_digest=_digest(manifest.as_dict()),
        registry_digest=isolated_registry_digest(),
        claim_id=claim_id,
        replay_id=replay_id,
        input_schema=manifest.input_schema,
        input_extractor_id=manifest.input_extractor_id,
        input_payload_digest=_digest(dict(input_payload)),
        fuel=fuel,
    )


def extract_isolated_input(
    invocation: IsolatedVerifierInvocation,
    evidence_payload: Mapping[str, Any],
) -> dict[str, Any]:
    if invocation.input_extractor_id != "retained-witness-checks-v1":
        raise ValueError("isolated invocation is not evidence-derived")
    witness = evidence_payload.get("verification_witness")
    if not isinstance(witness, Mapping):
        raise TypeError("isolated verifier witness is missing")
    components = witness.get("evidence_components")
    if not isinstance(components, Mapping) or set(components) != {"checks"}:
        raise ValueError("isolated verifier evidence components differ")
    payload = {"checks": _json_copy(components["checks"])}
    _payload_item_count(invocation.verifier_id, payload)
    if _digest(payload) != invocation.input_payload_digest:
        raise ValueError("isolated verifier derived input digest mismatch")
    return payload


@dataclass(frozen=True)
class IsolationLimits:
    cpu_seconds: int
    address_space_bytes: int
    file_size_bytes: int
    open_files: int
    process_count: int
    wall_clock_seconds: float
    stderr_bytes: int = 65536

    def __post_init__(self) -> None:
        for label, value in (
            ("cpu_seconds", self.cpu_seconds),
            ("address_space_bytes", self.address_space_bytes),
            ("file_size_bytes", self.file_size_bytes),
            ("open_files", self.open_files),
            ("process_count", self.process_count),
            ("stderr_bytes", self.stderr_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"isolation limit {label} must be positive")
        if (
            not isinstance(self.wall_clock_seconds, (int, float))
            or self.wall_clock_seconds <= 0
        ):
            raise ValueError("isolation wall-clock limit must be positive")

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_seconds": self.cpu_seconds,
            "address_space_bytes": self.address_space_bytes,
            "file_size_bytes": self.file_size_bytes,
            "open_files": self.open_files,
            "process_count": self.process_count,
            "wall_clock_seconds": self.wall_clock_seconds,
            "stderr_bytes": self.stderr_bytes,
        }


@dataclass(frozen=True)
class IsolationPolicy:
    backend: str
    python_path: str
    python_sha256: str
    worker_path: str
    worker_sha256: str
    readonly_paths: tuple[str, ...]
    environment: Mapping[str, str]
    limits: IsolationLimits
    bubblewrap_path: str | None = None
    bubblewrap_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.backend not in {"bubblewrap", "subprocess"}:
            raise ValueError("unsupported isolation backend")
        for label, value in (
            ("python_path", self.python_path),
            ("worker_path", self.worker_path),
        ):
            path = Path(value)
            if not path.is_absolute() or not path.exists():
                raise ValueError(f"isolation {label} must be an existing absolute path")
        for label, value in (
            ("python_sha256", self.python_sha256),
            ("worker_sha256", self.worker_sha256),
        ):
            if not _DIGEST.fullmatch(value):
                raise ValueError(f"isolation {label} must be a digest")
        if tuple(sorted(set(self.readonly_paths))) != self.readonly_paths:
            raise ValueError("isolation readonly paths must be canonical")
        if any(not Path(path).is_absolute() for path in self.readonly_paths):
            raise ValueError("isolation readonly paths must be absolute")
        environment = dict(self.environment)
        if set(environment) - _ALLOWED_ENVIRONMENT:
            raise ValueError("isolation environment contains an unapproved name")
        if any(not isinstance(value, str) for value in environment.values()):
            raise TypeError("isolation environment values must be strings")
        object.__setattr__(self, "environment", MappingProxyType(environment))
        if self.backend == "bubblewrap":
            if self.bubblewrap_path is None or self.bubblewrap_sha256 is None:
                raise ValueError("bubblewrap backend requires binary path and digest")
            if not Path(self.bubblewrap_path).is_absolute() or not _DIGEST.fullmatch(
                self.bubblewrap_sha256
            ):
                raise ValueError("bubblewrap binding is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": ISOLATION_POLICY_SCHEMA,
            "backend": self.backend,
            "python_ref": self.python_path,
            "python_sha256": self.python_sha256,
            "worker_ref": self.worker_path,
            "worker_sha256": self.worker_sha256,
            "readonly_paths": list(self.readonly_paths),
            "environment": dict(sorted(self.environment.items())),
            "limits": self.limits.as_dict(),
            "bubblewrap_ref": self.bubblewrap_path,
            "bubblewrap_sha256": self.bubblewrap_sha256,
            "network_unshared": self.backend == "bubblewrap",
            "root_mounts_read_only": self.backend == "bubblewrap",
            "private_tmpfs": self.backend == "bubblewrap",
            "host_kernel_and_parent_in_tcb": True,
        }

    @property
    def policy_digest(self) -> str:
        return _digest(self.as_dict())


def make_isolation_policy(
    *,
    backend: str,
    python_path: Path,
    worker_path: Path | None = None,
    readonly_paths: Sequence[Path] = (),
    environment: Mapping[str, str] | None = None,
    limits: IsolationLimits,
    bubblewrap_path: Path | None = None,
) -> IsolationPolicy:
    worker = (worker_path or default_worker_path()).resolve()
    python_ref = python_path.absolute()
    python_resolved = python_path.resolve()
    readonly_values: set[str] = set()
    for path in (*readonly_paths, worker, python_ref, python_resolved):
        absolute = path.absolute()
        readonly_values.add(str(absolute))
        readonly_values.add(str(absolute.resolve()))
        if absolute.is_symlink():
            target = absolute.readlink()
            explicit_target = (
                target if target.is_absolute() else absolute.parent / target
            ).absolute()
            readonly_values.add(str(explicit_target))
            readonly_values.add(str(explicit_target.resolve()))
            if explicit_target.parent.name == "bin":
                explicit_prefix = explicit_target.parent.parent
                if explicit_prefix.is_dir():
                    readonly_values.add(str(explicit_prefix))
                    readonly_values.add(str(explicit_prefix.resolve()))
    retained: list[Path] = []
    for candidate in sorted(
        (Path(value) for value in readonly_values),
        key=lambda value: (len(value.parts), str(value)),
    ):
        if any(parent.is_dir() and parent in candidate.parents for parent in retained):
            continue
        retained.append(candidate)
    readonly = tuple(sorted(str(path) for path in retained))
    bwrap = bubblewrap_path.resolve() if bubblewrap_path is not None else None
    return IsolationPolicy(
        backend=backend,
        python_path=str(python_ref),
        python_sha256=_file_digest(python_resolved),
        worker_path=str(worker),
        worker_sha256=_file_digest(worker),
        readonly_paths=readonly,
        environment=dict(environment or {}),
        limits=limits,
        bubblewrap_path=str(bwrap) if bwrap is not None else None,
        bubblewrap_sha256=_file_digest(bwrap) if bwrap is not None else None,
    )


class IsolatedExecutionStatus(StrEnum):
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    ERROR = "ERROR"


@dataclass(frozen=True)
class IsolatedWorkerOutcome:
    status: IsolatedExecutionStatus
    return_code: int | None
    output_bytes: bytes | None
    errors: tuple[str, ...]
    stderr_sha256: str
    wall_time_ms: int
    backend: str

    @property
    def executed(self) -> bool:
        return self.status is IsolatedExecutionStatus.EXECUTED

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-isolated-worker-outcome-v1",
            "status": str(self.status),
            "return_code": self.return_code,
            "output_sha256": (
                hashlib.sha256(self.output_bytes).hexdigest()
                if self.output_bytes is not None
                else None
            ),
            "output_bytes": len(self.output_bytes)
            if self.output_bytes is not None
            else 0,
            "errors": list(self.errors),
            "stderr_sha256": self.stderr_sha256,
            "wall_time_ms": self.wall_time_ms,
            "backend": self.backend,
            "executed": self.executed,
            "network_unshared": self.backend == "bubblewrap",
        }


@dataclass(frozen=True)
class IsolatedExecutionReceipt:
    invocation_digest: str
    policy_digest: str
    request_digest: str
    status: IsolatedExecutionStatus
    return_code: int | None
    answer: bool | None
    steps: int
    worker_result: Mapping[str, Any] | None
    errors: tuple[str, ...]
    stderr_sha256: str
    wall_time_ms: int
    backend: str

    @property
    def executed(self) -> bool:
        return self.status is IsolatedExecutionStatus.EXECUTED

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": ISOLATED_RECEIPT_SCHEMA,
            "invocation_digest": self.invocation_digest,
            "policy_digest": self.policy_digest,
            "request_digest": self.request_digest,
            "status": str(self.status),
            "return_code": self.return_code,
            "answer": self.answer,
            "steps": self.steps,
            "worker_result": (
                _json_copy(self.worker_result)
                if self.worker_result is not None
                else None
            ),
            "errors": list(self.errors),
            "stderr_sha256": self.stderr_sha256,
            "wall_time_ms": self.wall_time_ms,
            "backend": self.backend,
            "executed": self.executed,
            "network_unshared": self.backend == "bubblewrap",
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.as_dict())


def _parent_dir_args(path: Path) -> list[str]:
    parents = list(path.parents)[:-1]
    return [
        argument for parent in reversed(parents) for argument in ("--dir", str(parent))
    ]


def _bubblewrap_command(
    policy: IsolationPolicy,
    command: Sequence[str],
    *,
    input_dir: Path,
    output_dir: Path,
) -> list[str]:
    if policy.bubblewrap_path is None:
        raise ValueError("bubblewrap path is missing")
    args = [
        policy.bubblewrap_path,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    created: set[str] = {"/", "/proc", "/dev", "/tmp"}
    for value in policy.readonly_paths:
        path = Path(value)
        for parent in reversed(path.parents):
            if str(parent) not in created and str(parent) != "/":
                args.extend(("--dir", str(parent)))
                created.add(str(parent))
        args.extend(("--ro-bind", str(path), str(path)))
        created.add(str(path))
    for path, writable in ((input_dir, False), (output_dir, True)):
        for parent in reversed(path.parents):
            if str(parent) not in created and str(parent) != "/":
                args.extend(("--dir", str(parent)))
                created.add(str(parent))
        args.extend(("--bind" if writable else "--ro-bind", str(path), str(path)))
    args.extend(("--remount-ro", "/"))
    clean_environment = {
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        **dict(policy.environment),
    }
    for name, value in sorted(clean_environment.items()):
        args.extend(("--setenv", name, value))
    args.extend(("--chdir", "/tmp", "--", *command))
    return args


def _limit_process(limits: IsolationLimits, *, strict: bool) -> None:
    requested = (
        (resource.RLIMIT_CPU, limits.cpu_seconds),
        (resource.RLIMIT_AS, limits.address_space_bytes),
        (resource.RLIMIT_FSIZE, limits.file_size_bytes),
        (resource.RLIMIT_NOFILE, limits.open_files),
        (resource.RLIMIT_NPROC, limits.process_count),
        (resource.RLIMIT_CORE, 0),
    )
    for resource_id, value in requested:
        try:
            resource.setrlimit(resource_id, (value, value))
        except (OSError, ValueError):
            if strict:
                raise


def _rejected_receipt(
    invocation: IsolatedVerifierInvocation,
    policy: IsolationPolicy,
    request_digest: str,
    errors: Sequence[str],
    *,
    status: IsolatedExecutionStatus = IsolatedExecutionStatus.REJECTED,
    return_code: int | None = None,
    stderr: bytes = b"",
    wall_time_ms: int = 0,
) -> IsolatedExecutionReceipt:
    return IsolatedExecutionReceipt(
        invocation_digest=invocation.invocation_digest,
        policy_digest=policy.policy_digest,
        request_digest=request_digest,
        status=status,
        return_code=return_code,
        answer=None,
        steps=0,
        worker_result=None,
        errors=tuple(errors),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        wall_time_ms=wall_time_ms,
        backend=policy.backend,
    )


def run_isolated_worker(
    policy: IsolationPolicy,
    *,
    input_bytes: bytes,
    extra_arguments: Sequence[str] = (),
    input_filename: str = "input.json",
    output_filename: str = "output.jsonl",
) -> IsolatedWorkerOutcome:
    if any(not isinstance(value, str) or "\x00" in value for value in extra_arguments):
        raise ValueError("isolated worker arguments must be closed strings")
    if (
        Path(input_filename).name != input_filename
        or Path(output_filename).name != output_filename
    ):
        raise ValueError("isolated worker filenames must be basenames")
    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="auditspec-isolated-worker-") as directory:
        root = Path(directory)
        input_dir = root / "input"
        output_dir = root / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        input_path = input_dir / input_filename
        output_path = output_dir / output_filename
        input_path.write_bytes(input_bytes)
        worker_command = [
            policy.python_path,
            policy.worker_path,
            str(input_path),
            *extra_arguments,
            str(output_path),
        ]
        command = (
            _bubblewrap_command(
                policy,
                worker_command,
                input_dir=input_dir,
                output_dir=output_dir,
            )
            if policy.backend == "bubblewrap"
            else worker_command
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
        if _file_digest(Path(policy.python_path)) != policy.python_sha256:
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.REJECTED,
                None,
                None,
                ("isolated_python_digest:mismatch",),
                hashlib.sha256(b"").hexdigest(),
                0,
                policy.backend,
            )
        if _file_digest(Path(policy.worker_path)) != policy.worker_sha256:
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.REJECTED,
                None,
                None,
                ("isolated_worker_digest:mismatch",),
                hashlib.sha256(b"").hexdigest(),
                0,
                policy.backend,
            )
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_environment,
            start_new_session=True,
            preexec_fn=lambda: _limit_process(  # noqa: PLW1509
                policy.limits, strict=policy.backend == "bubblewrap"
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
            stdout, stderr = process.communicate()
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.TIMEOUT,
                process.returncode,
                None,
                ("isolated_worker:wall_clock_timeout",),
                hashlib.sha256(stderr[: policy.limits.stderr_bytes]).hexdigest(),
                (time.monotonic_ns() - started) // 1_000_000,
                policy.backend,
            )
        wall_ms = (time.monotonic_ns() - started) // 1_000_000
        bounded_stderr = stderr[: policy.limits.stderr_bytes]
        if (
            len(stdout) > policy.limits.stderr_bytes
            or len(stderr) > policy.limits.stderr_bytes
        ):
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.RESOURCE_LIMIT,
                process.returncode,
                None,
                ("isolated_worker:pipe_output_limit",),
                hashlib.sha256(bounded_stderr).hexdigest(),
                wall_ms,
                policy.backend,
            )
        if process.returncode != 0:
            status = (
                IsolatedExecutionStatus.RESOURCE_LIMIT
                if process.returncode is not None and process.returncode < 0
                else IsolatedExecutionStatus.ERROR
            )
            return IsolatedWorkerOutcome(
                status,
                process.returncode,
                None,
                (f"isolated_worker:return_code:{process.returncode}",),
                hashlib.sha256(bounded_stderr).hexdigest(),
                wall_ms,
                policy.backend,
            )
        if not output_path.is_file() or output_path.is_symlink():
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.ERROR,
                process.returncode,
                None,
                ("isolated_worker:output_missing",),
                hashlib.sha256(bounded_stderr).hexdigest(),
                wall_ms,
                policy.backend,
            )
        if output_path.stat().st_size > policy.limits.file_size_bytes:
            return IsolatedWorkerOutcome(
                IsolatedExecutionStatus.RESOURCE_LIMIT,
                process.returncode,
                None,
                ("isolated_worker:output_size_limit",),
                hashlib.sha256(bounded_stderr).hexdigest(),
                wall_ms,
                policy.backend,
            )
        return IsolatedWorkerOutcome(
            IsolatedExecutionStatus.EXECUTED,
            process.returncode,
            output_path.read_bytes(),
            (),
            hashlib.sha256(bounded_stderr).hexdigest(),
            wall_ms,
            policy.backend,
        )


def execute_isolated_verifier(
    invocation: IsolatedVerifierInvocation,
    input_payload: Mapping[str, Any],
    policy: IsolationPolicy,
) -> IsolatedExecutionReceipt:
    request = {
        "schema": WORKER_REQUEST_SCHEMA,
        "request_id": invocation.invocation_digest,
        "verifier_id": invocation.verifier_id,
        "verifier_version": invocation.verifier_version,
        "input_schema": invocation.input_schema,
        "input_payload": _json_copy(input_payload),
        "fuel": invocation.fuel,
    }
    request_digest = _digest(request)
    errors: list[str] = []
    manifest = ISOLATED_VERIFIERS.get(invocation.verifier_id)
    if invocation.registry_digest != isolated_registry_digest():
        errors.append("isolated_registry_digest:mismatch")
    if manifest is None:
        errors.append("isolated_verifier:unregistered")
    else:
        if invocation.verifier_version != manifest.version:
            errors.append("isolated_verifier_version:mismatch")
        if invocation.verifier_manifest_digest != _digest(manifest.as_dict()):
            errors.append("isolated_verifier_manifest_digest:mismatch")
        if invocation.input_schema != manifest.input_schema:
            errors.append("isolated_input_schema:mismatch")
        if invocation.input_extractor_id != manifest.input_extractor_id:
            errors.append("isolated_input_extractor:mismatch")
        if invocation.fuel > manifest.max_fuel:
            errors.append("isolated_fuel:above_registered_maximum")
        if manifest.worker_source_digest != policy.worker_sha256:
            errors.append("isolated_worker_source_digest:mismatch")
    if _file_digest(Path(policy.python_path)) != policy.python_sha256:
        errors.append("isolated_python_digest:mismatch")
    if _file_digest(Path(policy.worker_path)) != policy.worker_sha256:
        errors.append("isolated_policy_worker_digest:mismatch")
    if policy.backend == "bubblewrap":
        if policy.bubblewrap_path is None or not Path(policy.bubblewrap_path).is_file():
            errors.append("bubblewrap:missing")
        elif _file_digest(Path(policy.bubblewrap_path)) != policy.bubblewrap_sha256:
            errors.append("bubblewrap:digest_mismatch")
    try:
        count = _payload_item_count(invocation.verifier_id, input_payload)
        if manifest is not None and (
            count < manifest.min_items or count > manifest.max_items
        ):
            errors.append("isolated_input_items:outside_registered_bounds")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"isolated_input:{type(exc).__name__}:{exc}")
    if _digest(dict(input_payload)) != invocation.input_payload_digest:
        errors.append("isolated_input_payload_digest:mismatch")
    if errors:
        return _rejected_receipt(invocation, policy, request_digest, errors)

    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="auditspec-isolated-") as directory:
        root = Path(directory)
        input_dir = root / "input"
        output_dir = root / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        request_path = input_dir / "request.json"
        output_path = output_dir / "result.json"
        request_path.write_text(canonical_json(request) + "\n", encoding="utf-8")
        worker_command = [
            policy.python_path,
            policy.worker_path,
            str(request_path),
            str(output_path),
        ]
        command = (
            _bubblewrap_command(
                policy,
                worker_command,
                input_dir=input_dir,
                output_dir=output_dir,
            )
            if policy.backend == "bubblewrap"
            else worker_command
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
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_environment,
            start_new_session=True,
            preexec_fn=lambda: _limit_process(  # noqa: PLW1509
                policy.limits, strict=policy.backend == "bubblewrap"
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
            stdout, stderr = process.communicate()
            wall_ms = (time.monotonic_ns() - started) // 1_000_000
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                ("isolated_process:wall_clock_timeout",),
                status=IsolatedExecutionStatus.TIMEOUT,
                return_code=process.returncode,
                stderr=stderr[: policy.limits.stderr_bytes],
                wall_time_ms=wall_ms,
            )
        wall_ms = (time.monotonic_ns() - started) // 1_000_000
        bounded_stderr = stderr[: policy.limits.stderr_bytes]
        if (
            len(stdout) > policy.limits.stderr_bytes
            or len(stderr) > policy.limits.stderr_bytes
        ):
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                ("isolated_process:pipe_output_limit",),
                status=IsolatedExecutionStatus.RESOURCE_LIMIT,
                return_code=process.returncode,
                stderr=bounded_stderr,
                wall_time_ms=wall_ms,
            )
        if process.returncode != 0:
            status = (
                IsolatedExecutionStatus.RESOURCE_LIMIT
                if process.returncode is not None and process.returncode < 0
                else IsolatedExecutionStatus.ERROR
            )
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                (f"isolated_process:return_code:{process.returncode}",),
                status=status,
                return_code=process.returncode,
                stderr=bounded_stderr,
                wall_time_ms=wall_ms,
            )
        if not output_path.is_file() or output_path.is_symlink():
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                ("isolated_process:result_missing",),
                status=IsolatedExecutionStatus.ERROR,
                return_code=process.returncode,
                stderr=bounded_stderr,
                wall_time_ms=wall_ms,
            )
        if output_path.stat().st_size > policy.limits.file_size_bytes:
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                ("isolated_process:result_size_limit",),
                status=IsolatedExecutionStatus.RESOURCE_LIMIT,
                return_code=process.returncode,
                stderr=bounded_stderr,
                wall_time_ms=wall_ms,
            )
        try:
            result = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return _rejected_receipt(
                invocation,
                policy,
                request_digest,
                (f"isolated_process:invalid_result:{type(exc).__name__}",),
                status=IsolatedExecutionStatus.ERROR,
                return_code=process.returncode,
                stderr=bounded_stderr,
                wall_time_ms=wall_ms,
            )
    expected_result_fields = {
        "schema",
        "request_id",
        "verifier_id",
        "verifier_version",
        "answer",
        "steps",
        "result",
    }
    if not isinstance(result, dict) or set(result) != expected_result_fields:
        return _rejected_receipt(
            invocation,
            policy,
            request_digest,
            ("isolated_process:result_schema",),
            status=IsolatedExecutionStatus.ERROR,
            return_code=process.returncode,
            stderr=bounded_stderr,
            wall_time_ms=wall_ms,
        )
    if (
        result["schema"] != WORKER_RESULT_SCHEMA
        or result["request_id"] != invocation.invocation_digest
        or result["verifier_id"] != invocation.verifier_id
        or result["verifier_version"] != invocation.verifier_version
        or not isinstance(result["answer"], bool)
        or not isinstance(result["steps"], int)
        or isinstance(result["steps"], bool)
        or result["steps"] < 0
        or result["steps"] > invocation.fuel
        or not isinstance(result["result"], dict)
    ):
        return _rejected_receipt(
            invocation,
            policy,
            request_digest,
            ("isolated_process:result_binding",),
            status=IsolatedExecutionStatus.ERROR,
            return_code=process.returncode,
            stderr=bounded_stderr,
            wall_time_ms=wall_ms,
        )
    return IsolatedExecutionReceipt(
        invocation_digest=invocation.invocation_digest,
        policy_digest=policy.policy_digest,
        request_digest=request_digest,
        status=IsolatedExecutionStatus.EXECUTED,
        return_code=process.returncode,
        answer=result["answer"],
        steps=result["steps"],
        worker_result=result["result"],
        errors=(),
        stderr_sha256=hashlib.sha256(bounded_stderr).hexdigest(),
        wall_time_ms=wall_ms,
        backend=policy.backend,
    )


def verify_isolated_execution_receipt(
    receipt: IsolatedExecutionReceipt,
    *,
    invocation: IsolatedVerifierInvocation,
    policy: IsolationPolicy,
    require_executed: bool = True,
) -> bool:
    return bool(
        receipt.invocation_digest == invocation.invocation_digest
        and receipt.policy_digest == policy.policy_digest
        and receipt.backend == policy.backend
        and (receipt.executed if require_executed else True)
        and receipt.wall_time_ms >= 0
        and _DIGEST.fullmatch(receipt.request_digest)
        and _DIGEST.fullmatch(receipt.stderr_sha256)
    )


def bubblewrap_available() -> Path | None:
    value = shutil.which("bwrap")
    return Path(value).resolve() if value is not None else None
