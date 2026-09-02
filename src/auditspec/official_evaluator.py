"""Closed registry and result verification for official benchmark replays."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .runtime.events import canonical_json

OFFICIAL_EVALUATOR_REGISTRY_SCHEMA = "AuditSpec-official-evaluator-registry-v1"
OFFICIAL_REPLAY_ROW_SCHEMA = "AuditSpec-official-evaluator-replay-row-v1"
OFFICIAL_EXECUTION_RECEIPT_SCHEMA = "AuditSpec-official-evaluator-execution-receipt-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class OfficialEvaluatorManifest:
    registry_id: str
    version: str
    environment: str
    checkout_commit: str
    worker_filename: str
    worker_sha256: str
    completed_episode_denominator: int
    fresh_process_per_row: bool
    strict_replay: bool | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "version": self.version,
            "environment": self.environment,
            "checkout_commit": self.checkout_commit,
            "worker_filename": self.worker_filename,
            "worker_sha256": self.worker_sha256,
            "completed_episode_denominator": self.completed_episode_denominator,
            "fresh_process_per_row": self.fresh_process_per_row,
            "strict_replay": self.strict_replay,
            "worker_makes_model_calls": False,
            "arbitrary_callback": False,
            "arbitrary_import_path": False,
        }


_DEFINITIONS: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        "tau2": {
            "registry_id": "tau2-official-evaluator-replay-fc0055d-v2",
            "checkout_commit": "fc0055dc4e0a316c3f83133267fbd6faaa770992",
            "worker_filename": "v13_tau2_official_replay_worker.py",
            "completed_episode_denominator": 537,
            "version": "1.1.0",
            "strict_replay": False,
        },
        "appworld": {
            "registry_id": "appworld-official-evaluator-replay-a072b7a-v2",
            "checkout_commit": "a072b7a86e7c1d5b1d7175659d750ebb9b79f10a",
            "worker_filename": "v13_appworld_official_replay_worker.py",
            "completed_episode_denominator": 539,
            "version": "1.1.0",
            "strict_replay": None,
        },
    }
)


def official_evaluator_manifest(
    environment: str,
    *,
    worker_path: Path,
) -> OfficialEvaluatorManifest:
    definition = _DEFINITIONS.get(environment)
    if definition is None:
        raise ValueError("unregistered official evaluator environment")
    worker = worker_path.resolve()
    if (
        worker.name != definition["worker_filename"]
        or not worker.is_file()
        or worker.is_symlink()
    ):
        raise ValueError("official evaluator worker path is not the registered file")
    return OfficialEvaluatorManifest(
        registry_id=definition["registry_id"],
        version=definition["version"],
        environment=environment,
        checkout_commit=definition["checkout_commit"],
        worker_filename=definition["worker_filename"],
        worker_sha256=_file_digest(worker),
        completed_episode_denominator=definition["completed_episode_denominator"],
        fresh_process_per_row=True,
        strict_replay=definition["strict_replay"],
    )


def official_evaluator_registry_digest(
    worker_paths: Mapping[str, Path],
) -> str:
    if set(worker_paths) != set(_DEFINITIONS):
        raise ValueError("official evaluator registry needs both frozen workers")
    return _digest(
        {
            "schema": OFFICIAL_EVALUATOR_REGISTRY_SCHEMA,
            "evaluators": {
                environment: official_evaluator_manifest(
                    environment, worker_path=worker_paths[environment]
                ).as_dict()
                for environment in sorted(worker_paths)
            },
        }
    )


def expected_official_rows(
    input_manifest: Mapping[str, Any], environment: str
) -> tuple[Mapping[str, Any], ...]:
    rows = tuple(
        row
        for row in input_manifest["official_inputs"]["rows"]
        if row["environment"] == environment and row["replay_eligible"] is True
    )
    expected = _DEFINITIONS[environment]["completed_episode_denominator"]
    if len(rows) != expected:
        raise ValueError("official evaluator input denominator mismatch")
    return rows


def verify_official_replay_row(
    result: Mapping[str, Any], expected: Mapping[str, Any]
) -> tuple[str, ...]:
    errors: list[str] = []
    fields = {
        "schema",
        "environment",
        "run_id",
        "task_id",
        "status",
        "official_task_success",
        "official_claims",
        "signed_witnesses",
        "worker_metadata",
        "new_model_calls",
    }
    if set(result) != fields:
        return ("result_fields:mismatch",)
    if result["schema"] != OFFICIAL_REPLAY_ROW_SCHEMA:
        errors.append("result_schema:mismatch")
    for name in ("environment", "run_id", "task_id"):
        if result[name] != expected[name]:
            errors.append(f"{name}:mismatch")
    if result["status"] != "EXECUTED":
        errors.append("status:not_executed")
    if result["official_task_success"] != expected["expected_official_task_success"]:
        errors.append("official_task_success:mismatch")
    if result["official_claims"] != expected["expected_official_claims"]:
        errors.append("official_claims:mismatch")
    if result["signed_witnesses"] != expected["expected_signed_witnesses"]:
        errors.append("signed_witnesses:mismatch")
    if result["new_model_calls"] != 0:
        errors.append("new_model_calls:nonzero")
    metadata = result["worker_metadata"]
    if not isinstance(metadata, Mapping):
        errors.append("worker_metadata:not_mapping")
        return tuple(errors)
    common_metadata = {
        "checkout_commit",
        "worker_pid",
        "parent_pid",
        "process_start_ticks",
        "open_fd_count",
        "sensitive_environment_names",
        "network_interfaces",
        "fresh_process_per_row",
    }
    expected_metadata = (
        common_metadata | {"reward_basis", "strict_replay"}
        if expected["environment"] == "tau2"
        else common_metadata | {"num_tests"}
    )
    if result["status"] != "EXECUTED":
        expected_metadata |= {"error_type", "error_message"}
        expected_metadata -= {"reward_basis", "num_tests"}
    if set(metadata) != expected_metadata:
        errors.append("worker_metadata:fields_mismatch")
        return tuple(errors)
    definition = _DEFINITIONS[expected["environment"]]
    if metadata["checkout_commit"] != definition["checkout_commit"]:
        errors.append("worker_metadata:checkout_commit_mismatch")
    if metadata["fresh_process_per_row"] is not True:
        errors.append("worker_metadata:fresh_process_false")
    if metadata["network_interfaces"] != ["lo"]:
        errors.append("worker_metadata:network_not_isolated")
    if metadata["sensitive_environment_names"] != []:
        errors.append("worker_metadata:sensitive_environment")
    for name in ("worker_pid", "parent_pid", "process_start_ticks", "open_fd_count"):
        if (
            not isinstance(metadata[name], int)
            or isinstance(metadata[name], bool)
            or metadata[name] < 0
        ):
            errors.append(f"worker_metadata:{name}_invalid")
    if isinstance(metadata["open_fd_count"], int) and metadata["open_fd_count"] >= 256:
        errors.append("worker_metadata:open_fd_limit_reached")
    if expected["environment"] == "tau2" and metadata.get("strict_replay") is not False:
        errors.append("worker_metadata:strict_replay_changed")
    return tuple(errors)


def verify_official_replay_rows(
    input_manifest: Mapping[str, Any],
    environment: str,
    results: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    expected = expected_official_rows(input_manifest, environment)
    if len(results) != len(expected):
        return ("result_denominator:mismatch",)
    errors: list[str] = []
    seen: set[str] = set()
    worker_instances: set[tuple[int, int]] = set()
    for index, (result, source) in enumerate(zip(results, expected)):
        run_id = result.get("run_id")
        if not isinstance(run_id, str) or run_id in seen:
            errors.append(f"row:{index}:run_id:missing_or_duplicate")
        else:
            seen.add(run_id)
        errors.extend(
            f"row:{index}:{error}"
            for error in verify_official_replay_row(result, source)
        )
        metadata = result.get("worker_metadata")
        if isinstance(metadata, Mapping):
            pid = metadata.get("worker_pid")
            start = metadata.get("process_start_ticks")
            if isinstance(pid, int) and isinstance(start, int):
                instance = (pid, start)
                if instance in worker_instances:
                    errors.append(f"row:{index}:worker_instance:reused")
                worker_instances.add(instance)
    if len(worker_instances) != len(results):
        errors.append("worker_instance_denominator:mismatch")
    return tuple(errors)


@dataclass(frozen=True)
class OfficialEvaluatorExecutionReceipt:
    environment: str
    registry_digest: str
    evaluator_manifest_digest: str
    input_manifest_sha256: str
    input_row_bundle_root: str
    isolation_policy_digest: str
    isolation_backend: str
    rows_sha256: str
    row_count: int
    passed: int
    failed: int
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.environment not in _DEFINITIONS:
            raise ValueError("official receipt environment is invalid")
        for label, value in (
            ("registry_digest", self.registry_digest),
            ("evaluator_manifest_digest", self.evaluator_manifest_digest),
            ("input_manifest_sha256", self.input_manifest_sha256),
            ("input_row_bundle_root", self.input_row_bundle_root),
            ("isolation_policy_digest", self.isolation_policy_digest),
            ("rows_sha256", self.rows_sha256),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"official receipt {label} is invalid")
        if self.isolation_backend not in {"bubblewrap", "subprocess"}:
            raise ValueError("official receipt isolation backend is invalid")
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (self.row_count, self.passed, self.failed)
        ):
            raise ValueError("official receipt counts are invalid")
        if self.passed + self.failed != self.row_count:
            raise ValueError("official receipt counts do not close")

    @property
    def valid(self) -> bool:
        return self.failed == 0 and not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": OFFICIAL_EXECUTION_RECEIPT_SCHEMA,
            "environment": self.environment,
            "registry_digest": self.registry_digest,
            "evaluator_manifest_digest": self.evaluator_manifest_digest,
            "input_manifest_sha256": self.input_manifest_sha256,
            "input_row_bundle_root": self.input_row_bundle_root,
            "isolation_policy_digest": self.isolation_policy_digest,
            "isolation_backend": self.isolation_backend,
            "rows_sha256": self.rows_sha256,
            "row_count": self.row_count,
            "passed": self.passed,
            "failed": self.failed,
            "errors": list(self.errors),
            "valid": self.valid,
            "official_evaluator_actual_execution": True,
            "new_model_calls": 0,
            "inventory_completeness_proven": False,
            "open_world": False,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.as_dict())
