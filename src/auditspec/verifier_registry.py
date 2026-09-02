from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import inspect
import marshal
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .runtime.events import canonical_json


VERIFIER_REGISTRY_SCHEMA = "AuditSpec-registered-audit-verifier-registry-v1"
VERIFIER_INVOCATION_SCHEMA = "AuditSpec-registered-audit-verifier-invocation-v1"
VERIFIER_RESULT_SCHEMA = "AuditSpec-registered-audit-verifier-result-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_REGISTERED_INPUT_ITEMS = 4096


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _implementation_digest(
    function: Callable[[Mapping[str, Any], int], tuple[bool, int]],
) -> str:
    source = inspect.getsource(function).encode("utf-8")
    code = marshal.dumps(function.__code__)
    return _digest(
        {
            "module": function.__module__,
            "qualname": function.__qualname__,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "code_sha256": hashlib.sha256(code).hexdigest(),
        }
    )


def _all_boolean_checks(payload: Mapping[str, Any], fuel: int) -> tuple[bool, int]:
    if set(payload) != {"checks"}:
        raise ValueError("all-checks verifier input differs from closed schema")
    checks = payload["checks"]
    if type(checks) is not list:
        raise TypeError("all-checks verifier requires a Boolean list")
    if len(checks) > fuel:
        raise FuelExhausted("registered verifier fuel exhausted")
    if any(type(item) is not bool for item in checks):
        raise TypeError("all-checks verifier requires a Boolean list")
    return all(checks), len(checks)


def _raising_verifier(payload: Mapping[str, Any], fuel: int) -> tuple[bool, int]:
    del payload, fuel
    raise RuntimeError("registered verifier test exception")


class FuelExhausted(RuntimeError):
    pass


@dataclass(frozen=True)
class RegisteredVerifierManifest:
    verifier_id: str
    version: str
    input_schema: str
    min_items: int
    max_items: int
    max_fuel: int
    implementation_ref: str
    implementation_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "verifier_id": self.verifier_id,
            "version": self.version,
            "input_schema": self.input_schema,
            "min_items": self.min_items,
            "max_items": self.max_items,
            "max_fuel": self.max_fuel,
            "implementation_ref": self.implementation_ref,
            "implementation_digest": self.implementation_digest,
        }


def _manifest(
    verifier_id: str,
    function: Callable[[Mapping[str, Any], int], tuple[bool, int]],
    *,
    input_schema: str,
    min_items: int,
    max_items: int,
    max_fuel: int,
) -> RegisteredVerifierManifest:
    return RegisteredVerifierManifest(
        verifier_id=verifier_id,
        version="1.0.0",
        input_schema=input_schema,
        min_items=min_items,
        max_items=max_items,
        max_fuel=max_fuel,
        implementation_ref=f"{__name__}:{function.__name__}",
        implementation_digest=_implementation_digest(function),
    )


_FUNCTIONS: Mapping[str, Callable[[Mapping[str, Any], int], tuple[bool, int]]] = (
    MappingProxyType(
        {
            "auditspec-all-boolean-checks-v1": _all_boolean_checks,
            "auditspec-raising-verifier-v1": _raising_verifier,
        }
    )
)

REGISTERED_AUDIT_VERIFIERS: Mapping[str, RegisteredVerifierManifest] = MappingProxyType(
    {
        "auditspec-all-boolean-checks-v1": _manifest(
            "auditspec-all-boolean-checks-v1",
            _all_boolean_checks,
            input_schema="AuditSpec-all-boolean-checks-input-v1",
            min_items=1,
            max_items=4096,
            max_fuel=4096,
        ),
        "auditspec-raising-verifier-v1": _manifest(
            "auditspec-raising-verifier-v1",
            _raising_verifier,
            input_schema="AuditSpec-raising-verifier-input-v1",
            min_items=0,
            max_items=0,
            max_fuel=1,
        ),
    }
)


def verifier_registry_digest() -> str:
    return _digest(
        {
            "schema": VERIFIER_REGISTRY_SCHEMA,
            "verifiers": {
                verifier_id: manifest.as_dict()
                for verifier_id, manifest in sorted(REGISTERED_AUDIT_VERIFIERS.items())
            },
        }
    )


def _closed_input_envelope_error(
    payload: object, *, min_items: int, max_items: int
) -> str | None:
    if type(payload) is not dict:
        return "verifier input must be a built-in dict"
    if len(payload) != 1 or set(payload) != {"checks"}:
        return "verifier input differs from closed checks schema"
    checks = payload["checks"]
    if type(checks) is not list:
        return "verifier checks must be a built-in list"
    if len(checks) < min_items:
        return "verifier input is below the registered item minimum"
    if len(checks) > max_items:
        return "verifier input exceeds the registered item bound"
    return None


@dataclass(frozen=True)
class RegisteredVerifierInvocation:
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
                raise ValueError(f"{label} must be a non-empty string")
        for label, value in (
            ("verifier_manifest_digest", self.verifier_manifest_digest),
            ("registry_digest", self.registry_digest),
        ):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"{label} must be a digest")
        if not isinstance(self.input_payload_digest, str) or not _DIGEST.fullmatch(
            self.input_payload_digest
        ):
            raise ValueError(
                "registered verifier input payload digest must be a digest"
            )
        if self.input_extractor_id != "retained-witness-checks-v1":
            raise ValueError("unsupported registered verifier input extractor")
        if (
            not isinstance(self.fuel, int)
            or isinstance(self.fuel, bool)
            or self.fuel < 0
        ):
            raise ValueError("registered verifier fuel must be a non-negative integer")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RegisteredVerifierInvocation":
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
        if set(raw) != expected:
            raise ValueError(
                "registered verifier invocation fields differ from closed schema"
            )
        if raw["schema"] != VERIFIER_INVOCATION_SCHEMA:
            raise ValueError("registered verifier invocation schema mismatch")
        return cls(
            raw["verifier_id"],
            raw["verifier_version"],
            raw["verifier_manifest_digest"],
            raw["registry_digest"],
            raw["claim_id"],
            raw["replay_id"],
            raw["input_schema"],
            raw["input_extractor_id"],
            raw["input_payload_digest"],
            raw["fuel"],
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": VERIFIER_INVOCATION_SCHEMA,
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

    @property
    def invocation_digest(self) -> str:
        return _digest(self.as_dict())


class VerifierExecutionStatus(StrEnum):
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    FUEL_EXHAUSTED = "FUEL_EXHAUSTED"


@dataclass(frozen=True)
class RegisteredVerifierExecutionResult:
    invocation_digest: str
    status: VerifierExecutionStatus
    answer: bool | None
    steps: int
    errors: tuple[str, ...]
    verifier_id: str
    verifier_manifest_digest: str | None
    registry_digest: str

    @property
    def executed(self) -> bool:
        return self.status is VerifierExecutionStatus.EXECUTED

    @property
    def accepted(self) -> bool:
        return self.executed and not self.errors and self.answer is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": VERIFIER_RESULT_SCHEMA,
            "invocation_digest": self.invocation_digest,
            "status": str(self.status),
            "answer": self.answer,
            "steps": self.steps,
            "errors": list(self.errors),
            "verifier_id": self.verifier_id,
            "verifier_manifest_digest": self.verifier_manifest_digest,
            "registry_digest": self.registry_digest,
            "executed": self.executed,
            "accepted": self.accepted,
        }


def registered_verifier_manifest_digest(verifier_id: str) -> str | None:
    manifest = REGISTERED_AUDIT_VERIFIERS.get(verifier_id)
    return _digest(manifest.as_dict()) if manifest is not None else None


def make_registered_verifier_invocation(
    *,
    verifier_id: str,
    claim_id: str,
    replay_id: str,
    input_payload: Mapping[str, Any],
    fuel: int,
) -> RegisteredVerifierInvocation:
    manifest = REGISTERED_AUDIT_VERIFIERS[verifier_id]
    envelope_error = _closed_input_envelope_error(
        input_payload,
        min_items=manifest.min_items,
        max_items=manifest.max_items,
    )
    if envelope_error is not None:
        raise ValueError(envelope_error)
    return RegisteredVerifierInvocation(
        verifier_id=verifier_id,
        verifier_version=manifest.version,
        verifier_manifest_digest=_digest(manifest.as_dict()),
        registry_digest=verifier_registry_digest(),
        claim_id=claim_id,
        replay_id=replay_id,
        input_schema=manifest.input_schema,
        input_extractor_id="retained-witness-checks-v1",
        input_payload_digest=_digest(input_payload),
        fuel=fuel,
    )


def extract_registered_verifier_input(
    invocation: RegisteredVerifierInvocation,
    evidence_payload: Mapping[str, Any],
) -> dict[str, Any]:
    if invocation.input_extractor_id != "retained-witness-checks-v1":
        raise ValueError("unsupported registered verifier input extractor")
    witness = evidence_payload.get("verification_witness")
    if not isinstance(witness, Mapping):
        raise ValueError("registered verifier witness is missing")
    components = witness.get("evidence_components")
    if not isinstance(components, Mapping) or set(components) != {"checks"}:
        raise ValueError(
            "registered verifier evidence components differ from closed schema"
        )
    checks = components["checks"]
    if type(checks) is not list:
        raise TypeError("registered verifier evidence checks must be a Boolean list")
    manifest = REGISTERED_AUDIT_VERIFIERS.get(invocation.verifier_id)
    min_items = manifest.min_items if manifest is not None else 0
    max_items = (
        manifest.max_items if manifest is not None else MAX_REGISTERED_INPUT_ITEMS
    )
    if len(checks) < min_items:
        raise ValueError("registered verifier evidence is below the input item minimum")
    if len(checks) > max_items:
        raise ValueError("registered verifier evidence exceeds the input item bound")
    if any(type(item) is not bool for item in checks):
        raise TypeError("registered verifier evidence checks must be a Boolean list")
    payload = {"checks": list(checks)}
    if _digest(payload) != invocation.input_payload_digest:
        raise ValueError("registered verifier derived input digest mismatch")
    return payload


def execute_registered_verifier(
    invocation: RegisteredVerifierInvocation,
    input_payload: Mapping[str, Any],
) -> RegisteredVerifierExecutionResult:
    current_registry = verifier_registry_digest()
    manifest = REGISTERED_AUDIT_VERIFIERS.get(invocation.verifier_id)
    manifest_digest = registered_verifier_manifest_digest(invocation.verifier_id)
    errors: list[str] = []
    if invocation.registry_digest != current_registry:
        errors.append("verifier_registry_digest:mismatch")
    if manifest is None:
        errors.append("verifier:unregistered")
    else:
        if invocation.verifier_version != manifest.version:
            errors.append("verifier_version:mismatch")
        if invocation.verifier_manifest_digest != manifest_digest:
            errors.append("verifier_manifest_digest:mismatch")
        if invocation.input_schema != manifest.input_schema:
            errors.append("verifier_input_schema:mismatch")
        if invocation.fuel > manifest.max_fuel:
            errors.append("verifier_fuel:above_registered_maximum")
    if errors or manifest is None:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.REJECTED,
            None,
            0,
            tuple(errors),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    function = _FUNCTIONS[invocation.verifier_id]
    try:
        implementation_matches = (
            getattr(function, "__globals__", None) is globals()
            and _implementation_digest(function) == manifest.implementation_digest
        )
    except (OSError, TypeError, ValueError):
        implementation_matches = False
    if not implementation_matches:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.REJECTED,
            None,
            0,
            ("verifier_implementation_digest:mismatch",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    envelope_error = _closed_input_envelope_error(
        input_payload,
        min_items=manifest.min_items,
        max_items=manifest.max_items,
    )
    if envelope_error is not None:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.REJECTED,
            None,
            0,
            (f"verifier_input_payload:{envelope_error}",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    try:
        supplied_payload_digest = _digest(input_payload)
    except (TypeError, ValueError) as exc:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.REJECTED,
            None,
            0,
            (f"verifier_input_payload:not_canonical:{type(exc).__name__}:{exc}",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    if supplied_payload_digest != invocation.input_payload_digest:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.REJECTED,
            None,
            0,
            ("verifier_input_payload_digest:mismatch",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    try:
        answer, steps = function(input_payload, invocation.fuel)
    except FuelExhausted as exc:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.FUEL_EXHAUSTED,
            None,
            invocation.fuel,
            (str(exc),),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    except Exception as exc:
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.ERROR,
            None,
            0,
            (f"{type(exc).__name__}:{exc}",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    if (
        not isinstance(answer, bool)
        or not isinstance(steps, int)
        or isinstance(steps, bool)
        or steps < 0
        or steps > invocation.fuel
    ):
        return RegisteredVerifierExecutionResult(
            invocation.invocation_digest,
            VerifierExecutionStatus.ERROR,
            None,
            0,
            ("registered verifier returned an invalid result shape",),
            invocation.verifier_id,
            manifest_digest,
            current_registry,
        )
    return RegisteredVerifierExecutionResult(
        invocation.invocation_digest,
        VerifierExecutionStatus.EXECUTED,
        answer,
        steps,
        (),
        invocation.verifier_id,
        manifest_digest,
        current_registry,
    )
