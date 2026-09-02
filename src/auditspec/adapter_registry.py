from __future__ import annotations

import hashlib
import importlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .runtime.events import canonical_json


ADAPTER_REGISTRY_VERSION = "AuditSpec-adapter-registry-v1"
REGISTRY_ATTESTATION_SCHEMA = "AuditSpec-adapter-registry-attestation-v3"
SOURCE_REGISTRY_ATTESTATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "proofs"
    / "adapter_registry_attestation.json"
)
PACKAGE_REGISTRY_ATTESTATION_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "adapter_registry_attestation.json"
)
# Compatibility alias for callers that inspect the source-tree proof path.
REGISTRY_ATTESTATION_PATH = SOURCE_REGISTRY_ATTESTATION_PATH


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    modes: tuple[str, ...]
    producers: tuple[str, ...]
    capture_points: tuple[str, ...]
    integrity: tuple[str, ...]
    observation_kinds: tuple[str, ...]
    binding_edges: tuple[tuple[str, str], ...] = ()
    coverage_channels: tuple[str, ...] = ()
    refinement_level: str = "model_checked"
    implementation_ref: str = "auditspec.model:ObservationSpec.evaluate"
    version: str = "1.0.0"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReplayAdapterManifest:
    """Versioned schema for one executable or schema-checked replay adapter.

    Registration proves that the contract vocabulary is known.  The
    `assurance_level` field deliberately distinguishes an executable conformance
    proof from a schema-only registration; later compiler gates must not treat
    the latter as runtime refinement evidence.
    """

    adapter_id: str
    target: str
    prefix_checkpoint: str
    snapshot: str
    nondeterminism: tuple[str, ...]
    isolation: str
    side_effect_mode: str
    verifier: str
    minimum_trials: int
    implementation_ref: str
    assurance_level: str  # executable | schema_only
    version: str = "1.0.0"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _manifest(
    adapter_id: str,
    producer: str | tuple[str, ...],
    capture_point: str | tuple[str, ...],
    integrity: str | tuple[str, ...],
    *,
    modes: tuple[str, ...] = ("passive",),
    observation_kinds: tuple[str, ...] = ("exact",),
    binding_edges: tuple[tuple[str, str], ...] = (),
    coverage_channels: tuple[str, ...] = (),
    refinement_level: str = "model_checked",
    implementation_ref: str = "auditspec.model:ObservationSpec.evaluate",
) -> AdapterManifest:
    def values(item: str | tuple[str, ...]) -> tuple[str, ...]:
        return (item,) if isinstance(item, str) else item

    return AdapterManifest(
        adapter_id=adapter_id,
        modes=modes,
        producers=values(producer),
        capture_points=values(capture_point),
        integrity=values(integrity),
        observation_kinds=observation_kinds,
        binding_edges=binding_edges,
        coverage_channels=coverage_channels,
        refinement_level=refinement_level,
        implementation_ref=implementation_ref,
    )


ADAPTER_MANIFESTS: dict[str, AdapterManifest] = {
    "agent-final": _manifest("agent-final", "agent", "agent", "none"),
    "generic-trace": _manifest(
        "generic-trace",
        "framework_runtime",
        "framework_runtime",
        "hash_chain",
        binding_edges=(
            ("action", "review"),
            ("application", "decision"),
            ("case_action", "review"),
        ),
    ),
    "langgraph-node-trace": _manifest(
        "langgraph-node-trace",
        "framework_runtime",
        "framework_runtime",
        "hash_chain",
        binding_edges=(("action", "review"),),
    ),
    "canonical-action": _manifest(
        "canonical-action", "action_gateway", "action_gateway", "hmac-sha256"
    ),
    "canonical-application": _manifest(
        "canonical-application", "decision_gateway", "decision_gateway", "hmac-sha256"
    ),
    "canonical-case-action": _manifest(
        "canonical-case-action", "case_gateway", "case_gateway", "hmac-sha256"
    ),
    "approval-receipt": _manifest(
        "approval-receipt",
        "approval_service",
        "approval_service",
        "hmac-sha256",
        binding_edges=(("action", "approval"),),
    ),
    "delegation-cim": _manifest(
        "delegation-cim",
        "identity_gateway",
        "identity_gateway",
        "hmac-sha256",
        binding_edges=(("action", "delegation"), ("case_action", "delegation")),
    ),
    "policy-snapshot": _manifest(
        "policy-snapshot",
        "policy_registry",
        "policy_registry",
        "hmac-sha256",
        binding_edges=(
            ("action", "policy_version"),
            ("application", "policy_version"),
            ("case_action", "policy_version"),
        ),
    ),
    "model-advice": _manifest(
        "model-advice",
        "model_gateway",
        "model_gateway",
        "hash_chain",
        binding_edges=(("action", "review"),),
    ),
    "human-review": _manifest(
        "human-review",
        "approval_service",
        "approval_service",
        "hmac-sha256",
        binding_edges=(("action", "review"),),
    ),
    "sqlite-ledger-receipt": _manifest(
        "sqlite-ledger-receipt",
        "ledger",
        "ledger",
        "hmac-sha256",
        binding_edges=(("action", "ledger_transaction"),),
        implementation_ref="auditspec.runtime.payment_graph:run_payment_fixture",
    ),
    "gateway-coverage": _manifest(
        "gateway-coverage",
        "action_gateway",
        "action_gateway",
        "hmac-sha256",
        coverage_channels=("tool_dispatch",),
    ),
    "feature-provenance": _manifest(
        "feature-provenance",
        "feature_gateway",
        "feature_gateway",
        "hmac-sha256",
        binding_edges=(("application", "feature"),),
    ),
    "model-decision": _manifest(
        "model-decision",
        "model_gateway",
        "model_gateway",
        "hash_chain",
        binding_edges=(("application", "decision"),),
    ),
    "decision-receipt": _manifest(
        "decision-receipt",
        "decision_service",
        "decision_service",
        "hmac-sha256",
        binding_edges=(("application", "decision"),),
    ),
    "notice-receipt": _manifest(
        "notice-receipt",
        "notice_service",
        "notice_service",
        "hmac-sha256",
        binding_edges=(("application", "adverse_notice"),),
    ),
    "feature-coverage": _manifest(
        "feature-coverage",
        "feature_gateway",
        "feature_gateway",
        "hmac-sha256",
        binding_edges=(("application", "feature"),),
        coverage_channels=("feature_ingest",),
    ),
    "vendor-receipt": _manifest(
        "vendor-receipt",
        "vendor_gateway",
        "vendor_gateway",
        "hmac-sha256",
        binding_edges=(("case_action", "screening_result"),),
    ),
    "analyst-review": _manifest(
        "analyst-review",
        "review_service",
        "review_service",
        "hmac-sha256",
        binding_edges=(("case_action", "review"),),
    ),
    "durable-case-receipt": _manifest(
        "durable-case-receipt",
        "case_store",
        "case_store",
        "hmac-sha256",
        binding_edges=(("case_action", "case_state"),),
    ),
    "vendor-coverage": _manifest(
        "vendor-coverage",
        "vendor_gateway",
        "vendor_gateway",
        "hmac-sha256",
        binding_edges=(("case_action", "screening_result"),),
        coverage_channels=("screening_api",),
    ),
    "predicate-attestation": _manifest(
        "predicate-attestation",
        ("action_gateway", "decision_gateway", "case_gateway"),
        ("action_gateway", "decision_gateway", "case_gateway"),
        "hmac-sha256",
        observation_kinds=("predicate", "relation", "aggregate"),
        binding_edges=(
            ("action", "approval"),
            ("action", "delegation"),
            ("action", "policy_version"),
            ("action", "ledger_transaction"),
            ("application", "policy_version"),
            ("application", "decision"),
            ("application", "feature"),
            ("case_action", "screening_result"),
            ("case_action", "policy_version"),
            ("case_action", "delegation"),
            ("case_action", "review"),
            ("case_action", "case_state"),
        ),
    ),
    "coarse-bucket": _manifest(
        "coarse-bucket",
        ("action_gateway", "policy_registry", "decision_gateway", "case_gateway", "vendor_gateway"),
        ("action_gateway", "policy_registry", "decision_gateway", "case_gateway", "vendor_gateway"),
        "hmac-sha256",
        observation_kinds=("bucket", "presence"),
        binding_edges=(
            ("action", "policy_version"),
            ("application", "policy_version"),
            ("case_action", "policy_version"),
            ("case_action", "screening_result"),
        ),
    ),
    "digest-token": _manifest(
        "digest-token",
        ("action_gateway", "policy_registry", "decision_gateway", "case_gateway", "vendor_gateway"),
        ("action_gateway", "policy_registry", "decision_gateway", "case_gateway", "vendor_gateway"),
        "hmac-sha256",
        observation_kinds=("digest",),
        binding_edges=(
            ("action", "policy_version"),
            ("application", "policy_version"),
            ("case_action", "policy_version"),
            ("case_action", "screening_result"),
        ),
    ),
}


REPLAY_ADAPTERS: Mapping[str, ReplayAdapterManifest] = {
    "sqlite-counterfactual-replay": ReplayAdapterManifest(
        adapter_id="sqlite-counterfactual-replay",
        target="omit_tool_response",
        prefix_checkpoint="before_effect",
        snapshot="sqlite_backup",
        nondeterminism=("agent_decision", "tool_response", "clock"),
        isolation="offline_temp_database",
        side_effect_mode="virtualized",
        verifier="ledger_loss_predicate",
        minimum_trials=1,
        implementation_ref="auditspec.runtime.replay:PaymentReplayHarness",
        assurance_level="executable",
    ),
    "external-wire-replay": ReplayAdapterManifest(
        adapter_id="external-wire-replay",
        target="omit_tool_response",
        prefix_checkpoint="before_effect",
        snapshot="external_bank_state",
        nondeterminism=("tool_response",),
        isolation="production_wire_network",
        side_effect_mode="irreversible",
        verifier="external_balance_diff",
        minimum_trials=1,
        implementation_ref="unavailable",
        assurance_level="schema_only",
    ),
    "feature-ablation": ReplayAdapterManifest(
        adapter_id="feature-ablation",
        target="remove_income_feature",
        prefix_checkpoint="before_model_decision",
        snapshot="application_feature_snapshot",
        nondeterminism=("model_output", "policy_version"),
        isolation="offline_decision_sandbox",
        side_effect_mode="virtualized",
        verifier="denial_outcome_predicate",
        minimum_trials=3,
        implementation_ref="auditspec.runtime.credit_replay:CreditReplayHarness",
        assurance_level="executable",
    ),
    "vendor-ablation": ReplayAdapterManifest(
        adapter_id="vendor-ablation",
        target="remove_vendor_signal",
        prefix_checkpoint="before_screening_decision",
        snapshot="case_state_snapshot",
        nondeterminism=("model_decision", "analyst_decision", "vendor_response"),
        isolation="offline_case_sandbox",
        side_effect_mode="virtualized",
        verifier="release_outcome_predicate",
        minimum_trials=3,
        implementation_ref="planned:aml-vendor-ablation",
        assurance_level="schema_only",
    ),
}

for _replay_adapter in REPLAY_ADAPTERS.values():
    ADAPTER_MANIFESTS[_replay_adapter.adapter_id] = _manifest(
        _replay_adapter.adapter_id,
        "audit_sandbox",
        "audit_sandbox",
        "hmac-sha256",
        modes=("active",),
        binding_edges=(
            ("action", "replay_run"),
            ("application", "replay_run"),
            ("case_action", "replay_run"),
        ),
        refinement_level=(
            "runtime_verified"
            if _replay_adapter.assurance_level == "executable"
            else "schema_only"
        ),
        implementation_ref=_replay_adapter.implementation_ref,
    )


def registry_digest() -> str:
    payload = {
        "schema": ADAPTER_REGISTRY_VERSION,
        "adapters": {
            name: manifest.as_dict()
            for name, manifest in sorted(ADAPTER_MANIFESTS.items())
        },
        "replay_adapters": {
            name: manifest.as_dict() for name, manifest in sorted(REPLAY_ADAPTERS.items())
        },
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def registry_attestation_status() -> tuple[bool, tuple[str, ...]]:
    try:
        if SOURCE_REGISTRY_ATTESTATION_PATH.is_file():
            attestation_path = SOURCE_REGISTRY_ATTESTATION_PATH
            evidence_root = Path(__file__).resolve().parents[2]
            expected_layout = "source_tree"
        else:
            attestation_path = PACKAGE_REGISTRY_ATTESTATION_PATH
            evidence_root = Path(__file__).resolve().parent
            expected_layout = "installed_package"
        raw = json.loads(attestation_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, ("missing:adapter_registry_attestation",)
    except (OSError, json.JSONDecodeError):
        return False, ("invalid:adapter_registry_attestation",)
    reasons: list[str] = []
    if raw.get("schema") != REGISTRY_ATTESTATION_SCHEMA:
        reasons.append("mismatch:adapter_registry_attestation_schema")
    if raw.get("registry_schema") != ADAPTER_REGISTRY_VERSION:
        reasons.append("mismatch:adapter_registry_schema")
    if raw.get("layout") != expected_layout:
        reasons.append("mismatch:adapter_registry_attestation_layout")
    if raw.get("registry_sha256") != registry_digest():
        reasons.append("mismatch:adapter_registry_digest")
    if raw.get("verifier") != "auditspec.adapter_registry:registry_attestation_status":
        reasons.append("mismatch:adapter_registry_verifier")
    evidence = raw.get("evidence")
    if not isinstance(evidence, Mapping):
        reasons.append("missing:adapter_registry_evidence")
    else:
        files = evidence.get("files")
        if not isinstance(files, Mapping) or not files:
            reasons.append("missing:adapter_registry_evidence_files")
        else:
            for relative, expected in sorted(files.items()):
                path = evidence_root / str(relative)
                try:
                    actual = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    reasons.append(f"missing:attested_file:{relative}")
                    continue
                if actual != expected:
                    reasons.append(f"mismatch:attested_file:{relative}")
    for manifest in ADAPTER_MANIFESTS.values():
        if manifest.refinement_level not in {"model_checked", "runtime_verified"}:
            continue
        try:
            module_name, qualified_name = manifest.implementation_ref.split(":", 1)
            implementation: Any = importlib.import_module(module_name)
            for component in qualified_name.split("."):
                implementation = getattr(implementation, component)
            if not callable(implementation):
                reasons.append(f"not_callable:implementation_ref:{manifest.adapter_id}")
        except (ImportError, AttributeError, ValueError):
            reasons.append(f"unresolved:implementation_ref:{manifest.adapter_id}")
    return not reasons, tuple(reasons)


def validate_mechanism_adapter(mechanism: Any) -> tuple[str, ...]:
    attested, attestation_reasons = registry_attestation_status()
    if not attested:
        return attestation_reasons
    manifest = ADAPTER_MANIFESTS.get(mechanism.adapter)
    if manifest is None:
        return (f"unregistered:adapter:{mechanism.adapter}",)
    reasons: list[str] = []
    if mechanism.mode not in manifest.modes:
        reasons.append(f"adapter_mode_mismatch:{mechanism.mode}")
    if mechanism.producer not in manifest.producers:
        reasons.append(f"adapter_producer_mismatch:{mechanism.producer}")
    if mechanism.capture_point not in manifest.capture_points:
        reasons.append(f"adapter_capture_point_mismatch:{mechanism.capture_point}")
    if mechanism.integrity not in manifest.integrity:
        reasons.append(f"adapter_integrity_mismatch:{mechanism.integrity}")
    observation_kinds = {
        observation.kind for observation in getattr(mechanism, "observations", ())
    } or {"exact"}
    unsupported_kinds = observation_kinds - set(manifest.observation_kinds)
    if unsupported_kinds:
        reasons.append(
            f"adapter_observation_kind_mismatch:{','.join(sorted(unsupported_kinds))}"
        )
    unsupported_bindings = set(getattr(mechanism, "binding_edges", ())) - set(
        manifest.binding_edges
    )
    if unsupported_bindings:
        reasons.append(
            "adapter_binding_mismatch:"
            + ",".join(f"{left}->{right}" for left, right in sorted(unsupported_bindings))
        )
    if mechanism.coverage_channel and mechanism.coverage_channel not in manifest.coverage_channels:
        reasons.append(f"adapter_coverage_mismatch:{mechanism.coverage_channel}")
    if manifest.refinement_level not in {"model_checked", "runtime_verified"}:
        reasons.append(f"adapter_refinement_unproven:{manifest.refinement_level}")
    return tuple(reasons)


def validate_replay_adapter(adapter: str, replay: Any) -> tuple[str, ...]:
    manifest = REPLAY_ADAPTERS.get(adapter)
    if manifest is None:
        return (f"unregistered:adapter:{adapter}",)

    reasons: list[str] = []
    exact_fields = {
        "target": manifest.target,
        "prefix_checkpoint": manifest.prefix_checkpoint,
        "snapshot": manifest.snapshot,
        "isolation": manifest.isolation,
        "side_effect_mode": manifest.side_effect_mode,
        "verifier": manifest.verifier,
    }
    for field_name, expected in exact_fields.items():
        actual = getattr(replay, field_name)
        if actual != expected:
            reasons.append(
                f"registry_mismatch:{field_name}:expected={expected}:actual={actual}"
            )
    if tuple(replay.nondeterminism) != manifest.nondeterminism:
        reasons.append("registry_mismatch:nondeterminism")
    if replay.min_trials < manifest.minimum_trials:
        reasons.append(
            f"registry_mismatch:min_trials:minimum={manifest.minimum_trials}"
        )
    if manifest.assurance_level not in {"executable", "schema_only"}:
        reasons.append("invalid:registry_assurance_level")
    return tuple(reasons)
