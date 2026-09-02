from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from ..adapter_registry import REPLAY_ADAPTERS
from ..model import ReplayContract
from .events import canonical_json


REPLAY_PROOF_SCHEMA = "AuditSpec-replay-proof-v2"


def nondeterminism_capture(
    source: str,
    original_value: Any,
    replay_values: Sequence[Any],
    *,
    mode: str,
) -> dict[str, Any]:
    if mode not in {"captured", "intervened", "frozen", "proved_unused"}:
        raise ValueError(f"Unsupported nondeterminism capture mode: {mode}")
    payload = {
        "source": source,
        "mode": mode,
        "original_value": original_value,
        "replay_values": list(replay_values),
    }
    payload["value_digest"] = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload


def build_replay_proof(
    replay: ReplayContract,
    *,
    adapter_id: str,
    captures: Mapping[str, Mapping[str, Any]],
    trials: int,
    prefix_equal: bool,
    verifier_passed: bool,
) -> dict[str, Any]:
    manifest = REPLAY_ADAPTERS.get(adapter_id)
    if manifest is None:
        raise ValueError(f"Unregistered replay adapter: {adapter_id}")
    capture_map = {name: dict(value) for name, value in sorted(captures.items())}
    capture_digest = hashlib.sha256(
        canonical_json(capture_map).encode("utf-8")
    ).hexdigest()
    return {
        "schema": REPLAY_PROOF_SCHEMA,
        "adapter_id": adapter_id,
        "implementation_ref": manifest.implementation_ref,
        "target": replay.target,
        "prefix_checkpoint": replay.prefix_checkpoint,
        "snapshot": replay.snapshot,
        "nondeterminism": list(replay.nondeterminism),
        "nondeterminism_capture": capture_map,
        "nondeterminism_capture_digest": capture_digest,
        "isolation": replay.isolation,
        "side_effect_mode": replay.side_effect_mode,
        "verifier": replay.verifier,
        "trials": int(trials),
        "prefix_equal": bool(prefix_equal),
        "verifier_passed": bool(verifier_passed),
    }
