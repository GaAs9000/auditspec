from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    run_id: str
    sequence: int
    mechanism: str
    adapter_id: str
    adapter_version: str
    registry_sha256: str
    producer: str
    capture_point: str
    action_id: str
    attributes: dict[str, Any]
    captured_ns: int
    previous_hash: str
    event_hash: str
    signature: str
    capture_latency_ms: float

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventSink:
    """Small chained/HMAC event sink for the deterministic runtime fixture.

    HMAC authenticates the fixture's producer-to-sink binding. It does not claim
    that a signed attribute is semantically true.
    """

    def __init__(
        self,
        enabled_mechanisms: Iterable[str],
        producer_keys: Mapping[str, bytes] | None = None,
    ) -> None:
        self.enabled_mechanisms = frozenset(enabled_mechanisms)
        self.producer_keys = dict(producer_keys or {})
        self.events: list[AuditEvent] = []
        self._last_hash: dict[str, str] = {}
        self._sequence: dict[str, int] = {}

    def _key(self, producer: str) -> bytes:
        return self.producer_keys.get(
            producer,
            hashlib.sha256(f"auditspec-fixture:{producer}".encode("utf-8")).digest(),
        )

    def emit(
        self,
        *,
        mechanism: str,
        adapter_id: str = "unregistered",
        adapter_version: str = "0",
        registry_sha256: str = "",
        producer: str,
        capture_point: str,
        run_id: str,
        action_id: str,
        attributes: Mapping[str, Any],
    ) -> AuditEvent | None:
        if mechanism not in self.enabled_mechanisms:
            return None
        started = time.perf_counter_ns()
        sequence = self._sequence.get(run_id, 0) + 1
        previous_hash = self._last_hash.get(run_id, "0" * 64)
        captured_ns = time.time_ns()
        body = {
            "run_id": run_id,
            "sequence": sequence,
            "mechanism": mechanism,
            "adapter_id": adapter_id,
            "adapter_version": adapter_version,
            "registry_sha256": registry_sha256,
            "producer": producer,
            "capture_point": capture_point,
            "action_id": action_id,
            "attributes": dict(attributes),
            "captured_ns": captured_ns,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            (previous_hash + canonical_json(body)).encode("utf-8")
        ).hexdigest()
        signature = hmac.new(
            self._key(producer), event_hash.encode("ascii"), hashlib.sha256
        ).hexdigest()
        event_id = hashlib.sha256(
            f"{run_id}:{sequence}:{event_hash}".encode("utf-8")
        ).hexdigest()[:24]
        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        event = AuditEvent(
            event_id=event_id,
            run_id=run_id,
            sequence=sequence,
            mechanism=mechanism,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            registry_sha256=registry_sha256,
            producer=producer,
            capture_point=capture_point,
            action_id=action_id,
            attributes=dict(attributes),
            captured_ns=captured_ns,
            previous_hash=previous_hash,
            event_hash=event_hash,
            signature=signature,
            capture_latency_ms=latency_ms,
        )
        self.events.append(event)
        self._last_hash[run_id] = event_hash
        self._sequence[run_id] = sequence
        return event

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prior: dict[str, str] = {}
        expected_sequence: dict[str, int] = {}
        for event in self.events:
            sequence = expected_sequence.get(event.run_id, 0) + 1
            previous_hash = prior.get(event.run_id, "0" * 64)
            if event.sequence != sequence:
                errors.append(f"sequence:{event.event_id}")
            if event.previous_hash != previous_hash:
                errors.append(f"chain:{event.event_id}")
            body = {
                "run_id": event.run_id,
                "sequence": event.sequence,
                "mechanism": event.mechanism,
                "adapter_id": event.adapter_id,
                "adapter_version": event.adapter_version,
                "registry_sha256": event.registry_sha256,
                "producer": event.producer,
                "capture_point": event.capture_point,
                "action_id": event.action_id,
                "attributes": event.attributes,
                "captured_ns": event.captured_ns,
                "previous_hash": event.previous_hash,
            }
            event_hash = hashlib.sha256(
                (event.previous_hash + canonical_json(body)).encode("utf-8")
            ).hexdigest()
            signature = hmac.new(
                self._key(event.producer), event_hash.encode("ascii"), hashlib.sha256
            ).hexdigest()
            if event_hash != event.event_hash:
                errors.append(f"hash:{event.event_id}")
            if not hmac.compare_digest(signature, event.signature):
                errors.append(f"signature:{event.event_id}")
            prior[event.run_id] = event.event_hash
            expected_sequence[event.run_id] = event.sequence
        return not errors, errors

    def serialized_bytes(self, mechanisms: Iterable[str] | None = None) -> int:
        selected = frozenset(mechanisms) if mechanisms is not None else None
        return sum(
            len((canonical_json(event.as_dict()) + "\n").encode("utf-8"))
            for event in self.events
            if selected is None or event.mechanism in selected
        )

    def bytes_by_mechanism(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for event in self.events:
            result[event.mechanism] = result.get(event.mechanism, 0) + len(
                (canonical_json(event.as_dict()) + "\n").encode("utf-8")
            )
        return result

    def latency_by_mechanism(self) -> dict[str, list[float]]:
        result: dict[str, list[float]] = {}
        for event in self.events:
            result.setdefault(event.mechanism, []).append(event.capture_latency_ms)
        return result

    def write_jsonl(self, path: str | Path) -> None:
        text = "".join(canonical_json(event.as_dict()) + "\n" for event in self.events)
        Path(path).write_text(text, encoding="utf-8")
