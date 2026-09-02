from __future__ import annotations

import hashlib
import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from .events import canonical_json


@dataclass(frozen=True)
class PlannerDecision:
    """A reproducible decision from the seeded planner used by runtime fixtures.

    The planner is intentionally small: it provides genuine stochastic branches
    without introducing a network/model-service dependency into the artifact.
    Its seed, version and input/output digest are retained as replay evidence.
    """

    planner_id: str
    planner_version: str
    seed: int
    output: str
    trace_digest: str
    reason_code: str = "unspecified"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SeededPlanner:
    planner_id = "auditspec-seeded-policy-planner"
    planner_version = "1.0.0"

    def __init__(self, seed: int) -> None:
        self.seed = int(seed)
        self._rng = random.Random(self.seed)

    def payment(
        self,
        *,
        amount: int,
        policy_limit: int,
        context: Mapping[str, Any] | None = None,
    ) -> PlannerDecision:
        baseline = "approve" if amount <= policy_limit else "deny"
        # A bounded exploration branch makes the fixture genuinely stochastic
        # while remaining exactly reproducible from the retained seed.
        output = (
            "deny" if baseline == "approve" else "approve"
        ) if self._rng.random() < 0.25 else baseline
        return self._decision(
            task="payment",
            inputs={"amount": int(amount), "policy_limit": int(policy_limit)},
            output=output,
        )

    def credit(
        self,
        *,
        score: int,
        policy_threshold: int,
        context: Mapping[str, Any] | None = None,
    ) -> PlannerDecision:
        baseline = "approve" if score >= policy_threshold else "deny"
        output = (
            "deny" if baseline == "approve" else "approve"
        ) if self._rng.random() < 0.25 else baseline
        return self._decision(
            task="credit",
            inputs={"score": int(score), "policy_threshold": int(policy_threshold)},
            output=output,
        )

    def _decision(
        self, *, task: str, inputs: dict[str, Any], output: str
    ) -> PlannerDecision:
        payload = {
            "planner_id": self.planner_id,
            "planner_version": self.planner_version,
            "seed": self.seed,
            "task": task,
            "inputs": inputs,
            "output": output,
        }
        return PlannerDecision(
            planner_id=self.planner_id,
            planner_version=self.planner_version,
            seed=self.seed,
            output=output,
            trace_digest=hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest(),
        )


class PlannerProtocolError(RuntimeError):
    """The model endpoint returned no valid, typed planner decision."""


@dataclass(frozen=True)
class LLMCallTrace:
    """Reproducibility record for one external planner call.

    The trace retains the complete request and the audit-relevant response, but
    replaces free-form hidden reasoning with a digest.  Reasoning is neither a
    trusted observation nor an input to the AuditSpec verifier.
    """

    request: dict[str, Any]
    response: dict[str, Any]
    request_sha256: str
    response_sha256: str
    latency_ms: float
    prompt_tokens: int | None
    completion_tokens: int | None
    protocol_valid: bool
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class OpenAICompatiblePlanner:
    """Typed payment/credit planner backed by an OpenAI-compatible endpoint."""

    planner_version = "openai-compatible-v1"

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        model_revision: str,
        seed: int,
        reasoning_mode: str = "thinking",
        timeout_seconds: float = 180.0,
        max_tokens: int = 2048,
    ) -> None:
        if reasoning_mode not in {"thinking", "instruct"}:
            raise ValueError("reasoning_mode must be 'thinking' or 'instruct'")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.model_revision = model_revision
        self.seed = int(seed)
        self.reasoning_mode = reasoning_mode
        self.timeout_seconds = float(timeout_seconds)
        self.max_tokens = int(max_tokens)
        self.traces: list[LLMCallTrace] = []

    @property
    def planner_id(self) -> str:
        return self.model

    def payment(
        self,
        *,
        amount: int,
        policy_limit: int,
        context: Mapping[str, Any] | None = None,
    ) -> PlannerDecision:
        source = dict(context or {})
        values = {
            "amount": int(amount),
            "policy_limit": int(policy_limit),
            "approval_signature_valid": bool(
                source.get("approval_signature_valid", True)
            ),
            "approval_action_bound": bool(source.get("approval_action_bound", True)),
            "delegation_scope_payment": bool(
                source.get("delegation_scope_payment", True)
            ),
            "delegation_executor_bound": bool(
                source.get("delegation_executor_bound", True)
            ),
            "policy_effective": bool(source.get("policy_effective", True)),
        }
        return self._call(
            task="payment",
            values=values,
            tool_name="record_payment_decision",
            reason_codes=(
                "within_policy",
                "amount_exceeds_limit",
                "invalid_approval",
                "unbound_approval",
                "invalid_delegation",
                "inactive_policy",
                "insufficient_evidence",
            ),
            policy=(
                "Approve only when amount is within the effective policy limit, "
                "approval is valid and action-bound, and delegation scope and "
                "executor binding are valid. Otherwise deny."
            ),
        )

    def credit(
        self,
        *,
        score: int,
        policy_threshold: int,
        context: Mapping[str, Any] | None = None,
    ) -> PlannerDecision:
        source = dict(context or {})
        values = {
            "score": int(score),
            "policy_threshold": int(policy_threshold),
            "policy_effective": bool(source.get("policy_effective", True)),
            "income_source_verified": bool(
                source.get("income_source_verified", True)
            ),
            "feature_source_bound": bool(source.get("feature_source_bound", True)),
        }
        return self._call(
            task="credit",
            values=values,
            tool_name="record_credit_decision",
            reason_codes=(
                "meets_threshold",
                "below_threshold",
                "unverified_income_source",
                "unbound_feature_source",
                "inactive_policy",
                "insufficient_evidence",
            ),
            policy=(
                "Approve only when score meets the effective threshold and the "
                "income and feature sources are verified and bound. Otherwise deny."
            ),
        )

    def _call(
        self,
        *,
        task: str,
        values: Mapping[str, Any],
        tool_name: str,
        reason_codes: tuple[str, ...],
        policy: str,
    ) -> PlannerDecision:
        schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "decision": {"type": "string", "enum": ["approve", "deny"]},
                "reason_code": {"type": "string", "enum": list(reason_codes)},
            },
            "required": ["decision", "reason_code"],
        }
        request_payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a bounded financial workflow planner. Apply the "
                        "stated policy exactly. Call the supplied decision tool "
                        "once; do not invent missing facts."
                    ),
                },
                {
                    "role": "user",
                    "content": canonical_json(
                        {"task": task, "policy": policy, "observed_inputs": values}
                    ),
                },
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "description": "Record the planner's typed decision.",
                        "parameters": schema,
                    },
                }
            ],
            "tool_choice": "required",
            "seed": self.seed,
            "max_tokens": self.max_tokens,
            "chat_template_kwargs": {
                "enable_thinking": self.reasoning_mode == "thinking"
            },
        }
        if self.reasoning_mode == "thinking":
            request_payload.update(
                {"temperature": 1.0, "top_p": 0.95, "top_k": 20}
            )
        else:
            request_payload.update(
                {
                    "temperature": 0.7,
                    "top_p": 0.8,
                    "top_k": 20,
                    "presence_penalty": 1.5,
                }
            )

        endpoint = (
            self.base_url + "/chat/completions"
            if self.base_url.endswith("/v1")
            else self.base_url + "/v1/chat/completions"
        )
        encoded = canonical_json(request_payload).encode("utf-8")
        started = time.perf_counter_ns()
        response_payload: dict[str, Any] = {}
        error: str | None = None
        try:
            request = urllib.request.Request(
                endpoint,
                data=encoded,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
            arguments = self._tool_arguments(response_payload, tool_name)
            decision = str(arguments["decision"])
            reason_code = str(arguments["reason_code"])
            if decision not in {"approve", "deny"} or reason_code not in reason_codes:
                raise PlannerProtocolError("tool arguments violate the decision schema")
            valid = True
        except (
            KeyError,
            IndexError,
            TypeError,
            ValueError,
            PlannerProtocolError,
            json.JSONDecodeError,
            urllib.error.URLError,
            TimeoutError,
        ) as exc:
            error = f"{type(exc).__name__}: {exc}"
            valid = False
            decision = ""
            reason_code = ""

        latency_ms = (time.perf_counter_ns() - started) / 1_000_000
        sanitized = _sanitize_response(response_payload)
        usage = response_payload.get("usage", {})
        trace = LLMCallTrace(
            request=request_payload,
            response=sanitized,
            request_sha256=hashlib.sha256(encoded).hexdigest(),
            response_sha256=hashlib.sha256(
                canonical_json(sanitized).encode("utf-8")
            ).hexdigest(),
            latency_ms=latency_ms,
            prompt_tokens=_optional_int(usage.get("prompt_tokens")),
            completion_tokens=_optional_int(usage.get("completion_tokens")),
            protocol_valid=valid,
            error=error,
        )
        self.traces.append(trace)
        if not valid:
            raise PlannerProtocolError(error or "invalid planner response")
        trace_digest = hashlib.sha256(
            canonical_json(
                {
                    "request_sha256": trace.request_sha256,
                    "response_sha256": trace.response_sha256,
                    "model_revision": self.model_revision,
                }
            ).encode("utf-8")
        ).hexdigest()
        return PlannerDecision(
            planner_id=self.model,
            planner_version=self.model_revision,
            seed=self.seed,
            output=decision,
            trace_digest=trace_digest,
            reason_code=reason_code,
            metadata={
                "reasoning_mode": self.reasoning_mode,
                "request_sha256": trace.request_sha256,
                "response_sha256": trace.response_sha256,
                "latency_ms": latency_ms,
                "prompt_tokens": trace.prompt_tokens,
                "completion_tokens": trace.completion_tokens,
            },
        )

    @staticmethod
    def _tool_arguments(response: Mapping[str, Any], tool_name: str) -> dict[str, Any]:
        message = response["choices"][0]["message"]
        calls = message["tool_calls"]
        if len(calls) != 1 or calls[0]["function"]["name"] != tool_name:
            raise PlannerProtocolError("model did not call the required tool exactly once")
        arguments = calls[0]["function"]["arguments"]
        if isinstance(arguments, str):
            arguments = json.loads(arguments)
        if not isinstance(arguments, dict):
            raise PlannerProtocolError("tool arguments are not a JSON object")
        return arguments


def _sanitize_response(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"reasoning", "reasoning_content"} and isinstance(item, str):
                sanitized[key] = {
                    "redacted": True,
                    "utf8_bytes": len(item.encode("utf-8")),
                    "sha256": hashlib.sha256(item.encode("utf-8")).hexdigest(),
                }
            else:
                sanitized[key] = _sanitize_response(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_response(item) for item in value]
    return value


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
