"""Generic runtime evidence adapters for the v0.8 instrumented runtime.

The compiler's contracts name mechanisms; this package holds their generic
runtime realizations (receipt schemas and the instrumented dispatch
boundary). Environment bindings (τ², AppWorld) live in ``experiments/``.
"""

from .instrumented import (
    ExecutedResult,
    InstrumentedDispatcher,
    ToolExecutor,
    ledgers_root_map,
)
from .receipts import (
    RECEIPT_SCHEMA,
    canonical_json_bytes,
    interaction_ledger_entry,
    interaction_request_entry,
    ledger_root,
    policy_delivery_receipt,
    run_closure_receipt,
    request_disposition_entry,
    sha256_text,
    sha256_value,
    termination_receipt,
    tool_result_coverage_receipt,
    write_coverage_receipt,
    write_effect_entry,
)

__all__ = [
    "ExecutedResult",
    "InstrumentedDispatcher",
    "RECEIPT_SCHEMA",
    "ToolExecutor",
    "canonical_json_bytes",
    "interaction_ledger_entry",
    "interaction_request_entry",
    "ledger_root",
    "ledgers_root_map",
    "policy_delivery_receipt",
    "run_closure_receipt",
    "request_disposition_entry",
    "sha256_text",
    "sha256_value",
    "termination_receipt",
    "tool_result_coverage_receipt",
    "write_coverage_receipt",
    "write_effect_entry",
]
