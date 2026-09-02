"""Generic instrumented dispatch boundary for the v0.8 runtime.

The dispatcher wraps a host environment's tool executor and captures the
receipt families defined in :mod:`auditspec.adapters.receipts` at the trust
boundary, outside the agent:

- a Complete Interaction Ledger entry for every dispatched call;
- a Write-Effect Ledger entry for every mutating call, with the pre/post
  state roots observed around execution.

The host supplies three capabilities through :class:`ToolExecutor`: mutation
classification, a state root, and execution. Nothing here is τ²-specific.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from . import receipts


class ToolExecutor(Protocol):
    """Host-environment capabilities required at the dispatch boundary."""

    def is_mutating(self, tool_name: str) -> bool:
        """Whether dispatching ``tool_name`` can change durable state."""

    def state_root(self) -> str:
        """Commitment to the current durable state (both agent/user views)."""

    def execute(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        requestor: str,
    ) -> "ExecutedResult":
        """Execute one call and return its result content and error flag."""


@dataclass(frozen=True)
class ExecutedResult:
    call_id: str
    content: Any
    error: bool


class InstrumentedDispatcher:
    """Captures interaction and write-effect receipts around a ToolExecutor."""

    def __init__(self, executor: ToolExecutor, *, agent_requestor: str = "assistant"):
        self._executor = executor
        self._agent_requestor = agent_requestor
        self._ledger: list[dict[str, Any]] = []
        self._write_ledger: list[dict[str, Any]] = []
        self._request_ledger: list[dict[str, Any]] = []
        self._terminal_dispositions: list[dict[str, Any]] = []

    @property
    def interaction_ledger(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._ledger)

    @property
    def write_effect_ledger(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._write_ledger)

    @property
    def request_ledger(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._request_ledger)

    @property
    def terminal_dispositions(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._terminal_dispositions)

    def record_request(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        requestor: str,
    ) -> None:
        """Capture a request before the orchestrator attempts dispatch."""

        existing = next(
            (entry for entry in self._request_ledger if entry["call_id"] == call_id),
            None,
        )
        candidate = receipts.interaction_request_entry(
            sequence=(
                int(existing["sequence"])
                if existing is not None
                else len(self._request_ledger)
            ),
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            requestor=requestor,
            mutating=self._executor.is_mutating(tool_name),
        )
        if existing is not None:
            if existing != candidate:
                raise ValueError(f"conflicting request reuse for call id {call_id!r}")
            return
        self._request_ledger.append(candidate)

    def close_requests(self, *, termination_reason: str) -> None:
        """Commit terminal dispositions for requests with no tool result."""

        result_ids = {str(entry["call_id"]) for entry in self._ledger}
        existing = {str(entry["call_id"]) for entry in self._terminal_dispositions}
        for request in self._request_ledger:
            call_id = str(request["call_id"])
            if call_id in result_ids or call_id in existing:
                continue
            self._terminal_dispositions.append(
                receipts.request_disposition_entry(
                    request=request, termination_reason=termination_reason
                )
            )

    def execute_call(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        requestor: str,
    ) -> ExecutedResult:
        """Dispatch one tool call, capturing receipts around execution."""

        self.record_request(
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            requestor=requestor,
        )
        if any(entry["call_id"] == call_id for entry in self._ledger):
            raise ValueError(f"duplicate result for call id {call_id!r}")
        sequence = len(self._ledger)
        mutating = self._executor.is_mutating(tool_name)
        pre_root = self._executor.state_root() if mutating else None
        result = self._executor.execute(
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            requestor=requestor,
        )
        if result.call_id != call_id:
            raise ValueError(
                f"executor returned result for {result.call_id!r}, expected {call_id!r}"
            )
        self._ledger.append(
            receipts.interaction_ledger_entry(
                sequence=sequence,
                call_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
                requestor=requestor,
                result_content=result.content,
                error=result.error,
            )
        )
        if mutating:
            post_root = self._executor.state_root()
            entry = receipts.write_effect_entry(
                sequence=sequence,
                call_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
                pre_state_root=pre_root if pre_root is not None else "",
                post_state_root=post_root,
            )
            if requestor == self._agent_requestor:
                self._write_ledger.append(entry)
        return result

    def tool_result_coverage(
        self,
        *,
        run_id: str,
        task_id: str,
        requested_not_dispatched: int = 0,
    ) -> dict[str, Any]:
        """Run-level coverage closure over agent-requested calls (T06)."""

        agent_entries = [
            entry
            for entry in self._ledger
            if entry["requestor"] == self._agent_requestor
        ]
        request_entries = [
            entry
            for entry in self._request_ledger
            if entry["requestor"] == self._agent_requestor
        ]
        dispositions = [
            entry
            for entry in self._terminal_dispositions
            if entry["requestor"] == self._agent_requestor
        ]
        return receipts.tool_result_coverage_receipt(
            run_id=run_id,
            task_id=task_id,
            agent_requested_call_count=len(request_entries),
            entries=agent_entries,
            requested_not_dispatched=requested_not_dispatched,
            request_entries=request_entries,
            terminal_dispositions=dispositions,
        )

    def write_coverage(
        self,
        *,
        run_id: str,
        task_id: str,
        agent_requested_write_count: int | None = None,
    ) -> dict[str, Any]:
        """Run-level closure over the write-effect ledger (T04)."""

        return receipts.write_coverage_receipt(
            run_id=run_id,
            task_id=task_id,
            agent_requested_write_count=(
                agent_requested_write_count
                if agent_requested_write_count is not None
                else sum(
                    entry["requestor"] == self._agent_requestor
                    and bool(entry.get("mutating"))
                    for entry in self._request_ledger
                )
            ),
            entries=self._write_ledger,
            request_entries=(
                [
                    entry
                    for entry in self._request_ledger
                    if entry["requestor"] == self._agent_requestor
                ]
                if agent_requested_write_count is None
                else None
            ),
            terminal_dispositions=[
                entry
                for entry in self._terminal_dispositions
                if entry["requestor"] == self._agent_requestor
            ],
        )


def ledgers_root_map(
    *,
    interaction: Sequence[Mapping[str, Any]],
    write_effect: Sequence[Mapping[str, Any]],
    requests: Sequence[Mapping[str, Any]] = (),
    terminal_dispositions: Sequence[Mapping[str, Any]] = (),
) -> dict[str, str]:
    """Ledger roots consumed by the run-closure receipt."""

    return {
        "tool_result_ledger_root": receipts.ledger_root(interaction),
        "write_ledger_root": receipts.ledger_root(write_effect),
        "request_ledger_root": receipts.ledger_root(requests),
        "terminal_disposition_root": receipts.ledger_root(terminal_dispositions),
    }
