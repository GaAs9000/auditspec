"""AppWorld binding for the generic instrumented dispatch boundary.

AppWorld agents act through HTTP-style app APIs. This module adapts that
shape to the environment-agnostic :class:`ToolExecutor` protocol so the same
Complete Interaction Ledger and Write-Effect Ledger used for τ² capture
AppWorld API calls unchanged:

- ``is_mutating`` classifies by HTTP method (POST/PUT/PATCH/DELETE mutate),
  matching the effectful-call definition used by the v0.6 AppWorld adapter;
- ``state_root`` commits to the durable app state supplied by the host;
- ``execute`` forwards to the host dispatch callable and maps HTTP-style
  failure statuses onto the receipt error flag.

The host supplies dispatch and state access; nothing here contacts AppWorld.

This module is deliberately *not* re-exported from
``auditspec.adapters.__init__``: that package init is pinned by the v0.8 live
freeze bundle, while this binding is additive post-freeze code.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .instrumented import ExecutedResult

MUTATING_METHODS = frozenset({"post", "put", "patch", "delete"})


def split_api_tool_name(tool_name: str) -> tuple[str, str]:
    """Split an AppWorld API tool name (``"METHOD app/endpoint"``)."""

    method, _, path = str(tool_name).partition(" ")
    return method.lower(), path


class AppWorldApiExecutor:
    """ToolExecutor over a host-supplied AppWorld API dispatch callable."""

    def __init__(
        self,
        *,
        dispatch: Callable[[str, str, Mapping[str, Any]], tuple[Any, int]],
        state_root: Callable[[], str],
        mutating_methods: frozenset[str] = MUTATING_METHODS,
    ) -> None:
        self._dispatch = dispatch
        self._state_root = state_root
        self._mutating_methods = mutating_methods

    def is_mutating(self, tool_name: str) -> bool:
        method, _ = split_api_tool_name(tool_name)
        return method in self._mutating_methods

    def state_root(self) -> str:
        return self._state_root()

    def execute(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        requestor: str,
    ) -> ExecutedResult:
        method, path = split_api_tool_name(tool_name)
        if not method or not path:
            raise ValueError(f"malformed AppWorld API tool name: {tool_name!r}")
        content, status = self._dispatch(method, path, arguments)
        return ExecutedResult(call_id=call_id, content=content, error=status >= 400)
