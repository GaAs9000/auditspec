from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

from .model import DeploymentTopology


@dataclass(frozen=True)
class MediationProof:
    channel: str
    valid: bool
    mediator: str | None
    checked_pairs: tuple[tuple[str, str], ...]
    bypass_witnesses: tuple[tuple[str, ...], ...] = ()
    reason: str | None = None


def verify_mediation(
    topology: DeploymentTopology,
    channel_name: str,
    *,
    bypass_edges: Iterable[tuple[str, str]] = (),
) -> MediationProof:
    """Prove that the declared mediator dominates every source-to-sink path.

    For each source/sink pair we require a reachable deployment path, then remove
    the mediator and search again. Any surviving path is a concrete bypass
    witness. This is a graph proof, not a capability label.
    """

    channel = topology.channels.get(channel_name)
    if channel is None:
        return MediationProof(
            channel=channel_name,
            valid=False,
            mediator=None,
            checked_pairs=(),
            reason="unknown_channel",
        )
    edges = tuple(dict.fromkeys((*topology.edges, *tuple(bypass_edges))))
    checked: list[tuple[str, str]] = []
    bypasses: list[tuple[str, ...]] = []
    for source in channel.sources:
        for sink in channel.sinks:
            checked.append((source, sink))
            path = _shortest_path(edges, source, sink, removed=None)
            if path is None:
                return MediationProof(
                    channel=channel_name,
                    valid=False,
                    mediator=channel.mediator,
                    checked_pairs=tuple(checked),
                    reason=f"unreachable:{source}:{sink}",
                )
            if source == channel.mediator or sink == channel.mediator:
                continue
            bypass = _shortest_path(edges, source, sink, removed=channel.mediator)
            if bypass is not None:
                bypasses.append(bypass)
    return MediationProof(
        channel=channel_name,
        valid=not bypasses,
        mediator=channel.mediator,
        checked_pairs=tuple(checked),
        bypass_witnesses=tuple(bypasses),
        reason=None if not bypasses else "mediator_does_not_dominate",
    )


def _shortest_path(
    edges: Iterable[tuple[str, str]],
    source: str,
    sink: str,
    *,
    removed: str | None,
) -> tuple[str, ...] | None:
    if source == removed or sink == removed:
        return None
    adjacency: dict[str, list[str]] = defaultdict(list)
    for left, right in edges:
        if left == removed or right == removed:
            continue
        adjacency[left].append(right)
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(source, (source,))])
    visited = {source}
    while queue:
        current, path = queue.popleft()
        if current == sink:
            return path
        for next_node in sorted(adjacency.get(current, ())):
            if next_node not in visited:
                visited.add(next_node)
                queue.append((next_node, (*path, next_node)))
    return None
