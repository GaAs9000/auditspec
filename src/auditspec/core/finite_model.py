"""Finite Core model plus an independent SQLite-row adequacy check."""

from __future__ import annotations

import itertools
import sqlite3
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Mapping

from .canonical import canonical_json, digest
from .expression import Expr
from .wire import TypeNode


@dataclass(frozen=True)
class FiniteDomain:
    domain_id: str
    variable_types: Mapping[str, TypeNode]
    variable_domains: Mapping[str, tuple[Any, ...]]
    constraints: tuple[Expr, ...]
    worlds: tuple[dict[str, Any], ...]
    universe_root: str
    domain_root: str

    @classmethod
    def build(
        cls,
        domain_id: str,
        variable_types: Mapping[str, TypeNode],
        variable_domains: Mapping[str, tuple[Any, ...]],
        constraints: tuple[Expr, ...],
    ) -> "FiniteDomain":
        names = tuple(variable_domains)
        worlds: list[dict[str, Any]] = []
        for values in itertools.product(*(variable_domains[name] for name in names)):
            world = dict(zip(names, values))
            if all(bool(constraint.evaluate(world)) for constraint in constraints):
                worlds.append(world)
        if not worlds:
            raise ValueError("finite domain has no satisfying worlds")
        worlds.sort(key=canonical_json)
        universe_root = digest("AuditSpec-core-phase1-finite-universe-v1", worlds)
        domain_payload = {
            "domain_id": domain_id,
            "variable_types": {
                name: variable_types[name].to_wire() for name in sorted(variable_types)
            },
            "variable_domains": {
                name: list(variable_domains[name]) for name in sorted(variable_domains)
            },
            "constraints": [item.to_wire() for item in constraints],
            "universe_root": universe_root,
            "world_count": len(worlds),
        }
        return cls(
            domain_id,
            dict(variable_types),
            dict(variable_domains),
            constraints,
            tuple(worlds),
            universe_root,
            digest("auditspec.impl.finite-domain.v1", domain_payload),
        )

    def record(self) -> dict[str, Any]:
        return {
            "schema": "auditspec.impl.finite-domain.v1",
            "id": self.domain_id,
            "variable_types": {
                name: self.variable_types[name].to_wire()
                for name in sorted(self.variable_types)
            },
            "variable_domains": {
                name: list(self.variable_domains[name])
                for name in sorted(self.variable_domains)
            },
            "constraints": [item.to_wire() for item in self.constraints],
            "universe_root": self.universe_root,
            "world_count": len(self.worlds),
            "domain_root": self.domain_root,
        }


@dataclass(frozen=True)
class ModelTwin:
    execution_a: dict[str, Any]
    execution_b: dict[str, Any]
    abstract_world: dict[str, Any]
    external_truth_a: bool
    external_truth_b: bool
    witness_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "AuditSpec-model-twin-certificate-v1",
            "execution_a": self.execution_a,
            "execution_b": self.execution_b,
            "abstract_world": self.abstract_world,
            "external_truth_a": self.external_truth_a,
            "external_truth_b": self.external_truth_b,
            "witness_digest": self.witness_digest,
        }


@dataclass(frozen=True)
class AdequacyPass:
    domain_root: str
    universe_root: str
    predicate_digest: str
    abstraction_mode: str
    action_id: str
    concrete_executions_checked: int
    abstract_worlds_checked: int
    witness_digest: str

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": "auditspec.impl.model-adequacy-pass.v1",
            "domain_root": self.domain_root,
            "universe_root": self.universe_root,
            "predicate_digest": self.predicate_digest,
            "abstraction_mode": self.abstraction_mode,
            "action_id": self.action_id,
            "concrete_executions_checked": self.concrete_executions_checked,
            "abstract_worlds_checked": self.abstract_worlds_checked,
            "witness_digest": self.witness_digest,
            "concrete_truth_source": "sqlite_select_count_where_action_id",
        }


@dataclass(frozen=True)
class AdequacyGap:
    verdict: str
    twin: ModelTwin


def check_sqlite_count_adequacy(
    domain: FiniteDomain,
    predicate: Expr,
    *,
    action_id: str,
    abstraction_mode: str = "exact_row_count",
) -> AdequacyPass | AdequacyGap:
    """Check abstract count against concrete committed-row populations.

    Concrete executions replace ``ledger_commit_count`` with explicit SQLite
    row identities for the selected action/window. The external truth reads the
    row population; the abstract query reads the reconstructed model variable.
    """

    seen: dict[str, tuple[bool, dict[str, Any], dict[str, Any]]] = {}
    abstract_keys: set[str] = set()
    released_keys = {canonical_json(world) for world in domain.worlds}
    checked = 0
    # Enumerate the concrete row population independently of the abstract count
    # field. Membership is checked only after applying the declared abstraction.
    base_worlds = {
        canonical_json(
            {
                name: value
                for name, value in world.items()
                if name != "ledger_commit_count"
            }
        ): {
            name: value
            for name, value in world.items()
            if name != "ledger_commit_count"
        }
        for world in domain.worlds
    }
    row_count_domain = tuple(domain.variable_domains["ledger_commit_count"])
    for base_key in sorted(base_worlds):
        for raw_row_count in row_count_domain:
            row_count = int(raw_row_count)
            concrete = dict(base_worlds[base_key])
            sqlite_count, sqlite_rows = _sqlite_count_for_action(row_count, action_id)
            concrete["ledger_rows"] = [dict(row) for row in sqlite_rows]
            concrete["sqlite_count_for_action"] = sqlite_count
            external_truth = sqlite_count == 1
            if abstraction_mode == "exact_row_count":
                abstract_count = sqlite_count
            elif abstraction_mode == "cap_at_one":
                abstract_count = min(sqlite_count, 1)
            else:
                raise ValueError("unknown SQLite abstraction mode")
            abstract = dict(concrete)
            abstract.pop("ledger_rows")
            abstract.pop("sqlite_count_for_action")
            abstract["ledger_commit_count"] = abstract_count
            # An abstraction outside the released domain is not silently admitted.
            key = canonical_json(abstract)
            if key not in released_keys:
                continue
            checked += 1
            query_answer = bool(predicate.evaluate(abstract))
            if query_answer != external_truth:
                # Q has already established predicate/query identity. A therefore
                # treats this as an abstraction/model failure, not a new QUERY_GAP.
                previous = seen.get(key)
                if previous is not None and previous[0] != external_truth:
                    return AdequacyGap(
                        "MODEL_GAP",
                        _make_twin(
                            previous[1], concrete, abstract, previous[0], external_truth
                        ),
                    )
            previous = seen.get(key)
            if previous is not None and previous[0] != external_truth:
                return AdequacyGap(
                    "MODEL_GAP",
                    _make_twin(
                        previous[1], concrete, abstract, previous[0], external_truth
                    ),
                )
            seen.setdefault(key, (external_truth, concrete, abstract))
            abstract_keys.add(key)
    if checked == 0:
        raise ValueError("SQLite adequacy domain is empty")
    witness = {
        "domain_root": domain.domain_root,
        "universe_root": domain.universe_root,
        "predicate_digest": predicate.ast_digest,
        "abstraction_mode": abstraction_mode,
        "concrete_executions_checked": checked,
        "abstract_worlds_checked": len(abstract_keys),
        "external_truth_source": "sqlite_select_count_where_action_id",
        "action_id": action_id,
    }
    return AdequacyPass(
        domain.domain_root,
        domain.universe_root,
        predicate.ast_digest,
        abstraction_mode,
        action_id,
        checked,
        len(abstract_keys),
        digest("auditspec.impl.model-adequacy-pass.v1", witness),
    )


@lru_cache(maxsize=32)
def _sqlite_count_for_action(
    target_row_count: int, action_id: str
) -> tuple[int, tuple[dict[str, Any], ...]]:
    """Execute the pinned fixture's concrete COUNT-by-action semantics."""

    if target_row_count < 0:
        raise ValueError("SQLite row count cannot be negative")
    with sqlite3.connect(":memory:") as connection:
        connection.execute(
            "CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "run_id TEXT NOT NULL, action_id TEXT NOT NULL, amount INTEGER NOT NULL, "
            "route TEXT NOT NULL)"
        )
        for index in range(target_row_count):
            connection.execute(
                "INSERT INTO ledger(run_id, action_id, amount, route) VALUES (?, ?, ?, ?)",
                (f"target_{index}", action_id, 150, "gateway"),
            )
        # A distractor row proves the concrete query is scoped by action_id,
        # matching payment_graph.py's actual WHERE clause.
        connection.execute(
            "INSERT INTO ledger(run_id, action_id, amount, route) VALUES (?, ?, ?, ?)",
            ("distractor", "other_action", 150, "gateway"),
        )
        connection.commit()
        count = int(
            connection.execute(
                "SELECT COUNT(*) FROM ledger WHERE action_id = ?", (action_id,)
            ).fetchone()[0]
        )
        rows = tuple(
            {
                "row_id": int(row[0]),
                "run_id": str(row[1]),
                "action_id": str(row[2]),
                "amount": int(row[3]),
                "route": str(row[4]),
            }
            for row in connection.execute(
                "SELECT id, run_id, action_id, amount, route FROM ledger "
                "WHERE action_id = ? ORDER BY id",
                (action_id,),
            ).fetchall()
        )
    return count, rows


def _make_twin(
    execution_a: dict[str, Any],
    execution_b: dict[str, Any],
    abstract: dict[str, Any],
    truth_a: bool,
    truth_b: bool,
) -> ModelTwin:
    body = {
        "execution_a": execution_a,
        "execution_b": execution_b,
        "abstract_world": abstract,
        "external_truth_a": truth_a,
        "external_truth_b": truth_b,
    }
    return ModelTwin(
        execution_a,
        execution_b,
        abstract,
        truth_a,
        truth_b,
        digest("AuditSpec-model-twin-certificate-v1", body),
    )
