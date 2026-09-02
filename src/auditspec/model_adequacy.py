from __future__ import annotations

import copy
import hashlib
import itertools
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .catalog import spec_digest
from .compiler import AuditCompiler
from .expr import evaluate, referenced_names
from .model import AuditSpec, Query, SynthesisResult, World
from .runtime.events import canonical_json
from .spec import enumerate_worlds


MODEL_TWIN_SCHEMA = "AuditSpec-model-twin-certificate-v1"
ADEQUACY_SUITE_FORMAT = "AuditSpec-model-adequacy-suite-v1"
ASSURANCE_CHECKING_ORDER = ("Q", "A", "D", "R", "M", "V")


class AssuranceVerdict(StrEnum):
    QUERY_GAP = "QUERY_GAP"
    MODEL_GAP = "MODEL_GAP"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    TCB_GAP = "TCB_GAP"
    INTERVENTION_GAP = "INTERVENTION_GAP"
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    CONTRACT_READY = "CONTRACT_READY"
    VERIFIED_AUDITABLE = "VERIFIED_AUDITABLE"


@dataclass(frozen=True)
class AdequacyCase:
    obligation_id: str
    pack: str
    external_predicate: str
    abstract_query: str | None
    external_variables: Mapping[str, tuple[Any, ...]]
    concrete_constraints: tuple[str, ...] = ()
    abstraction: Mapping[str, str] | None = None
    missing_semantics: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    kind: str = "fact"
    anchor_entity: str | None = None
    intervention_target: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "pack": self.pack,
            "external_predicate": self.external_predicate,
            "abstract_query": self.abstract_query,
            "external_variables": {
                name: list(values)
                for name, values in sorted(self.external_variables.items())
            },
            "concrete_constraints": list(self.concrete_constraints),
            "abstraction": dict(sorted((self.abstraction or {}).items())),
            "missing_semantics": list(self.missing_semantics),
            "source_refs": list(self.source_refs),
            "kind": self.kind,
            "anchor_entity": self.anchor_entity,
            "intervention_target": self.intervention_target,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.as_dict()).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class ModelTwinCertificate:
    schema_version: str
    case_digest: str
    spec_digest: str
    obligation_id: str
    pack: str
    execution_a: Mapping[str, Any]
    execution_b: Mapping[str, Any]
    abstract_world: Mapping[str, Any]
    external_truth_a: bool
    external_truth_b: bool
    missing_semantics: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["certificate_type"] = "model-inadequacy"
        result["missing_semantics"] = list(self.missing_semantics)
        return result

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ModelTwinCertificate":
        if raw.get("certificate_type") not in {None, "model-inadequacy"}:
            raise ValueError("Unsupported model-adequacy certificate type")
        return cls(
            schema_version=str(raw.get("schema_version", "")),
            case_digest=str(raw.get("case_digest", "")),
            spec_digest=str(raw.get("spec_digest", "")),
            obligation_id=str(raw.get("obligation_id", "")),
            pack=str(raw.get("pack", "")),
            execution_a=dict(raw.get("execution_a", {})),
            execution_b=dict(raw.get("execution_b", {})),
            abstract_world=dict(raw.get("abstract_world", {})),
            external_truth_a=bool(raw.get("external_truth_a")),
            external_truth_b=bool(raw.get("external_truth_b")),
            missing_semantics=tuple(str(x) for x in raw.get("missing_semantics", ())),
        )


@dataclass(frozen=True)
class AdequacyResult:
    adequate: bool
    verdict: AssuranceVerdict | None
    concrete_executions_checked: int
    abstract_worlds_checked: int
    certificate: ModelTwinCertificate | None = None
    witness: Mapping[str, Any] | None = None
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "adequate": self.adequate,
            "verdict": str(self.verdict) if self.verdict else None,
            "concrete_executions_checked": self.concrete_executions_checked,
            "abstract_worlds_checked": self.abstract_worlds_checked,
            "certificate": self.certificate.as_dict() if self.certificate else None,
            "witness": dict(self.witness) if self.witness else None,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class AssuranceCompilationResult:
    verdict: AssuranceVerdict
    failed_layer: str | None
    adequacy: AdequacyResult
    synthesis: SynthesisResult | None
    checking_order: tuple[str, ...] = ASSURANCE_CHECKING_ORDER
    additional_detected_failures: tuple[str, ...] = ()

    @property
    def primary_verdict(self) -> AssuranceVerdict:
        """Return the first verdict established by the declared check order.

        ``primary_verdict`` is an ordered diagnostic, not a claim of a unique
        causal root.  Later checks can be skipped because their premises did
        not hold; independently established additional failures may be attached
        through ``additional_detected_failures``.
        """

        return self.verdict

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": str(self.verdict),
            "primary_verdict": str(self.primary_verdict),
            "failed_layer": self.failed_layer,
            "checking_order": list(self.checking_order),
            "additional_detected_failures": list(
                self.additional_detected_failures
            ),
            "adequacy": self.adequacy.as_dict(),
            "synthesis": self.synthesis.as_dict() if self.synthesis else None,
        }


class ModelAdequacyChecker:
    """Check bounded abstraction adequacy before evidence determinacy.

    Concrete executions extend one released AuditSpec world with declared
    external variables.  The abstraction function maps the concrete execution
    back into an AuditSpec world.  A model twin is two in-domain concrete
    executions with the same abstract world and different external truth.
    """

    def __init__(self, spec: AuditSpec, case: AdequacyCase):
        self.spec = spec
        self.case = case
        self.worlds = enumerate_worlds(spec)
        self._world_keys = {
            self._canonical_world(world) for world in self.worlds
        }
        self._validate_case()

    def _validate_case(self) -> None:
        if not self.case.obligation_id:
            raise ValueError("Adequacy case needs an obligation_id")
        if self.case.pack not in {self.spec.name, str(self.spec.metadata.get("domain", ""))}:
            aliases = {
                "payment": "finance-payment",
                "credit": "finance-credit",
                "aml": "finance-aml",
            }
            if aliases.get(self.case.pack) != self.spec.metadata.get("domain"):
                raise ValueError(
                    f"Adequacy case pack {self.case.pack!r} does not match {self.spec.name!r}"
                )
        collisions = set(self.case.external_variables) & set(self.spec.variables)
        if collisions:
            raise ValueError(
                f"External variables collide with abstract variables: {sorted(collisions)}"
            )
        if any(not values for values in self.case.external_variables.values()):
            raise ValueError("External variable domains must be non-empty")
        concrete_names = set(self.spec.variables) | set(self.case.external_variables)
        expressions = [self.case.external_predicate, *self.case.concrete_constraints]
        expressions.extend((self.case.abstraction or {}).values())
        unknown_concrete = set().union(
            *(referenced_names(expression) for expression in expressions)
        ) - concrete_names
        if unknown_concrete:
            raise ValueError(
                f"Adequacy expressions reference unknown concrete names: {sorted(unknown_concrete)}"
            )
        unknown_abstract_targets = set(self.case.abstraction or {}) - set(self.spec.variables)
        if unknown_abstract_targets:
            raise ValueError(
                f"Abstraction assigns unknown model variables: {sorted(unknown_abstract_targets)}"
            )
        if self.case.abstract_query is not None:
            unknown_query = referenced_names(self.case.abstract_query) - set(self.spec.variables)
            if unknown_query:
                raise ValueError(
                    f"Abstract query references unknown model names: {sorted(unknown_query)}"
                )

    def _canonical_world(self, world: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
        return tuple((name, world[name]) for name in self.spec.variables)

    def concrete_executions(self) -> Iterable[World]:
        external_names = tuple(self.case.external_variables)
        external_domains = tuple(
            self.case.external_variables[name] for name in external_names
        )
        combinations: Iterable[tuple[Any, ...]] = (
            itertools.product(*external_domains) if external_names else [()]
        )
        combinations = tuple(combinations)
        for world in self.worlds:
            for values in combinations:
                execution = dict(world)
                execution.update(dict(zip(external_names, values)))
                if all(
                    bool(evaluate(expression, execution))
                    for expression in self.case.concrete_constraints
                ):
                    yield execution

    def abstract(self, execution: Mapping[str, Any]) -> World:
        mappings = self.case.abstraction or {}
        abstract = {
            name: evaluate(mappings.get(name, name), execution)
            for name in self.spec.variables
        }
        key = self._canonical_world(abstract)
        if key not in self._world_keys:
            raise ValueError("Abstraction produced a world outside the released model")
        return abstract

    def check(self) -> AdequacyResult:
        seen: dict[
            tuple[tuple[str, Any], ...], tuple[bool, World, World]
        ] = {}
        query_mismatch: Mapping[str, Any] | None = None
        checked = 0
        for execution in self.concrete_executions():
            checked += 1
            abstract = self.abstract(execution)
            key = self._canonical_world(abstract)
            truth = bool(evaluate(self.case.external_predicate, execution))
            previous = seen.get(key)
            if previous is not None and previous[0] != truth:
                certificate = ModelTwinCertificate(
                    schema_version=MODEL_TWIN_SCHEMA,
                    case_digest=self.case.digest,
                    spec_digest=spec_digest(self.spec),
                    obligation_id=self.case.obligation_id,
                    pack=self.case.pack,
                    execution_a=previous[1],
                    execution_b=dict(execution),
                    abstract_world=abstract,
                    external_truth_a=previous[0],
                    external_truth_b=truth,
                    missing_semantics=self.case.missing_semantics,
                )
                return AdequacyResult(
                    adequate=False,
                    verdict=AssuranceVerdict.MODEL_GAP,
                    concrete_executions_checked=checked,
                    abstract_worlds_checked=len(seen),
                    certificate=certificate,
                    notes=(
                        "Two concrete executions collapse to the same AuditSpec world but have different external audit truth.",
                    ),
                )
            seen.setdefault(key, (truth, dict(execution), abstract))
            if self.case.abstract_query is not None:
                query_answer = bool(evaluate(self.case.abstract_query, abstract))
                if query_answer != truth and query_mismatch is None:
                    query_mismatch = {
                        "execution": dict(execution),
                        "abstract_world": abstract,
                        "external_truth": truth,
                        "query_answer": query_answer,
                    }
        if not checked:
            raise ValueError("Adequacy case has no satisfying concrete executions")
        if query_mismatch is not None:
            return AdequacyResult(
                adequate=False,
                verdict=AssuranceVerdict.QUERY_GAP,
                concrete_executions_checked=checked,
                abstract_worlds_checked=len(seen),
                witness=query_mismatch,
                notes=(
                    "The external predicate is stable under the abstraction, but the proposed AuditSpec query disagrees with it.",
                ),
            )
        if self.case.abstract_query is None:
            return AdequacyResult(
                adequate=False,
                verdict=AssuranceVerdict.QUERY_GAP,
                concrete_executions_checked=checked,
                abstract_worlds_checked=len(seen),
                notes=(
                    "No formal query was supplied for an external predicate that is stable under the declared abstraction.",
                ),
            )
        return AdequacyResult(
            adequate=True,
            verdict=None,
            concrete_executions_checked=checked,
            abstract_worlds_checked=len(seen),
            notes=(
                "Adequacy is exact only for the declared concrete domains, constraints, abstraction, and external predicate.",
            ),
        )

    def verify_certificate(self, certificate: ModelTwinCertificate) -> bool:
        if certificate.schema_version != MODEL_TWIN_SCHEMA:
            return False
        if certificate.case_digest != self.case.digest:
            return False
        if certificate.spec_digest != spec_digest(self.spec):
            return False
        if certificate.obligation_id != self.case.obligation_id:
            return False
        if certificate.pack != self.case.pack:
            return False
        if certificate.missing_semantics != self.case.missing_semantics:
            return False
        for execution in (certificate.execution_a, certificate.execution_b):
            if set(execution) != set(self.spec.variables) | set(self.case.external_variables):
                return False
            if any(
                execution[name] not in domain
                for name, domain in self.spec.variables.items()
            ):
                return False
            if any(
                execution[name] not in domain
                for name, domain in self.case.external_variables.items()
            ):
                return False
            try:
                if not all(
                    bool(evaluate(expression, execution))
                    for expression in (*self.spec.constraints, *self.case.concrete_constraints)
                ):
                    return False
            except (KeyError, TypeError, ValueError):
                return False
        try:
            abstract_a = self.abstract(certificate.execution_a)
            abstract_b = self.abstract(certificate.execution_b)
            truth_a = bool(
                evaluate(self.case.external_predicate, certificate.execution_a)
            )
            truth_b = bool(
                evaluate(self.case.external_predicate, certificate.execution_b)
            )
        except (KeyError, TypeError, ValueError):
            return False
        return bool(
            abstract_a == abstract_b == dict(certificate.abstract_world)
            and truth_a == certificate.external_truth_a
            and truth_b == certificate.external_truth_b
            and truth_a != truth_b
        )


class AuditAssuranceCompiler:
    """Run model adequacy before the existing evidence counterexample loop."""

    def __init__(self, spec: AuditSpec, case: AdequacyCase):
        self.spec = spec
        self.case = case
        self.adequacy_checker = ModelAdequacyChecker(spec, case)

    def compile(
        self,
        *,
        threat_model: str = "cooperative",
        mode: str = "auto",
        weights: Mapping[str, float] | None = None,
    ) -> AssuranceCompilationResult:
        adequacy = self.adequacy_checker.check()
        if not adequacy.adequate:
            assert adequacy.verdict is not None
            return AssuranceCompilationResult(
                verdict=adequacy.verdict,
                failed_layer="A" if adequacy.verdict == AssuranceVerdict.MODEL_GAP else "Q",
                adequacy=adequacy,
                synthesis=None,
            )
        assert self.case.abstract_query is not None
        working_spec = copy.copy(self.spec)
        query_name = f"external::{self.case.obligation_id}"
        working_spec.queries = dict(self.spec.queries)
        working_spec.queries[query_name] = Query(
            name=query_name,
            expression=self.case.abstract_query,
            description=f"External obligation {self.case.obligation_id}",
            kind=self.case.kind,
            anchor_entity=self.case.anchor_entity
            or str(self.spec.metadata.get("anchor_entity", "action")),
            intervention_target=self.case.intervention_target,
            split="held_out",
        )
        synthesis = AuditCompiler(working_spec).synthesize(
            query_name,
            threat_model=threat_model,
            mode=mode,
            weights=weights,
        )
        if synthesis.status == "UNREALIZABLE_INTERVENTION":
            verdict = AssuranceVerdict.INTERVENTION_GAP
            layer = "R/V"
        elif synthesis.status == "NOT_AUDITABLE_UNDER_CURRENT_TCB":
            if synthesis.unresolved_certificate is not None:
                verdict = AssuranceVerdict.EVIDENCE_GAP
                layer = "D"
            else:
                verdict = AssuranceVerdict.TCB_GAP
                layer = "R/M"
        elif synthesis.status in {
            "PASSIVE_AUDITABLE",
            "ACTIVE_AUDIT_REQUIRED",
            "AUDITABLE",
        }:
            verdict = AssuranceVerdict.CONTRACT_READY
            layer = None
        else:
            verdict = AssuranceVerdict.VERIFICATION_FAILURE
            layer = "V"
        return AssuranceCompilationResult(
            verdict=verdict,
            failed_layer=layer,
            adequacy=adequacy,
            synthesis=synthesis,
        )


def load_adequacy_cases(path: str | Path) -> dict[str, AdequacyCase]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or raw.get("format") != ADEQUACY_SUITE_FORMAT:
        raise ValueError("Unsupported model-adequacy suite format")
    cases: dict[str, AdequacyCase] = {}
    for item in raw.get("cases", ()):
        if not isinstance(item, Mapping):
            raise ValueError("Adequacy case must be a mapping")
        case = AdequacyCase(
            obligation_id=str(item["id"]),
            pack=str(item["pack"]),
            external_predicate=str(item["external_predicate"]),
            abstract_query=(
                str(item["abstract_query"])
                if item.get("abstract_query") is not None
                else None
            ),
            external_variables={
                str(name): tuple(values)
                for name, values in (item.get("external_variables", {}) or {}).items()
            },
            concrete_constraints=tuple(
                str(x) for x in item.get("concrete_constraints", ())
            ),
            abstraction={
                str(name): str(expression)
                for name, expression in (item.get("abstraction", {}) or {}).items()
            },
            missing_semantics=tuple(
                str(x) for x in item.get("missing_semantics", ())
            ),
            source_refs=tuple(str(x) for x in item.get("source_refs", ())),
            kind=str(item.get("kind", "fact")),
            anchor_entity=(
                str(item["anchor_entity"])
                if item.get("anchor_entity") is not None
                else None
            ),
            intervention_target=(
                str(item["intervention_target"])
                if item.get("intervention_target") is not None
                else None
            ),
        )
        if case.obligation_id in cases:
            raise ValueError(f"Duplicate adequacy case {case.obligation_id!r}")
        cases[case.obligation_id] = case
    if not cases:
        raise ValueError("Adequacy suite contains no cases")
    return cases
