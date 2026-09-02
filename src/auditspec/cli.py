from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .catalog import spec_digest
from .compiler import AuditCompiler, DEFAULT_WEIGHTS
from .model import TwinCertificate
from .model_adequacy import (
    AuditAssuranceCompiler,
    ModelAdequacyChecker,
    ModelTwinCertificate,
    load_adequacy_cases,
)
from .runtime.events import canonical_json
from .spec import load_spec
from .symbolic import SymbolicDeterminacyChecker, problem_from_spec


def _weights(value: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for item in value.split(","):
        key, raw = item.split("=", 1)
        result[key.strip()] = float(raw)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditctl")
    parser.add_argument("spec", help="AuditSpec YAML file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("summary")

    check = sub.add_parser("check")
    check.add_argument("--query", required=True)
    check.add_argument("--contract", default="")
    check.add_argument("--threat-model", default="cooperative")

    symbolic = sub.add_parser("symbolic-check")
    symbolic.add_argument("--query", required=True)
    symbolic.add_argument("--contract", required=True)
    symbolic.add_argument("--timeout-ms", type=int, default=30_000)

    synth = sub.add_parser("synthesize")
    synth.add_argument("--query", required=True)
    synth.add_argument("--threat-model", default="cooperative")
    synth.add_argument("--mode", choices=["passive", "all", "auto"], default="auto")
    synth.add_argument("--weights", type=_weights, default=dict(DEFAULT_WEIGHTS))
    synth.add_argument("--out")

    compile_parser = sub.add_parser("compile")
    compile_parser.add_argument("--query", required=True)
    compile_parser.add_argument("--threat-model", default="cooperative")
    compile_parser.add_argument("--out")

    frontier = sub.add_parser("frontier")
    frontier.add_argument("--query", required=True)
    frontier.add_argument("--threat-model", default="cooperative")

    sampled = sub.add_parser("sampled-solutions")
    sampled.add_argument("--query", required=True)
    sampled.add_argument("--threat-model", default="cooperative")

    verify = sub.add_parser("verify-certificate")
    verify.add_argument("--certificate", required=True)

    adequacy = sub.add_parser("check-adequacy")
    adequacy.add_argument("--suite", required=True)
    adequacy.add_argument("--obligation", required=True)

    assurance = sub.add_parser("compile-assurance")
    assurance.add_argument("--suite", required=True)
    assurance.add_argument("--obligation", required=True)
    assurance.add_argument("--threat-model", default="cooperative")
    assurance.add_argument(
        "--mode", choices=["passive", "all", "auto"], default="auto"
    )
    assurance.add_argument("--weights", type=_weights, default=dict(DEFAULT_WEIGHTS))
    assurance.add_argument("--out")

    verify_model = sub.add_parser("verify-model-certificate")
    verify_model.add_argument("--suite", required=True)
    verify_model.add_argument("--obligation", required=True)
    verify_model.add_argument("--certificate", required=True)

    plan = sub.add_parser("plan-install")
    plan.add_argument("--query", required=True)
    plan.add_argument("--threat-model", default="cooperative")
    plan.add_argument("--out")

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--plan", required=True)

    minimality = sub.add_parser("verify-minimality")
    minimality.add_argument("--query", required=True)
    minimality.add_argument("--contract", default="")
    minimality.add_argument("--threat-model", default="cooperative")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    spec = load_spec(args.spec)
    compiler = None if args.command == "symbolic-check" else AuditCompiler(spec)

    if args.command == "summary":
        assert compiler is not None
        payload = {
            "name": spec.name,
            "description": spec.description,
            "worlds": len(compiler.worlds),
            "catalog_version": spec.metadata.get("catalog_version"),
            "queries": {
                name: {
                    "description": query.description,
                    "kind": query.kind,
                    "split": query.split,
                    "dependencies": list(compiler.query_dependencies(name)),
                    "derived_requirements": list(compiler.derived_requirements(name)),
                }
                for name, query in spec.queries.items()
            },
            "mechanisms": {
                name: mechanism.as_dict() for name, mechanism in spec.mechanisms.items()
            },
            "threat_models": {
                name: {
                    "compromised_producers": sorted(tm.compromised_producers),
                    "trusted_capture_points": sorted(tm.trusted_capture_points),
                    "mandatory_channels": sorted(tm.mandatory_channels),
                    "available_mechanisms": (
                        sorted(tm.available_mechanisms)
                        if tm.available_mechanisms is not None
                        else None
                    ),
                }
                for name, tm in spec.threat_models.items()
            },
        }
    elif args.command == "check":
        assert compiler is not None
        contract = [name for name in args.contract.split(",") if name]
        checked = compiler.check_contract(
            args.query, contract, threat_model=args.threat_model
        )
        payload = {
            "auditable": checked.auditable,
            "unmet_requirements": list(checked.unmet_requirements),
            "missing_dependencies": list(checked.missing_dependencies),
            "certificate": checked.certificate.as_dict() if checked.certificate else None,
            "ambiguity": compiler.ambiguity_metrics(
                args.query, contract, threat_model=args.threat_model
            ),
        }
    elif args.command == "symbolic-check":
        contract = [name for name in args.contract.split(",") if name]
        payload = SymbolicDeterminacyChecker(
            problem_from_spec(spec, args.query, contract)
        ).check(timeout_ms=args.timeout_ms).as_dict()
    elif args.command == "synthesize":
        assert compiler is not None
        payload = compiler.synthesize(
            args.query,
            threat_model=args.threat_model,
            mode=args.mode,
            weights=args.weights,
        ).as_dict()
    elif args.command == "compile":
        assert compiler is not None
        result = compiler.synthesize(args.query, threat_model=args.threat_model)
        payload = {
            "synthesis": result.as_dict(),
            "instrumentation_plan": [
                item.as_dict() for item in compiler.compile_instrumentation(result.contract)
            ],
        }
    elif args.command == "frontier":
        assert compiler is not None
        payload = [
            result.as_dict()
            for result in compiler.sampled_weight_solutions(
                args.query, args.threat_model
            )
        ]
    elif args.command == "sampled-solutions":
        assert compiler is not None
        payload = [
            result.as_dict()
            for result in compiler.sampled_weight_solutions(
                args.query, args.threat_model
            )
        ]
    elif args.command == "verify-certificate":
        assert compiler is not None
        raw = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "certificate" in raw:
            raw = raw["certificate"]
        certificate = TwinCertificate.from_dict(raw)
        payload = {
            "valid": compiler.verify_certificate(certificate),
            "spec": certificate.spec_name,
            "query": certificate.query,
            "contract": list(certificate.contract),
        }
    elif args.command == "check-adequacy":
        case = load_adequacy_cases(args.suite)[args.obligation]
        payload = ModelAdequacyChecker(spec, case).check().as_dict()
    elif args.command == "compile-assurance":
        case = load_adequacy_cases(args.suite)[args.obligation]
        payload = AuditAssuranceCompiler(spec, case).compile(
            threat_model=args.threat_model,
            mode=args.mode,
            weights=args.weights,
        ).as_dict()
    elif args.command == "verify-model-certificate":
        case = load_adequacy_cases(args.suite)[args.obligation]
        checker = ModelAdequacyChecker(spec, case)
        raw = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "certificate" in raw:
            raw = raw["certificate"]
        certificate = ModelTwinCertificate.from_dict(raw)
        payload = {
            "valid": checker.verify_certificate(certificate),
            "obligation": certificate.obligation_id,
            "pack": certificate.pack,
            "missing_semantics": list(certificate.missing_semantics),
        }
    elif args.command == "plan-install":
        assert compiler is not None
        result = compiler.synthesize(args.query, threat_model=args.threat_model)
        install_items = [
            item.as_dict()
            for item in compiler.compile_instrumentation(result.contract)
        ]
        plan_body = {
            "schema": "AuditSpec-installation-plan-v1",
            "spec": spec.name,
            "spec_digest": spec_digest(spec),
            "query": args.query,
            "threat_model": args.threat_model,
            "status": result.status,
            "contract": list(result.contract),
            "cost": result.cost.as_dict(),
            "install": install_items,
            "preflight": [
                "spec digest matches the compiling spec",
                "every planned mechanism is registered and threat-eligible",
                "the planned contract still passes check_contract",
                "plan digest recomputes over the plan body",
            ],
            "minimality_witnesses": result.minimality_witnesses,
            "notes": [
                *result.notes,
                "Runtime activation of each adapter is environment-side; this "
                "plan is the compiler's prescription, not proof of installation.",
            ],
        }
        payload = {
            **plan_body,
            "plan_digest": hashlib.sha256(
                canonical_json(plan_body).encode("utf-8")
            ).hexdigest(),
        }
    elif args.command == "preflight":
        assert compiler is not None
        raw = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        checks: list[dict[str, Any]] = []

        def _record(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"check": name, "ok": bool(ok), "detail": detail})

        body = {key: value for key, value in raw.items() if key != "plan_digest"}
        digest_ok = hashlib.sha256(
            canonical_json(body).encode("utf-8")
        ).hexdigest() == raw.get("plan_digest")
        _record("plan_digest", digest_ok)
        _record(
            "spec_digest",
            raw.get("spec_digest") == spec_digest(spec),
            f"plan={raw.get('spec_digest')} spec={spec_digest(spec)}",
        )
        contract = [str(name) for name in raw.get("contract", [])]
        unknown = sorted(set(contract) - set(spec.mechanisms))
        _record("mechanisms_registered", not unknown, f"unknown={unknown}")
        threat_model = str(raw.get("threat_model", "cooperative"))
        try:
            eligible, _ = compiler.eligible_mechanisms(
                threat_model, {"passive", "active"}
            )
            ineligible = sorted(set(contract) - set(eligible))
        except KeyError as exc:
            ineligible = [f"threat-model:{exc}"]
        _record("mechanisms_threat_eligible", not ineligible, f"{ineligible}")
        auditable = False
        detail = ""
        if not unknown and not ineligible:
            try:
                checked = compiler.check_contract(
                    str(raw.get("query")), contract, threat_model=threat_model
                )
                auditable = checked.auditable
                detail = (
                    f"unmet={list(checked.unmet_requirements)} "
                    f"missing={list(checked.missing_dependencies)}"
                )
            except (KeyError, ValueError) as exc:
                detail = str(exc)
        _record("contract_still_sound", auditable, detail)
        payload = {
            "ok": all(item["ok"] for item in checks),
            "plan": str(args.plan),
            "query": raw.get("query"),
            "checks": checks,
        }
    elif args.command == "verify-minimality":
        assert compiler is not None
        if args.contract:
            contract = sorted(
                {name for name in args.contract.split(",") if name}
            )
        else:
            contract = list(
                compiler.synthesize(
                    args.query, threat_model=args.threat_model
                ).contract
            )
        full = compiler.check_contract(
            args.query, contract, threat_model=args.threat_model
        )
        deletions: dict[str, Any] = {}
        for mechanism in contract:
            reduced = [name for name in contract if name != mechanism]
            try:
                checked = compiler.check_contract(
                    args.query, reduced, threat_model=args.threat_model
                )
                deletions[mechanism] = {
                    "necessary": not checked.auditable,
                    "unmet_requirements": list(checked.unmet_requirements),
                    "missing_dependencies": list(checked.missing_dependencies),
                    "certificate": (
                        checked.certificate.as_dict() if checked.certificate else None
                    ),
                }
            except ValueError as exc:
                deletions[mechanism] = {"necessary": True, "detail": str(exc)}
        payload = {
            "query": args.query,
            "threat_model": args.threat_model,
            "contract": contract,
            "full_contract_auditable": full.auditable,
            "minimal": full.auditable
            and all(item["necessary"] for item in deletions.values()),
            "deletions": deletions,
        }
    else:
        raise AssertionError(args.command)

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    output_path = getattr(args, "out", None)
    if output_path:
        Path(output_path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
