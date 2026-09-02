"""AuditSpec: bounded Agent audit-assurance compiler.

Public compiler objects are imported lazily so dependency-light deployment
verifiers can use :mod:`auditspec.deployment` without loading the YAML parser or
the finite-world compiler.
"""

from typing import Any

__all__ = [
    "AssuranceConfiguration",
    "AuditAssuranceCompiler",
    "AuditCompiler",
    "CanonicalPremiseSet",
    "DeclaredInventoryScope",
    "DeclaredScheduleClosureCertificate",
    "FullAssuranceExtensionManifest",
    "InventoryAuthorityStatement",
    "InventoryAuthorityTrustContext",
    "ScheduleClosureVerificationResult",
    "ScheduleClosureTrustContext",
    "IsolatedVerifierInvocation",
    "IsolationPolicy",
    "ModelAdequacyChecker",
    "OfficialGateContext",
    "OfficialGateInvocation",
    "PMinimalityCertificate",
    "PremiseAtom",
    "RegisteredVerifierInvocation",
    "load_spec",
    "make_declared_schedule_closure_certificate",
    "run_exact_assurance_gate",
    "summarize_schedule_population",
    "verify_full_assurance_extension",
    "verify_p_minimality_certificate",
    "verify_declared_schedule_closure_certificate",
]
__version__ = "1.1.3"


def __getattr__(name: str) -> Any:
    if name == "AuditCompiler":
        from .compiler import AuditCompiler

        return AuditCompiler
    if name in {"AuditAssuranceCompiler", "ModelAdequacyChecker"}:
        from .model_adequacy import AuditAssuranceCompiler, ModelAdequacyChecker

        return {
            "AuditAssuranceCompiler": AuditAssuranceCompiler,
            "ModelAdequacyChecker": ModelAdequacyChecker,
        }[name]
    if name == "load_spec":
        from .spec import load_spec

        return load_spec
    if name in {
        "AssuranceConfiguration",
        "DeclaredInventoryScope",
        "run_exact_assurance_gate",
    }:
        from .assurance import (
            AssuranceConfiguration,
            DeclaredInventoryScope,
            run_exact_assurance_gate,
        )

        return {
            "AssuranceConfiguration": AssuranceConfiguration,
            "DeclaredInventoryScope": DeclaredInventoryScope,
            "run_exact_assurance_gate": run_exact_assurance_gate,
        }[name]
    if name in {"FullAssuranceExtensionManifest", "verify_full_assurance_extension"}:
        from .extension_manifest import (
            FullAssuranceExtensionManifest,
            verify_full_assurance_extension,
        )

        return {
            "FullAssuranceExtensionManifest": FullAssuranceExtensionManifest,
            "verify_full_assurance_extension": verify_full_assurance_extension,
        }[name]
    if name == "RegisteredVerifierInvocation":
        from .verifier_registry import RegisteredVerifierInvocation

        return RegisteredVerifierInvocation
    if name in {
        "DeclaredScheduleClosureCertificate",
        "InventoryAuthorityStatement",
        "InventoryAuthorityTrustContext",
        "ScheduleClosureVerificationResult",
        "ScheduleClosureTrustContext",
        "make_declared_schedule_closure_certificate",
        "summarize_schedule_population",
        "verify_declared_schedule_closure_certificate",
    }:
        from .inventory_authority import (
            DeclaredScheduleClosureCertificate,
            InventoryAuthorityStatement,
            InventoryAuthorityTrustContext,
            ScheduleClosureVerificationResult,
            ScheduleClosureTrustContext,
            make_declared_schedule_closure_certificate,
            summarize_schedule_population,
            verify_declared_schedule_closure_certificate,
        )

        return {
            "DeclaredScheduleClosureCertificate": DeclaredScheduleClosureCertificate,
            "InventoryAuthorityStatement": InventoryAuthorityStatement,
            "InventoryAuthorityTrustContext": InventoryAuthorityTrustContext,
            "ScheduleClosureVerificationResult": ScheduleClosureVerificationResult,
            "ScheduleClosureTrustContext": ScheduleClosureTrustContext,
            "make_declared_schedule_closure_certificate": make_declared_schedule_closure_certificate,
            "summarize_schedule_population": summarize_schedule_population,
            "verify_declared_schedule_closure_certificate": verify_declared_schedule_closure_certificate,
        }[name]
    if name in {"IsolatedVerifierInvocation", "IsolationPolicy"}:
        from .isolated_verifier import IsolatedVerifierInvocation, IsolationPolicy

        return {
            "IsolatedVerifierInvocation": IsolatedVerifierInvocation,
            "IsolationPolicy": IsolationPolicy,
        }[name]
    if name in {"OfficialGateContext", "OfficialGateInvocation"}:
        from .official_gate import OfficialGateContext, OfficialGateInvocation

        return {
            "OfficialGateContext": OfficialGateContext,
            "OfficialGateInvocation": OfficialGateInvocation,
        }[name]
    if name in {
        "CanonicalPremiseSet",
        "PMinimalityCertificate",
        "PremiseAtom",
        "verify_p_minimality_certificate",
    }:
        from .minimality import (
            CanonicalPremiseSet,
            PMinimalityCertificate,
            PremiseAtom,
            verify_p_minimality_certificate,
        )

        return {
            "CanonicalPremiseSet": CanonicalPremiseSet,
            "PMinimalityCertificate": PMinimalityCertificate,
            "PremiseAtom": PremiseAtom,
            "verify_p_minimality_certificate": verify_p_minimality_certificate,
        }[name]
    raise AttributeError(name)
