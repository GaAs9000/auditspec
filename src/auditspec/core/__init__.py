"""AuditSpec design-time compilation kernel."""

from .pipeline import (
    CompileFailure,
    PlannedCompilation,
    compile_overlay,
    compile_overlay_data,
    load_overlay,
)
from .information_order import (
    DeterministicProcessor,
    InformationOrderError,
    analyze_auditability,
    analyze_lifecycle_transformation,
    classify_obstruction,
    compile_minimum_contract,
    make_migration_bundle,
    no_posthoc_repair_certificate,
    semantic_audit_horizon,
    verify_auditability_certificate,
    verify_contract_certificate,
    verify_lifecycle_certificate,
    verify_migration_bundle,
)

__all__ = [
    "CompileFailure",
    "PlannedCompilation",
    "compile_overlay",
    "compile_overlay_data",
    "load_overlay",
    "DeterministicProcessor",
    "InformationOrderError",
    "analyze_auditability",
    "analyze_lifecycle_transformation",
    "classify_obstruction",
    "compile_minimum_contract",
    "make_migration_bundle",
    "no_posthoc_repair_certificate",
    "semantic_audit_horizon",
    "verify_auditability_certificate",
    "verify_contract_certificate",
    "verify_lifecycle_certificate",
    "verify_migration_bundle",
]
