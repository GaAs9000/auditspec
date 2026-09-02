"""AuditSpec design-time compilation kernel."""

from .pipeline import (
    CompileFailure,
    PlannedCompilation,
    compile_overlay,
    compile_overlay_data,
    load_overlay,
)

__all__ = [
    "CompileFailure",
    "PlannedCompilation",
    "compile_overlay",
    "compile_overlay_data",
    "load_overlay",
]
