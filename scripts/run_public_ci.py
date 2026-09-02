"""Run the history-independent public AuditSpec test surface."""

from __future__ import annotations

import subprocess
import sys


PUBLIC_TESTS = (
    "tests/test_assurance_gate.py",
    "tests/test_baselines.py",
    "tests/test_compiler.py",
    "tests/test_core_evidence_vault.py",
    "tests/test_end_to_end_quickstart.py",
    "tests/test_vault_state_model.py",
    "tests/test_credit_runtime.py",
    "tests/test_extension_manifest.py",
    "tests/test_external_evidence.py",
    "tests/test_information.py",
    "tests/test_inventory_authority.py",
    "tests/test_isolated_verifier.py",
    "tests/test_model_adequacy.py",
    "tests/test_p_minimality.py",
    "tests/test_registered_verifier.py",
    "tests/test_run_verification.py",
    "tests/test_runtime.py",
    "tests/test_symbolic.py",
    "tests/test_validation.py",
)


def main() -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *PUBLIC_TESTS], check=False
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
