from __future__ import annotations

from pathlib import Path

from examples.end_to_end import run


def test_public_end_to_end_quickstart(tmp_path: Path) -> None:
    result = run(tmp_path / "vault")
    assert result["compiler_status"] == "PASSIVE_AUDITABLE"
    assert result["compiled_contract"] == [
        "canonical_action",
        "durable_effect_receipt",
    ]
    assert result["vault_authentication_status"] == "EXTERNALLY_AUTHENTICATED"
    assert result["audit_time_status"] == "REVERIFIED_AT_AUDIT_TIME"
    assert result["verdict"] == "SUPPORTED"
