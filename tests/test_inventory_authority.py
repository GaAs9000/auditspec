from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_assurance_gate import REVISION, configurations

from auditspec.assurance import run_exact_assurance_gate
from auditspec.extension_manifest import (
    ExtensionMode,
    FullAssuranceExtensionManifest,
    actual_structural_delta,
    verify_full_assurance_extension,
)
from auditspec.inventory_authority import (
    InventoryAuthorityStatement,
    InventoryAuthorityTrustContext,
    sign_inventory_authority_statement,
)

AUTHORITY_ID = "test-inventory-authority-v1"


def _layer_details(gate, layer: str) -> tuple[str, ...]:
    return next(item.details for item in gate.trace if item.layer == layer)


@pytest.fixture()
def authority_keys(tmp_path: Path) -> tuple[Path, bytes, Path]:
    openssl = Path(shutil.which("openssl") or "/usr/bin/openssl").resolve()
    private = tmp_path / "authority-private.pem"
    public = tmp_path / "authority-public.pem"
    subprocess.run(
        [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(openssl),
            "pkey",
            "-in",
            str(private),
            "-pubout",
            "-out",
            str(public),
        ],
        check=True,
        capture_output=True,
    )
    return private, public.read_bytes(), openssl


def _trust(
    public_key: bytes,
    openssl: Path,
    *,
    authority_ids: frozenset[str] = frozenset({AUTHORITY_ID}),
    verification_time: int = 150,
) -> InventoryAuthorityTrustContext:
    key_id = f"sha256:{hashlib.sha256(public_key).hexdigest()}"
    return InventoryAuthorityTrustContext(
        authority_public_keys={key_id: public_key},
        accepted_authority_ids=authority_ids,
        expected_environment="tau2",
        expected_benchmark_revision=REVISION,
        verification_time=verification_time,
        openssl_path=str(openssl),
        openssl_sha256=hashlib.sha256(openssl.read_bytes()).hexdigest(),
    )


def _authority_config(
    authority_keys: tuple[Path, bytes, Path],
    *,
    issued_at: int = 100,
    expires_at: int = 200,
    authority_id: str = AUTHORITY_ID,
):
    private, public_key, openssl = authority_keys
    base = configurations()["base"]
    key_id = f"sha256:{hashlib.sha256(public_key).hexdigest()}"
    statement = sign_inventory_authority_statement(
        authority_id=authority_id,
        key_id=key_id,
        scope_id=base.inventory_scope.scope_id,
        channel=base.inventory_scope.channel,
        inventory_manifest=base.inventory_scope.inventory_manifest,
        environment="tau2",
        benchmark_revision=REVISION,
        issued_at=issued_at,
        expires_at=expires_at,
        private_key=private,
        openssl=openssl,
    )
    scope = replace(base.inventory_scope, authority_statement=statement.as_dict())
    return replace(
        base,
        inventory_scope=scope,
        inventory_authority_required=True,
        inventory_authority_trust=_trust(public_key, openssl),
    )


def test_signed_inventory_authority_passes_m_and_stays_bounded(
    authority_keys,
) -> None:
    config = _authority_config(authority_keys)
    gate = run_exact_assurance_gate(config)
    assert gate.supported_within_declared_tcb
    assert gate.inventory_authority_result is not None
    assert gate.inventory_authority_result["valid"] is True
    assert gate.inventory_authority_result["inventory_completeness_attested"] is True
    assert gate.inventory_authority_result["inventory_completeness_proven"] is False
    assert gate.inventory_authority_result["open_world"] is False


def test_inventory_authority_rejects_unknown_authority_and_key(
    authority_keys,
) -> None:
    config = _authority_config(authority_keys)
    rejected_authority = replace(
        config,
        inventory_authority_trust=replace(
            config.inventory_authority_trust,
            accepted_authority_ids=frozenset({"other-authority"}),
        ),
    )
    assert run_exact_assurance_gate(rejected_authority).first_failed_layer == "M"

    private, _, openssl = authority_keys
    other_private = private.parent / "other-private.pem"
    other_public = private.parent / "other-public.pem"
    subprocess.run(
        [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(other_private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(openssl),
            "pkey",
            "-in",
            str(other_private),
            "-pubout",
            "-out",
            str(other_public),
        ],
        check=True,
        capture_output=True,
    )
    wrong_key = replace(
        config,
        inventory_authority_trust=_trust(other_public.read_bytes(), openssl),
    )
    gate = run_exact_assurance_gate(wrong_key)
    assert gate.first_failed_layer == "M"
    assert "inventory_authority:key_id:not_trusted" in _layer_details(gate, "M")


def test_inventory_authority_rejects_signature_scope_and_manifest_tamper(
    authority_keys,
) -> None:
    config = _authority_config(authority_keys)
    raw = dict(config.inventory_scope.authority_statement)
    signature = bytearray(base64.b64decode(raw["signature_base64"]))
    signature[0] ^= 1
    raw["signature_base64"] = base64.b64encode(signature).decode("ascii")
    tampered_signature = replace(
        config,
        inventory_scope=replace(config.inventory_scope, authority_statement=raw),
    )
    gate = run_exact_assurance_gate(tampered_signature)
    assert gate.first_failed_layer == "M"
    assert "inventory_authority:signature:invalid" in _layer_details(gate, "M")

    raw = dict(config.inventory_scope.authority_statement)
    raw["scope_id"] = "different-scope"
    tampered_scope = replace(
        config,
        inventory_scope=replace(config.inventory_scope, authority_statement=raw),
    )
    assert run_exact_assurance_gate(tampered_scope).first_failed_layer == "M"

    manifest = dict(config.inventory_scope.inventory_manifest)
    manifest["channel"] = "different-channel"
    tampered_manifest = replace(
        config,
        inventory_scope=replace(config.inventory_scope, inventory_manifest=manifest),
    )
    assert run_exact_assurance_gate(tampered_manifest).first_failed_layer == "M"


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "verification_time", "error"),
    [
        (160, 200, 150, "validity:not_yet_valid"),
        (100, 140, 150, "validity:expired"),
    ],
)
def test_inventory_authority_validity_interval_fails_closed(
    authority_keys,
    issued_at: int,
    expires_at: int,
    verification_time: int,
    error: str,
) -> None:
    config = _authority_config(
        authority_keys, issued_at=issued_at, expires_at=expires_at
    )
    config = replace(
        config,
        inventory_authority_trust=replace(
            config.inventory_authority_trust,
            verification_time=verification_time,
        ),
    )
    gate = run_exact_assurance_gate(config)
    assert gate.first_failed_layer == "M"
    assert f"inventory_authority:{error}" in _layer_details(gate, "M")


def test_inventory_authority_wire_schema_rejects_false_completeness_and_extras(
    authority_keys,
) -> None:
    config = _authority_config(authority_keys)
    raw = dict(config.inventory_scope.authority_statement)
    raw["completeness_asserted_for_declared_inventory"] = False
    with pytest.raises(ValueError, match="must assert"):
        InventoryAuthorityStatement.from_dict(raw)
    raw = dict(config.inventory_scope.authority_statement)
    raw["extra"] = True
    with pytest.raises(ValueError, match="closed schema"):
        InventoryAuthorityStatement.from_dict(raw)


def test_extension_manifest_binds_inventory_authority_coordinate(
    authority_keys,
) -> None:
    base = _authority_config(authority_keys, issued_at=100, expires_at=200)
    extension = replace(
        _authority_config(authority_keys, issued_at=110, expires_at=210),
        configuration_id="authority-extension",
    )
    delta = actual_structural_delta(base, extension)
    assert delta == ("inventory_authority",)
    manifest = FullAssuranceExtensionManifest.build(
        "authority-delta",
        ExtensionMode.ADMITTED_STRUCTURAL_DELTA,
        base,
        extension,
        section_defaults={},
        declared_delta=delta,
    )
    result = verify_full_assurance_extension(manifest, base, extension)
    assert result.manifest_valid
    assert result.extension_supported
