"""Five-minute compiler-to-Vault quickstart using only public product APIs."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from auditspec.compiler import AuditCompiler
from auditspec.core.evidence_vault import EvidenceVault, VaultSigner
from auditspec.spec import load_spec


T0 = "2026-01-01T00:00:00Z"
T1 = "2027-01-01T00:00:00Z"
T2 = "2028-01-01T00:00:00Z"
T3 = "2030-01-01T00:00:00Z"


def run(output: Path) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    spec = load_spec(root / "examples" / "payment.yaml")
    synthesis = AuditCompiler(spec).synthesize("settled_exactly_once")
    if synthesis.contract is None:
        raise RuntimeError("quickstart claim did not compile")

    signer = VaultSigner.generate()
    vault = EvidenceVault.create(
        output,
        vault_id="vault.quickstart",
        created_at=T0,
        signer=signer,
    )
    vault.archive_component(
        kind="schema",
        component_id="settlement",
        version="1",
        content=b'{"type":"object"}',
        media_type="application/json",
        metadata={"readable": True, "migration_mode": "lossless"},
        recorded_at=T0,
    )
    verifier = {
        "schema": "AuditSpec-vault-json-predicate-verifier-v1",
        "predicate": {
            "op": "eq",
            "left": {"op": "field", "name": "settled_count"},
            "right": {"op": "const", "value": 1},
        },
    }
    vault.archive_component(
        kind="verifier",
        component_id="settled-once",
        version="1",
        content=json.dumps(verifier, sort_keys=True, separators=(",", ":")).encode(),
        media_type="application/json",
        metadata={"archive_executable": True},
        recorded_at=T0,
    )
    vault.archive_component(
        kind="key",
        component_id="producer",
        version="1",
        content=b"example-historic-public-key",
        media_type="application/octet-stream",
        metadata={
            "valid_from": T0,
            "valid_until": T1,
            "revoked_at": T1,
            "revocation_kind": "routine",
            "compromise_effective_from": None,
        },
        recorded_at=T0,
    )
    vault.archive_component(
        kind="policy",
        component_id="retention",
        version="1",
        content=b"retain-through-2030",
        media_type="text/plain",
        metadata={"archived": True},
        recorded_at=T0,
    )
    vault.append_evidence(
        evidence_id="evidence.settlement.1",
        claim_id="settled_exactly_once",
        run_id="run.quickstart.1",
        content=b'{"settled_count":1}',
        media_type="application/json",
        schema_ref="schema:settlement:1",
        key_ref="key:producer:1",
        verifier_ref="verifier:settled-once:1",
        policy_ref="policy:retention:1",
        world_scope={
            "type": "declared_closed_world",
            "scope_commitment": "1" * 64,
            "universe_root": "2" * 64,
        },
        captured_at=T0,
        minimum_retain_until=T1,
        deletion_required_by=T3,
        recorded_at=T0,
    )
    vault.create_bundle(
        bundle_id="bundle.settlement.1",
        evidence_ids=["evidence.settlement.1"],
        recorded_at=T0,
    )

    authenticated = EvidenceVault.open_read_only(
        output,
        expected_vault_id=vault.vault_id,
        expected_manifest_root=vault.manifest_root,
        expected_public_key_hex=vault.initial_public_key_hex,
    )
    result = authenticated.reverify_json_predicate(
        "bundle.settlement.1",
        claim_id="settled_exactly_once",
        audited_at=T2,
    )
    return {
        "compiler_status": synthesis.status,
        "compiled_contract": list(synthesis.contract),
        "vault_authentication_status": result["vault_authentication_status"],
        "audit_time_status": result["status"],
        "verdict": result["verdict"],
        "vault_root": authenticated.replay()["vault_root"],
        "output": str(output.resolve()),
        "remaining_unproven": [
            "capture_truth",
            "open_world_inventory_completeness",
            "trusted_real_world_time",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix="auditspec-quickstart-"))
    print(json.dumps(run(output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
