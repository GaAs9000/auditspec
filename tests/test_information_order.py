from __future__ import annotations

import copy
import gzip
import hashlib
import json

import pytest

from auditspec.core.information_order import (
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
from auditspec.core.evidence_vault import EvidenceVault, VaultSigner


def _worlds() -> list[dict[str, object]]:
    return [
        {"world_id": f"w{approval}{comment}", "approval": approval, "comment": comment}
        for approval in (False, True)
        for comment in (False, True)
    ]


def test_quotient_factorization_and_twin_are_dual_certificates() -> None:
    rows = [
        {
            "world_id": row["world_id"],
            "world": {"approval": row["approval"], "comment": row["comment"]},
            "claim_value": row["approval"],
            "evidence_value": {"approval": row["approval"]},
        }
        for row in _worlds()
    ]
    positive = analyze_auditability(
        claim_id="claim.approval", evidence_id="evidence.approval", rows=rows
    )
    assert positive["factorization_exists"] is True
    assert positive["kernel_inclusion"] is True
    assert len(positive["decoder_table"]) == 2
    assert verify_auditability_certificate(positive)

    twin_rows = [
        {**row, "evidence_value": {"constant": 0}} for row in rows
    ]
    negative = analyze_auditability(
        claim_id="claim.approval", evidence_id="evidence.constant", rows=twin_rows
    )
    assert negative["status"] == "TWIN_OBSTRUCTION"
    assert negative["twin"]["left_claim_value"] != negative["twin"]["right_claim_value"]
    assert verify_auditability_certificate(negative)
    attacked = copy.deepcopy(negative)
    attacked["twin"]["right_claim_value"] = attacked["twin"]["left_claim_value"]
    assert not verify_auditability_certificate(attacked)


def test_contract_duality_compiles_exact_hitting_set_and_certificates() -> None:
    worlds = [
        {"world_id": f"w{a}{b}", "a": bool(a), "b": bool(b)}
        for a in (0, 1)
        for b in (0, 1)
    ]
    rows = [
        {
            "world_id": row["world_id"],
            "world": {"a": row["a"], "b": row["b"]},
            "claim_value": row["a"] and row["b"],
            "observations": {
                "m.a": row["a"],
                "m.b": row["b"],
                "m.ab": [row["a"], row["b"]],
                "m.noise": 0,
                "m.full": [row["a"], row["b"], "extra"],
            },
        }
        for row in worlds
    ]
    mechanisms = {
        "m.a": {"cost": 4, "requires": [], "admissible": True},
        "m.b": {"cost": 5, "requires": ["m.a"], "admissible": True},
        "m.ab": {"cost": 8, "requires": [], "admissible": True},
        "m.noise": {"cost": 1, "requires": [], "admissible": True},
        "m.full": {"cost": 20, "requires": [], "admissible": True},
    }
    certificate = compile_minimum_contract(
        claim_id="claim.a-and-b", rows=rows, mechanisms=mechanisms
    )
    assert certificate["status"] == "CONTRACT"
    assert certificate["selected"] == ["m.ab"]
    assert certificate["selected_cost"] == 8
    assert certificate["critical_pair_count"] == 3
    assert len(certificate["separation_certificate"]) == 3
    assert certificate["minimality_certificate"][0]["witness_type"] == "critical_pair"
    assert certificate["optimality_certificate"]["all_lower_cost_candidates_infeasible"]
    assert certificate["full_contract_sufficient"] is True
    assert verify_contract_certificate(certificate)

    attacked = copy.deepcopy(certificate)
    attacked["selected_cost"] = 7
    assert not verify_contract_certificate(attacked)


def test_contract_gap_and_analysis_limit_are_distinct() -> None:
    rows = [
        {
            "world_id": "w0",
            "world": {"answer": False},
            "claim_value": False,
            "observations": {"m.constant": 0},
        },
        {
            "world_id": "w1",
            "world": {"answer": True},
            "claim_value": True,
            "observations": {"m.constant": 0},
        },
    ]
    mechanisms = {
        "m.constant": {"cost": 1, "requires": [], "admissible": True}
    }
    gap = compile_minimum_contract(
        claim_id="claim.answer", rows=rows, mechanisms=mechanisms
    )
    assert gap["status"] == "EVIDENCE_GAP"
    assert gap["obstruction"]["pair"]["separators"] == []
    assert verify_contract_certificate(gap)

    incomplete = compile_minimum_contract(
        claim_id="claim.answer", rows=rows, mechanisms=mechanisms, state_cap=0
    )
    assert incomplete["status"] == "ANALYSIS_INCOMPLETE"
    assert incomplete["analysis_limit"]["states_explored"] == 0
    assert verify_contract_certificate(incomplete)


def _migration_rows(claim: str) -> list[dict[str, object]]:
    rows = []
    for world in _worlds():
        source = {"approval": world["approval"], "comment": world["comment"]}
        transformed = {"approval": world["approval"]}
        claim_value = world["approval"] if claim == "approval" else world["comment"]
        rows.append(
            {
                "state_id": world["world_id"],
                "source_evidence": source,
                "transformed_evidence": transformed,
                "claim_value": claim_value,
            }
        )
    return rows


def test_same_globally_lossy_migration_is_claim_relative() -> None:
    safe = analyze_lifecycle_transformation(
        claim_id="claim.approval",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("approval"),
    )
    hard = analyze_lifecycle_transformation(
        claim_id="claim.comment",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("comment"),
    )
    assert safe["status"] == "PRESERVED"
    assert len(safe["induced_decoder"]) == 2
    assert hard["status"] == "HARD_SEMANTIC_GAP"
    assert hard["lifecycle_twin"]["left_claim_value"] != hard["lifecycle_twin"][
        "right_claim_value"
    ]
    assert verify_lifecycle_certificate(safe)
    assert verify_lifecycle_certificate(hard)

    bundle = make_migration_bundle(
        transformation_id="migration.drop-comment",
        certificates={"claim.approval": safe, "claim.comment": hard},
    )
    assert verify_migration_bundle(bundle, claim_id="claim.approval")["status"] == (
        "PRESERVED"
    )
    assert verify_migration_bundle(bundle, claim_id="claim.comment")["status"] == (
        "HARD_SEMANTIC_GAP"
    )
    with pytest.raises(InformationOrderError, match="absent"):
        verify_migration_bundle(bundle, claim_id="claim.other")


def test_hard_soft_no_posthoc_and_horizon_have_distinct_semantics() -> None:
    safe = analyze_lifecycle_transformation(
        claim_id="claim.approval",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("approval"),
    )
    hard = analyze_lifecycle_transformation(
        claim_id="claim.comment",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("comment"),
    )
    soft = classify_obstruction(
        lifecycle_certificate=safe,
        operationally_usable=False,
        missing_dependencies=["verifier:comment:1"],
    )
    hard_class = classify_obstruction(
        lifecycle_certificate=hard, operationally_usable=True
    )
    restored = classify_obstruction(
        lifecycle_certificate=safe, operationally_usable=True
    )
    assert soft["classification"] == "SOFT_TRUST_INTERPRETABILITY_OBSTRUCTION"
    assert soft["repairable_without_new_execution_specific_evidence"] is True
    assert hard_class["classification"] == "HARD_SEMANTIC_OBSTRUCTION"
    assert hard_class["repairable_without_new_execution_specific_evidence"] is False
    assert restored["classification"] == "AUDITABLE"

    posthoc = no_posthoc_repair_certificate(
        hard,
        [
            DeterministicProcessor("json-reencode", lambda value: json.dumps(value, sort_keys=True)),
            DeterministicProcessor("gzip", lambda value: gzip.compress(json.dumps(value, sort_keys=True).encode()).hex()),
            DeterministicProcessor("sha256", lambda value: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()),
            DeterministicProcessor("strong-decoder-stub", lambda value: {"input": value, "answer": "same-input"}),
        ],
    )
    assert posthoc["all_postprocessors_preserve_collision"] is True

    initial_rows = [
        {
            "world_id": row["state_id"],
            "world": {"source": row["source_evidence"]},
            "claim_value": row["claim_value"],
            "evidence_value": row["source_evidence"],
        }
        for row in _migration_rows("comment")
    ]
    transformed_rows = [
        {
            "world_id": row["state_id"],
            "world": {"source": row["source_evidence"]},
            "claim_value": row["claim_value"],
            "evidence_value": row["transformed_evidence"],
        }
        for row in _migration_rows("comment")
    ]
    horizon = semantic_audit_horizon(
        claim_id="claim.comment",
        timeline=[
            {"time": "t0", "evidence_id": "source", "rows": initial_rows},
            {"time": "t1", "evidence_id": "drop-comment", "rows": transformed_rows},
            {"time": "t2", "evidence_id": "reencoded", "rows": transformed_rows},
        ],
        no_new_evidence=True,
    )
    assert horizon["semantic_horizon_prefix_closed"] is True
    assert horizon["last_semantically_auditable_index"] == 0


def test_vault_executes_claim_relative_lossy_migration_bundle(tmp_path) -> None:
    safe = analyze_lifecycle_transformation(
        claim_id="claim.approval",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("approval"),
    )
    hard = analyze_lifecycle_transformation(
        claim_id="claim.comment",
        transformation_id="migration.drop-comment",
        rows=_migration_rows("comment"),
    )
    bundle = make_migration_bundle(
        transformation_id="migration.drop-comment",
        certificates={"claim.approval": safe, "claim.comment": hard},
    )
    signer = VaultSigner.generate()
    vault = EvidenceVault.create(
        tmp_path / "vault",
        vault_id="vault.claim-relative-migration",
        created_at="2026-01-01T00:00:00Z",
        signer=signer,
    )
    vault.archive_component(
        kind="schema",
        component_id="migrated",
        version="1",
        content=b'{"type":"object"}',
        media_type="application/json",
        metadata={
            "readable": True,
            "migration_mode": "lossy",
            "claim_relative_migration": bundle,
        },
        recorded_at="2026-01-01T00:00:00Z",
    )
    for claim_id, field in (("claim.approval", "approval"), ("claim.comment", "comment")):
        slug = claim_id.split(".")[-1]
        verifier = {
            "schema": "AuditSpec-vault-json-predicate-verifier-v1",
            "predicate": {
                "op": "eq",
                "left": {"op": "field", "name": field},
                "right": {"op": "const", "value": True},
            },
        }
        vault.archive_component(
            kind="verifier",
            component_id=slug,
            version="1",
            content=json.dumps(verifier, sort_keys=True, separators=(",", ":")).encode(),
            media_type="application/json",
            metadata={"archive_executable": True},
            recorded_at="2026-01-01T00:00:00Z",
        )
    vault.archive_component(
        kind="key",
        component_id="producer",
        version="1",
        content=b"historic-key",
        media_type="application/octet-stream",
        metadata={
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "revoked_at": "2027-01-01T00:00:00Z",
            "revocation_kind": "routine",
            "compromise_effective_from": None,
        },
        recorded_at="2026-01-01T00:00:00Z",
    )
    vault.archive_component(
        kind="policy",
        component_id="retention",
        version="1",
        content=b"policy",
        media_type="text/plain",
        metadata={"archived": True},
        recorded_at="2026-01-01T00:00:00Z",
    )
    for claim_id in ("claim.approval", "claim.comment"):
        slug = claim_id.split(".")[-1]
        vault.append_evidence(
            evidence_id=f"evidence.{slug}",
            claim_id=claim_id,
            run_id="run.migration.1",
            content=b'{"approval":true}',
            media_type="application/json",
            schema_ref="schema:migrated:1",
            key_ref="key:producer:1",
            verifier_ref=f"verifier:{slug}:1",
            policy_ref="policy:retention:1",
            world_scope={
                "type": "declared_closed_world",
                "scope_commitment": "1" * 64,
                "universe_root": "2" * 64,
            },
            captured_at="2026-01-01T00:00:00Z",
            minimum_retain_until="2027-01-01T00:00:00Z",
            deletion_required_by="2030-01-01T00:00:00Z",
            recorded_at="2026-01-01T00:00:00Z",
        )
        vault.create_bundle(
            bundle_id=f"bundle.{slug}",
            evidence_ids=[f"evidence.{slug}"],
            recorded_at="2026-01-01T00:00:00Z",
        )

    positive = vault.reverify_json_predicate(
        "bundle.approval",
        claim_id="claim.approval",
        audited_at="2028-01-01T00:00:00Z",
    )
    assert positive["verdict"] == "SUPPORTED"
    assert positive["obstructions"] == []
    negative = vault.reverify_json_predicate(
        "bundle.comment",
        claim_id="claim.comment",
        audited_at="2028-01-01T00:00:00Z",
    )
    assert negative["verdict"] == "LIFECYCLE_GAP"
    assert negative["primary_failure"]["subtype"] == (
        "MIGRATION_CLAIM_INFORMATION_LOSS"
    )
    assert negative["obstructions"][0]["obstruction_class"] == (
        "HARD_SEMANTIC_OBSTRUCTION"
    )
