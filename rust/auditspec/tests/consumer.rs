use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use auditspec::canonical::canonical_bytes;
use auditspec::canonical::digest;
use auditspec::canonical::raw_sha256;
use auditspec::trust::evaluate_institutional_responses;
use auditspec::vault::{EvidenceVault, VaultSigner};
use serde_json::{Value, json};
use tempfile::TempDir;

const T0: &str = "2026-01-01T00:00:00Z";
const T1: &str = "2027-01-01T00:00:00Z";
const T2: &str = "2028-01-01T00:00:00Z";
const T3: &str = "2030-01-01T00:00:00Z";

fn independent_model_case(case_id: &str) -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/vault_state_model_vectors.json"
    ))
    .expect("independent model fixture");
    fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["case_id"] == case_id)
        .unwrap_or_else(|| panic!("missing independent model case: {case_id}"))["expected"]
        .clone()
}

fn signer() -> VaultSigner {
    VaultSigner::from_bytes(&[7_u8; 32]).expect("fixed test key")
}

fn new_vault(
    base: &TempDir,
    name: &str,
    key_metadata: Value,
    bridge_metadata: Option<Value>,
) -> EvidenceVault {
    let root = base.path().join(name);
    let vault =
        EvidenceVault::create(&root, &format!("vault.{name}"), T0, signer()).expect("create vault");
    vault
        .archive_component(
            "schema",
            "payment-evidence",
            "1",
            br#"{"type":"object"}"#,
            "application/json",
            json!({"readable": true, "migration_mode": "lossless"}),
            T0,
        )
        .expect("schema");
    let verifier = json!({
        "schema": "AuditSpec-vault-json-predicate-verifier-v1",
        "predicate": {
            "op": "eq",
            "left": {"op": "field", "name": "settled_count"},
            "right": {"op": "const", "value": 1}
        }
    });
    vault
        .archive_component(
            "verifier",
            "payment-predicate",
            "1",
            &canonical_bytes(&verifier).unwrap(),
            "application/json",
            json!({"archive_executable": true}),
            T0,
        )
        .expect("verifier");
    vault
        .archive_component(
            "key",
            "producer-key",
            "1",
            b"historical-public-key",
            "application/octet-stream",
            key_metadata,
            T0,
        )
        .expect("key");
    vault
        .archive_component(
            "policy",
            "payment-policy",
            "1",
            b"policy-v1",
            "text/plain",
            json!({"archived": true}),
            T0,
        )
        .expect("policy");
    if let Some(metadata) = bridge_metadata {
        vault
            .archive_component(
                "bridge",
                "inventory",
                "1",
                b"signed-public-inventory-root",
                "application/octet-stream",
                metadata,
                T0,
            )
            .expect("bridge");
    }
    vault
}

fn routine_key() -> Value {
    json!({
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": T1,
        "revoked_at": T1,
        "revocation_kind": "routine",
        "compromise_effective_from": null
    })
}

fn append_and_bundle(vault: &EvidenceVault, bridged: bool, deadline: &str) {
    let scope = if bridged {
        json!({
            "type": "externally_bridged_world",
            "scope_commitment": "1".repeat(64),
            "bridge_ref": "bridge:inventory:1"
        })
    } else {
        json!({
            "type": "declared_closed_world",
            "scope_commitment": "1".repeat(64),
            "universe_root": "2".repeat(64)
        })
    };
    vault
        .append_evidence(
            "evidence.payment.1",
            "claim.payment.once",
            "run.payment.1",
            br#"{"settled_count":1}"#,
            "application/json",
            "schema:payment-evidence:1",
            "key:producer-key:1",
            "verifier:payment-predicate:1",
            "policy:payment-policy:1",
            scope,
            T0,
            T1,
            deadline,
            T0,
        )
        .expect("append evidence");
    vault
        .create_bundle("bundle.payment.1", &["evidence.payment.1".to_owned()], T0)
        .expect("bundle");
}

#[test]
fn consumer_flow_reverifies_and_fails_closed() {
    let revocation_expected = independent_model_case("routine_revocation_boundary");
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "positive", routine_key(), None);
    append_and_bundle(&vault, false, T3);
    assert_eq!(
        vault
            .retrieve_for_audit("bundle.payment.1", T2)
            .unwrap()
            .record["status"],
        revocation_expected["capture_before_revocation"]
    );
    let result = EvidenceVault::open_read_only(vault.root())
        .unwrap()
        .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
        .unwrap();
    assert_eq!(result["status"], "REVERIFIED_AT_AUDIT_TIME");
    assert_eq!(result["verdict"], "SUPPORTED");
    assert_eq!(result["claim_value"], true);

    let compromised = new_vault(
        &temp,
        "compromised",
        json!({
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": null,
            "revoked_at": T1,
            "revocation_kind": "retroactive_compromise",
            "compromise_effective_from": "2025-12-01T00:00:00Z"
        }),
        None,
    );
    append_and_bundle(&compromised, false, T3);
    let result = compromised
        .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
        .unwrap();
    assert_eq!(result["verdict"], "LIFECYCLE_GAP");
    assert_eq!(
        result["primary_failure"]["subtype"],
        "HISTORIC_KEY_UNRESOLVED"
    );

    let expired_bridge = new_vault(
        &temp,
        "bridge",
        routine_key(),
        Some(json!({
            "valid_from": T0,
            "valid_until": T1,
            "revoked_at": null,
            "mode": "external_inventory"
        })),
    );
    append_and_bundle(&expired_bridge, true, T3);
    let result = expired_bridge
        .retrieve_for_audit("bundle.payment.1", T2)
        .unwrap()
        .record;
    assert_eq!(result["status"], "LIFECYCLE_GAP");
    assert_eq!(
        result["primary_failure"]["subtype"],
        "BRIDGE_EXPIRED_OR_REVOKED"
    );
}

#[test]
fn routine_revocation_bounds_capture_when_valid_until_is_null() {
    let expected = independent_model_case("routine_revocation_boundary");
    let temp = TempDir::new().unwrap();
    let vault = new_vault(
        &temp,
        "routine-revoked",
        json!({
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": null,
            "revoked_at": T1,
            "revocation_kind": "routine",
            "compromise_effective_from": null
        }),
        None,
    );
    vault
        .append_evidence(
            "evidence.payment.1",
            "claim.payment.once",
            "run.payment.1",
            br#"{"settled_count":1}"#,
            "application/json",
            "schema:payment-evidence:1",
            "key:producer-key:1",
            "verifier:payment-predicate:1",
            "policy:payment-policy:1",
            json!({
                "type": "declared_closed_world",
                "scope_commitment": "1".repeat(64),
                "universe_root": "2".repeat(64)
            }),
            T2,
            T2,
            T3,
            T2,
        )
        .unwrap();
    vault
        .create_bundle("bundle.payment.1", &["evidence.payment.1".to_owned()], T2)
        .unwrap();
    let result = vault
        .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
        .unwrap();
    assert_eq!(result["verdict"], "LIFECYCLE_GAP");
    assert_eq!(
        result["primary_failure"]["subtype"],
        expected["capture_at_or_after_revocation"]
    );
}

#[test]
fn legal_hold_delete_race_serializes_to_one_valid_outcome() {
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "race", routine_key(), None);
    append_and_bundle(&vault, false, T3);
    let hold_vault = EvidenceVault::open_with_signer(vault.root(), Some(signer())).unwrap();
    let delete_vault = EvidenceVault::open_with_signer(vault.root(), Some(signer())).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let hold_barrier = Arc::clone(&barrier);
    let hold = thread::spawn(move || {
        hold_barrier.wait();
        hold_vault.place_legal_hold(
            "hold.race",
            &["evidence.payment.1".to_owned()],
            "legal.authority.1",
            &"3".repeat(64),
            T2,
        )
    });
    let delete_barrier = Arc::clone(&barrier);
    let delete = thread::spawn(move || {
        delete_barrier.wait();
        delete_vault.delete_evidence(
            "evidence.payment.1",
            T2,
            "permitted_disposal",
            "custody.authority.1",
        )
    });
    barrier.wait();
    let hold_succeeded = hold.join().unwrap().is_ok();
    let delete_succeeded = delete.join().unwrap().is_ok();
    assert_ne!(hold_succeeded, delete_succeeded);
    let state = EvidenceVault::open_read_only(vault.root())
        .unwrap()
        .replay()
        .unwrap();
    assert_eq!(state.active_hold_count() > 0, hold_succeeded);
    assert_eq!(state.deletion_count() > 0, delete_succeeded);
}

#[test]
fn retention_hold_deletion_and_retirement_are_public_operations() {
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "retention", routine_key(), None);
    append_and_bundle(&vault, false, T2);
    vault
        .place_legal_hold(
            "hold.1",
            &["evidence.payment.1".to_owned()],
            "legal.authority.1",
            &"3".repeat(64),
            T1,
        )
        .unwrap();
    assert_eq!(
        vault.retention_decision("evidence.payment.1", T2).unwrap()["status"],
        "LEGAL_HOLD"
    );
    vault
        .release_legal_hold("hold.1", "legal.authority.1", &"4".repeat(64), T1)
        .unwrap();
    let tombstone = vault
        .delete_evidence(
            "evidence.payment.1",
            T2,
            "policy_deadline",
            "custody.authority.1",
        )
        .unwrap();
    assert_eq!(tombstone["body"]["physical_deleted"], true);
    let result = vault
        .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
        .unwrap();
    assert_eq!(
        result["primary_failure"]["subtype"],
        "LEGAL_DELETION_PREVENTS_REVERIFY"
    );

    let retirement = new_vault(&temp, "retirement", routine_key(), None);
    append_and_bundle(&retirement, false, T3);
    retirement
        .retire_component(
            "verifier:payment-predicate:1",
            None,
            &["claim.payment.once".to_owned()],
            &["claim.payment.future".to_owned()],
            T1,
        )
        .unwrap();
    assert_eq!(
        retirement
            .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
            .unwrap()["verdict"],
        "SUPPORTED"
    );
}

#[test]
fn component_alias_prevents_physical_evidence_object_deletion() {
    let expected = independent_model_case("shared_component_delete");
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "component-alias", routine_key(), None);
    let shared = br#"{"type":"object"}"#;
    vault
        .append_evidence(
            "evidence.payment.1",
            "claim.payment.once",
            "run.payment.1",
            shared,
            "application/json",
            "schema:payment-evidence:1",
            "key:producer-key:1",
            "verifier:payment-predicate:1",
            "policy:payment-policy:1",
            json!({
                "type": "declared_closed_world",
                "scope_commitment": "1".repeat(64),
                "universe_root": "2".repeat(64)
            }),
            T0,
            T1,
            T3,
            T0,
        )
        .unwrap();
    let sha = raw_sha256(shared);
    let object_path = vault
        .root()
        .join("objects/sha256")
        .join(&sha[..2])
        .join(&sha[2..]);

    let tombstone = vault
        .delete_evidence(
            "evidence.payment.1",
            T2,
            "permitted_disposal",
            "custody.authority.1",
        )
        .unwrap();

    assert_eq!(
        tombstone["body"]["physical_deleted"],
        expected["physical_deleted"]
    );
    assert_eq!(
        tombstone["body"]["retained_by_component_refs"],
        expected["retained_by_component_refs"]
    );
    assert_eq!(object_path.is_file(), expected["object_survives"] == true);
}

#[test]
fn legal_hold_and_audit_retrieval_share_deadline_semantics() {
    let expected = independent_model_case("hold_deadline_release");
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "hold-deadline", routine_key(), None);
    append_and_bundle(&vault, false, T2);
    vault
        .place_legal_hold(
            "hold.deadline",
            &["evidence.payment.1".to_owned()],
            "legal.authority.1",
            &"5".repeat(64),
            T1,
        )
        .unwrap();

    assert_eq!(
        vault.retention_decision("evidence.payment.1", T2).unwrap()["status"],
        expected["held_retention_status"]
    );
    assert_eq!(
        vault
            .reverify_json_predicate("bundle.payment.1", "claim.payment.once", T2)
            .unwrap()["verdict"],
        "SUPPORTED"
    );
    assert_eq!(
        vault
            .retrieve_for_audit("bundle.payment.1", T2)
            .unwrap()
            .record["status"],
        expected["held_retrieval_status"]
    );

    vault
        .release_legal_hold("hold.deadline", "legal.authority.1", &"6".repeat(64), T2)
        .unwrap();
    assert_eq!(
        vault.retention_decision("evidence.payment.1", T2).unwrap()["status"],
        expected["released_retention_status"]
    );
    let released = vault
        .retrieve_for_audit("bundle.payment.1", T2)
        .unwrap()
        .record;
    assert_eq!(released["status"], expected["released_retrieval_status"]);
    assert_eq!(
        released["primary_failure"]["subtype"],
        expected["released_primary_failure"]
    );
}

#[test]
fn shared_evidence_delete_sequence_matches_independent_model() {
    let expected = independent_model_case("shared_evidence_delete_sequence");
    let temp = TempDir::new().unwrap();
    let vault = new_vault(&temp, "shared-evidence", routine_key(), None);
    let content = br#"{"settled_count":1}"#;
    for (evidence_id, run_id) in [
        ("evidence.payment.1", "run.payment.1"),
        ("evidence.payment.2", "run.payment.2"),
    ] {
        vault
            .append_evidence(
                evidence_id,
                "claim.payment.once",
                run_id,
                content,
                "application/json",
                "schema:payment-evidence:1",
                "key:producer-key:1",
                "verifier:payment-predicate:1",
                "policy:payment-policy:1",
                json!({
                    "type": "declared_closed_world",
                    "scope_commitment": "1".repeat(64),
                    "universe_root": "2".repeat(64)
                }),
                T0,
                T1,
                T3,
                T0,
            )
            .unwrap();
    }
    let sha = raw_sha256(content);
    let object_path = vault
        .root()
        .join("objects/sha256")
        .join(&sha[..2])
        .join(&sha[2..]);
    let first = vault
        .delete_evidence(
            "evidence.payment.1",
            T2,
            "permitted_disposal",
            "custody.authority.1",
        )
        .unwrap();
    assert_eq!(
        first["body"]["physical_deleted"],
        expected["first_physical_deleted"]
    );
    assert_eq!(
        first["body"]["retained_by_live_evidence_ids"],
        expected["first_retained_by_live_evidence_ids"]
    );
    assert_eq!(
        object_path.is_file(),
        expected["object_survives_after_first"] == true
    );
    let second = vault
        .delete_evidence(
            "evidence.payment.2",
            T2,
            "permitted_disposal",
            "custody.authority.1",
        )
        .unwrap();
    assert_eq!(
        second["body"]["physical_deleted"],
        expected["second_physical_deleted"]
    );
    assert_eq!(
        object_path.is_file(),
        expected["object_survives_after_second"] == true
    );
}

#[test]
fn signature_key_substitution_and_cross_vault_transplant_are_rejected() {
    let temp = TempDir::new().unwrap();
    let source = new_vault(&temp, "source", routine_key(), None);
    let source_event = first_event(source.root());

    let attacked = temp.path().join("attacked-signature");
    copy_dir(source.root(), &attacked);
    let attacked_event = first_event(&attacked);
    let mut value: Value = serde_json::from_slice(&fs::read(&attacked_event).unwrap()).unwrap();
    value["signature"]["public_key_hex"] = Value::String("0".repeat(64));
    fs::write(&attacked_event, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        EvidenceVault::open_read_only(&attacked)
            .unwrap()
            .replay()
            .unwrap_err()
            .to_string()
            .contains("signature")
    );

    let target =
        EvidenceVault::create(&temp.path().join("target"), "vault.target", T0, signer()).unwrap();
    target
        .archive_component(
            "schema",
            "placeholder",
            "1",
            b"x",
            "text/plain",
            json!({}),
            T0,
        )
        .unwrap();
    let target_events = target.root().join("events");
    for path in fs::read_dir(&target_events).unwrap() {
        fs::remove_file(path.unwrap().path()).unwrap();
    }
    fs::copy(
        &source_event,
        target_events.join(source_event.file_name().unwrap()),
    )
    .unwrap();
    assert!(
        EvidenceVault::open_read_only(target.root())
            .unwrap()
            .replay()
            .unwrap_err()
            .to_string()
            .contains("chain/root")
    );
}

#[test]
fn missing_institutional_receipts_remain_tcb_gap() {
    let roles = [
        "availability_monitor",
        "result",
        "result_ledger",
        "result_monitor",
        "result_validator",
        "transparency_log",
    ];
    let requests = roles
        .iter()
        .map(|role| json!({"role": role}))
        .collect::<Vec<_>>();
    let request_set = json!({
        "schema": "AuditSpec-institutional-authority-request-set-v1",
        "required_role_count": 6,
        "required_pair_count": 15,
        "requests": requests,
        "request_set_root": digest(
            "AuditSpec-institutional-authority-request-set-v1",
            &Value::Array(requests)
        ).unwrap()
    });
    let result = evaluate_institutional_responses(&request_set, &[], &[], None).unwrap();
    assert_eq!(result["status"], "TCB_GAP");
    assert_eq!(result["verdict"], "TCB_GAP");
    assert_eq!(result["valid_response_count"], 0);
    assert_eq!(result["required_response_count"], 6);
    assert_eq!(result["institutional_independence_proven"], false);
}

fn copy_dir(source: &std::path::Path, target: &std::path::Path) {
    fs::create_dir(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn first_event(vault_root: &std::path::Path) -> std::path::PathBuf {
    let mut events = fs::read_dir(vault_root.join("events"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    events.sort();
    events.into_iter().next().expect("vault has an event")
}
