//! Signed, append-only, content-addressed Evidence Vault.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::canonical::{canonical_bytes, digest, json_line, raw_sha256, strict_json_loads};
use crate::predicate;
use crate::{Result, invalid};

pub const VAULT_SCHEMA: &str = "AuditSpec-evidence-vault-v1";
pub const EVENT_SCHEMA: &str = "AuditSpec-evidence-vault-event-v1";
pub const OBJECT_SCHEMA: &str = "AuditSpec-evidence-vault-object-ref-v1";
pub const COMPONENT_SCHEMA: &str = "AuditSpec-evidence-vault-component-v1";
pub const EVIDENCE_SCHEMA: &str = "AuditSpec-evidence-vault-evidence-record-v1";
pub const BUNDLE_SCHEMA: &str = "AuditSpec-evidence-vault-bundle-v1";
pub const RETRIEVAL_SCHEMA: &str = "AuditSpec-evidence-vault-audit-retrieval-v1";
pub const REVERIFY_SCHEMA: &str = "AuditSpec-evidence-vault-reverification-v1";
const DELETION_INTENT_SCHEMA_V1: &str = "AuditSpec-evidence-vault-deletion-intent-v1";
const DELETION_INTENT_SCHEMA_V2: &str = "AuditSpec-evidence-vault-deletion-intent-v2";
const DELETION_INTENT_SCHEMA_V3: &str = "AuditSpec-evidence-vault-deletion-intent-v3";
const DELETION_TOMBSTONE_SCHEMA_V1: &str = "AuditSpec-evidence-vault-deletion-tombstone-v1";
const DELETION_TOMBSTONE_SCHEMA_V2: &str = "AuditSpec-evidence-vault-deletion-tombstone-v2";
const DELETION_TOMBSTONE_SCHEMA_V3: &str = "AuditSpec-evidence-vault-deletion-tombstone-v3";
const JOURNAL_AUTHORITY_ROTATION_SCHEMA: &str =
    "AuditSpec-evidence-vault-journal-authority-rotation-v1";
const LEGAL_HOLD_SCHEMA_V2: &str = "AuditSpec-evidence-vault-legal-hold-v2";
const LEGAL_HOLD_RELEASE_SCHEMA_V2: &str = "AuditSpec-evidence-vault-legal-hold-release-v2";
const RETIREMENT_SCHEMA_V2: &str = "AuditSpec-evidence-vault-retirement-certificate-v2";
const AUTHORITY_ATTRIBUTION_SEMANTICS: &str = "attribution_metadata_asserted_by_vault_authority";

const COMPONENT_KINDS: &[&str] = &["bridge", "key", "policy", "schema", "verifier"];

#[derive(Clone)]
pub struct VaultSigner {
    key: SigningKey,
}

impl VaultSigner {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid("private key is not a raw 32-byte Ed25519 key"))?;
        Ok(Self {
            key: SigningKey::from_bytes(&raw),
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign_root(&self, event_root: &str) -> Result<String> {
        Ok(hex::encode(
            self.key.sign(&signature_message(event_root)?).to_bytes(),
        ))
    }
}

pub fn write_new_private_key(path: &Path, signer: &VaultSigner) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&signer.to_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn load_private_key(path: &Path) -> Result<VaultSigner> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "private-key path must be a regular non-symlink file",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid(
            "private-key file permissions must exclude group/other",
        ));
    }
    VaultSigner::from_bytes(&fs::read(path)?)
}

#[derive(Clone, Debug, Default)]
pub struct VaultTrustPins {
    pub expected_vault_id: Option<String>,
    pub expected_manifest_root: Option<String>,
    pub expected_public_key_hex: Option<String>,
    pub expected_vault_root: Option<String>,
}

impl VaultTrustPins {
    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.expected_vault_id {
            identifier(value, "expected_vault_id")?;
        }
        for (value, label) in [
            (&self.expected_manifest_root, "expected_manifest_root"),
            (&self.expected_vault_root, "expected_vault_root"),
        ] {
            if let Some(value) = value {
                sha256_digest(value, label)?;
            }
        }
        if let Some(value) = &self.expected_public_key_hex {
            verifying_key(value)?;
        }
        if self.expected_vault_id.is_some() && !self.has_cryptographic_pin() {
            return Err(invalid(
                "expected_vault_id requires a manifest, public-key, or vault-root pin",
            ));
        }
        Ok(())
    }

    fn has_cryptographic_pin(&self) -> bool {
        self.expected_manifest_root.is_some()
            || self.expected_public_key_hex.is_some()
            || self.expected_vault_root.is_some()
    }

    fn names(&self) -> Vec<&'static str> {
        [
            ("vault_id", self.expected_vault_id.is_some()),
            ("manifest_root", self.expected_manifest_root.is_some()),
            ("public_key", self.expected_public_key_hex.is_some()),
            ("vault_root", self.expected_vault_root.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect()
    }

    fn authentication_status(&self) -> &'static str {
        if self.expected_vault_root.is_some() || self.expected_manifest_root.is_some() {
            "EXTERNALLY_AUTHENTICATED"
        } else if self.expected_public_key_hex.is_some() {
            "AUTHORITY_PINNED"
        } else {
            "SELF_CONSISTENT"
        }
    }

    fn authentication_scope(&self) -> &'static str {
        if self.expected_vault_root.is_some() {
            "SNAPSHOT"
        } else if self.expected_manifest_root.is_some() {
            "GENESIS"
        } else if self.expected_public_key_hex.is_some() {
            "SIGNING_AUTHORITY"
        } else {
            "INTERNAL_ONLY"
        }
    }
}

#[derive(Clone, Debug)]
struct EventRecord {
    body: Value,
    event_root: String,
}

#[derive(Clone, Debug)]
struct HoldRecord {
    evidence_ids: Vec<String>,
    released: bool,
    placed_event_root: String,
}

#[derive(Clone, Debug)]
pub struct VaultState {
    components: BTreeMap<String, EventRecord>,
    evidence: BTreeMap<String, EventRecord>,
    bundles: BTreeMap<String, EventRecord>,
    holds: BTreeMap<String, HoldRecord>,
    deletion_intents: BTreeMap<String, EventRecord>,
    deletions: BTreeMap<String, EventRecord>,
    retirements: BTreeMap<String, EventRecord>,
    pub event_count: usize,
    pub vault_root: String,
    pub initial_public_key_hex: String,
    pub active_public_key_hex: String,
    pub public_key_history: Vec<String>,
    pub journal_authority_rotations: Vec<Value>,
}

impl VaultState {
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    pub fn active_hold_count(&self) -> usize {
        self.holds.values().filter(|hold| !hold.released).count()
    }

    pub fn deletion_count(&self) -> usize {
        self.deletions.len()
    }

    fn deletion_pending(&self, evidence_id: &str) -> bool {
        self.deletion_intents.contains_key(evidence_id) && !self.deletions.contains_key(evidence_id)
    }
}

pub struct AuditRetrieval {
    pub record: Value,
    pub evidence_bytes: BTreeMap<String, Vec<u8>>,
}

pub struct EvidenceVault {
    root: PathBuf,
    signer: Option<VaultSigner>,
    manifest: Value,
    trust_pins: VaultTrustPins,
}

impl EvidenceVault {
    pub fn create(
        root: &Path,
        vault_id: &str,
        created_at: &str,
        signer: VaultSigner,
    ) -> Result<Self> {
        identifier(vault_id, "vault_id")?;
        instant(created_at)?;
        if root.exists() && fs::read_dir(root)?.next().is_some() {
            return Err(invalid("vault root already exists and is not empty"));
        }
        fs::create_dir_all(root)?;
        for relative in ["events", "objects/sha256", "tmp"] {
            fs::create_dir_all(root.join(relative))?;
        }
        let manifest_body = json!({
            "schema": VAULT_SCHEMA,
            "vault_id": vault_id,
            "created_at": created_at,
            "hash_algorithm": "sha256",
            "signature_algorithm": "ed25519",
            "public_key_hex": signer.public_key_hex(),
            "event_schema": EVENT_SCHEMA,
            "object_addressing": "sha256_raw_bytes",
            "private_key_persisted": false
        });
        let mut manifest = manifest_body.clone();
        object_mut(&mut manifest)?.insert(
            "manifest_root".to_owned(),
            Value::String(digest(VAULT_SCHEMA, &manifest_body)?),
        );
        exclusive_write(&root.join("vault.json"), &json_line(&manifest)?, 0o644)?;
        exclusive_write(&root.join(".lock"), b"", 0o644)?;
        Self::open_with_signer(root, Some(signer))
    }

    pub fn open_read_only(root: &Path) -> Result<Self> {
        Self::open_read_only_with_pins(root, VaultTrustPins::default())
    }

    pub fn open_read_only_with_pins(root: &Path, trust_pins: VaultTrustPins) -> Result<Self> {
        Self::open_internal(root, None, trust_pins)
    }

    pub fn open_with_signer(root: &Path, signer: Option<VaultSigner>) -> Result<Self> {
        Self::open_internal(root, signer, VaultTrustPins::default())
    }

    fn open_internal(
        root: &Path,
        signer: Option<VaultSigner>,
        trust_pins: VaultTrustPins,
    ) -> Result<Self> {
        trust_pins.validate()?;
        let root = absolute(root)?;
        let manifest = load_manifest(&root)?;
        let vault = Self {
            root,
            signer,
            manifest,
            trust_pins,
        };
        vault.verify_manifest_pins()?;
        if vault.signer.is_some() || vault.trust_pins.has_cryptographic_pin() {
            let state = vault.replay()?;
            vault.verify_vault_root_pin(&state)?;
            if let Some(active) = &vault.signer {
                if active.public_key_hex() != state.active_public_key_hex {
                    return Err(invalid(
                        "vault signer does not match active journal authority",
                    ));
                }
            }
        }
        if vault.signer.is_some() {
            vault.with_lock(|active| active.recover_locked())?;
        }
        Ok(vault)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault_id(&self) -> Result<&str> {
        field_str(&self.manifest, "vault_id")
    }

    pub fn manifest_root(&self) -> Result<&str> {
        field_str(&self.manifest, "manifest_root")
    }

    pub fn initial_public_key_hex(&self) -> Result<&str> {
        field_str(&self.manifest, "public_key_hex")
    }

    pub fn assurance(&self, state: Option<&VaultState>) -> Result<Value> {
        let owned;
        let current = match state {
            Some(value) => value,
            None => {
                owned = self.replay()?;
                &owned
            }
        };
        self.verify_vault_root_pin(current)?;
        Ok(json!({
            "schema": "AuditSpec-evidence-vault-assurance-v1",
            "status": self.trust_pins.authentication_status(),
            "authentication_scope": self.trust_pins.authentication_scope(),
            "rollback_protection": self.trust_pins.expected_vault_root.is_some(),
            "integrity_status": "VALID",
            "external_pin_names": self.trust_pins.names(),
            "vault_id": self.vault_id()?,
            "manifest_root": self.manifest_root()?,
            "vault_root": current.vault_root,
            "initial_public_key_hex": current.initial_public_key_hex,
            "active_public_key_hex": current.active_public_key_hex,
            "journal_authority_rotation_count": current.journal_authority_rotations.len(),
            "time_assurance": "DECLARED_BY_VAULT_AUTHORITY"
        }))
    }

    pub fn rotate_journal_authority(
        &self,
        successor_public_key_hex: &str,
        reason_digest: &str,
        recorded_at: &str,
    ) -> Result<Value> {
        verifying_key(successor_public_key_hex)?;
        sha256_digest(reason_digest, "reason_digest")?;
        instant(recorded_at)?;
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            if state
                .public_key_history
                .iter()
                .any(|value| value == successor_public_key_hex)
            {
                return Err(invalid("journal authority key was already used"));
            }
            vault.append_event_locked(
                "JOURNAL_AUTHORITY_ROTATED",
                json!({
                    "schema": JOURNAL_AUTHORITY_ROTATION_SCHEMA,
                    "predecessor_public_key_hex": state.active_public_key_hex,
                    "successor_public_key_hex": successor_public_key_hex,
                    "reason_digest": reason_digest
                }),
                recorded_at,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn archive_component(
        &self,
        kind: &str,
        component_id: &str,
        version: &str,
        content: &[u8],
        media_type_value: &str,
        metadata: Value,
        recorded_at: &str,
    ) -> Result<Value> {
        if !COMPONENT_KINDS.contains(&kind) {
            return Err(invalid("component kind is invalid"));
        }
        identifier(component_id, "component_id")?;
        identifier(version, "component version")?;
        instant(recorded_at)?;
        if content.is_empty() {
            return Err(invalid("component content must be non-empty bytes"));
        }
        media_type(media_type_value)?;
        require_object(&metadata, "component metadata")?;
        canonical_bytes(&metadata)?;
        let component_ref = format!("{kind}:{component_id}:{version}");
        self.with_transaction(|vault| {
            if vault.replay()?.components.contains_key(&component_ref) {
                return Err(invalid("component reference already exists"));
            }
            let object_ref = vault.put_object(content, media_type_value)?;
            let body = json!({
                "schema": COMPONENT_SCHEMA,
                "component_ref": component_ref,
                "kind": kind,
                "component_id": component_id,
                "version": version,
                "object_ref": object_ref,
                "metadata": metadata
            });
            vault.append_event_locked("COMPONENT_ARCHIVED", body, recorded_at)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_evidence(
        &self,
        evidence_id: &str,
        claim_id: &str,
        run_id: &str,
        content: &[u8],
        media_type_value: &str,
        schema_ref: &str,
        key_ref: &str,
        verifier_ref: &str,
        policy_ref: &str,
        world_scope: Value,
        captured_at: &str,
        minimum_retain_until: &str,
        deletion_required_by: &str,
        recorded_at: &str,
    ) -> Result<Value> {
        for (value, label) in [
            (evidence_id, "evidence_id"),
            (claim_id, "claim_id"),
            (run_id, "run_id"),
        ] {
            identifier(value, label)?;
        }
        let captured = instant(captured_at)?;
        let minimum = instant(minimum_retain_until)?;
        let deletion = instant(deletion_required_by)?;
        instant(recorded_at)?;
        if !(captured <= minimum && minimum <= deletion) {
            return Err(invalid("evidence retention interval is invalid"));
        }
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            if state.evidence.contains_key(evidence_id) {
                return Err(invalid("evidence id already exists"));
            }
            for (name, reference, expected) in [
                ("schema_ref", schema_ref, "schema"),
                ("key_ref", key_ref, "key"),
                ("verifier_ref", verifier_ref, "verifier"),
                ("policy_ref", policy_ref, "policy"),
            ] {
                let component = state.components.get(reference);
                if component.and_then(|row| field_str(&row.body, "kind").ok()) != Some(expected) {
                    return Err(invalid(format!("{name} is unresolved or has wrong kind")));
                }
                vault.require_capture_eligible_component(&state, reference, claim_id, name)?;
            }
            validate_world_scope(&world_scope, &state.components)?;
            if field_str(&world_scope, "type")? == "externally_bridged_world" {
                vault.require_capture_eligible_component(
                    &state,
                    field_str(&world_scope, "bridge_ref")?,
                    claim_id,
                    "bridge_ref",
                )?;
            }
            let object_ref = vault.put_object(content, media_type_value)?;
            let body = json!({
                "schema": EVIDENCE_SCHEMA,
                "evidence_id": evidence_id,
                "claim_id": claim_id,
                "run_id": run_id,
                "object_ref": object_ref,
                "schema_ref": schema_ref,
                "key_ref": key_ref,
                "verifier_ref": verifier_ref,
                "policy_ref": policy_ref,
                "world_scope": world_scope,
                "captured_at": captured_at,
                "minimum_retain_until": minimum_retain_until,
                "deletion_required_by": deletion_required_by
            });
            vault.append_event_locked("EVIDENCE_APPENDED", body, recorded_at)
        })
    }

    pub fn create_bundle(
        &self,
        bundle_id: &str,
        evidence_ids: &[String],
        recorded_at: &str,
    ) -> Result<Value> {
        identifier(bundle_id, "bundle_id")?;
        instant(recorded_at)?;
        let mut ids = evidence_ids.to_vec();
        ids.sort();
        ids.dedup();
        if ids.is_empty() || ids.len() != evidence_ids.len() {
            return Err(invalid("bundle evidence ids must be non-empty and unique"));
        }
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            if state.bundles.contains_key(bundle_id) {
                return Err(invalid("bundle id already exists"));
            }
            let mut rows = Vec::new();
            for evidence_id in ids {
                let record = state
                    .evidence
                    .get(&evidence_id)
                    .filter(|_| {
                        !state.deletions.contains_key(&evidence_id)
                            && !state.deletion_pending(&evidence_id)
                    })
                    .ok_or_else(|| invalid("bundle references unknown evidence"))?;
                rows.push(json!({
                    "evidence_id": evidence_id,
                    "evidence_event_root": record.event_root,
                    "object_ref": field(&record.body, "object_ref")?.clone()
                }));
            }
            let evidence_count = rows.len();
            let rows_value = Value::Array(rows);
            let bundle_root = digest(BUNDLE_SCHEMA, &rows_value)?;
            let body = json!({
                "schema": BUNDLE_SCHEMA,
                "bundle_id": bundle_id,
                "evidence": rows_value,
                "evidence_count": evidence_count,
                "bundle_root": bundle_root
            });
            vault.append_event_locked("BUNDLE_SEALED", body, recorded_at)
        })
    }

    pub fn place_legal_hold(
        &self,
        hold_id: &str,
        evidence_ids: &[String],
        authority_ref: &str,
        reason_digest: &str,
        recorded_at: &str,
    ) -> Result<Value> {
        identifier(hold_id, "hold_id")?;
        identifier(authority_ref, "authority_ref")?;
        sha256_digest(reason_digest, "reason_digest")?;
        instant(recorded_at)?;
        let mut ids = evidence_ids.to_vec();
        ids.sort();
        ids.dedup();
        if ids.is_empty() || ids.len() != evidence_ids.len() {
            return Err(invalid(
                "legal hold evidence ids must be non-empty and unique",
            ));
        }
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            if state.holds.contains_key(hold_id) {
                return Err(invalid("legal hold id already exists"));
            }
            if ids.iter().any(|id| {
                !state.evidence.contains_key(id)
                    || state.deletions.contains_key(id)
                    || state.deletion_pending(id)
            }) {
                return Err(invalid("legal hold references unknown evidence"));
            }
            vault.append_event_locked(
                "LEGAL_HOLD_PLACED",
                json!({
                    "schema": LEGAL_HOLD_SCHEMA_V2,
                    "hold_id": hold_id,
                    "evidence_ids": ids,
                    "authority_ref": authority_ref,
                    "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
                    "reason_digest": reason_digest
                }),
                recorded_at,
            )
        })
    }

    pub fn release_legal_hold(
        &self,
        hold_id: &str,
        authority_ref: &str,
        release_reason_digest: &str,
        recorded_at: &str,
    ) -> Result<Value> {
        identifier(authority_ref, "authority_ref")?;
        sha256_digest(release_reason_digest, "release_reason_digest")?;
        instant(recorded_at)?;
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            let hold = state
                .holds
                .get(hold_id)
                .filter(|hold| !hold.released)
                .ok_or_else(|| invalid("legal hold is absent or already released"))?;
            vault.append_event_locked(
                "LEGAL_HOLD_RELEASED",
                json!({
                    "schema": LEGAL_HOLD_RELEASE_SCHEMA_V2,
                    "hold_id": hold_id,
                    "authority_ref": authority_ref,
                    "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
                    "release_reason_digest": release_reason_digest,
                    "placed_event_root": hold.placed_event_root
                }),
                recorded_at,
            )
        })
    }

    pub fn retention_decision(&self, evidence_id: &str, evaluated_at: &str) -> Result<Value> {
        let state = self.replay()?;
        self.retention_decision_from_state(&state, evidence_id, evaluated_at)
    }

    fn retention_decision_from_state(
        &self,
        state: &VaultState,
        evidence_id: &str,
        evaluated_at: &str,
    ) -> Result<Value> {
        let at = instant(evaluated_at)?;
        let record = state
            .evidence
            .get(evidence_id)
            .ok_or_else(|| invalid("evidence id is unknown"))?;
        let body = &record.body;
        let active_hold_ids = state
            .holds
            .iter()
            .filter(|(_, hold)| {
                !hold.released && hold.evidence_ids.iter().any(|id| id == evidence_id)
            })
            .map(|(hold_id, _)| Value::String(hold_id.clone()))
            .collect::<Vec<_>>();
        let status = if state.deletions.contains_key(evidence_id) {
            "DELETED"
        } else if state.deletion_pending(evidence_id) {
            "DELETION_IN_PROGRESS"
        } else if !active_hold_ids.is_empty() {
            "LEGAL_HOLD"
        } else if at < instant(field_str(body, "minimum_retain_until")?)? {
            "RETAIN_REQUIRED"
        } else if at >= instant(field_str(body, "deletion_required_by")?)? {
            "DELETION_REQUIRED"
        } else {
            "DELETION_ELIGIBLE"
        };
        Ok(json!({
            "schema": "AuditSpec-evidence-vault-retention-decision-v1",
            "evidence_id": evidence_id,
            "evaluated_at": evaluated_at,
            "status": status,
            "active_hold_ids": active_hold_ids,
            "minimum_retain_until": field(body, "minimum_retain_until")?.clone(),
            "deletion_required_by": field(body, "deletion_required_by")?.clone()
        }))
    }

    pub fn delete_evidence(
        &self,
        evidence_id: &str,
        deleted_at: &str,
        deletion_basis: &str,
        authority_ref: &str,
    ) -> Result<Value> {
        instant(deleted_at)?;
        identifier(authority_ref, "authority_ref")?;
        if !["policy_deadline", "permitted_disposal"].contains(&deletion_basis) {
            return Err(invalid("deletion basis is invalid"));
        }
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            let decision = vault.retention_decision_from_state(&state, evidence_id, deleted_at)?;
            let expected = if deletion_basis == "policy_deadline" {
                "DELETION_REQUIRED"
            } else {
                "DELETION_ELIGIBLE"
            };
            if field_str(&decision, "status")? != expected {
                return Err(invalid("retention or legal hold prevents deletion"));
            }
            let record = &state
                .evidence
                .get(evidence_id)
                .ok_or_else(|| invalid("evidence id is unknown"))?
                .body;
            let object_ref = field(record, "object_ref")?;
            let object_sha = field_str(object_ref, "sha256")?;
            let (other_live, component_refs) = vault.object_retention_references_from_state(
                &state,
                object_sha,
                Some(evidence_id),
            )?;
            let physical_delete_required = other_live.is_empty() && component_refs.is_empty();
            let object_path = vault.object_path(object_sha)?;
            if physical_delete_required {
                let metadata = fs::symlink_metadata(&object_path)
                    .map_err(|_| invalid("evidence object is already unavailable"))?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(invalid("evidence object is already unavailable"));
                }
            }
            let intent = vault.append_event_locked(
                "EVIDENCE_DELETION_INTENT",
                json!({
                    "schema": DELETION_INTENT_SCHEMA_V3,
                    "evidence_id": evidence_id,
                    "deleted_at": deleted_at,
                    "object_sha256": object_sha,
                    "deletion_basis": deletion_basis,
                    "authority_ref": authority_ref,
                    "authority_semantics": AUTHORITY_ATTRIBUTION_SEMANTICS,
                    "retention_decision": decision,
                    "physical_delete_required": physical_delete_required,
                    "retained_by_live_evidence_ids": other_live,
                    "retained_by_component_refs": component_refs
                }),
                deleted_at,
            )?;
            if physical_delete_required {
                fs::remove_file(&object_path)?;
                sync_directory(
                    object_path
                        .parent()
                        .ok_or_else(|| invalid("evidence object parent is absent"))?,
                )?;
            }
            vault.append_event_locked(
                "EVIDENCE_DELETED",
                deletion_commit_body(&intent)?,
                deleted_at,
            )
        })
    }

    pub fn retire_component(
        &self,
        component_ref: &str,
        replacement_ref: Option<&str>,
        impacted_claim_ids: &[String],
        future_unsupported_claim_ids: &[String],
        recorded_at: &str,
    ) -> Result<Value> {
        instant(recorded_at)?;
        self.with_transaction(|vault| {
            let state = vault.replay()?;
            if !state.components.contains_key(component_ref) {
                return Err(invalid("retired component is unknown"));
            }
            if state.retirements.contains_key(component_ref) {
                return Err(invalid("component is already retired"));
            }
            if replacement_ref.is_some_and(|reference| !state.components.contains_key(reference)) {
                return Err(invalid("replacement component is unknown"));
            }
            if replacement_ref == Some(component_ref) {
                return Err(invalid("replacement component must differ"));
            }
            if let Some(reference) = replacement_ref {
                if state.retirements.contains_key(reference) {
                    return Err(invalid("replacement component is retired"));
                }
                if field_str(&state.components[reference].body, "kind")?
                    != field_str(&state.components[component_ref].body, "kind")?
                {
                    return Err(invalid("replacement component has wrong kind"));
                }
            }
            let mut impacted = impacted_claim_ids.to_vec();
            impacted.sort();
            impacted.dedup();
            let mut unsupported = future_unsupported_claim_ids.to_vec();
            unsupported.sort();
            unsupported.dedup();
            let archive_object_ref =
                field(&state.components[component_ref].body, "object_ref")?.clone();
            vault.append_event_locked(
                "COMPONENT_RETIRED",
                json!({
                    "schema": RETIREMENT_SCHEMA_V2,
                    "component_ref": component_ref,
                    "replacement_ref": replacement_ref,
                    "impacted_claim_ids": impacted,
                    "future_unsupported_claim_ids": unsupported,
                    "archive_object_ref": archive_object_ref,
                    "existing_contracts_reverify_before_retirement": true,
                    "future_capture_policy": "reject_retired_reference",
                    "retired_at": recorded_at
                }),
                recorded_at,
            )
        })
    }

    pub fn retrieve_for_audit(&self, bundle_id: &str, audited_at: &str) -> Result<AuditRetrieval> {
        instant(audited_at)?;
        let state = self.replay()?;
        let bundle = state
            .bundles
            .get(bundle_id)
            .ok_or_else(|| invalid("bundle id is unknown"))?;
        let rows = field(&bundle.body, "evidence")?;
        if digest(BUNDLE_SCHEMA, rows)? != field_str(&bundle.body, "bundle_root")? {
            return Err(invalid("bundle root does not recompute"));
        }
        let mut gaps = Vec::new();
        let mut material = BTreeMap::new();
        for row in array(rows)? {
            let evidence_id = field_str(row, "evidence_id")?;
            let record = state
                .evidence
                .get(evidence_id)
                .ok_or_else(|| invalid("bundle evidence binding differs"))?;
            if record.event_root != field_str(row, "evidence_event_root")? {
                return Err(invalid("bundle evidence binding differs"));
            }
            let evidence = &record.body;
            if let Some(deletion) = state.deletions.get(evidence_id) {
                let subtype = if field_str(&deletion.body, "deletion_basis")? == "policy_deadline" {
                    "LEGAL_DELETION_PREVENTS_REVERIFY"
                } else {
                    "EVIDENCE_UNAVAILABLE"
                };
                gaps.push(gap(subtype, evidence_id));
                continue;
            }
            if state.deletion_pending(evidence_id) {
                gaps.push(gap("DELETION_TRANSITION_INCOMPLETE", evidence_id));
                continue;
            }
            let object_ref = field(evidence, "object_ref")?;
            let object_sha = field_str(object_ref, "sha256")?;
            let object_path = self.object_path(object_sha)?;
            let metadata = fs::symlink_metadata(&object_path);
            if metadata
                .as_ref()
                .map(|meta| !meta.is_file() || meta.file_type().is_symlink())
                .unwrap_or(true)
            {
                gaps.push(gap("RETENTION_NONCOMPLIANCE", evidence_id));
                continue;
            }
            let data = fs::read(&object_path)?;
            if raw_sha256(&data) != object_sha {
                gaps.push(gap("EVIDENCE_INTEGRITY_FAILURE", evidence_id));
                continue;
            }
            let retention = self.retention_decision_from_state(&state, evidence_id, audited_at)?;
            if field_str(&retention, "status")? == "DELETION_REQUIRED" {
                gaps.push(gap("RETENTION_NONCOMPLIANCE", evidence_id));
            }
            self.check_component_dependencies(
                evidence,
                &state,
                audited_at,
                evidence_id,
                &mut gaps,
            )?;
            material.insert(evidence_id.to_owned(), data);
        }
        gaps = deduplicate_gaps(gaps)?;
        let assurance = self.assurance(Some(&state))?;
        let mut record = json!({
            "schema": RETRIEVAL_SCHEMA,
            "vault_id": self.vault_id()?,
            "bundle_id": bundle_id,
            "bundle_root": field(&bundle.body, "bundle_root")?.clone(),
            "audited_at": audited_at,
            "status": if gaps.is_empty() {"READY_FOR_REVERIFICATION"} else {"LIFECYCLE_GAP"},
            "primary_failure": gaps.first().cloned(),
            "additional_detected_failures": if gaps.len() > 1 {gaps[1..].to_vec()} else {Vec::new()},
            "retrieved_evidence_ids": material.keys().cloned().collect::<Vec<_>>(),
            "retrieved_evidence_count": material.len(),
            "journal_event_count": state.event_count,
            "vault_root": state.vault_root,
            "vault_authentication_status": field(&assurance, "status")?.clone(),
            "vault_authentication_scope": field(&assurance, "authentication_scope")?.clone(),
            "vault_rollback_protection": field(&assurance, "rollback_protection")?.clone(),
            "external_pin_names": field(&assurance, "external_pin_names")?.clone(),
            "remaining_unproven": ["capture_truth", "open_world_inventory_completeness"]
        });
        let proof = digest(RETRIEVAL_SCHEMA, &record)?;
        object_mut(&mut record)?.insert("proof_digest".to_owned(), Value::String(proof));
        Ok(AuditRetrieval {
            record,
            evidence_bytes: material,
        })
    }

    pub fn reverify_json_predicate(
        &self,
        bundle_id: &str,
        claim_id: &str,
        audited_at: &str,
    ) -> Result<Value> {
        let retrieval = self.retrieve_for_audit(bundle_id, audited_at)?;
        let base = json!({
            "schema": REVERIFY_SCHEMA,
            "vault_id": self.vault_id()?,
            "bundle_id": bundle_id,
            "claim_id": claim_id,
            "audited_at": audited_at,
            "retrieval_proof_digest": field(&retrieval.record, "proof_digest")?.clone(),
            "vault_authentication_status": field(&retrieval.record, "vault_authentication_status")?.clone(),
            "vault_authentication_scope": field(&retrieval.record, "vault_authentication_scope")?.clone(),
            "vault_rollback_protection": field(&retrieval.record, "vault_rollback_protection")?.clone(),
            "external_pin_names": field(&retrieval.record, "external_pin_names")?.clone()
        });
        if field_str(&retrieval.record, "status")? != "READY_FOR_REVERIFICATION" {
            let mut body = object(&base)?.clone();
            body.extend(object(&json!({
                "status": "LIFECYCLE_GAP",
                "verdict": "LIFECYCLE_GAP",
                "claim_value": null,
                "primary_failure": field(&retrieval.record, "primary_failure")?.clone(),
                "additional_detected_failures": field(&retrieval.record, "additional_detected_failures")?.clone()
            }))?.clone());
            return with_proof(REVERIFY_SCHEMA, Value::Object(body));
        }
        let state = self.replay()?;
        let mut records = Vec::new();
        for evidence_id in string_array(field(&retrieval.record, "retrieved_evidence_ids")?)? {
            let body = &state.evidence[&evidence_id].body;
            if field_str(body, "claim_id")? == claim_id {
                records.push(body);
            }
        }
        if records.is_empty() {
            let mut body = object(&base)?.clone();
            body.extend(
                object(&json!({
                    "status": "INVENTORY_GAP",
                    "verdict": "INVENTORY_GAP",
                    "claim_value": null,
                    "primary_failure": {
                        "subtype": "CLAIM_EVIDENCE_ABSENT",
                        "claim_id": claim_id
                    },
                    "additional_detected_failures": []
                }))?
                .clone(),
            );
            return with_proof(REVERIFY_SCHEMA, Value::Object(body));
        }
        let verifier_refs = records
            .iter()
            .map(|record| field_str(record, "verifier_ref").map(ToOwned::to_owned))
            .collect::<Result<BTreeSet<_>>>()?;
        if verifier_refs.len() != 1 {
            return Err(invalid("claim evidence has multiple verifier archives"));
        }
        let verifier_ref = verifier_refs.iter().next().expect("one verifier").clone();
        let verifier = self.component_content(&state, &verifier_ref)?;
        let spec = strict_json_loads(
            std::str::from_utf8(&verifier)
                .map_err(|_| invalid("archived verifier is not UTF-8 JSON"))?,
        )?;
        exact_keys(&spec, &["predicate", "schema"], "archived verifier")?;
        if field_str(&spec, "schema")? != "AuditSpec-vault-json-predicate-verifier-v1" {
            return Err(invalid(
                "archived verifier is not executable json predicate v1",
            ));
        }
        let mut values = Map::new();
        for record in records {
            let evidence_id = field_str(record, "evidence_id")?;
            let raw = &retrieval.evidence_bytes[evidence_id];
            let parsed = strict_json_loads(
                std::str::from_utf8(raw).map_err(|_| invalid("evidence JSON is not UTF-8"))?,
            )?;
            for (key, value) in object(&parsed)? {
                if values.insert(key.clone(), value.clone()).is_some() {
                    return Err(invalid("evidence JSON projection is invalid or ambiguous"));
                }
            }
        }
        let values_value = Value::Object(values);
        let claim_value = predicate::evaluate_bool(field(&spec, "predicate")?, &values_value)?;
        let mut body = object(&base)?.clone();
        body.extend(object(&json!({
            "status": "REVERIFIED_AT_AUDIT_TIME",
            "verdict": if claim_value {"SUPPORTED"} else {"REFUTED"},
            "claim_value": claim_value,
            "primary_failure": null,
            "additional_detected_failures": [],
            "verifier_ref": verifier_ref,
            "evidence_value_root": digest("AuditSpec-evidence-vault-reverified-values-v1", &values_value)?
        }))?.clone());
        with_proof(REVERIFY_SCHEMA, Value::Object(body))
    }

    pub fn replay(&self) -> Result<VaultState> {
        let initial_public_key_hex = self.initial_public_key_hex()?.to_owned();
        let mut active_public_key_hex = initial_public_key_hex.clone();
        let mut public_key_history = vec![initial_public_key_hex.clone()];
        let mut journal_authority_rotations = Vec::new();
        let mut paths = fs::read_dir(self.root.join("events"))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        let mut events = Vec::new();
        let mut previous: Option<String> = None;
        for (index, path) in paths.iter().enumerate() {
            let sequence = index + 1;
            let metadata = fs::symlink_metadata(path)?;
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid("vault event filename is not UTF-8"))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || !filename.starts_with(&format!("{sequence:020}-"))
            {
                return Err(invalid("vault event filename sequence is invalid"));
            }
            let event = strict_json_loads(&fs::read_to_string(path)?)?;
            let public = verifying_key(&active_public_key_hex)?;
            verify_event(
                &event,
                &public,
                sequence,
                previous.as_deref(),
                self.vault_id()?,
                &active_public_key_hex,
            )?;
            let event_root = field_str(&event, "event_root")?.to_owned();
            if filename != format!("{sequence:020}-{event_root}.json") {
                return Err(invalid("vault event filename/root mismatch"));
            }
            previous = Some(event_root);
            if field_str(&event, "event_type")? == "JOURNAL_AUTHORITY_ROTATED" {
                let successor = validate_journal_authority_rotation(
                    field(&event, "body")?,
                    &active_public_key_hex,
                    &public_key_history,
                )?;
                journal_authority_rotations.push(json!({
                    "sequence": sequence,
                    "event_root": field(&event, "event_root")?.clone(),
                    "recorded_at": field(&event, "recorded_at")?.clone(),
                    "predecessor_public_key_hex": active_public_key_hex,
                    "successor_public_key_hex": successor,
                    "reason_digest": field(field(&event, "body")?, "reason_digest")?.clone()
                }));
                public_key_history.push(successor.clone());
                active_public_key_hex = successor;
            }
            events.push(event);
        }
        let mut state = VaultState {
            components: BTreeMap::new(),
            evidence: BTreeMap::new(),
            bundles: BTreeMap::new(),
            holds: BTreeMap::new(),
            deletion_intents: BTreeMap::new(),
            deletions: BTreeMap::new(),
            retirements: BTreeMap::new(),
            event_count: events.len(),
            vault_root: previous.clone().unwrap_or_else(|| {
                field_str(&self.manifest, "manifest_root")
                    .unwrap()
                    .to_owned()
            }),
            initial_public_key_hex,
            active_public_key_hex,
            public_key_history,
            journal_authority_rotations,
        };
        for event in events {
            let event_type = field_str(&event, "event_type")?;
            let body = field(&event, "body")?.clone();
            let event_root = field_str(&event, "event_root")?.to_owned();
            let row = EventRecord {
                body: body.clone(),
                event_root: event_root.clone(),
            };
            match event_type {
                "COMPONENT_ARCHIVED" => insert_once(
                    &mut state.components,
                    field_str(&body, "component_ref")?.to_owned(),
                    row,
                )?,
                "EVIDENCE_APPENDED" => insert_once(
                    &mut state.evidence,
                    field_str(&body, "evidence_id")?.to_owned(),
                    row,
                )?,
                "BUNDLE_SEALED" => insert_once(
                    &mut state.bundles,
                    field_str(&body, "bundle_id")?.to_owned(),
                    row,
                )?,
                "LEGAL_HOLD_PLACED" => {
                    let hold_id = field_str(&body, "hold_id")?.to_owned();
                    if state.holds.contains_key(&hold_id) {
                        return Err(invalid("append-only journal contains duplicate identity"));
                    }
                    state.holds.insert(
                        hold_id,
                        HoldRecord {
                            evidence_ids: string_array(field(&body, "evidence_ids")?)?,
                            released: false,
                            placed_event_root: event_root,
                        },
                    );
                }
                "LEGAL_HOLD_RELEASED" => {
                    let hold = state
                        .holds
                        .get_mut(field_str(&body, "hold_id")?)
                        .filter(|hold| !hold.released)
                        .ok_or_else(|| {
                            invalid("legal-hold release journal transition is invalid")
                        })?;
                    hold.released = true;
                }
                "EVIDENCE_DELETION_INTENT" => {
                    let evidence_id = field_str(&body, "evidence_id")?.to_owned();
                    if !state.evidence.contains_key(&evidence_id)
                        || state.deletions.contains_key(&evidence_id)
                    {
                        return Err(invalid("deletion-intent journal transition is invalid"));
                    }
                    insert_once(&mut state.deletion_intents, evidence_id, row)?;
                }
                "EVIDENCE_DELETED" => {
                    let evidence_id = field_str(&body, "evidence_id")?.to_owned();
                    if !state.evidence.contains_key(&evidence_id) {
                        return Err(invalid("deletion journal references unknown evidence"));
                    }
                    if object(&body)?.contains_key("intent_event_root") {
                        let intent_root = field_str(&body, "intent_event_root")?;
                        let intent = state
                            .deletion_intents
                            .get(&evidence_id)
                            .filter(|intent| intent.event_root == intent_root)
                            .ok_or_else(|| {
                                invalid("deletion commit does not match signed intent")
                            })?;
                        if body
                            != deletion_commit_body(&json!({
                                "body": intent.body.clone(),
                                "event_root": intent.event_root.clone()
                            }))?
                        {
                            return Err(invalid("deletion commit does not match signed intent"));
                        }
                    }
                    insert_once(&mut state.deletions, evidence_id, row)?;
                }
                "COMPONENT_RETIRED" => {
                    let component_ref = field_str(&body, "component_ref")?.to_owned();
                    if !state.components.contains_key(&component_ref) {
                        return Err(invalid("retirement journal references unknown component"));
                    }
                    validate_retirement(&body, &state.components)?;
                    insert_once(&mut state.retirements, component_ref, row)?;
                }
                "JOURNAL_AUTHORITY_ROTATED" => {}
                _ => return Err(invalid("vault event type is unknown")),
            }
        }
        Ok(state)
    }

    fn check_component_dependencies(
        &self,
        evidence: &Value,
        state: &VaultState,
        audited_at: &str,
        evidence_id: &str,
        gaps: &mut Vec<Value>,
    ) -> Result<()> {
        for (field_name, subtype) in [
            ("schema_ref", "UNREADABLE_SCHEMA"),
            ("key_ref", "HISTORIC_KEY_UNRESOLVED"),
            ("verifier_ref", "VERIFIER_UNAVAILABLE"),
            ("policy_ref", "VERSION_ROOT_UNRESOLVED"),
        ] {
            let reference = field_str(evidence, field_name)?;
            let Some(component) = state.components.get(reference) else {
                gaps.push(gap(subtype, evidence_id));
                continue;
            };
            if !self.component_object_available(&component.body)? {
                gaps.push(gap(subtype, evidence_id));
                continue;
            }
            let metadata = field(&component.body, "metadata")?;
            if field_name == "schema_ref"
                && (field(metadata, "readable").ok().and_then(Value::as_bool) != Some(true)
                    || field_str(metadata, "migration_mode").ok() == Some("lossy"))
            {
                gaps.push(gap(
                    if field_str(metadata, "migration_mode").ok() == Some("lossy") {
                        "LOSSY_SCHEMA_MIGRATION"
                    } else {
                        subtype
                    },
                    evidence_id,
                ));
            } else {
                let metadata_invalid = (field_name == "verifier_ref"
                    && field(metadata, "archive_executable")
                        .ok()
                        .and_then(Value::as_bool)
                        != Some(true))
                    || (field_name == "key_ref"
                        && !historic_key_valid(metadata, field_str(evidence, "captured_at")?)?);
                if metadata_invalid {
                    gaps.push(gap(subtype, evidence_id));
                }
            }
        }
        let scope = field(evidence, "world_scope")?;
        if field_str(scope, "type")? == "externally_bridged_world" {
            let bridge_ref = field_str(scope, "bridge_ref")?;
            let Some(component) = state.components.get(bridge_ref) else {
                gaps.push(gap("BRIDGE_UNRESOLVED", evidence_id));
                return Ok(());
            };
            if !self.component_object_available(&component.body)? {
                gaps.push(gap("BRIDGE_UNRESOLVED", evidence_id));
            } else if !bridge_valid(field(&component.body, "metadata")?, audited_at)? {
                gaps.push(gap("BRIDGE_EXPIRED_OR_REVOKED", evidence_id));
            }
        }
        Ok(())
    }

    fn component_object_available(&self, component: &Value) -> Result<bool> {
        let reference = field(component, "object_ref")?;
        let sha = field_str(reference, "sha256")?;
        let path = self.object_path(sha)?;
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return Ok(false);
        };
        Ok(metadata.is_file()
            && !metadata.file_type().is_symlink()
            && raw_sha256(&fs::read(path)?) == sha)
    }

    fn require_capture_eligible_component(
        &self,
        state: &VaultState,
        component_ref: &str,
        claim_id: &str,
        field_name: &str,
    ) -> Result<()> {
        let Some(retirement) = state.retirements.get(component_ref) else {
            return Ok(());
        };
        let body = &retirement.body;
        let unsupported = string_array(field(body, "future_unsupported_claim_ids")?)?
            .iter()
            .any(|value| value == claim_id);
        let detail = if unsupported {
            "future claim is explicitly unsupported".to_owned()
        } else if let Some(replacement) = optional_str(field(body, "replacement_ref")?)? {
            format!("use replacement {replacement}")
        } else {
            "no replacement".to_owned()
        };
        Err(invalid(format!(
            "{field_name} references retired component ({detail})"
        )))
    }

    fn object_retention_references_from_state(
        &self,
        state: &VaultState,
        object_sha: &str,
        excluding_evidence_id: Option<&str>,
    ) -> Result<(Vec<String>, Vec<String>)> {
        sha256_digest(object_sha, "object sha256")?;
        let mut evidence_ids = Vec::new();
        for (evidence_id, evidence) in &state.evidence {
            if excluding_evidence_id == Some(evidence_id.as_str())
                || state.deletions.contains_key(evidence_id)
                || state.deletion_pending(evidence_id)
            {
                continue;
            }
            if field_str(field(&evidence.body, "object_ref")?, "sha256")? == object_sha {
                evidence_ids.push(evidence_id.clone());
            }
        }
        let mut component_refs = Vec::new();
        for (component_ref, component) in &state.components {
            if field_str(field(&component.body, "object_ref")?, "sha256")? == object_sha {
                component_refs.push(component_ref.clone());
            }
        }
        Ok((evidence_ids, component_refs))
    }

    fn component_content(&self, state: &VaultState, component_ref: &str) -> Result<Vec<u8>> {
        let component = state
            .components
            .get(component_ref)
            .ok_or_else(|| invalid("archived component object is unavailable"))?;
        if !self.component_object_available(&component.body)? {
            return Err(invalid("archived component object is unavailable"));
        }
        let sha = field_str(field(&component.body, "object_ref")?, "sha256")?;
        Ok(fs::read(self.object_path(sha)?)?)
    }

    fn put_object(&self, content: &[u8], media_type_value: &str) -> Result<Value> {
        if self.signer.is_none() {
            return Err(invalid("read-only vault cannot append objects"));
        }
        media_type(media_type_value)?;
        let sha = raw_sha256(content);
        let target = self.object_path(&sha)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        if target.exists() {
            let metadata = fs::symlink_metadata(&target)?;
            if metadata.file_type().is_symlink() || raw_sha256(&fs::read(&target)?) != sha {
                return Err(invalid("content-addressed object collision or corruption"));
            }
        } else {
            let mut temporary = tempfile::NamedTempFile::new_in(self.root.join("tmp"))?;
            temporary.write_all(content)?;
            temporary.as_file().sync_all()?;
            match fs::hard_link(temporary.path(), &target) {
                Ok(()) => {
                    sync_directory(
                        target
                            .parent()
                            .ok_or_else(|| invalid("object parent is absent"))?,
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if raw_sha256(&fs::read(&target)?) != sha {
                        return Err(invalid("content-addressed object race mismatch"));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(json!({
            "schema": OBJECT_SCHEMA,
            "sha256": sha,
            "size_bytes": content.len(),
            "media_type": media_type_value
        }))
    }

    fn with_lock<T>(&self, action: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .read(true)
            .open(self.root.join(".lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let result = action(self);
        let unlock = fs2::FileExt::unlock(&lock);
        match (result, unlock) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn with_transaction<T>(&self, action: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        if self.signer.is_none() {
            return Err(invalid("read-only vault cannot mutate"));
        }
        self.with_lock(|vault| {
            vault.recover_locked()?;
            action(vault)
        })
    }

    fn recover_locked(&self) -> Result<()> {
        if self.signer.is_none() {
            return Ok(());
        }
        let state = self.replay()?;
        let pending = state
            .deletion_intents
            .iter()
            .filter(|(evidence_id, _)| !state.deletions.contains_key(*evidence_id))
            .map(|(_, intent)| intent.clone())
            .collect::<Vec<_>>();
        for intent in pending {
            let body = &intent.body;
            let deleted_at = field_str(body, "deleted_at")?.to_owned();
            let (evidence_ids, component_refs) = self.object_retention_references_from_state(
                &state,
                field_str(body, "object_sha256")?,
                Some(field_str(body, "evidence_id")?),
            )?;
            if field(body, "physical_delete_required")?.as_bool() == Some(true)
                && (!evidence_ids.is_empty() || !component_refs.is_empty())
            {
                return Err(invalid(
                    "pending deletion conflicts with live object references",
                ));
            }
            if field(body, "physical_delete_required")?.as_bool() == Some(true) {
                let path = self.object_path(field_str(body, "object_sha256")?)?;
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        if !metadata.is_file() || metadata.file_type().is_symlink() {
                            return Err(invalid("pending deletion object path is unsafe"));
                        }
                        fs::remove_file(&path)?;
                        sync_directory(
                            path.parent()
                                .ok_or_else(|| invalid("evidence object parent is absent"))?,
                        )?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let intent_value = json!({
                "body": intent.body,
                "event_root": intent.event_root
            });
            self.append_event_locked(
                "EVIDENCE_DELETED",
                deletion_commit_body(&intent_value)?,
                &deleted_at,
            )?;
        }

        let state = self.replay()?;
        let object_root = self.root.join("objects/sha256");
        for prefix in fs::read_dir(&object_root)? {
            let prefix = prefix?;
            let prefix_metadata = prefix.file_type()?;
            if !prefix_metadata.is_dir() || prefix_metadata.is_symlink() {
                return Err(invalid("vault object prefix path is unsafe"));
            }
            let prefix_name = prefix
                .file_name()
                .to_str()
                .ok_or_else(|| invalid("vault object prefix is not UTF-8"))?
                .to_owned();
            for object in fs::read_dir(prefix.path())? {
                let object = object?;
                let metadata = object.file_type()?;
                if !metadata.is_file() || metadata.is_symlink() {
                    return Err(invalid("vault object path is unsafe"));
                }
                let name = object
                    .file_name()
                    .to_str()
                    .ok_or_else(|| invalid("vault object name is not UTF-8"))?
                    .to_owned();
                let sha = format!("{prefix_name}{name}");
                sha256_digest(&sha, "object sha256")?;
                let (evidence_ids, component_refs) =
                    self.object_retention_references_from_state(&state, &sha, None)?;
                if evidence_ids.is_empty() && component_refs.is_empty() {
                    fs::remove_file(object.path())?;
                    sync_directory(&prefix.path())?;
                }
            }
        }
        Ok(())
    }

    fn append_event_locked(
        &self,
        event_type: &str,
        body: Value,
        recorded_at: &str,
    ) -> Result<Value> {
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| invalid("read-only vault cannot append events"))?;
        instant(recorded_at)?;
        canonical_bytes(&body)?;
        let state = self.replay()?;
        if signer.public_key_hex() != state.active_public_key_hex {
            return Err(invalid(
                "vault signer does not match active journal authority",
            ));
        }
        let sequence = state.event_count + 1;
        let payload = json!({
            "schema": EVENT_SCHEMA,
            "vault_id": self.vault_id()?,
            "sequence": sequence,
            "previous_event_root": if state.event_count == 0 {Value::Null} else {Value::String(state.vault_root)},
            "event_type": event_type,
            "recorded_at": recorded_at,
            "body": body
        });
        let event_root = digest(EVENT_SCHEMA, &payload)?;
        let mut event = object(&payload)?.clone();
        event.insert("event_root".to_owned(), Value::String(event_root.clone()));
        event.insert(
            "signature".to_owned(),
            json!({
                "algorithm": "ed25519",
                "public_key_hex": state.active_public_key_hex,
                "signature_hex": signer.sign_root(&event_root)?
            }),
        );
        let value = Value::Object(event);
        exclusive_write(
            &self
                .root
                .join("events")
                .join(format!("{sequence:020}-{event_root}.json")),
            &json_line(&value)?,
            0o644,
        )?;
        Ok(value)
    }

    fn verify_manifest_pins(&self) -> Result<()> {
        for (actual, pinned, label) in [
            (
                self.vault_id()?,
                self.trust_pins.expected_vault_id.as_deref(),
                "vault id",
            ),
            (
                self.manifest_root()?,
                self.trust_pins.expected_manifest_root.as_deref(),
                "manifest root",
            ),
            (
                self.initial_public_key_hex()?,
                self.trust_pins.expected_public_key_hex.as_deref(),
                "initial public key",
            ),
        ] {
            if pinned.is_some_and(|expected| actual != expected) {
                return Err(invalid(format!("external {label} pin mismatch")));
            }
        }
        Ok(())
    }

    fn verify_vault_root_pin(&self, state: &VaultState) -> Result<()> {
        if self
            .trust_pins
            .expected_vault_root
            .as_deref()
            .is_some_and(|expected| state.vault_root != expected)
        {
            return Err(invalid("external vault root pin mismatch"));
        }
        Ok(())
    }

    fn object_path(&self, sha: &str) -> Result<PathBuf> {
        sha256_digest(sha, "object sha256")?;
        Ok(self
            .root
            .join("objects")
            .join("sha256")
            .join(&sha[..2])
            .join(&sha[2..]))
    }
}

fn load_manifest(root: &Path) -> Result<Value> {
    let path = root.join("vault.json");
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| invalid("vault manifest is absent or unsafe"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("vault manifest is absent or unsafe"));
    }
    let manifest = strict_json_loads(&fs::read_to_string(path)?)?;
    exact_keys(
        &manifest,
        &[
            "created_at",
            "event_schema",
            "hash_algorithm",
            "manifest_root",
            "object_addressing",
            "private_key_persisted",
            "public_key_hex",
            "schema",
            "signature_algorithm",
            "vault_id",
        ],
        "vault manifest",
    )?;
    let mut body = object(&manifest)?.clone();
    body.remove("manifest_root");
    if field_str(&manifest, "schema")? != VAULT_SCHEMA
        || field_str(&manifest, "hash_algorithm")? != "sha256"
        || field_str(&manifest, "signature_algorithm")? != "ed25519"
        || field_str(&manifest, "event_schema")? != EVENT_SCHEMA
        || field_str(&manifest, "object_addressing")? != "sha256_raw_bytes"
        || field(&manifest, "private_key_persisted")?.as_bool() != Some(false)
        || field_str(&manifest, "manifest_root")? != digest(VAULT_SCHEMA, &Value::Object(body))?
    {
        return Err(invalid("vault manifest identity/root mismatch"));
    }
    identifier(field_str(&manifest, "vault_id")?, "vault_id")?;
    instant(field_str(&manifest, "created_at")?)?;
    verifying_key(field_str(&manifest, "public_key_hex")?)?;
    Ok(manifest)
}

fn deletion_commit_body(intent: &Value) -> Result<Value> {
    let body = field(intent, "body")?;
    let schema = field_str(body, "schema")?;
    let (keys, tombstone_schema) = match schema {
        DELETION_INTENT_SCHEMA_V1 => (
            vec![
                "authority_ref",
                "deleted_at",
                "deletion_basis",
                "evidence_id",
                "object_sha256",
                "physical_delete_required",
                "retained_by_live_evidence_ids",
                "retention_decision",
                "schema",
            ],
            DELETION_TOMBSTONE_SCHEMA_V1,
        ),
        DELETION_INTENT_SCHEMA_V2 => (
            vec![
                "authority_ref",
                "deleted_at",
                "deletion_basis",
                "evidence_id",
                "object_sha256",
                "physical_delete_required",
                "retained_by_component_refs",
                "retained_by_live_evidence_ids",
                "retention_decision",
                "schema",
            ],
            DELETION_TOMBSTONE_SCHEMA_V2,
        ),
        DELETION_INTENT_SCHEMA_V3 => (
            vec![
                "authority_ref",
                "authority_semantics",
                "deleted_at",
                "deletion_basis",
                "evidence_id",
                "object_sha256",
                "physical_delete_required",
                "retained_by_component_refs",
                "retained_by_live_evidence_ids",
                "retention_decision",
                "schema",
            ],
            DELETION_TOMBSTONE_SCHEMA_V3,
        ),
        _ => return Err(invalid("deletion intent schema mismatch")),
    };
    exact_keys(body, &keys, "deletion intent body")?;
    if schema == DELETION_INTENT_SCHEMA_V3
        && field_str(body, "authority_semantics")? != AUTHORITY_ATTRIBUTION_SEMANTICS
    {
        return Err(invalid("deletion authority semantics mismatch"));
    }
    let mut tombstone = json!({
        "schema": tombstone_schema,
        "evidence_id": field(body, "evidence_id")?.clone(),
        "object_sha256": field(body, "object_sha256")?.clone(),
        "deletion_basis": field(body, "deletion_basis")?.clone(),
        "authority_ref": field(body, "authority_ref")?.clone(),
        "retention_decision": field(body, "retention_decision")?.clone(),
        "physical_deleted": field(body, "physical_delete_required")?.clone(),
        "retained_by_live_evidence_ids": field(body, "retained_by_live_evidence_ids")?.clone(),
        "intent_event_root": field(intent, "event_root")?.clone()
    });
    if [DELETION_INTENT_SCHEMA_V2, DELETION_INTENT_SCHEMA_V3].contains(&schema) {
        object_mut(&mut tombstone)?.insert(
            "retained_by_component_refs".to_owned(),
            field(body, "retained_by_component_refs")?.clone(),
        );
    }
    if schema == DELETION_INTENT_SCHEMA_V3 {
        object_mut(&mut tombstone)?.insert(
            "authority_semantics".to_owned(),
            field(body, "authority_semantics")?.clone(),
        );
    }
    Ok(tombstone)
}

fn verify_event(
    event: &Value,
    public: &VerifyingKey,
    sequence: usize,
    previous: Option<&str>,
    expected_vault_id: &str,
    expected_public_key_hex: &str,
) -> Result<()> {
    exact_keys(
        event,
        &[
            "body",
            "event_root",
            "event_type",
            "previous_event_root",
            "recorded_at",
            "schema",
            "sequence",
            "signature",
            "vault_id",
        ],
        "vault event",
    )?;
    let mut payload = object(event)?.clone();
    payload.remove("event_root");
    payload.remove("signature");
    let expected_previous = previous.map_or(Value::Null, |value| Value::String(value.to_owned()));
    if field_str(event, "schema")? != EVENT_SCHEMA
        || field(event, "sequence")?.as_u64() != Some(sequence as u64)
        || field(event, "previous_event_root")? != &expected_previous
        || field_str(event, "vault_id")? != expected_vault_id
        || field_str(event, "event_root")? != digest(EVENT_SCHEMA, &Value::Object(payload))?
    {
        return Err(invalid("vault event chain/root mismatch"));
    }
    instant(field_str(event, "recorded_at")?)?;
    let signature = field(event, "signature")?;
    exact_keys(
        signature,
        &["algorithm", "public_key_hex", "signature_hex"],
        "vault event signature",
    )?;
    if field_str(signature, "algorithm")? != "ed25519"
        || field_str(signature, "public_key_hex")? != expected_public_key_hex
    {
        return Err(invalid("vault event signature record mismatch"));
    }
    let raw = hex::decode(field_str(signature, "signature_hex")?)
        .map_err(|_| invalid("vault event signature invalid"))?;
    let raw: [u8; 64] = raw
        .try_into()
        .map_err(|_| invalid("vault event signature invalid"))?;
    public
        .verify(
            &signature_message(field_str(event, "event_root")?)?,
            &Signature::from_bytes(&raw),
        )
        .map_err(|_| invalid("vault event signature invalid"))
}

fn validate_journal_authority_rotation(
    body: &Value,
    predecessor_public_key_hex: &str,
    public_key_history: &[String],
) -> Result<String> {
    exact_keys(
        body,
        &[
            "predecessor_public_key_hex",
            "reason_digest",
            "schema",
            "successor_public_key_hex",
        ],
        "journal authority rotation body",
    )?;
    if field_str(body, "schema")? != JOURNAL_AUTHORITY_ROTATION_SCHEMA
        || field_str(body, "predecessor_public_key_hex")? != predecessor_public_key_hex
    {
        return Err(invalid("journal authority rotation predecessor mismatch"));
    }
    let successor = field_str(body, "successor_public_key_hex")?.to_owned();
    verifying_key(&successor)?;
    sha256_digest(
        field_str(body, "reason_digest")?,
        "journal authority rotation reason_digest",
    )?;
    if public_key_history.iter().any(|value| value == &successor) {
        return Err(invalid("journal authority rotation reuses a prior key"));
    }
    Ok(successor)
}

fn validate_retirement(body: &Value, components: &BTreeMap<String, EventRecord>) -> Result<()> {
    let schema = field_str(body, "schema")?;
    let mut keys = vec![
        "archive_object_ref",
        "component_ref",
        "existing_contracts_reverify_before_retirement",
        "future_unsupported_claim_ids",
        "impacted_claim_ids",
        "replacement_ref",
        "schema",
    ];
    match schema {
        "AuditSpec-evidence-vault-retirement-certificate-v1" => {}
        RETIREMENT_SCHEMA_V2 => {
            keys.extend(["future_capture_policy", "retired_at"]);
            if field_str(body, "future_capture_policy")? != "reject_retired_reference" {
                return Err(invalid("retirement future-capture policy mismatch"));
            }
            instant(field_str(body, "retired_at")?)?;
        }
        _ => return Err(invalid("retirement certificate schema mismatch")),
    }
    exact_keys(body, &keys, "retirement certificate body")?;
    let component_ref = field_str(body, "component_ref")?;
    if let Some(replacement_ref) = optional_str(field(body, "replacement_ref")?)? {
        let component = components
            .get(component_ref)
            .ok_or_else(|| invalid("retirement replacement is invalid"))?;
        let replacement = components
            .get(replacement_ref)
            .ok_or_else(|| invalid("retirement replacement is invalid"))?;
        if replacement_ref == component_ref
            || field_str(&component.body, "kind")? != field_str(&replacement.body, "kind")?
        {
            return Err(invalid("retirement replacement is invalid"));
        }
    }
    if field(body, "existing_contracts_reverify_before_retirement")?.as_bool() != Some(true) {
        return Err(invalid(
            "retirement historical-verification policy mismatch",
        ));
    }
    for field_name in ["impacted_claim_ids", "future_unsupported_claim_ids"] {
        let values = string_array(field(body, field_name)?)?;
        let canonical = values.iter().cloned().collect::<BTreeSet<_>>();
        if values != canonical.into_iter().collect::<Vec<_>>() {
            return Err(invalid("retirement claim ids are not canonical"));
        }
        for value in values {
            identifier(&value, field_name)?;
        }
    }
    Ok(())
}

fn signature_message(event_root: &str) -> Result<Vec<u8>> {
    sha256_digest(event_root, "event_root")?;
    let mut message = b"AuditSpec-evidence-vault-event-signature-v1\0".to_vec();
    message.extend(hex::decode(event_root).map_err(|_| invalid("event_root is not hexadecimal"))?);
    Ok(message)
}

fn historic_key_valid(metadata: &Value, captured_at: &str) -> Result<bool> {
    if exact_keys(
        metadata,
        &[
            "compromise_effective_from",
            "revocation_kind",
            "revoked_at",
            "valid_from",
            "valid_until",
        ],
        "historic key metadata",
    )
    .is_err()
    {
        return Ok(false);
    }
    let captured = instant(captured_at)?;
    if captured < instant(field_str(metadata, "valid_from")?)? {
        return Ok(false);
    }
    if let Some(valid_until) = optional_str(field(metadata, "valid_until")?)? {
        if captured > instant(valid_until)? {
            return Ok(false);
        }
    }
    let revocation = optional_str(field(metadata, "revocation_kind")?)?;
    if ![None, Some("routine"), Some("retroactive_compromise")].contains(&revocation) {
        return Ok(false);
    }
    let revoked_at = optional_str(field(metadata, "revoked_at")?)?;
    if revocation.is_none() {
        return Ok(revoked_at.is_none() && field(metadata, "compromise_effective_from")?.is_null());
    }
    let Some(revoked_at) = revoked_at else {
        return Ok(false);
    };
    let revoked = instant(revoked_at)?;
    if revocation == Some("routine") {
        return Ok(field(metadata, "compromise_effective_from")?.is_null() && captured < revoked);
    }
    if revocation == Some("retroactive_compromise") {
        let Some(effective) = optional_str(field(metadata, "compromise_effective_from")?)? else {
            return Ok(false);
        };
        let effective = instant(effective)?;
        return Ok(effective <= revoked && captured < effective);
    }
    Ok(false)
}

fn bridge_valid(metadata: &Value, audited_at: &str) -> Result<bool> {
    if exact_keys(
        metadata,
        &["mode", "revoked_at", "valid_from", "valid_until"],
        "bridge metadata",
    )
    .is_err()
    {
        return Ok(false);
    }
    if !["complete_mediation", "external_inventory"].contains(&field_str(metadata, "mode")?) {
        return Ok(false);
    }
    let at = instant(audited_at)?;
    if at < instant(field_str(metadata, "valid_from")?)? {
        return Ok(false);
    }
    if let Some(valid_until) = optional_str(field(metadata, "valid_until")?)? {
        if at > instant(valid_until)? {
            return Ok(false);
        }
    }
    Ok(match optional_str(field(metadata, "revoked_at")?)? {
        None => true,
        Some(revoked_at) => at < instant(revoked_at)?,
    })
}

fn validate_world_scope(value: &Value, components: &BTreeMap<String, EventRecord>) -> Result<()> {
    match field_str(value, "type")? {
        "declared_closed_world" => {
            exact_keys(
                value,
                &["scope_commitment", "type", "universe_root"],
                "declared closed-world scope",
            )?;
            sha256_digest(field_str(value, "scope_commitment")?, "scope commitment")?;
            sha256_digest(field_str(value, "universe_root")?, "universe root")?;
        }
        "externally_bridged_world" => {
            exact_keys(
                value,
                &["bridge_ref", "scope_commitment", "type"],
                "externally bridged scope",
            )?;
            sha256_digest(field_str(value, "scope_commitment")?, "scope commitment")?;
            let bridge = components
                .get(field_str(value, "bridge_ref")?)
                .ok_or_else(|| invalid("world scope bridge reference is unresolved"))?;
            if field_str(&bridge.body, "kind")? != "bridge" {
                return Err(invalid("world scope bridge reference is unresolved"));
            }
        }
        _ => return Err(invalid("world scope is invalid")),
    }
    Ok(())
}

fn with_proof(schema: &str, mut body: Value) -> Result<Value> {
    let proof = digest(schema, &body)?;
    object_mut(&mut body)?.insert("proof_digest".to_owned(), Value::String(proof));
    Ok(body)
}

fn gap(subtype: &str, evidence_id: &str) -> Value {
    json!({"subtype": subtype, "evidence_id": evidence_id})
}

fn deduplicate_gaps(gaps: Vec<Value>) -> Result<Vec<Value>> {
    let priority = BTreeMap::from([
        ("EVIDENCE_INTEGRITY_FAILURE", 0),
        ("HISTORIC_KEY_UNRESOLVED", 1),
        ("UNREADABLE_SCHEMA", 2),
        ("LOSSY_SCHEMA_MIGRATION", 3),
        ("VERIFIER_UNAVAILABLE", 4),
        ("VERSION_ROOT_UNRESOLVED", 5),
        ("BRIDGE_UNRESOLVED", 6),
        ("BRIDGE_EXPIRED_OR_REVOKED", 7),
        ("RETENTION_NONCOMPLIANCE", 8),
        ("LEGAL_DELETION_PREVENTS_REVERIFY", 9),
        ("EVIDENCE_UNAVAILABLE", 10),
    ]);
    let mut unique = BTreeMap::new();
    for row in gaps {
        let key = (
            field_str(&row, "subtype")?.to_owned(),
            field_str(&row, "evidence_id")?.to_owned(),
        );
        unique.insert(key, row);
    }
    let mut rows = unique.into_values().collect::<Vec<_>>();
    rows.sort_by_key(|row| {
        (
            priority
                .get(field_str(row, "subtype").unwrap_or(""))
                .copied()
                .unwrap_or(99),
            field_str(row, "evidence_id").unwrap_or("").to_owned(),
        )
    });
    Ok(rows)
}

fn insert_once<T>(target: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if target.insert(key, value).is_some() {
        return Err(invalid("append-only journal contains duplicate identity"));
    }
    Ok(())
}

fn exclusive_write(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("exclusive-write parent is absent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new().read(true).open(path)?.sync_all()?;
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn instant(value: &str) -> Result<DateTime<FixedOffset>> {
    if !value.ends_with('Z') {
        return Err(invalid("timestamp must be an RFC3339 UTC string"));
    }
    let parsed =
        DateTime::parse_from_rfc3339(value).map_err(|_| invalid("timestamp is invalid"))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(invalid("timestamp is not UTC"));
    }
    Ok(parsed)
}

fn identifier(value: &str, label: &str) -> Result<()> {
    let regex = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
        .map_err(|_| invalid("identifier validator failed"))?;
    if !regex.is_match(value) {
        return Err(invalid(format!("{label} is invalid")));
    }
    Ok(())
}

fn sha256_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn media_type(value: &str) -> Result<()> {
    let regex = Regex::new(r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")
        .map_err(|_| invalid("media-type validator failed"))?;
    if value.len() > 127 || !regex.is_match(value) {
        return Err(invalid("media type is invalid"));
    }
    Ok(())
}

fn verifying_key(value: &str) -> Result<VerifyingKey> {
    let raw = hex::decode(value).map_err(|_| invalid("vault public key is invalid"))?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| invalid("vault public key is invalid"))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| invalid("vault public key is invalid"))
}

fn exact_keys(value: &Value, required: &[&str], label: &str) -> Result<()> {
    let actual = object(value)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = required.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(invalid(format!("{label} keys mismatch")));
    }
    Ok(())
}

fn require_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} must be a mapping")))
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("JSON value must be an object"))
}

fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| invalid("JSON value must be an object"))
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| invalid("JSON value must be an array"))
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    object(value)?
        .get(name)
        .ok_or_else(|| invalid(format!("JSON field is absent: {name}")))
}

fn field_str<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| invalid(format!("JSON field is not a string: {name}")))
}

fn optional_str(value: &Value) -> Result<Option<&str>> {
    if value.is_null() {
        Ok(None)
    } else {
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid("JSON optional value is not a string or null"))
    }
}

fn string_array(value: &Value) -> Result<Vec<String>> {
    array(value)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("JSON array item is not a string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: &str = "2026-01-01T00:00:00Z";
    const T1: &str = "2027-01-01T00:00:00Z";
    const T2: &str = "2028-01-01T00:00:00Z";
    const T3: &str = "2030-01-01T00:00:00Z";

    fn fixed_signer() -> VaultSigner {
        VaultSigner::from_bytes(&[9_u8; 32]).unwrap()
    }

    #[test]
    fn v1_deletion_intent_remains_readable() {
        let intent = json!({
            "event_root": "a".repeat(64),
            "body": {
                "schema": DELETION_INTENT_SCHEMA_V1,
                "evidence_id": "evidence.legacy.1",
                "deleted_at": T2,
                "object_sha256": "b".repeat(64),
                "deletion_basis": "permitted_disposal",
                "authority_ref": "custody.authority.1",
                "retention_decision": {"status": "DELETION_ELIGIBLE"},
                "physical_delete_required": true,
                "retained_by_live_evidence_ids": []
            }
        });
        let tombstone = deletion_commit_body(&intent).unwrap();
        assert_eq!(tombstone["schema"], DELETION_TOMBSTONE_SCHEMA_V1);
        assert!(tombstone.get("retained_by_component_refs").is_none());
    }

    #[test]
    fn pending_deletion_fails_closed_and_writable_reopen_recovers() {
        let temporary = tempfile::TempDir::new().unwrap();
        let root = temporary.path().join("vault");
        let vault = EvidenceVault::create(&root, "vault.recovery", T0, fixed_signer()).unwrap();
        vault
            .archive_component(
                "schema",
                "evidence",
                "1",
                br#"{"type":"object"}"#,
                "application/json",
                json!({"readable": true, "migration_mode": "lossless"}),
                T0,
            )
            .unwrap();
        vault
            .archive_component(
                "verifier",
                "predicate",
                "1",
                br#"{"schema":"AuditSpec-vault-json-predicate-verifier-v1","predicate":{"op":"const","value":true}}"#,
                "application/json",
                json!({"archive_executable": true}),
                T0,
            )
            .unwrap();
        vault
            .archive_component(
                "key",
                "producer",
                "1",
                b"historic-key",
                "application/octet-stream",
                json!({
                    "valid_from": "2025-01-01T00:00:00Z",
                    "valid_until": T1,
                    "revoked_at": T1,
                    "revocation_kind": "routine",
                    "compromise_effective_from": null
                }),
                T0,
            )
            .unwrap();
        vault
            .archive_component(
                "policy",
                "retention",
                "1",
                b"policy",
                "text/plain",
                json!({"archived": true}),
                T0,
            )
            .unwrap();
        vault
            .append_evidence(
                "evidence.1",
                "claim.1",
                "run.1",
                br#"{"value":true}"#,
                "application/json",
                "schema:evidence:1",
                "key:producer:1",
                "verifier:predicate:1",
                "policy:retention:1",
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
        vault
            .create_bundle("bundle.1", &["evidence.1".to_owned()], T0)
            .unwrap();

        let object_path = vault
            .with_transaction(|active| {
                let state = active.replay()?;
                let decision = active.retention_decision_from_state(&state, "evidence.1", T2)?;
                let object_sha = field_str(
                    field(&state.evidence["evidence.1"].body, "object_ref")?,
                    "sha256",
                )?
                .to_owned();
                active.append_event_locked(
                    "EVIDENCE_DELETION_INTENT",
                    json!({
                        "schema": "AuditSpec-evidence-vault-deletion-intent-v1",
                        "evidence_id": "evidence.1",
                        "deleted_at": T2,
                        "object_sha256": object_sha,
                        "deletion_basis": "permitted_disposal",
                        "authority_ref": "custody.1",
                        "retention_decision": decision,
                        "physical_delete_required": true,
                        "retained_by_live_evidence_ids": []
                    }),
                    T2,
                )?;
                let path = active.object_path(&object_sha)?;
                fs::remove_file(&path)?;
                sync_directory(path.parent().unwrap())?;
                Ok(path)
            })
            .unwrap();

        let read_only = EvidenceVault::open_read_only(&root).unwrap();
        assert!(read_only.replay().unwrap().deletion_pending("evidence.1"));
        let retrieval = read_only.retrieve_for_audit("bundle.1", T2).unwrap().record;
        assert_eq!(
            retrieval["primary_failure"]["subtype"],
            "DELETION_TRANSITION_INCOMPLETE"
        );

        let recovered = EvidenceVault::open_with_signer(&root, Some(fixed_signer())).unwrap();
        let recovered_state = recovered.replay().unwrap();
        assert!(!recovered_state.deletion_pending("evidence.1"));
        assert_eq!(recovered_state.deletion_count(), 1);
        assert!(!object_path.exists());
        let event_count = recovered_state.event_count;
        let reopened = EvidenceVault::open_with_signer(&root, Some(fixed_signer())).unwrap();
        assert_eq!(reopened.replay().unwrap().event_count, event_count);
    }
}
