use std::fs;
use std::path::{Path, PathBuf};

use auditspec::canonical::{canonical_json, digest, strict_json_loads};
use auditspec::trust::evaluate_institutional_responses;
use auditspec::vault::{
    EvidenceVault, VaultSigner, VaultTrustPins, load_private_key, write_new_private_key,
};
use auditspec::{AuditSpecError, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

#[derive(Parser)]
#[command(
    name = "auditspec",
    version,
    about = "AuditSpec System 1.1 Rust consumer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug)]
struct ExternalPins {
    #[arg(long)]
    expected_vault_id: Option<String>,
    #[arg(long)]
    expected_manifest_root: Option<String>,
    #[arg(long)]
    expected_public_key: Option<String>,
    #[arg(long)]
    expected_vault_root: Option<String>,
}

impl ExternalPins {
    fn into_vault_pins(self) -> VaultTrustPins {
        VaultTrustPins {
            expected_vault_id: self.expected_vault_id,
            expected_manifest_root: self.expected_manifest_root,
            expected_public_key_hex: self.expected_public_key,
            expected_vault_root: self.expected_vault_root,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    Canonicalize {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        domain: Option<String>,
    },
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    VaultInit {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        vault_id: String,
        #[arg(long)]
        created_at: String,
        #[arg(long)]
        private_key: PathBuf,
    },
    ArchiveComponent {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        component_id: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        content: PathBuf,
        #[arg(long)]
        media_type: String,
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        recorded_at: String,
    },
    AppendEvidence {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        evidence_id: String,
        #[arg(long)]
        claim_id: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        content: PathBuf,
        #[arg(long)]
        media_type: String,
        #[arg(long)]
        schema_ref: String,
        #[arg(long)]
        key_ref: String,
        #[arg(long)]
        verifier_ref: String,
        #[arg(long)]
        policy_ref: String,
        #[arg(long)]
        world_scope: PathBuf,
        #[arg(long)]
        captured_at: String,
        #[arg(long)]
        minimum_retain_until: String,
        #[arg(long)]
        deletion_required_by: String,
        #[arg(long)]
        recorded_at: String,
    },
    SealBundle {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        bundle_id: String,
        #[arg(long = "evidence-id", required = true)]
        evidence_ids: Vec<String>,
        #[arg(long)]
        recorded_at: String,
    },
    RotateJournalAuthority {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        successor_public_key: String,
        #[arg(long)]
        reason_digest: String,
        #[arg(long)]
        recorded_at: String,
    },
    PlaceHold {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        hold_id: String,
        #[arg(long = "evidence-id", required = true)]
        evidence_ids: Vec<String>,
        #[arg(long)]
        authority_ref: String,
        #[arg(long)]
        reason_digest: String,
        #[arg(long)]
        recorded_at: String,
    },
    ReleaseHold {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        hold_id: String,
        #[arg(long)]
        authority_ref: String,
        #[arg(long)]
        release_reason_digest: String,
        #[arg(long)]
        recorded_at: String,
    },
    RetentionDecision {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        evidence_id: String,
        #[arg(long)]
        evaluated_at: String,
        #[command(flatten)]
        pins: ExternalPins,
    },
    DeleteEvidence {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        evidence_id: String,
        #[arg(long)]
        deleted_at: String,
        #[arg(long)]
        deletion_basis: String,
        #[arg(long)]
        authority_ref: String,
    },
    RetireComponent {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        component_ref: String,
        #[arg(long)]
        replacement_ref: Option<String>,
        #[arg(long = "impacted-claim-id")]
        impacted_claim_ids: Vec<String>,
        #[arg(long = "future-unsupported-claim-id")]
        future_unsupported_claim_ids: Vec<String>,
        #[arg(long)]
        recorded_at: String,
    },
    Retrieve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        bundle_id: String,
        #[arg(long)]
        audited_at: String,
        #[command(flatten)]
        pins: ExternalPins,
    },
    ReverifyJson {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        bundle_id: String,
        #[arg(long)]
        claim_id: String,
        #[arg(long)]
        audited_at: String,
        #[command(flatten)]
        pins: ExternalPins,
    },
    Status {
        #[arg(long)]
        root: PathBuf,
        #[command(flatten)]
        pins: ExternalPins,
    },
    TrustEvaluate {
        #[arg(long)]
        request_set: PathBuf,
        #[arg(long = "response")]
        responses: Vec<PathBuf>,
        #[arg(long = "institution-root")]
        institution_roots: Vec<PathBuf>,
        #[arg(long)]
        onboarding_authority: Option<PathBuf>,
    },
}

fn main() {
    match execute(Cli::parse()) {
        Ok(value) => {
            println!(
                "{}",
                canonical_json(&value).expect("result is canonical JSON")
            );
        }
        Err(error) => {
            let value = json!({"status": "ERROR", "error": error.to_string()});
            println!(
                "{}",
                canonical_json(&value).expect("error is canonical JSON")
            );
            std::process::exit(2);
        }
    }
}

fn execute(cli: Cli) -> Result<Value> {
    match cli.command {
        Command::Canonicalize { input, domain } => {
            let value = json_file(&input)?;
            Ok(json!({
                "schema": "AuditSpec-rust-canonicalization-result-v1",
                "canonical_json": canonical_json(&value)?,
                "domain": domain,
                "digest": domain.as_deref().map(|name| digest(name, &value)).transpose()?
            }))
        }
        Command::Keygen { output } => {
            let signer = VaultSigner::generate();
            write_new_private_key(&output, &signer)?;
            Ok(json!({
                "status": "KEY_GENERATED",
                "path": absolute(&output)?.display().to_string(),
                "public_key_hex": signer.public_key_hex(),
                "file_mode": "0600"
            }))
        }
        Command::VaultInit {
            root,
            vault_id,
            created_at,
            private_key,
        } => {
            let vault = EvidenceVault::create(
                &root,
                &vault_id,
                &created_at,
                load_private_key(&private_key)?,
            )?;
            Ok(json!({
                "status": "VAULT_CREATED",
                "vault_id": vault.vault_id()?,
                "root": vault.root().display().to_string()
            }))
        }
        Command::ArchiveComponent {
            root,
            private_key,
            kind,
            component_id,
            version,
            content,
            media_type,
            metadata,
            recorded_at,
        } => writable(&root, &private_key)?.archive_component(
            &kind,
            &component_id,
            &version,
            &regular_bytes(&content)?,
            &media_type,
            json_file(&metadata)?,
            &recorded_at,
        ),
        Command::AppendEvidence {
            root,
            private_key,
            evidence_id,
            claim_id,
            run_id,
            content,
            media_type,
            schema_ref,
            key_ref,
            verifier_ref,
            policy_ref,
            world_scope,
            captured_at,
            minimum_retain_until,
            deletion_required_by,
            recorded_at,
        } => writable(&root, &private_key)?.append_evidence(
            &evidence_id,
            &claim_id,
            &run_id,
            &regular_bytes(&content)?,
            &media_type,
            &schema_ref,
            &key_ref,
            &verifier_ref,
            &policy_ref,
            json_file(&world_scope)?,
            &captured_at,
            &minimum_retain_until,
            &deletion_required_by,
            &recorded_at,
        ),
        Command::SealBundle {
            root,
            private_key,
            bundle_id,
            evidence_ids,
            recorded_at,
        } => writable(&root, &private_key)?.create_bundle(&bundle_id, &evidence_ids, &recorded_at),
        Command::RotateJournalAuthority {
            root,
            private_key,
            successor_public_key,
            reason_digest,
            recorded_at,
        } => writable(&root, &private_key)?.rotate_journal_authority(
            &successor_public_key,
            &reason_digest,
            &recorded_at,
        ),
        Command::PlaceHold {
            root,
            private_key,
            hold_id,
            evidence_ids,
            authority_ref,
            reason_digest,
            recorded_at,
        } => writable(&root, &private_key)?.place_legal_hold(
            &hold_id,
            &evidence_ids,
            &authority_ref,
            &reason_digest,
            &recorded_at,
        ),
        Command::ReleaseHold {
            root,
            private_key,
            hold_id,
            authority_ref,
            release_reason_digest,
            recorded_at,
        } => writable(&root, &private_key)?.release_legal_hold(
            &hold_id,
            &authority_ref,
            &release_reason_digest,
            &recorded_at,
        ),
        Command::RetentionDecision {
            root,
            evidence_id,
            evaluated_at,
            pins,
        } => EvidenceVault::open_read_only_with_pins(&root, pins.into_vault_pins())?
            .retention_decision(&evidence_id, &evaluated_at),
        Command::DeleteEvidence {
            root,
            private_key,
            evidence_id,
            deleted_at,
            deletion_basis,
            authority_ref,
        } => writable(&root, &private_key)?.delete_evidence(
            &evidence_id,
            &deleted_at,
            &deletion_basis,
            &authority_ref,
        ),
        Command::RetireComponent {
            root,
            private_key,
            component_ref,
            replacement_ref,
            impacted_claim_ids,
            future_unsupported_claim_ids,
            recorded_at,
        } => writable(&root, &private_key)?.retire_component(
            &component_ref,
            replacement_ref.as_deref(),
            &impacted_claim_ids,
            &future_unsupported_claim_ids,
            &recorded_at,
        ),
        Command::Retrieve {
            root,
            bundle_id,
            audited_at,
            pins,
        } => Ok(
            EvidenceVault::open_read_only_with_pins(&root, pins.into_vault_pins())?
                .retrieve_for_audit(&bundle_id, &audited_at)?
                .record,
        ),
        Command::ReverifyJson {
            root,
            bundle_id,
            claim_id,
            audited_at,
            pins,
        } => EvidenceVault::open_read_only_with_pins(&root, pins.into_vault_pins())?
            .reverify_json_predicate(&bundle_id, &claim_id, &audited_at),
        Command::Status { root, pins } => {
            let vault = EvidenceVault::open_read_only_with_pins(&root, pins.into_vault_pins())?;
            let state = vault.replay()?;
            let assurance = vault.assurance(Some(&state))?;
            Ok(json!({
                "status": assurance["status"],
                "integrity_status": assurance["integrity_status"],
                "authentication_scope": assurance["authentication_scope"],
                "rollback_protection": assurance["rollback_protection"],
                "external_pin_names": assurance["external_pin_names"],
                "vault_id": vault.vault_id()?,
                "manifest_root": vault.manifest_root()?,
                "event_count": state.event_count,
                "vault_root": state.vault_root,
                "initial_public_key_hex": state.initial_public_key_hex,
                "active_public_key_hex": state.active_public_key_hex,
                "journal_authority_rotation_count": state.journal_authority_rotations.len(),
                "time_assurance": "DECLARED_BY_VAULT_AUTHORITY",
                "component_count": state.component_count(),
                "evidence_count": state.evidence_count(),
                "bundle_count": state.bundle_count(),
                "active_hold_count": state.active_hold_count(),
                "deletion_count": state.deletion_count()
            }))
        }
        Command::TrustEvaluate {
            request_set,
            responses,
            institution_roots,
            onboarding_authority,
        } => {
            let request_set = json_file(&request_set)?;
            let responses = responses
                .iter()
                .map(|path| json_file(path))
                .collect::<Result<Vec<_>>>()?;
            let roots = institution_roots
                .iter()
                .map(|path| json_file(path))
                .collect::<Result<Vec<_>>>()?;
            let authority = onboarding_authority
                .as_ref()
                .map(|path| json_file(path))
                .transpose()?;
            evaluate_institutional_responses(&request_set, &responses, &roots, authority.as_ref())
        }
    }
}

fn writable(root: &Path, private_key: &Path) -> Result<EvidenceVault> {
    EvidenceVault::open_with_signer(root, Some(load_private_key(private_key)?))
}

fn regular_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AuditSpecError::Invalid(
            "input path must be a regular non-symlink file".to_owned(),
        ));
    }
    Ok(fs::read(path)?)
}

fn json_file(path: &Path) -> Result<Value> {
    let bytes = regular_bytes(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AuditSpecError::Invalid("JSON input is not valid UTF-8".to_owned()))?;
    strict_json_loads(text)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
