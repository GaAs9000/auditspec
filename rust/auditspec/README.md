# AuditSpec Rust consumer

This crate supplies a standalone binary for signed Evidence Vault custody,
audit-time JSON-predicate re-verification, retention and legal-hold operations,
two-stage deletion recovery, and fail-closed trust evaluation. It also verifies
Python-generated claim-relative lifecycle and migration certificates: a
preserved claim may continue through a globally lossy schema, while a lifecycle
twin terminates as a hard semantic gap.

## Build and test

```bash
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

## Minimal flow

```bash
auditspec keygen --output vault-authority.key
auditspec vault-init \
  --root vault \
  --vault-id example \
  --created-at 2026-01-01T00:00:00Z \
  --private-key vault-authority.key
auditspec status --root vault
```
