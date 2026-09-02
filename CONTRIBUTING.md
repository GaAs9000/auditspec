# Contributing

Contributions to the AuditSpec compiler are welcome.

Before opening a pull request:

```bash
python -m pip install -e '.[all]'
python scripts/freeze_catalog.py
python scripts/run_public_ci.py
cargo fmt --all --manifest-path rust/auditspec/Cargo.toml -- --check
cargo test --locked --manifest-path rust/auditspec/Cargo.toml
cargo clippy --all-targets --locked --manifest-path rust/auditspec/Cargo.toml -- -D warnings
```

Keep assurance boundaries explicit. A new positive verdict must identify its
declared world, trust assumptions, verifier, and failure behavior. Do not turn
an authenticated statement into a claim that its semantic content is true.
