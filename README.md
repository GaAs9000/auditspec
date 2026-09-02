# AuditSpec Compiler

AuditSpec is an open-source compiler and runtime verifier for bounded AI-agent
audit contracts. It starts from a typed claim, an explicit world model, a
mechanism catalog, and a trust policy. It either compiles a sufficient contract
or returns a typed gap explaining why the requested assurance is unavailable.

The repository contains the compiler/Agent implementation, its Rust consumer,
examples, and product tests.

## Install from source

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[all]'
```

Available commands:

```bash
auditctl --help
auditvault --help
```

## What the compiler provides

- typed claim and mechanism specifications;
- finite-model evidence determinacy checks;
- least-cost contract synthesis inside a declared catalog;
- typed model, evidence, mediation, inventory, trust, and lifecycle gaps;
- an append-only Evidence Vault with signed events and content-addressed data;
- audit-time retrieval and re-verification;
- Python and Rust consumers with shared canonical encodings.

## Verify the source tree

```bash
python scripts/freeze_catalog.py
python scripts/run_public_ci.py
cargo test --locked --manifest-path rust/auditspec/Cargo.toml
```

The GitHub workflows also build an isolated wheel consumer, run Rust formatting
and clippy, audit Python and Rust dependencies, and run CodeQL.

## Repository layout

```text
src/auditspec/       Python compiler, runtime verifier, and Vault
rust/auditspec/      Rust consumer and interoperability implementation
examples/            finite claim/mechanism packs and a consumer example
tests/               history-independent product tests
scripts/             catalog and consumer verification utilities
```

## Assurance boundary

AuditSpec is exact only inside the declared finite world, mechanism catalog,
dependency graph, trust roots, threat model, and cost objective. It does not
prove that an inventory exhausts reality, translate law into the correct formal
claim, establish production custody, or provide an open-world guarantee.

## License

Apache-2.0.
