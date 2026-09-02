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

Run the complete compiler-to-audit-time example:

```bash
python examples/end_to_end.py
```

See [the five-minute quickstart](docs/QUICKSTART.md) for the resulting trust
status and direct CLI examples.

## What the compiler provides

- typed claim and mechanism specifications;
- finite-model evidence determinacy checks;
- information-order and claim-quotient certificates;
- dependency-closed least-cost contract synthesis inside a declared catalog;
- separation, deletion-minimality, and optimality witnesses;
- claim-relative lifecycle and migration certificates;
- hard semantic versus soft trust/interpretability obstruction classes;
- typed model, evidence, mediation, inventory, trust, and lifecycle gaps;
- an append-only Evidence Vault with signed events and content-addressed data;
- audit-time retrieval and re-verification;
- caller-owned Vault identity/root pins and journal-authority key rotation;
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

An unpinned Vault reports `SELF_CONSISTENT`. An initial-key-only check reports
`AUTHORITY_PINNED`; it does not authenticate manifest identity or freshness.
`EXTERNALLY_AUTHENTICATED` requires a caller-owned manifest or Vault-root pin,
and only a Vault-root pin provides rollback protection. `authority_ref` is
explicitly attribution metadata asserted by the Vault authority, not an
independently verified institution credential.

Detailed operational boundaries:

- [Threat model](docs/THREAT_MODEL.md)
- [Information-order calculus](docs/INFORMATION_ORDER.md)
- [Vault trust and lifecycle model](docs/VAULT_TRUST_MODEL.md)
- [Compatibility and Python/Rust parity](docs/COMPATIBILITY.md)
- [Release procedure](docs/RELEASING.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0.
