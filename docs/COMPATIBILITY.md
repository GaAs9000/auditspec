# Compatibility and public API policy

AuditSpec follows semantic versioning for the Python package and Rust CLI.

- Patch releases may add fields to command output and add backward-readable
  journal schemas, but do not silently strengthen an assurance status.
- New journal writers emit the latest schema. Readers retain explicit support
  for the prior deletion and retirement schemas covered by regression tests.
- A breaking command, input schema, or guarantee change requires a major version.
- Catalog-relative compilation results remain tied to the catalog version and
  are not portable across catalog changes without re-verification.

## Python/Rust feature parity

| Surface | Python | Rust |
|---|---:|---:|
| signed append-only Vault | yes | yes |
| caller-owned external pins | yes | yes |
| journal-authority key rotation | yes | yes |
| retirement blocks future capture | yes | yes |
| hold/deletion attribution semantics | yes | yes |
| audit-time JSON predicate verification | yes | yes |
| claim-relative migration enforcement | yes | yes |
| migration certificate verification | yes | yes |
| quotient and exact contract synthesis | yes | verification consumer |
| independent finite-world compiler | yes | consumer/verification path |

Both implementations use the same canonical JSON and domain-separated digest
rules. Language parity does not replace an independent semantic oracle; the
Python public tests also compare Vault behavior to a separate state model.
