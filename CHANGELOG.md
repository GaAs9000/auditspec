# Changelog

## 1.2.0

- authenticate Vault genesis or exact snapshots with caller-owned pins;
- distinguish `SELF_CONSISTENT`, `AUTHORITY_PINNED`, and
  `EXTERNALLY_AUTHENTICATED` outcomes;
- add chained journal-authority key rotation;
- enforce retired components as historical-verification-only dependencies;
- make hold/deletion authority attribution machine-explicit;
- return a typed inventory gap for cross-claim bundle requests;
- ship adapter-registry attestations and runtime example specs inside wheels;
- pin Rust 1.85.0 and test reproducible wheel builds with `SOURCE_DATE_EPOCH`;
- add a compiler-to-audit-time quickstart and deployment trust documentation.

