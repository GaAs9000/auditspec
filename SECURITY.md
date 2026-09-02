# Security Policy

Please report suspected vulnerabilities through GitHub's private vulnerability
reporting interface for this repository. Do not include private keys, access
tokens, customer data, or exploit payloads in a public issue.

AuditSpec is not a production security certification. Its trust and lifecycle
verdicts remain conditional on the configured roots, host boundary, adapters,
and declared world.

When validating a Vault obtained from storage or another party, supply a
manifest or Vault-root value retained outside that Vault. An unpinned
`SELF_CONSISTENT` result does not authenticate the directory's identity. A
key-only `AUTHORITY_PINNED` result authenticates the signer for present events,
not the manifest or snapshot freshness. See `docs/THREAT_MODEL.md` and
`docs/VAULT_TRUST_MODEL.md` before production deployment.
