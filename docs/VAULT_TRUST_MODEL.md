# Evidence Vault trust and lifecycle model

## Three distinct properties

| Property | Established by | Not established by |
|---|---|---|
| Internal integrity | manifest root, signed hash-chained events, CAS digests | evidence truth |
| Signing authority | caller-owned initial-key pin | manifest identity or event freshness |
| Vault genesis identity | caller-owned manifest-root pin | latest event frontier |
| Exact Vault snapshot | caller-owned Vault-root pin | later, unacknowledged events |
| Claim support | archived verifier over retained evidence in the declared world | open-world inventory completeness |

## Journal authority lifecycle

The manifest public key is the initial journal authority. The active authority
may authorize a successor with `rotate-journal-authority`. The rotation event is
signed by the predecessor; every later event must be signed by the successor.
Replay rejects skipped predecessors, reused keys, stale writers, or a broken
rotation chain.

Example:

```bash
auditvault rotate-journal-authority \
  --root /path/to/vault \
  --private-key /secure/current.key \
  --successor-public-key "$NEXT_PUBLIC_KEY_HEX" \
  --reason-digest "$ROTATION_REASON_SHA256" \
  --recorded-at 2028-01-01T00:00:00Z
```

The successor private key is never placed in the Vault. Algorithm migration,
HSM policy, and external timestamping remain deployment responsibilities.

## Authority references

`authority_ref` on legal-hold, hold-release, and deletion operations is
attribution metadata asserted by the Vault journal authority. It is not an
independently verified institutional credential. New events and tombstones carry
the machine-readable value:

```text
authority_semantics = attribution_metadata_asserted_by_vault_authority
```

Deployments that require separation of duties must enforce and attest that
policy outside this Vault API.

## Component retirement

Retirement is asymmetric:

- evidence captured before retirement remains eligible for historical
  re-verification while its archived dependencies survive;
- a retired schema, key, verifier, policy, or bridge cannot be referenced by a
  new evidence append;
- a replacement must exist, have the same component kind, and itself be active;
- `future_unsupported_claim_ids` remains explicit in the signed retirement
  certificate and is surfaced in a rejection reason.

This makes retirement an executable lifecycle restriction rather than a comment.

## Typed terminal outcomes

- `SUPPORTED` / `REFUTED`: the archived verifier executed over retained evidence;
- `LIFECYCLE_GAP`: required historical material is unavailable or invalid;
- `INVENTORY_GAP`: the requested claim has no evidence in the supplied bundle.

These terminals describe support under the supplied bundle and trust context;
they do not establish capture truth or open-world completeness.

## Claim-relative migrations

A schema can be globally lossy while remaining sufficient for a particular
claim. When schema metadata uses the lossy migration mode, the Vault accepts an
optional claim-relative migration bundle. The bundle binds one deterministic
transformation table to a lifecycle certificate for each named claim.

- **PRESERVED** means the claim decoder is constant on every transformation
  fiber, so audit-time verification may continue.
- **HARD_SEMANTIC_GAP** means the bundle carries two source states that the
  migration merges even though their claim values differ. Retrieval returns
  **MIGRATION_CLAIM_INFORMATION_LOSS**.
- an absent, malformed, or mismatched bundle fails closed as
  **MIGRATION_CERTIFICATE_INVALID**.

This certificate changes neither capture truth nor trust in the declared
transformation table. It establishes only the finite claim-relative
factorization encoded by that table. See
[the information-order calculus](INFORMATION_ORDER.md).

## Deployment checklist

- retain the manifest root outside the Vault directory; retain acknowledged
  Vault roots as well when rollback matters;
- publish or custody acknowledged Vault-root checkpoints when rollback matters;
- rotate the journal key before its custody or cryptoperiod expires;
- protect signing keys outside the Vault and restrict writable access;
- bind host time to the deployment's chosen trusted-time mechanism;
- document evidence-producer and Vault-authority roles separately;
- test restore, read-only replay, and audit-time verification before relying on a
  retention plan.
