# Five-minute end-to-end quickstart

Install the product and run the complete public example:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[all]'
python examples/end_to_end.py
```

The example performs one bounded chain:

1. loads the declared payment world and mechanism catalog;
2. compiles `settled_exactly_once` to a minimum catalog-relative contract;
3. installs the schema, producer key, verifier, and retention policy in a new
   Evidence Vault;
4. captures one JSON evidence record and seals a bundle;
5. reopens the Vault using caller-owned manifest/key pins; and
6. re-verifies the claim at audit time.

The terminal JSON should include:

```json
{
  "compiler_status": "PASSIVE_AUDITABLE",
  "vault_authentication_status": "EXTERNALLY_AUTHENTICATED",
  "audit_time_status": "REVERIFIED_AT_AUDIT_TIME",
  "verdict": "SUPPORTED"
}
```

This example demonstrates product wiring, not capture truth or open-world
completeness. Its final `remaining_unproven` list keeps those boundaries
machine-visible.

## Direct CLI use

Compile a contract:

```bash
auditctl examples/payment.yaml compile --query settled_exactly_once
```

Inspect a Vault without an external pin:

```bash
auditvault status --root /path/to/vault
```

This returns `SELF_CONSISTENT`. Authenticate the directory against a root
retained outside that directory:

```bash
auditvault status \
  --root /path/to/vault \
  --expected-vault-id vault.production \
  --expected-manifest-root "$EXPECTED_MANIFEST_ROOT"
```

This returns `EXTERNALLY_AUTHENTICATED` only after the supplied pin matches and
the complete signed journal replays.

