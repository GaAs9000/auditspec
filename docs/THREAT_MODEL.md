# Threat model and assurance boundary

AuditSpec protects bounded claims against ambiguity and lifecycle loss inside
declared inputs. It does not convert an authenticated record into a proof that
the record is true.

## In scope

- omission or substitution of required evidence inside a declared finite world;
- tampering with signed Vault events or content-addressed objects;
- event transplant between Vault identities;
- wrong-genesis directory substitution when the caller pins the manifest root;
- rollback or unacknowledged advancement when the caller pins the Vault root;
- expired, revoked, missing, unreadable, or retired dependencies;
- retention/deletion transitions, including crash recovery;
- exact refusal when the declared catalog cannot discharge an obligation.

## Required trust roots

- the supplied formal claim and finite world;
- the declared mechanism catalog, dependency graph, and cost objective;
- evidence producers and capture points named by the contract;
- the initial Vault key or manifest/root value retained outside the Vault;
- the host, filesystem, clock source, and key custody chosen by the deployer.

## Out of scope

- discovering every real-world path, asset, actor, or trust dependency;
- proving that a legal or policy statement was translated into the right claim;
- proving the semantic truth of producer-supplied evidence;
- protecting a private key on a compromised host;
- deriving trusted real-world time from an RFC3339 string;
- production PKI, HSM custody, transparency-log operation, or legal authority.

## Identity and directory replacement

A Vault opened without caller-owned expectations can establish only internal
consistency. `SELF_CONSISTENT` means the manifest, signed journal, and objects
agree with one another. It does not mean this is the Vault previously trusted by
the caller.

`AUTHORITY_PINNED` requires a caller-supplied initial public key. It authenticates
the signer for the events currently present, but it does not bind unsigned
manifest identity and does not prevent event rollback.

`EXTERNALLY_AUTHENTICATED` requires a caller-supplied manifest root or current
Vault root. A manifest-root pin authenticates the genesis manifest but not the
latest event frontier. A current Vault-root pin authenticates the exact snapshot
and detects both rollback and unacknowledged journal advancement. A descriptive
Vault id alone is rejected as an authentication input.

## Time

Journal sequence is cryptographically ordered. `recorded_at`, `captured_at`,
retention deadlines, and audit time are declared timestamps signed or consumed
by the Vault. They become trusted real-world time only when a deployment binds
them to an external time authority. Status output therefore reports
`DECLARED_BY_VAULT_AUTHORITY`.
