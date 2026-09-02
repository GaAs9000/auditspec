# Information-order calculus

AuditSpec 1.3 adds a finite deterministic calculus for deciding what evidence
can prove, which catalog mechanisms are sufficient, and whether a lifecycle
transformation preserves a particular claim.

## Assurance boundary

Every result is relative to supplied finite tables:

- the declared worlds or source evidence states;
- the supplied claim values;
- the registered observation or transformation values;
- the frozen mechanism catalog, dependencies, admissibility flags, and costs.

The calculus does not prove that those tables exhaust reality, that the claim
is the correct legal or policy interpretation, or that captured values are
truthful.

## 1. Auditability quotient

For a claim q and evidence channel E, exact auditability exists precisely when
equal evidence never hides unequal claim values. **analyze_auditability**
returns either a decoder table or a constructive twin:

    from auditspec.core import (
        analyze_auditability,
        verify_auditability_certificate,
    )

    rows = [
        {
            "world_id": "w0",
            "world": {"approved": False},
            "claim_value": False,
            "evidence_value": {"approved": False},
        },
        {
            "world_id": "w1",
            "world": {"approved": True},
            "claim_value": True,
            "evidence_value": {"approved": True},
        },
    ]

    certificate = analyze_auditability(
        claim_id="claim.approved",
        evidence_id="evidence.approval",
        rows=rows,
    )
    assert certificate["status"] == "FACTORIZATION"
    assert verify_auditability_certificate(certificate)

The certificate records the world table, evidence and claim partitions,
decoder or twin, explicit finite-domain boundaries, and a canonical root.

## 2. Minimum contracts

**compile_minimum_contract** converts claim-critical pairs into an exact
weighted hitting-set problem. Each row supplies one observation for every
catalog mechanism:

    from auditspec.core import (
        compile_minimum_contract,
        verify_contract_certificate,
    )

    mechanisms = {
        "approval": {"cost": 4, "requires": [], "admissible": True},
        "packet": {"cost": 2, "requires": ["reader"], "admissible": True},
        "reader": {"cost": 3, "requires": [], "admissible": True},
    }
    rows = [
        {
            "world_id": "w0",
            "world": {"approved": False},
            "claim_value": False,
            "observations": {
                "approval": False,
                "packet": False,
                "reader": "reader-v1",
            },
        },
        {
            "world_id": "w1",
            "world": {"approved": True},
            "claim_value": True,
            "observations": {
                "approval": True,
                "packet": True,
                "reader": "reader-v1",
            },
        },
    ]

    contract = compile_minimum_contract(
        claim_id="claim.approved",
        rows=rows,
        mechanisms=mechanisms,
    )
    assert contract["selected"] == ["approval"]
    assert contract["selected_cost"] == 4
    assert verify_contract_certificate(contract)

A positive result separately records:

- a separator for every opposite-claim pair;
- a removal witness for every selected mechanism;
- exhaustive infeasibility of every lower-cost candidate.

If a critical pair has no admissible separator, the result is
**EVIDENCE_GAP**. If **state_cap** stops exact search first, the result is
**ANALYSIS_INCOMPLETE**; it is not promoted to non-existence.

## 3. Claim-relative lifecycle

The same globally lossy transformation can preserve one claim and destroy
another. The lifecycle analyzer checks whether the claim decoder is constant on
each transformation fiber:

    from auditspec.core import (
        analyze_lifecycle_transformation,
        make_migration_bundle,
        verify_migration_bundle,
    )

    def rows(field):
        result = []
        for approved in (False, True):
            for comment in (False, True):
                source = {"approved": approved, "comment": comment}
                result.append(
                    {
                        "state_id": f"s{int(approved)}{int(comment)}",
                        "source_evidence": source,
                        "transformed_evidence": {"approved": approved},
                        "claim_value": source[field],
                    }
                )
        return result

    approval = analyze_lifecycle_transformation(
        claim_id="claim.approved",
        transformation_id="drop-comment",
        rows=rows("approved"),
    )
    comment = analyze_lifecycle_transformation(
        claim_id="claim.comment",
        transformation_id="drop-comment",
        rows=rows("comment"),
    )

    assert approval["status"] == "PRESERVED"
    assert comment["status"] == "HARD_SEMANTIC_GAP"

    bundle = make_migration_bundle(
        transformation_id="drop-comment",
        certificates={
            "claim.approved": approval,
            "claim.comment": comment,
        },
    )
    assert verify_migration_bundle(
        bundle, claim_id="claim.approved"
    ) == approval

For a hard gap, every deterministic postprocessor still receives identical
values for the lifecycle twin. **no_posthoc_repair_certificate** records this
fact for concrete processors. **semantic_audit_horizon** checks that, without a
new execution-specific channel, semantic sufficiency is prefix-closed.

## Vault integration

Place the migration bundle in the archived schema metadata:

    metadata = {
        "readable": True,
        "migration_mode": "lossy",
        "claim_relative_migration": bundle,
    }

At re-verification, the Vault selects the certificate for the requested claim.
A preserved claim continues through the archived verifier. A lifecycle twin
returns **MIGRATION_CLAIM_INFORMATION_LOSS**. Missing verifier bytes are instead
a soft **VERIFIER_UNAVAILABLE** obstruction: restoring the legitimate verifier
can repair that condition, but cannot repair a hard lifecycle twin.

The Rust consumer verifies the same migration-bundle and lifecycle schemas
before applying them to Vault retrieval.
