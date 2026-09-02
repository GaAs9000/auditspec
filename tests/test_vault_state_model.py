from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from auditspec.core.canonical import raw_sha256
from auditspec.core.evidence_vault import EvidenceVault, EvidenceVaultError, VaultSigner
from tests.reference_models.vault_model import ModelError, VaultStateModel


T0 = "2026-01-01T00:00:00Z"
T1 = "2027-01-01T00:00:00Z"
T2 = "2028-01-01T00:00:00Z"
T3 = "2030-01-01T00:00:00Z"
TIMES = (T0, T1, T2, T3)
SCHEMA_BYTES = b'{"type":"object"}'
EVIDENCE_BYTES = b'{"settled_count":1}'
PREDICATE = {
    "op": "eq",
    "left": {"op": "field", "name": "settled_count"},
    "right": {"op": "const", "value": 1},
}


def _key_metadata() -> dict[str, object]:
    return {
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": T1,
        "revoked_at": T1,
        "revocation_kind": "routine",
        "compromise_effective_from": None,
    }


def _create_pair(root: Path) -> tuple[EvidenceVault, VaultSigner, VaultStateModel]:
    signer = VaultSigner.generate()
    vault = EvidenceVault.create(
        root, vault_id="vault.state-model", created_at=T0, signer=signer
    )
    model = VaultStateModel()
    verifier_bytes = json.dumps(
        {
            "schema": "AuditSpec-vault-json-predicate-verifier-v1",
            "predicate": PREDICATE,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    components = (
        (
            "schema",
            "payment-evidence",
            SCHEMA_BYTES,
            "application/json",
            {"readable": True, "migration_mode": "lossless"},
        ),
        (
            "verifier",
            "payment-predicate",
            verifier_bytes,
            "application/json",
            {"archive_executable": True},
        ),
        (
            "key",
            "producer-key",
            b"historical-public-key",
            "application/octet-stream",
            _key_metadata(),
        ),
        (
            "policy",
            "payment-policy",
            b"policy-v1",
            "text/plain",
            {"archived": True},
        ),
    )
    for kind, component_id, content, media_type, metadata in components:
        reference = f"{kind}:{component_id}:1"
        vault.archive_component(
            kind=kind,
            component_id=component_id,
            version="1",
            content=content,
            media_type=media_type,
            metadata=metadata,
            recorded_at=T0,
        )
        model.archive_component(
            reference=reference,
            kind=kind,
            content=content,
            metadata=metadata,
        )
    return vault, signer, model


def _create_reference_model() -> VaultStateModel:
    model = VaultStateModel()
    verifier_bytes = json.dumps(
        {
            "schema": "AuditSpec-vault-json-predicate-verifier-v1",
            "predicate": PREDICATE,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    for reference, kind, content, metadata in (
        (
            "schema:payment-evidence:1",
            "schema",
            SCHEMA_BYTES,
            {"readable": True, "migration_mode": "lossless"},
        ),
        (
            "verifier:payment-predicate:1",
            "verifier",
            verifier_bytes,
            {"archive_executable": True},
        ),
        ("key:producer-key:1", "key", b"historical-public-key", _key_metadata()),
        ("policy:payment-policy:1", "policy", b"policy-v1", {"archived": True}),
    ):
        model.archive_component(
            reference=reference, kind=kind, content=content, metadata=metadata
        )
    return model


def _model_append(
    model: VaultStateModel,
    *,
    evidence_id: str,
    content: bytes = EVIDENCE_BYTES,
    captured_at: str = T0,
    minimum_retain_until: str = T1,
    deletion_required_by: str = T3,
) -> None:
    model.append_evidence(
        evidence_id=evidence_id,
        claim_id="claim.payment.once",
        run_id=f"run.{evidence_id}",
        content=content,
        schema_ref="schema:payment-evidence:1",
        key_ref="key:producer-key:1",
        verifier_ref="verifier:payment-predicate:1",
        policy_ref="policy:payment-policy:1",
        bridge_ref=None,
        captured_at=captured_at,
        minimum_retain_until=minimum_retain_until,
        deletion_required_by=deletion_required_by,
    )


class VaultModelMachine(RuleBasedStateMachine):
    """Compare generated public operation sequences with an independent model."""

    def __init__(self) -> None:
        super().__init__()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "vault"
        self.vault, self.signer, self.model = _create_pair(self.root)

    def teardown(self) -> None:
        self.temporary.cleanup()

    @rule(slot=st.integers(min_value=0, max_value=2), alias_schema=st.booleans())
    def append_evidence(self, slot: int, alias_schema: bool) -> None:
        evidence_id = f"evidence.{slot}"
        if evidence_id in self.model.evidence:
            return
        content = SCHEMA_BYTES if alias_schema else EVIDENCE_BYTES
        self.vault.append_evidence(
            evidence_id=evidence_id,
            claim_id="claim.payment.once",
            run_id=f"run.{slot}",
            content=content,
            media_type="application/json",
            schema_ref="schema:payment-evidence:1",
            key_ref="key:producer-key:1",
            verifier_ref="verifier:payment-predicate:1",
            policy_ref="policy:payment-policy:1",
            world_scope={
                "type": "declared_closed_world",
                "scope_commitment": "1" * 64,
                "universe_root": "2" * 64,
            },
            captured_at=T0,
            minimum_retain_until=T1,
            deletion_required_by=T3,
            recorded_at=T0,
        )
        self.model.append_evidence(
            evidence_id=evidence_id,
            claim_id="claim.payment.once",
            run_id=f"run.{slot}",
            content=content,
            schema_ref="schema:payment-evidence:1",
            key_ref="key:producer-key:1",
            verifier_ref="verifier:payment-predicate:1",
            policy_ref="policy:payment-policy:1",
            bridge_ref=None,
            captured_at=T0,
            minimum_retain_until=T1,
            deletion_required_by=T3,
        )

    @rule(slot=st.integers(min_value=0, max_value=2))
    def seal_bundle(self, slot: int) -> None:
        evidence_id = f"evidence.{slot}"
        bundle_id = f"bundle.{slot}"
        if (
            evidence_id not in self.model.evidence
            or evidence_id in self.model.deletions
            or evidence_id in self.model.pending_deletions
            or bundle_id in self.model.bundles
        ):
            return
        self.vault.create_bundle(
            bundle_id=bundle_id, evidence_ids=[evidence_id], recorded_at=T0
        )
        self.model.seal_bundle(bundle_id=bundle_id, evidence_ids=(evidence_id,))

    @rule(slot=st.integers(min_value=0, max_value=2))
    def place_hold(self, slot: int) -> None:
        evidence_id = f"evidence.{slot}"
        hold_id = f"hold.{slot}"
        if (
            evidence_id not in self.model.evidence
            or evidence_id in self.model.deletions
            or evidence_id in self.model.pending_deletions
            or hold_id in self.model.holds
        ):
            return
        self.vault.place_legal_hold(
            hold_id=hold_id,
            evidence_ids=[evidence_id],
            authority_ref="legal.authority.1",
            reason_digest="3" * 64,
            recorded_at=T1,
        )
        self.model.place_hold(hold_id=hold_id, evidence_ids=(evidence_id,))

    @rule(slot=st.integers(min_value=0, max_value=2))
    def release_hold(self, slot: int) -> None:
        hold_id = f"hold.{slot}"
        hold = self.model.holds.get(hold_id)
        if hold is None or hold.released:
            return
        self.vault.release_legal_hold(
            hold_id=hold_id,
            authority_ref="legal.authority.1",
            release_reason_digest="4" * 64,
            recorded_at=T2,
        )
        self.model.release_hold(hold_id=hold_id)

    @rule(
        slot=st.integers(min_value=0, max_value=2),
        policy_deadline=st.booleans(),
    )
    def delete(self, slot: int, policy_deadline: bool) -> None:
        evidence_id = f"evidence.{slot}"
        if (
            evidence_id not in self.model.evidence
            or evidence_id in self.model.deletions
            or evidence_id in self.model.pending_deletions
        ):
            return
        basis = "policy_deadline" if policy_deadline else "permitted_disposal"
        deleted_at = T3 if policy_deadline else T2
        try:
            expected = self.model.delete(
                evidence_id=evidence_id,
                deleted_at=deleted_at,
                deletion_basis=basis,
            )
        except ModelError:
            try:
                self.vault.delete_evidence(
                    evidence_id=evidence_id,
                    deleted_at=deleted_at,
                    deletion_basis=basis,
                    authority_ref="custody.authority.1",
                )
            except EvidenceVaultError:
                return
            raise AssertionError("implementation accepted a model-invalid deletion")
        tombstone = self.vault.delete_evidence(
            evidence_id=evidence_id,
            deleted_at=deleted_at,
            deletion_basis=basis,
            authority_ref="custody.authority.1",
        )["body"]
        assert tombstone["physical_deleted"] is expected.physical_delete_required
        assert tuple(tombstone["retained_by_live_evidence_ids"]) == (
            expected.retained_by_evidence_ids
        )
        assert tuple(tombstone["retained_by_component_refs"]) == (
            expected.retained_by_component_refs
        )

    @rule(writable=st.booleans())
    def reopen(self, writable: bool) -> None:
        if writable:
            self.vault = EvidenceVault(self.root, signer=self.signer)
            self.model.recover()
        else:
            read_only = EvidenceVault.open_read_only(self.root)
            assert read_only.replay()["vault_root"] == self.vault.replay()["vault_root"]

    @rule(slot=st.integers(min_value=0, max_value=2), audit_time=st.sampled_from(TIMES))
    def retrieve(self, slot: int, audit_time: str) -> None:
        bundle_id = f"bundle.{slot}"
        if bundle_id not in self.model.bundles:
            return
        expected = self.model.retrieve(bundle_id=bundle_id, audited_at=audit_time)
        actual = self.vault.retrieve_for_audit(bundle_id, audited_at=audit_time).record
        assert actual["status"] == expected["status"]
        assert actual["primary_failure"] == expected["primary_failure"]
        assert actual["additional_detected_failures"] == expected[
            "additional_detected_failures"
        ]
        assert tuple(actual["retrieved_evidence_ids"]) == expected[
            "retrieved_evidence_ids"
        ]

    @invariant()
    def states_and_invariants_agree(self) -> None:
        state = self.vault.replay()
        assert set(state["components"]) == set(self.model.components)
        assert set(state["evidence"]) == set(self.model.evidence)
        assert set(state["bundles"]) == set(self.model.bundles)
        assert set(state["pending_deletions"]) == set(self.model.pending_deletions)
        assert set(state["deletions"]) == set(self.model.deletions)
        assert self.model.invariant_violations() == ()

        actual_holds = {
            hold_id: (frozenset(hold["evidence_ids"]), hold["released"])
            for hold_id, hold in state["holds"].items()
        }
        model_holds = {
            hold_id: (hold.evidence_ids, hold.released)
            for hold_id, hold in self.model.holds.items()
        }
        assert actual_holds == model_holds

        object_root = self.root / "objects" / "sha256"
        actual_objects = {
            f"{path.parent.name}{path.name}": path.read_bytes()
            for path in object_root.glob("*/*")
        }
        assert actual_objects == self.model.objects
        assert all(raw_sha256(content) == digest for digest, content in actual_objects.items())

        for evidence_id in self.model.evidence:
            for evaluated_at in TIMES:
                assert self.vault.retention_decision(
                    evidence_id, evaluated_at=evaluated_at
                )["status"] == self.model.retention_status(
                    evidence_id, evaluated_at=evaluated_at
                )


TestVaultModelMachine = VaultModelMachine.TestCase
TestVaultModelMachine.settings = settings(
    max_examples=60,
    stateful_step_count=35,
    deadline=None,
    derandomize=True,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _append_one_pair(
    vault: EvidenceVault,
    model: VaultStateModel,
    *,
    content: bytes = EVIDENCE_BYTES,
) -> None:
    vault.append_evidence(
        evidence_id="evidence.0",
        claim_id="claim.payment.once",
        run_id="run.0",
        content=content,
        media_type="application/json",
        schema_ref="schema:payment-evidence:1",
        key_ref="key:producer-key:1",
        verifier_ref="verifier:payment-predicate:1",
        policy_ref="policy:payment-policy:1",
        world_scope={
            "type": "declared_closed_world",
            "scope_commitment": "1" * 64,
            "universe_root": "2" * 64,
        },
        captured_at=T0,
        minimum_retain_until=T1,
        deletion_required_by=T3,
        recorded_at=T0,
    )
    model.append_evidence(
        evidence_id="evidence.0",
        claim_id="claim.payment.once",
        run_id="run.0",
        content=content,
        schema_ref="schema:payment-evidence:1",
        key_ref="key:producer-key:1",
        verifier_ref="verifier:payment-predicate:1",
        policy_ref="policy:payment-policy:1",
        bridge_ref=None,
        captured_at=T0,
        minimum_retain_until=T1,
        deletion_required_by=T3,
    )
    vault.create_bundle(
        bundle_id="bundle.0", evidence_ids=["evidence.0"], recorded_at=T0
    )
    model.seal_bundle(bundle_id="bundle.0", evidence_ids=("evidence.0",))


def _assert_retrieval_matches_model(
    vault: EvidenceVault, model: VaultStateModel, *, audited_at: str
) -> None:
    expected = model.retrieve(bundle_id="bundle.0", audited_at=audited_at)
    actual = vault.retrieve_for_audit("bundle.0", audited_at=audited_at).record
    assert actual["status"] == expected["status"]
    assert actual["primary_failure"] == expected["primary_failure"]


def test_bounded_crash_after_intent_before_object_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, signer, model = _create_pair(tmp_path / "vault")
    _append_one_pair(vault, model)
    object_sha = model.evidence["evidence.0"].object_sha256
    object_path = vault._object_path(object_sha)
    original_unlink = Path.unlink

    def crash_on_object_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == object_path:
            raise OSError("bounded crash after intent")
        original_unlink(path, *args, **kwargs)

    model.begin_delete(
        evidence_id="evidence.0",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", crash_on_object_unlink)
        with pytest.raises(OSError, match="bounded crash"):
            vault.delete_evidence(
                evidence_id="evidence.0",
                deleted_at=T2,
                deletion_basis="permitted_disposal",
                authority_ref="custody.authority.1",
            )
    assert object_path.is_file()
    _assert_retrieval_matches_model(
        EvidenceVault.open_read_only(vault.root), model, audited_at=T2
    )

    recovered = EvidenceVault(vault.root, signer=signer)
    model.recover()
    assert not object_path.exists()
    _assert_retrieval_matches_model(recovered, model, audited_at=T2)
    event_count = recovered.replay()["event_count"]
    assert EvidenceVault(vault.root, signer=signer).replay()["event_count"] == event_count


def test_bounded_crash_after_object_transition_before_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, signer, model = _create_pair(tmp_path / "vault")
    _append_one_pair(vault, model)
    object_sha = model.evidence["evidence.0"].object_sha256
    object_path = vault._object_path(object_sha)
    original_append = vault._append_event

    def crash_before_commit(
        event_type: str, body: object, *, recorded_at: str
    ) -> dict[str, object]:
        if event_type == "EVIDENCE_DELETED":
            raise OSError("bounded crash before commit")
        return original_append(event_type, body, recorded_at=recorded_at)

    model.begin_delete(
        evidence_id="evidence.0",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    model.apply_pending_physical_transition("evidence.0")
    with monkeypatch.context() as patch:
        patch.setattr(vault, "_append_event", crash_before_commit)
        with pytest.raises(OSError, match="bounded crash"):
            vault.delete_evidence(
                evidence_id="evidence.0",
                deleted_at=T2,
                deletion_basis="permitted_disposal",
                authority_ref="custody.authority.1",
            )
    assert not object_path.exists()
    _assert_retrieval_matches_model(
        EvidenceVault.open_read_only(vault.root), model, audited_at=T2
    )

    recovered = EvidenceVault(vault.root, signer=signer)
    model.recover()
    _assert_retrieval_matches_model(recovered, model, audited_at=T2)


def test_bounded_crash_preserves_component_alias_during_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault, signer, model = _create_pair(tmp_path / "vault")
    _append_one_pair(vault, model, content=SCHEMA_BYTES)
    object_sha = model.evidence["evidence.0"].object_sha256
    object_path = vault._object_path(object_sha)
    original_append = vault._append_event

    def crash_before_commit(
        event_type: str, body: object, *, recorded_at: str
    ) -> dict[str, object]:
        if event_type == "EVIDENCE_DELETED":
            raise OSError("bounded crash before shared commit")
        return original_append(event_type, body, recorded_at=recorded_at)

    intent = model.begin_delete(
        evidence_id="evidence.0",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    assert intent.physical_delete_required is False
    with monkeypatch.context() as patch:
        patch.setattr(vault, "_append_event", crash_before_commit)
        with pytest.raises(OSError, match="bounded crash"):
            vault.delete_evidence(
                evidence_id="evidence.0",
                deleted_at=T2,
                deletion_basis="permitted_disposal",
                authority_ref="custody.authority.1",
            )
    assert object_path.is_file()
    recovered = EvidenceVault(vault.root, signer=signer)
    model.recover()
    assert object_path.is_file()
    assert model.invariant_violations() == ()
    _assert_retrieval_matches_model(recovered, model, audited_at=T2)


def test_bounded_crash_orphan_object_is_collected_on_writable_reopen(
    tmp_path: Path,
) -> None:
    vault, signer, model = _create_pair(tmp_path / "vault")
    orphan = b"unreferenced-after-bounded-crash"
    object_ref = vault._put_object(orphan, media_type="application/octet-stream")
    object_sha = object_ref["sha256"]
    model.objects[object_sha] = orphan
    assert vault._object_path(object_sha).is_file()

    model.collect_unreferenced_objects()
    EvidenceVault(vault.root, signer=signer)
    assert object_sha not in model.objects
    assert not vault._object_path(object_sha).exists()


def test_cross_runtime_vectors_are_outputs_of_the_independent_model() -> None:
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/vault_state_model_vectors.json").read_text(
            encoding="utf-8"
        )
    )
    expected = {row["case_id"]: row["expected"] for row in fixture["cases"]}

    shared_component = _create_reference_model()
    _model_append(
        shared_component, evidence_id="evidence.payment.1", content=SCHEMA_BYTES
    )
    intent = shared_component.delete(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    assert expected["shared_component_delete"] == {
        "physical_deleted": intent.physical_delete_required,
        "retained_by_live_evidence_ids": list(intent.retained_by_evidence_ids),
        "retained_by_component_refs": list(intent.retained_by_component_refs),
        "object_survives": intent.object_sha256 in shared_component.objects,
    }

    hold = _create_reference_model()
    _model_append(
        hold,
        evidence_id="evidence.payment.1",
        minimum_retain_until=T1,
        deletion_required_by=T2,
    )
    hold.seal_bundle(
        bundle_id="bundle.payment.1", evidence_ids=("evidence.payment.1",)
    )
    hold.place_hold(
        hold_id="hold.deadline", evidence_ids=("evidence.payment.1",)
    )
    held_retrieval = hold.retrieve(bundle_id="bundle.payment.1", audited_at=T2)
    held_status = hold.retention_status("evidence.payment.1", evaluated_at=T2)
    hold.release_hold(hold_id="hold.deadline")
    released_retrieval = hold.retrieve(bundle_id="bundle.payment.1", audited_at=T2)
    assert expected["hold_deadline_release"] == {
        "held_retention_status": held_status,
        "held_retrieval_status": held_retrieval["status"],
        "released_retention_status": hold.retention_status(
            "evidence.payment.1", evaluated_at=T2
        ),
        "released_retrieval_status": released_retrieval["status"],
        "released_primary_failure": released_retrieval["primary_failure"]["subtype"],
    }

    shared_evidence = _create_reference_model()
    _model_append(shared_evidence, evidence_id="evidence.payment.1")
    _model_append(shared_evidence, evidence_id="evidence.payment.2")
    object_sha = shared_evidence.evidence["evidence.payment.1"].object_sha256
    first = shared_evidence.delete(
        evidence_id="evidence.payment.1",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    survives_first = object_sha in shared_evidence.objects
    second = shared_evidence.delete(
        evidence_id="evidence.payment.2",
        deleted_at=T2,
        deletion_basis="permitted_disposal",
    )
    assert expected["shared_evidence_delete_sequence"] == {
        "first_physical_deleted": first.physical_delete_required,
        "first_retained_by_live_evidence_ids": list(first.retained_by_evidence_ids),
        "second_physical_deleted": second.physical_delete_required,
        "object_survives_after_first": survives_first,
        "object_survives_after_second": object_sha in shared_evidence.objects,
    }

    revocation = _create_reference_model()
    _model_append(revocation, evidence_id="evidence.before", captured_at=T0)
    _model_append(
        revocation,
        evidence_id="evidence.after",
        captured_at=T2,
        minimum_retain_until=T2,
    )
    revocation.seal_bundle(
        bundle_id="bundle.before", evidence_ids=("evidence.before",)
    )
    revocation.seal_bundle(bundle_id="bundle.after", evidence_ids=("evidence.after",))
    before = revocation.retrieve(bundle_id="bundle.before", audited_at=T2)
    after = revocation.retrieve(bundle_id="bundle.after", audited_at=T2)
    assert expected["routine_revocation_boundary"] == {
        "capture_before_revocation": before["status"],
        "capture_at_or_after_revocation": after["primary_failure"]["subtype"],
    }
