from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from kivra_memory.application import selection
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
    SelectionEngine,
    SelectionExecutionError,
    SelectionResult,
    _command_digest,
    _input_digest,
    _new_candidate_evidence,
    _replay_from_receipt,
    _validate_session_scope_anchors,
    _validate_unsealed_identity,
)
from kivra_memory.application.selection import (
    _event as selection_event,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import MemoryCreatedPayloadV2
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    ContentSignal,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    NominationProposal,
    SelectionBasis,
)
from kivra_memory.storage.event_store import EventStoreError
from kivra_memory.storage.models import CommandReceipt
from kivra_memory.storage.projector import ProjectionPersistenceError
from kivra_memory.storage.selection_history import SelectionHistoryError
from sqlalchemy.ext.asyncio import AsyncSession


def _principal(*, scopes: frozenset[str], tenant_id: UUID | None = None) -> CommandPrincipal:
    return CommandPrincipal(
        tenant_id=tenant_id if tenant_id is not None else new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=scopes,
    )


def _command() -> SimpleNamespace:
    return SimpleNamespace(idempotency_key="selection-provider-unit")


def _proposal() -> NominationProposal:
    return NominationProposal(
        subject_id=new_uuid7(),
        subject_kind=SubjectKind.GLOBAL,
        category=MemoryCategory.USER_PREFERENCE,
        ontological_status=OntologicalStatus.LITERAL_USER_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement="The user prefers concise technical updates.",
        reason_to_remember="This preference shapes future technical collaboration.",
        interpretation_limits=("The preference is revisable.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.7"),
        durability=Decimal("0.8"),
        sensitivity=0,
        metadata={},
        selection_basis=SelectionBasis.EXPLICIT_USER_PREFERENCE,
        epistemic_qualifiers=(),
        evidence_references=(),
    )


def _nomination_command(
    *,
    proposal: NominationProposal | None = None,
    logical_session_id: UUID | None = None,
) -> NominationCommandLike:
    return cast(
        NominationCommandLike,
        SimpleNamespace(
            idempotency_key="selection-provider-unit",
            persona_id=new_uuid7(),
            branch_id=new_uuid7(),
            reason="Nominate an explicit preference.",
            proposal=proposal or _proposal(),
            logical_session_id=logical_session_id,
        ),
    )


def _receipt(command: NominationCommandLike, principal: CommandPrincipal) -> CommandReceipt:
    receipt_id = new_uuid7()
    decision_id = new_uuid7()
    result = SelectionResult(
        receipt_id=receipt_id,
        decision_id=decision_id,
        outcome="omit",
        policy_sha256="0" * 64,
        reason_codes=("routine_banter",),
        matched_rule_ids=("basis.routine_banter",),
        event_id=None,
        memory_id=None,
        revision=None,
    )
    result_value = result.model_dump(mode="json")
    canonical = canonical_json_bytes(result_value)
    return CommandReceipt(
        receipt_id=receipt_id,
        tenant_id=principal.tenant_id,
        client_id=principal.client_id,
        idempotency_key=command.idempotency_key,
        command_sha256=_command_digest(principal, command),
        event_id=None,
        selection_decision_id=decision_id,
        memory_id=None,
        memory_revision=None,
        result=result_value,
        result_canonical=canonical,
        result_sha256=hashlib.sha256(canonical).digest(),
        created_at=datetime.now(UTC),
    )


def test_nomination_event_builder_hashes_the_v2_payload_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def hash_fields(**kwargs: object) -> tuple[dict[str, object], str, str, str]:
        captured.update(kwargs)
        return {}, "e30=", "0" * 64, "1" * 64

    def event_model(**kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(**kwargs)

    monkeypatch.setattr(selection, "event_hash_fields", hash_fields)
    monkeypatch.setattr(selection, "MemoryEvent", event_model)
    principal = CommandPrincipal(
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=frozenset({"memory.write.nominate"}),
    )
    branch_id = new_uuid7()
    command = cast(
        NominationCommandLike,
        SimpleNamespace(
            branch_id=branch_id,
            logical_session_id=None,
            idempotency_key="selection-v2-event-unit",
        ),
    )

    event = selection_event(
        operation=EventOperation.OBSERVED,
        principal=principal,
        command=command,
        lineage_id=new_uuid7(),
        payload=cast(MemoryCreatedPayloadV2, SimpleNamespace()),
        event_id=new_uuid7(),
        correlation_id=new_uuid7(),
        created_at=datetime(2026, 8, 8, tzinfo=UTC),
        memory_id=new_uuid7(),
        expected_revision=None,
        policy_input_digest=b"ignored-by-v2-envelope",
    )

    assert event.payload_version == 2
    assert captured["payload_version"] == 2


async def test_promotion_provider_requires_exact_internal_scope_and_binding() -> None:
    nominator = _principal(scopes=frozenset({"memory.write.nominate"}))
    promoted = _principal(
        scopes=frozenset({"memory.lifecycle.promote"}), tenant_id=nominator.tenant_id
    )

    async def resolver(*_args: object) -> CommandPrincipal:
        return promoted

    scalar = AsyncMock(return_value="internal_service")
    session = cast(AsyncSession, SimpleNamespace(scalar=scalar))
    engine = SelectionEngine(AsyncMock(), AsyncMock(), resolver)

    resolved = await engine._promotion_principal(
        session,
        nominator=nominator,
        command=_command(),
        memory_id=new_uuid7(),
    )

    assert resolved is promoted
    scalar.assert_awaited_once()


@pytest.mark.parametrize(
    ("scopes", "binding_kind"),
    [
        (frozenset({"memory.lifecycle.promote", "memory:internal"}), "internal_service"),
        (frozenset({"memory.lifecycle.promote"}), "direct_private"),
    ],
)
async def test_promotion_provider_fails_closed_for_non_narrow_authority(
    scopes: frozenset[str], binding_kind: str
) -> None:
    nominator = _principal(scopes=frozenset({"memory.write.nominate"}))
    promoted = _principal(scopes=scopes, tenant_id=nominator.tenant_id)

    async def resolver(*_args: object) -> CommandPrincipal:
        return promoted

    session = cast(AsyncSession, SimpleNamespace(scalar=AsyncMock(return_value=binding_kind)))
    engine = SelectionEngine(AsyncMock(), AsyncMock(), resolver)

    with pytest.raises(SelectionExecutionError, match="authority_unavailable"):
        await engine._promotion_principal(
            session,
            nominator=nominator,
            command=_command(),
            memory_id=new_uuid7(),
        )


async def test_promotion_provider_is_required_before_any_lifecycle_event() -> None:
    engine = SelectionEngine(AsyncMock(), AsyncMock())
    with pytest.raises(SelectionExecutionError, match="authority_unavailable"):
        await engine._promotion_principal(
            cast(AsyncSession, SimpleNamespace(scalar=AsyncMock())),
            nominator=_principal(scopes=frozenset({"memory.write.nominate"})),
            command=_command(),
            memory_id=new_uuid7(),
        )


def test_duplicate_candidate_evidence_requires_a_distinct_evidence_key() -> None:
    first = EvidenceSummary(
        evidence_key="trusted-observation-a",
        kind=EvidenceKind.ASSISTANT_OBSERVATION,
        trust=EvidenceTrust.TRUSTED,
    )
    second = EvidenceSummary(
        evidence_key="trusted-observation-b",
        kind=EvidenceKind.ASSISTANT_OBSERVATION,
        trust=EvidenceTrust.TRUSTED,
    )

    assert _new_candidate_evidence((first,), (first,)) == ()
    assert _new_candidate_evidence((first,), (second,)) == (second,)


def test_nomination_digest_is_json_safe_and_order_independent_for_trusted_facts() -> None:
    proposal = _proposal()
    principal = _principal(scopes=frozenset({"memory.write.nominate"}))
    command = cast(
        NominationCommandLike,
        SimpleNamespace(
            idempotency_key="digest-order-unit",
            persona_id=new_uuid7(),
            branch_id=new_uuid7(),
            reason="Nominate an explicit preference.",
            proposal=proposal,
            logical_session_id=None,
        ),
    )
    first = EvidenceSummary(
        evidence_key="evidence-a",
        kind=EvidenceKind.USER_STATEMENT,
        trust=EvidenceTrust.TRUSTED,
    )
    second = EvidenceSummary(
        evidence_key="evidence-b",
        kind=EvidenceKind.USER_CONFIRMATION,
        trust=EvidenceTrust.CORROBORATED,
    )
    content_signals = frozenset(
        {ContentSignal.ASSISTANT_PREFERENCE_LIKE, ContentSignal.ROLEPLAYED_SCENE}
    )
    left = ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
        content_signals=content_signals,
        evidence=(first, second),
    )
    right = ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
        content_signals=content_signals,
        evidence=(second, first),
    )

    assert _input_digest(principal, command, left) == _input_digest(principal, command, right)


def test_receipt_digest_excludes_resolver_facts_but_decision_digest_includes_them() -> None:
    command = _nomination_command()
    principal = _principal(scopes=frozenset({"memory.write.nominate"}))
    left = ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.EXPLICIT_USER_STATEMENT,
    )
    right = ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
        content_signals=frozenset({ContentSignal.ASSISTANT_PREFERENCE_LIKE}),
    )

    assert _command_digest(principal, command) == _command_digest(principal, command)
    rotated_binding = principal.model_copy(update={"transport_binding_id": new_uuid7()})
    different_actor = principal.model_copy(update={"actor_id": new_uuid7()})
    assert _command_digest(principal, command) == _command_digest(rotated_binding, command)
    assert _command_digest(principal, command) != _command_digest(different_actor, command)
    assert _input_digest(principal, command, left) != _input_digest(principal, command, right)


def test_receipt_replay_verifies_canonical_bytes_and_uses_json_coercion() -> None:
    command = _nomination_command()
    principal = _principal(scopes=frozenset({"memory.write.nominate"}))
    receipt = _receipt(command, principal)

    replay = _replay_from_receipt(receipt, command_digest=_command_digest(principal, command))

    assert replay.idempotent_replay is True
    assert replay.receipt_id == receipt.receipt_id


@pytest.mark.parametrize("corruption", ["canonical", "sha256", "jsonb"])
def test_receipt_replay_rejects_corrupt_immutable_representations(corruption: str) -> None:
    command = _nomination_command()
    principal = _principal(scopes=frozenset({"memory.write.nominate"}))
    receipt = _receipt(command, principal)
    if corruption == "canonical":
        receipt.result_canonical = b"{}"
    elif corruption == "sha256":
        receipt.result_sha256 = b"x" * 32
    else:
        receipt.result = {**receipt.result, "outcome": "reject"}

    with pytest.raises(SelectionExecutionError, match="dependency_unavailable"):
        _replay_from_receipt(receipt, command_digest=_command_digest(principal, command))


async def test_committed_replay_bypasses_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    from kivra_memory.application import selection as selection_module

    command = _nomination_command()
    principal = _principal(scopes=frozenset({"memory.write.nominate"}))
    receipt = _receipt(command, principal)
    session = cast(AsyncSession, SimpleNamespace(scalar=AsyncMock(return_value=receipt)))

    async def transaction(_factory: object, _tenant_id: UUID, operation: object) -> object:
        return await operation(session)  # type: ignore[operator]

    monkeypatch.setattr(selection_module, "run_serializable_transaction", transaction)
    resolver = AsyncMock(side_effect=RuntimeError("resolver must not run"))
    engine = SelectionEngine(AsyncMock(), resolver)

    replay = await engine.execute(principal, command)

    assert replay.idempotent_replay is True
    resolver.assert_not_awaited()


@pytest.mark.parametrize(
    "failure",
    [
        EventStoreError("event_invalid", "safe"),
        ProjectionPersistenceError("invalid_live_projection"),
        SelectionHistoryError("selection_counter_unavailable"),
    ],
)
async def test_persistence_failures_map_to_content_free_selection_codes(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    from kivra_memory.application import selection as selection_module

    async def transaction(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(selection_module, "run_serializable_transaction", transaction)
    engine = SelectionEngine(AsyncMock(), AsyncMock())

    with pytest.raises(SelectionExecutionError, match="dependency_unavailable") as caught:
        await engine.execute(
            _principal(scopes=frozenset({"memory.write.nominate"})),
            _nomination_command(),
        )
    assert caught.value.code == "dependency_unavailable"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("sealed_field", ["persona", "lineage", "branch"])
def test_nomination_rejects_retired_or_sealed_identity(sealed_field: str) -> None:
    sealed_at = datetime.now(UTC)
    values = {
        "persona_retired_at": sealed_at if sealed_field == "persona" else None,
        "lineage_sealed_at": sealed_at if sealed_field == "lineage" else None,
        "branch_sealed_at": sealed_at if sealed_field == "branch" else None,
    }

    with pytest.raises(SelectionExecutionError, match="forbidden"):
        _validate_unsealed_identity(**values)


@pytest.mark.parametrize("scope", [MemoryScope.SCENE_LOCAL, MemoryScope.EPISODIC])
def test_session_scoped_nomination_requires_exact_command_proposal_subject_anchor(
    scope: MemoryScope,
) -> None:
    session_id = new_uuid7()
    proposal = _proposal().model_copy(update={"scope": scope, "origin_session_id": session_id})
    command = _nomination_command(proposal=proposal, logical_session_id=session_id)

    _validate_session_scope_anchors(command, subject_origin_session_id=session_id)
    with pytest.raises(SelectionExecutionError, match="forbidden"):
        _validate_session_scope_anchors(command, subject_origin_session_id=new_uuid7())
    with pytest.raises(SelectionExecutionError, match="forbidden"):
        _validate_session_scope_anchors(
            _nomination_command(proposal=proposal, logical_session_id=None),
            subject_origin_session_id=session_id,
        )
