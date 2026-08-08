from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    NominationCommandLike,
    ResolvedNominationContext,
    SelectionEngine,
    SelectionExecutionError,
    _input_digest,
    _new_candidate_evidence,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    ContentSignal,
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    NominationProposal,
    SelectionBasis,
)
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
    proposal = NominationProposal(
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

    assert _input_digest(command, left) == _input_digest(command, right)
