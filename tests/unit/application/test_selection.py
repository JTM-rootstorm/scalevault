from __future__ import annotations

from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import (
    SelectionEngine,
    SelectionExecutionError,
    _new_candidate_evidence,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import EvidenceKind, EvidenceSummary, EvidenceTrust
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
