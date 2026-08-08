from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.models import SelectionDecision, SelectionDecisionCounter
from kivra_memory.storage.selection_history import (
    SelectionDecisionRecord,
    SelectionHistoryFilters,
    SelectionHistoryRepository,
    append_selection_decision,
)
from sqlalchemy.ext.asyncio import AsyncSession


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def decision(sequence: int = 1) -> SelectionDecision:
    return SelectionDecision(
        selection_sequence=sequence,
        decision_id=uid(1),
        tenant_id=uid(2),
        lineage_id=uid(3),
        branch_id=uid(4),
        persona_id=uid(5),
        actor_id=uid(6),
        client_id=uid(7),
        transport_binding_id=uid(8),
        policy_id="scalevault-memory-selection",
        policy_version=1,
        policy_sha256=b"p" * 32,
        policy_rule_code="routine_banter",
        input_sha256=b"i" * 32,
        source_kind="live_interaction",
        requested_operation="nominate",
        outcome="omit",
        reason_codes=["routine_banter_omitted"],
        matched_rule_ids=["routine_banter"],
        selection_basis="routine_banter",
        scope="global",
        visibility="private_root",
        sensitivity=0,
        subject_id=uid(9),
        subject_kind="global",
        memory_id=None,
        event_id=None,
        decided_at=NOW,
    )


def filters() -> SelectionHistoryFilters:
    return SelectionHistoryFilters(
        tenant_id=uid(2),
        persona_id=uid(5),
        lineage_id=uid(3),
        branch_id=uid(4),
        allowed_scopes=frozenset({MemoryScope.GLOBAL}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=0,
        selection_bases=frozenset({"routine_banter"}),
    )


@pytest.mark.asyncio
async def test_append_allocates_one_rollback_owned_sequence() -> None:
    counter = SelectionDecisionCounter(counter_id=1, next_sequence=12)
    session = Mock(spec=AsyncSession)
    session.in_transaction.return_value = True
    session.scalar = AsyncMock(return_value=counter)
    session.flush = AsyncMock()

    stored = await append_selection_decision(
        cast(AsyncSession, session), lambda sequence: decision(sequence)
    )

    assert stored.selection_sequence == 12
    assert counter.next_sequence == 13
    session.add.assert_called_once_with(stored)
    session.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_history_applies_immutable_authorization_anchors_and_safe_dto() -> None:
    scalar_result = Mock()
    scalar_result.all.return_value = [decision(9)]
    session = Mock(spec=AsyncSession)
    session.scalars = AsyncMock(return_value=scalar_result)

    records = await SelectionHistoryRepository(cast(AsyncSession, session)).list_decisions(
        filters(), before_sequence=10, limit=25
    )

    assert len(records) == 1
    assert records[0].selection_sequence == 9
    assert records[0].reason_codes == ("routine_banter_omitted",)
    assert records[0].matched_rule_ids == ("routine_banter",)
    assert "actor_id" not in SelectionDecisionRecord.__dataclass_fields__
    assert "client_id" not in SelectionDecisionRecord.__dataclass_fields__
    assert "transport_binding_id" not in SelectionDecisionRecord.__dataclass_fields__
    assert "input_sha256" not in SelectionDecisionRecord.__dataclass_fields__

    statement = session.scalars.await_args.args[0]
    sql = str(statement)
    assert "selection_decisions.tenant_id" in sql
    assert "selection_decisions.persona_id" in sql
    assert "selection_decisions.lineage_id" in sql
    assert "selection_decisions.branch_id" in sql
    assert "selection_decisions.sensitivity <=" in sql
    assert "selection_decisions.selection_basis IN" in sql
    assert "selection_decisions.selection_sequence <" in sql
    assert "ORDER BY selection_decisions.selection_sequence DESC" in sql


@pytest.mark.parametrize(
    "changes",
    (
        {"selection_bases": frozenset()},
        {"selection_bases": frozenset({"unknown_basis"})},
        {"max_sensitivity": 5},
    ),
)
def test_history_filters_fail_closed(changes: dict[str, object]) -> None:
    values = {field: getattr(filters(), field) for field in filters().__dataclass_fields__}
    values.update(changes)
    with pytest.raises(ValueError):
        SelectionHistoryFilters(**values)
