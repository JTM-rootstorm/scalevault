from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from kivra_memory.application import candidate_lifecycle
from kivra_memory.application.candidate_lifecycle import (
    CandidateLifecycleEngine,
    CandidateLifecycleExecutionError,
    _LifecycleIdentifiers,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.commands import CandidatePromotionCommand
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.event_store import EventStoreError
from kivra_memory.storage.models import Memory, SelectionDecision


def test_lifecycle_retry_allocations_are_stable_per_command() -> None:
    now = datetime(2026, 8, 8, 12, tzinfo=UTC)
    allocations = _LifecycleIdentifiers(evaluated_at=now)

    assert allocations.evaluated_at == now
    assert allocations.decision_id == allocations.decision_id
    assert allocations.event_id == allocations.event_id
    assert allocations.correlation_id == allocations.correlation_id
    assert len(allocations.job_ids) == 2
    assert len(set(allocations.job_ids)) == 2


def _principal() -> CommandPrincipal:
    return CommandPrincipal(
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=frozenset({"memory.lifecycle.promote"}),
    )


def _command(memory_id: UUID, decision_id: UUID) -> CandidatePromotionCommand:
    return CandidatePromotionCommand(
        memory_id=memory_id,
        expected_revision=3,
        selection_decision_id=decision_id,
        policy_rule_code="candidate_promoted",
    )


@pytest.mark.asyncio
async def test_policy_noop_ledger_copies_anchors_and_has_no_mutable_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = _principal()
    memory_id = new_uuid7()
    source_id = new_uuid7()
    memory = SimpleNamespace(
        memory_id=memory_id,
        lineage_id=new_uuid7(),
        branch_id=new_uuid7(),
        revision=3,
    )
    source = SimpleNamespace(
        decision_id=source_id,
        persona_id=new_uuid7(),
        selection_basis="assistant_observation",
        scope="persona",
        visibility="restricted",
        sensitivity=2,
        subject_id=new_uuid7(),
        subject_kind="persona",
    )
    identifiers = _LifecycleIdentifiers(evaluated_at=datetime(2026, 8, 8, tzinfo=UTC))
    captured: list[Any] = []

    async def append(_session: object, builder: object) -> object:
        created = builder(11)  # type: ignore[operator]
        captured.append(created)
        return SimpleNamespace(decision_id=created.decision_id)

    monkeypatch.setattr(candidate_lifecycle, "append_selection_decision", append)
    result = await CandidateLifecycleEngine._record_policy_noop(
        session=AsyncMock(),
        principal=principal,
        command=_command(memory_id, source_id),
        source=cast(SelectionDecision, source),
        memory=cast(Memory, memory),
        operation="promote",
        identifiers=identifiers,
        policy_sha256="a" * 64,
        reason_code="protected_candidate",
    )

    created = captured[0]
    assert created.decision_id == identifiers.decision_id
    assert created.source_kind == "candidate_reassessment"
    assert created.requested_operation == "promote"
    assert created.outcome == "omit"
    assert created.memory_id is None
    assert created.event_id is None
    assert created.actor_id == principal.actor_id
    assert created.selection_basis == source.selection_basis
    assert created.subject_id == source.subject_id
    assert result.decision_id == identifiers.decision_id
    assert result.source_decision_id == source_id


@pytest.mark.asyncio
async def test_sealed_lineage_persona_or_branch_fails_before_lifecycle_evaluation() -> None:
    principal = _principal()
    memory_id = new_uuid7()
    source_id = new_uuid7()
    memory = SimpleNamespace(
        memory_id=memory_id,
        tenant_id=principal.tenant_id,
        lineage_id=new_uuid7(),
        branch_id=new_uuid7(),
        persona_id=new_uuid7(),
        revision=3,
        status="candidate",
    )
    session = AsyncMock()
    session.scalar = AsyncMock(side_effect=("internal_service", memory))
    session.execute = AsyncMock(
        return_value=SimpleNamespace(
            one_or_none=lambda: (datetime(2026, 8, 8, tzinfo=UTC), None, None)
        )
    )

    with pytest.raises(CandidateLifecycleExecutionError, match="forbidden"):
        await CandidateLifecycleEngine(AsyncMock())._attempt(
            session,
            principal,
            _command(memory_id, source_id),
            operation="promote",
            identifiers=_LifecycleIdentifiers(evaluated_at=datetime(2026, 8, 8, tzinfo=UTC)),
        )


@pytest.mark.asyncio
async def test_event_storage_failure_is_collapsed_without_content_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = _principal()
    command = _command(new_uuid7(), new_uuid7())

    async def fail(*_args: object, **_kwargs: object) -> object:
        raise EventStoreError("event_invalid", "untrusted nominated content")

    monkeypatch.setattr(candidate_lifecycle, "run_serializable_transaction", fail)

    with pytest.raises(CandidateLifecycleExecutionError) as caught:
        await CandidateLifecycleEngine(AsyncMock()).promote(principal, command)

    assert caught.value.code == "validation_failed"
    assert "untrusted" not in str(caught.value)
