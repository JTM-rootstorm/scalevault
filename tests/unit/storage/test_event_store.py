from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
    TransportKind,
)
from kivra_memory.domain.events import (
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    OperationPayload,
    event_hash_fields,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.event_store import EventStoreError, append_memory_event
from kivra_memory.storage.models.events import MemoryEvent as MemoryEventRow
from kivra_memory.storage.models.events import MemoryEventCounter
from kivra_memory.storage.models.identity import TransportBinding
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

NOW = datetime(2026, 8, 3, 20, 0, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def memory_state(*, revision: int = 1, sensitivity: int = 0) -> MemoryState:
    return MemoryState(
        memory_id=uid(10),
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        subject_id=uid(11),
        subject_kind=SubjectKind.GLOBAL,
        revision=revision,
        category=MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="Synthetic event-store fixture.",
        reason_to_remember="Exercises atomic persistence.",
        interpretation_limits=("Test data only.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=sensitivity,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        valid_from=None,
        valid_to=None,
        observed_at=NOW,
        origin_session_id=None,
        publication_approved_at=None,
        publication_approved_by_actor_id=None,
        content_protection="plaintext",
        content_key_id=None,
        created_at=NOW,
        updated_at=NOW,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


def make_event(
    sequence: int,
    *,
    operation: EventOperation = EventOperation.REMEMBERED,
    ingress_id: UUID | None = None,
    sensitivity: int = 0,
) -> MemoryEvent:
    revision = 2 if operation is EventOperation.REVISED else 1
    memory = memory_state(revision=revision, sensitivity=sensitivity)
    if operation is EventOperation.REVISED:
        payload: OperationPayload = MemoryTransitionPayload(previous_revision=1, memory=memory)
        expected_revision = 1
    else:
        payload = MemoryCreatedPayload(memory=memory)
        expected_revision = None

    values, canonical, payload_hash, command_hash = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        actor_id=uid(4),
        client_id=uid(5),
        memory_id=memory.memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=uid(100 + sequence),
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        actor_id=uid(4),
        client_id=uid(5),
        transport_binding_id=uid(6),
        session_id=None,
        ingress_id=ingress_id,
        operation=operation,
        memory_id=memory.memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
        correlation_id=uid(30),
        idempotency_key=f"event-store:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=values,
        payload_canonical=canonical,
        payload_sha256=payload_hash,
        command_sha256=command_hash,
        created_at=NOW,
    )


def binding(
    *,
    kind: TransportKind = TransportKind.DIRECT_PRIVATE,
    operations: tuple[EventOperation, ...] = (EventOperation.REMEMBERED,),
    valid_until: datetime | None = None,
) -> TransportBinding:
    return TransportBinding(
        transport_binding_id=uid(6),
        tenant_id=uid(1),
        actor_id=uid(4),
        client_id=uid(5),
        transport_kind=kind.value,
        disclosure_boundary="private_node",
        installation_id=uid(7) if kind is TransportKind.RELAY else None,
        authorized_operations={"operations": [operation.value for operation in operations]},
        created_at=NOW,
        valid_until=valid_until or NOW + timedelta(days=3650),
    )


class ScalarResult:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class RowResult:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def one_or_none(self) -> object | None:
        return self.value


def fake_session(
    counter: MemoryEventCounter,
    transport_binding: TransportBinding | None,
    *,
    actor_revoked_at: datetime | None = None,
    client_revoked_at: datetime | None = None,
    installation_present: bool = True,
    installation_revoked_at: datetime | None = None,
) -> tuple[AsyncSession, Mock]:
    raw = Mock(spec=AsyncSession)
    binding_row = (
        None
        if transport_binding is None
        else (
            transport_binding,
            actor_revoked_at,
            client_revoked_at,
            transport_binding.installation_id if installation_present else None,
            installation_revoked_at,
        )
    )
    raw.execute = AsyncMock(side_effect=[ScalarResult(counter), RowResult(binding_row)])
    raw.add = Mock()
    raw.flush = AsyncMock()
    return cast(AsyncSession, raw), raw


async def test_allocator_locks_counter_and_increments_only_after_staging() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=17)
    session, raw = fake_session(counter, binding())
    allocated: list[int] = []

    def builder(sequence: int) -> MemoryEvent:
        allocated.append(sequence)
        return make_event(sequence)

    event = await append_memory_event(session, builder)

    assert event.sequence == 17
    assert allocated == [17]
    assert counter.next_sequence == 18
    counter_statement = raw.execute.await_args_list[0].args[0]
    compiled = str(counter_statement)
    assert "FOR UPDATE" in compiled
    raw.flush.assert_awaited_once_with()


async def test_validation_failure_does_not_mutate_counter_or_stage_row() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=7)
    session, raw = fake_session(counter, binding())

    def invalid_builder(sequence: int) -> MemoryEvent:
        del sequence
        raise ValueError("payload-bearing implementation detail")

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, invalid_builder)

    assert caught.value.code == "event_invalid"
    assert "payload-bearing" not in str(caught.value)
    assert caught.value.__suppress_context__ is True
    assert counter.next_sequence == 7
    assert raw.execute.await_count == 1
    raw.add.assert_not_called()
    raw.flush.assert_not_awaited()


async def test_counter_mismatch_fails_before_binding_lookup() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=4)
    session, raw = fake_session(counter, binding())

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, lambda sequence: make_event(sequence + 1))

    assert caught.value.code == "event_sequence_mismatch"
    assert counter.next_sequence == 4
    assert raw.execute.await_count == 1
    raw.add.assert_not_called()


async def test_revoked_actor_revokes_exact_binding() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    session, raw = fake_session(counter, binding(), actor_revoked_at=NOW)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "binding_revoked"
    assert counter.next_sequence == 1
    raw.add.assert_not_called()


async def test_expired_binding_is_rejected() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    expired = binding(valid_until=datetime(2020, 1, 1, tzinfo=UTC))
    session, raw = fake_session(counter, expired)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "binding_expired"
    assert counter.next_sequence == 1
    raw.add.assert_not_called()


@pytest.mark.parametrize(
    ("operation", "ingress_id", "code"),
    [
        (EventOperation.REMEMBERED, None, "github_ingress_required"),
        (EventOperation.REVISED, uid(40), "github_operation_forbidden"),
    ],
)
async def test_github_binding_requires_provenance_and_creation_operation(
    operation: EventOperation, ingress_id: UUID | None, code: str
) -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    github = binding(
        kind=TransportKind.GITHUB_INGRESS,
        operations=(EventOperation.REMEMBERED, EventOperation.REVISED),
    )
    session, raw = fake_session(counter, github)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(
            session,
            lambda sequence: make_event(sequence, operation=operation, ingress_id=ingress_id),
        )

    assert caught.value.code == code
    raw.add.assert_not_called()


async def test_github_binding_accepts_observed_event_with_ingress_provenance() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    github = binding(
        kind=TransportKind.GITHUB_INGRESS,
        operations=(EventOperation.OBSERVED,),
    )
    session, raw = fake_session(counter, github)

    await append_memory_event(
        session,
        lambda sequence: make_event(
            sequence, operation=EventOperation.OBSERVED, ingress_id=uid(40)
        ),
    )

    assert counter.next_sequence == 2
    raw.add.assert_called_once()


async def test_non_github_binding_forbids_ingress_provenance() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    session, raw = fake_session(counter, binding())

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(
            session, lambda sequence: make_event(sequence, ingress_id=uid(40))
        )

    assert caught.value.code == "ingress_forbidden"
    raw.add.assert_not_called()


async def test_relay_rejects_sensitivity_four_after_image() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    relay = binding(kind=TransportKind.RELAY)
    session, raw = fake_session(counter, relay)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, lambda sequence: make_event(sequence, sensitivity=4))

    assert caught.value.code == "relay_sensitivity_forbidden"
    assert counter.next_sequence == 1
    raw.add.assert_not_called()


async def test_relay_rejects_revoked_installation() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    relay = binding(kind=TransportKind.RELAY)
    session, raw = fake_session(counter, relay, installation_revoked_at=NOW)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "binding_revoked"
    assert counter.next_sequence == 1
    raw.add.assert_not_called()


async def test_relay_rejects_missing_installation() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    relay = binding(kind=TransportKind.RELAY)
    session, raw = fake_session(counter, relay, installation_present=False)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "binding_installation_unavailable"
    assert counter.next_sequence == 1
    raw.add.assert_not_called()


async def test_authorization_document_must_explicitly_allow_operation() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=1)
    denied = binding(operations=(EventOperation.OBSERVED,))
    session, raw = fake_session(counter, denied)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "operation_not_authorized"
    raw.add.assert_not_called()


async def test_persistence_maps_canonical_bytes_and_binary_hashes() -> None:
    counter = MemoryEventCounter(counter_id=1, next_sequence=23)
    session, raw = fake_session(counter, binding())
    event = make_event(23)

    await append_memory_event(session, lambda sequence: event)

    row = raw.add.call_args.args[0]
    assert isinstance(row, MemoryEventRow)
    assert row.sequence == event.sequence
    assert row.payload == event.payload
    assert row.payload_canonical == base64.b64decode(event.payload_canonical, validate=True)
    assert row.payload_sha256 == bytes.fromhex(event.payload_sha256)
    assert row.command_sha256 == bytes.fromhex(event.command_sha256)
    assert row.operation == event.operation.value


async def test_database_failure_is_rendered_as_safe_typed_error() -> None:
    raw = Mock(spec=AsyncSession)
    raw.execute = AsyncMock(side_effect=SQLAlchemyError("connection contains private details"))
    session = cast(AsyncSession, raw)

    with pytest.raises(EventStoreError) as caught:
        await append_memory_event(session, make_event)

    assert caught.value.code == "event_store_unavailable"
    assert "private details" not in str(caught.value)
    assert caught.value.__suppress_context__ is True
