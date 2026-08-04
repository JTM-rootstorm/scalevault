from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
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
)
from kivra_memory.domain.events import (
    BranchCreatedPayload,
    BranchState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    OperationPayload,
    event_hash_fields,
)
from kivra_memory.domain.identifiers import new_uuid7
from pydantic import ValidationError

NOW = datetime(2026, 8, 3, 20, 0, 0, 123456, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


DEFAULT_MEMORY_ID = uid(10)
DEFAULT_TENANT_ID = uid(1)
DEFAULT_LINEAGE_ID = uid(2)
DEFAULT_BRANCH_ID = uid(3)
DEFAULT_SUBJECT_ID = uid(11)
DEFAULT_CORRELATION_ID = uid(30)


def memory_state(
    *,
    memory_id: UUID = DEFAULT_MEMORY_ID,
    tenant_id: UUID = DEFAULT_TENANT_ID,
    lineage_id: UUID = DEFAULT_LINEAGE_ID,
    branch_id: UUID = DEFAULT_BRANCH_ID,
    subject_id: UUID = DEFAULT_SUBJECT_ID,
    revision: int = 1,
    status: MemoryStatus = MemoryStatus.ACTIVE,
    created_at: datetime = NOW,
    updated_at: datetime = NOW,
    statement: str | None = "The synthetic project uses a stable test floor.",
    reason: str | None = "This is a durable synthetic test decision.",
) -> MemoryState:
    tombstoned = status is MemoryStatus.TOMBSTONED
    return MemoryState(
        memory_id=memory_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        subject_id=subject_id,
        subject_kind=SubjectKind.GLOBAL,
        revision=revision,
        category=MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=status,
        statement=None if tombstoned else statement,
        reason_to_remember=None if tombstoned else reason,
        interpretation_limits=() if tombstoned else ("Synthetic test record only.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        valid_from=None,
        valid_to=None,
        observed_at=created_at,
        origin_session_id=None,
        publication_approved_at=None,
        publication_approved_by_actor_id=None,
        content_protection="plaintext",
        content_key_id=None,
        created_at=created_at,
        updated_at=updated_at,
        fingerprint_version=1,
        normalized_fingerprint=None if tombstoned else "ab" * 32,
        metadata={"fixture": True},
    )


def make_event(
    *,
    sequence: int,
    operation: EventOperation,
    payload: OperationPayload,
    memory_id: UUID | None,
    expected_revision: int | None = None,
    tenant_id: UUID = DEFAULT_TENANT_ID,
    lineage_id: UUID = DEFAULT_LINEAGE_ID,
    branch_id: UUID = DEFAULT_BRANCH_ID,
    created_at: datetime = NOW,
    session_id: UUID | None = None,
    correlation_id: UUID = DEFAULT_CORRELATION_ID,
) -> MemoryEvent:
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=uid(4),
        client_id=uid(5),
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=uid(100 + sequence),
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=uid(4),
        client_id=uid(5),
        transport_binding_id=uid(6),
        session_id=session_id,
        ingress_id=None,
        operation=operation,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
        correlation_id=correlation_id,
        idempotency_key=f"fixture:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


def test_event_round_trips_closed_payload_and_verifies_hashes() -> None:
    memory = memory_state()
    event = make_event(
        sequence=1,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
    )

    assert event.typed_payload() == MemoryCreatedPayload(memory=memory)
    event.verify_hashes()


def test_event_rejects_payload_for_another_operation() -> None:
    branch = BranchState(
        branch_id=uid(3),
        tenant_id=uid(1),
        lineage_id=uid(2),
        parent_branch_id=None,
        fork_event_sequence=None,
        name="root",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=NOW,
        sealed_at=None,
    )

    with pytest.raises(ValidationError):
        make_event(
            sequence=1,
            operation=EventOperation.REMEMBERED,
            payload=BranchCreatedPayload(branch=branch),
            memory_id=uid(10),
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"memory_id": None}, "invalid envelope target shape"),
        ({"expected_revision": 1}, "invalid envelope target shape"),
    ],
)
def test_create_event_construction_rejects_invalid_target_shape(
    changes: dict[str, object], message: str
) -> None:
    memory = memory_state()
    event = make_event(
        sequence=1,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
    )
    document = event.model_dump(mode="python")
    document.update(changes)

    with pytest.raises(ValidationError, match=message):
        MemoryEvent.model_validate(document)


def test_transition_and_aggregate_construction_reject_invalid_target_shapes() -> None:
    memory = memory_state()
    revised_document = memory.model_dump(mode="python")
    revised_document.update(revision=2, updated_at=NOW)
    revised = MemoryState.model_validate(revised_document)
    transition = make_event(
        sequence=1,
        operation=EventOperation.REVISED,
        payload=MemoryTransitionPayload(previous_revision=1, memory=revised),
        memory_id=memory.memory_id,
        expected_revision=1,
    )
    transition_document = transition.model_dump(mode="python")
    transition_document["expected_revision"] = None

    with pytest.raises(ValidationError, match="invalid envelope target shape"):
        MemoryEvent.model_validate(transition_document)

    branch = BranchState(
        branch_id=uid(3),
        tenant_id=uid(1),
        lineage_id=uid(2),
        parent_branch_id=None,
        fork_event_sequence=None,
        name="root",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=NOW,
        sealed_at=None,
    )
    aggregate = make_event(
        sequence=1,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=branch),
        memory_id=None,
    )
    aggregate_document = aggregate.model_dump(mode="python")
    aggregate_document["memory_id"] = memory.memory_id

    with pytest.raises(ValidationError, match="invalid envelope target shape"):
        MemoryEvent.model_validate(aggregate_document)


@pytest.mark.parametrize("field", ["payload_sha256", "command_sha256"])
def test_event_rejects_hash_tampering(field: str) -> None:
    memory = memory_state()
    event = make_event(
        sequence=1,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
    )
    document = event.model_dump(mode="python")
    document[field] = "00" * 32

    with pytest.raises(ValidationError, match="SHA-256 mismatch"):
        MemoryEvent.model_validate(document)


def test_command_hash_excludes_session_and_correlation() -> None:
    memory = memory_state()
    payload = MemoryCreatedPayload(memory=memory)
    first = make_event(
        sequence=1,
        operation=EventOperation.REMEMBERED,
        payload=payload,
        memory_id=memory.memory_id,
        session_id=uid(40),
        correlation_id=uid(41),
    )
    second = make_event(
        sequence=2,
        operation=EventOperation.REMEMBERED,
        payload=payload,
        memory_id=memory.memory_id,
        session_id=uid(42),
        correlation_id=uid(43),
    )

    assert first.command_sha256 == second.command_sha256


def test_tombstone_after_image_rejects_retained_content() -> None:
    document = memory_state().model_dump(mode="python")
    document["status"] = MemoryStatus.TOMBSTONED
    with pytest.raises(ValidationError, match="tombstoned memory content must be sanitized"):
        MemoryState.model_validate(document)


def test_memory_after_image_rejects_non_uuid7() -> None:
    with pytest.raises(ValidationError, match="UUIDv7"):
        memory_state(memory_id=UUID("00000000-0000-4000-8000-000000000000"))


def test_global_memory_rejects_roleplayed_scene() -> None:
    document = memory_state().model_dump(mode="python")
    document.update(
        category=MemoryCategory.EPISODIC_ANCHOR,
        ontological_status=OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE,
    )

    with pytest.raises(ValidationError, match="global memory cannot represent"):
        MemoryState.model_validate(document)


def test_episodic_memory_requires_origin_or_import_provenance() -> None:
    document = memory_state().model_dump(mode="python")
    document.update(
        category=MemoryCategory.EPISODIC_ANCHOR,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.EPISODIC,
        subject_kind=SubjectKind.EPISODE,
        origin_session_id=None,
    )

    with pytest.raises(ValidationError, match="episodic memory requires"):
        MemoryState.model_validate(document)

    document["authority_class"] = AuthorityClass.IMPORTED_LEGACY_MEMORY
    assert MemoryState.model_validate(document).origin_session_id is None
