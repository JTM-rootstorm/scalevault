from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import (
    AffectedMemory,
    BranchCreatedPayload,
    BranchState,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    EvidenceAttachedPayload,
    EvidenceRedactedPayload,
    EvidenceState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryState,
    OperationPayload,
    PayloadPurgeCompletedPayload,
    TombstonedPayload,
    UnlinkedPayload,
    event_hash_fields,
)
from kivra_memory.domain.events import (
    MemoryEvent as DomainMemoryEvent,
)
from kivra_memory.domain.folding import ProjectionState, canonical_aggregate_bytes, rebuild
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.models import Branch, MemoryEvent
from kivra_memory.storage.projector import (
    ProjectionPersistenceError,
    build_projection_rows,
    canonical_aggregate_bytes_from_rows,
    event_row_to_domain,
    load_canonical_aggregate_bytes,
    rebuild_semantic_projections,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.dml import Delete
from sqlalchemy.sql.selectable import Select

NOW = datetime(2026, 8, 3, 20, 0, 0, 123456, tzinfo=UTC)
LATER = NOW + timedelta(seconds=1)
UNLINKED_AT = NOW + timedelta(seconds=2)
RESOLVED_AT = NOW + timedelta(seconds=3)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


TENANT_ID = uid(1)
LINEAGE_ID = uid(2)
BRANCH_ID = uid(3)
MEMORY_ID = uid(10)
SUBJECT_ID = uid(11)


def memory_state(
    *,
    memory_id: UUID = MEMORY_ID,
    tenant_id: UUID = TENANT_ID,
    lineage_id: UUID = LINEAGE_ID,
    branch_id: UUID = BRANCH_ID,
    subject_id: UUID = SUBJECT_ID,
) -> MemoryState:
    return MemoryState(
        memory_id=memory_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        subject_id=subject_id,
        subject_kind=SubjectKind.GLOBAL,
        revision=1,
        category=MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="The synthetic project uses a stable test floor.",
        reason_to_remember="This is a durable synthetic test decision.",
        interpretation_limits=("Synthetic test record only.",),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.7"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=NOW,
        content_protection="plaintext",
        created_at=NOW,
        updated_at=NOW,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


def make_event(
    *,
    sequence: int,
    operation: EventOperation,
    payload: OperationPayload,
    memory_id: UUID | None,
    expected_revision: int | None = None,
    tenant_id: UUID = TENANT_ID,
    lineage_id: UUID = LINEAGE_ID,
    branch_id: UUID = BRANCH_ID,
    created_at: datetime = NOW,
) -> DomainMemoryEvent:
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
    return DomainMemoryEvent(
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
        session_id=None,
        ingress_id=None,
        operation=operation,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=None,
        correlation_id=uid(30),
        idempotency_key=f"fixture:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


def branch_event(*, sequence: int = 1) -> DomainMemoryEvent:
    branch = BranchState(
        branch_id=uid(3),
        tenant_id=uid(1),
        lineage_id=uid(2),
        parent_branch_id=None,
        fork_event_sequence=None,
        name="root",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=NOW,
    )
    return make_event(
        sequence=sequence,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=branch),
        memory_id=None,
    )


def remembered_event(memory: MemoryState, *, sequence: int = 2) -> DomainMemoryEvent:
    return make_event(
        sequence=sequence,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
        tenant_id=memory.tenant_id,
        lineage_id=memory.lineage_id,
        branch_id=memory.branch_id,
    )


def child_branch_event(*, sequence: int = 3, fork_event_sequence: int = 2) -> DomainMemoryEvent:
    branch = BranchState(
        branch_id=uid(13),
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        parent_branch_id=BRANCH_ID,
        fork_event_sequence=fork_event_sequence,
        name="child",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=LATER,
    )
    return make_event(
        sequence=sequence,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=branch),
        memory_id=None,
        branch_id=branch.branch_id,
        created_at=LATER,
    )


def changed_memory(memory: MemoryState, **changes: object) -> MemoryState:
    document = memory.model_dump(mode="python")
    document.update(changes)
    return MemoryState.model_validate(document)


def evidence_state(evidence_id: UUID, memory_id: UUID) -> EvidenceState:
    return EvidenceState(
        evidence_id=evidence_id,
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        memory_id=memory_id,
        source_type="fixture",
        source_reference={"ref": str(evidence_id)},
        excerpt="Synthetic evidence excerpt.",
        occurred_at=NOW,
        content_sha256="cd" * 32,
        trust_classification="verified_fixture",
        status="active",
        created_at=NOW,
        metadata={},
    )


def _event_row(event: DomainMemoryEvent) -> MemoryEvent:
    return MemoryEvent(
        sequence=event.sequence,
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        lineage_id=event.lineage_id,
        branch_id=event.branch_id,
        actor_id=event.actor_id,
        client_id=event.client_id,
        transport_binding_id=event.transport_binding_id,
        session_id=event.session_id,
        ingress_id=event.ingress_id,
        operation=event.operation.value,
        memory_id=event.memory_id,
        expected_revision=event.expected_revision,
        causation_event_id=event.causation_event_id,
        correlation_id=event.correlation_id,
        idempotency_key=event.idempotency_key,
        schema_version=event.schema_version,
        payload_version=event.payload_version,
        policy_version=event.policy_version,
        normalization_version=event.normalization_version,
        payload=dict(event.payload),
        payload_canonical=base64.b64decode(event.payload_canonical),
        payload_sha256=bytes.fromhex(event.payload_sha256.upper()),
        command_sha256=bytes.fromhex(event.command_sha256.upper()),
        created_at=event.created_at,
    )


def _history_with_all_children() -> list[DomainMemoryEvent]:
    first_memory = memory_state(memory_id=uid(10))
    second_memory = changed_memory(
        memory_state(memory_id=uid(12)),
        normalized_fingerprint="ef" * 32,
    )
    evidence = evidence_state(uid(50), first_memory.memory_id)
    link = LinkState(
        link_id=uid(60),
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        source_memory_id=first_memory.memory_id,
        target_memory_id=second_memory.memory_id,
        link_type=LinkType.CONTRADICTS,
        status="active",
        created_at=NOW,
        unlinked_at=None,
        metadata={"kind": "fixture"},
    )
    first_disputed = changed_memory(
        first_memory,
        revision=2,
        status=MemoryStatus.DISPUTED,
        updated_at=LATER,
    )
    second_disputed = changed_memory(
        second_memory,
        revision=2,
        status=MemoryStatus.DISPUTED,
        updated_at=LATER,
    )
    conflict = ConflictState(
        conflict_id=uid(70),
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        subject_id=first_memory.subject_id,
        status="open",
        reason="synthetic_conflict",
        resolution_kind=None,
        resolution_rationale=None,
        opened_at=LATER,
        resolved_at=None,
        metadata={"fixture": True},
    )
    open_members = (
        ConflictMemberState(
            conflict_id=conflict.conflict_id,
            memory_id=first_memory.memory_id,
            disposition="unresolved",
            joined_at=LATER,
        ),
        ConflictMemberState(
            conflict_id=conflict.conflict_id,
            memory_id=second_memory.memory_id,
            disposition="unresolved",
            joined_at=LATER,
        ),
    )
    unlinked = link.model_copy(update={"status": "unlinked", "unlinked_at": UNLINKED_AT})
    first_resolved = changed_memory(
        first_disputed,
        revision=3,
        status=MemoryStatus.ACTIVE,
        updated_at=RESOLVED_AT,
    )
    second_resolved = changed_memory(
        second_disputed,
        revision=3,
        status=MemoryStatus.RETIRED,
        updated_at=RESOLVED_AT,
    )
    resolved_conflict = conflict.model_copy(
        update={
            "status": "resolved",
            "resolution_kind": "first_preferred",
            "resolution_rationale": "Synthetic resolution.",
            "resolved_at": RESOLVED_AT,
        }
    )
    resolved_members = (
        open_members[0].model_copy(update={"disposition": "preferred"}),
        open_members[1].model_copy(update={"disposition": "retired"}),
    )
    return [
        branch_event(),
        remembered_event(first_memory, sequence=2),
        remembered_event(second_memory, sequence=3),
        make_event(
            sequence=4,
            operation=EventOperation.EVIDENCE_ATTACHED,
            payload=EvidenceAttachedPayload(evidence=evidence),
            memory_id=first_memory.memory_id,
        ),
        make_event(
            sequence=5,
            operation=EventOperation.LINKED,
            payload=LinkedPayload(link=link),
            memory_id=None,
        ),
        make_event(
            sequence=6,
            operation=EventOperation.CONFLICT_OPENED,
            payload=ConflictOpenedPayload(
                conflict=conflict,
                members=open_members,
                affected_memories=(
                    AffectedMemory(previous_revision=1, memory=first_disputed),
                    AffectedMemory(previous_revision=1, memory=second_disputed),
                ),
            ),
            memory_id=None,
            created_at=LATER,
        ),
        make_event(
            sequence=7,
            operation=EventOperation.UNLINKED,
            payload=UnlinkedPayload(link=unlinked),
            memory_id=None,
            created_at=UNLINKED_AT,
        ),
        make_event(
            sequence=8,
            operation=EventOperation.CONFLICT_RESOLVED,
            payload=ConflictResolvedPayload(
                conflict=resolved_conflict,
                members=resolved_members,
                affected_memories=(
                    AffectedMemory(previous_revision=2, memory=first_resolved),
                    AffectedMemory(previous_revision=2, memory=second_resolved),
                ),
            ),
            memory_id=None,
            created_at=RESOLVED_AT,
        ),
    ]


class _ScalarResult:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def scalars(self) -> _ScalarResult:
        return self

    def all(self) -> list[object]:
        return self._rows

    def scalar_one_or_none(self) -> object | None:
        if not self._rows:
            return None
        if len(self._rows) != 1:
            raise AssertionError("fixture expected at most one scalar")
        return self._rows[0]


class _FakeSession:
    def __init__(
        self,
        event_rows: list[MemoryEvent],
        *,
        branch_rows: list[Branch] | None = None,
        fail_branch_load: bool = False,
        active: bool = True,
    ) -> None:
        self.event_rows = event_rows
        self.branch_rows = [] if branch_rows is None else branch_rows
        self.fail_branch_load = fail_branch_load
        self.active = active
        self.statements: list[object] = []
        self.added_batches: list[tuple[object, ...]] = []
        self.flush_count = 0

    def in_transaction(self) -> bool:
        return self.active

    async def execute(self, statement: object) -> _ScalarResult:
        self.statements.append(statement)
        if isinstance(statement, Select):
            entity = statement.column_descriptions[0].get("entity")
            if entity is MemoryEvent:
                return _ScalarResult(cast(list[object], self.event_rows))
            if entity is Branch:
                if self.fail_branch_load:
                    raise SQLAlchemyError("untrusted branch query detail")
                return _ScalarResult(cast(list[object], self.branch_rows))
        return _ScalarResult([])

    def add_all(self, rows: Any) -> None:
        self.added_batches.append(tuple(rows))

    async def flush(self) -> None:
        self.flush_count += 1


class _QueuedSession:
    def __init__(self, result_rows: list[list[object]]) -> None:
        self.result_rows = result_rows
        self.statements: list[object] = []

    async def execute(self, statement: object) -> _ScalarResult:
        self.statements.append(statement)
        return _ScalarResult(self.result_rows.pop(0))


class _FailingSession:
    async def execute(self, statement: object) -> _ScalarResult:
        raise SQLAlchemyError("untrusted database detail")


def test_event_row_conversion_verifies_raw_bytes_and_lowercase_hashes() -> None:
    event = branch_event()
    converted = event_row_to_domain(_event_row(event))

    assert converted == event
    assert converted.payload_canonical == event.payload_canonical
    assert converted.payload_sha256 == event.payload_sha256.lower()
    assert converted.command_sha256 == event.command_sha256.lower()

    corrupted = _event_row(event)
    corrupted.payload_sha256 = bytes(32)
    with pytest.raises(ProjectionPersistenceError, match=r"^invalid_event$") as caught:
        event_row_to_domain(corrupted)
    assert caught.value.__suppress_context__ is True


def test_projection_rows_map_all_children_and_operational_provenance() -> None:
    events = _history_with_all_children()
    state = rebuild(events)
    rows = build_projection_rows(state, events)

    assert [row.branch_id for row in rows.branches] == [BRANCH_ID]
    assert rows.branches[0].visibility_ceiling == "private_root"
    assert [row.memory_id for row in rows.memories] == [uid(10), uid(12)]
    assert {row.last_event_id for row in rows.memories} == {events[7].event_id}
    assert rows.memories[0].normalized_fingerprint == bytes.fromhex("ab" * 32)
    assert rows.memories[0].metadata_ == {"fixture": True}
    assert len(rows.evidence) == 1
    assert rows.evidence[0].source_event_id == events[3].event_id
    assert rows.evidence[0].content_sha256 == bytes.fromhex("cd" * 32)
    assert len(rows.links) == 1
    assert rows.links[0].created_event_id == events[4].event_id
    assert rows.links[0].unlinked_event_id == events[6].event_id
    assert rows.links[0].status == "unlinked"
    assert len(rows.conflicts) == 1
    assert rows.conflicts[0].opened_event_id == events[5].event_id
    assert rows.conflicts[0].resolution_event_id == events[7].event_id
    assert [row.memory_id for row in rows.conflict_members] == [uid(10), uid(12)]
    assert {row.last_event_id for row in rows.conflict_members} == {events[7].event_id}


def test_branch_rows_are_ordered_root_before_child() -> None:
    memory = memory_state()
    events = [branch_event(), remembered_event(memory), child_branch_event()]

    rows = build_projection_rows(rebuild(events), events)

    assert [row.branch_id for row in rows.branches] == [BRANCH_ID, uid(13)]
    assert rows.branches[1].parent_branch_id == BRANCH_ID
    assert rows.branches[1].fork_event_sequence == 2


def test_projection_mapping_is_deterministic_and_canonical_round_trips() -> None:
    events = _history_with_all_children()
    state = rebuild(events)
    reversed_state = ProjectionState(
        sequence=state.sequence,
        memories=dict(reversed(tuple(state.memories.items()))),
        evidence=dict(reversed(tuple(state.evidence.items()))),
        links=dict(reversed(tuple(state.links.items()))),
        conflicts=dict(reversed(tuple(state.conflicts.items()))),
        conflict_members=dict(reversed(tuple(state.conflict_members.items()))),
        branches=state.branches,
        event_scopes=state.event_scopes,
        sequence_scopes=state.sequence_scopes,
    )

    first = build_projection_rows(state, events)
    second = build_projection_rows(reversed_state, events)
    assert [row.memory_id for row in first.memories] == [row.memory_id for row in second.memories]
    assert [row.memory_id for row in first.conflict_members] == [
        row.memory_id for row in second.conflict_members
    ]
    assert canonical_aggregate_bytes_from_rows(
        first.memories[0],
        evidence=first.evidence,
        links=first.links,
        conflicts=first.conflicts,
        conflict_members=first.conflict_members,
    ) == canonical_aggregate_bytes(state, uid(10))


@pytest.mark.asyncio
async def test_loader_reconstructs_the_same_canonical_aggregate_bytes() -> None:
    events = _history_with_all_children()
    state = rebuild(events)
    rows = build_projection_rows(state, events)
    memory = rows.memories[0]
    session = _QueuedSession(
        [
            [memory],
            list(rows.evidence),
            list(rows.links),
            [rows.conflicts[0].conflict_id],
            list(rows.conflicts),
            list(rows.conflict_members),
        ]
    )

    loaded = await load_canonical_aggregate_bytes(
        cast(Any, session),
        tenant_id=memory.tenant_id,
        memory_id=memory.memory_id,
    )

    assert loaded == canonical_aggregate_bytes(state, memory.memory_id)
    assert session.result_rows == []


@pytest.mark.asyncio
async def test_loader_suppresses_database_diagnostics() -> None:
    with pytest.raises(ProjectionPersistenceError, match=r"^aggregate_load_failed$") as caught:
        await load_canonical_aggregate_bytes(
            cast(Any, _FailingSession()),
            tenant_id=TENANT_ID,
            memory_id=MEMORY_ID,
        )

    assert caught.value.__suppress_context__ is True


def test_tombstone_maps_sanitized_nullable_content() -> None:
    original = memory_state()
    tombstone = changed_memory(
        original,
        revision=2,
        status=MemoryStatus.TOMBSTONED,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        normalized_fingerprint=None,
        updated_at=LATER,
    )
    tombstone_event = make_event(
        sequence=3,
        operation=EventOperation.TOMBSTONED,
        payload=TombstonedPayload(
            previous_revision=1,
            memory=tombstone,
            forget_mode="logical",
        ),
        memory_id=original.memory_id,
        expected_revision=1,
        created_at=LATER,
    )
    events = [branch_event(), remembered_event(original), tombstone_event]

    row = build_projection_rows(rebuild(events), events).memories[0]

    assert row.status == "tombstoned"
    assert row.statement is None
    assert row.reason_to_remember is None
    assert row.interpretation_limits == []
    assert row.normalized_fingerprint is None
    assert row.last_event_id == tombstone_event.event_id


def test_redacted_evidence_is_absent_from_projection_rows() -> None:
    memory = memory_state()
    evidence = evidence_state(uid(50), memory.memory_id)
    redacted = make_event(
        sequence=4,
        operation=EventOperation.EVIDENCE_REDACTED,
        payload=EvidenceRedactedPayload(
            evidence_id=evidence.evidence_id,
            memory_id=memory.memory_id,
            redacted_at=LATER,
            reason_code="fixture_cleanup",
        ),
        memory_id=memory.memory_id,
        created_at=LATER,
    )
    events = [
        branch_event(),
        remembered_event(memory),
        make_event(
            sequence=3,
            operation=EventOperation.EVIDENCE_ATTACHED,
            payload=EvidenceAttachedPayload(evidence=evidence),
            memory_id=memory.memory_id,
        ),
        redacted,
    ]

    rows = build_projection_rows(rebuild(events), events)

    assert rows.evidence == ()


def test_hard_tombstone_purge_maps_cryptographic_erasure() -> None:
    key_id = uid(90)
    protected = changed_memory(
        memory_state(),
        content_protection="envelope_encrypted",
        content_key_id=key_id,
    )
    tombstone = changed_memory(
        protected,
        revision=2,
        status=MemoryStatus.TOMBSTONED,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        normalized_fingerprint=None,
        updated_at=LATER,
    )
    tombstone_event = make_event(
        sequence=3,
        operation=EventOperation.TOMBSTONED,
        payload=TombstonedPayload(
            previous_revision=1,
            memory=tombstone,
            forget_mode="hard",
        ),
        memory_id=protected.memory_id,
        expected_revision=1,
        created_at=LATER,
    )
    purged_at = LATER + timedelta(seconds=1)
    erased = changed_memory(
        tombstone,
        revision=3,
        content_protection="cryptographically_erased",
        updated_at=purged_at,
    )
    purge_event = make_event(
        sequence=4,
        operation=EventOperation.PAYLOAD_PURGE_COMPLETED,
        payload=PayloadPurgeCompletedPayload(
            previous_revision=2,
            memory=erased,
            content_key_id=key_id,
            key_destroyed_at=purged_at,
            destruction_receipt_sha256="01" * 32,
        ),
        memory_id=protected.memory_id,
        expected_revision=2,
        created_at=purged_at,
    )
    events = [branch_event(), remembered_event(protected), tombstone_event, purge_event]

    row = build_projection_rows(rebuild(events), events).memories[0]

    assert row.status == "tombstoned"
    assert row.content_protection == "cryptographically_erased"
    assert row.content_key_id == key_id
    assert row.statement is None
    assert row.last_event_id == purge_event.event_id


@pytest.mark.asyncio
async def test_rebuild_replaces_only_projection_tables_in_fk_safe_order() -> None:
    events = _history_with_all_children()
    session = _FakeSession([_event_row(event) for event in events])

    state = await rebuild_semantic_projections(cast(Any, session))

    deletes = [statement for statement in session.statements if isinstance(statement, Delete)]
    assert [cast(Any, statement.table).name for statement in deletes] == [
        "memory_conflict_members",
        "memory_conflicts",
        "memory_links",
        "memory_evidence",
        "memories",
    ]
    assert session.flush_count == 4
    assert [len(batch) for batch in session.added_batches] == [1, 2, 3, 2]
    assert isinstance(session.added_batches[0][0], Branch)
    assert state.sequence == 8


@pytest.mark.asyncio
async def test_rebuild_inserts_missing_branches_parent_first() -> None:
    memory = memory_state()
    events = [branch_event(), remembered_event(memory), child_branch_event()]
    session = _FakeSession([_event_row(event) for event in events])

    await rebuild_semantic_projections(cast(Any, session))

    assert [row.branch_id for row in cast(tuple[Branch, ...], session.added_batches[0])] == [
        BRANCH_ID,
        uid(13),
    ]


@pytest.mark.asyncio
async def test_rebuild_validates_existing_branch_without_replacing_it() -> None:
    events = _history_with_all_children()
    projected = build_projection_rows(rebuild(events), events)
    session = _FakeSession(
        [_event_row(event) for event in events],
        branch_rows=list(projected.branches),
    )

    await rebuild_semantic_projections(cast(Any, session))

    assert session.flush_count == 3
    assert [len(batch) for batch in session.added_batches] == [2, 3, 2]
    assert all(not isinstance(row, Branch) for batch in session.added_batches for row in batch)


@pytest.mark.asyncio
async def test_branch_mismatch_fails_before_semantic_delete() -> None:
    events = [branch_event()]
    projected = build_projection_rows(rebuild(events), events).branches[0]
    mismatched = Branch(
        branch_id=projected.branch_id,
        tenant_id=projected.tenant_id,
        lineage_id=projected.lineage_id,
        parent_branch_id=projected.parent_branch_id,
        fork_event_sequence=projected.fork_event_sequence,
        name="wrong",
        visibility_ceiling=projected.visibility_ceiling,
        created_at=projected.created_at,
        sealed_at=projected.sealed_at,
    )
    session = _FakeSession([_event_row(events[0])], branch_rows=[mismatched])

    with pytest.raises(ProjectionPersistenceError, match=r"^branch_projection_mismatch$"):
        await rebuild_semantic_projections(cast(Any, session))

    assert not any(isinstance(statement, Delete) for statement in session.statements)
    assert session.added_batches == []
    assert session.flush_count == 0


@pytest.mark.asyncio
async def test_extra_branch_fails_before_semantic_delete() -> None:
    extra = Branch(
        branch_id=BRANCH_ID,
        tenant_id=TENANT_ID,
        lineage_id=LINEAGE_ID,
        parent_branch_id=None,
        fork_event_sequence=None,
        name="extra",
        visibility_ceiling="private_root",
        created_at=NOW,
        sealed_at=None,
    )
    session = _FakeSession([], branch_rows=[extra])

    with pytest.raises(ProjectionPersistenceError, match=r"^branch_projection_extra$"):
        await rebuild_semantic_projections(cast(Any, session))

    assert not any(isinstance(statement, Delete) for statement in session.statements)
    assert session.added_batches == []
    assert session.flush_count == 0


@pytest.mark.asyncio
async def test_branch_load_failure_is_sanitized_before_semantic_delete() -> None:
    event = branch_event()
    session = _FakeSession([_event_row(event)], fail_branch_load=True)

    with pytest.raises(
        ProjectionPersistenceError,
        match=r"^branch_projection_load_failed$",
    ) as caught:
        await rebuild_semantic_projections(cast(Any, session))

    assert caught.value.__suppress_context__ is True
    assert not any(isinstance(statement, Delete) for statement in session.statements)
    assert session.added_batches == []
    assert session.flush_count == 0


@pytest.mark.asyncio
async def test_tenant_rebuild_accepts_global_sequence_gaps_and_scopes_deletes() -> None:
    memory = memory_state()
    events = [branch_event(), remembered_event(memory, sequence=3)]
    session = _FakeSession([_event_row(event) for event in events])

    state = await rebuild_semantic_projections(
        cast(Any, session),
        tenant_id=memory.tenant_id,
    )

    assert state.sequence == 3
    assert cast(Any, session.statements[0]).whereclause is not None
    assert cast(Any, session.statements[1]).whereclause is not None
    deletes = [statement for statement in session.statements if isinstance(statement, Delete)]
    assert len(deletes) == 5
    assert all(cast(Any, statement).whereclause is not None for statement in deletes)


@pytest.mark.asyncio
async def test_invalid_event_fails_before_any_projection_delete() -> None:
    invalid = _event_row(branch_event())
    invalid.payload_sha256 = bytes(32)
    session = _FakeSession([invalid])

    with pytest.raises(ProjectionPersistenceError, match=r"^invalid_event$"):
        await rebuild_semantic_projections(cast(Any, session))

    assert len(session.statements) == 1
    assert isinstance(session.statements[0], Select)
    assert session.added_batches == []
    assert session.flush_count == 0


@pytest.mark.asyncio
async def test_rebuild_requires_callers_existing_transaction() -> None:
    session = _FakeSession([], active=False)

    with pytest.raises(ProjectionPersistenceError, match="active_transaction_required"):
        await rebuild_semantic_projections(cast(Any, session), tenant_id=uid(1))

    assert session.statements == []
