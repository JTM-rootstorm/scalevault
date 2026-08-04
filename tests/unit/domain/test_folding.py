from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest
from kivra_memory.domain.enums import (
    EventOperation,
    LinkType,
    MemoryStatus,
    MemoryVisibility,
)
from kivra_memory.domain.events import (
    AffectedMemory,
    BranchCreatedPayload,
    BranchState,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictState,
    EvidenceAttachedPayload,
    EvidenceRedactedPayload,
    EvidenceState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    PayloadPurgeCompletedPayload,
    TombstonedPayload,
)
from kivra_memory.domain.folding import (
    FoldError,
    ProjectionState,
    TenantReplayState,
    canonical_aggregate_bytes,
    fold_event,
    fold_tenant_event,
    rebuild,
    rebuild_tenant,
)

from .test_events import NOW, make_event, memory_state, uid

LATER = NOW + timedelta(seconds=1)


def changed_memory(memory: MemoryState, **changes: object) -> MemoryState:
    document = memory.model_dump(mode="python")
    document.update(changes)
    return MemoryState.model_validate(document)


def branch_event(
    *,
    sequence: int = 1,
    tenant_id: UUID | None = None,
    lineage_id: UUID | None = None,
    branch_id: UUID | None = None,
) -> MemoryEvent:
    resolved_tenant_id = uid(1) if tenant_id is None else tenant_id
    resolved_lineage_id = uid(2) if lineage_id is None else lineage_id
    resolved_branch_id = uid(3) if branch_id is None else branch_id
    branch = BranchState(
        branch_id=resolved_branch_id,
        tenant_id=resolved_tenant_id,
        lineage_id=resolved_lineage_id,
        parent_branch_id=None,
        fork_event_sequence=None,
        name="root",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=NOW,
        sealed_at=None,
    )
    return make_event(
        sequence=sequence,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=branch),
        memory_id=None,
        branch_id=resolved_branch_id,
        tenant_id=resolved_tenant_id,
        lineage_id=resolved_lineage_id,
    )


def remembered_event(memory: MemoryState, *, sequence: int = 2) -> MemoryEvent:
    return make_event(
        sequence=sequence,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
        branch_id=memory.branch_id,
        tenant_id=memory.tenant_id,
        lineage_id=memory.lineage_id,
    )


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


def test_revision_fold_is_pure_and_rebuild_is_byte_equivalent() -> None:
    initial = memory_state()
    first = branch_event()
    second = remembered_event(initial)
    after = changed_memory(
        initial,
        revision=2,
        statement="The synthetic project uses a revised stable test floor.",
        updated_at=LATER,
    )
    third = make_event(
        sequence=3,
        operation=EventOperation.REVISED,
        payload=MemoryTransitionPayload(previous_revision=1, memory=after),
        memory_id=initial.memory_id,
        expected_revision=1,
        created_at=LATER,
    )

    before_revision = rebuild([first, second])
    incremental = fold_event(before_revision, third)
    rebuilt = rebuild([first, second, third])

    assert before_revision.memories[initial.memory_id].revision == 1
    assert incremental.memories[initial.memory_id].revision == 2
    assert canonical_aggregate_bytes(incremental, initial.memory_id) == canonical_aggregate_bytes(
        rebuilt, initial.memory_id
    )


def test_fold_rejects_sequence_gap_and_stale_revision() -> None:
    initial = memory_state()
    state = rebuild([branch_event(), remembered_event(initial)])
    after = changed_memory(initial, revision=2, updated_at=LATER)
    gap = make_event(
        sequence=4,
        operation=EventOperation.REVISED,
        payload=MemoryTransitionPayload(previous_revision=1, memory=after),
        memory_id=initial.memory_id,
        expected_revision=1,
        created_at=LATER,
    )

    with pytest.raises(FoldError, match="sequence_gap"):
        fold_event(state, gap)

    stale = make_event(
        sequence=3,
        operation=EventOperation.REVISED,
        payload=MemoryTransitionPayload(previous_revision=2, memory=after),
        memory_id=initial.memory_id,
        expected_revision=2,
        created_at=LATER,
    )
    with pytest.raises(FoldError, match="stale_event_revision"):
        fold_event(state, stale)


def test_fold_reuses_event_envelope_validation_for_unvalidated_copies() -> None:
    state = fold_event(ProjectionState(), branch_event())
    remembered = remembered_event(memory_state())
    invalid = remembered.model_copy(update={"expected_revision": 1})

    with pytest.raises(FoldError, match="invalid_envelope"):
        fold_event(state, invalid)


def test_tenant_replay_accepts_interleaved_global_gaps_without_weakening_global_fold() -> None:
    tenant_a = uid(1)
    tenant_b = uid(201)
    tenant_a_branch = branch_event(sequence=1, tenant_id=tenant_a)
    tenant_b_branch = branch_event(
        sequence=2,
        tenant_id=tenant_b,
        lineage_id=uid(202),
        branch_id=uid(203),
    )
    tenant_a_memory = memory_state(tenant_id=tenant_a)
    tenant_a_remembered = remembered_event(tenant_a_memory, sequence=3)

    global_state = rebuild([tenant_a_branch, tenant_b_branch, tenant_a_remembered])
    assert global_state.sequence == 3

    tenant_a_state = rebuild_tenant(tenant_a, [tenant_a_branch, tenant_a_remembered])
    tenant_b_state = rebuild_tenant(tenant_b, [tenant_b_branch])
    assert tenant_a_state.projection.sequence == 3
    assert tenant_a_memory.memory_id in tenant_a_state.projection.memories
    assert tenant_b_state.projection.sequence == 2
    assert all(scope[0] == tenant_a for scope in tenant_a_state.projection.event_scopes.values())

    with pytest.raises(FoldError, match="sequence_gap"):
        rebuild([tenant_a_branch, tenant_a_remembered])


def test_tenant_replay_rejects_scope_drift_and_non_increasing_global_sequence() -> None:
    tenant_a = uid(1)
    tenant_b_event = branch_event(
        sequence=2,
        tenant_id=uid(201),
        lineage_id=uid(202),
        branch_id=uid(203),
    )
    empty = TenantReplayState(tenant_id=tenant_a)

    with pytest.raises(FoldError, match="tenant_scope_mismatch"):
        fold_tenant_event(empty, tenant_b_event)

    tenant_a_branch = branch_event(sequence=1, tenant_id=tenant_a)
    tenant_a_memory = memory_state(tenant_id=tenant_a)
    tenant_a_remembered = remembered_event(tenant_a_memory, sequence=3)
    replayed = rebuild_tenant(tenant_a, [tenant_a_branch, tenant_a_remembered])

    with pytest.raises(FoldError, match="sequence_not_increasing"):
        fold_tenant_event(replayed, tenant_a_branch)


def test_child_branch_fork_must_reference_parent_branch_event() -> None:
    root = branch_event()
    child_id = uid(80)
    child = BranchState(
        branch_id=child_id,
        tenant_id=uid(1),
        lineage_id=uid(2),
        parent_branch_id=uid(3),
        fork_event_sequence=1,
        name="child",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=LATER,
        sealed_at=None,
    )
    valid = make_event(
        sequence=2,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=child),
        memory_id=None,
        branch_id=child_id,
        created_at=LATER,
    )
    assert fold_event(rebuild([root]), valid).branches[child_id] == child

    invalid_child = child.model_copy(update={"fork_event_sequence": 2})
    invalid = make_event(
        sequence=2,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=invalid_child),
        memory_id=None,
        branch_id=child_id,
        created_at=LATER,
    )
    with pytest.raises(FoldError, match="invalid_fork_sequence"):
        fold_event(rebuild([root]), invalid)


def test_memory_visibility_cannot_exceed_branch_ceiling() -> None:
    memory = changed_memory(memory_state(), visibility=MemoryVisibility.RESTRICTED)
    event = remembered_event(memory)

    with pytest.raises(FoldError, match="branch_visibility_forbidden"):
        fold_event(rebuild([branch_event()]), event)


def test_evidence_is_sorted_in_aggregate_and_redaction_deletes_projection() -> None:
    memory = memory_state()
    first = branch_event()
    second = remembered_event(memory)
    low = evidence_state(uid(50), memory.memory_id)
    high = evidence_state(uid(51), memory.memory_id)

    low_event = make_event(
        sequence=3,
        operation=EventOperation.EVIDENCE_ATTACHED,
        payload=EvidenceAttachedPayload(evidence=low),
        memory_id=memory.memory_id,
    )
    high_event = make_event(
        sequence=4,
        operation=EventOperation.EVIDENCE_ATTACHED,
        payload=EvidenceAttachedPayload(evidence=high),
        memory_id=memory.memory_id,
    )
    reversed_high = high_event.model_copy(update={"sequence": 3, "event_id": uid(103)})
    reversed_low = low_event.model_copy(update={"sequence": 4, "event_id": uid(104)})

    ordered = rebuild([first, second, low_event, high_event])
    reversed_state = rebuild([first, second, reversed_high, reversed_low])
    assert canonical_aggregate_bytes(ordered, memory.memory_id) == canonical_aggregate_bytes(
        reversed_state, memory.memory_id
    )

    redacted = make_event(
        sequence=5,
        operation=EventOperation.EVIDENCE_REDACTED,
        payload=EvidenceRedactedPayload(
            evidence_id=low.evidence_id,
            memory_id=memory.memory_id,
            redacted_at=LATER,
            reason_code="fixture_cleanup",
        ),
        memory_id=memory.memory_id,
        created_at=LATER,
    )
    after_redaction = fold_event(ordered, redacted)
    assert low.evidence_id not in after_redaction.evidence


def test_tombstone_requires_evidence_to_be_redacted_first() -> None:
    memory = memory_state()
    evidence = evidence_state(uid(50), memory.memory_id)
    attached = make_event(
        sequence=3,
        operation=EventOperation.EVIDENCE_ATTACHED,
        payload=EvidenceAttachedPayload(evidence=evidence),
        memory_id=memory.memory_id,
    )
    state = rebuild([branch_event(), remembered_event(memory), attached])
    tombstone = changed_memory(
        memory,
        revision=2,
        status=MemoryStatus.TOMBSTONED,
        statement=None,
        reason_to_remember=None,
        interpretation_limits=(),
        normalized_fingerprint=None,
        updated_at=LATER,
    )
    event = make_event(
        sequence=4,
        operation=EventOperation.TOMBSTONED,
        payload=TombstonedPayload(previous_revision=1, memory=tombstone, forget_mode="logical"),
        memory_id=memory.memory_id,
        expected_revision=1,
        created_at=LATER,
    )

    with pytest.raises(FoldError, match="unsanitized_tombstone"):
        fold_event(state, event)


def test_hard_tombstone_and_purge_keep_only_safe_key_metadata() -> None:
    key_id = uid(90)
    protected = changed_memory(
        memory_state(), content_protection="envelope_encrypted", content_key_id=key_id
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
        payload=TombstonedPayload(previous_revision=1, memory=tombstone, forget_mode="hard"),
        memory_id=protected.memory_id,
        expected_revision=1,
        created_at=LATER,
    )
    tombstoned_state = rebuild([branch_event(), remembered_event(protected), tombstone_event])

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
            destruction_receipt_sha256="ef" * 32,
        ),
        memory_id=protected.memory_id,
        expected_revision=2,
        created_at=purged_at,
    )

    final = fold_event(tombstoned_state, purge_event)
    assert final.memories[protected.memory_id].content_protection == "cryptographically_erased"
    assert final.memories[protected.memory_id].statement is None


def test_link_and_conflict_children_are_derived_and_exported() -> None:
    first_memory = memory_state(memory_id=uid(10))
    second_memory = memory_state(memory_id=uid(12))
    history = [
        branch_event(),
        remembered_event(first_memory, sequence=2),
        remembered_event(second_memory, sequence=3),
    ]
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
        metadata={},
    )
    history.append(
        make_event(
            sequence=4,
            operation=EventOperation.LINKED,
            payload=LinkedPayload(link=link),
            memory_id=None,
        )
    )
    first_disputed = changed_memory(
        first_memory, revision=2, status=MemoryStatus.DISPUTED, updated_at=LATER
    )
    second_disputed = changed_memory(
        second_memory, revision=2, status=MemoryStatus.DISPUTED, updated_at=LATER
    )
    conflict = ConflictState(
        conflict_id=uid(70),
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        subject_id=first_memory.subject_id,
        status="open",
        reason="fixture_contradiction",
        resolution_kind=None,
        resolution_rationale=None,
        opened_at=LATER,
        resolved_at=None,
        metadata={},
    )
    members = (
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
    history.append(
        make_event(
            sequence=5,
            operation=EventOperation.CONFLICT_OPENED,
            payload=ConflictOpenedPayload(
                conflict=conflict,
                members=members,
                affected_memories=(
                    AffectedMemory(previous_revision=1, memory=first_disputed),
                    AffectedMemory(previous_revision=1, memory=second_disputed),
                ),
            ),
            memory_id=None,
            created_at=LATER,
        )
    )

    state = rebuild(history)
    aggregate = canonical_aggregate_bytes(state, first_memory.memory_id)
    assert link.link_id in state.links
    assert conflict.conflict_id in state.conflicts
    assert aggregate.count(b'"conflict_id"') == 3


def test_projection_mappings_cannot_be_mutated() -> None:
    state = ProjectionState()
    with pytest.raises(TypeError):
        state.memories[uid(10)] = memory_state()  # type: ignore[index]
