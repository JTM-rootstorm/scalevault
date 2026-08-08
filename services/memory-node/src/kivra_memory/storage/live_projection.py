"""Transactional live-projection loading, validation, and incremental persistence.

The helpers in this module never begin or commit a transaction.  Direct-command
handlers insert their immutable event first, then stage its validated after-images
in the same caller-owned transaction.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import cast
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.events import (
    BranchState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    TombstonedPayload,
)
from kivra_memory.domain.folding import ProjectionState, fold_event
from kivra_memory.storage.models import (
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryEvidence,
    MemoryLink,
)
from kivra_memory.storage.models import (
    MemoryEvent as MemoryEventRow,
)
from kivra_memory.storage.projector import (
    ProjectionPersistenceError,
    conflict_member_row_to_state,
    conflict_row_to_state,
    evidence_row_to_state,
    link_row_to_state,
    link_state_to_row,
    memory_row_to_state,
    memory_state_to_row,
)
from kivra_memory.storage.transactions import database_sqlstate


def _raise_serialization_failure(error: SQLAlchemyError) -> None:
    if isinstance(error, DBAPIError) and database_sqlstate(error) == "40001":
        raise error


def _sorted_ids(values: Iterable[UUID]) -> tuple[UUID, ...]:
    return tuple(sorted(set(values), key=str))


def _targets(event: MemoryEvent) -> tuple[tuple[UUID, ...], UUID | None, UUID | None]:
    """Return memory, link, and conflict identifiers required by the reducer."""

    payload = event.typed_payload()
    memory_ids: set[UUID] = set()
    link_id: UUID | None = None
    conflict_id: UUID | None = None
    if isinstance(payload, MemoryCreatedPayload | MemoryTransitionPayload):
        memory_ids.add(payload.memory.memory_id)
    elif isinstance(payload, LinkedPayload):
        link_id = payload.link.link_id
        memory_ids.update((payload.link.source_memory_id, payload.link.target_memory_id))
    elif isinstance(payload, ConflictOpenedPayload | ConflictResolvedPayload):
        conflict_id = payload.conflict.conflict_id
        memory_ids.update(change.memory.memory_id for change in payload.affected_memories)
        memory_ids.update(member.memory_id for member in payload.members)
    return _sorted_ids(memory_ids), link_id, conflict_id


async def load_projection_state_for_update(
    session: AsyncSession,
    *,
    event: MemoryEvent,
    branch: BranchState,
) -> ProjectionState:
    """Lock and load the minimal current projection needed to fold ``event``.

    Multi-row locks are acquired in UUID order.  Conversion failures are reduced
    to stable codes so invalid stored content cannot escape through diagnostics.
    """

    if not session.in_transaction():
        raise ProjectionPersistenceError("active_transaction_required")
    if (
        branch.tenant_id,
        branch.lineage_id,
        branch.branch_id,
    ) != (event.tenant_id, event.lineage_id, event.branch_id):
        raise ProjectionPersistenceError("branch_scope_mismatch")

    memory_ids, link_id, conflict_id = _targets(event)
    try:
        memories: list[Memory] = []
        if memory_ids:
            result = await session.execute(
                select(Memory)
                .where(
                    Memory.tenant_id == event.tenant_id,
                    Memory.lineage_id == event.lineage_id,
                    Memory.memory_id.in_(memory_ids),
                )
                .order_by(Memory.memory_id)
                .with_for_update()
            )
            memories = list(result.scalars().all())

        evidence: list[MemoryEvidence] = []
        if isinstance(event.typed_payload(), TombstonedPayload):
            result = await session.execute(
                select(MemoryEvidence)
                .where(
                    MemoryEvidence.tenant_id == event.tenant_id,
                    MemoryEvidence.lineage_id == event.lineage_id,
                    MemoryEvidence.memory_id.in_(memory_ids),
                )
                .order_by(MemoryEvidence.evidence_id)
                .with_for_update()
            )
            evidence = list(cast(Sequence[MemoryEvidence], result.scalars().all()))

        links: list[MemoryLink] = []
        if link_id is not None:
            result = await session.execute(
                select(MemoryLink)
                .where(
                    MemoryLink.tenant_id == event.tenant_id,
                    MemoryLink.lineage_id == event.lineage_id,
                    MemoryLink.link_id == link_id,
                )
                .order_by(MemoryLink.link_id)
                .with_for_update()
            )
            links = list(cast(Sequence[MemoryLink], result.scalars().all()))

        conflicts: list[MemoryConflict] = []
        members: list[MemoryConflictMember] = []
        if conflict_id is not None:
            result = await session.execute(
                select(MemoryConflict)
                .where(
                    MemoryConflict.tenant_id == event.tenant_id,
                    MemoryConflict.lineage_id == event.lineage_id,
                    MemoryConflict.conflict_id == conflict_id,
                )
                .order_by(MemoryConflict.conflict_id)
                .with_for_update()
            )
            conflicts = list(cast(Sequence[MemoryConflict], result.scalars().all()))
            result = await session.execute(
                select(MemoryConflictMember)
                .where(
                    MemoryConflictMember.tenant_id == event.tenant_id,
                    MemoryConflictMember.lineage_id == event.lineage_id,
                    MemoryConflictMember.conflict_id == conflict_id,
                )
                .order_by(MemoryConflictMember.memory_id)
                .with_for_update()
            )
            members = list(cast(Sequence[MemoryConflictMember], result.scalars().all()))

        event_scopes: dict[UUID, tuple[UUID, UUID, UUID]] = {}
        if event.causation_event_id is not None:
            result = await session.execute(
                select(MemoryEventRow).where(
                    MemoryEventRow.event_id == event.causation_event_id,
                    MemoryEventRow.tenant_id == event.tenant_id,
                    MemoryEventRow.lineage_id == event.lineage_id,
                )
            )
            cause = cast(MemoryEventRow | None, result.scalar_one_or_none())
            if cause is not None:
                event_scopes[cause.event_id] = (
                    cause.tenant_id,
                    cause.lineage_id,
                    cause.branch_id,
                )

        memory_states = {row.memory_id: memory_row_to_state(row) for row in memories}
        evidence_states = {row.evidence_id: evidence_row_to_state(row) for row in evidence}
        link_states = {row.link_id: link_row_to_state(row) for row in links}
        conflict_states = {row.conflict_id: conflict_row_to_state(row) for row in conflicts}
        member_states = {
            (row.conflict_id, row.memory_id): conflict_member_row_to_state(row) for row in members
        }
    except SQLAlchemyError as error:
        _raise_serialization_failure(error)
        raise ProjectionPersistenceError("live_projection_load_failed") from None
    except (TypeError, ValueError):
        raise ProjectionPersistenceError("invalid_live_projection") from None

    return ProjectionState(
        sequence=event.sequence - 1,
        memories=memory_states,
        evidence=evidence_states,
        links=link_states,
        conflicts=conflict_states,
        conflict_members=member_states,
        branches={branch.branch_id: branch},
        event_scopes=event_scopes,
    )


def validate_live_event(state: ProjectionState, event: MemoryEvent) -> ProjectionState:
    """Validate and reduce a proposed live event through the canonical reducer."""

    return fold_event(state, event)


def _memory_values(state: MemoryState, event_id: UUID) -> dict[str, object]:
    row = memory_state_to_row(state, last_event_id=event_id)
    return {key: value for key, value in vars(row).items() if key != "_sa_instance_state"}


def _link_values(state: LinkState, event_id: UUID) -> dict[str, object]:
    row = link_state_to_row(state, created_event_id=event_id)
    return {key: value for key, value in vars(row).items() if key != "_sa_instance_state"}


def _conflict_row(state: ConflictState, event_id: UUID) -> MemoryConflict:
    return MemoryConflict(
        conflict_id=state.conflict_id,
        tenant_id=state.tenant_id,
        lineage_id=state.lineage_id,
        branch_id=state.branch_id,
        subject_id=state.subject_id,
        status=state.status,
        reason=state.reason,
        resolution_kind=state.resolution_kind,
        resolution_rationale=state.resolution_rationale,
        opened_event_id=event_id,
        resolution_event_id=None,
        opened_at=state.opened_at,
        resolved_at=state.resolved_at,
        metadata_=dict(state.metadata),
    )


async def stage_live_projection(
    session: AsyncSession,
    *,
    before: ProjectionState,
    after: ProjectionState,
    event: MemoryEvent,
) -> None:
    """Stage one validated event's complete after-images and flush them.

    The immutable event must already be pending or persisted in the caller's
    transaction.  This function neither creates nor commits that transaction.
    """

    if not session.in_transaction():
        raise ProjectionPersistenceError("active_transaction_required")
    memory_ids, link_id, conflict_id = _targets(event)
    payload = event.typed_payload()
    try:
        changed_memory_ids = tuple(
            memory_id
            for memory_id in memory_ids
            if after.memories.get(memory_id) != before.memories.get(memory_id)
        )
        for memory_id in changed_memory_ids:
            memory_state = after.memories.get(memory_id)
            if memory_state is None:
                raise ProjectionPersistenceError("missing_memory_after_image")
            if memory_id not in before.memories:
                session.add(memory_state_to_row(memory_state, last_event_id=event.event_id))
            else:
                values = _memory_values(memory_state, event.event_id)
                await session.execute(
                    update(Memory)
                    .where(
                        Memory.tenant_id == memory_state.tenant_id,
                        Memory.memory_id == memory_state.memory_id,
                    )
                    .values(**values)
                )

        if isinstance(payload, LinkedPayload):
            link_state = after.links.get(link_id) if link_id is not None else None
            if link_state is None:
                raise ProjectionPersistenceError("missing_link_after_image")
            if link_id not in before.links:
                session.add(link_state_to_row(link_state, created_event_id=event.event_id))
            else:
                await session.execute(
                    update(MemoryLink)
                    .where(
                        MemoryLink.tenant_id == link_state.tenant_id,
                        MemoryLink.link_id == link_state.link_id,
                    )
                    .values(**_link_values(link_state, event.event_id))
                )

        if isinstance(payload, ConflictOpenedPayload):
            conflict = after.conflicts.get(conflict_id) if conflict_id is not None else None
            if conflict is None:
                raise ProjectionPersistenceError("missing_conflict_after_image")
            session.add(_conflict_row(conflict, event.event_id))
            for member in sorted(payload.members, key=lambda value: str(value.memory_id)):
                session.add(
                    MemoryConflictMember(
                        tenant_id=conflict.tenant_id,
                        lineage_id=conflict.lineage_id,
                        conflict_id=member.conflict_id,
                        memory_id=member.memory_id,
                        disposition=member.disposition,
                        joined_at=member.joined_at,
                        last_event_id=event.event_id,
                    )
                )

        if isinstance(payload, ConflictResolvedPayload):
            conflict = after.conflicts.get(conflict_id) if conflict_id is not None else None
            if conflict is None:
                raise ProjectionPersistenceError("missing_conflict_after_image")
            await session.execute(
                update(MemoryConflict)
                .where(
                    MemoryConflict.tenant_id == conflict.tenant_id,
                    MemoryConflict.conflict_id == conflict.conflict_id,
                )
                .values(
                    status=conflict.status,
                    reason=conflict.reason,
                    resolution_kind=conflict.resolution_kind,
                    resolution_rationale=conflict.resolution_rationale,
                    resolution_event_id=event.event_id,
                    opened_at=conflict.opened_at,
                    resolved_at=conflict.resolved_at,
                    metadata_=dict(conflict.metadata),
                )
            )
            for member in sorted(payload.members, key=lambda value: str(value.memory_id)):
                await session.execute(
                    update(MemoryConflictMember)
                    .where(
                        MemoryConflictMember.tenant_id == conflict.tenant_id,
                        MemoryConflictMember.conflict_id == member.conflict_id,
                        MemoryConflictMember.memory_id == member.memory_id,
                    )
                    .values(
                        disposition=member.disposition,
                        joined_at=member.joined_at,
                        last_event_id=event.event_id,
                    )
                )
        await session.flush()
    except SQLAlchemyError as error:
        _raise_serialization_failure(error)
        raise ProjectionPersistenceError("live_projection_write_failed") from None
