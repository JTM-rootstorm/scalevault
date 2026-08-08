"""Verified event replay and transactional semantic projection persistence."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

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
    BranchState,
    CandidateLifecyclePayload,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    EvidenceAttachedPayload,
    EvidenceState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryState,
    MemoryStateV2,
    MemoryTransitionPayload,
    SupersededPayload,
    UnlinkedPayload,
)
from kivra_memory.domain.events import MemoryEvent as DomainMemoryEvent
from kivra_memory.domain.folding import (
    ProjectionState,
    canonical_aggregate_bytes,
    rebuild,
    rebuild_tenant,
)
from kivra_memory.storage.models import (
    Branch,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryEvent,
    MemoryEvidence,
    MemoryLink,
)


class ProjectionPersistenceError(RuntimeError):
    """A safe projection persistence failure without memory content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class ProjectionRows:
    """Fully validated replacement rows, ordered deterministically."""

    branches: tuple[Branch, ...]
    memories: tuple[Memory, ...]
    evidence: tuple[MemoryEvidence, ...]
    links: tuple[MemoryLink, ...]
    conflicts: tuple[MemoryConflict, ...]
    conflict_members: tuple[MemoryConflictMember, ...]


@dataclass(frozen=True, slots=True)
class _Provenance:
    memory_last: Mapping[UUID, UUID]
    evidence_source: Mapping[UUID, UUID]
    link_created: Mapping[UUID, UUID]
    link_unlinked: Mapping[UUID, UUID]
    conflict_opened: Mapping[UUID, UUID]
    conflict_resolved: Mapping[UUID, UUID]
    member_last: Mapping[tuple[UUID, UUID], UUID]


def event_row_to_domain(row: MemoryEvent) -> DomainMemoryEvent:
    """Convert and verify one immutable ORM event row."""

    try:
        return DomainMemoryEvent.model_validate(
            {
                "schema_version": row.schema_version,
                "payload_version": row.payload_version,
                "sequence": row.sequence,
                "event_id": row.event_id,
                "tenant_id": row.tenant_id,
                "lineage_id": row.lineage_id,
                "branch_id": row.branch_id,
                "actor_id": row.actor_id,
                "client_id": row.client_id,
                "transport_binding_id": row.transport_binding_id,
                "session_id": row.session_id,
                "ingress_id": row.ingress_id,
                "operation": EventOperation(row.operation),
                "memory_id": row.memory_id,
                "expected_revision": row.expected_revision,
                "causation_event_id": row.causation_event_id,
                "correlation_id": row.correlation_id,
                "idempotency_key": row.idempotency_key,
                "policy_version": row.policy_version,
                "normalization_version": row.normalization_version,
                "payload": dict(row.payload),
                "payload_canonical": base64.b64encode(bytes(row.payload_canonical)).decode("ascii"),
                "payload_sha256": bytes(row.payload_sha256).hex(),
                "command_sha256": bytes(row.command_sha256).hex(),
                "created_at": row.created_at,
            }
        )
    except (TypeError, ValueError):
        raise ProjectionPersistenceError("invalid_event") from None


async def load_verified_events(
    session: AsyncSession,
    *,
    tenant_id: UUID | None = None,
) -> tuple[DomainMemoryEvent, ...]:
    """Load accepted events in increasing global sequence order."""

    statement = select(MemoryEvent).order_by(MemoryEvent.sequence)
    if tenant_id is not None:
        statement = statement.where(MemoryEvent.tenant_id == tenant_id)
    try:
        result = await session.execute(statement)
    except SQLAlchemyError:
        raise ProjectionPersistenceError("event_load_failed") from None
    return tuple(event_row_to_domain(row) for row in result.scalars().all())


def _derive_provenance(events: Sequence[DomainMemoryEvent]) -> _Provenance:
    memory_last: dict[UUID, UUID] = {}
    evidence_source: dict[UUID, UUID] = {}
    link_created: dict[UUID, UUID] = {}
    link_unlinked: dict[UUID, UUID] = {}
    conflict_opened: dict[UUID, UUID] = {}
    conflict_resolved: dict[UUID, UUID] = {}
    member_last: dict[tuple[UUID, UUID], UUID] = {}

    for event in events:
        payload = event.typed_payload()
        if isinstance(payload, MemoryCreatedPayload):
            memory_last[payload.memory.memory_id] = event.event_id
            for evidence in payload.evidence:
                evidence_source[evidence.evidence_id] = event.event_id
        if isinstance(payload, MemoryTransitionPayload):
            memory_last[payload.memory.memory_id] = event.event_id
        if isinstance(payload, CandidateLifecyclePayload):
            for evidence in payload.evidence:
                evidence_source[evidence.evidence_id] = event.event_id
        if isinstance(payload, EvidenceAttachedPayload):
            evidence_source[payload.evidence.evidence_id] = event.event_id
        if isinstance(payload, LinkedPayload | SupersededPayload):
            link_created[payload.link.link_id] = event.event_id
        if isinstance(payload, UnlinkedPayload):
            link_unlinked[payload.link.link_id] = event.event_id
        if isinstance(payload, ConflictOpenedPayload | ConflictResolvedPayload):
            for affected in payload.affected_memories:
                memory_last[affected.memory.memory_id] = event.event_id
            for member in payload.members:
                member_last[(member.conflict_id, member.memory_id)] = event.event_id
        if isinstance(payload, ConflictOpenedPayload):
            conflict_opened[payload.conflict.conflict_id] = event.event_id
        if isinstance(payload, ConflictResolvedPayload):
            conflict_resolved[payload.conflict.conflict_id] = event.event_id

    return _Provenance(
        memory_last=memory_last,
        evidence_source=evidence_source,
        link_created=link_created,
        link_unlinked=link_unlinked,
        conflict_opened=conflict_opened,
        conflict_resolved=conflict_resolved,
        member_last=member_last,
    )


def _required[ValueT](mapping: Mapping[ValueT, UUID], key: ValueT, code: str) -> UUID:
    try:
        return mapping[key]
    except KeyError as error:
        raise ProjectionPersistenceError(code) from error


def _memory_row(state: MemoryState, last_event_id: UUID) -> Memory:
    return Memory(
        memory_id=state.memory_id,
        tenant_id=state.tenant_id,
        lineage_id=state.lineage_id,
        branch_id=state.branch_id,
        subject_id=state.subject_id,
        subject_kind=state.subject_kind.value,
        origin_session_id=state.origin_session_id,
        revision=state.revision,
        category=state.category.value,
        ontological_status=state.ontological_status.value,
        scope=state.scope.value,
        visibility=state.visibility.value,
        status=state.status.value,
        statement=state.statement,
        reason_to_remember=state.reason_to_remember,
        interpretation_limits=list(state.interpretation_limits),
        confidence=state.confidence,
        salience=state.salience,
        durability=state.durability,
        sensitivity=state.sensitivity,
        authority_class=state.authority_class.value,
        valid_from=state.valid_from,
        valid_to=state.valid_to,
        observed_at=state.observed_at,
        created_at=state.created_at,
        updated_at=state.updated_at,
        candidate_expires_at=getattr(state, "candidate_expires_at", None),
        normalized_fingerprint=(
            bytes.fromhex(state.normalized_fingerprint)
            if state.normalized_fingerprint is not None
            else None
        ),
        fingerprint_version=state.fingerprint_version,
        metadata_=dict(state.metadata),
        publication_approved_at=state.publication_approved_at,
        publication_approved_by_actor_id=state.publication_approved_by_actor_id,
        content_protection=state.content_protection,
        content_key_id=state.content_key_id,
        last_event_id=last_event_id,
    )


def memory_state_to_row(state: MemoryState, *, last_event_id: UUID) -> Memory:
    """Map a complete memory after-image to a projection row."""

    return _memory_row(state, last_event_id)


def _branch_rows(states: Mapping[UUID, BranchState]) -> tuple[Branch, ...]:
    """Map branches in deterministic parent-before-child order."""

    remaining = dict(states)
    emitted: set[UUID] = set()
    ordered: list[Branch] = []
    while remaining:
        ready = sorted(
            (
                state
                for state in remaining.values()
                if state.parent_branch_id is None or state.parent_branch_id in emitted
            ),
            key=lambda state: (str(state.tenant_id), str(state.lineage_id), str(state.branch_id)),
        )
        if not ready:
            raise ProjectionPersistenceError("branch_parent_order")
        for state in ready:
            ordered.append(
                Branch(
                    branch_id=state.branch_id,
                    tenant_id=state.tenant_id,
                    lineage_id=state.lineage_id,
                    parent_branch_id=state.parent_branch_id,
                    fork_event_sequence=state.fork_event_sequence,
                    name=state.name,
                    visibility_ceiling=state.visibility_ceiling.value,
                    created_at=state.created_at,
                    sealed_at=state.sealed_at,
                )
            )
            emitted.add(state.branch_id)
            del remaining[state.branch_id]
    return tuple(ordered)


def _evidence_row(state: EvidenceState, source_event_id: UUID) -> MemoryEvidence:
    return MemoryEvidence(
        evidence_id=state.evidence_id,
        tenant_id=state.tenant_id,
        lineage_id=state.lineage_id,
        branch_id=state.branch_id,
        memory_id=state.memory_id,
        source_event_id=source_event_id,
        source_type=state.source_type,
        source_reference=dict(state.source_reference),
        excerpt=state.excerpt,
        occurred_at=state.occurred_at,
        content_sha256=(
            bytes.fromhex(state.content_sha256) if state.content_sha256 is not None else None
        ),
        trust_classification=state.trust_classification,
        status=state.status,
        created_at=state.created_at,
        metadata_=dict(state.metadata),
    )


def evidence_state_to_row(state: EvidenceState, *, source_event_id: UUID) -> MemoryEvidence:
    """Map policy-approved evidence to its projection row."""

    return _evidence_row(state, source_event_id)


def _link_row(
    state: LinkState,
    created_event_id: UUID,
    unlinked_event_id: UUID | None,
) -> MemoryLink:
    return MemoryLink(
        link_id=state.link_id,
        tenant_id=state.tenant_id,
        lineage_id=state.lineage_id,
        branch_id=state.branch_id,
        source_memory_id=state.source_memory_id,
        target_memory_id=state.target_memory_id,
        link_type=state.link_type.value,
        status=state.status,
        created_event_id=created_event_id,
        unlinked_event_id=unlinked_event_id,
        created_at=state.created_at,
        unlinked_at=state.unlinked_at,
        metadata_=dict(state.metadata),
    )


def link_state_to_row(
    state: LinkState,
    *,
    created_event_id: UUID,
    unlinked_event_id: UUID | None = None,
) -> MemoryLink:
    """Map a complete link after-image to a projection row."""

    return _link_row(state, created_event_id, unlinked_event_id)


def build_projection_rows(
    state: ProjectionState,
    events: Sequence[DomainMemoryEvent],
) -> ProjectionRows:
    """Map a fully folded projection to ORM rows before any database mutation."""

    provenance = _derive_provenance(events)
    memories = tuple(
        _memory_row(
            memory_state,
            _required(provenance.memory_last, memory_state.memory_id, "memory_provenance"),
        )
        for memory_state in sorted(state.memories.values(), key=lambda value: str(value.memory_id))
    )
    evidence = tuple(
        _evidence_row(
            evidence_state,
            _required(
                provenance.evidence_source,
                evidence_state.evidence_id,
                "evidence_provenance",
            ),
        )
        for evidence_state in sorted(
            state.evidence.values(), key=lambda value: str(value.evidence_id)
        )
    )

    links: list[MemoryLink] = []
    for link_state in sorted(state.links.values(), key=lambda value: str(value.link_id)):
        created_event_id = _required(
            provenance.link_created,
            link_state.link_id,
            "link_created_provenance",
        )
        unlinked_event_id = provenance.link_unlinked.get(link_state.link_id)
        if (link_state.status == "unlinked") != (unlinked_event_id is not None):
            raise ProjectionPersistenceError("link_unlinked_provenance")
        links.append(_link_row(link_state, created_event_id, unlinked_event_id))

    conflicts: list[MemoryConflict] = []
    for conflict_state in sorted(
        state.conflicts.values(), key=lambda value: str(value.conflict_id)
    ):
        opened_event_id = _required(
            provenance.conflict_opened,
            conflict_state.conflict_id,
            "conflict_opened_provenance",
        )
        resolution_event_id = provenance.conflict_resolved.get(conflict_state.conflict_id)
        if (conflict_state.status == "resolved") != (resolution_event_id is not None):
            raise ProjectionPersistenceError("conflict_resolution_provenance")
        conflicts.append(
            MemoryConflict(
                conflict_id=conflict_state.conflict_id,
                tenant_id=conflict_state.tenant_id,
                lineage_id=conflict_state.lineage_id,
                branch_id=conflict_state.branch_id,
                subject_id=conflict_state.subject_id,
                status=conflict_state.status,
                reason=conflict_state.reason,
                resolution_kind=conflict_state.resolution_kind,
                resolution_rationale=conflict_state.resolution_rationale,
                opened_event_id=opened_event_id,
                resolution_event_id=resolution_event_id,
                opened_at=conflict_state.opened_at,
                resolved_at=conflict_state.resolved_at,
                metadata_=dict(conflict_state.metadata),
            )
        )

    conflict_members = tuple(
        MemoryConflictMember(
            tenant_id=state.conflicts[key[0]].tenant_id,
            lineage_id=state.conflicts[key[0]].lineage_id,
            conflict_id=item.conflict_id,
            memory_id=item.memory_id,
            disposition=item.disposition,
            joined_at=item.joined_at,
            last_event_id=_required(provenance.member_last, key, "conflict_member_provenance"),
        )
        for key, item in sorted(
            state.conflict_members.items(),
            key=lambda pair: (str(pair[0][0]), str(pair[0][1])),
        )
    )
    return ProjectionRows(
        branches=_branch_rows(state.branches),
        memories=memories,
        evidence=evidence,
        links=tuple(links),
        conflicts=tuple(conflicts),
        conflict_members=conflict_members,
    )


async def _delete_projection_rows(session: AsyncSession, tenant_id: UUID | None) -> None:
    for model in (
        MemoryConflictMember,
        MemoryConflict,
        MemoryLink,
        MemoryEvidence,
        Memory,
    ):
        statement = delete(model)
        if tenant_id is not None:
            statement = statement.where(model.tenant_id == tenant_id)
        await session.execute(statement)


def _branch_values(row: Branch) -> tuple[object, ...]:
    return (
        row.branch_id,
        row.tenant_id,
        row.lineage_id,
        row.parent_branch_id,
        row.fork_event_sequence,
        row.name,
        row.visibility_ceiling,
        row.created_at,
        row.sealed_at,
    )


async def _missing_branch_rows(
    session: AsyncSession,
    expected: Sequence[Branch],
    tenant_id: UUID | None,
) -> tuple[Branch, ...]:
    """Validate scoped branch identity exactly and return missing replay rows."""

    statement = select(Branch).order_by(Branch.tenant_id, Branch.lineage_id, Branch.branch_id)
    if tenant_id is not None:
        statement = statement.where(Branch.tenant_id == tenant_id)
    try:
        result = await session.execute(statement)
    except SQLAlchemyError:
        raise ProjectionPersistenceError("branch_projection_load_failed") from None
    existing = {row.branch_id: row for row in result.scalars().all()}
    expected_by_id = {row.branch_id: row for row in expected}
    if existing.keys() - expected_by_id.keys():
        raise ProjectionPersistenceError("branch_projection_extra")
    for branch_id in existing.keys() & expected_by_id.keys():
        if _branch_values(existing[branch_id]) != _branch_values(expected_by_id[branch_id]):
            raise ProjectionPersistenceError("branch_projection_mismatch")
    return tuple(row for row in expected if row.branch_id not in existing)


async def rebuild_semantic_projections(
    session: AsyncSession,
    *,
    tenant_id: UUID | None = None,
) -> ProjectionState:
    """Verify, fold, and replace semantic projections in the caller's transaction."""

    if not session.in_transaction():
        raise ProjectionPersistenceError("active_transaction_required")
    events = await load_verified_events(session, tenant_id=tenant_id)
    state = rebuild(events) if tenant_id is None else rebuild_tenant(tenant_id, events).projection
    rows = build_projection_rows(state, events)
    missing_branches = await _missing_branch_rows(session, rows.branches, tenant_id)

    try:
        if missing_branches:
            session.add_all(missing_branches)
            await session.flush()
        await _delete_projection_rows(session, tenant_id)
        session.add_all(rows.memories)
        await session.flush()
        session.add_all((*rows.evidence, *rows.links, *rows.conflicts))
        await session.flush()
        session.add_all(rows.conflict_members)
        await session.flush()
    except SQLAlchemyError:
        raise ProjectionPersistenceError("projection_write_failed") from None
    return state


def memory_row_to_state(row: Memory) -> MemoryState:
    """Convert one memory projection row to its validated domain after-image."""

    state_type = MemoryStateV2 if row.candidate_expires_at is not None else MemoryState
    values: dict[str, object] = {
        "memory_id": row.memory_id,
        "tenant_id": row.tenant_id,
        "lineage_id": row.lineage_id,
        "branch_id": row.branch_id,
        "subject_id": row.subject_id,
        "subject_kind": SubjectKind(row.subject_kind),
        "revision": row.revision,
        "category": MemoryCategory(row.category),
        "ontological_status": OntologicalStatus(row.ontological_status),
        "scope": MemoryScope(row.scope),
        "visibility": MemoryVisibility(row.visibility),
        "status": MemoryStatus(row.status),
        "statement": row.statement,
        "reason_to_remember": row.reason_to_remember,
        "interpretation_limits": tuple(str(value) for value in row.interpretation_limits),
        "confidence": row.confidence,
        "salience": row.salience,
        "durability": row.durability,
        "sensitivity": row.sensitivity,
        "authority_class": AuthorityClass(row.authority_class),
        "valid_from": row.valid_from,
        "valid_to": row.valid_to,
        "observed_at": row.observed_at,
        "origin_session_id": row.origin_session_id,
        "publication_approved_at": row.publication_approved_at,
        "publication_approved_by_actor_id": row.publication_approved_by_actor_id,
        "content_protection": row.content_protection,
        "content_key_id": row.content_key_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "fingerprint_version": row.fingerprint_version,
        "normalized_fingerprint": (
            bytes(row.normalized_fingerprint).hex()
            if row.normalized_fingerprint is not None
            else None
        ),
        "metadata": dict(row.metadata_),
    }
    if state_type is MemoryStateV2:
        values["candidate_expires_at"] = row.candidate_expires_at
    return state_type.model_validate(values)


def evidence_row_to_state(row: MemoryEvidence) -> EvidenceState:
    """Convert one evidence projection row to its validated domain after-image."""

    return EvidenceState(
        evidence_id=row.evidence_id,
        tenant_id=row.tenant_id,
        lineage_id=row.lineage_id,
        branch_id=row.branch_id,
        memory_id=row.memory_id,
        source_type=row.source_type,
        source_reference=dict(row.source_reference),
        excerpt=row.excerpt,
        occurred_at=row.occurred_at,
        content_sha256=(
            bytes(row.content_sha256).hex() if row.content_sha256 is not None else None
        ),
        trust_classification=row.trust_classification,
        status=row.status,  # type: ignore[arg-type]
        created_at=row.created_at,
        metadata=dict(row.metadata_),
    )


def link_row_to_state(row: MemoryLink) -> LinkState:
    """Convert one link projection row to its validated domain after-image."""

    return LinkState(
        link_id=row.link_id,
        tenant_id=row.tenant_id,
        lineage_id=row.lineage_id,
        branch_id=row.branch_id,
        source_memory_id=row.source_memory_id,
        target_memory_id=row.target_memory_id,
        link_type=LinkType(row.link_type),
        status=row.status,  # type: ignore[arg-type]
        created_at=row.created_at,
        unlinked_at=row.unlinked_at,
        metadata=dict(row.metadata_),
    )


def canonical_aggregate_bytes_from_rows(
    memory: Memory,
    *,
    evidence: Iterable[MemoryEvidence] = (),
    links: Iterable[MemoryLink] = (),
    conflicts: Iterable[MemoryConflict] = (),
    conflict_members: Iterable[MemoryConflictMember] = (),
) -> bytes:
    """Reconstruct and canonically serialize one persisted aggregate."""

    memory_state = memory_row_to_state(memory)
    evidence_states = {_row.evidence_id: evidence_row_to_state(_row) for _row in evidence}
    link_states = {_row.link_id: link_row_to_state(_row) for _row in links}
    conflict_states = {_row.conflict_id: conflict_row_to_state(_row) for _row in conflicts}
    member_states = {
        (_row.conflict_id, _row.memory_id): conflict_member_row_to_state(_row)
        for _row in conflict_members
    }
    state = ProjectionState(
        memories={memory_state.memory_id: memory_state},
        evidence=evidence_states,
        links=link_states,
        conflicts=conflict_states,
        conflict_members=member_states,
    )
    return canonical_aggregate_bytes(state, memory_state.memory_id)


def conflict_row_to_state(row: MemoryConflict) -> ConflictState:
    """Convert one conflict projection row to its validated domain after-image."""

    return ConflictState(
        conflict_id=row.conflict_id,
        tenant_id=row.tenant_id,
        lineage_id=row.lineage_id,
        branch_id=row.branch_id,
        subject_id=row.subject_id,
        status=row.status,  # type: ignore[arg-type]
        reason=row.reason,
        resolution_kind=row.resolution_kind,
        resolution_rationale=row.resolution_rationale,
        opened_at=row.opened_at,
        resolved_at=row.resolved_at,
        metadata=dict(row.metadata_),
    )


def conflict_member_row_to_state(row: MemoryConflictMember) -> ConflictMemberState:
    """Convert one conflict-member row to its validated domain after-image."""

    return ConflictMemberState(
        conflict_id=row.conflict_id,
        memory_id=row.memory_id,
        disposition=row.disposition,
        joined_at=row.joined_at,
    )


async def load_canonical_aggregate_bytes(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    memory_id: UUID,
) -> bytes:
    """Load one persisted aggregate and return its canonical domain bytes."""

    try:
        return await _load_canonical_aggregate_bytes(
            session,
            tenant_id=tenant_id,
            memory_id=memory_id,
        )
    except SQLAlchemyError:
        raise ProjectionPersistenceError("aggregate_load_failed") from None


async def _load_canonical_aggregate_bytes(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    memory_id: UUID,
) -> bytes:
    """Perform aggregate projection queries for the sanitized public loader."""

    memory_result = await session.execute(
        select(Memory).where(Memory.tenant_id == tenant_id, Memory.memory_id == memory_id)
    )
    memory = memory_result.scalar_one_or_none()
    if memory is None:
        raise KeyError(memory_id)
    evidence_result = await session.execute(
        select(MemoryEvidence).where(
            MemoryEvidence.tenant_id == tenant_id,
            MemoryEvidence.memory_id == memory_id,
        )
    )
    links_result = await session.execute(
        select(MemoryLink).where(
            MemoryLink.tenant_id == tenant_id,
            or_(MemoryLink.source_memory_id == memory_id, MemoryLink.target_memory_id == memory_id),
        )
    )
    conflict_ids_result = await session.execute(
        select(MemoryConflictMember.conflict_id).where(
            MemoryConflictMember.tenant_id == tenant_id,
            MemoryConflictMember.memory_id == memory_id,
        )
    )
    conflict_ids = tuple(conflict_ids_result.scalars().all())
    conflicts: Sequence[MemoryConflict] = ()
    members: Sequence[MemoryConflictMember] = ()
    if conflict_ids:
        conflicts_result = await session.execute(
            select(MemoryConflict).where(
                MemoryConflict.tenant_id == tenant_id,
                MemoryConflict.conflict_id.in_(conflict_ids),
            )
        )
        conflicts = conflicts_result.scalars().all()
        members_result = await session.execute(
            select(MemoryConflictMember).where(
                MemoryConflictMember.tenant_id == tenant_id,
                MemoryConflictMember.conflict_id.in_(conflict_ids),
            )
        )
        members = members_result.scalars().all()
    return canonical_aggregate_bytes_from_rows(
        memory,
        evidence=evidence_result.scalars().all(),
        links=links_result.scalars().all(),
        conflicts=conflicts,
        conflict_members=members,
    )
