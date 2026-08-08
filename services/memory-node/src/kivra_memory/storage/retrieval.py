"""Mandatory hard-filtered PostgreSQL retrieval primitives.

Every candidate channel and hydration path applies the same tenant, lineage,
exact-branch, lifecycle, scope, visibility, and subject predicates. Callers may
further reduce results, but must not query retrieval tables directly.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from sqlalchemy import Text, and_, cast, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import MemoryState
from kivra_memory.storage.models import (
    Branch,
    EmbeddingModel,
    Lineage,
    LogicalSession,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryEmbeddingV1,
    Persona,
    Subject,
    SubjectAlias,
)
from kivra_memory.storage.models import MemoryEvent as MemoryEventRow
from kivra_memory.storage.projector import memory_row_to_state

CandidateChannel = Literal["lexical", "trigram", "vector"]


@dataclass(frozen=True, slots=True)
class RetrievalFilters:
    """Authorization-intersected filters for one exact branch."""

    tenant_id: UUID
    lineage_id: UUID
    branch_id: UUID
    allowed_scopes: frozenset[MemoryScope]
    allowed_visibilities: frozenset[MemoryVisibility]
    allowed_statuses: frozenset[MemoryStatus]
    max_sensitivity: int
    requested_subject_ids: frozenset[UUID] | None = None
    project_subject_ids: frozenset[UUID] = frozenset()
    relationship_subject_ids: frozenset[UUID] = frozenset()
    session_subject_ids: frozenset[UUID] = frozenset()
    allowed_subject_kinds: frozenset[SubjectKind] | None = None
    allowed_categories: frozenset[MemoryCategory] | None = None
    allowed_ontological_statuses: frozenset[OntologicalStatus] | None = None
    valid_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.allowed_scopes:
            raise ValueError("retrieval requires at least one allowed scope")
        if not self.allowed_visibilities:
            raise ValueError("retrieval requires at least one allowed visibility")
        if not self.allowed_statuses:
            raise ValueError("retrieval requires at least one allowed status")
        if isinstance(self.max_sensitivity, bool) or not 0 <= self.max_sensitivity <= 4:
            raise ValueError("maximum sensitivity must be between zero and four")


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    memory_id: UUID
    channel: CandidateChannel
    channel_rank: int
    channel_score: float


@dataclass(frozen=True, slots=True)
class HydratedMemory:
    """A canonical memory projection with its immutable provenance event."""

    state: MemoryState
    last_event_id: UUID


@dataclass(frozen=True, slots=True)
class OpenConflictGroup:
    conflict_id: UUID
    visible_memory_ids: tuple[UUID, ...]
    total_member_count: int

    @property
    def is_partial(self) -> bool:
        return len(self.visible_memory_ids) != self.total_member_count


@dataclass(frozen=True, slots=True)
class ResolvedReadContext:
    lineage_id: UUID
    branch_id: UUID
    logical_session_id: UUID | None
    project_subject_ids: frozenset[UUID]
    relationship_subject_ids: frozenset[UUID]
    session_subject_ids: frozenset[UUID]


@dataclass(frozen=True, slots=True)
class LineageMetadata:
    persona_id: UUID
    lineage_id: UUID
    branch_id: UUID
    parent_branch_id: UUID | None
    fork_event_sequence: int | None
    visibility_ceiling: MemoryVisibility
    sealed_at: datetime | None


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    sequence: int
    event_id: UUID
    operation: str
    memory_id: UUID | None
    created_at: datetime


def _bounded_limit(limit: int) -> int:
    if isinstance(limit, bool) or not 1 <= limit <= 500:
        raise ValueError("retrieval limit must be between 1 and 500")
    return limit


def _bounded_query(query: str) -> str:
    value = query.strip()
    if not value or len(value) > 4096:
        raise ValueError("retrieval query must contain between 1 and 4096 characters")
    return value


def _hard_predicates(filters: RetrievalFilters) -> tuple[ColumnElement[bool], ...]:
    predicates: list[ColumnElement[bool]] = [
        Memory.tenant_id == filters.tenant_id,
        Memory.lineage_id == filters.lineage_id,
        Memory.branch_id == filters.branch_id,
        Memory.scope.in_(scope.value for scope in filters.allowed_scopes),
        Memory.visibility.in_(value.value for value in filters.allowed_visibilities),
        Memory.status.in_(status.value for status in filters.allowed_statuses),
        Memory.sensitivity <= filters.max_sensitivity,
        Memory.statement.is_not(None),
        or_(
            Memory.scope.in_((MemoryScope.GLOBAL.value, MemoryScope.PERSONA.value)),
            and_(
                Memory.scope == MemoryScope.PROJECT.value,
                Memory.subject_id.in_(filters.project_subject_ids),
            ),
            and_(
                Memory.scope == MemoryScope.RELATIONSHIP.value,
                Memory.subject_id.in_(filters.relationship_subject_ids),
            ),
            and_(
                Memory.scope.in_((MemoryScope.EPISODIC.value, MemoryScope.SCENE_LOCAL.value)),
                Memory.subject_id.in_(filters.session_subject_ids),
            ),
        ),
    ]
    if filters.requested_subject_ids is not None:
        predicates.append(Memory.subject_id.in_(filters.requested_subject_ids))
    if filters.allowed_subject_kinds is not None:
        predicates.append(
            Memory.subject_kind.in_(value.value for value in filters.allowed_subject_kinds)
        )
    if filters.allowed_categories is not None:
        predicates.append(Memory.category.in_(value.value for value in filters.allowed_categories))
    if filters.allowed_ontological_statuses is not None:
        predicates.append(
            Memory.ontological_status.in_(
                value.value for value in filters.allowed_ontological_statuses
            )
        )
    if filters.valid_at is not None:
        predicates.extend(
            (
                (Memory.valid_from.is_(None)) | (Memory.valid_from <= filters.valid_at),
                (Memory.valid_to.is_(None)) | (Memory.valid_to >= filters.valid_at),
            )
        )
    return tuple(predicates)


def embedding_content_sha256_expression() -> ColumnElement[bytes]:
    """Return the v1 source hash expression used to reject stale vectors.

    V1 embeds the canonical memory statement. The source hash is SHA-256 over
    the frozen domain separator, one NUL byte, and the statement's exact UTF-8
    bytes. Revisions that change the statement cannot reuse an older vector.
    """

    prefix = func.convert_to("scalevault.memory.statement.embedding.v1", "UTF8")
    framed = prefix.op("||")(func.decode("00", "hex")).op("||")(
        func.convert_to(Memory.statement, "UTF8")
    )
    return func.digest(framed, "sha256")


class RetrievalRepository:
    """Parameterized exact-branch candidate and hydration repository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def resolve_context(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        client_id: UUID,
        transport_binding_id: UUID,
        persona_id: UUID,
        branch_id: UUID,
        logical_session_id: UUID | None = None,
        project_ref: str | None = None,
        relationship_ref: str | None = None,
    ) -> ResolvedReadContext | None:
        identity = (
            await self._session.execute(
                select(Lineage.lineage_id)
                .join(
                    Persona,
                    and_(
                        Persona.tenant_id == Lineage.tenant_id,
                        Persona.persona_id == Lineage.persona_id,
                    ),
                )
                .join(
                    Branch,
                    and_(
                        Branch.tenant_id == Lineage.tenant_id,
                        Branch.lineage_id == Lineage.lineage_id,
                    ),
                )
                .where(
                    Persona.tenant_id == tenant_id,
                    Persona.persona_id == persona_id,
                    Persona.retired_at.is_(None),
                    Lineage.sealed_at.is_(None),
                    Branch.branch_id == branch_id,
                )
            )
        ).scalar_one_or_none()
        if identity is None:
            return None
        lineage_id = identity
        if logical_session_id is not None:
            session_id = await self._session.scalar(
                select(LogicalSession.session_id).where(
                    LogicalSession.tenant_id == tenant_id,
                    LogicalSession.lineage_id == lineage_id,
                    LogicalSession.branch_id == branch_id,
                    LogicalSession.session_id == logical_session_id,
                    LogicalSession.actor_id == actor_id,
                    LogicalSession.client_id == client_id,
                    LogicalSession.transport_binding_id == transport_binding_id,
                )
            )
            if session_id is None:
                return None

        project_subject_ids: frozenset[UUID] = frozenset()
        if project_ref is not None:
            value = project_ref.strip()
            if not value or len(value) > 4096:
                raise ValueError("project_ref must contain between 1 and 4096 characters")
            project_subject_ids = frozenset(
                await self._session.scalars(
                    select(Subject.subject_id).where(
                        Subject.tenant_id == tenant_id,
                        Subject.lineage_id == lineage_id,
                        Subject.kind == "project",
                        Subject.project_ref == value,
                    )
                )
            )

        relationship_subject_ids: frozenset[UUID] = frozenset()
        if relationship_ref is not None:
            value = relationship_ref.strip()
            if not value or len(value) > 256:
                raise ValueError("relationship_ref must contain between 1 and 256 characters")
            relationship_subject_ids = frozenset(
                await self._session.scalars(
                    select(Subject.subject_id)
                    .outerjoin(
                        SubjectAlias,
                        and_(
                            SubjectAlias.tenant_id == Subject.tenant_id,
                            SubjectAlias.lineage_id == Subject.lineage_id,
                            SubjectAlias.subject_id == Subject.subject_id,
                        ),
                    )
                    .where(
                        Subject.tenant_id == tenant_id,
                        Subject.lineage_id == lineage_id,
                        Subject.kind == "relationship",
                        (
                            (func.lower(cast(Subject.canonical_key, Text)) == value.lower())
                            | (func.lower(cast(SubjectAlias.alias, Text)) == value.lower())
                        ),
                    )
                    .distinct()
                )
            )

        session_subject_ids = (
            frozenset(
                await self._session.scalars(
                    select(Subject.subject_id).where(
                        Subject.tenant_id == tenant_id,
                        Subject.lineage_id == lineage_id,
                        Subject.origin_session_id == logical_session_id,
                    )
                )
            )
            if logical_session_id is not None
            else frozenset()
        )
        return ResolvedReadContext(
            lineage_id=lineage_id,
            branch_id=branch_id,
            logical_session_id=logical_session_id,
            project_subject_ids=project_subject_ids,
            relationship_subject_ids=relationship_subject_ids,
            session_subject_ids=session_subject_ids,
        )

    async def lexical_candidates(
        self, filters: RetrievalFilters, query: str, limit: int
    ) -> tuple[RankedCandidate, ...]:
        query_value = _bounded_query(query)
        result_limit = _bounded_limit(limit)
        tsquery = func.websearch_to_tsquery("simple", query_value)
        score = func.ts_rank_cd(Memory.search_document, tsquery)
        rows = (
            await self._session.execute(
                select(Memory.memory_id, score.label("score"))
                .where(*_hard_predicates(filters), Memory.search_document.op("@@")(tsquery))
                .order_by(score.desc(), Memory.memory_id)
                .limit(result_limit)
            )
        ).all()
        return tuple(
            RankedCandidate(memory_id, "lexical", rank, float(value))
            for rank, (memory_id, value) in enumerate(rows, start=1)
        )

    async def trigram_candidates(
        self, filters: RetrievalFilters, query: str, limit: int
    ) -> tuple[RankedCandidate, ...]:
        query_value = _bounded_query(query)
        result_limit = _bounded_limit(limit)
        alias_score = func.coalesce(
            func.max(func.similarity(cast(SubjectAlias.alias, Text), query_value)), 0.0
        )
        score = func.greatest(
            func.similarity(Memory.statement, query_value),
            func.similarity(Subject.display_name, query_value),
            func.similarity(cast(Subject.canonical_key, Text), query_value),
            alias_score,
        )
        rows = (
            await self._session.execute(
                select(Memory.memory_id, score.label("score"))
                .join(
                    Subject,
                    and_(
                        Subject.tenant_id == Memory.tenant_id,
                        Subject.lineage_id == Memory.lineage_id,
                        Subject.subject_id == Memory.subject_id,
                    ),
                )
                .outerjoin(
                    SubjectAlias,
                    and_(
                        SubjectAlias.tenant_id == Subject.tenant_id,
                        SubjectAlias.lineage_id == Subject.lineage_id,
                        SubjectAlias.subject_id == Subject.subject_id,
                    ),
                )
                .where(*_hard_predicates(filters))
                .group_by(
                    Memory.memory_id,
                    Memory.statement,
                    Subject.display_name,
                    Subject.canonical_key,
                )
                .having(score > 0.0)
                .order_by(score.desc(), Memory.memory_id)
                .limit(result_limit)
            )
        ).all()
        return tuple(
            RankedCandidate(memory_id, "trigram", rank, float(value))
            for rank, (memory_id, value) in enumerate(rows, start=1)
        )

    async def vector_candidates(
        self,
        filters: RetrievalFilters,
        query_embedding: Sequence[float],
        limit: int,
    ) -> tuple[RankedCandidate, ...]:
        result_limit = _bounded_limit(limit)
        vector = tuple(float(value) for value in query_embedding)
        if len(vector) != 384 or any(not math.isfinite(value) for value in vector):
            raise ValueError("query embedding must contain exactly 384 finite values")
        if not any(value != 0 for value in vector):
            raise ValueError("query embedding must not be the zero vector")

        await self._session.execute(text("SET LOCAL hnsw.iterative_scan = 'strict_order'"))
        distance = MemoryEmbeddingV1.embedding.cosine_distance(vector)
        rows = (
            await self._session.execute(
                select(Memory.memory_id, distance.label("distance"))
                .join(
                    MemoryEmbeddingV1,
                    and_(
                        MemoryEmbeddingV1.tenant_id == Memory.tenant_id,
                        MemoryEmbeddingV1.lineage_id == Memory.lineage_id,
                        MemoryEmbeddingV1.branch_id == Memory.branch_id,
                        MemoryEmbeddingV1.memory_id == Memory.memory_id,
                        MemoryEmbeddingV1.source_memory_revision == Memory.revision,
                        MemoryEmbeddingV1.source_event_id == Memory.last_event_id,
                        MemoryEmbeddingV1.input_contract_version == "memory-statement-embedding-v1",
                        MemoryEmbeddingV1.source_content_sha256
                        == embedding_content_sha256_expression(),
                    ),
                )
                .join(
                    EmbeddingModel,
                    and_(
                        EmbeddingModel.tenant_id == MemoryEmbeddingV1.tenant_id,
                        EmbeddingModel.embedding_model_id == MemoryEmbeddingV1.embedding_model_id,
                        EmbeddingModel.state == "approved",
                        EmbeddingModel.retired_at.is_(None),
                        EmbeddingModel.dimension == 384,
                        EmbeddingModel.distance_metric == "cosine",
                    ),
                )
                .where(*_hard_predicates(filters))
                .order_by(distance, Memory.memory_id)
                .limit(result_limit)
            )
        ).all()
        return tuple(
            RankedCandidate(
                memory_id,
                "vector",
                rank,
                max(0.0, min(1.0, 1.0 - float(value))),
            )
            for rank, (memory_id, value) in enumerate(rows, start=1)
        )

    async def hydrate_memories(
        self, filters: RetrievalFilters, memory_ids: Sequence[UUID]
    ) -> tuple[HydratedMemory, ...]:
        ordered_ids = tuple(dict.fromkeys(memory_ids))
        if not ordered_ids:
            return ()
        rows = (
            await self._session.execute(
                select(Memory, Memory.last_event_id).where(
                    *_hard_predicates(filters), Memory.memory_id.in_(ordered_ids)
                )
            )
        ).all()
        by_id = {
            memory.memory_id: HydratedMemory(
                state=memory_row_to_state(memory), last_event_id=last_event_id
            )
            for memory, last_event_id in rows
        }
        return tuple(by_id[memory_id] for memory_id in ordered_ids if memory_id in by_id)

    async def get_memory(self, filters: RetrievalFilters, memory_id: UUID) -> HydratedMemory | None:
        values = await self.hydrate_memories(filters, (memory_id,))
        return values[0] if values else None

    async def lineage_metadata(
        self, *, tenant_id: UUID, persona_id: UUID, branch_id: UUID
    ) -> LineageMetadata | None:
        row = (
            await self._session.execute(
                select(
                    Persona.persona_id,
                    Lineage.lineage_id,
                    Branch.branch_id,
                    Branch.parent_branch_id,
                    Branch.fork_event_sequence,
                    Branch.visibility_ceiling,
                    Branch.sealed_at,
                )
                .join(
                    Lineage,
                    and_(
                        Lineage.tenant_id == Persona.tenant_id,
                        Lineage.persona_id == Persona.persona_id,
                    ),
                )
                .join(
                    Branch,
                    and_(
                        Branch.tenant_id == Lineage.tenant_id,
                        Branch.lineage_id == Lineage.lineage_id,
                    ),
                )
                .where(
                    Persona.tenant_id == tenant_id,
                    Persona.persona_id == persona_id,
                    Branch.branch_id == branch_id,
                )
            )
        ).one_or_none()
        if row is None:
            return None
        return LineageMetadata(
            persona_id=row.persona_id,
            lineage_id=row.lineage_id,
            branch_id=row.branch_id,
            parent_branch_id=row.parent_branch_id,
            fork_event_sequence=row.fork_event_sequence,
            visibility_ceiling=MemoryVisibility(row.visibility_ceiling),
            sealed_at=row.sealed_at,
        )

    async def timeline(
        self,
        filters: RetrievalFilters,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        before_sequence: int | None = None,
        limit: int = 100,
    ) -> tuple[TimelineEntry, ...]:
        result_limit = _bounded_limit(limit)
        predicates: list[ColumnElement[bool]] = [
            MemoryEventRow.tenant_id == filters.tenant_id,
            MemoryEventRow.lineage_id == filters.lineage_id,
            MemoryEventRow.branch_id == filters.branch_id,
        ]
        if start is not None:
            predicates.append(MemoryEventRow.created_at >= start)
        if end is not None:
            predicates.append(MemoryEventRow.created_at <= end)
        if before_sequence is not None:
            if before_sequence < 1:
                raise ValueError("before_sequence must be positive")
            predicates.append(MemoryEventRow.sequence < before_sequence)
        rows = (
            await self._session.execute(
                select(
                    MemoryEventRow.sequence,
                    MemoryEventRow.event_id,
                    MemoryEventRow.operation,
                    MemoryEventRow.memory_id,
                    MemoryEventRow.created_at,
                )
                .join(
                    Memory,
                    and_(
                        Memory.tenant_id == MemoryEventRow.tenant_id,
                        Memory.lineage_id == MemoryEventRow.lineage_id,
                        Memory.branch_id == MemoryEventRow.branch_id,
                        Memory.memory_id == MemoryEventRow.memory_id,
                    ),
                )
                .where(
                    *predicates,
                    MemoryEventRow.memory_id.is_not(None),
                    *_hard_predicates(filters),
                )
                .order_by(MemoryEventRow.sequence.desc())
                .limit(result_limit)
            )
        ).all()
        return tuple(TimelineEntry(*row) for row in rows)

    async def selection_events(
        self,
        filters: RetrievalFilters,
        *,
        before_sequence: int | None = None,
        limit: int = 100,
    ) -> tuple[TimelineEntry, ...]:
        return await self.timeline(filters, before_sequence=before_sequence, limit=limit)

    async def open_conflict_members(
        self, filters: RetrievalFilters, memory_ids: Sequence[UUID]
    ) -> Mapping[UUID, OpenConflictGroup]:
        candidate_ids = tuple(dict.fromkeys(memory_ids))
        if not candidate_ids:
            return {}
        conflict_ids = tuple(
            await self._session.scalars(
                select(MemoryConflictMember.conflict_id)
                .join(
                    MemoryConflict,
                    and_(
                        MemoryConflict.tenant_id == MemoryConflictMember.tenant_id,
                        MemoryConflict.lineage_id == MemoryConflictMember.lineage_id,
                        MemoryConflict.conflict_id == MemoryConflictMember.conflict_id,
                    ),
                )
                .where(
                    MemoryConflict.tenant_id == filters.tenant_id,
                    MemoryConflict.lineage_id == filters.lineage_id,
                    MemoryConflict.branch_id == filters.branch_id,
                    MemoryConflict.status == "open",
                    MemoryConflictMember.memory_id.in_(candidate_ids),
                )
                .distinct()
            )
        )
        groups: dict[UUID, OpenConflictGroup] = {}
        for conflict_id in conflict_ids:
            total = int(
                await self._session.scalar(
                    select(func.count())
                    .select_from(MemoryConflictMember)
                    .where(
                        MemoryConflictMember.tenant_id == filters.tenant_id,
                        MemoryConflictMember.lineage_id == filters.lineage_id,
                        MemoryConflictMember.conflict_id == conflict_id,
                    )
                )
                or 0
            )
            visible = tuple(
                await self._session.scalars(
                    select(Memory.memory_id)
                    .join(
                        MemoryConflictMember,
                        and_(
                            MemoryConflictMember.tenant_id == Memory.tenant_id,
                            MemoryConflictMember.lineage_id == Memory.lineage_id,
                            MemoryConflictMember.memory_id == Memory.memory_id,
                            MemoryConflictMember.conflict_id == conflict_id,
                        ),
                    )
                    .where(*_hard_predicates(filters))
                    .order_by(Memory.memory_id)
                )
            )
            groups[conflict_id] = OpenConflictGroup(conflict_id, visible, total)
        return groups

    async def find_open_conflicts(
        self,
        filters: RetrievalFilters,
        subject_id: UUID | None = None,
        limit: int = 100,
    ) -> Mapping[UUID, OpenConflictGroup]:
        """Return internally complete-or-partial groups without exposing hidden rows.

        Callers must include only groups for which ``is_partial`` is false. The
        partial marker exists solely to support that fail-closed decision.
        """

        result_limit = _bounded_limit(limit)
        predicates = list(_hard_predicates(filters))
        if subject_id is not None:
            predicates.append(Memory.subject_id == subject_id)
        memory_ids = tuple(
            await self._session.scalars(
                select(Memory.memory_id)
                .join(
                    MemoryConflictMember,
                    and_(
                        MemoryConflictMember.tenant_id == Memory.tenant_id,
                        MemoryConflictMember.lineage_id == Memory.lineage_id,
                        MemoryConflictMember.memory_id == Memory.memory_id,
                    ),
                )
                .join(
                    MemoryConflict,
                    and_(
                        MemoryConflict.tenant_id == MemoryConflictMember.tenant_id,
                        MemoryConflict.lineage_id == MemoryConflictMember.lineage_id,
                        MemoryConflict.conflict_id == MemoryConflictMember.conflict_id,
                    ),
                )
                .where(
                    *predicates,
                    MemoryConflict.branch_id == filters.branch_id,
                    MemoryConflict.status == "open",
                )
                .order_by(MemoryConflict.opened_at.desc(), Memory.memory_id)
                .limit(result_limit)
            )
        )
        return await self.open_conflict_members(filters, memory_ids)
