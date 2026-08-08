"""Transport-neutral orchestration for authorized semantic memory reads."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.enums import (
    EventOperation,
    MemoryStatus,
)
from kivra_memory.domain.events import MemoryState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.budgeting import BudgetTooSmallError
from kivra_memory.retrieval.context_pack import assemble_context_pack
from kivra_memory.retrieval.contracts import (
    BranchView,
    ChannelAvailability,
    ChannelState,
    ConflictGroup,
    ContextPackQuery,
    DirectReadQuery,
    MemoryConflictsPayload,
    MemoryConflictsQuery,
    MemoryConflictsResult,
    MemoryFilters,
    MemoryGetPayload,
    MemoryGetQuery,
    MemoryGetResult,
    MemoryHit,
    MemoryLineagePayload,
    MemoryLineageQuery,
    MemoryLineageResult,
    MemoryScore,
    MemorySearchPage,
    MemorySearchQuery,
    MemorySearchResult,
    MemorySelectionDecisionsPayload,
    MemorySelectionDecisionsQuery,
    MemorySelectionDecisionsResult,
    MemorySelectionHistoryPayload,
    MemorySelectionHistoryQuery,
    MemorySelectionHistoryResult,
    MemoryTimelinePayload,
    MemoryTimelineQuery,
    MemoryTimelineResult,
    PaginationMetadata,
    QueryPrincipal,
    ReadError,
    ReadErrorBody,
    ReadErrorV2,
    ReadQueryV2,
    ReadResponse,
    ReadResponseV2,
    ReadResultMetadata,
    ReadWarningCode,
    RetrievalProfileInfo,
    ScoreModifiers,
    SelectionDecisionView,
    SelectionEventRecord,
    TimelineEvent,
)
from kivra_memory.retrieval.eligibility import (
    EligibilityCandidate,
    ResolvedReadContext,
    conflict_group_eligible,
    evaluate_eligibility,
    operation_authorized,
)
from kivra_memory.retrieval.ranking import (
    RRF_V1_PROFILE_SHA256,
    SourceRanking,
    score_modifiers_v1,
    weighted_rrf_v1,
)
from kivra_memory.storage.retrieval import (
    HydratedMemory,
    LineageMetadata,
    OpenConflictGroup,
    RankedCandidate,
    RetrievalFilters,
    TimelineEntry,
)
from kivra_memory.storage.retrieval import (
    ResolvedReadContext as StorageReadContext,
)
from kivra_memory.storage.selection_history import (
    SelectionDecisionRecord,
    SelectionHistoryError,
    SelectionHistoryFilters,
    SelectionHistoryRepository,
)

_READABLE_STATUSES = frozenset({MemoryStatus.ACTIVE, MemoryStatus.DISPUTED})


class QueryEmbedder(Protocol):
    async def embed_query(self, tenant_id: UUID, query: str) -> Sequence[float]: ...


class CandidateRepository(Protocol):
    async def resolve_context(
        self,
        *,
        tenant_id: UUID,
        actor_id: UUID,
        client_id: UUID,
        transport_binding_id: UUID,
        persona_id: UUID,
        branch_id: UUID,
        logical_session_id: UUID | None,
        project_ref: str | None,
        relationship_ref: str | None,
    ) -> StorageReadContext | None: ...

    async def lexical_candidates(
        self, filters: RetrievalFilters, query: str, limit: int
    ) -> tuple[RankedCandidate, ...]: ...

    async def trigram_candidates(
        self, filters: RetrievalFilters, query: str, limit: int
    ) -> tuple[RankedCandidate, ...]: ...

    async def vector_candidates(
        self, filters: RetrievalFilters, query_embedding: Sequence[float], limit: int
    ) -> tuple[RankedCandidate, ...]: ...

    async def hydrate_memories(
        self, filters: RetrievalFilters, memory_ids: Sequence[UUID]
    ) -> tuple[HydratedMemory, ...]: ...

    async def get_memory(
        self, filters: RetrievalFilters, memory_id: UUID
    ) -> HydratedMemory | None: ...

    async def open_conflict_members(
        self, filters: RetrievalFilters, memory_ids: Sequence[UUID]
    ) -> Mapping[UUID, OpenConflictGroup]: ...

    async def find_open_conflicts(
        self, filters: RetrievalFilters, subject_id: UUID | None, limit: int
    ) -> Mapping[UUID, OpenConflictGroup]: ...

    async def timeline(
        self,
        filters: RetrievalFilters,
        *,
        start: datetime | None,
        end: datetime | None,
        before_sequence: int | None,
        limit: int,
    ) -> tuple[TimelineEntry, ...]: ...

    async def lineage_metadata(
        self, *, tenant_id: UUID, persona_id: UUID, branch_id: UUID
    ) -> LineageMetadata | None: ...

    async def selection_events(
        self, filters: RetrievalFilters, *, before_sequence: int | None, limit: int
    ) -> tuple[TimelineEntry, ...]: ...


type SessionFactory = Callable[[UUID], AbstractAsyncContextManager[AsyncSession]]
type RepositoryFactory = Callable[[AsyncSession], CandidateRepository]


class SelectionHistoryReader(Protocol):
    async def list_decisions(
        self,
        filters: SelectionHistoryFilters,
        *,
        before_sequence: int | None = None,
        limit: int = 100,
    ) -> tuple[SelectionDecisionRecord, ...]: ...


type SelectionHistoryRepositoryFactory = Callable[[AsyncSession], SelectionHistoryReader]


def _error(
    code: Literal[
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "not_found",
        "invalid_cursor",
        "budget_too_small",
        "dependency_unavailable",
        "internal_error",
    ],
    *,
    retryable: bool = False,
) -> ReadError:
    return ReadError(
        error=ReadErrorBody(
            code=code,
            message=ReadErrorBody.SAFE_MESSAGES[code],
            retryable=retryable,
        )
    )


def _error_v2(
    code: Literal[
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "not_found",
        "invalid_cursor",
        "budget_too_small",
        "dependency_unavailable",
        "internal_error",
    ],
    *,
    retryable: bool = False,
) -> ReadErrorV2:
    return ReadErrorV2(
        error=ReadErrorBody(
            code=code,
            message=ReadErrorBody.SAFE_MESSAGES[code],
            retryable=retryable,
        )
    )


_SELECTION_CURSOR_PREFIX = b"selection-decisions-v2:"


def _encode_selection_cursor(sequence: int) -> str:
    payload = _SELECTION_CURSOR_PREFIX + str(sequence).encode("ascii")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_selection_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    try:
        encoded = cursor.encode("ascii")
        payload = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        if not payload.startswith(_SELECTION_CURSOR_PREFIX):
            raise ValueError("invalid selection cursor")
        sequence = int(payload.removeprefix(_SELECTION_CURSOR_PREFIX))
    except (UnicodeError, ValueError):
        raise ValueError("invalid selection cursor") from None
    if sequence < 1:
        raise ValueError("invalid selection cursor")
    return sequence


def _selection_decision(record: SelectionDecisionRecord) -> SelectionDecisionView:
    return SelectionDecisionView(
        selection_sequence=record.selection_sequence,
        decision_id=record.decision_id,
        profile_version="selection-v1",
        profile_sha256=record.policy_sha256,
        matched_rule_ids=record.matched_rule_ids,
        outcome=cast(
            Literal["omit", "reject", "candidate", "active", "promoted", "expired"],
            record.outcome,
        ),
        reason_codes=record.reason_codes,
        memory_id=record.memory_id,
        event_id=record.event_id,
        decided_at=record.decided_at,
    )


def _query_filters(query: DirectReadQuery) -> MemoryFilters:
    if isinstance(query, MemorySearchQuery | MemoryTimelineQuery):
        return query.filters
    if isinstance(query, ContextPackQuery):
        return MemoryFilters(scopes=query.requested_memory_scopes)
    return MemoryFilters()


def _storage_filters(
    principal: QueryPrincipal,
    context: ResolvedReadContext,
    anchors: StorageReadContext,
    requested: MemoryFilters,
) -> RetrievalFilters:
    scopes = principal.allowed_memory_scopes
    if requested.scopes:
        scopes = scopes & requested.scopes
    visibilities = principal.allowed_visibilities
    if requested.visibilities:
        visibilities = visibilities & requested.visibilities
    statuses = set(_READABLE_STATUSES)
    if principal.allow_candidates and requested.include_candidates:
        statuses.add(MemoryStatus.CANDIDATE)
    return RetrievalFilters(
        tenant_id=principal.tenant_id,
        lineage_id=context.lineage_id,
        branch_id=context.branch_id,
        allowed_scopes=frozenset(scopes),
        allowed_visibilities=frozenset(visibilities),
        allowed_statuses=frozenset(statuses),
        max_sensitivity=principal.max_sensitivity,
        requested_subject_ids=frozenset(requested.subject_ids) or None,
        project_subject_ids=anchors.project_subject_ids,
        relationship_subject_ids=anchors.relationship_subject_ids,
        session_subject_ids=anchors.session_subject_ids,
        allowed_subject_kinds=requested.subject_kinds or None,
        allowed_categories=requested.categories or None,
        allowed_ontological_statuses=requested.ontological_statuses or None,
        valid_at=requested.valid_at,
    )


def _candidate(memory: MemoryState) -> EligibilityCandidate:
    return EligibilityCandidate(
        tenant_id=memory.tenant_id,
        lineage_id=memory.lineage_id,
        branch_id=memory.branch_id,
        memory_id=memory.memory_id,
        subject_id=memory.subject_id,
        subject_kind=memory.subject_kind,
        scope=memory.scope,
        visibility=memory.visibility,
        sensitivity=memory.sensitivity,
        status=memory.status,
        origin_session_id=memory.origin_session_id,
        valid_from=memory.valid_from,
        valid_to=memory.valid_to,
        category=memory.category,
        ontological_status=memory.ontological_status,
    )


def _modifiers(memory: MemoryState, evaluated_at: datetime) -> ScoreModifiers:
    return score_modifiers_v1(
        scope_match=1.0,
        authority_class=memory.authority_class,
        confidence=float(memory.confidence),
        salience=float(memory.salience),
        category=memory.category,
        observed_at=memory.observed_at,
        evaluated_at=evaluated_at,
    )


def _hit(memory: MemoryState, score: MemoryScore, last_event_id: UUID) -> MemoryHit:
    if memory.statement is None:
        raise ValueError("retrieved memory has no statement")
    return MemoryHit(
        memory_id=memory.memory_id,
        revision=memory.revision,
        last_event_id=last_event_id,
        branch_id=memory.branch_id,
        subject_id=memory.subject_id,
        subject_kind=memory.subject_kind,
        category=memory.category,
        ontological_status=memory.ontological_status,
        scope=memory.scope,
        visibility=memory.visibility,
        status=cast(Literal["candidate", "active", "disputed"], memory.status.value),
        statement=memory.statement,
        reason_to_remember=memory.reason_to_remember,
        interpretation_limits=memory.interpretation_limits,
        authority_class=memory.authority_class,
        valid_from=memory.valid_from,
        valid_to=memory.valid_to,
        observed_at=memory.observed_at,
        score=score,
    )


def _timeline_event(entry: TimelineEntry) -> TimelineEvent:
    return TimelineEvent(
        event_id=entry.event_id,
        sequence=entry.sequence,
        operation=EventOperation(entry.operation),
        memory_id=entry.memory_id,
        created_at=entry.created_at,
    )


def _selection_event(entry: TimelineEntry) -> SelectionEventRecord:
    return SelectionEventRecord(
        event_id=entry.event_id,
        sequence=entry.sequence,
        operation=EventOperation(entry.operation),
        memory_id=entry.memory_id,
        created_at=entry.created_at,
    )


def _branch_view(value: LineageMetadata) -> BranchView:
    return BranchView(
        branch_id=value.branch_id,
        parent_branch_id=value.parent_branch_id,
        fork_event_sequence=value.fork_event_sequence,
        name="current",
        visibility_ceiling=value.visibility_ceiling,
        sealed=value.sealed_at is not None,
    )


def _retrieval_profile(semantic_available: bool) -> RetrievalProfileInfo:
    return RetrievalProfileInfo(
        sha256=RRF_V1_PROFILE_SHA256,
        channels=ChannelAvailability(
            lexical=ChannelState(availability="available"),
            trigram=ChannelState(availability="available"),
            semantic=(
                ChannelState(availability="available")
                if semantic_available
                else ChannelState(availability="unavailable", reason="dependency_unavailable")
            ),
        ),
    )


class QueryEngine:
    """Resolve identity, authorize, retrieve, and shape reads without transport state."""

    def __init__(
        self,
        session_factory: SessionFactory,
        repository_factory: RepositoryFactory,
        *,
        query_embedder: QueryEmbedder | None = None,
        selection_history_repository_factory: SelectionHistoryRepositoryFactory = (
            SelectionHistoryRepository
        ),
    ) -> None:
        self._session_factory = session_factory
        self._repository_factory = repository_factory
        self._query_embedder = query_embedder
        self._selection_history_repository_factory = selection_history_repository_factory

    async def execute(
        self, principal: QueryPrincipal, query: DirectReadQuery | ReadQueryV2
    ) -> ReadResponse | ReadResponseV2:
        if not operation_authorized(principal, cast(DirectReadQuery, query)):
            return (
                _error_v2("forbidden")
                if isinstance(query, MemorySelectionDecisionsQuery)
                else _error("forbidden")
            )
        try:
            async with self._session_factory(principal.tenant_id) as session:
                repository = self._repository_factory(session)
                storage_context = await repository.resolve_context(
                    tenant_id=principal.tenant_id,
                    actor_id=principal.actor_id,
                    client_id=principal.client_id,
                    transport_binding_id=principal.transport_binding_id,
                    persona_id=query.persona_id,
                    branch_id=query.branch_id,
                    logical_session_id=query.logical_session_id,
                    project_ref=query.project_ref,
                    relationship_ref=query.relationship_ref,
                )
                if storage_context is None:
                    return _error("not_found")
                if (
                    len(storage_context.project_subject_ids) > 1
                    or len(storage_context.relationship_subject_ids) > 1
                ):
                    return _error("not_found")
                context = ResolvedReadContext(
                    tenant_id=principal.tenant_id,
                    lineage_id=storage_context.lineage_id,
                    branch_id=storage_context.branch_id,
                    logical_session_id=storage_context.logical_session_id,
                    project_subject_id=next(iter(storage_context.project_subject_ids), None),
                    relationship_subject_id=next(
                        iter(storage_context.relationship_subject_ids), None
                    ),
                )
                if isinstance(query, MemorySelectionDecisionsQuery):
                    return await self._selection_decisions(
                        session,
                        principal,
                        context,
                        storage_context,
                        query,
                    )
                requested = _query_filters(query)
                try:
                    filters = _storage_filters(principal, context, storage_context, requested)
                except ValueError:
                    return _error("forbidden")
                return await self._dispatch(
                    repository, principal, context, filters, requested, query
                )
        except (OSError, TimeoutError):
            return (
                _error_v2("dependency_unavailable", retryable=True)
                if isinstance(query, MemorySelectionDecisionsQuery)
                else _error("dependency_unavailable", retryable=True)
            )
        except Exception:
            return (
                _error_v2("internal_error")
                if isinstance(query, MemorySelectionDecisionsQuery)
                else _error("internal_error")
            )

    async def _selection_decisions(
        self,
        session: AsyncSession,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        anchors: StorageReadContext,
        query: MemorySelectionDecisionsQuery,
    ) -> ReadResponseV2:
        try:
            before_sequence = _decode_selection_cursor(query.cursor)
        except ValueError:
            return _error_v2("invalid_cursor")

        scopes = principal.allowed_memory_scopes
        if query.requested_memory_scopes:
            scopes &= query.requested_memory_scopes
        visibilities = principal.allowed_visibilities
        if query.requested_visibilities:
            visibilities &= query.requested_visibilities
        if not scopes or not visibilities:
            return _error_v2("forbidden")
        max_sensitivity = principal.max_sensitivity
        if query.max_sensitivity is not None:
            max_sensitivity = min(max_sensitivity, query.max_sensitivity)
        filters = SelectionHistoryFilters(
            tenant_id=principal.tenant_id,
            persona_id=query.persona_id,
            lineage_id=context.lineage_id,
            branch_id=context.branch_id,
            allowed_scopes=scopes,
            allowed_visibilities=visibilities,
            max_sensitivity=max_sensitivity,
            selection_bases=frozenset(item.value for item in query.selection_bases) or None,
            requested_subject_ids=frozenset(query.requested_subject_ids) or None,
            project_subject_ids=anchors.project_subject_ids,
            relationship_subject_ids=anchors.relationship_subject_ids,
            session_subject_ids=anchors.session_subject_ids,
            allowed_subject_kinds=query.requested_subject_kinds or None,
        )
        repository = self._selection_history_repository_factory(session)
        try:
            records = await repository.list_decisions(
                filters,
                before_sequence=before_sequence,
                limit=query.limit + 1,
            )
        except SelectionHistoryError:
            return _error_v2("dependency_unavailable")
        has_more = len(records) > query.limit
        visible = records[: query.limit]
        next_cursor = (
            _encode_selection_cursor(visible[-1].selection_sequence)
            if has_more and visible
            else None
        )
        return MemorySelectionDecisionsResult(
            result=MemorySelectionDecisionsPayload(
                decisions=tuple(_selection_decision(record) for record in visible)
            ),
            metadata=ReadResultMetadata(
                pagination=PaginationMetadata(
                    next_cursor=next_cursor,
                    has_more=has_more,
                )
            ),
        )

    async def _dispatch(
        self,
        repository: CandidateRepository,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        filters: RetrievalFilters,
        requested: MemoryFilters,
        query: DirectReadQuery,
    ) -> ReadResponse:
        evaluated_at = datetime.now(UTC)
        if isinstance(query, MemorySearchQuery | ContextPackQuery):
            hits, warnings = await self._ranked_hits(
                repository, principal, context, filters, requested, query, evaluated_at
            )
            conflicts = await self._conflicts(
                repository,
                principal,
                context,
                filters,
                requested,
                query,
                hits,
                evaluated_at,
            )
            limit = query.limit if isinstance(query, MemorySearchQuery) else 64
            if isinstance(query, MemorySearchQuery):
                conflict_members = {
                    member.memory_id: member for group in conflicts for member in group.members
                }
                expanded = {hit.memory_id: hit for hit in hits}
                expanded.update(conflict_members)
                ordered = tuple(
                    sorted(
                        expanded.values(),
                        key=lambda item: (-item.score.final_score, str(item.memory_id)),
                    )
                )
                hits = ordered[:limit]
                complete_ids = {hit.memory_id for hit in hits}
                partial_ids = {
                    member.memory_id
                    for group in conflicts
                    if not {member.memory_id for member in group.members} <= complete_ids
                    for member in group.members
                }
                hits = tuple(hit for hit in hits if hit.memory_id not in partial_ids)
                return MemorySearchResult(
                    result=MemorySearchPage(query_id=new_uuid7(), hits=hits),
                    warnings=warnings,
                    metadata=ReadResultMetadata(retrieval=_retrieval_profile(not warnings)),
                )
            try:
                return assemble_context_pack(
                    context_pack_id=new_uuid7(),
                    hits=hits,
                    conflicts=conflicts,
                    requested_units=query.token_budget,
                    retrieval=_retrieval_profile(not warnings),
                    include_evidence=False,
                    requested_scope_reduction=bool(query.requested_memory_scopes),
                )
            except BudgetTooSmallError:
                return _error("budget_too_small")
        if isinstance(query, MemoryGetQuery):
            memory = await repository.get_memory(filters, query.memory_id)
            if memory is None or not self._eligible(
                principal, context, requested, query, memory.state, evaluated_at
            ):
                return _error("not_found")
            score = weighted_rrf_v1(
                (SourceRanking(source="lexical", memory_ids=(memory.state.memory_id,)),),
                {memory.state.memory_id: _modifiers(memory.state, evaluated_at)},
            )[0].score
            hit = _hit(memory.state, score, memory.last_event_id)
            conflicts = (
                await self._conflicts(
                    repository,
                    principal,
                    context,
                    filters,
                    requested,
                    query,
                    (hit,),
                    evaluated_at,
                )
                if query.include_conflicts
                else ()
            )
            return MemoryGetResult(
                result=MemoryGetPayload(memory=hit, conflicts=conflicts),
                metadata=ReadResultMetadata(),
            )
        if isinstance(query, MemoryTimelineQuery):
            entries = await repository.timeline(
                filters,
                start=query.window.starts_at,
                end=query.window.ends_at,
                before_sequence=None,
                limit=query.limit,
            )
            return MemoryTimelineResult(
                result=MemoryTimelinePayload(
                    events=tuple(_timeline_event(item) for item in entries)
                ),
                metadata=ReadResultMetadata(),
            )
        if isinstance(query, MemoryLineageQuery):
            lineage = await repository.lineage_metadata(
                tenant_id=principal.tenant_id,
                persona_id=query.persona_id,
                branch_id=query.branch_id,
            )
            if lineage is None or lineage.lineage_id != context.lineage_id:
                return _error("not_found")
            return MemoryLineageResult(
                result=MemoryLineagePayload(branch=_branch_view(lineage)),
                metadata=ReadResultMetadata(),
            )
        if isinstance(query, MemorySelectionHistoryQuery):
            entries = await repository.selection_events(
                filters, before_sequence=None, limit=query.limit
            )
            return MemorySelectionHistoryResult(
                result=MemorySelectionHistoryPayload(
                    events=tuple(_selection_event(item) for item in entries)
                ),
                metadata=ReadResultMetadata(),
            )
        if isinstance(query, MemoryConflictsQuery):
            subject_ids = {query.subject_id} if query.subject_id is not None else set()
            if query.query is not None:
                lexical = await repository.lexical_candidates(filters, query.query, query.limit)
                trigram = await repository.trigram_candidates(filters, query.query, query.limit)
                candidate_ids = tuple(
                    dict.fromkeys(item.memory_id for item in (*lexical, *trigram))
                )
                candidates = await repository.hydrate_memories(filters, candidate_ids)
                subject_ids.update(
                    item.state.subject_id
                    for item in candidates
                    if self._eligible(
                        principal, context, requested, query, item.state, evaluated_at
                    )
                )
            groups: dict[UUID, OpenConflictGroup] = {}
            for subject_id in subject_ids:
                groups.update(
                    await repository.find_open_conflicts(filters, subject_id, query.limit)
                )
            conflicts = await self._hydrate_conflict_groups(
                repository,
                principal,
                context,
                filters,
                requested,
                query,
                groups,
                evaluated_at,
            )
            return MemoryConflictsResult(
                result=MemoryConflictsPayload(conflicts=conflicts),
                metadata=ReadResultMetadata(),
            )
        return _error("invalid_input")

    def _eligible(
        self,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        filters: MemoryFilters,
        query: DirectReadQuery,
        memory: MemoryState,
        evaluated_at: datetime,
    ) -> bool:
        return evaluate_eligibility(
            principal,
            context,
            _candidate(memory),
            query=query,
            filters=filters,
            evaluated_at=evaluated_at,
        ).eligible

    async def _ranked_hits(
        self,
        repository: CandidateRepository,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        filters: RetrievalFilters,
        requested: MemoryFilters,
        query: MemorySearchQuery | ContextPackQuery,
        evaluated_at: datetime,
    ) -> tuple[tuple[MemoryHit, ...], tuple[ReadWarningCode, ...]]:
        requested_limit = query.limit if isinstance(query, MemorySearchQuery) else 64
        depth = min(500, max(100, requested_limit * 4))
        lexical = await repository.lexical_candidates(filters, query.query, depth)
        trigram = await repository.trigram_candidates(filters, query.query, depth)
        vector: tuple[RankedCandidate, ...] = ()
        warnings: tuple[ReadWarningCode, ...] = ()
        if self._query_embedder is None:
            warnings = ("embeddings_unavailable",)
        else:
            try:
                embedded = await self._query_embedder.embed_query(principal.tenant_id, query.query)
                vector = await repository.vector_candidates(filters, embedded, depth)
            except Exception:
                warnings = ("embeddings_unavailable",)
        source_rankings = tuple(
            SourceRanking(
                source=cast(Literal["lexical", "trigram", "semantic"], source),
                memory_ids=tuple(item.memory_id for item in values),
            )
            for source, values in (
                ("lexical", lexical),
                ("trigram", trigram),
                ("semantic", vector),
            )
            if values
        )
        ordered_ids = tuple(
            dict.fromkeys(
                item.memory_id for values in (lexical, trigram, vector) for item in values
            )
        )
        memories = await repository.hydrate_memories(filters, ordered_ids)
        memories = tuple(
            memory
            for memory in memories
            if self._eligible(principal, context, requested, query, memory.state, evaluated_at)
        )
        by_id = {memory.state.memory_id: memory for memory in memories}
        ranked = weighted_rrf_v1(
            source_rankings,
            {item.state.memory_id: _modifiers(item.state, evaluated_at) for item in memories},
        )
        hits = tuple(
            _hit(by_id[item.memory_id].state, item.score, by_id[item.memory_id].last_event_id)
            for item in ranked
            if item.memory_id in by_id
        )
        return hits, warnings

    async def _conflicts(
        self,
        repository: CandidateRepository,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        filters: RetrievalFilters,
        requested: MemoryFilters,
        query: DirectReadQuery,
        hits: tuple[MemoryHit, ...],
        evaluated_at: datetime,
    ) -> tuple[ConflictGroup, ...]:
        groups = await repository.open_conflict_members(
            filters, tuple(hit.memory_id for hit in hits)
        )
        return await self._hydrate_conflict_groups(
            repository, principal, context, filters, requested, query, groups, evaluated_at
        )

    async def _hydrate_conflict_groups(
        self,
        repository: CandidateRepository,
        principal: QueryPrincipal,
        context: ResolvedReadContext,
        filters: RetrievalFilters,
        requested: MemoryFilters,
        query: DirectReadQuery,
        groups: Mapping[UUID, OpenConflictGroup],
        evaluated_at: datetime,
    ) -> tuple[ConflictGroup, ...]:
        output: list[ConflictGroup] = []
        for group in groups.values():
            if group.is_partial:
                continue
            memories = await repository.hydrate_memories(filters, group.visible_memory_ids)
            decisions = tuple(
                evaluate_eligibility(
                    principal,
                    context,
                    _candidate(memory.state),
                    query=query,
                    filters=requested,
                    evaluated_at=evaluated_at,
                )
                for memory in memories
            )
            if len(memories) != group.total_member_count or not conflict_group_eligible(decisions):
                continue
            ranking = weighted_rrf_v1(
                (
                    SourceRanking(
                        source="lexical",
                        memory_ids=tuple(item.state.memory_id for item in memories),
                    ),
                ),
                {item.state.memory_id: _modifiers(item.state, evaluated_at) for item in memories},
            )
            scores = {item.memory_id: item.score for item in ranking}
            members = tuple(
                _hit(item.state, scores[item.state.memory_id], item.last_event_id)
                for item in memories
            )
            output.append(
                ConflictGroup(
                    conflict_id=group.conflict_id,
                    subject_id=members[0].subject_id,
                    members=members,
                )
            )
        return tuple(output)
