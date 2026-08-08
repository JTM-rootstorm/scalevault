from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import cast

from kivra_memory.application.queries import CandidateRepository, QueryEngine, _hit, _modifiers
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import MemoryState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import (
    MemoryLineageQuery,
    QueryPrincipal,
)
from kivra_memory.retrieval.ranking import RRF_V1_PROFILE, SourceRanking, weighted_rrf_v1
from sqlalchemy.ext.asyncio import AsyncSession


def principal(*scopes: str) -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
        scopes=frozenset(scopes),
        allowed_memory_scopes=frozenset(MemoryScope),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=2,
    )


def lineage_query() -> MemoryLineageQuery:
    return MemoryLineageQuery(
        contract_version="mcp-read-v1",
        persona_id=new_uuid7(),
        branch_id=new_uuid7(),
    )


def memory() -> MemoryState:
    now = datetime.now(UTC)
    return MemoryState(
        memory_id=new_uuid7(),
        tenant_id=new_uuid7(),
        lineage_id=new_uuid7(),
        branch_id=new_uuid7(),
        subject_id=new_uuid7(),
        subject_kind=SubjectKind.PROJECT,
        revision=1,
        category=MemoryCategory.PROJECT_STATE,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="Synthetic retrieval statement.",
        reason_to_remember="Synthetic retrieval rationale.",
        interpretation_limits=("Synthetic fixture only.",),
        confidence=Decimal("0.8"),
        salience=Decimal("0.7"),
        durability=Decimal("0.6"),
        sensitivity=0,
        authority_class=AuthorityClass.IMPORTED_LEGACY_MEMORY,
        observed_at=now,
        publication_approved_at=None,
        publication_approved_by_actor_id=None,
        content_protection="plaintext",
        content_key_id=None,
        created_at=now,
        updated_at=now,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


async def test_query_engine_rejects_missing_operation_scope_before_opening_session() -> None:
    opened = False

    @asynccontextmanager
    async def session_factory(_tenant_id: object) -> AsyncIterator[AsyncSession]:
        nonlocal opened
        opened = True
        yield cast(AsyncSession, object())

    engine = QueryEngine(
        session_factory,
        lambda _session: cast(CandidateRepository, object()),
    )

    result = await engine.execute(principal("memory.read.search"), lineage_query())

    assert result.ok is False
    assert result.error.code == "forbidden"
    assert opened is False


async def test_legacy_read_alias_authorizes_all_seven_reads_but_unknown_context_is_hidden() -> None:
    class Repository:
        async def resolve_context(self, **_kwargs: object) -> None:
            return None

    @asynccontextmanager
    async def session_factory(_tenant_id: object) -> AsyncIterator[AsyncSession]:
        yield cast(AsyncSession, object())

    engine = QueryEngine(
        session_factory,
        lambda _session: cast(CandidateRepository, Repository()),
    )

    result = await engine.execute(principal("memory:read"), lineage_query())

    assert result.ok is False
    assert result.error.code == "not_found"


async def test_session_dependency_failure_returns_safe_retryable_error() -> None:
    @asynccontextmanager
    async def session_factory(_tenant_id: object) -> AsyncIterator[AsyncSession]:
        raise OSError("private database address must not escape")
        yield cast(AsyncSession, object())

    engine = QueryEngine(
        session_factory,
        lambda _session: cast(CandidateRepository, object()),
    )

    result = await engine.execute(principal("memory.read.lineage"), lineage_query())

    assert result.ok is False
    assert result.error.code == "dependency_unavailable"
    assert result.error.retryable is True
    assert "database" not in result.error.message.lower()


def test_hit_preserves_reason_and_modifiers_use_checked_in_profile() -> None:
    state = memory().model_copy(update={"authority_class": AuthorityClass.IMPORTED_LEGACY_MEMORY})
    evaluated_at = datetime.now(UTC)
    modifiers = _modifiers(state, evaluated_at)
    score = weighted_rrf_v1(
        (SourceRanking(source="lexical", memory_ids=(state.memory_id,)),),
        {state.memory_id: modifiers},
    )[0].score

    hit = _hit(state, score, new_uuid7())

    assert (
        modifiers.authority
        == RRF_V1_PROFILE.authority_values[AuthorityClass.IMPORTED_LEGACY_MEMORY]
    )
    assert hit.reason_to_remember == state.reason_to_remember
