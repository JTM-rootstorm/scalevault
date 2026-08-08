from __future__ import annotations

from dataclasses import replace
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.domain.enums import MemoryScope, MemoryStatus, MemoryVisibility
from kivra_memory.storage.retrieval import (
    RetrievalFilters,
    RetrievalRepository,
    embedding_content_sha256_expression,
)
from sqlalchemy.ext.asyncio import AsyncSession


def uid(value: int) -> UUID:
    return UUID(f"019c0000-0000-7000-8000-{value:012x}")


def filters() -> RetrievalFilters:
    return RetrievalFilters(
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        allowed_scopes=frozenset({MemoryScope.GLOBAL}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        allowed_statuses=frozenset({MemoryStatus.ACTIVE}),
        max_sensitivity=1,
        requested_subject_ids=frozenset({uid(4)}),
        project_subject_ids=frozenset({uid(5)}),
        relationship_subject_ids=frozenset({uid(6)}),
        session_subject_ids=frozenset({uid(7)}),
    )


def test_retrieval_filters_fail_closed_when_a_hard_filter_is_empty() -> None:
    with pytest.raises(ValueError, match="at least one"):
        replace(filters(), allowed_scopes=frozenset())
    with pytest.raises(ValueError, match="at least one"):
        replace(filters(), allowed_visibilities=frozenset())
    with pytest.raises(ValueError, match="at least one"):
        replace(filters(), allowed_statuses=frozenset())


async def test_lexical_query_is_parameterized_and_contains_every_hard_filter() -> None:
    result = MagicMock()
    result.all.return_value = []
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock(return_value=result)
    repository = RetrievalRepository(cast(AsyncSession, session))

    assert await repository.lexical_candidates(filters(), "secret search text", 10) == ()

    statement = session.execute.await_args.args[0]
    compiled = statement.compile()
    sql = str(compiled)
    assert "secret search text" not in sql
    assert "memories.tenant_id" in sql
    assert "memories.lineage_id" in sql
    assert "memories.branch_id" in sql
    assert "memories.scope IN" in sql
    assert "memories.visibility IN" in sql
    assert "memories.status IN" in sql
    assert "memories.sensitivity <=" in sql
    assert "memories.subject_id IN" in sql
    assert "secret search text" in compiled.params.values()


def test_embedding_source_hash_uses_the_frozen_domain_separator() -> None:
    compiled = embedding_content_sha256_expression().compile(compile_kwargs={"literal_binds": True})
    sql = str(compiled)

    assert "scalevault.memory.statement.embedding.v1" in sql
    assert "decode('00', 'hex')" in sql
    assert "convert_to(memories.statement, 'UTF8')" in sql
    assert "digest" in sql
    assert "sha256" in sql


@pytest.mark.parametrize(
    "vector",
    [
        [0.1] * 383,
        [0.0] * 384,
        [float("nan")] + [0.1] * 383,
        [float("inf")] + [0.1] * 383,
    ],
)
async def test_vector_query_rejects_invalid_vectors_before_database_access(
    vector: list[float],
) -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    repository = RetrievalRepository(cast(AsyncSession, session))

    with pytest.raises(ValueError, match="query embedding"):
        await repository.vector_candidates(filters(), vector, 10)
    session.execute.assert_not_awaited()


async def test_vector_query_binds_pgvector_compatible_list() -> None:
    result = MagicMock()
    result.all.return_value = []
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock(side_effect=(MagicMock(), result))
    repository = RetrievalRepository(cast(AsyncSession, session))

    assert await repository.vector_candidates(filters(), (1.0,) + (0.0,) * 383, 10) == ()

    statement = session.execute.await_args_list[1].args[0]
    compiled = statement.compile()
    bound_vectors = [
        value for value in compiled.params.values() if isinstance(value, list) and len(value) == 384
    ]
    assert len(bound_vectors) == 1
    assert bound_vectors[0][0] == 1.0
