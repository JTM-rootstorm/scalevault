from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, cast
from uuid import UUID

from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.domain.commands import (
    ForgetCommand,
    MemoryChanges,
    MemoryInput,
    MutationResponse,
    MutationResult,
    RememberCommand,
    ReviseCommand,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import EmbeddingModel, MemoryEmbeddingV1, OutboxJob
from kivra_memory.storage.outbox_worker import (
    ClaimedOutboxJob,
    acknowledge_outbox_job,
    claim_outbox_jobs,
)
from kivra_memory.storage.retrieval import RetrievalFilters, RetrievalRepository
from kivra_memory.workers.embedding_jobs import handle_embed_memory_job
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    MODEL_NAME,
    MODEL_REVISION,
    EmbeddingModelContract,
    EmbeddingOutput,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 9, tzinfo=UTC)
_ARTIFACT_DIGEST = bytes.fromhex("cd" * 32)


class PostgreSQLTestServer(Protocol):
    database_url: str


class _FakeEmbeddingRuntime:
    def __init__(self) -> None:
        self._contract = EmbeddingModelContract(
            artifact_sha256=_ARTIFACT_DIGEST.hex(),
            model_name=MODEL_NAME,
            upstream_revision=MODEL_REVISION,
        )
        self.calls: list[tuple[str, ...]] = []

    @property
    def contract(self) -> EmbeddingModelContract:
        return self._contract

    def embed_batch(self, texts: Sequence[str]) -> tuple[EmbeddingOutput, ...]:
        batch = tuple(texts)
        self.calls.append(batch)
        return tuple(
            EmbeddingOutput(
                vector=_vector(1 if "revised" in text.lower() else 0),
                truncated=False,
            )
            for text in batch
        )


def _vector(index: int) -> tuple[float, ...]:
    values = [0.0] * EMBEDDING_DIMENSION
    values[index] = 1.0
    return tuple(values)


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _principal() -> CommandPrincipal:
    binding = seed_rows()["transport_bindings"][0]
    return CommandPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=frozenset({"memory:write"}),
    )


def _base_command(key: str) -> dict[str, Any]:
    return {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": key,
        "logical_session_id": None,
        "persona_id": _seed_identifier("personas", "persona_id"),
        "branch_id": _seed_identifier("branches", "branch_id"),
        "reason": "Exercise deterministic asynchronous embedding behavior.",
    }


def _remember() -> RememberCommand:
    return RememberCommand(
        **_base_command("embedding-memory-create"),
        memory=MemoryInput(
            subject_id=_seed_identifier("subjects", "subject_id"),
            subject_kind=SubjectKind.GLOBAL,
            category=MemoryCategory.STABLE_FACT,
            ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
            scope=MemoryScope.GLOBAL,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement="Synthetic embedding version one.",
            reason_to_remember="This record verifies asynchronous vector replacement.",
            interpretation_limits=("Synthetic integration-test data only.",),
            confidence=Decimal("0.900000"),
            salience=Decimal("0.800000"),
            durability=Decimal("0.700000"),
            sensitivity=0,
            authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
            observed_at=_NOW,
            metadata={"fixture": True},
        ),
    )


def _success(response: MutationResponse) -> MutationResult:
    assert isinstance(response, MutationResult), response
    return response


def _filters() -> RetrievalFilters:
    return RetrievalFilters(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        lineage_id=_seed_identifier("lineages", "lineage_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        allowed_scopes=frozenset({MemoryScope.GLOBAL}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        allowed_statuses=frozenset({MemoryStatus.ACTIVE}),
        max_sensitivity=0,
    )


@asynccontextmanager
async def _seeded_engine(
    database_url: str,
) -> AsyncIterator[tuple[Database, MutationEngine]]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_principal().tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            session.add(
                EmbeddingModel(
                    embedding_model_id=new_uuid7(),
                    tenant_id=_principal().tenant_id,
                    model_name=MODEL_NAME,
                    artifact_sha256=_ARTIFACT_DIGEST,
                    dimension=EMBEDDING_DIMENSION,
                    distance_metric="cosine",
                    tokenizer_details={"max_input_tokens": 256},
                    runtime_details={"provider": "synthetic-test"},
                    normalization_settings={"kind": "l2"},
                    state="approved",
                    created_at=_NOW,
                    activated_at=_NOW,
                    retired_at=None,
                )
            )
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        yield database, MutationEngine(factory)
    finally:
        await database.dispose()


async def _claim_embedding(database: Database, *, owner: str) -> ClaimedOutboxJob:
    async with database.tenant_session(_principal().tenant_id) as session:
        jobs = await claim_outbox_jobs(
            session,
            tenant_id=_principal().tenant_id,
            worker_owner=owner,
            job_types=("embed_memory",),
            batch_size=1,
            lease_seconds=30,
            now=_NOW,
        )
        assert len(jobs) == 1
        return jobs[0]


async def _handle_and_ack(
    database: Database,
    job: ClaimedOutboxJob,
    runtime: _FakeEmbeddingRuntime,
) -> str:
    async with database.tenant_session(_principal().tenant_id) as session:
        result = await handle_embed_memory_job(
            session,
            job=job,
            runtimes_by_artifact={_ARTIFACT_DIGEST: runtime},
            now=_NOW,
        )
        await acknowledge_outbox_job(
            session,
            tenant_id=_principal().tenant_id,
            job_id=job.job_id,
            lease_token=job.lease_token,
            now=_NOW,
        )
        return result.outcome


async def test_embedding_queue_is_async_revision_safe_idempotent_and_tombstone_clean(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    runtime = _FakeEmbeddingRuntime()
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        created = _success(await engine.execute(_principal(), _remember()))
        memory_id = created.memory_id
        assert memory_id is not None
        assert runtime.calls == []

        async with database.tenant_session(_principal().tenant_id) as session:
            repository = RetrievalRepository(session)
            lexical = await repository.lexical_candidates(_filters(), "embedding version", 5)
            assert [item.memory_id for item in lexical] == [memory_id]
            assert not await repository.vector_candidates(_filters(), _vector(0), 5)

        version_one_job = await _claim_embedding(database, owner="embedding-worker-v1")
        assert version_one_job.payload["memory_version"] == 1
        assert await _handle_and_ack(database, version_one_job, runtime) == "embedded"
        assert runtime.calls == [("Synthetic embedding version one.",)]

        async with database.tenant_session(_principal().tenant_id) as session:
            repository = RetrievalRepository(session)
            semantic = await repository.vector_candidates(_filters(), _vector(0), 5)
            assert [item.memory_id for item in semantic] == [memory_id]
            assert semantic[0].channel == "vector"
            assert semantic[0].channel_score == 1.0
            assert await session.scalar(select(func.count()).select_from(MemoryEmbeddingV1)) == 1

        # Re-running the pure handler for the same source revision does not duplicate storage.
        async with database.tenant_session(_principal().tenant_id) as session:
            replay = await handle_embed_memory_job(
                session,
                job=version_one_job,
                runtimes_by_artifact={_ARTIFACT_DIGEST: runtime},
                now=_NOW,
            )
            assert replay.outcome == "embedded"
            assert await session.scalar(select(func.count()).select_from(MemoryEmbeddingV1)) == 1

        revised = _success(
            await engine.execute(
                _principal(),
                ReviseCommand(
                    **_base_command("embedding-memory-revise"),
                    memory_id=memory_id,
                    expected_revision=1,
                    changes=MemoryChanges(statement="Synthetic revised embedding version two."),
                ),
            )
        )
        assert revised.revision == 2
        async with database.tenant_session(_principal().tenant_id) as session:
            repository = RetrievalRepository(session)
            assert not await repository.vector_candidates(_filters(), _vector(0), 5)
            stale = await handle_embed_memory_job(
                session,
                job=version_one_job,
                runtimes_by_artifact={_ARTIFACT_DIGEST: runtime},
                now=_NOW,
            )
            assert stale.outcome == "stale"

        version_two_job = await _claim_embedding(database, owner="embedding-worker-v2")
        assert version_two_job.payload["memory_version"] == 2
        assert await _handle_and_ack(database, version_two_job, runtime) == "embedded"
        async with database.tenant_session(_principal().tenant_id) as session:
            repository = RetrievalRepository(session)
            old_direction = await repository.vector_candidates(_filters(), _vector(0), 5)
            assert [item.memory_id for item in old_direction] == [memory_id]
            assert old_direction[0].channel_score == 0.0
            replacement = await repository.vector_candidates(_filters(), _vector(1), 5)
            assert [item.memory_id for item in replacement] == [memory_id]
            assert replacement[0].channel_score == 1.0
            row = await session.scalar(
                select(MemoryEmbeddingV1).where(MemoryEmbeddingV1.memory_id == memory_id)
            )
            assert row is not None
            assert row.source_memory_revision == 2

        forgotten = _success(
            await engine.execute(
                _principal(),
                ForgetCommand(
                    **_base_command("embedding-memory-forget"),
                    memory_id=memory_id,
                    expected_revision=2,
                    mode="logical",
                    confirmation="confirm_logical_forget",
                ),
            )
        )
        assert forgotten.revision == 3
        cleanup_job = await _claim_embedding(database, owner="embedding-worker-cleanup")
        assert cleanup_job.payload["memory_version"] == 3
        assert await _handle_and_ack(database, cleanup_job, runtime) == "deleted"
        async with database.tenant_session(_principal().tenant_id) as session:
            repository = RetrievalRepository(session)
            assert not await repository.lexical_candidates(_filters(), "embedding", 5)
            assert not await repository.vector_candidates(_filters(), _vector(1), 5)
            assert await session.scalar(select(func.count()).select_from(MemoryEmbeddingV1)) == 0
            cleanup = await session.get(OutboxJob, cleanup_job.job_id)
            assert cleanup is not None
            assert cleanup.state == "succeeded"
