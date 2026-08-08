"""Idempotent database handler for content-free ``embed_memory`` outbox jobs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.storage.models import EmbeddingModel, Memory, MemoryEmbeddingV1
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob
from kivra_memory.workers.embedding_runtime import (
    EMBEDDING_DIMENSION,
    MODEL_NAME,
    EmbeddingRuntime,
    EmbeddingRuntimeError,
    embedding_source_sha256,
)

_ELIGIBLE_STATUSES: Final = frozenset({"candidate", "active", "disputed"})


class EmbeddingJobError(RuntimeError):
    """Safe handler failure carrying an allowlisted worker error code."""

    def __init__(self, code: Literal["invalid_job", "model_unavailable", "embedding_failed"]):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class EmbeddingJobResult:
    outcome: Literal["embedded", "deleted", "stale", "no_model"]
    model_count: int = 0


def _job_target(job: ClaimedOutboxJob) -> tuple[UUID, int]:
    if (
        job.job_type != "embed_memory"
        or job.aggregate_type != "memory"
        or set(job.payload) != {"event_id", "memory_id", "memory_version"}
    ):
        raise EmbeddingJobError("invalid_job")
    try:
        memory_id = UUID(str(job.payload["memory_id"]))
        event_id = UUID(str(job.payload["event_id"]))
    except (TypeError, ValueError):
        raise EmbeddingJobError("invalid_job") from None
    memory_version = job.payload["memory_version"]
    if (
        isinstance(memory_version, bool)
        or not isinstance(memory_version, int)
        or memory_version < 1
        or job.aggregate_id != memory_id
        or event_id.int == 0
    ):
        raise EmbeddingJobError("invalid_job")
    return memory_id, memory_version


async def handle_embed_memory_job(
    session: AsyncSession,
    *,
    job: ClaimedOutboxJob,
    runtimes_by_artifact: Mapping[bytes, EmbeddingRuntime],
    now: datetime | None = None,
) -> EmbeddingJobResult:
    """Embed the exact current revision or deterministically discard a stale job."""

    memory_id, requested_revision = _job_target(job)
    memory = await session.scalar(
        select(Memory)
        .where(Memory.tenant_id == job.tenant_id, Memory.memory_id == memory_id)
        .with_for_update()
    )
    if memory is None or memory.revision > requested_revision:
        return EmbeddingJobResult("stale")
    if memory.revision < requested_revision:
        raise EmbeddingJobError("invalid_job")
    if memory.status not in _ELIGIBLE_STATUSES or not memory.statement:
        await session.execute(
            delete(MemoryEmbeddingV1).where(
                MemoryEmbeddingV1.tenant_id == job.tenant_id,
                MemoryEmbeddingV1.memory_id == memory_id,
            )
        )
        return EmbeddingJobResult("deleted")

    models = (
        await session.scalars(
            select(EmbeddingModel)
            .where(
                EmbeddingModel.tenant_id == job.tenant_id,
                EmbeddingModel.state.in_(("approved", "evaluating")),
                EmbeddingModel.retired_at.is_(None),
            )
            .order_by(EmbeddingModel.embedding_model_id)
        )
    ).all()
    if not models:
        return EmbeddingJobResult("no_model")

    source_digest = embedding_source_sha256(memory.statement)
    embedded_at = now or datetime.now(UTC)
    completed = 0
    for model in models:
        if (
            model.model_name != MODEL_NAME
            or model.dimension != EMBEDDING_DIMENSION
            or model.distance_metric != "cosine"
        ):
            raise EmbeddingJobError("model_unavailable")
        runtime = runtimes_by_artifact.get(bytes(model.artifact_sha256))
        if runtime is None or bytes.fromhex(runtime.contract.artifact_sha256) != bytes(
            model.artifact_sha256
        ):
            raise EmbeddingJobError("model_unavailable")
        try:
            output = runtime.embed_batch((memory.statement,))[0]
        except EmbeddingRuntimeError:
            raise EmbeddingJobError("embedding_failed") from None

        insert = postgresql_insert(MemoryEmbeddingV1).values(
            tenant_id=memory.tenant_id,
            lineage_id=memory.lineage_id,
            branch_id=memory.branch_id,
            memory_id=memory.memory_id,
            embedding_model_id=model.embedding_model_id,
            source_memory_revision=memory.revision,
            source_event_id=memory.last_event_id,
            input_contract_version="memory-statement-embedding-v1",
            source_content_sha256=source_digest,
            input_truncated=output.truncated,
            embedding=list(output.vector),
            created_at=embedded_at,
        )
        excluded = insert.excluded
        await session.execute(
            insert.on_conflict_do_update(
                index_elements=(
                    MemoryEmbeddingV1.tenant_id,
                    MemoryEmbeddingV1.memory_id,
                    MemoryEmbeddingV1.embedding_model_id,
                ),
                set_={
                    "lineage_id": excluded.lineage_id,
                    "branch_id": excluded.branch_id,
                    "source_memory_revision": excluded.source_memory_revision,
                    "source_event_id": excluded.source_event_id,
                    "input_contract_version": excluded.input_contract_version,
                    "source_content_sha256": excluded.source_content_sha256,
                    "input_truncated": excluded.input_truncated,
                    "embedding": excluded.embedding,
                    "created_at": excluded.created_at,
                },
                where=(excluded.source_memory_revision > MemoryEmbeddingV1.source_memory_revision),
            )
        )
        stored = await session.scalar(
            select(MemoryEmbeddingV1).where(
                MemoryEmbeddingV1.tenant_id == memory.tenant_id,
                MemoryEmbeddingV1.memory_id == memory.memory_id,
                MemoryEmbeddingV1.embedding_model_id == model.embedding_model_id,
            )
        )
        if (
            stored is None
            or stored.source_memory_revision != memory.revision
            or bytes(stored.source_content_sha256) != source_digest
        ):
            raise EmbeddingJobError("invalid_job")
        completed += 1
    await session.flush()
    return EmbeddingJobResult("embedded", model_count=completed)
