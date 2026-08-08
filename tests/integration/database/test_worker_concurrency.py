from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import OutboxJob
from kivra_memory.storage.outbox import enqueue_outbox_job
from kivra_memory.storage.outbox_worker import (
    ClaimedOutboxJob,
    LeaseLostError,
    acknowledge_outbox_job,
    claim_outbox_jobs,
    fail_outbox_job,
    heartbeat_outbox_job,
    recover_expired_outbox_leases,
)
from sqlalchemy import select

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 9, tzinfo=UTC)


class PostgreSQLTestServer(Protocol):
    database_url: str


def _tenant_id() -> UUID:
    return cast(UUID, seed_rows()["tenants"][0]["tenant_id"])


@asynccontextmanager
async def _seeded_database(database_url: str) -> AsyncIterator[Database]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_tenant_id()) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
        yield database
    finally:
        await database.dispose()


async def _claim(
    database: Database,
    owner: str,
    *,
    job_types: tuple[str, ...] = ("embed_memory",),
    batch_size: int = 2,
    now: datetime = _NOW,
) -> tuple[ClaimedOutboxJob, ...]:
    async with database.tenant_session(_tenant_id()) as session:
        return await claim_outbox_jobs(
            session,
            tenant_id=_tenant_id(),
            worker_owner=owner,
            job_types=job_types,
            batch_size=batch_size,
            lease_seconds=5,
            now=now,
        )


async def test_worker_claims_are_disjoint_fenced_and_retry_bounded(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_database(postgresql_server.database_url) as database:
        async with database.tenant_session(_tenant_id()) as session:
            for ordinal in range(12):
                memory_id = new_uuid7()
                await enqueue_outbox_job(
                    session,
                    tenant_id=_tenant_id(),
                    job_type="embed_memory",
                    aggregate_type="memory",
                    aggregate_id=memory_id,
                    references={"memory_id": memory_id, "memory_version": ordinal + 1},
                )

        batches = await asyncio.gather(
            *(_claim(database, f"worker-{ordinal}") for ordinal in range(8))
        )
        claimed = tuple(item for batch in batches for item in batch)
        assert len(claimed) == 12
        assert len({item.job_id for item in claimed}) == 12
        assert len({item.job_uuid for item in claimed}) == 12
        assert len({item.lease_token for item in claimed}) == 12
        assert all(item.attempt_count == 1 for item in claimed)
        assert all(set(item.payload) == {"memory_id", "memory_version"} for item in claimed)

        expired = min(claimed, key=lambda item: item.job_id)
        recovered_at = _NOW + timedelta(seconds=6)
        async with database.tenant_session(_tenant_id()) as session:
            pending, dead = await recover_expired_outbox_leases(
                session,
                tenant_id=_tenant_id(),
                job_types=("embed_memory",),
                batch_size=1,
                retry_delay_seconds=0,
                now=recovered_at,
            )
        assert (pending, dead) == (1, 0)

        replacement = (
            await _claim(
                database,
                "replacement-worker",
                batch_size=1,
                now=recovered_at,
            )
        )[0]
        assert replacement.job_id == expired.job_id
        assert replacement.attempt_count == 2
        assert replacement.lease_token != expired.lease_token

        with pytest.raises(LeaseLostError, match="outbox_lease_lost"):
            async with database.tenant_session(_tenant_id()) as session:
                await acknowledge_outbox_job(
                    session,
                    tenant_id=_tenant_id(),
                    job_id=expired.job_id,
                    lease_token=expired.lease_token,
                    now=recovered_at,
                )

        async with database.tenant_session(_tenant_id()) as session:
            await heartbeat_outbox_job(
                session,
                tenant_id=_tenant_id(),
                job_id=replacement.job_id,
                lease_token=replacement.lease_token,
                lease_seconds=10,
                now=recovered_at + timedelta(seconds=1),
            )
            await acknowledge_outbox_job(
                session,
                tenant_id=_tenant_id(),
                job_id=replacement.job_id,
                lease_token=replacement.lease_token,
                now=recovered_at + timedelta(seconds=2),
            )

        with pytest.raises(LeaseLostError, match="outbox_lease_lost"):
            async with database.tenant_session(_tenant_id()) as session:
                await acknowledge_outbox_job(
                    session,
                    tenant_id=_tenant_id(),
                    job_id=replacement.job_id,
                    lease_token=replacement.lease_token,
                    now=recovered_at + timedelta(seconds=3),
                )

        retry_memory_id = new_uuid7()
        async with database.tenant_session(_tenant_id()) as session:
            await enqueue_outbox_job(
                session,
                tenant_id=_tenant_id(),
                job_type="check_duplicates",
                aggregate_type="memory",
                aggregate_id=retry_memory_id,
                references={"memory_id": retry_memory_id, "memory_version": 1},
                max_attempts=2,
            )

        first_attempt = (
            await _claim(
                database,
                "retry-worker-one",
                job_types=("check_duplicates",),
                batch_size=1,
                now=_NOW,
            )
        )[0]
        async with database.tenant_session(_tenant_id()) as session:
            state = await fail_outbox_job(
                session,
                tenant_id=_tenant_id(),
                job_id=first_attempt.job_id,
                lease_token=first_attempt.lease_token,
                error_code="embedding_failed",
                retryable=True,
                retry_delay_seconds=0,
                now=_NOW + timedelta(seconds=1),
            )
        assert state == "pending"

        second_attempt = (
            await _claim(
                database,
                "retry-worker-two",
                job_types=("check_duplicates",),
                batch_size=1,
                now=_NOW + timedelta(seconds=1),
            )
        )[0]
        assert second_attempt.attempt_count == 2
        async with database.tenant_session(_tenant_id()) as session:
            state = await fail_outbox_job(
                session,
                tenant_id=_tenant_id(),
                job_id=second_attempt.job_id,
                lease_token=second_attempt.lease_token,
                error_code="embedding_failed",
                retryable=True,
                retry_delay_seconds=0,
                now=_NOW + timedelta(seconds=2),
            )
        assert state == "dead"

        async with database.tenant_session(_tenant_id()) as session:
            stored = await session.get(OutboxJob, second_attempt.job_id)
            assert stored is not None
            assert stored.state == "dead"
            assert stored.attempt_count == 2
            assert stored.lease_owner is None
            assert stored.lease_expires_at is None
            assert stored.last_error_code == "embedding_failed"
            assert stored.last_error_summary == "The local embedding operation failed."
            assert "memory" not in stored.last_error_summary.lower()
            remaining = (
                await session.scalars(
                    select(OutboxJob).where(
                        OutboxJob.job_type == "check_duplicates",
                        OutboxJob.state.in_(("pending", "leased")),
                    )
                )
            ).all()
            assert remaining == []
