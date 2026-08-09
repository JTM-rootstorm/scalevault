from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import (
    ArchiveStorageError,
    RestorePlan,
    archive_row_dto,
    load_archive_batch_source,
    restore_archive_rows,
    try_acquire_archive_target_lock,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    ArchiveTarget,
    MemoryEvent,
    MemoryEventCounter,
)
from sqlalchemy import select, text, update

from tests.fixtures.database_seed import seed_model_layers, seed_rows


class PostgreSQLTestServer(Protocol):
    database_url: str


def _tenant_id() -> UUID:
    return cast(UUID, seed_rows()["tenants"][0]["tenant_id"])


@asynccontextmanager
async def _database(database_url: str) -> AsyncIterator[Database]:
    database = Database(database_url)
    try:
        yield database
    finally:
        await database.dispose()


@pytest.mark.database
async def test_archive_target_lock_elects_one_writer_and_releases_at_transaction_end(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _tenant_id()
    target_id = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=100)

    async with _database(postgresql_server.database_url) as database:
        first = database.session_factory()
        second = database.session_factory()
        try:
            await first.begin()
            await second.begin()
            for session in (first, second):
                await session.execute(
                    text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
                    {"tenant_id": str(tenant_id)},
                )

            assert await try_acquire_archive_target_lock(
                first, tenant_id=tenant_id, archive_target_id=target_id
            )
            assert not await try_acquire_archive_target_lock(
                second, tenant_id=tenant_id, archive_target_id=target_id
            )

            await first.rollback()
            assert await try_acquire_archive_target_lock(
                second, tenant_id=tenant_id, archive_target_id=target_id
            )
        finally:
            await first.close()
            await second.close()


@pytest.mark.database
async def test_restore_writes_a_nonempty_later_event_with_reversible_json(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    rows = seed_rows()
    tenant_id = cast(UUID, rows["tenants"][0]["tenant_id"])
    branch = rows["branches"][0]
    binding = rows["transport_bindings"][0]
    payload = {
        "branch": {
            "branch_id": str(branch["branch_id"]),
            "tenant_id": str(tenant_id),
            "lineage_id": str(branch["lineage_id"]),
            "parent_branch_id": None,
            "fork_event_sequence": None,
            "name": str(branch["name"]),
            "visibility_ceiling": str(branch["visibility_ceiling"]),
            "created_at": "2026-01-01T00:00:00.000000Z",
            "sealed_at": None,
        }
    }
    canonical_payload = canonical_json_bytes(payload)
    later_event = MemoryEvent(
        sequence=1,
        event_id=new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=201),
        tenant_id=tenant_id,
        lineage_id=cast(UUID, branch["lineage_id"]),
        branch_id=cast(UUID, branch["branch_id"]),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        session_id=None,
        ingress_id=None,
        operation="branch_created",
        memory_id=None,
        expected_revision=None,
        causation_event_id=None,
        correlation_id=new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=202),
        idempotency_key="archive-real-restore:1",
        schema_version=1,
        payload_version=1,
        policy_version=1,
        normalization_version=1,
        payload=payload,
        payload_canonical=canonical_payload,
        payload_sha256=hashlib.sha256(canonical_payload).digest(),
        command_sha256=b"c" * 32,
        created_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
    )
    recovery_rows = {
        type(layer[0]).__tablename__: tuple(archive_row_dto(row) for row in layer)
        for layer in seed_model_layers()
    }
    plan = RestorePlan(
        tenant_id=tenant_id,
        snapshot_high_water_sequence=0,
        final_high_water_sequence=1,
        rows=recovery_rows,
        later_events=(archive_row_dto(later_event),),
    )

    async with _database(postgresql_server.database_url) as database:
        async with database.tenant_session(tenant_id) as session:
            await restore_archive_rows(session, plan)

        async with database.tenant_session(tenant_id) as session:
            restored = (await session.execute(select(MemoryEvent))).scalar_one()
            assert restored.payload == payload
            assert bytes(restored.payload_canonical) == canonical_payload
            assert restored.sequence == 1


@pytest.mark.database
async def test_archive_rejects_a_global_counter_prefix_not_owned_by_the_tenant(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _tenant_id()
    target_id = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=300)

    async with (
        _database(postgresql_server.database_url) as database,
        database.tenant_session(tenant_id) as session,
    ):
        for layer in seed_model_layers():
            session.add_all(layer)
            await session.flush()
        session.add(
            ArchiveTarget(
                archive_target_id=target_id,
                tenant_id=tenant_id,
                name="synthetic",
                target_kind="forgejo_git",
                repository_reference="synthetic/archive",
                branch_name="main",
            )
        )
        await session.execute(
            update(MemoryEventCounter)
            .where(MemoryEventCounter.counter_id == 1)
            .values(next_sequence=2)
        )
        await session.flush()

        with pytest.raises(ArchiveStorageError, match="archive_multitenant_unsupported"):
            await load_archive_batch_source(
                session,
                tenant_id=tenant_id,
                archive_target_id=target_id,
            )
