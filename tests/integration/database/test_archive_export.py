from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import try_acquire_archive_target_lock
from kivra_memory.storage.database import Database
from sqlalchemy import text

from tests.fixtures.database_seed import seed_rows


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
