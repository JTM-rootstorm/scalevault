from __future__ import annotations

from typing import Protocol

import pytest
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.config import Settings
from psycopg import AsyncConnection
from pydantic import PostgresDsn


class PostgreSQLTestServer(Protocol):
    database_url: str

    def stop(self) -> None: ...


async def test_disposable_postgresql_supports_pgvector(
    postgresql_server: PostgreSQLTestServer,
) -> None:
    connection = await AsyncConnection.connect(postgresql_server.database_url)
    async with connection:
        version_cursor = await connection.execute("SHOW server_version_num")
        version_row = await version_cursor.fetchone()
        assert version_row is not None
        assert int(version_row[0]) >= 170000

        vector_cursor = await connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector')"
        )
        vector_row = await vector_cursor.fetchone()
        assert vector_row is not None
        if not vector_row[0]:
            pytest.skip("the selected PostgreSQL 17+ installation does not provide pgvector")

        await connection.execute("CREATE EXTENSION vector")
        extension_cursor = await connection.execute(
            "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
        )
        assert await extension_cursor.fetchone() is not None


async def test_memory_node_readiness_tracks_real_postgresql(
    postgresql_server: PostgreSQLTestServer,
) -> None:
    settings = Settings(
        database_url=PostgresDsn(postgresql_server.database_url),
        database_connect_timeout_seconds=1,
    )
    app = create_app(settings)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        ready_response = await client.get("/readyz")
        assert ready_response.status_code == 200
        assert ready_response.json() == {
            "status": "ready",
            "checks": {"database": "ok"},
        }

        postgresql_server.stop()

        unavailable_response = await client.get("/readyz")
        assert unavailable_response.status_code == 503
        assert unavailable_response.json() == {
            "status": "not_ready",
            "checks": {"database": "unavailable"},
        }
