from __future__ import annotations

from typing import Protocol

import pytest
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.config import Settings
from kivra_memory.storage.readiness import (
    MINIMUM_EXTENSION_VERSIONS,
    _extension_version_is_supported,
)
from psycopg import AsyncConnection
from pydantic import PostgresDsn
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from tests.integration.database.conftest import (
    REQUIRED_EXTENSIONS,
    AlembicRunner,
    bootstrap_required_extensions,
)


class PostgreSQLTestServer(Protocol):
    database_url: str

    def stop(self) -> None: ...


async def test_disposable_postgresql_supports_required_extensions(
    postgresql_server: PostgreSQLTestServer,
) -> None:
    connection = await AsyncConnection.connect(postgresql_server.database_url)
    async with connection:
        version_cursor = await connection.execute("SHOW server_version_num")
        version_row = await version_cursor.fetchone()
        assert version_row is not None
        assert int(version_row[0]) >= 170000

        available_cursor = await connection.execute(
            "SELECT name FROM pg_available_extensions WHERE name = ANY(%s)",
            (sorted(REQUIRED_EXTENSIONS),),
        )
        available = {str(row[0]) for row in await available_cursor.fetchall()}
        missing = sorted(REQUIRED_EXTENSIONS - available)
        if missing:
            pytest.skip("required PostgreSQL extensions are unavailable: " + ", ".join(missing))

    bootstrap_required_extensions(postgresql_server.database_url)
    verification_connection = await AsyncConnection.connect(postgresql_server.database_url)
    async with verification_connection:
        extension_cursor = await verification_connection.execute(
            "SELECT extname, extversion FROM pg_extension WHERE extname = ANY(%s)",
            (sorted(REQUIRED_EXTENSIONS),),
        )
        installed = {str(row[0]): str(row[1]) for row in await extension_cursor.fetchall()}
        assert installed.keys() == REQUIRED_EXTENSIONS
        assert all(
            _extension_version_is_supported(installed[name], minimum)
            for name, minimum in MINIMUM_EXTENSION_VERSIONS.items()
        )


async def test_memory_node_readiness_tracks_real_postgresql(
    postgresql_server: PostgreSQLTestServer,
) -> None:
    settings = Settings(
        database_url=PostgresDsn(postgresql_server.database_url),
        database_connect_timeout_seconds=1,
    )
    app = create_app(settings)
    sqlalchemy_url = make_url(postgresql_server.database_url).set(drivername="postgresql+psycopg")
    runner = AlembicRunner(
        create_engine(
            sqlalchemy_url,
            hide_parameters=True,
            poolclass=NullPool,
        )
    )

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            unmigrated_response = await client.get("/readyz")
            assert unmigrated_response.status_code == 503
            assert unmigrated_response.json() == {
                "status": "not_ready",
                "checks": {
                    "database": "ok",
                    "migrations": "incompatible",
                    "extensions": "incomplete",
                },
            }

            bootstrap_required_extensions(postgresql_server.database_url)
            runner.upgrade()

            ready_response = await client.get("/readyz")
            assert ready_response.status_code == 200
            assert ready_response.json() == {
                "status": "ready",
                "checks": {"database": "ok", "migrations": "ok", "extensions": "ok"},
            }

            postgresql_server.stop()

            unavailable_response = await client.get("/readyz")
            assert unavailable_response.status_code == 503
            assert unavailable_response.json() == {
                "status": "not_ready",
                "checks": {
                    "database": "unavailable",
                    "migrations": "unchecked",
                    "extensions": "unchecked",
                },
            }
    finally:
        runner.dispose()
