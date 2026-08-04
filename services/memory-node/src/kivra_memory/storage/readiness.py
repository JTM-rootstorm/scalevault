"""Privacy-preserving PostgreSQL readiness checks."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from psycopg import AsyncConnection
from pydantic import PostgresDsn

EXPECTED_ALEMBIC_HEAD = "0001_initial_domain"
REQUIRED_EXTENSIONS = frozenset({"vector", "pg_trgm", "citext", "pgcrypto"})

DatabaseStatus = Literal["ok", "not_configured", "unavailable"]
MigrationStatus = Literal["ok", "incompatible", "unavailable", "unchecked"]
ExtensionStatus = Literal["ok", "incomplete", "unavailable", "unchecked"]


@dataclass(frozen=True, slots=True)
class DatabaseReadiness:
    """Sanitized database dependency states suitable for operator responses."""

    database: DatabaseStatus
    migrations: MigrationStatus
    extensions: ExtensionStatus

    @property
    def ready(self) -> bool:
        """Return whether every required database dependency is compatible."""

        return self.database == self.migrations == self.extensions == "ok"

    @classmethod
    def not_configured(cls) -> "DatabaseReadiness":
        """Return the state for a process without a database configuration."""

        return cls(database="not_configured", migrations="unchecked", extensions="unchecked")

    @classmethod
    def unavailable(cls) -> "DatabaseReadiness":
        """Return a sanitized state for an unreachable or failed database probe."""

        return cls(database="unavailable", migrations="unchecked", extensions="unchecked")


DatabaseProbeResult = DatabaseReadiness | bool
DatabaseProbe = Callable[[PostgresDsn, int], Awaitable[DatabaseProbeResult]]


def psycopg_connection_info(database_url: PostgresDsn) -> str:
    """Convert an SQLAlchemy Psycopg URL into a libpq-compatible URL."""

    return database_url.unicode_string().replace(
        "postgresql+psycopg://",
        "postgresql://",
        1,
    )


async def database_is_ready(
    database_url: PostgresDsn,
    timeout_seconds: int,
) -> DatabaseReadiness:
    """Check connectivity, the exact migration head, and required extensions.

    Database exceptions and their potentially secret-bearing connection details are
    deliberately collapsed into fixed operator states.
    """

    try:
        async with asyncio.timeout(timeout_seconds):
            connection = await AsyncConnection.connect(
                psycopg_connection_info(database_url),
                connect_timeout=timeout_seconds,
                autocommit=True,
            )
            async with connection:
                migrations = await _migration_status(connection)
                extensions = await _extension_status(connection)
    except Exception:
        return DatabaseReadiness.unavailable()

    return DatabaseReadiness(
        database="ok",
        migrations=migrations,
        extensions=extensions,
    )


async def _migration_status(connection: AsyncConnection[tuple[object, ...]]) -> MigrationStatus:
    """Return whether the database is at the one compatible Alembic head."""

    try:
        table_cursor = await connection.execute(
            "SELECT pg_catalog.to_regclass('public.alembic_version')"
        )
        table_row = await table_cursor.fetchone()
        if table_row is None or table_row[0] is None:
            return "incompatible"

        version_cursor = await connection.execute(
            "SELECT version_num FROM public.alembic_version ORDER BY version_num"
        )
        versions = {str(row[0]) for row in await version_cursor.fetchall()}
    except Exception:
        return "unavailable"

    return "ok" if versions == {EXPECTED_ALEMBIC_HEAD} else "incompatible"


async def _extension_status(connection: AsyncConnection[tuple[object, ...]]) -> ExtensionStatus:
    """Return whether every required PostgreSQL extension is installed."""

    try:
        cursor = await connection.execute(
            "SELECT extname FROM pg_catalog.pg_extension WHERE extname = ANY(%s)",
            (sorted(REQUIRED_EXTENSIONS),),
        )
        installed = {str(row[0]) for row in await cursor.fetchall()}
    except Exception:
        return "unavailable"

    return "ok" if installed == REQUIRED_EXTENSIONS else "incomplete"
