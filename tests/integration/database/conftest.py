from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Never, Protocol

import pytest
from alembic import command
from alembic.config import Config
from psycopg import Connection
from psycopg import sql as psycopg_sql
from sqlalchemy import Connection as SQLAlchemyConnection
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REQUIRED_EXTENSIONS = frozenset({"citext", "pg_trgm", "pgcrypto", "vector"})


class PostgreSQLTestServer(Protocol):
    database_url: str


def _database_unavailable(reason: str) -> Never:
    if os.environ.get("SCALEVAULT_REQUIRE_DATABASE_TESTS") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def _sqlalchemy_url(database_url: str) -> str:
    url = make_url(database_url)
    return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


def _alembic_config() -> Config:
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    return config


@dataclass
class AlembicRunner:
    """Run Alembic through an injected connection, never a configured database URL."""

    engine: Engine

    def _run(self, operation: str, revision: str) -> None:
        config = _alembic_config()
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            getattr(command, operation)(config, revision)

    def upgrade(self, revision: str = "head") -> None:
        self._run("upgrade", revision)

    def downgrade(self, revision: str) -> None:
        self._run("downgrade", revision)

    def connect(self) -> SQLAlchemyConnection:
        return self.engine.connect()

    def dispose(self) -> None:
        self.engine.dispose()


def bootstrap_required_extensions(database_url: str) -> None:
    """Install extensions through the disposable cluster's elevated bootstrap role."""

    with Connection.connect(database_url) as connection:
        available_rows = connection.execute(
            "SELECT name FROM pg_available_extensions WHERE name = ANY(%s)",
            (list(REQUIRED_EXTENSIONS),),
        ).fetchall()
        available = {str(row[0]) for row in available_rows}
        missing = sorted(REQUIRED_EXTENSIONS - available)
        if missing:
            _database_unavailable(
                "required PostgreSQL test extensions are unavailable: " + ", ".join(missing)
            )

        for extension in sorted(REQUIRED_EXTENSIONS):
            connection.execute(
                psycopg_sql.SQL("CREATE EXTENSION IF NOT EXISTS {}").format(
                    psycopg_sql.Identifier(extension)
                )
            )


@pytest.fixture
def alembic_runner(postgresql_server: PostgreSQLTestServer) -> Iterator[AlembicRunner]:
    engine = create_engine(
        _sqlalchemy_url(postgresql_server.database_url),
        hide_parameters=True,
        poolclass=NullPool,
    )
    runner = AlembicRunner(engine)
    try:
        yield runner
    finally:
        runner.dispose()


@pytest.fixture
def bootstrapped_alembic_runner(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> AlembicRunner:
    bootstrap_required_extensions(postgresql_server.database_url)
    return alembic_runner


@pytest.fixture
def migrated_database(bootstrapped_alembic_runner: AlembicRunner) -> AlembicRunner:
    bootstrapped_alembic_runner.upgrade()
    return bootstrapped_alembic_runner


def installed_extensions(connection: SQLAlchemyConnection) -> dict[str, str]:
    rows = connection.execute(
        text(
            "SELECT extname, extversion FROM pg_extension "
            "WHERE extname = ANY(:extensions) ORDER BY extname"
        ),
        {"extensions": list(REQUIRED_EXTENSIONS)},
    )
    return {str(name): str(version) for name, version in rows}
