"""Run the canonical database migration through a guarded operator entrypoint."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Never

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import NullPool

DATABASE_URL_ENV = "KIVRA_MEMORY_MIGRATION_DATABASE_URL"
EXPECTED_DATABASE_ENV = "KIVRA_MEMORY_EXPECTED_DATABASE"
MIGRATOR_ROLE = "kivra_memory_migrator"
OWNER_ROLE = "kivra_memory_owner"
POSTGRES_OPERATOR_ROLE = "postgres"

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class MigrationFailure(RuntimeError):
    """A sanitized migration failure safe to show to an operator."""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: unsupported migration arguments\n")


EngineFactory = Callable[[str], Engine]
UpgradeRunner = Callable[[Config, str], None]


def _create_migration_engine(database_url: str) -> Engine:
    return create_engine(
        database_url,
        hide_parameters=True,
        poolclass=NullPool,
    )


def _alembic_config() -> Config:
    config = Config(str(REPOSITORY_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    return config


def _require_environment(environment: Mapping[str, str]) -> tuple[str, str]:
    database_url = environment.get(DATABASE_URL_ENV)
    if not database_url:
        raise MigrationFailure("migration database URL is not configured")

    expected_database = environment.get(EXPECTED_DATABASE_ENV)
    if not expected_database:
        raise MigrationFailure("expected migration database is not configured")

    return database_url, expected_database


def _verify_and_assume_owner(connection: Connection, expected_database: str) -> None:
    identity = (
        connection.execute(
            text(
                "SELECT current_database() AS database_name, "
                "session_user AS session_role, "
                "inet_client_addr() IS NULL AS is_local_connection"
            )
        )
        .mappings()
        .one()
    )
    if identity["database_name"] != expected_database:
        raise MigrationFailure("connected database does not match the expected database")

    owner = (
        connection.execute(
            text(
                "SELECT rolcanlogin AS can_login, rolsuper AS is_superuser "
                "FROM pg_catalog.pg_roles WHERE rolname = :owner_role"
            ),
            {"owner_role": OWNER_ROLE},
        )
        .mappings()
        .one_or_none()
    )
    if owner is None or bool(owner["can_login"]) or bool(owner["is_superuser"]):
        raise MigrationFailure("migration owner role is not safely configured")

    session_role = identity["session_role"]
    migrator_is_member = False
    if session_role == MIGRATOR_ROLE:
        migrator_is_member = bool(
            connection.execute(
                text("SELECT pg_has_role(session_user, :owner_role, 'SET')"),
                {"owner_role": OWNER_ROLE},
            ).scalar_one()
        )

    local_postgres_operator = session_role == POSTGRES_OPERATOR_ROLE and bool(
        identity["is_local_connection"]
    )
    if not migrator_is_member and not local_postgres_operator:
        raise MigrationFailure("migration operator is not authorized")

    try:
        connection.execute(text(f"SET ROLE {OWNER_ROLE}"))
    except Exception:
        raise MigrationFailure("migration owner role could not be assumed") from None

    if connection.execute(text("SELECT current_user")).scalar_one() != OWNER_ROLE:
        raise MigrationFailure("migration owner role could not be assumed")


def migrate_to_head(
    environment: Mapping[str, str],
    *,
    engine_factory: EngineFactory = _create_migration_engine,
    upgrade_runner: UpgradeRunner = command.upgrade,
) -> None:
    """Upgrade the expected canonical database to head in one transaction."""

    database_url, expected_database = _require_environment(environment)
    try:
        engine = engine_factory(database_url)
        try:
            with engine.begin() as connection:
                _verify_and_assume_owner(connection, expected_database)
                config = _alembic_config()
                config.attributes["connection"] = connection
                upgrade_runner(config, "head")
        finally:
            engine.dispose()
    except MigrationFailure:
        raise
    except Exception:
        raise MigrationFailure("database migration failed") from None


def _argument_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description="Upgrade the canonical ScaleVault database using guarded environment settings."
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    upgrade = subparsers.add_parser("upgrade", help="upgrade the database schema")
    upgrade.add_argument("revision", choices=("head",))
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    engine_factory: EngineFactory = _create_migration_engine,
    upgrade_runner: UpgradeRunner = command.upgrade,
) -> int:
    arguments = _argument_parser().parse_args(argv)
    if arguments.operation != "upgrade" or arguments.revision != "head":
        raise AssertionError("the argument parser admitted an unsupported migration operation")

    try:
        migrate_to_head(
            os.environ if environment is None else environment,
            engine_factory=engine_factory,
            upgrade_runner=upgrade_runner,
        )
    except MigrationFailure as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
