from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from kivra_memory.storage import metadata
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from .conftest import (
    REQUIRED_EXTENSIONS,
    AlembicRunner,
    _alembic_config,
    installed_extensions,
)

EXPECTED_HEAD = "0001_initial_domain"


def _schema_differences(connection: Connection) -> Sequence[object]:
    context = MigrationContext.configure(connection)
    return cast(Sequence[object], compare_metadata(context, metadata))


def _current_revision(connection: Connection) -> str | None:
    if not inspect(connection).has_table("alembic_version"):
        return None
    return connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_revision_history_has_one_expected_head() -> None:
    heads = ScriptDirectory.from_config(_alembic_config()).get_heads()
    assert heads == [EXPECTED_HEAD]


def test_online_migration_requires_injected_connection(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(RuntimeError, match="injected SQLAlchemy connection"):
        command.current(_alembic_config())

    captured = capsys.readouterr()
    assert "postgresql://" not in captured.out
    assert "postgresql://" not in captured.err


def test_migration_fails_before_ddl_when_extensions_are_missing(
    alembic_runner: AlembicRunner,
) -> None:
    with pytest.raises(RuntimeError, match="required PostgreSQL extensions are not installed"):
        alembic_runner.upgrade()

    with alembic_runner.connect() as connection:
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
        assert _current_revision(connection) is None


def test_zero_to_head_and_full_round_trip(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    with runner.connect() as connection:
        assert set(installed_extensions(connection)) == REQUIRED_EXTENSIONS
        assert set(inspect(connection).get_table_names()) == set()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert _schema_differences(connection) == []
        first_head_tables = set(inspect(connection).get_table_names())
        assert set(metadata.tables).issubset(first_head_tables)
        assert connection.execute(text("SELECT count(*) FROM tenants")).scalar_one() == 0
        assert connection.execute(
            text("SELECT counter_id, next_sequence FROM memory_event_counter")
        ).one() == (1, 1)
        assert connection.execute(
            text(
                "SELECT contract_version, minimum_reader_revision, minimum_writer_revision "
                "FROM alembic_compatibility WHERE component = 'memory_node'"
            )
        ).one() == (1, EXPECTED_HEAD, EXPECTED_HEAD)

    runner.downgrade("base")
    with runner.connect() as connection:
        assert _current_revision(connection) is None
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
        assert set(installed_extensions(connection)) == REQUIRED_EXTENSIONS

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert _schema_differences(connection) == []
        assert set(inspect(connection).get_table_names()) == first_head_tables
