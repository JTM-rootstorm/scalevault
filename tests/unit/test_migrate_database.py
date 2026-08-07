from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypedDict, Unpack, cast
from unittest.mock import MagicMock, Mock

import pytest
from alembic.config import Config
from sqlalchemy import Connection
from sqlalchemy.engine import Engine

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.migrate_database import (  # noqa: E402
    DATABASE_URL_ENV,
    EXPECTED_DATABASE_ENV,
    MIGRATOR_ROLE,
    OWNER_ROLE,
    MigrationFailure,
    main,
    migrate_to_head,
)

DATABASE_URL = "postgresql+psycopg://migrator:private-value@database/scalevault"
EXPECTED_DATABASE = "scalevault"


class _DependencyOverrides(TypedDict, total=False):
    session_role: str
    database_name: str
    is_local: bool
    owner: Mapping[str, object] | None
    owner_exists: bool
    is_member: bool
    assumed_role: str
    set_role_failure: bool


def _result(*, mapping: Mapping[str, object] | None = None, scalar: object = None) -> Any:
    result = MagicMock()
    result.mappings.return_value.one.return_value = mapping
    result.mappings.return_value.one_or_none.return_value = mapping
    result.scalar_one.return_value = scalar
    return result


def _migration_dependencies(
    **overrides: Unpack[_DependencyOverrides],
) -> tuple[MagicMock, MagicMock, Mock, Mock]:
    session_role = overrides.get("session_role", MIGRATOR_ROLE)
    database_name = overrides.get("database_name", EXPECTED_DATABASE)
    is_local = overrides.get("is_local", False)
    owner = overrides.get("owner")
    owner_exists = overrides.get("owner_exists", True)
    is_member = overrides.get("is_member", True)
    assumed_role = overrides.get("assumed_role", OWNER_ROLE)
    set_role_failure = overrides.get("set_role_failure", False)
    connection = MagicMock(spec=Connection)
    identity_result = _result(
        mapping={
            "database_name": database_name,
            "session_role": session_role,
            "is_local_connection": is_local,
        }
    )
    owner_mapping = {"can_login": False, "is_superuser": False} if owner is None else owner
    owner_result = _result(mapping=owner_mapping if owner_exists else None)
    results = [identity_result, owner_result]
    if session_role == MIGRATOR_ROLE:
        results.append(_result(scalar=is_member))
    results.extend(
        (
            RuntimeError("driver detail") if set_role_failure else _result(),
            _result(scalar=assumed_role),
        )
    )
    connection.execute.side_effect = results

    engine = MagicMock(spec=Engine)
    engine.begin.return_value.__enter__.return_value = connection
    engine_factory = Mock(return_value=engine)
    upgrade_runner = Mock()
    return connection, engine, engine_factory, upgrade_runner


def _environment() -> dict[str, str]:
    return {
        DATABASE_URL_ENV: DATABASE_URL,
        EXPECTED_DATABASE_ENV: EXPECTED_DATABASE,
    }


@pytest.mark.parametrize(
    ("environment", "message"),
    (
        ({}, "migration database URL is not configured"),
        (
            {DATABASE_URL_ENV: DATABASE_URL},
            "expected migration database is not configured",
        ),
    ),
)
def test_required_environment_is_checked_before_connecting(
    environment: Mapping[str, str], message: str
) -> None:
    engine_factory = Mock()

    with pytest.raises(MigrationFailure, match=f"^{message}$"):
        migrate_to_head(environment, engine_factory=engine_factory)

    engine_factory.assert_not_called()


def test_migrator_member_runs_head_with_an_injected_owner_connection() -> None:
    connection, engine, engine_factory, upgrade_runner = _migration_dependencies()

    migrate_to_head(
        _environment(),
        engine_factory=cast(Any, engine_factory),
        upgrade_runner=cast(Any, upgrade_runner),
    )

    engine_factory.assert_called_once_with(DATABASE_URL)
    engine.dispose.assert_called_once_with()
    upgrade_runner.assert_called_once()
    config, revision = upgrade_runner.call_args.args
    assert isinstance(config, Config)
    assert config.attributes["connection"] is connection
    assert revision == "head"
    assert any(
        str(call.args[0]) == f"SET ROLE {OWNER_ROLE}" for call in connection.execute.call_args_list
    )


def test_local_postgres_operator_can_assume_the_owner_role() -> None:
    _, _, engine_factory, upgrade_runner = _migration_dependencies(
        session_role="postgres", is_local=True
    )

    migrate_to_head(
        _environment(),
        engine_factory=cast(Any, engine_factory),
        upgrade_runner=cast(Any, upgrade_runner),
    )

    upgrade_runner.assert_called_once()


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"database_name": "unexpected"},
            "connected database does not match the expected database",
        ),
        (
            {"session_role": "postgres", "is_local": False},
            "migration operator is not authorized",
        ),
        ({"is_member": False}, "migration operator is not authorized"),
        (
            {"owner_exists": False},
            "migration owner role is not safely configured",
        ),
        (
            {"owner": {"can_login": True, "is_superuser": False}},
            "migration owner role is not safely configured",
        ),
        (
            {"owner": {"can_login": False, "is_superuser": True}},
            "migration owner role is not safely configured",
        ),
        (
            {"assumed_role": "kivra_memory_migrator"},
            "migration owner role could not be assumed",
        ),
        (
            {"set_role_failure": True},
            "migration owner role could not be assumed",
        ),
    ),
)
def test_preflight_failures_stop_before_alembic(
    overrides: _DependencyOverrides, message: str
) -> None:
    _, engine, engine_factory, upgrade_runner = _migration_dependencies(**overrides)

    with pytest.raises(MigrationFailure, match=f"^{message}$"):
        migrate_to_head(
            _environment(),
            engine_factory=cast(Any, engine_factory),
            upgrade_runner=cast(Any, upgrade_runner),
        )

    upgrade_runner.assert_not_called()
    engine.dispose.assert_called_once_with()


def test_backend_errors_are_sanitized() -> None:
    def failing_engine_factory(_database_url: str) -> Engine:
        raise RuntimeError(f"could not connect to {DATABASE_URL}")

    with pytest.raises(MigrationFailure) as error:
        migrate_to_head(_environment(), engine_factory=failing_engine_factory)

    assert str(error.value) == "database migration failed"
    assert "private-value" not in str(error.value)


def test_cli_reports_fixed_errors_without_echoing_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["upgrade", "head", DATABASE_URL], environment={})

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert "unsupported migration arguments" in captured.err
    assert "private-value" not in captured.err
    assert captured.out == ""


def test_cli_returns_failure_for_a_sanitized_migration_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["upgrade", "head"], environment={})

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == "error: migration database URL is not configured\n"
    assert captured.out == ""
