from collections.abc import Mapping
from typing import Any, cast

import pytest
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app, main
from kivra_memory.config import Settings, get_settings
from kivra_memory.storage.readiness import (
    EXPECTED_ALEMBIC_HEAD,
    MINIMUM_EXTENSION_VERSIONS,
    DatabaseReadiness,
    _extension_status,
    _extension_version_is_supported,
    _migration_status,
    database_is_ready,
    psycopg_connection_info,
)
from pydantic import PostgresDsn

DATABASE_URL = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")


class _Cursor:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    async def fetchone(self) -> tuple[object, ...] | None:
        return self._rows[0] if self._rows else None

    async def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class _ReadinessConnection:
    def __init__(
        self,
        *,
        version_table_exists: bool = True,
        versions: tuple[str, ...] = (EXPECTED_ALEMBIC_HEAD,),
        extensions: Mapping[str, str] = MINIMUM_EXTENSION_VERSIONS,
    ) -> None:
        self._version_table_exists = version_table_exists
        self._versions = versions
        self._extensions = extensions

    async def execute(
        self,
        query: str,
        _parameters: object = None,
    ) -> _Cursor:
        if "to_regclass" in query:
            table_name = "alembic_version" if self._version_table_exists else None
            return _Cursor([(table_name,)])
        if "FROM public.alembic_version" in query:
            return _Cursor([(version,) for version in self._versions])
        if "FROM pg_catalog.pg_extension" in query:
            return _Cursor(sorted(self._extensions.items()))
        raise AssertionError(f"unexpected readiness query: {query}")


def test_sqlalchemy_database_url_is_normalized_for_psycopg() -> None:
    database_url = PostgresDsn("postgresql+psycopg://memory-api:example@127.0.0.1/kivra_memory")

    assert psycopg_connection_info(database_url).startswith("postgresql://")


async def test_migration_probe_requires_the_exact_expected_head() -> None:
    assert await _migration_status(cast(Any, _ReadinessConnection())) == "ok"
    assert (
        await _migration_status(cast(Any, _ReadinessConnection(version_table_exists=False)))
        == "incompatible"
    )
    assert (
        await _migration_status(cast(Any, _ReadinessConnection(versions=("0000_foundation",))))
        == "incompatible"
    )


async def test_extension_probe_requires_every_named_extension() -> None:
    assert await _extension_status(cast(Any, _ReadinessConnection())) == "ok"
    assert (
        await _extension_status(
            cast(
                Any,
                _ReadinessConnection(
                    extensions={
                        name: version
                        for name, version in MINIMUM_EXTENSION_VERSIONS.items()
                        if name != "vector"
                    }
                ),
            )
        )
        == "incomplete"
    )


def test_extension_probe_locks_approved_minimum_versions() -> None:
    assert MINIMUM_EXTENSION_VERSIONS == {
        "citext": "1.6",
        "pg_trgm": "1.6",
        "pgcrypto": "1.3",
        "vector": "0.8.0",
    }


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("citext", "1.5.9"),
        ("pg_trgm", "1.5.9"),
        ("pgcrypto", "1.2.9"),
        ("vector", "0.7.4"),
    ],
)
async def test_extension_probe_rejects_versions_below_each_minimum(
    name: str,
    version: str,
) -> None:
    extensions = dict(MINIMUM_EXTENSION_VERSIONS)
    extensions[name] = version

    assert (
        await _extension_status(cast(Any, _ReadinessConnection(extensions=extensions)))
        == "incomplete"
    )


@pytest.mark.parametrize("version", ["0.7.4", "", "0.8.x", "0..8", "-1.8.0"])
async def test_extension_probe_rejects_unsupported_or_malformed_versions(version: str) -> None:
    extensions = dict(MINIMUM_EXTENSION_VERSIONS)
    extensions["vector"] = version

    assert (
        await _extension_status(cast(Any, _ReadinessConnection(extensions=extensions)))
        == "incomplete"
    )


@pytest.mark.parametrize(
    ("installed", "minimum", "supported"),
    [
        ("0.8.0", "0.8.0", True),
        ("0.8.1", "0.8.0", True),
        ("1.6", "1.6.0", True),
        ("1.5.9", "1.6", False),
        ("1.6-dev", "1.6", False),
    ],
)
def test_extension_version_comparison(
    installed: str,
    minimum: str,
    supported: bool,
) -> None:
    assert _extension_version_is_supported(installed, minimum) is supported


async def test_database_probe_sanitizes_connection_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "SENTINEL-CONNECTION-DETAIL-MUST-NOT-APPEAR"

    async def fail_to_connect(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(sentinel)

    monkeypatch.setattr(
        "kivra_memory.storage.readiness.AsyncConnection.connect",
        fail_to_connect,
    )

    result = await database_is_ready(DATABASE_URL, 1)

    assert result == DatabaseReadiness.unavailable()
    assert sentinel not in repr(result)


async def test_liveness_is_available() -> None:
    app = create_app(Settings())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_readiness_fails_closed_without_dependencies() -> None:
    app = create_app(Settings())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "not_configured",
            "migrations": "unchecked",
            "extensions": "unchecked",
        },
    }


async def test_readiness_reports_configured_database_state() -> None:
    async def database_is_ready(*_args: object) -> DatabaseReadiness:
        return DatabaseReadiness(database="ok", migrations="ok", extensions="ok")

    app = create_app(
        Settings(database_url=DATABASE_URL),
        database_probe=database_is_ready,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok", "migrations": "ok", "extensions": "ok"},
    }


async def test_readiness_hides_database_failure_details() -> None:
    async def database_is_ready(*_args: object) -> DatabaseReadiness:
        return DatabaseReadiness.unavailable()

    app = create_app(
        Settings(database_url=DATABASE_URL),
        database_probe=database_is_ready,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "migrations": "unchecked",
            "extensions": "unchecked",
        },
    }


@pytest.mark.parametrize(
    ("dependency_state", "expected_checks"),
    [
        (
            DatabaseReadiness(database="ok", migrations="incompatible", extensions="ok"),
            {"database": "ok", "migrations": "incompatible", "extensions": "ok"},
        ),
        (
            DatabaseReadiness(database="ok", migrations="ok", extensions="incomplete"),
            {"database": "ok", "migrations": "ok", "extensions": "incomplete"},
        ),
    ],
)
async def test_readiness_fails_closed_for_incompatible_database_dependencies(
    dependency_state: DatabaseReadiness,
    expected_checks: dict[str, str],
) -> None:
    async def database_is_ready(*_args: object) -> DatabaseReadiness:
        return dependency_state

    app = create_app(Settings(database_url=DATABASE_URL), database_probe=database_is_ready)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "checks": expected_checks}


async def test_readiness_sanitizes_unexpected_probe_errors() -> None:
    sentinel = "SENTINEL-DATABASE-DETAIL-MUST-NOT-APPEAR"

    async def database_is_ready(*_args: object) -> DatabaseReadiness:
        raise RuntimeError(sentinel)

    app = create_app(Settings(database_url=DATABASE_URL), database_probe=database_is_ready)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "migrations": "unchecked",
            "extensions": "unchecked",
        },
    }
    assert sentinel not in response.text


def test_startup_configuration_error_is_sanitized(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "SENTINEL-PASSWORD-MUST-NOT-APPEAR"
    monkeypatch.setenv("KIVRA_MEMORY_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "KIVRA_MEMORY_DATABASE_URL",
        f"postgresql://memory-api:{sentinel}@database.example/kivra_memory",
    )
    get_settings.cache_clear()

    with pytest.raises(SystemExit) as caught:
        main()

    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert captured.out == ""
    assert captured.err == "ScaleVault configuration is invalid\n"
    assert sentinel not in captured.err
    get_settings.cache_clear()
