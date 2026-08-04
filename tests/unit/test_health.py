import pytest
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app, main, psycopg_connection_info
from kivra_memory.config import Settings, get_settings
from pydantic import PostgresDsn

DATABASE_URL = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")


def test_sqlalchemy_database_url_is_normalized_for_psycopg() -> None:
    database_url = PostgresDsn("postgresql+psycopg://memory-api:example@127.0.0.1/kivra_memory")

    assert psycopg_connection_info(database_url).startswith("postgresql://")


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
        "checks": {"database": "not_configured"},
    }


async def test_readiness_reports_configured_database_state() -> None:
    async def database_is_ready(*_args: object) -> bool:
        return True

    app = create_app(
        Settings(database_url=DATABASE_URL),
        database_probe=database_is_ready,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {"database": "ok"},
    }


async def test_readiness_hides_database_failure_details() -> None:
    async def database_is_ready(*_args: object) -> bool:
        return False

    app = create_app(
        Settings(database_url=DATABASE_URL),
        database_probe=database_is_ready,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/readyz")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"database": "unavailable"},
    }


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
