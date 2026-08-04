from pathlib import Path

import pytest
from kivra_memory.config import Settings, get_settings
from pydantic import PostgresDsn, ValidationError


def test_settings_use_loopback_defaults() -> None:
    settings = Settings()

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.database_url is None


def test_production_requires_database_url() -> None:
    with pytest.raises(ValidationError, match="database_url is required in production"):
        Settings(environment="production")


def test_database_url_rejects_unsupported_driver() -> None:
    with pytest.raises(ValidationError, match="database_url must use the Psycopg driver"):
        Settings(
            database_url=PostgresDsn("postgresql+asyncpg://memory-api:example@127.0.0.1/memory")
        )


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10", "memory-node.example"])
def test_production_rejects_non_loopback_api_bind(host: str) -> None:
    with pytest.raises(ValidationError, match="host must be loopback in production"):
        Settings(
            environment="production",
            host=host,
            database_url=PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory"),
        )


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://memory-api:example@192.0.2.10/kivra_memory",
        "postgresql://memory-api:example@database.example/kivra_memory",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?host=database.example",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?hostaddr=192.0.2.10",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?service=remote",
    ],
)
def test_production_rejects_non_local_database_destination(database_url: str) -> None:
    with pytest.raises(
        ValidationError,
        match="database_url must use a local PostgreSQL host in production",
    ):
        Settings(environment="production", database_url=PostgresDsn(database_url))


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://memory-api:example@127.0.0.1/kivra_memory",
        "postgresql://memory-api:example@localhost/kivra_memory",
        "postgresql://memory-api:example@[::1]/kivra_memory",
        "postgresql://memory-api:example@%2Fvar%2Frun%2Fpostgresql/kivra_memory",
    ],
)
def test_production_accepts_local_database_destination(database_url: str) -> None:
    settings = Settings(environment="production", database_url=PostgresDsn(database_url))

    assert settings.environment == "production"


def test_validation_errors_hide_database_url_input() -> None:
    sentinel = "SENTINEL-PASSWORD-MUST-NOT-APPEAR"

    with pytest.raises(ValidationError) as caught:
        Settings(
            environment="production",
            database_url=PostgresDsn(
                f"postgresql://memory-api:{sentinel}@database.example/kivra_memory"
            ),
        )

    assert sentinel not in str(caught.value)


def test_development_loads_working_directory_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tmp_path.joinpath(".env").write_text("KIVRA_MEMORY_PORT=8181\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KIVRA_MEMORY_ENVIRONMENT", raising=False)
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.environment == "development"
    assert settings.port == 8181
    get_settings.cache_clear()


def test_production_does_not_load_working_directory_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tmp_path.joinpath(".env").write_text(
        "KIVRA_MEMORY_HOST=0.0.0.0\n"
        "KIVRA_MEMORY_DATABASE_URL=postgresql://memory-api:dotenv-secret@database.example/db\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIVRA_MEMORY_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "KIVRA_MEMORY_DATABASE_URL",
        "postgresql://memory-api:runtime-secret@127.0.0.1/kivra_memory",
    )
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.host == "127.0.0.1"
    assert settings.database_url is not None
    assert settings.database_url.hosts()[0]["host"] == "127.0.0.1"
    get_settings.cache_clear()
