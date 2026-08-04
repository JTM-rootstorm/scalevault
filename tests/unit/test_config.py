import pytest
from kivra_memory.config import Settings
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
