from pathlib import Path
from typing import TypedDict

import pytest
from kivra_memory.config import Settings, get_settings
from pydantic import PostgresDsn, ValidationError


class _ProductionAuth(TypedDict):
    client_token_pepper_credential: Path
    client_token_pepper_key_id: str


PRODUCTION_AUTH: _ProductionAuth = {
    "client_token_pepper_credential": Path(
        "/run/credentials/kivra-memory-api.service/client-token-pepper"
    ),
    "client_token_pepper_key_id": "codex-primary-v1",
}


def test_settings_use_loopback_defaults() -> None:
    settings = Settings()

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.database_url is None
    assert settings.client_token_pepper_credential is None
    assert settings.client_token_pepper_key_id is None
    assert settings.sealed_content_enabled is False
    assert settings.sealed_key_provider_root is None
    assert settings.sealed_digest_binding_credential is None


def test_sealed_content_requires_an_explicit_absolute_provider_root() -> None:
    with pytest.raises(ValidationError, match="sealed_key_provider_root"):
        Settings(sealed_content_enabled=True)
    with pytest.raises(ValidationError, match="sealed_key_provider_root"):
        Settings(sealed_content_enabled=True, sealed_key_provider_root=Path("relative"))
    with pytest.raises(ValidationError, match="require sealed content to be enabled"):
        Settings(sealed_key_provider_root=Path("/tmp/keys"))
    with pytest.raises(ValidationError, match="sealed_digest_binding_credential"):
        Settings(
            sealed_content_enabled=True,
            sealed_key_provider_root=Path("/tmp/keys"),
        )
    with pytest.raises(ValidationError, match="sealed_digest_binding_credential"):
        Settings(
            sealed_content_enabled=True,
            sealed_key_provider_root=Path("/tmp/keys"),
            sealed_digest_binding_credential=Path("relative-binding"),
        )


def test_production_sealed_content_uses_separate_local_key_boundary() -> None:
    database_url = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")
    with pytest.raises(ValidationError, match="production key boundary"):
        Settings(
            environment="production",
            database_url=database_url,
            sealed_content_enabled=True,
            sealed_key_provider_root=Path("/mnt/memory/kivra-memory/sealed-keys"),
            sealed_digest_binding_credential=Path("/run/credentials/test/binding"),
            **PRODUCTION_AUTH,
        )

    with pytest.raises(ValidationError, match="systemd credential boundary"):
        Settings(
            environment="production",
            database_url=database_url,
            sealed_content_enabled=True,
            sealed_key_provider_root=Path("/var/lib/kivra-memory-sealed/keys"),
            sealed_digest_binding_credential=Path("/etc/kivra-memory/binding"),
            **PRODUCTION_AUTH,
        )

    settings = Settings(
        environment="production",
        database_url=database_url,
        sealed_content_enabled=True,
        sealed_key_provider_root=Path("/var/lib/kivra-memory-sealed/keys"),
        sealed_digest_binding_credential=Path(
            "/run/credentials/kivra-memory-api.service/sealed-digest-binding"
        ),
        **PRODUCTION_AUTH,
    )
    assert settings.sealed_content_enabled is True


def test_production_requires_database_url() -> None:
    with pytest.raises(ValidationError, match="database_url is required in production"):
        Settings(environment="production", **PRODUCTION_AUTH)


def test_client_token_pepper_configuration_is_paired_and_bounded() -> None:
    with pytest.raises(ValidationError, match="supplied together"):
        Settings(client_token_pepper_credential=Path("/tmp/pepper"))
    with pytest.raises(ValidationError, match="supplied together"):
        Settings(client_token_pepper_key_id="codex-primary-v1")
    with pytest.raises(ValidationError, match="absolute canonical path"):
        Settings(
            client_token_pepper_credential=Path("relative-pepper"),
            client_token_pepper_key_id="codex-primary-v1",
        )
    with pytest.raises(ValidationError, match="key ID is invalid"):
        Settings(
            client_token_pepper_credential=Path("/tmp/pepper"),
            client_token_pepper_key_id="INVALID KEY",
        )


def test_production_requires_exact_client_token_pepper_boundary() -> None:
    database_url = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")
    with pytest.raises(ValidationError, match="production boundary"):
        Settings(
            environment="production",
            database_url=database_url,
            client_token_pepper_credential=Path("/etc/scalevault/pepper"),
            client_token_pepper_key_id="codex-primary-v1",
        )


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
            **PRODUCTION_AUTH,
        )


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://memory-api:example@192.0.2.10/kivra_memory",
        "postgresql://memory-api:example@database.example/kivra_memory",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?host=database.example",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?hostaddr=192.0.2.10",
        "postgresql://memory-api:example@127.0.0.1/kivra_memory?service=remote",
        "postgresql://memory-api:example@%2Fvar%2Frun%2Fpostgresql-shadow/kivra_memory",
    ],
)
def test_production_rejects_non_local_database_destination(database_url: str) -> None:
    with pytest.raises(
        ValidationError,
        match="database_url must use a local PostgreSQL host in production",
    ):
        Settings(
            environment="production",
            database_url=PostgresDsn(database_url),
            **PRODUCTION_AUTH,
        )


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
    settings = Settings(
        environment="production",
        database_url=PostgresDsn(database_url),
        **PRODUCTION_AUTH,
    )

    assert settings.environment == "production"


def test_validation_errors_hide_database_url_input() -> None:
    sentinel = "SENTINEL-PASSWORD-MUST-NOT-APPEAR"

    with pytest.raises(ValidationError) as caught:
        Settings(
            environment="production",
            database_url=PostgresDsn(
                f"postgresql://memory-api:{sentinel}@database.example/kivra_memory"
            ),
            **PRODUCTION_AUTH,
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
    monkeypatch.setenv(
        "KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_CREDENTIAL",
        "/run/credentials/kivra-memory-api.service/client-token-pepper",
    )
    monkeypatch.setenv("KIVRA_MEMORY_CLIENT_TOKEN_PEPPER_KEY_ID", "codex-primary-v1")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.host == "127.0.0.1"
    assert settings.database_url is not None
    assert settings.database_url.hosts()[0]["host"] == "127.0.0.1"
    get_settings.cache_clear()
