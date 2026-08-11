from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import TypedDict
from uuid import UUID

import pytest
from kivra_memory.config import Settings, get_settings
from kivra_memory.domain.identifiers import new_uuid7
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

CODEX_INGRESS_AUTH: _ProductionAuth = {
    "client_token_pepper_credential": Path(
        "/run/credentials/kivra-memory-codex-ingress.service/client-token-pepper"
    ),
    "client_token_pepper_key_id": "codex-primary-v1",
}


def codex_ingress_settings(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "environment": "production",
        "server_profile": "codex_private_ingress",
        "database_url": PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory"),
        "metrics_enabled": False,
        "codex_ingress_host": "10.0.0.78",
        "codex_ingress_port": 8443,
        "codex_ingress_external_hostname": "memory.example.test",
        "codex_ingress_trusted_proxy_cidrs": (ip_network("10.0.0.10/32"),),
        "codex_ingress_tls_certificate": Path(
            "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-cert"
        ),
        "codex_ingress_tls_private_key": Path(
            "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-key"
        ),
        **CODEX_INGRESS_AUTH,
    }
    values.update(overrides)
    return values


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def test_settings_use_loopback_defaults() -> None:
    settings = Settings()

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.database_url is None
    assert settings.client_token_pepper_credential is None
    assert settings.client_token_pepper_key_id is None
    assert settings.chatgpt_secure_tunnel_enabled is False
    assert settings.chatgpt_secure_tunnel_installation_id is None
    assert settings.sealed_content_enabled is False
    assert settings.sealed_key_provider_root is None
    assert settings.sealed_digest_binding_credential is None


def test_codex_private_ingress_is_an_explicit_narrow_production_profile() -> None:
    settings = Settings(**codex_ingress_settings())  # type: ignore[arg-type]

    assert settings.host == "127.0.0.1"
    assert str(settings.codex_ingress_host) == "10.0.0.78"
    assert settings.codex_ingress_port == 8443
    assert settings.codex_ingress_external_hostname == "memory.example.test"
    assert settings.metrics_enabled is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("environment", "test", "production-only"),
        ("codex_ingress_host", "0.0.0.0", "exact private address"),
        ("codex_ingress_host", "127.0.0.1", "exact private address"),
        ("codex_ingress_port", 8080, "port must be 8443"),
        ("codex_ingress_external_hostname", "MEMORY.example.test", "hostname is invalid"),
        ("codex_ingress_trusted_proxy_cidrs", (), "proxy CIDRs are invalid"),
        (
            "codex_ingress_trusted_proxy_cidrs",
            (ip_network("10.0.0.0/24"),),
            "CIDRs must be exact hosts",
        ),
        ("metrics_enabled", True, "metrics must be disabled"),
        ("codex_ingress_tls_certificate", Path("/tmp/cert"), "TLS certificate"),
        ("codex_ingress_tls_private_key", Path("/tmp/key"), "TLS private key"),
    ],
)
def test_codex_private_ingress_rejects_unsafe_configuration(
    field: str, value: object, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        Settings(**codex_ingress_settings(**{field: value}))  # type: ignore[arg-type]


def test_canonical_profile_rejects_codex_ingress_settings() -> None:
    with pytest.raises(ValidationError, match="require the Codex ingress server profile"):
        Settings(codex_ingress_host=ip_address("10.0.0.78"))


def test_codex_private_ingress_uses_its_own_sealed_digest_boundary() -> None:
    with pytest.raises(ValidationError, match="systemd credential boundary"):
        Settings(
            **codex_ingress_settings(
                sealed_content_enabled=True,
                sealed_key_provider_root=Path("/var/lib/kivra-memory-sealed/keys"),
                sealed_digest_binding_credential=Path(
                    "/run/credentials/kivra-memory-api.service/sealed-digest-binding"
                ),
            )  # type: ignore[arg-type]
        )

    settings = Settings(
        **codex_ingress_settings(
            sealed_content_enabled=True,
            sealed_key_provider_root=Path("/var/lib/kivra-memory-sealed/keys"),
            sealed_digest_binding_credential=Path(
                "/run/credentials/kivra-memory-codex-ingress.service/sealed-digest-binding"
            ),
        )  # type: ignore[arg-type]
    )
    assert settings.sealed_content_enabled is True


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


def test_chatgpt_secure_tunnel_configuration_is_explicit_and_complete() -> None:
    database_url = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")
    with pytest.raises(ValidationError, match="installation ID is required"):
        Settings(
            database_url=database_url,
            chatgpt_secure_tunnel_enabled=True,
            client_token_pepper_credential=Path("/tmp/pepper"),
            client_token_pepper_key_id="codex-primary-v1",
        )
    with pytest.raises(ValidationError, match="database_url is required"):
        Settings(
            chatgpt_secure_tunnel_enabled=True,
            chatgpt_secure_tunnel_installation_id=uid(1),
            client_token_pepper_credential=Path("/tmp/pepper"),
            client_token_pepper_key_id="codex-primary-v1",
        )
    with pytest.raises(ValidationError, match="client token verifier is required"):
        Settings(
            database_url=database_url,
            chatgpt_secure_tunnel_enabled=True,
            chatgpt_secure_tunnel_installation_id=uid(1),
        )
    with pytest.raises(ValidationError, match="must be UUIDv7"):
        Settings(
            database_url=database_url,
            chatgpt_secure_tunnel_enabled=True,
            chatgpt_secure_tunnel_installation_id=UUID("00000000-0000-4000-8000-000000000001"),
            client_token_pepper_credential=Path("/tmp/pepper"),
            client_token_pepper_key_id="codex-primary-v1",
        )
    with pytest.raises(ValidationError, match="requires the tunnel to be enabled"):
        Settings(chatgpt_secure_tunnel_installation_id=uid(1))

    settings = Settings(
        database_url=database_url,
        chatgpt_secure_tunnel_enabled=True,
        chatgpt_secure_tunnel_installation_id=uid(1),
        client_token_pepper_credential=Path("/tmp/pepper"),
        client_token_pepper_key_id="codex-primary-v1",
    )

    assert settings.chatgpt_secure_tunnel_enabled is True
    assert settings.chatgpt_secure_tunnel_installation_id == uid(1)


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
