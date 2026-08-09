"""Typed runtime configuration for the canonical Memory Node."""

import os
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
from typing import Literal, Self, cast
from urllib.parse import unquote

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOCAL_DATABASE_SOCKET_DIRECTORIES = {"/run/postgresql", "/var/run/postgresql"}
_DATABASE_DESTINATION_QUERY_PARAMETERS = {"host", "hostaddr", "service", "servicefile"}


class Settings(BaseSettings):
    """Validated environment settings with safe local defaults."""

    model_config = SettingsConfigDict(
        env_prefix="KIVRA_MEMORY_",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    database_url: PostgresDsn | None = None
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    metrics_enabled: bool = True
    sealed_content_enabled: bool = False
    sealed_key_provider_root: Path | None = None
    sealed_digest_binding_credential: Path | None = None

    @model_validator(mode="after")
    def require_production_dependencies(self) -> Self:
        """Reject a production process that cannot become ready."""

        if self.environment == "production" and self.database_url is None:
            raise ValueError("database_url is required in production")
        if self.database_url is not None and self.database_url.scheme not in {
            "postgres",
            "postgresql",
            "postgresql+psycopg",
        }:
            raise ValueError("database_url must use the Psycopg driver")
        if self.environment == "production":
            if not _is_loopback_host(self.host):
                raise ValueError("host must be loopback in production")
            if self.database_url is not None and not _is_local_database_url(self.database_url):
                raise ValueError("database_url must use a local PostgreSQL host in production")
        if self.sealed_content_enabled:
            if (
                self.sealed_key_provider_root is None
                or not self.sealed_key_provider_root.is_absolute()
                or ".." in self.sealed_key_provider_root.parts
            ):
                raise ValueError("sealed_key_provider_root must be an absolute canonical path")
            if (
                self.sealed_digest_binding_credential is None
                or not self.sealed_digest_binding_credential.is_absolute()
                or ".." in self.sealed_digest_binding_credential.parts
            ):
                raise ValueError(
                    "sealed_digest_binding_credential must be an absolute canonical path"
                )
            if self.environment == "production" and self.sealed_key_provider_root != Path(
                "/var/lib/kivra-memory-sealed/keys"
            ):
                raise ValueError("sealed_key_provider_root must use the production key boundary")
            if self.environment == "production" and self.sealed_digest_binding_credential != Path(
                "/run/credentials/kivra-memory-api.service/sealed-digest-binding"
            ):
                raise ValueError(
                    "sealed_digest_binding_credential must use the systemd credential boundary"
                )
        elif (
            self.sealed_key_provider_root is not None
            or self.sealed_digest_binding_credential is not None
        ):
            raise ValueError("sealed provider settings require sealed content to be enabled")
        return self


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _is_local_database_url(database_url: PostgresDsn) -> bool:
    query_parameters = {name for name, _value in database_url.query_params()}
    if query_parameters & _DATABASE_DESTINATION_QUERY_PARAMETERS:
        return False

    for database_host in database_url.hosts():
        raw_host = database_host["host"]
        if raw_host is None:
            return False
        decoded_host = unquote(raw_host).removeprefix("[").removesuffix("]")
        if decoded_host in _LOCAL_DATABASE_SOCKET_DIRECTORIES:
            continue
        if not _is_loopback_host(decoded_host):
            return False
    return True


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    environment = os.environ.get("KIVRA_MEMORY_ENVIRONMENT", "development")
    env_file = ".env" if environment == "development" else None
    return Settings(
        environment=cast(Literal["development", "test", "production"], environment),
        _env_file=env_file,  # type: ignore[call-arg]
    )
