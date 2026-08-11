"""Typed runtime configuration for the canonical Memory Node."""

import os
import re
from functools import lru_cache
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Literal, Self, cast
from urllib.parse import unquote
from uuid import UUID

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from kivra_memory.domain.identifiers import require_uuid7

_LOCAL_DATABASE_SOCKET_DIRECTORIES = {"/run/postgresql", "/var/run/postgresql"}
_DATABASE_DESTINATION_QUERY_PARAMETERS = {"host", "hostaddr", "service", "servicefile"}
_CLIENT_TOKEN_PEPPER_KEY_ID_PATTERN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PRIVATE_INGRESS_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("fc00::/7"),
)

type IPAddress = IPv4Address | IPv6Address
type IPNetwork = IPv4Network | IPv6Network


class Settings(BaseSettings):
    """Validated environment settings with safe local defaults."""

    model_config = SettingsConfigDict(
        env_prefix="KIVRA_MEMORY_",
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    server_profile: Literal["canonical", "codex_private_ingress"] = "canonical"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    codex_ingress_host: IPAddress | None = None
    codex_ingress_port: int = Field(default=8443, ge=1, le=65535)
    codex_ingress_external_hostname: str | None = None
    codex_ingress_trusted_proxy_cidrs: tuple[IPNetwork, ...] = ()
    codex_ingress_tls_certificate: Path | None = None
    codex_ingress_tls_private_key: Path | None = None
    codex_ingress_max_concurrency: int = Field(default=4, ge=1, le=32)
    database_url: PostgresDsn | None = None
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    metrics_enabled: bool = True
    client_token_pepper_credential: Path | None = None
    client_token_pepper_key_id: str | None = None
    chatgpt_secure_tunnel_enabled: bool = False
    chatgpt_secure_tunnel_installation_id: UUID | None = None
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
        if self.server_profile == "codex_private_ingress":
            if self.environment != "production":
                raise ValueError("Codex private ingress is a production-only server profile")
            if self.codex_ingress_host is None or not _is_private_ingress_address(
                self.codex_ingress_host
            ):
                raise ValueError("Codex ingress host must be an exact private address")
            if self.codex_ingress_port != 8443:
                raise ValueError("Codex ingress port must be 8443")
            if self.codex_ingress_external_hostname is None or not _is_exact_dns_hostname(
                self.codex_ingress_external_hostname
            ):
                raise ValueError("Codex ingress external hostname is invalid")
            if not _valid_private_network_allowlist(self.codex_ingress_trusted_proxy_cidrs):
                raise ValueError("Codex ingress trusted proxy CIDRs are invalid")
            if any(
                network.prefixlen != network.max_prefixlen
                for network in self.codex_ingress_trusted_proxy_cidrs
            ):
                raise ValueError("Codex ingress trusted proxy CIDRs must be exact hosts")
            if self.codex_ingress_tls_certificate != Path(
                "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-cert"
            ):
                raise ValueError("Codex ingress TLS certificate must use the production boundary")
            if self.codex_ingress_tls_private_key != Path(
                "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-key"
            ):
                raise ValueError("Codex ingress TLS private key must use the production boundary")
            if self.chatgpt_secure_tunnel_enabled:
                raise ValueError("ChatGPT secure tunnel is unavailable on Codex ingress")
            if self.metrics_enabled:
                raise ValueError("metrics must be disabled on Codex ingress")
        elif (
            self.codex_ingress_host is not None
            or self.codex_ingress_external_hostname is not None
            or self.codex_ingress_trusted_proxy_cidrs
            or self.codex_ingress_tls_certificate is not None
            or self.codex_ingress_tls_private_key is not None
        ):
            raise ValueError("Codex ingress settings require the Codex ingress server profile")
        if (self.client_token_pepper_credential is None) != (
            self.client_token_pepper_key_id is None
        ):
            raise ValueError("client token pepper credential and key ID must be supplied together")
        if self.client_token_pepper_credential is not None and (
            not self.client_token_pepper_credential.is_absolute()
            or ".." in self.client_token_pepper_credential.parts
        ):
            raise ValueError("client token pepper credential must be an absolute canonical path")
        if self.client_token_pepper_key_id is not None and (
            _CLIENT_TOKEN_PEPPER_KEY_ID_PATTERN.fullmatch(self.client_token_pepper_key_id) is None
        ):
            raise ValueError("client token pepper key ID is invalid")
        if self.environment == "production":
            credential_boundary = (
                "/run/credentials/kivra-memory-codex-ingress.service/client-token-pepper"
                if self.server_profile == "codex_private_ingress"
                else "/run/credentials/kivra-memory-api.service/client-token-pepper"
            )
            if self.client_token_pepper_credential != Path(credential_boundary):
                raise ValueError("client token pepper credential must use the production boundary")
            if self.client_token_pepper_key_id is None:
                raise ValueError("client token pepper key ID is required in production")
        if self.chatgpt_secure_tunnel_enabled:
            if self.chatgpt_secure_tunnel_installation_id is None:
                raise ValueError("ChatGPT secure tunnel installation ID is required when enabled")
            if self.database_url is None:
                raise ValueError("database_url is required for the ChatGPT secure tunnel")
            if (
                self.client_token_pepper_credential is None
                or self.client_token_pepper_key_id is None
            ):
                raise ValueError("client token verifier is required for the ChatGPT secure tunnel")
            try:
                require_uuid7(
                    self.chatgpt_secure_tunnel_installation_id,
                    field_name="chatgpt_secure_tunnel_installation_id",
                )
            except (TypeError, ValueError):
                raise ValueError("ChatGPT secure tunnel installation ID must be UUIDv7") from None
        elif self.chatgpt_secure_tunnel_installation_id is not None:
            raise ValueError(
                "ChatGPT secure tunnel installation ID requires the tunnel to be enabled"
            )
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
            digest_boundary = (
                "/run/credentials/kivra-memory-codex-ingress.service/sealed-digest-binding"
                if self.server_profile == "codex_private_ingress"
                else "/run/credentials/kivra-memory-api.service/sealed-digest-binding"
            )
            if self.environment == "production" and self.sealed_digest_binding_credential != Path(
                digest_boundary
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


def _is_private_ingress_address(address: IPAddress) -> bool:
    return any(
        address.version == network.version and address in network
        for network in _PRIVATE_INGRESS_NETWORKS
    )


def _valid_private_network_allowlist(networks: tuple[IPNetwork, ...]) -> bool:
    if not networks or len(networks) != len(set(networks)):
        return False
    for index, network in enumerate(networks):
        if isinstance(network, IPv4Network):
            inside_private_boundary = any(
                isinstance(boundary, IPv4Network) and network.subnet_of(boundary)
                for boundary in _PRIVATE_INGRESS_NETWORKS
            )
        else:
            inside_private_boundary = any(
                isinstance(boundary, IPv6Network) and network.subnet_of(boundary)
                for boundary in _PRIVATE_INGRESS_NETWORKS
            )
        if not inside_private_boundary:
            return False
        if any(
            index != other_index and network.overlaps(other)
            for other_index, other in enumerate(networks)
            if network.version == other.version
        ):
            return False
    return True


def _is_exact_dns_hostname(hostname: str) -> bool:
    if (
        not hostname
        or len(hostname) > 253
        or hostname != hostname.lower()
        or hostname.endswith(".")
    ):
        return False
    try:
        hostname.encode("ascii")
        ip_address(hostname)
    except UnicodeEncodeError:
        return False
    except ValueError:
        pass
    else:
        return False
    labels = hostname.split(".")
    return len(labels) >= 2 and all(_DNS_LABEL_PATTERN.fullmatch(label) for label in labels)


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
