"""Typed runtime configuration for the canonical Memory Node."""

from functools import lru_cache

from pydantic import Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated environment settings with safe local defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KIVRA_MEMORY_",
        extra="ignore",
        frozen=True,
    )

    environment: str = "development"
    log_level: str = "INFO"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    database_url: PostgresDsn | None = None
    metrics_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
