"""Typed runtime configuration for the canonical Memory Node."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated environment settings with safe local defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="KIVRA_MEMORY_",
        extra="ignore",
        frozen=True,
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    database_url: PostgresDsn | None = None
    database_connect_timeout_seconds: int = Field(default=3, ge=1, le=30)
    metrics_enabled: bool = True

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
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return Settings()
