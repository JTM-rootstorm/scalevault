"""Memory Node application foundation."""

import asyncio
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from psycopg import AsyncConnection
from pydantic import PostgresDsn, ValidationError
from pydantic_settings import SettingsError

from kivra_memory import __version__
from kivra_memory.api.mcp_echo import create_echo_mcp
from kivra_memory.config import Settings, get_settings

HEALTH_REQUESTS = Counter(
    "kivra_memory_health_requests_total",
    "Health endpoint requests",
    labelnames=("endpoint", "result"),
)

DatabaseProbe = Callable[[PostgresDsn, int], Awaitable[bool]]


def psycopg_connection_info(database_url: PostgresDsn) -> str:
    """Convert an SQLAlchemy Psycopg URL into a libpq-compatible URL."""

    return database_url.unicode_string().replace(
        "postgresql+psycopg://",
        "postgresql://",
        1,
    )


async def database_is_ready(database_url: PostgresDsn, timeout_seconds: int) -> bool:
    """Probe PostgreSQL without exposing connection details in the response."""

    try:
        async with asyncio.timeout(timeout_seconds):
            connection = await AsyncConnection.connect(
                psycopg_connection_info(database_url),
                connect_timeout=timeout_seconds,
            )
            async with connection:
                await connection.execute("SELECT 1")
    except Exception:
        return False
    return True


def create_app(
    settings: Settings | None = None,
    database_probe: DatabaseProbe = database_is_ready,
) -> FastAPI:
    """Create an application without storing authoritative process-local state."""

    runtime_settings = settings or get_settings()
    mcp_server = create_echo_mcp()
    mcp_application = mcp_server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = runtime_settings
        async with mcp_server.session_manager.run():
            yield

    app = FastAPI(
        title="ScaleVault Memory Node",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/healthz", tags=["operator"])
    async def health() -> dict[str, str]:
        HEALTH_REQUESTS.labels(endpoint="healthz", result="ok").inc()
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["operator"])
    async def readiness(response: Response) -> dict[str, Any]:
        database_status = "not_configured"
        ready = False
        if runtime_settings.database_url is not None:
            ready = await database_probe(
                runtime_settings.database_url,
                runtime_settings.database_connect_timeout_seconds,
            )
            database_status = "ok" if ready else "unavailable"
        result = "ready" if ready else "not_ready"
        HEALTH_REQUESTS.labels(endpoint="readyz", result=result).inc()
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": result,
            "checks": {"database": database_status},
        }

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        if not runtime_settings.metrics_enabled:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.mount("/", mcp_application)

    return app


def main() -> None:
    """Run the ASGI server with sanitized startup configuration failures."""

    try:
        settings = get_settings()
    except (SettingsError, ValidationError):
        print("ScaleVault configuration is invalid", file=sys.stderr)
        raise SystemExit(2) from None
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
