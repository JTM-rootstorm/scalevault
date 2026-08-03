"""Memory Node application foundation."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest

from kivra_memory import __version__
from kivra_memory.config import Settings, get_settings

HEALTH_REQUESTS = Counter(
    "kivra_memory_health_requests_total",
    "Health endpoint requests",
    labelnames=("endpoint", "result"),
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create an application without storing authoritative process-local state."""

    runtime_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = runtime_settings
        app.state.dependencies_ready = False
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
        ready = bool(getattr(app.state, "dependencies_ready", False))
        result = "ready" if ready else "not_ready"
        HEALTH_REQUESTS.labels(endpoint="readyz", result=result).inc()
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": result,
            "checks": {"database": "not_configured"},
        }

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        if not runtime_settings.metrics_enabled:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()


def main() -> None:
    """Run the development ASGI server."""

    settings = get_settings()
    uvicorn.run(
        "kivra_memory.api.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
