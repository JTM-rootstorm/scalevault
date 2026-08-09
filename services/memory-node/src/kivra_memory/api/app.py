"""Memory Node application foundation."""

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from kivra_memory import __version__
from kivra_memory.api.mcp import (
    AuthenticatedMutationExecutor,
    MutationPrincipalResolver,
    NominationExecutor,
    ReadExecutor,
    ReadPrincipalResolver,
    create_mcp,
    dependency_unavailable_mutation_principal_resolver,
    dependency_unavailable_nomination_executor,
    dependency_unavailable_read_executor,
    dependency_unavailable_read_principal_resolver,
)
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import Settings, get_settings
from kivra_memory.storage.readiness import (
    DatabaseProbe,
    DatabaseReadiness,
    database_is_ready,
)

HEALTH_REQUESTS = Counter(
    "kivra_memory_health_requests_total",
    "Health endpoint requests",
    labelnames=("endpoint", "result"),
)


def create_app(
    settings: Settings | None = None,
    database_probe: DatabaseProbe = database_is_ready,
    mutation_principal_resolver: MutationPrincipalResolver = (
        dependency_unavailable_mutation_principal_resolver
    ),
    mutation_executor: AuthenticatedMutationExecutor | None = None,
    read_principal_resolver: ReadPrincipalResolver = (
        dependency_unavailable_read_principal_resolver
    ),
    read_executor: ReadExecutor = dependency_unavailable_read_executor,
    nomination_executor: NominationExecutor = dependency_unavailable_nomination_executor,
    sealed_runtime: SealedRuntime | None = None,
) -> FastAPI:
    """Create an application without storing authoritative process-local state."""

    runtime_settings = settings or get_settings()
    runtime_sealed = sealed_runtime or SealedRuntime(key_provider=None, digest_binder=None)
    if runtime_settings.sealed_content_enabled != runtime_sealed.enabled:
        raise RuntimeError("invalid_sealed_content_configuration")
    mcp_server = create_mcp(
        mutation_principal_resolver=mutation_principal_resolver,
        mutation_executor=mutation_executor,
        read_principal_resolver=read_principal_resolver,
        read_executor=read_executor,
        nomination_executor=nomination_executor,
    )
    mcp_application = mcp_server.streamable_http_app()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = runtime_settings
        app.state.sealed_content_configured = runtime_sealed.enabled
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
        dependency_state = DatabaseReadiness.not_configured()
        if runtime_settings.database_url is not None:
            try:
                probe_result = await database_probe(
                    runtime_settings.database_url,
                    runtime_settings.database_connect_timeout_seconds,
                )
            except Exception:
                dependency_state = DatabaseReadiness.unavailable()
            else:
                if isinstance(probe_result, bool):
                    dependency_state = (
                        DatabaseReadiness(database="ok", migrations="ok", extensions="ok")
                        if probe_result
                        else DatabaseReadiness.unavailable()
                    )
                else:
                    dependency_state = probe_result
        result = "ready" if dependency_state.ready else "not_ready"
        HEALTH_REQUESTS.labels(endpoint="readyz", result=result).inc()
        if not dependency_state.ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": result,
            "checks": {
                "database": dependency_state.database,
                "migrations": dependency_state.migrations,
                "extensions": dependency_state.extensions,
            },
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
        sealed_runtime = SealedRuntime.from_settings(settings)
    except (RuntimeError, SettingsError, ValidationError):
        print("ScaleVault configuration is invalid", file=sys.stderr)
        raise SystemExit(2) from None
    uvicorn.run(
        create_app(settings, sealed_runtime=sealed_runtime),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
