"""Memory Node application foundation."""

import sys
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import ValidationError
from pydantic_settings import SettingsError
from starlette.types import ASGIApp

from kivra_memory import __version__
from kivra_memory.api.mcp import (
    AuthenticatedMutationExecutor,
    MutationPrincipalResolver,
    NominationExecutor,
    ReadExecutor,
    ReadPrincipalResolver,
    create_chatgpt_read_mcp,
    create_mcp,
    dependency_unavailable_mutation_principal_resolver,
    dependency_unavailable_nomination_executor,
    dependency_unavailable_read_executor,
    dependency_unavailable_read_principal_resolver,
)
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import Settings, get_settings
from kivra_memory.runtime import (
    ChatGPTReadRuntime,
    MemoryNodeRuntime,
    current_command_principal,
    current_query_principal,
    current_secure_tunnel_query_principal,
)
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
    runtime: MemoryNodeRuntime | None = None,
    chatgpt_runtime: ChatGPTReadRuntime | None = None,
) -> FastAPI:
    """Create an application without storing authoritative process-local state."""

    runtime_settings = settings or get_settings()
    runtime_sealed = sealed_runtime or SealedRuntime(key_provider=None, digest_binder=None)
    if runtime_settings.sealed_content_enabled != runtime_sealed.enabled:
        raise RuntimeError("invalid_sealed_content_configuration")
    if runtime_settings.chatgpt_secure_tunnel_enabled != (chatgpt_runtime is not None):
        raise RuntimeError("invalid_chatgpt_runtime_configuration")
    mcp_server = create_mcp(
        mutation_principal_resolver=(
            current_command_principal if runtime is not None else mutation_principal_resolver
        ),
        mutation_executor=(runtime.execute_mutation if runtime is not None else mutation_executor),
        read_principal_resolver=(
            current_query_principal if runtime is not None else read_principal_resolver
        ),
        read_executor=(runtime.execute_read if runtime is not None else read_executor),
        nomination_executor=(
            runtime.execute_nomination if runtime is not None else nomination_executor
        ),
    )
    mcp_application: ASGIApp = mcp_server.streamable_http_app()
    if runtime is not None:
        mcp_application = runtime.authenticate_mcp(mcp_application)
    chatgpt_server = None
    chatgpt_application: ASGIApp | None = None
    if chatgpt_runtime is not None:
        chatgpt_server = create_chatgpt_read_mcp(
            read_principal_resolver=current_secure_tunnel_query_principal,
            read_executor=chatgpt_runtime.execute_read,
        )
        chatgpt_application = chatgpt_runtime.authenticate_mcp(chatgpt_server.streamable_http_app())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = runtime_settings
        app.state.sealed_content_configured = runtime_sealed.enabled
        app.state.runtime_configured = runtime is not None
        app.state.chatgpt_runtime_configured = chatgpt_runtime is not None
        try:
            async with AsyncExitStack() as stack:
                await stack.enter_async_context(mcp_server.session_manager.run())
                if chatgpt_server is not None:
                    await stack.enter_async_context(chatgpt_server.session_manager.run())
                yield
        finally:
            if runtime is not None:
                await runtime.dispose()

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
        chatgpt_ready = (
            not runtime_settings.chatgpt_secure_tunnel_enabled or chatgpt_runtime is not None
        )
        result = (
            "ready"
            if dependency_state.ready and runtime is not None and chatgpt_ready
            else "not_ready"
        )
        HEALTH_REQUESTS.labels(endpoint="readyz", result=result).inc()
        if result != "ready":
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

    if chatgpt_application is not None:
        app.mount("/chatgpt", chatgpt_application)
    app.mount("/", mcp_application)

    return app


def main() -> None:
    """Run the ASGI server with sanitized startup configuration failures."""

    try:
        settings = get_settings()
        sealed_runtime = SealedRuntime.from_settings(settings)
        runtime = MemoryNodeRuntime.from_settings(settings, sealed_runtime=sealed_runtime)
        chatgpt_runtime = (
            ChatGPTReadRuntime.from_memory_runtime(settings, runtime)
            if settings.chatgpt_secure_tunnel_enabled
            else None
        )
    except (RuntimeError, SettingsError, ValidationError):
        print("ScaleVault configuration is invalid", file=sys.stderr)
        raise SystemExit(2) from None
    uvicorn.run(
        create_app(
            settings,
            sealed_runtime=sealed_runtime,
            runtime=runtime,
            chatgpt_runtime=chatgpt_runtime,
        ),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
