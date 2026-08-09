from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.auth import RequestTransportIdentity
from kivra_memory.config import Settings
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import (
    QueryPrincipal,
    ReadError,
    ReadErrorBody,
)
from kivra_memory.runtime.chatgpt import ChatGPTReadQuery, ChatGPTReadRuntime
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import PostgresDsn
from starlette.types import ASGIApp


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


INSTALLATION_ID = uid(1)
DATABASE_URL = PostgresDsn("postgresql://memory-api:example@127.0.0.1/kivra_memory")


def chatgpt_settings() -> Settings:
    return Settings(
        environment="test",
        database_url=DATABASE_URL,
        client_token_pepper_credential=Path("/tmp/test-client-token-pepper"),
        client_token_pepper_key_id="codex-primary-v1",
        chatgpt_secure_tunnel_enabled=True,
        chatgpt_secure_tunnel_installation_id=INSTALLATION_ID,
    )


def principal(ordinal: int = 10) -> QueryPrincipal:
    return QueryPrincipal(
        tenant_id=uid(ordinal),
        actor_id=uid(ordinal + 1),
        client_id=uid(ordinal + 2),
        transport_binding_id=uid(ordinal + 3),
        scopes=frozenset({"memory.read.lineage"}),
        allowed_memory_scopes=frozenset({MemoryScope.PERSONA}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=3,
    )


class FixedQueryAuthenticator:
    def __init__(self, resolved: QueryPrincipal) -> None:
        self.resolved = resolved
        self.calls: list[tuple[str | None, RequestTransportIdentity]] = []

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> QueryPrincipal:
        self.calls.append((authorization_header, expected_transport))
        if authorization_header != "Bearer test-token":
            raise ValueError
        return self.resolved


class RecordingQueries:
    def __init__(self) -> None:
        self.calls: list[tuple[QueryPrincipal, ChatGPTReadQuery]] = []

    async def execute(
        self,
        resolved: QueryPrincipal,
        query: ChatGPTReadQuery,
    ) -> ReadError:
        self.calls.append((resolved, query))
        return ReadError(
            error=ReadErrorBody(
                code="not_found",
                message=ReadErrorBody.SAFE_MESSAGES["not_found"],
            )
        )


class InertMemoryRuntime:
    def __init__(self) -> None:
        self.disposed = False

    async def execute_mutation(self, *_args: object) -> Any:
        raise AssertionError("direct mutation surface was not expected")

    async def execute_nomination(self, *_args: object) -> Any:
        raise AssertionError("direct nomination surface was not expected")

    async def execute_read(self, *_args: object) -> Any:
        raise AssertionError("direct read surface was not expected")

    def authenticate_mcp(self, application: ASGIApp) -> ASGIApp:
        return application

    async def dispose(self) -> None:
        self.disposed = True


@asynccontextmanager
async def chatgpt_session(app: FastAPI) -> AsyncIterator[ClientSession]:
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8080",
            headers={"Authorization": "Bearer test-token"},
        ) as client,
        streamable_http_client(
            "http://127.0.0.1:8080/chatgpt/mcp",
            http_client=client,
        ) as (read_stream, write_stream, _),
        ClientSession(read_stream, write_stream) as session,
    ):
        yield session


async def test_chatgpt_route_authenticates_and_reaches_only_read_executor() -> None:
    query_principal = principal()
    authenticator = FixedQueryAuthenticator(query_principal)
    queries = RecordingQueries()
    runtime = InertMemoryRuntime()
    chatgpt_runtime = ChatGPTReadRuntime(
        authenticator=authenticator,
        installation_id=INSTALLATION_ID,
        queries=cast(Any, queries),
        status=cast(Any, object()),
    )
    app = create_app(
        chatgpt_settings(),
        runtime=cast(Any, runtime),
        chatgpt_runtime=chatgpt_runtime,
    )

    async with app.router.lifespan_context(app), chatgpt_session(app) as session:
        initialized = await session.initialize()
        tools = (await session.list_tools()).tools
        result = await session.call_tool(
            "memory_lineage",
            {
                "contract_version": "mcp-read-v1",
                "persona_id": str(uid(20)),
                "branch_id": str(uid(21)),
            },
        )

    assert initialized.serverInfo.name == "ScaleVault ChatGPT Read Node"
    assert len(tools) == 10
    assert all(tool.annotations is not None and tool.annotations.readOnlyHint for tool in tools)
    assert "memory_nominate" not in {tool.name for tool in tools}
    assert result.structuredContent is not None
    assert result.structuredContent["ok"] is False
    assert result.structuredContent["error"]["code"] == "not_found"
    assert queries.calls[0][0] == query_principal
    assert all(call[0] == "Bearer test-token" for call in authenticator.calls)
    assert all(
        call[1]
        == RequestTransportIdentity(
            transport_kind=TransportKind.SECURE_TUNNEL,
            installation_id=INSTALLATION_ID,
        )
        for call in authenticator.calls
    )
    assert runtime.disposed is True


async def test_chatgpt_route_rejects_missing_or_wrong_authorization() -> None:
    runtime = InertMemoryRuntime()
    chatgpt_runtime = ChatGPTReadRuntime(
        authenticator=FixedQueryAuthenticator(principal()),
        installation_id=INSTALLATION_ID,
        queries=cast(Any, RecordingQueries()),
        status=cast(Any, object()),
    )
    app = create_app(
        chatgpt_settings(),
        runtime=cast(Any, runtime),
        chatgpt_runtime=chatgpt_runtime,
    )
    transport = ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client,
    ):
        missing = await client.post("/chatgpt/mcp")
        wrong = await client.post(
            "/chatgpt/mcp",
            headers={"Authorization": "Bearer direct-private-token"},
        )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert missing.json() == wrong.json() == {"error": "authentication_required"}


async def test_oauth_protected_resource_discovery_is_bare_not_advertised() -> None:
    runtime = InertMemoryRuntime()
    chatgpt_runtime = ChatGPTReadRuntime(
        authenticator=FixedQueryAuthenticator(principal()),
        installation_id=INSTALLATION_ID,
        queries=cast(Any, RecordingQueries()),
        status=cast(Any, object()),
    )
    app = create_app(
        chatgpt_settings(),
        runtime=cast(Any, runtime),
        chatgpt_runtime=chatgpt_runtime,
    )
    transport = ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=transport, base_url="http://127.0.0.1:8080") as client,
    ):
        responses = [
            await client.get("/.well-known/oauth-protected-resource/chatgpt/mcp"),
            await client.get("/.well-known/oauth-protected-resource"),
        ]
        protected_mcp = await client.get("/chatgpt/mcp")

    assert all(response.status_code == 404 for response in responses)
    assert all(response.content == b"{}" for response in responses)
    assert all(response.headers["content-type"] == "application/json" for response in responses)
    assert all("www-authenticate" not in response.headers for response in responses)
    assert protected_mcp.status_code == 401
    assert protected_mcp.json() == {"error": "authentication_required"}


def test_chatgpt_runtime_configuration_must_match_enabled_setting() -> None:
    with pytest.raises(RuntimeError, match=r"^invalid_chatgpt_runtime_configuration$"):
        create_app(chatgpt_settings(), runtime=cast(Any, InertMemoryRuntime()))

    disabled = Settings(environment="test")
    unexpected = ChatGPTReadRuntime(
        authenticator=FixedQueryAuthenticator(principal()),
        installation_id=INSTALLATION_ID,
        queries=cast(Any, RecordingQueries()),
        status=cast(Any, object()),
    )
    with pytest.raises(RuntimeError, match=r"^invalid_chatgpt_runtime_configuration$"):
        create_app(disabled, chatgpt_runtime=unexpected)
