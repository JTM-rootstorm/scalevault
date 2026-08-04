from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.config import Settings
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def mcp_session(app: FastAPI | None = None) -> AsyncIterator[ClientSession]:
    """Connect the official MCP client to the in-process Streamable HTTP app."""

    runtime_app = app or create_app(Settings(environment="test"))
    transport = ASGITransport(app=runtime_app)
    async with (
        runtime_app.router.lifespan_context(runtime_app),
        AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8080",
        ) as http_client,
        streamable_http_client(
            "http://127.0.0.1:8080/mcp",
            http_client=http_client,
        ) as (read_stream, write_stream, _),
        ClientSession(read_stream, write_stream) as session,
    ):
        yield session


async def test_mcp_initialize_identifies_echo_probe() -> None:
    async with mcp_session() as session:
        result = await session.initialize()

    assert result.serverInfo.name == "ScaleVault MCP Echo Probe"
    assert result.capabilities.tools is not None


async def test_mcp_lists_only_non_mutating_echo_tool() -> None:
    async with mcp_session() as session:
        await session.initialize()
        result = await session.list_tools()

    assert [tool.name for tool in result.tools] == ["echo"]
    assert result.tools[0].annotations is not None
    assert result.tools[0].annotations.readOnlyHint is True
    assert result.tools[0].annotations.destructiveHint is False
    assert result.tools[0].inputSchema == {
        "properties": {"message": {"title": "Message", "type": "string"}},
        "required": ["message"],
        "title": "echoArguments",
        "type": "object",
    }


async def test_mcp_echo_returns_input_without_database_access() -> None:
    database_probe_calls: list[tuple[Any, ...]] = []

    async def database_probe(*args: Any) -> bool:
        database_probe_calls.append(args)
        return False

    app = create_app(Settings(environment="test"), database_probe=database_probe)
    async with mcp_session(app) as session:
        await session.initialize()
        result = await session.call_tool("echo", {"message": "transport works"})

    assert result.isError is False
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    assert result.content[0].text == "transport works"
    assert database_probe_calls == []
