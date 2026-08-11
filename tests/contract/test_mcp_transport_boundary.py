from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.http_transport import MAX_MCP_REQUEST_BODY_BYTES
from kivra_memory.api.mcp import (
    create_chatgpt_read_mcp,
    create_mcp,
    create_mutation_mcp,
)
from mcp.server.fastmcp import FastMCP


@pytest.mark.parametrize(
    "server",
    [
        create_mutation_mcp(),
        create_chatgpt_read_mcp(),
        create_mcp(),
    ],
)
def test_production_mcp_servers_pin_loopback_security_and_body_limit(
    server: FastMCP[None],
) -> None:
    security = server.settings.transport_security

    assert server.settings.max_request_body_size == MAX_MCP_REQUEST_BODY_BYTES
    assert security is not None
    assert security.enable_dns_rebinding_protection is True
    assert security.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    assert security.allowed_origins == [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]


async def test_oversized_mcp_body_is_rejected_before_protocol_parsing() -> None:
    server = create_mcp()
    application = server.streamable_http_app()
    sentinel = b"SENTINEL-BODY-MUST-NOT-APPEAR"
    body = sentinel + b"a" * MAX_MCP_REQUEST_BODY_BYTES

    async with AsyncClient(
        transport=ASGITransport(app=application),
        base_url="http://127.0.0.1:8080",
    ) as client:
        response = await client.post(
            "/mcp",
            content=body,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413
    assert sentinel not in response.content
