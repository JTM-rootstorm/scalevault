from __future__ import annotations

from collections.abc import Iterable
from typing import cast

import pytest
from kivra_memory.api.http_transport import (
    MAX_MCP_HEADER_BYTES,
    MAX_MCP_HEADER_COUNT,
    MCPHTTPBoundaryMiddleware,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def _scope(headers: Iterable[tuple[bytes, bytes]]) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": list(headers),
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8080),
    }


async def _call(headers: Iterable[tuple[bytes, bytes]]) -> tuple[bool, list[Message]]:
    reached = False
    messages: list[Message] = []

    async def inner(_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal reached
        reached = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    app: ASGIApp = MCPHTTPBoundaryMiddleware(inner)
    await app(_scope(headers), cast(Receive, receive), cast(Send, send))
    return reached, messages


async def test_boundary_accepts_unambiguous_loopback_request_headers() -> None:
    reached, messages = await _call(
        [
            (b"host", b"127.0.0.1:8080"),
            (b"content-type", b"application/json"),
            (b"content-length", b"0"),
            (b"authorization", b"Bearer already-validated"),
        ]
    )

    assert reached is True
    assert messages[0]["status"] == 204


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"host", b"127.0.0.1:8080"), (b"host", b"localhost:8080")],
        [(b"host", b"127.0.0.1:8080"), (b"origin", b"a"), (b"origin", b"b")],
        [
            (b"host", b"127.0.0.1:8080"),
            (b"content-type", b"application/json"),
            (b"content-type", b"application/json"),
        ],
        [
            (b"host", b"127.0.0.1:8080"),
            (b"content-length", b"0"),
            (b"transfer-encoding", b"chunked"),
        ],
        [(b"host", b"127.0.0.1:8080"), (b"forwarded", b"for=192.0.2.1")],
        [(b"host", b"127.0.0.1:8080"), (b"x-forwarded-for", b"192.0.2.1")],
        [(b"host", b"127.0.0.1:8080"), (b"x-real-ip", b"192.0.2.1")],
        [(b"host", b"127.0.0.1:8080"), (b"via", b"1.1 proxy")],
    ],
)
async def test_boundary_rejects_ambiguous_or_forwarded_headers(
    headers: list[tuple[bytes, bytes]],
) -> None:
    reached, messages = await _call(headers)

    assert reached is False
    assert messages[0]["status"] == 400
    assert messages[1]["body"] == b'{"error":"invalid_request"}'


async def test_boundary_rejects_excessive_header_count_without_echoing_values() -> None:
    sentinel = b"SENTINEL-HEADER-MUST-NOT-APPEAR"
    headers = [(b"host", b"127.0.0.1:8080")]
    headers.extend((f"x-test-{index}".encode(), sentinel) for index in range(MAX_MCP_HEADER_COUNT))

    reached, messages = await _call(headers)

    assert reached is False
    assert messages[0]["status"] == 431
    assert sentinel not in messages[1]["body"]


async def test_boundary_rejects_excessive_aggregate_header_bytes() -> None:
    headers = [
        (b"host", b"127.0.0.1:8080"),
        (b"x-large", b"a" * MAX_MCP_HEADER_BYTES),
    ]

    reached, messages = await _call(headers)

    assert reached is False
    assert messages[0]["status"] == 431
    assert messages[1]["body"] == b'{"error":"invalid_request"}'
