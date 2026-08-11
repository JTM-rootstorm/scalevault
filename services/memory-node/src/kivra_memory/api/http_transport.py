"""Explicit fail-closed HTTP boundaries shared by ScaleVault MCP surfaces."""

from __future__ import annotations

from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_MCP_REQUEST_BODY_BYTES = 1024 * 1024
MAX_MCP_HEADER_COUNT = 64
MAX_MCP_HEADER_BYTES = 16 * 1024

_SINGLETON_HEADERS = frozenset(
    {
        b"host",
        b"origin",
        b"content-type",
        b"content-length",
        b"transfer-encoding",
        b"mcp-protocol-version",
        b"mcp-session-id",
    }
)
_FORWARDED_HEADERS = frozenset({b"forwarded", b"via", b"x-real-ip"})


def loopback_transport_security() -> TransportSecuritySettings:
    """Return the exact loopback-only MCP SDK transport policy."""

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
        allowed_origins=[
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ],
    )


class MCPHTTPBoundaryMiddleware:
    """Reject ambiguous or proxy-derived MCP headers before protocol parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = scope.get("headers", ())
        if len(headers) > MAX_MCP_HEADER_COUNT:
            await _reject(send, status=431)
            return

        counts: dict[bytes, int] = {}
        total_bytes = 0
        for raw_name, raw_value in headers:
            if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
                await _reject(send, status=400)
                return
            name = raw_name.lower()
            total_bytes += len(raw_name) + len(raw_value)
            if total_bytes > MAX_MCP_HEADER_BYTES:
                await _reject(send, status=431)
                return
            counts[name] = counts.get(name, 0) + 1
            if (
                name in _FORWARDED_HEADERS
                or name.startswith(b"x-forwarded-")
                or (name in _SINGLETON_HEADERS and counts[name] > 1)
            ):
                await _reject(send, status=400)
                return

        if counts.get(b"host") != 1:
            await _reject(send, status=400)
            return
        if counts.get(b"content-length", 0) and counts.get(b"transfer-encoding", 0):
            await _reject(send, status=400)
            return

        await self._app(scope, receive, send)


async def _reject(send: Send, *, status: int) -> None:
    body = b'{"error":"invalid_request"}'
    start: Message = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    }
    await send(start)
    await send({"type": "http.response.body", "body": body})


__all__ = [
    "MAX_MCP_HEADER_BYTES",
    "MAX_MCP_HEADER_COUNT",
    "MAX_MCP_REQUEST_BODY_BYTES",
    "MCPHTTPBoundaryMiddleware",
    "loopback_transport_security",
]
