"""Dedicated private HTTPS ingress for direct Codex MCP clients."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from ipaddress import ip_address

import uvicorn
from pydantic import ValidationError
from pydantic_settings import SettingsError
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kivra_memory.api.http_transport import (
    MAX_MCP_HEADER_BYTES,
    MAX_MCP_HEADER_COUNT,
    MAX_MCP_REQUEST_BODY_BYTES,
    MCPHTTPBoundaryMiddleware,
)
from kivra_memory.api.mcp import create_mcp
from kivra_memory.application.sealed_runtime import SealedRuntime
from kivra_memory.config import IPAddress, IPNetwork, Settings, get_settings
from kivra_memory.runtime import (
    MemoryNodeRuntime,
    current_command_principal,
    current_query_principal,
)

_LOOPBACK_UPSTREAM_HOST = b"127.0.0.1:8080"
CODEX_INGRESS_GET_TOTAL_DURATION_SECONDS = 300
CODEX_INGRESS_COMMAND_TOTAL_DURATION_SECONDS = 30
_INGRESS_SINGLETON_HEADERS = frozenset(
    {
        b"authorization",
        b"host",
        b"origin",
        b"content-type",
        b"content-length",
        b"transfer-encoding",
        b"mcp-protocol-version",
        b"mcp-session-id",
    }
)
_FORWARDING_HEADERS = frozenset({b"forwarded", b"via", b"x-real-ip"})


class CodexPrivateIngressBoundaryMiddleware:
    """Validate one trusted reverse-proxy hop and normalize into the loopback contract."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self._app = app
        hostname = settings.codex_ingress_external_hostname
        if settings.server_profile != "codex_private_ingress" or hostname is None:
            raise RuntimeError("invalid_codex_ingress_configuration")
        self._external_host = hostname.encode("ascii")
        self._external_origin = b"https://" + self._external_host
        self._trusted_proxy_cidrs = settings.codex_ingress_trusted_proxy_cidrs

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope["type"]
        if scope_type == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope_type == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope_type != "http":
            raise RuntimeError("unsupported_asgi_scope")

        status = self._validate_request(scope)
        if status is not None:
            await _reject(send, status=status)
            return

        normalized_scope = dict(scope)
        normalized_scope["scheme"] = "http"
        normalized_scope["server"] = ("127.0.0.1", 8080)
        normalized_scope["client"] = ("127.0.0.1", 0)
        normalized_scope["headers"] = [
            (b"host", _LOOPBACK_UPSTREAM_HOST)
            if raw_name.lower() == b"host"
            else (raw_name, raw_value)
            for raw_name, raw_value in scope["headers"]
            if raw_name.lower() != b"origin" and not _is_forwarding_header(raw_name.lower())
        ]
        response_started = False
        response_complete = False

        async def bounded_send(message: Message) -> None:
            nonlocal response_complete, response_started
            if message["type"] == "http.response.start":
                response_started = True
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                response_complete = True
            await send(message)

        total_duration = (
            CODEX_INGRESS_GET_TOTAL_DURATION_SECONDS
            if scope["method"] == "GET"
            else CODEX_INGRESS_COMMAND_TOTAL_DURATION_SECONDS
        )
        try:
            async with asyncio.timeout(total_duration):
                await self._app(normalized_scope, receive, bounded_send)
        except TimeoutError:
            if response_started:
                if not response_complete:
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
            else:
                await _reject_timeout(send)

    def _validate_request(self, scope: Scope) -> int | None:
        method = scope.get("method")
        if (
            method not in {"GET", "POST", "DELETE"}
            or scope.get("scheme") != "http"
            or scope.get("path") != "/mcp"
            or scope.get("raw_path") != b"/mcp"
            or scope.get("query_string") != b""
        ):
            return 400
        if not _peer_is_allowed(scope.get("client"), self._trusted_proxy_cidrs):
            return 403

        headers = scope.get("headers", ())
        if not isinstance(headers, (list, tuple)) or len(headers) > MAX_MCP_HEADER_COUNT:
            return 431
        counts: dict[bytes, int] = {}
        values: dict[bytes, bytes] = {}
        total_bytes = 0
        for header in headers:
            if not isinstance(header, tuple) or len(header) != 2:
                return 400
            raw_name, raw_value = header
            if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
                return 400
            name = raw_name.lower()
            total_bytes += len(raw_name) + len(raw_value)
            if total_bytes > MAX_MCP_HEADER_BYTES:
                return 431
            counts[name] = counts.get(name, 0) + 1
            values[name] = raw_value
            if (name in _INGRESS_SINGLETON_HEADERS and counts[name] > 1) or (
                _is_forwarding_header(name) and counts[name] > 1
            ):
                return 400

        if (
            counts.get(b"host") != 1
            or values.get(b"host") != self._external_host
            or counts.get(b"transfer-encoding", 0) != 0
        ):
            return 400
        origin = values.get(b"origin")
        if origin is not None and origin != self._external_origin:
            return 403
        content_length = values.get(b"content-length")
        if method == "POST":
            if counts.get(b"content-length") != 1 or content_length is None:
                return 400
            parsed_content_length = _parse_content_length(content_length)
            if parsed_content_length is None:
                return 400
            if parsed_content_length > MAX_MCP_REQUEST_BODY_BYTES:
                return 413
        elif content_length is not None and _parse_content_length(content_length) != 0:
            return 400
        return None


def _peer_is_allowed(peer: object, networks: tuple[IPNetwork, ...]) -> bool:
    if not isinstance(peer, (list, tuple)) or len(peer) != 2 or not isinstance(peer[0], str):
        return False
    try:
        address = ip_address(peer[0])
    except ValueError:
        return False
    return _address_is_allowed(address, networks)


def _address_is_allowed(address: IPAddress, networks: tuple[IPNetwork, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _parse_content_length(value: bytes) -> int | None:
    if not value or not value.isdigit() or (value.startswith(b"0") and value != b"0"):
        return None
    return int(value)


def _is_forwarding_header(name: bytes) -> bool:
    return name in _FORWARDING_HEADERS or name.startswith(b"x-forwarded-")


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


async def _reject_timeout(send: Send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 504,
            "headers": [(b"content-length", b"0"), (b"cache-control", b"no-store")],
        }
    )
    await send({"type": "http.response.body", "body": b""})


def create_codex_ingress_app(settings: Settings, runtime: MemoryNodeRuntime) -> Starlette:
    """Create the exact direct-private MCP surface without operator or tunnel routes."""

    if (
        settings.environment != "production"
        or settings.server_profile != "codex_private_ingress"
        or settings.chatgpt_secure_tunnel_enabled
    ):
        raise RuntimeError("invalid_codex_ingress_configuration")

    mcp_server = create_mcp(
        mutation_principal_resolver=current_command_principal,
        mutation_executor=runtime.execute_mutation,
        read_principal_resolver=current_query_principal,
        read_executor=runtime.execute_read,
        nomination_executor=runtime.execute_nomination,
    )
    mcp_application = runtime.authenticate_mcp(
        MCPHTTPBoundaryMiddleware(mcp_server.streamable_http_app())
    )

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        try:
            async with mcp_server.session_manager.run():
                yield
        finally:
            await runtime.dispose()

    app = Starlette(routes=[Mount("/", app=mcp_application)], lifespan=lifespan)
    app.add_middleware(CodexPrivateIngressBoundaryMiddleware, settings=settings)
    return app


def main() -> None:
    """Run the bounded private HTTPS ingress with sanitized configuration failures."""

    try:
        settings = get_settings()
        if settings.server_profile != "codex_private_ingress":
            raise RuntimeError("invalid_codex_ingress_configuration")
        sealed_runtime = SealedRuntime.from_settings(settings)
        runtime = MemoryNodeRuntime.from_settings(settings, sealed_runtime=sealed_runtime)
        host = settings.codex_ingress_host
        if host is None:
            raise RuntimeError("invalid_codex_ingress_configuration")
    except (RuntimeError, SettingsError, ValidationError):
        print("ScaleVault Codex ingress configuration is invalid", file=sys.stderr)
        raise SystemExit(2) from None

    uvicorn.run(
        create_codex_ingress_app(settings, runtime),
        host=str(host),
        port=settings.codex_ingress_port,
        log_level=settings.log_level.lower(),
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
        access_log=False,
        limit_concurrency=settings.codex_ingress_max_concurrency,
        timeout_keep_alive=5,
    )


__all__ = [
    "CODEX_INGRESS_COMMAND_TOTAL_DURATION_SECONDS",
    "CODEX_INGRESS_GET_TOTAL_DURATION_SECONDS",
    "CodexPrivateIngressBoundaryMiddleware",
    "create_codex_ingress_app",
    "main",
]
