from __future__ import annotations

import asyncio
from collections.abc import Iterable
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient, Response
from kivra_memory.api import app as canonical_app
from kivra_memory.api import codex_ingress
from kivra_memory.api.codex_ingress import (
    CodexPrivateIngressBoundaryMiddleware,
    create_codex_ingress_app,
)
from kivra_memory.api.http_transport import MAX_MCP_HEADER_BYTES, MAX_MCP_REQUEST_BODY_BYTES
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.auth import (
    AuthenticatedRequestIdentity,
    BearerAuthenticationError,
    RequestTransportIdentity,
    StatusIdentity,
)
from kivra_memory.config import Settings
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal
from kivra_memory.runtime.composition import MemoryNodeRuntime
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_SYNTHETIC_BEARER = "synthetic-test-credential"


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


class SyntheticAuthenticator:
    def __init__(self) -> None:
        tenant_id, actor_id, client_id, credential_id, binding_id = tuple(
            uid(index) for index in range(1, 6)
        )
        self.identity = AuthenticatedRequestIdentity(
            command_principal=CommandPrincipal(
                tenant_id=tenant_id,
                actor_id=actor_id,
                client_id=client_id,
                transport_binding_id=binding_id,
                scopes=frozenset({"memory.write.remember"}),
            ),
            query_principal=QueryPrincipal(
                tenant_id=tenant_id,
                actor_id=actor_id,
                client_id=client_id,
                transport_binding_id=binding_id,
                scopes=frozenset({"memory.read.get"}),
                allowed_memory_scopes=frozenset({MemoryScope.PERSONA}),
                allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
                max_sensitivity=1,
            ),
            status_identity=StatusIdentity(
                tenant_id=tenant_id,
                actor_id=actor_id,
                client_id=client_id,
                credential_id=credential_id,
                transport_binding_id=binding_id,
                transport_kind=TransportKind.DIRECT_PRIVATE,
                disclosure_boundary="private_node",
            ),
        )
        self.calls: list[RequestTransportIdentity] = []

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> AuthenticatedRequestIdentity:
        self.calls.append(expected_transport)
        if authorization_header != f"Bearer {_SYNTHETIC_BEARER}":
            raise BearerAuthenticationError
        return self.identity


class SyntheticDatabase:
    def __init__(self) -> None:
        self.disposed = False

    async def dispose(self) -> None:
        self.disposed = True


def composed_app() -> tuple[Any, SyntheticAuthenticator, SyntheticDatabase]:
    authenticator = SyntheticAuthenticator()
    database = SyntheticDatabase()
    runtime = MemoryNodeRuntime(
        database=cast(Any, database),
        authenticator=authenticator,
        mutations=cast(Any, object()),
        nominations=cast(Any, object()),
        queries=cast(Any, object()),
        status=cast(Any, object()),
    )
    runtime_settings = Settings.model_construct(
        environment="production",
        server_profile="codex_private_ingress",
        chatgpt_secure_tunnel_enabled=False,
        codex_ingress_external_hostname="memory.example.test",
        codex_ingress_trusted_proxy_cidrs=(ip_network("10.0.0.10/32"),),
    )
    return create_codex_ingress_app(runtime_settings, runtime), authenticator, database


def settings() -> Settings:
    return Settings.model_construct(
        server_profile="codex_private_ingress",
        codex_ingress_external_hostname="memory.example.test",
        codex_ingress_trusted_proxy_cidrs=(ip_network("10.0.0.10/32"),),
    )


def scope(
    *,
    method: str = "POST",
    path: str = "/mcp",
    raw_path: bytes = b"/mcp",
    query: bytes = b"",
    scheme: str = "https",
    client: tuple[str, int] = ("10.0.0.10", 41234),
    headers: Iterable[tuple[bytes, bytes]] | None = None,
) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path,
        "raw_path": raw_path,
        "query_string": query,
        "root_path": "",
        "headers": list(
            headers
            if headers is not None
            else [
                (b"host", b"memory.example.test"),
                (b"content-type", b"application/json"),
                (b"content-length", b"2"),
                (b"authorization", b"Bearer opaque"),
                (b"origin", b"https://memory.example.test"),
            ]
        ),
        "client": client,
        "server": ("10.0.0.78", 8443),
    }


async def call(request_scope: Scope) -> tuple[Scope | None, list[Message]]:
    reached: Scope | None = None
    messages: list[Message] = []

    async def inner(inner_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal reached
        reached = inner_scope
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    app: ASGIApp = CodexPrivateIngressBoundaryMiddleware(inner, settings=settings())
    await app(request_scope, cast(Receive, receive), cast(Send, send))
    if reached is None and messages and messages[0]["type"] == "http.response.start":
        assert_safe_http_rejection(messages)
    return reached, messages


def assert_safe_http_rejection(messages: list[Message]) -> None:
    start = messages[0]
    assert start["type"] == "http.response.start"
    header_names = {name.lower() for name, _value in start.get("headers", [])}
    assert b"location" not in header_names
    assert b"server" not in header_names
    serialized = repr(messages).encode("ascii")
    for forbidden in (
        b"memory.example.test",
        b"10.0.0.10",
        b"10.0.0.78",
        b"127.0.0.1",
        b"8080",
        b"8443",
    ):
        assert forbidden not in serialized


def assert_safe_response(response: Response) -> None:
    assert "location" not in response.headers
    assert "server" not in response.headers
    serialized = repr((dict(response.headers), response.content)).encode("ascii")
    for forbidden in (
        b"memory.example.test",
        b"10.0.0.10",
        b"10.0.0.78",
        b"127.0.0.1",
        b"8080",
        b"8443",
    ):
        assert forbidden not in serialized


async def test_boundary_normalizes_valid_external_request_to_loopback_policy() -> None:
    reached, messages = await call(scope())

    assert reached is not None
    assert reached["scheme"] == "http"
    assert reached["client"] == ("127.0.0.1", 0)
    assert reached["server"] == ("127.0.0.1", 8080)
    assert (b"host", b"127.0.0.1:8080") in reached["headers"]
    assert not any(name.lower() == b"origin" for name, _value in reached["headers"])
    assert messages[0]["status"] == 204


async def test_boundary_passes_only_lifespan_among_non_http_scopes() -> None:
    reached: list[str] = []
    messages: list[Message] = []

    async def inner(inner_scope: Scope, _receive: Receive, _send: Send) -> None:
        reached.append(inner_scope["type"])

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        messages.append(message)

    middleware = CodexPrivateIngressBoundaryMiddleware(inner, settings=settings())
    lifespan_scope = cast(Scope, {"type": "lifespan", "asgi": {"version": "3.0"}})
    await middleware(lifespan_scope, cast(Receive, receive), cast(Send, send))
    assert reached == ["lifespan"]

    websocket_scope = cast(
        Scope,
        {
            "type": "websocket",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "scheme": "wss",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("10.0.0.10", 41234),
            "server": ("10.0.0.78", 8443),
            "subprotocols": [],
        },
    )
    await middleware(websocket_scope, cast(Receive, receive), cast(Send, send))
    assert reached == ["lifespan"]
    assert messages == [{"type": "websocket.close", "code": 1008}]

    unknown_scope = cast(Scope, {"type": "unknown", "asgi": {"version": "3.0"}})
    with pytest.raises(RuntimeError, match="unsupported_asgi_scope"):
        await middleware(unknown_scope, cast(Receive, receive), cast(Send, send))
    assert reached == ["lifespan"]


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_boundary_accepts_bodyless_mcp_methods(method: str) -> None:
    reached, messages = await call(
        scope(
            method=method,
            headers=[
                (b"host", b"memory.example.test"),
                (b"authorization", b"Bearer opaque"),
            ],
        )
    )

    assert reached is not None
    assert messages[0]["status"] == 204


@pytest.mark.parametrize(
    "request_scope",
    [
        scope(method="PATCH"),
        scope(path="/mcp/", raw_path=b"/mcp/"),
        scope(path="/chatgpt/mcp", raw_path=b"/chatgpt/mcp"),
        scope(query=b"x=1"),
        scope(scheme="http"),
    ],
)
async def test_boundary_rejects_non_exact_route_scheme_or_method(request_scope: Scope) -> None:
    reached, messages = await call(request_scope)

    assert reached is None
    assert messages[0]["status"] == 400


@pytest.mark.parametrize(
    "headers",
    [
        [(b"host", b"wrong.example"), (b"content-length", b"0")],
        [
            (b"host", b"memory.example.test"),
            (b"origin", b"https://wrong.example.test"),
            (b"content-length", b"0"),
        ],
        [
            (b"host", b"memory.example.test"),
            (b"host", b"memory.example.test"),
            (b"content-length", b"0"),
        ],
    ],
)
async def test_boundary_rejects_wrong_or_ambiguous_authority(
    headers: list[tuple[bytes, bytes]],
) -> None:
    reached, messages = await call(scope(headers=headers))

    assert reached is None
    assert messages[0]["status"] in {400, 403}


@pytest.mark.parametrize(
    "duplicated_header",
    [
        b"origin",
        b"authorization",
        b"content-length",
        b"transfer-encoding",
        b"mcp-protocol-version",
        b"mcp-session-id",
    ],
)
async def test_boundary_rejects_security_sensitive_duplicate_headers(
    duplicated_header: bytes,
) -> None:
    values = {
        b"origin": b"https://memory.example.test",
        b"authorization": b"Bearer synthetic",
        b"content-length": b"0",
        b"transfer-encoding": b"chunked",
        b"mcp-protocol-version": b"2025-06-18",
        b"mcp-session-id": b"synthetic-session",
    }
    headers = [(b"host", b"memory.example.test"), (b"content-length", b"0")]
    if duplicated_header == b"content-length":
        headers = [(b"host", b"memory.example.test")]
    headers.extend([(duplicated_header, values[duplicated_header])] * 2)

    reached, messages = await call(scope(headers=headers))

    assert reached is None
    assert messages[0]["status"] == 400


async def test_boundary_rejects_content_length_with_transfer_encoding() -> None:
    reached, messages = await call(
        scope(
            headers=[
                (b"host", b"memory.example.test"),
                (b"content-length", b"0"),
                (b"transfer-encoding", b"chunked"),
            ]
        )
    )

    assert reached is None
    assert messages[0]["status"] == 400


@pytest.mark.parametrize(
    "forwarding_header",
    [b"forwarded", b"via", b"x-real-ip", b"x-forwarded-for", b"x-forwarded-proto"],
)
async def test_boundary_rejects_every_forwarding_header(forwarding_header: bytes) -> None:
    reached, messages = await call(
        scope(
            headers=[
                (b"host", b"memory.example.test"),
                (b"content-length", b"0"),
                (forwarding_header, b"untrusted"),
            ]
        )
    )

    assert reached is None
    assert messages[0]["status"] == 400


async def test_boundary_rejects_peer_outside_exact_proxy_allowlist() -> None:
    reached, messages = await call(scope(client=("10.0.0.11", 41234)))

    assert reached is None
    assert messages[0]["status"] == 403


async def test_boundary_preserves_header_and_body_bounds() -> None:
    reached, messages = await call(
        scope(
            headers=[
                (b"host", b"memory.example.test"),
                (b"x-large", b"a" * MAX_MCP_HEADER_BYTES),
                (b"content-length", b"0"),
            ]
        )
    )
    assert reached is None
    assert messages[0]["status"] == 431

    reached, messages = await call(
        scope(
            headers=[
                (b"host", b"memory.example.test"),
                (b"content-length", str(MAX_MCP_REQUEST_BODY_BYTES + 1).encode()),
            ]
        )
    )
    assert reached is None
    assert messages[0]["status"] == 413


async def test_composed_ingress_authenticates_all_sdk_methods() -> None:
    app, authenticator, database = composed_app()
    transport = ASGITransport(app=app, client=("10.0.0.10", 41234))
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "synthetic-client", "version": "1"},
        },
    }
    authenticated = {
        "authorization": f"Bearer {_SYNTHETIC_BEARER}",
        "accept": "application/json, text/event-stream",
    }

    async with (
        app.router.lifespan_context(app),
        AsyncClient(
            transport=transport,
            base_url="https://memory.example.test",
        ) as client,
    ):
        initialized = await client.post("/mcp", json=initialize, headers=authenticated)
        authenticated_get = await client.get(
            "/mcp",
            headers={**authenticated, "accept": "application/json"},
        )
        authenticated_delete = await client.delete("/mcp", headers=authenticated)
        unauthenticated = {
            "POST": await client.post("/mcp", json=initialize),
            "GET": await client.get("/mcp", headers={"accept": "application/json"}),
            "DELETE": await client.delete("/mcp"),
        }

    assert initialized.status_code == 200
    assert initialized.json()["result"]["serverInfo"]["name"] == "ScaleVault Memory Node"
    assert authenticated_get.status_code == 406
    assert "must accept text/event-stream" in authenticated_get.text
    assert authenticated_delete.status_code == 405
    assert authenticated_delete.json() == {
        "jsonrpc": "2.0",
        "id": "server-error",
        "error": {
            "code": -32600,
            "message": "Method Not Allowed: Session termination not supported",
        },
    }
    assert_safe_response(authenticated_get)
    assert_safe_response(authenticated_delete)
    assert {method: response.status_code for method, response in unauthenticated.items()} == {
        "POST": 401,
        "GET": 401,
        "DELETE": 401,
    }
    for response in unauthenticated.values():
        assert_safe_response(response)
    assert len(authenticator.calls) == 6
    assert all(
        call.transport_kind is TransportKind.DIRECT_PRIVATE and call.installation_id is None
        for call in authenticator.calls
    )
    assert database.disposed is True


async def test_composed_ingress_rejects_streamed_body_larger_than_declared_limit() -> None:
    app, _authenticator, _database = composed_app()
    messages: list[Message] = []
    chunk_index = 0

    async def receive() -> Message:
        nonlocal chunk_index
        chunks = (b"a" * MAX_MCP_REQUEST_BODY_BYTES, b"overflow")
        if chunk_index < len(chunks):
            body = chunks[chunk_index]
            chunk_index += 1
            return {
                "type": "http.request",
                "body": body,
                "more_body": chunk_index < len(chunks),
            }
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        messages.append(message)

    request_scope = scope(
        headers=[
            (b"host", b"memory.example.test"),
            (b"authorization", f"Bearer {_SYNTHETIC_BEARER}".encode()),
            (b"accept", b"application/json, text/event-stream"),
            (b"content-type", b"application/json"),
            (b"content-length", b"1"),
        ]
    )
    async with app.router.lifespan_context(app):
        await app(request_scope, cast(Receive, receive), cast(Send, send))

    assert messages[0]["status"] == 413
    assert_safe_http_rejection(messages)


async def test_periodic_get_sends_cannot_extend_total_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codex_ingress, "CODEX_INGRESS_GET_TOTAL_DURATION_SECONDS", 0.02)
    messages: list[Message] = []
    cancelled = False

    async def streaming(_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal cancelled
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            }
        )
        try:
            while True:
                await send({"type": "http.response.body", "body": b": ping\n\n", "more_body": True})
                await asyncio.sleep(0.001)
        finally:
            cancelled = True

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    middleware = CodexPrivateIngressBoundaryMiddleware(streaming, settings=settings())
    await asyncio.wait_for(
        middleware(
            scope(
                method="GET",
                headers=[
                    (b"host", b"memory.example.test"),
                    (b"authorization", b"Bearer opaque"),
                ],
            ),
            cast(Receive, receive),
            cast(Send, send),
        ),
        timeout=0.2,
    )

    assert cancelled is True
    assert sum(message["type"] == "http.response.body" for message in messages) > 2
    assert messages[-1] == {"type": "http.response.body", "body": b"", "more_body": False}


async def test_stalled_commands_release_all_bounded_slots_with_payload_free_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(codex_ingress, "CODEX_INGRESS_COMMAND_TOTAL_DURATION_SECONDS", 0.01)

    async def stalled(_scope: Scope, _receive: Receive, _send: Send) -> None:
        await asyncio.Event().wait()

    async def one_request() -> list[Message]:
        messages: list[Message] = []

        async def receive() -> Message:
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(message: Message) -> None:
            messages.append(message)

        middleware = CodexPrivateIngressBoundaryMiddleware(stalled, settings=settings())
        await middleware(scope(), cast(Receive, receive), cast(Send, send))
        return messages

    results = await asyncio.wait_for(
        asyncio.gather(*(one_request() for _index in range(4))),
        timeout=0.2,
    )

    for messages in results:
        assert messages == [
            {
                "type": "http.response.start",
                "status": 504,
                "headers": [(b"content-length", b"0"), (b"cache-control", b"no-store")],
            },
            {"type": "http.response.body", "body": b""},
        ]
        assert_safe_http_rejection(messages)


@pytest.mark.parametrize("content_length", [None, b"00", b"-1", b"1.0"])
async def test_post_requires_one_canonical_content_length(
    content_length: bytes | None,
) -> None:
    headers = [(b"host", b"memory.example.test")]
    if content_length is not None:
        headers.append((b"content-length", content_length))

    reached, messages = await call(scope(headers=headers))

    assert reached is None
    assert messages[0]["status"] == 400


def test_main_runs_only_the_exact_bounded_tls_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_settings = Settings.model_construct(
        server_profile="codex_private_ingress",
        codex_ingress_host=ip_address("10.0.0.78"),
        codex_ingress_port=8443,
        codex_ingress_max_concurrency=4,
        codex_ingress_tls_certificate=Path(
            "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-cert"
        ),
        codex_ingress_tls_private_key=Path(
            "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-key"
        ),
        log_level="INFO",
    )
    runtime = object()
    application = object()
    captured: dict[str, object] = {}

    monkeypatch.setattr(codex_ingress, "get_settings", lambda: runtime_settings)
    monkeypatch.setattr(
        "kivra_memory.api.codex_ingress.SealedRuntime.from_settings",
        staticmethod(lambda _settings: object()),
    )
    monkeypatch.setattr(
        "kivra_memory.api.codex_ingress.MemoryNodeRuntime.from_settings",
        staticmethod(lambda _settings, *, sealed_runtime: runtime),
    )
    monkeypatch.setattr(
        codex_ingress,
        "create_codex_ingress_app",
        lambda _settings, _runtime: application,
    )

    def run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("kivra_memory.api.codex_ingress.uvicorn.run", run)

    codex_ingress.main()

    assert captured == {
        "app": application,
        "host": "10.0.0.78",
        "port": 8443,
        "log_level": "info",
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "server_header": False,
        "access_log": False,
        "limit_concurrency": 4,
        "timeout_keep_alive": 5,
        "ssl_certfile": ("/run/credentials/kivra-memory-codex-ingress.service/backend-tls-cert"),
        "ssl_keyfile": "/run/credentials/kivra-memory-codex-ingress.service/backend-tls-key",
    }


def test_canonical_entrypoint_rejects_codex_ingress_profile(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime_settings = Settings.model_construct(server_profile="codex_private_ingress")
    monkeypatch.setattr("kivra_memory.api.app.get_settings", lambda: runtime_settings)

    with pytest.raises(SystemExit) as caught:
        canonical_app.main()

    assert caught.value.code == 2
    assert capsys.readouterr().err == "ScaleVault configuration is invalid\n"
