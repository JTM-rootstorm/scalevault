"""Strict direct-private ASGI authentication and principal accessors."""

from __future__ import annotations

from typing import Protocol

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.auth import (
    AuthenticatedRequestIdentity,
    BearerAuthenticationError,
    RequestTransportIdentity,
    authenticated_request_context,
    current_authenticated_request,
)
from kivra_memory.domain.commands import MutationError, MutationErrorBody
from kivra_memory.domain.enums import TransportKind
from kivra_memory.retrieval.contracts import QueryPrincipal, ReadError, ReadErrorBody

_DIRECT_PRIVATE = RequestTransportIdentity(
    transport_kind=TransportKind.DIRECT_PRIVATE,
    installation_id=None,
)


class RequestBearerAuthenticator(Protocol):
    """Authenticate one exact Authorization header against current storage state."""

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> AuthenticatedRequestIdentity: ...


class DirectBearerAuthenticationMiddleware:
    """Authenticate each mounted MCP HTTP request and clear identity afterward."""

    def __init__(self, app: ASGIApp, authenticator: RequestBearerAuthenticator) -> None:
        self._app = app
        self._authenticator = authenticator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        authorization = _authorization_header(scope)
        try:
            identity = await self._authenticator.authenticate(authorization, _DIRECT_PRIVATE)
            if not isinstance(identity, AuthenticatedRequestIdentity):
                raise BearerAuthenticationError
        except Exception:
            await _reject_unauthenticated(send)
            return
        with authenticated_request_context(identity):
            await self._app(scope, receive, send)


def _authorization_header(scope: Scope) -> str | None:
    values = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
    if len(values) != 1:
        return None
    value = values[0]
    if not isinstance(value, bytes):
        return None
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


async def _reject_unauthenticated(send: Send) -> None:
    body = b'{"error":"authentication_required"}'
    start: Message = {
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"www-authenticate", b"Bearer"),
        ],
    }
    await send(start)
    await send({"type": "http.response.body", "body": body})


async def current_command_principal(context: object) -> CommandPrincipal | MutationError:
    """Select command authority from the current authenticated request only."""

    del context
    identity = current_authenticated_request()
    if identity is None:
        return MutationError(
            contract_version="mcp-mutation-v1",
            error=MutationErrorBody(
                code="unauthenticated",
                message=MutationErrorBody.SAFE_MESSAGES["unauthenticated"],
            ),
        )
    return identity.command_principal


async def current_query_principal(context: object) -> QueryPrincipal | ReadError:
    """Select query authority from the current authenticated request only."""

    del context
    identity = current_authenticated_request()
    if identity is None:
        return ReadError(
            error=ReadErrorBody(
                code="unauthenticated",
                message=ReadErrorBody.SAFE_MESSAGES["unauthenticated"],
            )
        )
    return identity.query_principal


__all__ = [
    "DirectBearerAuthenticationMiddleware",
    "RequestBearerAuthenticator",
    "current_command_principal",
    "current_query_principal",
]
