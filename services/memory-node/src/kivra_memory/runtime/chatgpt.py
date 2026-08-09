"""Query-only authentication and execution for the ChatGPT secure tunnel."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from pydantic import ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from kivra_memory.application.authentication import (
    CredentialIdentity,
    CredentialRepository,
)
from kivra_memory.application.queries import QueryEngine
from kivra_memory.application.status import (
    IngressStatusQuery,
    StatusEngine,
    StatusResponse,
    TransportStatusQuery,
)
from kivra_memory.auth import (
    BearerAuthenticationError,
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
    RequestTransportIdentity,
)
from kivra_memory.config import Settings
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility, TransportKind
from kivra_memory.retrieval.contracts import (
    DirectReadQuery,
    QueryPrincipal,
    ReadError,
    ReadErrorBody,
    ReadQueryV2,
    ReadResponse,
    ReadResponseV2,
)
from kivra_memory.runtime.composition import MemoryNodeRuntime, _read_client_token_pepper
from kivra_memory.storage.credentials import CredentialRepository as StorageCredentialRepository

_SECURE_TUNNEL_DISCLOSURE_BOUNDARY = "openai_secure_tunnel"
_SECURE_TUNNEL_SCOPES = frozenset(
    {
        "memory.read.context",
        "memory.read.search",
        "memory.read.get",
        "memory.read.timeline",
        "memory.read.conflicts",
        "memory.read.lineage",
        "memory.read.selection_history",
        "memory.status.ingress",
        "memory.status.transport",
    }
)

type ChatGPTReadQuery = DirectReadQuery | ReadQueryV2 | IngressStatusQuery | TransportStatusQuery
type ChatGPTReadResponse = ReadResponse | ReadResponseV2 | StatusResponse

_query_principal_context: ContextVar[QueryPrincipal | None] = ContextVar(
    "chatgpt_secure_tunnel_query_principal",
    default=None,
)


class SecureTunnelQueryAuthenticator(Protocol):
    """Resolve one bearer header to query authority only."""

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> QueryPrincipal: ...


class SecureTunnelBearerAuthenticator:
    """Verify an installation-pinned secure-tunnel credential without write authority."""

    def __init__(
        self,
        repository: CredentialRepository,
        *,
        hashers: Mapping[str, BearerTokenHasher],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not hashers or any(
            not key or not isinstance(value, BearerTokenHasher) for key, value in hashers.items()
        ):
            raise ValueError("secure tunnel authenticator configuration is invalid")
        self._repository = repository
        self._hashers = dict(hashers)
        self._dummy_hasher = next(iter(self._hashers.values()))
        self._clock = clock or (lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return "SecureTunnelBearerAuthenticator(<redacted>)"

    async def authenticate(
        self,
        authorization_header: str | None,
        expected_transport: RequestTransportIdentity,
        /,
    ) -> QueryPrincipal:
        """Authenticate against current storage state or fail indistinguishably."""

        hmac_performed = False
        try:
            credential = BearerTokenCodec.parse_authorization(authorization_header)
            if (
                expected_transport.transport_kind is not TransportKind.SECURE_TUNNEL
                or expected_transport.installation_id is None
            ):
                self._dummy_hasher.verify(credential, "")
                hmac_performed = True
                raise BearerAuthenticationError
            lookup = await self._repository.lookup(
                credential.tenant_id,
                credential.credential_id,
            )
            if lookup is None:
                self._dummy_hasher.verify(credential, "")
                hmac_performed = True
                raise BearerAuthenticationError
            if (
                lookup.tenant_id != credential.tenant_id
                or lookup.credential_id != credential.credential_id
            ):
                self._dummy_hasher.verify(credential, lookup.secret_verifier)
                hmac_performed = True
                raise BearerAuthenticationError
            hasher = self._hashers.get(lookup.hash_key_id)
            if hasher is None:
                self._dummy_hasher.verify(credential, lookup.secret_verifier)
                hmac_performed = True
                raise BearerAuthenticationError
            verified = hasher.verify(credential, lookup.secret_verifier)
            hmac_performed = True
            if not verified:
                raise BearerAuthenticationError
            used_at = self._clock()
            if used_at.tzinfo is None or used_at.utcoffset() is None:
                raise BearerAuthenticationError
            identity = await self._repository.record_successful_use(
                lookup,
                transport_kind=expected_transport.transport_kind,
                installation_id=expected_transport.installation_id,
                used_at=used_at.astimezone(UTC),
            )
            if identity is None:
                raise BearerAuthenticationError
            if (
                identity.tenant_id != lookup.tenant_id
                or identity.credential_id != lookup.credential_id
            ):
                raise BearerAuthenticationError
            return _query_principal(identity, expected_transport)
        except BearerAuthenticationError:
            if not hmac_performed:
                self._perform_dummy_verification()
            raise
        except Exception:
            if not hmac_performed:
                self._perform_dummy_verification()
            raise BearerAuthenticationError from None

    def _perform_dummy_verification(self) -> None:
        dummy = BearerTokenCodec.parse_authorization(
            "Bearer svb1.00000000-0000-7000-8000-000000000000."
            "00000000-0000-7000-8000-000000000001.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        self._dummy_hasher.verify(dummy, "")


def _query_principal(
    identity: CredentialIdentity,
    expected_transport: RequestTransportIdentity,
) -> QueryPrincipal:
    if (
        identity.transport_kind != TransportKind.SECURE_TUNNEL.value
        or identity.disclosure_boundary != _SECURE_TUNNEL_DISCLOSURE_BOUNDARY
        or identity.installation_id is None
        or identity.installation_id != expected_transport.installation_id
        or expected_transport.transport_kind is not TransportKind.SECURE_TUNNEL
        or identity.authorized_operations != ()
    ):
        raise BearerAuthenticationError
    scopes = _validated_scopes(identity.client_scopes)
    profile = _validated_capability_profile(identity.capability_profile)
    if profile.read is None:
        raise BearerAuthenticationError
    read = profile.read
    try:
        return QueryPrincipal(
            tenant_id=identity.tenant_id,
            actor_id=identity.actor_id,
            client_id=identity.client_id,
            transport_binding_id=identity.transport_binding_id,
            scopes=scopes,
            allowed_memory_scopes=frozenset(read.allowed_memory_scopes),
            allowed_visibilities=frozenset(read.allowed_visibilities),
            max_sensitivity=read.max_sensitivity,
            allow_candidates=read.allow_candidates,
            ingress_id=None,
        )
    except ValidationError:
        raise BearerAuthenticationError from None


def _validated_scopes(values: tuple[str, ...]) -> frozenset[str]:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > len(_SECURE_TUNNEL_SCOPES)
        or len(values) != len(set(values))
        or any(not isinstance(value, str) for value in values)
        or not set(values) <= _SECURE_TUNNEL_SCOPES
    ):
        raise BearerAuthenticationError
    return frozenset(values)


def _validated_capability_profile(value: Mapping[str, object]) -> ClientCapabilityProfile:
    if not isinstance(value, dict):
        raise BearerAuthenticationError
    document = dict(value)
    read = document.get("read")
    if not isinstance(read, dict):
        raise BearerAuthenticationError
    read_document = dict(read)
    for field_name, enum_type in (
        ("allowed_memory_scopes", MemoryScope),
        ("allowed_visibilities", MemoryVisibility),
    ):
        raw_values = read_document.get(field_name)
        if (
            not isinstance(raw_values, list)
            or not raw_values
            or len(raw_values) != len(set(raw_values))
            or any(not isinstance(item, str) for item in raw_values)
        ):
            raise BearerAuthenticationError
        try:
            read_document[field_name] = frozenset(enum_type(item) for item in raw_values)
        except ValueError:
            raise BearerAuthenticationError from None
    document["read"] = read_document
    try:
        return ClientCapabilityProfile.model_validate(document)
    except ValidationError:
        raise BearerAuthenticationError from None


@contextmanager
def secure_tunnel_query_context(principal: QueryPrincipal) -> Iterator[None]:
    """Install one query principal for the current asynchronous request only."""

    if not isinstance(principal, QueryPrincipal):
        raise TypeError("query principal is required")
    token = _query_principal_context.set(principal)
    try:
        yield
    finally:
        _query_principal_context.reset(token)


def current_secure_tunnel_query() -> QueryPrincipal | None:
    """Return the task-local secure-tunnel query principal, if authenticated."""

    return _query_principal_context.get()


async def current_secure_tunnel_query_principal(context: object) -> QueryPrincipal | ReadError:
    """Resolve MCP read authority only from the secure-tunnel request context."""

    del context
    principal = current_secure_tunnel_query()
    if principal is None:
        return ReadError(
            error=ReadErrorBody(
                code="unauthenticated",
                message=ReadErrorBody.SAFE_MESSAGES["unauthenticated"],
            )
        )
    return principal


class SecureTunnelReadAuthenticationMiddleware:
    """Authenticate one secure-tunnel bearer and expose query authority only."""

    def __init__(
        self,
        app: ASGIApp,
        authenticator: SecureTunnelQueryAuthenticator,
        installation_id: UUID,
    ) -> None:
        self._app = app
        self._authenticator = authenticator
        self._expected_transport = RequestTransportIdentity(
            transport_kind=TransportKind.SECURE_TUNNEL,
            installation_id=installation_id,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        authorization = _authorization_header(scope)
        try:
            principal = await self._authenticator.authenticate(
                authorization,
                self._expected_transport,
            )
            if not isinstance(principal, QueryPrincipal):
                raise BearerAuthenticationError
        except Exception:
            await _reject_unauthenticated(send)
            return
        with secure_tunnel_query_context(principal):
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


@dataclass(frozen=True, slots=True)
class ChatGPTReadRuntime:
    """Request-authenticated query-only composition sharing the canonical engines."""

    authenticator: SecureTunnelQueryAuthenticator
    installation_id: UUID
    queries: QueryEngine
    status: StatusEngine

    @classmethod
    def from_memory_runtime(
        cls,
        settings: Settings,
        runtime: MemoryNodeRuntime,
    ) -> ChatGPTReadRuntime:
        credential = settings.client_token_pepper_credential
        key_id = settings.client_token_pepper_key_id
        installation_id = settings.chatgpt_secure_tunnel_installation_id
        if (
            not settings.chatgpt_secure_tunnel_enabled
            or credential is None
            or key_id is None
            or installation_id is None
        ):
            raise RuntimeError("invalid_chatgpt_runtime_configuration")
        try:
            pepper = _read_client_token_pepper(
                credential,
                required_owner_uid=os.geteuid() if settings.environment == "production" else None,
            )
            authenticator = SecureTunnelBearerAuthenticator(
                StorageCredentialRepository(runtime.database.session_factory),
                hashers={key_id: BearerTokenHasher(pepper)},
            )
        except Exception:
            raise RuntimeError("invalid_chatgpt_runtime_configuration") from None
        return cls(
            authenticator=authenticator,
            installation_id=installation_id,
            queries=runtime.queries,
            status=runtime.status,
        )

    async def execute_read(
        self,
        principal: QueryPrincipal,
        query: ChatGPTReadQuery,
    ) -> ChatGPTReadResponse:
        if isinstance(query, IngressStatusQuery):
            return await self.status.ingress_status(principal, query)
        if isinstance(query, TransportStatusQuery):
            return await self.status.transport_status(principal, query)
        return await self.queries.execute(principal, query)

    def authenticate_mcp(self, application: ASGIApp) -> ASGIApp:
        return SecureTunnelReadAuthenticationMiddleware(
            application,
            self.authenticator,
            self.installation_id,
        )


__all__ = [
    "ChatGPTReadQuery",
    "ChatGPTReadResponse",
    "ChatGPTReadRuntime",
    "SecureTunnelBearerAuthenticator",
    "SecureTunnelQueryAuthenticator",
    "SecureTunnelReadAuthenticationMiddleware",
    "current_secure_tunnel_query",
    "current_secure_tunnel_query_principal",
    "secure_tunnel_query_context",
]
