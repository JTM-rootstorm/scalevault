from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.application.authentication import CredentialIdentity, CredentialLookup
from kivra_memory.auth import BearerTokenCodec, BearerTokenHasher
from kivra_memory.domain.enums import TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal
from kivra_memory.runtime.chatgpt import (
    SecureTunnelBearerAuthenticator,
    SecureTunnelReadAuthenticationMiddleware,
    current_secure_tunnel_query,
)
from starlette.types import Message, Receive, Scope, Send


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


INSTALLATION_ID = uid(1)


class InMemoryCredentials:
    def __init__(self) -> None:
        self.lookups: dict[tuple[UUID, UUID], CredentialLookup] = {}
        self.identities: dict[tuple[UUID, UUID], CredentialIdentity | None] = {}
        self.successful_uses: list[dict[str, object]] = []

    async def lookup(self, tenant_id: UUID, credential_id: UUID) -> CredentialLookup | None:
        return self.lookups.get((tenant_id, credential_id))

    async def record_successful_use(
        self,
        lookup: CredentialLookup,
        /,
        **kwargs: object,
    ) -> CredentialIdentity | None:
        self.successful_uses.append(dict(kwargs))
        return self.identities.get((lookup.tenant_id, lookup.credential_id))


def add_credential(
    repository: InMemoryCredentials,
    hasher: BearerTokenHasher,
    ordinal: int,
    *,
    active: bool = True,
    identity_changes: dict[str, object] | None = None,
) -> tuple[str, CredentialIdentity]:
    tenant_id = uid(ordinal)
    credential_id = uid(ordinal + 1)
    issued = BearerTokenCodec.issue(
        tenant_id,
        credential_id,
        hasher,
        random_bytes=lambda size: bytes([ordinal % 251 + 1]) * size,
    )
    lookup = CredentialLookup(
        tenant_id=tenant_id,
        credential_id=credential_id,
        hash_key_id="codex-primary-v1",
        secret_verifier=issued.secret_hash,
    )
    identity = CredentialIdentity(
        tenant_id=tenant_id,
        actor_id=uid(ordinal + 2),
        client_id=uid(ordinal + 3),
        credential_id=credential_id,
        transport_binding_id=uid(ordinal + 4),
        transport_kind="secure_tunnel",
        disclosure_boundary="openai_secure_tunnel",
        installation_id=INSTALLATION_ID,
        client_scopes=(
            "memory.read.lineage",
            "memory.status.ingress",
            "memory.status.transport",
        ),
        capability_profile={
            "contract_version": "scalevault-client-capability-v1",
            "read": {
                "allowed_memory_scopes": ["persona", "relationship"],
                "allowed_visibilities": ["private_root", "restricted"],
                "max_sensitivity": 3,
                "allow_candidates": False,
            },
        },
        authorized_operations=(),
    )
    if identity_changes:
        identity = replace(identity, **cast(Any, identity_changes))
    repository.lookups[(tenant_id, credential_id)] = lookup
    repository.identities[(tenant_id, credential_id)] = identity if active else None
    return issued.token, identity


def authenticator_fixture() -> tuple[
    SecureTunnelBearerAuthenticator,
    InMemoryCredentials,
    str,
    str,
]:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    active_token, _ = add_credential(repository, hasher, 10)
    revoked_token, _ = add_credential(repository, hasher, 20, active=False)
    return (
        SecureTunnelBearerAuthenticator(repository, hashers={"codex-primary-v1": hasher}),
        repository,
        active_token,
        revoked_token,
    )


async def call_asgi(
    application: SecureTunnelReadAuthenticationMiddleware,
    headers: list[tuple[bytes, bytes]],
) -> list[Message]:
    messages: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8080),
    }
    await application(scope, cast(Receive, receive), cast(Send, send))
    return messages


@pytest.mark.parametrize(
    "headers_factory",
    [
        lambda _active, _revoked: [],
        lambda active, _revoked: [
            (b"authorization", f"Bearer {active}".encode()),
            (b"authorization", f"Bearer {active}".encode()),
        ],
        lambda _active, _revoked: [(b"authorization", b"Bearer \xff")],
        lambda _active, _revoked: [(b"authorization", b"Basic invalid")],
        lambda _active, _revoked: [(b"authorization", b"Bearer " + b"a" * 300)],
        lambda active, _revoked: [(b"authorization", f"Bearer {active[:-1]}A".encode())],
        lambda _active, revoked: [(b"authorization", f"Bearer {revoked}".encode())],
    ],
)
async def test_secure_tunnel_authentication_failures_are_identical(
    headers_factory: Any,
) -> None:
    authenticator, _, active_token, revoked_token = authenticator_fixture()
    reached = False

    async def inner(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal reached
        reached = True

    middleware = SecureTunnelReadAuthenticationMiddleware(
        inner,
        authenticator,
        INSTALLATION_ID,
    )
    messages = await call_asgi(middleware, headers_factory(active_token, revoked_token))

    assert not reached
    assert messages[0]["status"] == 401
    assert messages[1]["body"] == b'{"error":"authentication_required"}'
    assert current_secure_tunnel_query() is None


async def test_secure_tunnel_context_exposes_only_query_principal_and_is_cleared() -> None:
    authenticator, repository, active_token, _ = authenticator_fixture()
    seen: list[QueryPrincipal] = []

    async def inner(_scope: Scope, _receive: Receive, send: Send) -> None:
        principal = current_secure_tunnel_query()
        assert principal is not None
        seen.append(principal)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = SecureTunnelReadAuthenticationMiddleware(
        inner,
        authenticator,
        INSTALLATION_ID,
    )
    messages = await call_asgi(
        middleware,
        [(b"authorization", f"Bearer {active_token}".encode())],
    )

    assert messages[0]["status"] == 204
    assert seen[0].tenant_id == uid(10)
    assert seen[0].scopes == frozenset(
        {"memory.read.lineage", "memory.status.ingress", "memory.status.transport"}
    )
    assert not hasattr(seen[0], "command_principal")
    assert repository.successful_uses[0]["transport_kind"] is TransportKind.SECURE_TUNNEL
    assert repository.successful_uses[0]["installation_id"] == INSTALLATION_ID
    assert current_secure_tunnel_query() is None


async def test_concurrent_secure_tunnel_tokens_do_not_leak_principals() -> None:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    first_token, first = add_credential(repository, hasher, 30)
    second_token, second = add_credential(repository, hasher, 40)
    authenticator = SecureTunnelBearerAuthenticator(
        repository,
        hashers={"codex-primary-v1": hasher},
    )
    both_entered = asyncio.Event()
    entrants = 0
    seen: list[tuple[UUID, UUID]] = []

    async def inner(_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal entrants
        before = current_secure_tunnel_query()
        assert before is not None
        entrants += 1
        if entrants == 2:
            both_entered.set()
        await both_entered.wait()
        await asyncio.sleep(0)
        after = current_secure_tunnel_query()
        assert after is not None
        seen.append((before.tenant_id, after.tenant_id))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = SecureTunnelReadAuthenticationMiddleware(
        inner,
        authenticator,
        INSTALLATION_ID,
    )
    await asyncio.gather(
        call_asgi(middleware, [(b"authorization", f"Bearer {first_token}".encode())]),
        call_asgi(middleware, [(b"authorization", f"Bearer {second_token}".encode())]),
    )

    assert set(seen) == {
        (first.tenant_id, first.tenant_id),
        (second.tenant_id, second.tenant_id),
    }
    assert current_secure_tunnel_query() is None


@pytest.mark.parametrize(
    "identity_changes",
    [
        {"transport_kind": "direct_private", "disclosure_boundary": "private_node"},
        {"installation_id": uid(999)},
        {"authorized_operations": ("observed",)},
        {"client_scopes": ("memory.write.nominate",)},
        {"client_scopes": ("memory.read.lineage", "memory.read.lineage")},
        {"capability_profile": {"contract_version": "scalevault-client-capability-v1"}},
        {
            "capability_profile": {
                "contract_version": "scalevault-client-capability-v1",
                "read": {
                    "allowed_memory_scopes": ["persona", "persona"],
                    "allowed_visibilities": ["private_root"],
                    "max_sensitivity": 2,
                    "allow_candidates": False,
                },
            }
        },
    ],
)
async def test_secure_tunnel_identity_boundary_fails_closed(
    identity_changes: dict[str, object],
) -> None:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    token, _ = add_credential(
        repository,
        hasher,
        70,
        identity_changes=identity_changes,
    )
    authenticator = SecureTunnelBearerAuthenticator(
        repository,
        hashers={"codex-primary-v1": hasher},
    )

    async def inner(_scope: Scope, _receive: Receive, _send: Send) -> None:
        pytest.fail("invalid secure-tunnel identity reached the MCP application")

    middleware = SecureTunnelReadAuthenticationMiddleware(
        inner,
        authenticator,
        INSTALLATION_ID,
    )
    messages = await call_asgi(
        middleware,
        [(b"authorization", f"Bearer {token}".encode())],
    )

    assert messages[0]["status"] == 401
    assert messages[1]["body"] == b'{"error":"authentication_required"}'
