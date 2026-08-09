from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from kivra_memory.api.app import create_app
from kivra_memory.application.authentication import (
    BearerAuthenticator,
    CredentialIdentity,
    CredentialLookup,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import NominationCommandLike, SelectionResult
from kivra_memory.auth import (
    BearerTokenCodec,
    BearerTokenHasher,
    current_authenticated_request,
)
from kivra_memory.config import Settings
from kivra_memory.domain.commands import (
    DirectMutationCommand,
    MutationResponse,
    MutationResult,
    RetireCommand,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import (
    QueryPrincipal,
    ReadError,
    ReadErrorBody,
)
from kivra_memory.runtime.authentication import DirectBearerAuthenticationMiddleware
from kivra_memory.runtime.composition import MemoryNodeRuntime, RuntimeReadQuery
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.types import Message, Receive, Scope, Send


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


class InMemoryCredentials:
    def __init__(self) -> None:
        self.lookups: dict[tuple[UUID, UUID], CredentialLookup] = {}
        self.identities: dict[tuple[UUID, UUID], CredentialIdentity | None] = {}
        self.successful_uses = 0

    async def lookup(self, tenant_id: UUID, credential_id: UUID) -> CredentialLookup | None:
        return self.lookups.get((tenant_id, credential_id))

    async def record_successful_use(
        self,
        lookup: CredentialLookup,
        /,
        **_kwargs: object,
    ) -> CredentialIdentity | None:
        self.successful_uses += 1
        return self.identities.get((lookup.tenant_id, lookup.credential_id))


def add_credential(
    repository: InMemoryCredentials,
    hasher: BearerTokenHasher,
    ordinal: int,
    *,
    active: bool = True,
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
        transport_kind="direct_private",
        disclosure_boundary="private_node",
        installation_id=None,
        client_scopes=(
            "memory.read.lineage",
            "memory.write.nominate",
            "memory.write.retire",
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
        authorized_operations=("observed", "remembered", "retired"),
    )
    repository.lookups[(tenant_id, credential_id)] = lookup
    repository.identities[(tenant_id, credential_id)] = identity if active else None
    return issued.token, identity


def authenticator_fixture() -> tuple[BearerAuthenticator, InMemoryCredentials, str, str]:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    active_token, _ = add_credential(repository, hasher, 10)
    revoked_token, _ = add_credential(repository, hasher, 20, active=False)
    return (
        BearerAuthenticator(repository, hashers={"codex-primary-v1": hasher}),
        repository,
        active_token,
        revoked_token,
    )


async def call_asgi(
    application: DirectBearerAuthenticationMiddleware,
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
async def test_authentication_failures_are_identical_and_never_reach_mcp(
    headers_factory: Any,
) -> None:
    authenticator, _, active_token, revoked_token = authenticator_fixture()
    reached = False

    async def inner(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal reached
        reached = True

    middleware = DirectBearerAuthenticationMiddleware(inner, authenticator)
    messages = await call_asgi(middleware, headers_factory(active_token, revoked_token))

    assert not reached
    assert messages[0]["status"] == 401
    assert messages[1]["body"] == b'{"error":"authentication_required"}'
    assert current_authenticated_request() is None


async def test_authenticated_context_is_installed_only_around_request() -> None:
    authenticator, _, active_token, _ = authenticator_fixture()
    seen: list[UUID] = []

    async def inner(_scope: Scope, _receive: Receive, send: Send) -> None:
        identity = current_authenticated_request()
        assert identity is not None
        seen.append(identity.command_principal.tenant_id)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = DirectBearerAuthenticationMiddleware(inner, authenticator)
    messages = await call_asgi(
        middleware,
        [(b"authorization", f"Bearer {active_token}".encode())],
    )

    assert messages[0]["status"] == 204
    assert seen == [uid(10)]
    assert current_authenticated_request() is None


async def test_concurrent_tokens_keep_distinct_task_local_identity() -> None:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    first_token, first = add_credential(repository, hasher, 30)
    second_token, second = add_credential(repository, hasher, 40)
    authenticator = BearerAuthenticator(repository, hashers={"codex-primary-v1": hasher})
    both_entered = asyncio.Event()
    entrants = 0
    seen: list[tuple[UUID, UUID]] = []

    async def inner(_scope: Scope, _receive: Receive, send: Send) -> None:
        nonlocal entrants
        before = current_authenticated_request()
        assert before is not None
        entrants += 1
        if entrants == 2:
            both_entered.set()
        await both_entered.wait()
        await asyncio.sleep(0)
        after = current_authenticated_request()
        assert after is not None
        seen.append((before.command_principal.tenant_id, after.command_principal.tenant_id))
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = DirectBearerAuthenticationMiddleware(inner, authenticator)
    await asyncio.gather(
        call_asgi(middleware, [(b"authorization", f"Bearer {first_token}".encode())]),
        call_asgi(middleware, [(b"authorization", f"Bearer {second_token}".encode())]),
    )

    assert set(seen) == {
        (first.tenant_id, first.tenant_id),
        (second.tenant_id, second.tenant_id),
    }
    assert current_authenticated_request() is None


class RecordingMutations:
    def __init__(self) -> None:
        self.calls: list[tuple[CommandPrincipal, DirectMutationCommand]] = []

    async def execute(
        self,
        principal: CommandPrincipal,
        command: DirectMutationCommand,
    ) -> MutationResponse:
        assert isinstance(command, RetireCommand)
        self.calls.append((principal, command))
        return MutationResult(
            contract_version="mcp-mutation-v1",
            operation="retire",
            receipt_id=uid(80),
            event_id=uid(81),
            memory_id=command.memory_id,
            revision=command.expected_revision + 1,
        )


class RecordingNominations:
    def __init__(self) -> None:
        self.calls: list[tuple[CommandPrincipal, NominationCommandLike]] = []

    async def execute(
        self,
        principal: CommandPrincipal,
        command: NominationCommandLike,
    ) -> SelectionResult:
        self.calls.append((principal, command))
        return SelectionResult(
            receipt_id=uid(82),
            decision_id=uid(83),
            outcome="omit",
            policy_sha256="a" * 64,
            reason_codes=("routine_banter",),
            matched_rule_ids=("basis.routine_banter",),
            event_id=None,
            memory_id=None,
            revision=None,
        )


class RecordingQueries:
    def __init__(self) -> None:
        self.calls: list[tuple[QueryPrincipal, RuntimeReadQuery]] = []

    async def execute(
        self,
        principal: QueryPrincipal,
        query: RuntimeReadQuery,
    ) -> ReadError:
        self.calls.append((principal, query))
        return ReadError(
            error=ReadErrorBody(
                code="not_found",
                message=ReadErrorBody.SAFE_MESSAGES["not_found"],
            )
        )


class DisposableDatabase:
    def __init__(self) -> None:
        self.disposed = False

    async def dispose(self) -> None:
        self.disposed = True


@asynccontextmanager
async def mcp_session(app: FastAPI, token: str) -> AsyncIterator[ClientSession]:
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8080",
            headers={"Authorization": f"Bearer {token}"},
        ) as client,
        streamable_http_client("http://127.0.0.1:8080/mcp", http_client=client) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        yield session


async def test_authenticated_initialize_and_mutation_reach_request_scoped_engine() -> None:
    repository = InMemoryCredentials()
    hasher = BearerTokenHasher(b"p" * 32)
    first_token, first_identity = add_credential(repository, hasher, 50)
    second_token, second_identity = add_credential(repository, hasher, 60)
    authenticator = BearerAuthenticator(
        repository,
        hashers={"codex-primary-v1": hasher},
    )
    mutations = RecordingMutations()
    nominations = RecordingNominations()
    queries = RecordingQueries()
    database = DisposableDatabase()
    runtime = MemoryNodeRuntime(
        database=cast(Any, database),
        authenticator=authenticator,
        mutations=cast(Any, mutations),
        nominations=cast(Any, nominations),
        queries=cast(Any, queries),
        status=cast(Any, object()),
    )
    app = create_app(Settings(environment="test"), runtime=runtime)
    arguments = {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": "runtime-auth:retire",
        "persona_id": str(uid(70)),
        "branch_id": str(uid(71)),
        "reason": "Exercise authenticated production composition.",
        "memory_id": str(uid(72)),
        "expected_revision": 1,
    }

    nomination = {
        "contract_version": "mcp-mutation-v2",
        "idempotency_key": "runtime-auth:nominate",
        "persona_id": str(uid(70)),
        "branch_id": str(uid(71)),
        "reason": "Exercise authenticated nomination composition.",
        "proposal": {
            "subject_id": str(uid(73)),
            "subject_kind": "relationship",
            "category": "relationship_pattern",
            "ontological_status": "observed_assistant_behavior",
            "scope": "relationship",
            "visibility": "private_root",
            "statement": "A bounded synthetic observation.",
            "reason_to_remember": "Verify request authority routing.",
            "interpretation_limits": ["Synthetic fixture only."],
            "confidence": 0.7,
            "salience": 0.6,
            "durability": 0.5,
            "sensitivity": 0,
            "metadata": {},
            "selection_basis": "routine_banter",
            "epistemic_qualifiers": [],
            "evidence_references": [],
        },
    }
    read = {
        "contract_version": "mcp-read-v1",
        "persona_id": str(uid(70)),
        "branch_id": str(uid(71)),
    }

    async with app.router.lifespan_context(app):
        for token in (first_token, second_token):
            async with mcp_session(app, token) as session:
                initialized = await session.initialize()
                mutation_result = await session.call_tool("memory_retire", arguments)
                nomination_result = await session.call_tool("memory_nominate", nomination)
                read_result = await session.call_tool("memory_lineage", read)

            assert initialized.serverInfo.name == "ScaleVault Memory Node"
            assert mutation_result.structuredContent is not None
            assert mutation_result.structuredContent["ok"] is True
            assert nomination_result.structuredContent is not None
            assert nomination_result.structuredContent["ok"] is True
            assert read_result.structuredContent is not None
            assert read_result.structuredContent["error"]["code"] == "not_found"

    expected = [
        (first_identity.tenant_id, first_identity.client_id, first_identity.transport_binding_id),
        (
            second_identity.tenant_id,
            second_identity.client_id,
            second_identity.transport_binding_id,
        ),
    ]
    assert [
        (call[0].tenant_id, call[0].client_id, call[0].transport_binding_id)
        for call in mutations.calls
    ] == expected
    assert [
        (call[0].tenant_id, call[0].client_id, call[0].transport_binding_id)
        for call in nominations.calls
    ] == expected
    assert [
        (call[0].tenant_id, call[0].client_id, call[0].transport_binding_id)
        for call in queries.calls
    ] == expected
    assert database.disposed
