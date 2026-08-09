from __future__ import annotations

import asyncio

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.auth import (
    AuthenticatedRequestIdentity,
    RequestTransportIdentity,
    StatusIdentity,
    authenticated_request_context,
    current_authenticated_request,
)
from kivra_memory.domain.enums import TransportKind
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal


def _identity() -> AuthenticatedRequestIdentity:
    tenant_id, actor_id, client_id, binding_id, credential_id = (new_uuid7() for _ in range(5))
    command = CommandPrincipal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        scopes=frozenset({"memory.write.nominate"}),
    )
    query = QueryPrincipal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        scopes=frozenset({"memory.read.context"}),
        allowed_memory_scopes=frozenset(),
        allowed_visibilities=frozenset(),
        max_sensitivity=0,
    )
    status = StatusIdentity(
        tenant_id=tenant_id,
        actor_id=actor_id,
        client_id=client_id,
        credential_id=credential_id,
        transport_binding_id=binding_id,
        transport_kind=TransportKind.DIRECT_PRIVATE,
        disclosure_boundary="private_node",
    )
    return AuthenticatedRequestIdentity(
        command_principal=command,
        query_principal=query,
        status_identity=status,
    )


def test_context_is_absent_by_default_and_resets_after_failure() -> None:
    identity = _identity()
    assert current_authenticated_request() is None

    try:
        with authenticated_request_context(identity) as installed:
            assert installed is identity
            assert current_authenticated_request() is identity
            raise RuntimeError("synthetic")
    except RuntimeError:
        pass

    assert current_authenticated_request() is None


async def test_context_is_isolated_between_concurrent_tasks() -> None:
    first = _identity()
    second = _identity()
    ready = asyncio.Event()

    async def observe(identity: AuthenticatedRequestIdentity) -> AuthenticatedRequestIdentity:
        with authenticated_request_context(identity):
            ready.set()
            await asyncio.sleep(0)
            assert current_authenticated_request() is identity
            return identity

    results = await asyncio.gather(observe(first), observe(second))

    assert tuple(results) == (first, second)
    assert current_authenticated_request() is None


def test_request_transport_identity_is_not_implicitly_installed() -> None:
    RequestTransportIdentity(transport_kind=TransportKind.DIRECT_PRIVATE)
    assert current_authenticated_request() is None
