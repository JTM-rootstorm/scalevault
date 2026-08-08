from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID

from kivra_memory.application.status import (
    IngressStatusQuery,
    IngressStatusResult,
    StatusEngine,
    StatusError,
    TransportStatusQuery,
    TransportStatusResult,
)
from kivra_memory.domain.enums import MemoryScope, MemoryVisibility
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import QueryPrincipal
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import CommandReceipt, IngressItem, MemoryEvent, OutboxJob
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 8, 19, tzinfo=UTC)


class PostgreSQLTestServer(Protocol):
    database_url: str


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _principal(
    index: int,
    *,
    scopes: frozenset[str],
    ingress_id: UUID | None = None,
) -> QueryPrincipal:
    binding = seed_rows()["transport_bindings"][index]
    return QueryPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=scopes,
        allowed_memory_scopes=frozenset(MemoryScope),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        max_sensitivity=4,
        ingress_id=ingress_id,
    )


@asynccontextmanager
async def _seeded_status_engine(
    database_url: str,
    ingress_id: UUID,
) -> AsyncIterator[tuple[Database, StatusEngine]]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_seed_identifier("tenants", "tenant_id")) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            github = seed_rows()["transport_bindings"][2]
            ingress = IngressItem(
                ingress_id=ingress_id,
                tenant_id=_seed_identifier("tenants", "tenant_id"),
                transport_binding_id=cast(UUID, github["transport_binding_id"]),
                installation_id=cast(UUID, github["installation_id"]),
                actor_id=cast(UUID, github["actor_id"]),
                client_id=cast(UUID, github["client_id"]),
                provider="github",
                repository_external_id="PRIVATE_REPOSITORY_CANARY",
                branch_name="PRIVATE_BRANCH_CANARY",
                immutable_path="PRIVATE_PATH_CANARY/proposal.json",
                external_object_id="synthetic-status-object",
                commit_id="PRIVATE_COMMIT_CANARY",
                blob_id="PRIVATE_BLOB_CANARY",
                declared_idempotency_key="synthetic-status-idempotency",
                payload_sha256=bytes.fromhex("ab" * 32),
                state="discovered",
                discovered_at=_NOW,
                validated_at=None,
                processed_at=None,
            )
            session.add(ingress)
            await session.flush()
            ingress.state = "quarantined"
            ingress.error_code = "private_provider_diagnostic"
            ingress.safe_diagnostic = "TOKEN_CANARY_ghp_not_a_real_credential"
            ingress.processed_at = _NOW + timedelta(seconds=1)
            await session.flush()
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        yield database, StatusEngine(factory, clock=lambda: _NOW)
    finally:
        await database.dispose()


async def _canonical_write_counts(database: Database) -> tuple[int, int, int]:
    async with database.tenant_session(_seed_identifier("tenants", "tenant_id")) as session:
        values = [
            int(await session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (MemoryEvent, CommandReceipt, OutboxJob)
        ]
        return cast(tuple[int, int, int], tuple(values))


async def test_status_reads_are_authorized_safe_and_write_free(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    ingress_id = new_uuid7()
    async with _seeded_status_engine(postgresql_server.database_url, ingress_id) as (
        database,
        engine,
    ):
        before = await _canonical_write_counts(database)
        proposal_principal = _principal(
            2,
            scopes=frozenset({"memory:propose"}),
            ingress_id=ingress_id,
        )
        result = await engine.ingress_status(
            proposal_principal,
            IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=ingress_id),
        )
        assert isinstance(result, IngressStatusResult), result
        assert result.result.state == "quarantined"
        assert result.result.result_event_id is None
        assert result.result.result_memory_id is None
        assert result.result.error_code == "quarantined"

        serialized = result.model_dump_json()
        for forbidden_field in (
            "PRIVATE_REPOSITORY_CANARY",
            "PRIVATE_BRANCH_CANARY",
            "PRIVATE_PATH_CANARY",
            "PRIVATE_COMMIT_CANARY",
            "PRIVATE_BLOB_CANARY",
            "TOKEN_CANARY",
            "payload_sha256",
            "transport_binding_id",
            "installation_id",
            "actor_id",
            "client_id",
        ):
            assert forbidden_field not in serialized
        assert set(result.model_dump(mode="json")) == {
            "ok",
            "contract_version",
            "tool",
            "result",
            "warnings",
            "metadata",
        }

        missing = await engine.ingress_status(
            proposal_principal,
            IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=new_uuid7()),
        )
        assert isinstance(missing, StatusError)
        assert missing.error.code == "not_found"
        assert "PRIVATE" not in missing.model_dump_json()

        forbidden = await engine.ingress_status(
            _principal(2, scopes=frozenset(), ingress_id=ingress_id),
            IngressStatusQuery(contract_version="mcp-read-v1", ingress_id=ingress_id),
        )
        assert isinstance(forbidden, StatusError)
        assert forbidden.error.code == "forbidden"

        relay = await engine.transport_status(
            _principal(1, scopes=frozenset({"memory.status.transport"})),
            TransportStatusQuery(contract_version="mcp-read-v1"),
        )
        assert isinstance(relay, TransportStatusResult), relay
        assert relay.result.transport_kind == "relay"
        assert relay.result.binding_state == "active"
        assert relay.result.installation_state == "active"
        assert relay.result.health_state == "healthy"
        assert relay.result.freshness == "never"
        relay_json = relay.model_dump_json()
        assert "synthetic-test-node" not in relay_json
        assert "relay.invalid" not in relay_json
        assert "certificate" not in relay_json

        direct = await engine.transport_status(
            _principal(0, scopes=frozenset({"memory.status.transport"})),
            TransportStatusQuery(contract_version="mcp-read-v1"),
        )
        assert isinstance(direct, TransportStatusResult), direct
        assert direct.result.transport_kind == "direct_private"
        assert direct.result.installation_state == "not_applicable"
        assert direct.result.health_state is None
        assert direct.result.freshness == "never"

        read_alias_forbidden = await engine.transport_status(
            _principal(0, scopes=frozenset({"memory:read"})),
            TransportStatusQuery(contract_version="mcp-read-v1"),
        )
        assert isinstance(read_alias_forbidden, StatusError)
        assert read_alias_forbidden.error.code == "forbidden"

        after = await _canonical_write_counts(database)
        assert before == after == (0, 0, 0)
