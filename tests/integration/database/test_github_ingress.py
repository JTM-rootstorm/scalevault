from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.domain.enums import IngressState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.github_ingress import (
    GitHubIngressDiscovery,
    GitHubIngressRepository,
    IngressRegistration,
)
from kivra_memory.storage.models import IngressItem
from kivra_memory.storage.transactions import run_serializable_transaction
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from tests.fixtures.database_seed import seed_model_layers, seed_rows

from .conftest import AlembicRunner, PostgreSQLTestServer

_NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)


def _id(table: str, field: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][field])


def _discovery() -> GitHubIngressDiscovery:
    installation_id = _id("transport_installations", "installation_id")
    ingress_id = new_uuid7(timestamp_ms=1_786_276_800_000, random_bits=61)
    return GitHubIngressDiscovery(
        ingress_id=ingress_id,
        tenant_id=_id("tenants", "tenant_id"),
        transport_binding_id=_id("transport_bindings", "transport_binding_id", 2),
        installation_id=installation_id,
        actor_id=_id("actors", "actor_id", 1),
        client_id=_id("clients", "client_id", 2),
        repository_external_id="12345678",
        branch_name="main",
        immutable_path=f"ingress/v2/{installation_id}/2026/08/{ingress_id}.json",
        commit_id="1" * 40,
        blob_id="2" * 40,
        discovered_at=_NOW,
    )


async def _seed(database: Database) -> None:
    async with database.tenant_session(_id("tenants", "tenant_id")) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            await session.flush()


async def test_concurrent_registration_creates_one_honest_discovered_row(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubIngressRepository()
    discovery = _discovery()
    await _seed(database)

    async def register() -> IngressRegistration:
        async def operation(session: AsyncSession) -> IngressRegistration:
            return await repository.register(session, discovery)

        return await run_serializable_transaction(
            database.session_factory, discovery.tenant_id, operation
        )

    try:
        first, second = await asyncio.gather(register(), register())
        assert sum(int(result.created) for result in (first, second)) == 1
        async with database.tenant_session(discovery.tenant_id) as session:
            rows = (
                await session.scalars(
                    select(IngressItem).where(IngressItem.ingress_id == discovery.ingress_id)
                )
            ).all()
            assert len(rows) == 1
            assert rows[0].state == IngressState.DISCOVERED.value
            assert rows[0].declared_idempotency_key is None
            assert rows[0].payload_sha256 is None
    finally:
        await database.dispose()


async def test_validation_sets_semantic_identity_once_and_append_only_change_quarantines(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubIngressRepository()
    discovery = _discovery()
    await _seed(database)
    try:
        async with database.tenant_session(discovery.tenant_id) as session:
            await repository.register(session, discovery)
        async with database.tenant_session(discovery.tenant_id) as session:
            validated = await repository.validate(
                session,
                discovery=discovery,
                idempotency_key="github:synthetic-proposal",
                payload_sha256=b"p" * 32,
                validated_at=_NOW,
            )
            assert validated.state is IngressState.VALIDATED

        changed = replace(discovery, commit_id="3" * 40, blob_id="4" * 40)
        async with database.tenant_session(discovery.tenant_id) as session:
            registration = await repository.register(session, changed)
            assert registration.same_object is False
            assert registration.state is IngressState.QUARANTINED
        async with database.tenant_session(discovery.tenant_id) as session:
            row = await session.get(IngressItem, discovery.ingress_id)
            assert row is not None
            assert row.commit_id == discovery.commit_id
            assert row.blob_id == discovery.blob_id
            assert row.declared_idempotency_key == "github:synthetic-proposal"
            assert row.payload_sha256 == b"p" * 32
            assert row.error_code == "append_only_violation"
    finally:
        await database.dispose()


async def test_database_rejects_semantic_enrichment_without_validation_transition(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubIngressRepository()
    discovery = _discovery()
    await _seed(database)
    try:
        async with database.tenant_session(discovery.tenant_id) as session:
            await repository.register(session, discovery)
        with pytest.raises(DBAPIError) as caught:
            async with database.tenant_session(discovery.tenant_id) as session:
                await session.execute(
                    text(
                        "UPDATE ingress_items SET declared_idempotency_key = :key, "
                        "payload_sha256 = :digest WHERE ingress_id = :ingress_id"
                    ),
                    {
                        "key": "github:invalid-transition",
                        "digest": b"x" * 32,
                        "ingress_id": discovery.ingress_id,
                    },
                )
        assert getattr(caught.value.orig, "sqlstate", None) == "55000"
    finally:
        await database.dispose()
