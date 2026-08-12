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
from kivra_memory.storage.github_heads import (
    GITHUB_INGRESS_BOOTSTRAP_COMMIT,
    GITHUB_INGRESS_BOOTSTRAP_TREE,
    GitHubHeadStorageError,
    GitHubProviderHeadRepository,
    GitHubProviderIdentity,
)
from kivra_memory.storage.github_ingress import (
    GitHubIngressDiscovery,
    GitHubIngressRepository,
    IngressRegistration,
)
from kivra_memory.storage.github_revocation import GitHubInstallationRevoked
from kivra_memory.storage.models import (
    IngressItem,
    IngressProviderHead,
    IngressProviderViolation,
    TransportInstallation,
)
from kivra_memory.storage.transactions import run_serializable_transaction
from sqlalchemy import select, text, update
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


async def _revoke_installation(database: Database, installation_id: UUID) -> None:
    tenant_id = _id("tenants", "tenant_id")
    async with database.tenant_session(tenant_id) as session:
        await session.execute(
            update(TransportInstallation)
            .where(
                TransportInstallation.tenant_id == tenant_id,
                TransportInstallation.installation_id == installation_id,
            )
            .values(revoked_at=_NOW)
        )


async def test_local_revocation_fences_registration_and_provider_checkpoint(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    ingress = GitHubIngressRepository()
    heads = GitHubProviderHeadRepository()
    discovery = _discovery()
    identity = _provider_identity()
    await _seed(database)
    await _revoke_installation(database, discovery.installation_id)

    try:
        with pytest.raises(GitHubInstallationRevoked, match="github_installation_revoked"):
            async with database.tenant_session(discovery.tenant_id) as session:
                await ingress.register(session, discovery)
        with pytest.raises(GitHubInstallationRevoked, match="github_installation_revoked"):
            async with database.tenant_session(identity.tenant_id) as session:
                await heads.load_or_create(session, identity)

        async with database.tenant_session(discovery.tenant_id) as session:
            assert await session.scalar(select(IngressItem.ingress_id)) is None
            assert await session.scalar(select(IngressProviderHead.tenant_id)) is None
    finally:
        await database.dispose()


def _provider_identity() -> GitHubProviderIdentity:
    return GitHubProviderIdentity(
        tenant_id=_id("tenants", "tenant_id"),
        installation_id=_id("transport_installations", "installation_id"),
        transport_binding_id=_id("transport_bindings", "transport_binding_id", 2),
        repository_id=12_345_678,
        branch_name="main",
    )


async def test_provider_head_starts_at_exact_bootstrap_and_advances_once(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubProviderHeadRepository()
    identity = _provider_identity()
    await _seed(database)
    try:
        async with database.tenant_session(identity.tenant_id) as session:
            checkpoint = await repository.load_or_create(session, identity)
        assert checkpoint.bootstrap_commit_id == GITHUB_INGRESS_BOOTSTRAP_COMMIT
        assert checkpoint.bootstrap_tree_id == GITHUB_INGRESS_BOOTSTRAP_TREE
        assert checkpoint.last_verified_commit_id == GITHUB_INGRESS_BOOTSTRAP_COMMIT
        assert checkpoint.last_verified_tree_id == GITHUB_INGRESS_BOOTSTRAP_TREE
        assert checkpoint.etag is None

        async with database.tenant_session(identity.tenant_id) as session:
            advanced = await repository.advance(
                session,
                identity,
                expected_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                expected_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                commit_id="a" * 40,
                tree_id="b" * 40,
                etag='"verified-head"',
            )
        assert advanced.last_verified_commit_id == "a" * 40
        assert advanced.last_verified_tree_id == "b" * 40
        assert advanced.etag == '"verified-head"'

        with pytest.raises(GitHubHeadStorageError, match="verified_head_race"):
            async with database.tenant_session(identity.tenant_id) as session:
                await repository.advance(
                    session,
                    identity,
                    expected_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                    expected_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                    commit_id="c" * 40,
                    tree_id="d" * 40,
                    etag=None,
                )

        async with database.tenant_session(identity.tenant_id) as session:
            rows = (await session.scalars(select(IngressProviderHead))).all()
            assert len(rows) == 1
            assert rows[0].last_verified_commit_id == "a" * 40
    finally:
        await database.dispose()


async def test_provider_head_bootstrap_identity_is_database_immutable(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubProviderHeadRepository()
    identity = _provider_identity()
    await _seed(database)
    try:
        async with database.tenant_session(identity.tenant_id) as session:
            await repository.load_or_create(session, identity)
        with pytest.raises(DBAPIError) as caught:
            async with database.tenant_session(identity.tenant_id) as session:
                await session.execute(
                    text(
                        "UPDATE ingress_provider_heads SET bootstrap_commit_id = :commit "
                        "WHERE tenant_id = :tenant_id"
                    ),
                    {"commit": "f" * 40, "tenant_id": identity.tenant_id},
                )
        assert getattr(caught.value.orig, "sqlstate", None) == "55000"
    finally:
        await database.dispose()


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("last_verified_commit_id", "a" * 40),
        ("last_verified_tree_id", "b" * 40),
    ],
)
async def test_provider_head_rejects_commit_or_tree_advancing_alone(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
    column: str,
    value: str,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubProviderHeadRepository()
    identity = _provider_identity()
    await _seed(database)
    try:
        async with database.tenant_session(identity.tenant_id) as session:
            await repository.load_or_create(session, identity)
        with pytest.raises(DBAPIError) as caught:
            async with database.tenant_session(identity.tenant_id) as session:
                await session.execute(
                    text(
                        f"UPDATE ingress_provider_heads SET {column} = :value "
                        "WHERE tenant_id = :tenant_id"
                    ),
                    {"value": value, "tenant_id": identity.tenant_id},
                )
        assert getattr(caught.value.orig, "sqlstate", None) == "23514"
    finally:
        await database.dispose()


async def test_two_stale_provider_head_advances_have_one_cas_winner(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubProviderHeadRepository()
    identity = _provider_identity()
    await _seed(database)
    try:
        async with database.tenant_session(identity.tenant_id) as session:
            await repository.load_or_create(session, identity)

        async def advance(commit_id: str, tree_id: str) -> object:
            async with database.tenant_session(identity.tenant_id) as session:
                return await repository.advance(
                    session,
                    identity,
                    expected_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                    expected_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                    commit_id=commit_id,
                    tree_id=tree_id,
                    etag=None,
                )

        outcomes = await asyncio.gather(
            advance("a" * 40, "b" * 40),
            advance("c" * 40, "d" * 40),
            return_exceptions=True,
        )

        assert sum(isinstance(outcome, GitHubHeadStorageError) for outcome in outcomes) == 1
        assert sum(not isinstance(outcome, BaseException) for outcome in outcomes) == 1
        failure = next(
            outcome for outcome in outcomes if isinstance(outcome, GitHubHeadStorageError)
        )
        assert str(failure) == "verified_head_race"
    finally:
        await database.dispose()


async def test_provider_head_rejects_installation_from_an_unrelated_binding(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubProviderHeadRepository()
    identity = replace(
        _provider_identity(),
        transport_binding_id=_id("transport_bindings", "transport_binding_id", 0),
    )
    await _seed(database)
    try:
        with pytest.raises(DBAPIError) as caught:
            async with database.tenant_session(identity.tenant_id) as session:
                await repository.load_or_create(session, identity)
        assert getattr(caught.value.orig, "sqlstate", None) == "23503"
    finally:
        await database.dispose()


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
            violations = (
                await session.scalars(
                    select(IngressProviderViolation).where(
                        IngressProviderViolation.ingress_id == discovery.ingress_id
                    )
                )
            ).all()
            assert len(violations) == 1
            assert violations[0].violation_code == "append_only_violation"
            assert len(violations[0].expected_provenance_sha256) == 32
            assert len(violations[0].observed_provenance_sha256) == 32
            assert (
                violations[0].expected_provenance_sha256 != violations[0].observed_provenance_sha256
            )
    finally:
        await database.dispose()


async def test_terminal_provenance_change_is_audited_once_without_result_mutation(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    repository = GitHubIngressRepository()
    discovery = _discovery()
    changed = replace(discovery, commit_id="3" * 40, blob_id="4" * 40)
    await _seed(database)

    async def register_changed() -> IngressRegistration:
        async def operation(session: AsyncSession) -> IngressRegistration:
            return await repository.register(session, changed)

        return await run_serializable_transaction(
            database.session_factory, discovery.tenant_id, operation
        )

    try:
        async with database.tenant_session(discovery.tenant_id) as session:
            await repository.register(session, discovery)
        async with database.tenant_session(discovery.tenant_id) as session:
            await repository.quarantine(
                session,
                discovery=discovery,
                error_code="schema_invalid",
                processed_at=_NOW,
            )
        async with database.tenant_session(discovery.tenant_id) as session:
            terminal = await session.get(IngressItem, discovery.ingress_id)
            assert terminal is not None
            terminal_snapshot = (
                terminal.state,
                terminal.error_code,
                terminal.result_event_id,
                terminal.result_memory_id,
                terminal.validated_at,
                terminal.processed_at,
            )

        first, second = await asyncio.gather(register_changed(), register_changed())
        assert all(not result.same_object for result in (first, second))
        assert all(not result.canonical_changed for result in (first, second))
        assert all(result.state is IngressState.QUARANTINED for result in (first, second))

        async with database.tenant_session(discovery.tenant_id) as session:
            terminal = await session.get(IngressItem, discovery.ingress_id)
            assert terminal is not None
            assert (
                terminal.state,
                terminal.error_code,
                terminal.result_event_id,
                terminal.result_memory_id,
                terminal.validated_at,
                terminal.processed_at,
            ) == terminal_snapshot
            violations = (
                await session.scalars(
                    select(IngressProviderViolation).where(
                        IngressProviderViolation.ingress_id == discovery.ingress_id
                    )
                )
            ).all()
            assert len(violations) == 1
            assert violations[0].violation_code == "append_only_violation"
        with pytest.raises(DBAPIError) as deletion:
            async with database.tenant_session(discovery.tenant_id) as session:
                await session.execute(
                    text(
                        "DELETE FROM ingress_provider_violations "
                        "WHERE tenant_id = :tenant_id AND ingress_id = :ingress_id"
                    ),
                    {
                        "tenant_id": discovery.tenant_id,
                        "ingress_id": discovery.ingress_id,
                    },
                )
        assert getattr(deletion.value.orig, "sqlstate", None) == "55000"
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
