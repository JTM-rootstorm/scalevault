from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.application import mutations as mutations_module
from kivra_memory.domain.commands import (
    MemoryChanges,
    MemoryInput,
    MutationError,
    MutationResponse,
    MutationResult,
    RememberCommand,
    ReviseCommand,
    StaleRevisionDetails,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.fingerprints import exact_memory_fingerprint
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    CommandReceipt,
    IngressItem,
    Memory,
    MemoryEvent,
    OutboxJob,
    Subject,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


class PostgreSQLTestServer(Protocol):
    database_url: str


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _principal(
    index: int,
    *,
    ingress_id: UUID | None = None,
    scopes: frozenset[str] = frozenset({"memory:write"}),
) -> CommandPrincipal:
    binding = seed_rows()["transport_bindings"][index]
    return CommandPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=scopes,
        ingress_id=ingress_id,
    )


def _memory_input(statement: str, *, project_subject_id: UUID | None = None) -> MemoryInput:
    is_project = project_subject_id is not None
    return MemoryInput(
        subject_id=(
            project_subject_id
            if project_subject_id is not None
            else _seed_identifier("subjects", "subject_id")
        ),
        subject_kind=SubjectKind.PROJECT if is_project else SubjectKind.GLOBAL,
        category=MemoryCategory.PROJECT_DECISION if is_project else MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT if is_project else MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement=statement,
        reason_to_remember="This synthetic record verifies mutation transaction behavior.",
        interpretation_limits=("Synthetic integration-test data only.",),
        confidence=Decimal("0.900000"),
        salience=Decimal("0.800000"),
        durability=Decimal("0.700000"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=_NOW,
        metadata={"fixture": True},
    )


def _remember(
    idempotency_key: str,
    statement: str,
    *,
    project_subject_id: UUID | None = None,
) -> RememberCommand:
    return RememberCommand(
        contract_version="mcp-mutation-v1",
        idempotency_key=idempotency_key,
        logical_session_id=None,
        persona_id=_seed_identifier("personas", "persona_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        reason="Exercise the synthetic PostgreSQL mutation fixture.",
        memory=_memory_input(statement, project_subject_id=project_subject_id),
    )


def _revise(memory_id: UUID, ordinal: int) -> ReviseCommand:
    return ReviseCommand(
        contract_version="mcp-mutation-v1",
        idempotency_key=f"concurrent-revise:{ordinal}",
        logical_session_id=None,
        persona_id=_seed_identifier("personas", "persona_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        reason="Compete for the same synthetic optimistic revision.",
        memory_id=memory_id,
        expected_revision=1,
        changes=MemoryChanges(statement=f"Synthetic winning revision candidate {ordinal}."),
    )


@asynccontextmanager
async def _seeded_engine(
    database_url: str,
    *,
    project_subject_id: UUID | None = None,
    ingress: IngressItem | None = None,
) -> AsyncIterator[tuple[Database, MutationEngine]]:
    database = Database(database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    try:
        async with database.tenant_session(tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            if project_subject_id is not None:
                session.add(
                    Subject(
                        subject_id=project_subject_id,
                        tenant_id=tenant_id,
                        lineage_id=_seed_identifier("lineages", "lineage_id"),
                        kind="project",
                        canonical_key="synthetic-concurrency-project",
                        display_name="Synthetic Concurrency Project",
                        persona_id=None,
                        relationship_actor_id=None,
                        project_ref="synthetic-project",
                        episode_ref=None,
                        origin_session_id=None,
                        metadata_={"fixture": True},
                        created_at=_NOW,
                    )
                )
            if ingress is not None:
                session.add(ingress)
            await session.flush()

        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        yield database, MutationEngine(factory)
    finally:
        await database.dispose()


async def _counts(database: Database) -> tuple[int, int, int, int]:
    tenant_id = _seed_identifier("tenants", "tenant_id")
    async with database.tenant_session(tenant_id) as session:
        values = []
        for model in (MemoryEvent, Memory, CommandReceipt, OutboxJob):
            values.append(int(await session.scalar(select(func.count()).select_from(model)) or 0))
        return cast(tuple[int, int, int, int], tuple(values))


def _success(response: MutationResponse) -> MutationResult:
    assert isinstance(response, MutationResult), response
    return response


def _failure(response: MutationResponse) -> MutationError:
    assert isinstance(response, MutationError), response
    return response


async def test_concurrent_revisions_have_one_winner_and_no_lost_update(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        created = _success(
            await engine.execute(
                _principal(0),
                _remember("revise-seed", "Synthetic revision seed value."),
            )
        )
        assert created.memory_id is not None

        responses = await asyncio.gather(
            *(
                engine.execute(_principal(0), _revise(created.memory_id, index))
                for index in range(16)
            )
        )

        winners = [response for response in responses if isinstance(response, MutationResult)]
        losers = [response for response in responses if isinstance(response, MutationError)]
        assert len(winners) == 1
        assert winners[0].revision == 2
        assert len(losers) == 15
        assert {failure.error.code for failure in losers} == {"stale_revision"}
        assert all(
            isinstance(failure.error.details, StaleRevisionDetails)
            and failure.error.details.expected_revision == 1
            and failure.error.details.current_revision == 2
            for failure in losers
        )

        async with database.tenant_session(_principal(0).tenant_id) as session:
            row = await session.get(Memory, created.memory_id)
            assert row is not None
            assert row.revision == 2
            assert row.statement in {
                f"Synthetic winning revision candidate {index}." for index in range(16)
            }
        assert await _counts(database) == (2, 1, 2, 4)


async def test_concurrent_same_command_replays_one_atomic_result(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    command = _remember("shared-command-key", "Synthetic idempotent memory value.")
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        responses = await asyncio.gather(
            *(engine.execute(_principal(0), command) for _ in range(20))
        )
        results = [_success(response) for response in responses]

        assert len({result.receipt_id for result in results}) == 1
        assert len({result.event_id for result in results}) == 1
        assert len({result.memory_id for result in results}) == 1
        assert [result.idempotent_replay for result in results].count(False) == 1
        assert [result.idempotent_replay for result in results].count(True) == 19
        assert await _counts(database) == (1, 1, 1, 3)

        mismatched = _failure(
            await engine.execute(
                _principal(0),
                _remember("shared-command-key", "Synthetic mismatched command value."),
            )
        )
        assert mismatched.error.code == "idempotency_key_reused"
        assert mismatched.error.details is None
        assert await _counts(database) == (1, 1, 1, 3)


async def test_concurrent_exact_create_across_distinct_clients_has_one_live_fingerprint(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    statement = "Synthetic cross-client duplicate candidate."
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        responses = await asyncio.gather(
            engine.execute(_principal(0), _remember("direct-duplicate", statement)),
            engine.execute(_principal(1), _remember("relay-duplicate", statement)),
        )
        successes = [response for response in responses if isinstance(response, MutationResult)]
        failures = [response for response in responses if isinstance(response, MutationError)]

        assert len(successes) == 1
        assert len(failures) == 1
        assert failures[0].error.code == "invalid_input"
        fingerprint = exact_memory_fingerprint(
            statement=statement,
            category=MemoryCategory.STABLE_FACT,
            ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
            scope=MemoryScope.GLOBAL,
            interpretation_limits=("Synthetic integration-test data only.",),
        )
        async with database.tenant_session(_principal(0).tenant_id) as session:
            live_count = await session.scalar(
                select(func.count())
                .select_from(Memory)
                .where(
                    Memory.normalized_fingerprint == bytes.fromhex(fingerprint.sha256_hex),
                    Memory.status.in_(
                        [
                            MemoryStatus.CANDIDATE.value,
                            MemoryStatus.ACTIVE.value,
                            MemoryStatus.DISPUTED.value,
                        ]
                    ),
                )
            )
            assert live_count == 1
        assert await _counts(database) == (1, 1, 1, 3)


async def test_event_projection_receipt_and_outbox_roll_back_together(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = migrated_database

    async def fail_outbox(session: AsyncSession, **kwargs: object) -> OutboxJob:
        del session, kwargs
        raise RuntimeError("synthetic injected outbox failure")

    monkeypatch.setattr(mutations_module, "enqueue_outbox_job", fail_outbox)
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        response = _failure(
            await engine.execute(
                _principal(0),
                _remember("rollback-command", "Synthetic rollback candidate."),
            )
        )
        assert response.error.code == "internal_error"
        assert await _counts(database) == (0, 0, 0, 0)


async def test_direct_and_validated_ingress_share_engine_and_commit_ingress_atomically(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    project_subject_id = new_uuid7()
    ingress_id = new_uuid7()
    ingress_key = "synthetic-ingress-command"
    github_binding = seed_rows()["transport_bindings"][2]
    ingress = IngressItem(
        ingress_id=ingress_id,
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        transport_binding_id=cast(UUID, github_binding["transport_binding_id"]),
        installation_id=cast(UUID, github_binding["installation_id"]),
        actor_id=cast(UUID, github_binding["actor_id"]),
        client_id=cast(UUID, github_binding["client_id"]),
        provider="github",
        repository_external_id="synthetic/repository",
        branch_name="main",
        immutable_path="ingress/v1/synthetic/proposal.json",
        external_object_id="synthetic-object",
        commit_id="synthetic-commit",
        blob_id="synthetic-blob",
        declared_idempotency_key=ingress_key,
        payload_sha256=bytes(32),
        state="validated",
        discovered_at=_NOW - timedelta(minutes=1),
        validated_at=_NOW,
    )
    async with _seeded_engine(
        postgresql_server.database_url,
        project_subject_id=project_subject_id,
        ingress=ingress,
    ) as (database, engine):
        direct, ingested = await asyncio.gather(
            engine.execute(
                _principal(0),
                _remember(
                    "synthetic-direct-command",
                    "Synthetic direct project memory.",
                    project_subject_id=project_subject_id,
                ),
            ),
            engine.execute(
                _principal(
                    2,
                    ingress_id=ingress_id,
                    scopes=frozenset({"memory.write.remember"}),
                ),
                _remember(
                    ingress_key,
                    "Synthetic ingress project memory.",
                    project_subject_id=project_subject_id,
                ),
            ),
        )
        direct_result = _success(direct)
        ingress_result = _success(ingested)
        assert direct_result.memory_id != ingress_result.memory_id

        async with database.tenant_session(_principal(0).tenant_id) as session:
            stored = await session.get(IngressItem, ingress_id)
            assert stored is not None
            assert stored.state == "accepted"
            assert stored.result_event_id == ingress_result.event_id
            assert stored.result_memory_id == ingress_result.memory_id
            assert stored.processed_at is not None
        assert await _counts(database) == (2, 2, 2, 6)

        replay = _success(
            await engine.execute(
                _principal(
                    2,
                    ingress_id=ingress_id,
                    scopes=frozenset({"memory.write.remember"}),
                ),
                _remember(
                    ingress_key,
                    "Synthetic ingress project memory.",
                    project_subject_id=project_subject_id,
                ),
            )
        )
        assert replay.idempotent_replay is True
        assert replay.receipt_id == ingress_result.receipt_id
        assert replay.event_id == ingress_result.event_id
        assert replay.memory_id == ingress_result.memory_id
        assert await _counts(database) == (2, 2, 2, 6)
