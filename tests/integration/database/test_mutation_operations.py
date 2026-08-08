from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, cast
from uuid import UUID

from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.domain.commands import (
    ConflictResolution,
    ForgetCommand,
    LinkCommand,
    MemoryInput,
    MemoryRevisionExpectation,
    MutationError,
    MutationResponse,
    MutationResult,
    OpenConflictCommand,
    RememberCommand,
    ResolveConflictCommand,
    RetireCommand,
)
from kivra_memory.domain.enums import (
    AuthorityClass,
    LinkType,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    Branch,
    CommandReceipt,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    MemoryEvent,
    MemoryLink,
    OutboxJob,
)
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 8, 15, tzinfo=UTC)


class PostgreSQLTestServer(Protocol):
    database_url: str


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _principal() -> CommandPrincipal:
    binding = seed_rows()["transport_bindings"][0]
    return CommandPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=frozenset({"memory:write"}),
    )


def _base_command(key: str) -> dict[str, Any]:
    return {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": key,
        "logical_session_id": None,
        "persona_id": _seed_identifier("personas", "persona_id"),
        "branch_id": _seed_identifier("branches", "branch_id"),
        "reason": "Exercise a synthetic mutation operation transaction.",
    }


def _remember(key: str, statement: str) -> RememberCommand:
    return RememberCommand(
        **_base_command(key),
        memory=MemoryInput(
            subject_id=_seed_identifier("subjects", "subject_id"),
            subject_kind=SubjectKind.GLOBAL,
            category=MemoryCategory.STABLE_FACT,
            ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
            scope=MemoryScope.GLOBAL,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement=statement,
            reason_to_remember="This record exists only for deterministic integration testing.",
            interpretation_limits=("Synthetic integration-test data only.",),
            confidence=Decimal("0.900000"),
            salience=Decimal("0.800000"),
            durability=Decimal("0.700000"),
            sensitivity=0,
            authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
            observed_at=_NOW,
            metadata={"fixture": True},
        ),
    )


@asynccontextmanager
async def _seeded_engine(
    database_url: str,
) -> AsyncIterator[tuple[Database, MutationEngine]]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_principal().tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        yield database, MutationEngine(factory)
    finally:
        await database.dispose()


def _success(response: MutationResponse) -> MutationResult:
    assert isinstance(response, MutationResult), response
    return response


def _failure(response: MutationResponse) -> MutationError:
    assert isinstance(response, MutationError), response
    return response


async def _count(session: AsyncSession, model: type[object]) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def test_all_non_create_operations_commit_atomic_projection_receipt_and_outbox(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    principal = _principal()
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        created = [
            _success(
                await engine.execute(
                    principal,
                    _remember(f"operation-seed-{index}", f"Synthetic operation memory {index}."),
                )
            )
            for index in range(5)
        ]
        memory_ids = [cast(UUID, result.memory_id) for result in created]

        linked = _success(
            await engine.execute(
                principal,
                LinkCommand(
                    **_base_command("operation-link"),
                    source_memory_id=memory_ids[0],
                    source_expected_revision=1,
                    target_memory_id=memory_ids[1],
                    target_expected_revision=1,
                    link_type=LinkType.SUPPORTS,
                    metadata={"fixture": True},
                ),
            )
        )
        assert linked.memory_id is None

        opened = _success(
            await engine.execute(
                principal,
                OpenConflictCommand(
                    **_base_command("operation-open-conflict"),
                    subject_id=_seed_identifier("subjects", "subject_id"),
                    members=tuple(
                        MemoryRevisionExpectation(memory_id=memory_id, expected_revision=1)
                        for memory_id in memory_ids[:2]
                    ),
                    conflict_reason="Synthetic records intentionally disagree for this test.",
                    metadata={"fixture": True},
                ),
            )
        )
        assert opened.conflict_id is not None
        assert opened.conflict_state == "open"

        resolved = _success(
            await engine.execute(
                principal,
                ResolveConflictCommand(
                    **_base_command("operation-resolve-conflict"),
                    conflict_id=opened.conflict_id,
                    members=(
                        ConflictResolution(
                            memory_id=memory_ids[0],
                            expected_revision=2,
                            disposition="retained",
                            resulting_status="active",
                        ),
                        ConflictResolution(
                            memory_id=memory_ids[1],
                            expected_revision=2,
                            disposition="superseded",
                            resulting_status="superseded",
                        ),
                    ),
                    resolution_kind="select_winner",
                    resolution_rationale="Keep one deterministic synthetic record.",
                ),
            )
        )
        assert resolved.conflict_id == opened.conflict_id
        assert resolved.conflict_state == "resolved"

        retired = _success(
            await engine.execute(
                principal,
                RetireCommand(
                    **_base_command("operation-retire"),
                    memory_id=memory_ids[2],
                    expected_revision=1,
                ),
            )
        )
        assert retired.revision == 2

        logically_forgotten = _success(
            await engine.execute(
                principal,
                ForgetCommand(
                    **_base_command("operation-logical-forget"),
                    memory_id=memory_ids[3],
                    expected_revision=1,
                    mode="logical",
                    confirmation="confirm_logical_forget",
                ),
            )
        )
        assert logically_forgotten.forget_state == "logically_forgotten"

        unavailable = _failure(
            await engine.execute(
                principal,
                ForgetCommand(
                    **_base_command("operation-hard-forget-unavailable"),
                    memory_id=memory_ids[4],
                    expected_revision=1,
                    mode="hard",
                    confirmation="confirm_hard_forget",
                ),
            )
        )
        assert unavailable.error.code == "hard_forget_unavailable"

        content_key_id = new_uuid7()
        async with database.tenant_session(principal.tenant_id) as session:
            session.add(
                MemoryContentKey(
                    content_key_id=content_key_id,
                    tenant_id=principal.tenant_id,
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    memory_id=memory_ids[4],
                    provider_name="synthetic-test-provider",
                    provider_key_reference="synthetic/non-secret/reference",
                    state="active",
                    created_at=_NOW,
                )
            )
            await session.execute(
                update(Memory)
                .where(Memory.memory_id == memory_ids[4])
                .values(content_protection="envelope_encrypted", content_key_id=content_key_id)
            )

        hard_forgotten = _success(
            await engine.execute(
                principal,
                ForgetCommand(
                    **_base_command("operation-hard-forget"),
                    memory_id=memory_ids[4],
                    expected_revision=1,
                    mode="hard",
                    confirmation="confirm_hard_forget",
                ),
            )
        )
        assert hard_forgotten.forget_state == "purge_pending"

        operation_results = (
            *created,
            linked,
            opened,
            resolved,
            retired,
            logically_forgotten,
            hard_forgotten,
        )
        async with database.tenant_session(principal.tenant_id) as session:
            assert await _count(session, MemoryEvent) == 11
            assert await _count(session, CommandReceipt) == 11
            assert await _count(session, Memory) == 5
            assert await _count(session, MemoryLink) == 1
            assert await _count(session, MemoryConflict) == 1
            assert await _count(session, MemoryConflictMember) == 2
            assert await _count(session, OutboxJob) == 29

            stored_memories = {
                row.memory_id: row for row in (await session.scalars(select(Memory))).all()
            }
            first_state = (
                stored_memories[memory_ids[0]].revision,
                stored_memories[memory_ids[0]].status,
            )
            assert first_state == (
                3,
                MemoryStatus.ACTIVE.value,
            )
            second_state = (
                stored_memories[memory_ids[1]].revision,
                stored_memories[memory_ids[1]].status,
            )
            assert second_state == (
                3,
                MemoryStatus.SUPERSEDED.value,
            )
            assert stored_memories[memory_ids[2]].status == MemoryStatus.RETIRED.value
            assert stored_memories[memory_ids[3]].status == MemoryStatus.TOMBSTONED.value
            assert stored_memories[memory_ids[4]].status == MemoryStatus.TOMBSTONED.value
            assert stored_memories[memory_ids[4]].content_key_id == content_key_id
            content_key = await session.get(MemoryContentKey, content_key_id)
            assert content_key is not None
            assert content_key.state == "active"
            assert content_key.destruction_requested_at is None

            conflict = await session.get(MemoryConflict, opened.conflict_id)
            assert conflict is not None
            assert conflict.status == "resolved"
            assert conflict.resolution_event_id == resolved.event_id

            receipts = (
                await session.scalars(
                    select(CommandReceipt).where(
                        CommandReceipt.event_id.in_(result.event_id for result in operation_results)
                    )
                )
            ).all()
            assert {row.event_id for row in receipts} == {
                result.event_id for result in operation_results
            }

            export_event_ids = {
                UUID(cast(str, row.payload["event_id"]))
                for row in (
                    await session.scalars(
                        select(OutboxJob).where(OutboxJob.job_type == "export_git_batch")
                    )
                ).all()
            }
            assert export_event_ids == {result.event_id for result in operation_results}

            create_jobs = (
                await session.scalars(
                    select(OutboxJob).where(
                        OutboxJob.job_type.in_(["embed_memory", "check_duplicates"])
                    )
                )
            ).all()
            create_payloads = [
                (row.job_type, row.aggregate_id, row.payload) for row in create_jobs
            ]
            for result in created:
                assert result.memory_id is not None
                expected_references = {
                    "event_id": str(result.event_id),
                    "memory_id": str(result.memory_id),
                    "memory_version": 1,
                }
                assert ("embed_memory", result.memory_id, expected_references) in create_payloads
                assert (
                    "check_duplicates",
                    result.memory_id,
                    expected_references,
                ) in create_payloads

            embed_targets = {
                (
                    row.aggregate_id,
                    cast(int, row.payload["memory_version"]),
                    UUID(cast(str, row.payload["event_id"])),
                )
                for row in create_jobs
                if row.job_type == "embed_memory"
            }
            assert {
                (memory_ids[0], 2, opened.event_id),
                (memory_ids[1], 2, opened.event_id),
                (memory_ids[0], 3, resolved.event_id),
                (memory_ids[1], 3, resolved.event_id),
                (memory_ids[2], 2, retired.event_id),
                (memory_ids[3], 2, logically_forgotten.event_id),
                (memory_ids[4], 2, hard_forgotten.event_id),
            } <= embed_targets

            purge_job = await session.scalar(
                select(OutboxJob).where(OutboxJob.job_type == "purge_payload")
            )
            assert purge_job is not None
            assert purge_job.aggregate_id == memory_ids[4]
            assert purge_job.payload == {
                "event_id": str(hard_forgotten.event_id),
                "memory_id": str(memory_ids[4]),
                "memory_version": 2,
            }


async def test_sealed_branch_fails_closed_without_partial_transaction(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    principal = _principal()
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        async with database.tenant_session(principal.tenant_id) as session:
            await session.execute(
                update(Branch)
                .where(Branch.branch_id == _seed_identifier("branches", "branch_id"))
                .values(sealed_at=_NOW)
            )

        response = _failure(
            await engine.execute(
                principal,
                _remember("sealed-branch-command", "Synthetic forbidden branch write."),
            )
        )
        assert response.error.code == "forbidden"
        assert response.error.details is None

        async with database.tenant_session(principal.tenant_id) as session:
            assert await _count(session, MemoryEvent) == 0
            assert await _count(session, Memory) == 0
            assert await _count(session, CommandReceipt) == 0
            assert await _count(session, OutboxJob) == 0
