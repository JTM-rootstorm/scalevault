from __future__ import annotations

import base64
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol, cast
from uuid import UUID

from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import (
    BranchCreatedPayload,
    BranchState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    OperationPayload,
    event_hash_fields,
)
from kivra_memory.domain.folding import canonical_aggregate_bytes
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.event_store import append_memory_event
from kivra_memory.storage.models import MemoryEvent as MemoryEventRow
from kivra_memory.storage.models import MemoryEventCounter
from kivra_memory.storage.projector import (
    load_canonical_aggregate_bytes,
    rebuild_semantic_projections,
)
from sqlalchemy import func, select

from tests.fixtures.database_seed import insert_seed_rows, seed_rows

_EVENT_TIME = datetime(2026, 8, 3, 20, 0, 0, 123456, tzinfo=UTC)
_EVENT_TIMESTAMP_MS = 1_785_785_600_000


class PostgreSQLTestServer(Protocol):
    database_url: str


class _RollbackEvent(RuntimeError):
    pass


def _event_uuid(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_EVENT_TIMESTAMP_MS, random_bits=ordinal)


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _branch_state() -> BranchState:
    branch = seed_rows()["branches"][0]
    return BranchState(
        branch_id=cast(UUID, branch["branch_id"]),
        tenant_id=cast(UUID, branch["tenant_id"]),
        lineage_id=cast(UUID, branch["lineage_id"]),
        parent_branch_id=None,
        fork_event_sequence=None,
        name=cast(str, branch["name"]),
        visibility_ceiling=MemoryVisibility(cast(str, branch["visibility_ceiling"])),
        created_at=cast(datetime, branch["created_at"]),
    )


def _memory_state() -> MemoryState:
    return MemoryState(
        memory_id=_event_uuid(10),
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        lineage_id=_seed_identifier("lineages", "lineage_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        subject_id=_seed_identifier("subjects", "subject_id"),
        subject_kind=SubjectKind.GLOBAL,
        revision=1,
        category=MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="The synthetic database acceptance record is stable.",
        reason_to_remember="It verifies committed event replay against PostgreSQL.",
        interpretation_limits=("Synthetic integration-test data only.",),
        confidence=Decimal("0.900000"),
        salience=Decimal("0.800000"),
        durability=Decimal("0.700000"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=_EVENT_TIME,
        content_protection="plaintext",
        created_at=_EVENT_TIME,
        updated_at=_EVENT_TIME,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


def _event(
    sequence: int,
    *,
    operation: EventOperation,
    payload: OperationPayload,
    memory_id: UUID | None,
) -> MemoryEvent:
    tenant_id = _seed_identifier("tenants", "tenant_id")
    lineage_id = _seed_identifier("lineages", "lineage_id")
    branch_id = _seed_identifier("branches", "branch_id")
    binding = seed_rows()["transport_bindings"][0]
    actor_id = cast(UUID, binding["actor_id"])
    client_id = cast(UUID, binding["client_id"])
    values, canonical, payload_hash, command_hash = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=_event_uuid(100 + sequence),
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        session_id=None,
        ingress_id=None,
        operation=operation,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
        correlation_id=_event_uuid(20),
        idempotency_key=f"postgres-acceptance:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=values,
        payload_canonical=canonical,
        payload_sha256=payload_hash,
        command_sha256=command_hash,
        created_at=_EVENT_TIME,
    )


def _branch_event(sequence: int) -> MemoryEvent:
    return _event(
        sequence,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=_branch_state()),
        memory_id=None,
    )


def _remembered_event(sequence: int, memory: MemoryState) -> MemoryEvent:
    return _event(
        sequence,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
    )


async def test_committed_events_are_gap_free_and_rebuild_byte_equivalent(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    memory = _memory_state()

    try:
        async with database.tenant_session(tenant_id) as session:
            insert_seed_rows(session)
            await session.flush()
            branch = await append_memory_event(session, _branch_event)
            assert branch.sequence == 1

        try:
            async with database.tenant_session(tenant_id) as session:
                rolled_back = await append_memory_event(
                    session,
                    lambda sequence: _remembered_event(sequence, memory),
                )
                assert rolled_back.sequence == 2
                raise _RollbackEvent
        except _RollbackEvent:
            pass

        async with database.tenant_session(tenant_id) as session:
            remembered = await append_memory_event(
                session,
                lambda sequence: _remembered_event(sequence, memory),
            )
            assert remembered.sequence == 2

            row = (
                await session.execute(
                    select(MemoryEventRow).where(MemoryEventRow.sequence == remembered.sequence)
                )
            ).scalar_one()
            assert row.payload == remembered.payload
            assert bytes(row.payload_canonical) == base64.b64decode(
                remembered.payload_canonical, validate=True
            )
            assert bytes(row.payload_sha256) == bytes.fromhex(remembered.payload_sha256)
            assert bytes(row.command_sha256) == bytes.fromhex(remembered.command_sha256)

            assert await session.scalar(select(func.count()).select_from(MemoryEventRow)) == 2
            assert await session.scalar(select(MemoryEventCounter.next_sequence)) == 3

            state = await rebuild_semantic_projections(session, tenant_id=tenant_id)
            expected = canonical_aggregate_bytes(state, memory.memory_id)
            assert (
                await load_canonical_aggregate_bytes(
                    session,
                    tenant_id=tenant_id,
                    memory_id=memory.memory_id,
                )
                == expected
            )

        async with database.tenant_session(tenant_id) as session:
            rebuilt = await rebuild_semantic_projections(session, tenant_id=tenant_id)
            assert canonical_aggregate_bytes(rebuilt, memory.memory_id) == expected
            assert (
                await load_canonical_aggregate_bytes(
                    session,
                    tenant_id=tenant_id,
                    memory_id=memory.memory_id,
                )
                == expected
            )
    finally:
        await database.dispose()
