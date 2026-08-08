from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol, cast
from uuid import UUID

from kivra_memory.application import CommandPrincipal, MutationEngine
from kivra_memory.domain.commands import (
    ForgetCommand,
    MemoryInput,
    MemoryRevisionExpectation,
    MutationResponse,
    MutationResult,
    OpenConflictCommand,
    RememberCommand,
    RetireCommand,
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
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    Branch,
    CommandReceipt,
    Memory,
    MemoryEmbeddingV1,
    MemoryEvent,
    OutboxJob,
)
from kivra_memory.storage.retrieval import RetrievalFilters, RetrievalRepository
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows
from tests.fixtures.retrieval_corpus import retrieval_uuid

_NOW = datetime(2026, 8, 8, 20, tzinfo=UTC)


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


def _base_command(key: str, *, branch_id: UUID | None = None) -> dict[str, Any]:
    return {
        "contract_version": "mcp-mutation-v1",
        "idempotency_key": key,
        "logical_session_id": None,
        "persona_id": _seed_identifier("personas", "persona_id"),
        "branch_id": branch_id or _seed_identifier("branches", "branch_id"),
        "reason": "Create deterministic synthetic retrieval acceptance data.",
    }


def _remember(key: str, statement: str, *, branch_id: UUID | None = None) -> RememberCommand:
    return RememberCommand(
        **_base_command(key, branch_id=branch_id),
        memory=MemoryInput(
            subject_id=_seed_identifier("subjects", "subject_id"),
            subject_kind=SubjectKind.GLOBAL,
            category=MemoryCategory.STABLE_FACT,
            ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
            scope=MemoryScope.GLOBAL,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement=statement,
            reason_to_remember="This record verifies hybrid retrieval behavior.",
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


def _success(response: MutationResponse) -> MutationResult:
    assert isinstance(response, MutationResult), response
    return response


def _filters(
    *,
    tenant_id: UUID | None = None,
    lineage_id: UUID | None = None,
    branch_id: UUID | None = None,
    statuses: frozenset[MemoryStatus] | None = None,
    subjects: frozenset[UUID] | None = None,
) -> RetrievalFilters:
    return RetrievalFilters(
        tenant_id=tenant_id or _seed_identifier("tenants", "tenant_id"),
        lineage_id=lineage_id or _seed_identifier("lineages", "lineage_id"),
        branch_id=branch_id or _seed_identifier("branches", "branch_id"),
        allowed_scopes=frozenset({MemoryScope.GLOBAL}),
        allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
        allowed_statuses=statuses or frozenset({MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}),
        max_sensitivity=0,
        requested_subject_ids=subjects,
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


async def _canonical_counts(database: Database) -> tuple[int, int, int, int, int]:
    async with database.tenant_session(_principal().tenant_id) as session:
        values = [
            int(await session.scalar(select(func.count()).select_from(model)) or 0)
            for model in (MemoryEvent, Memory, CommandReceipt, OutboxJob, MemoryEmbeddingV1)
        ]
        return cast(tuple[int, int, int, int, int], tuple(values))


async def test_immediate_lexical_trigram_hard_filters_and_conflict_expansion(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    principal = _principal()
    async with _seeded_engine(postgresql_server.database_url) as (database, engine):
        left = _success(
            await engine.execute(
                principal,
                _remember(
                    "retrieval-finch-left",
                    "Synthetic service Finch listens on port 4100.",
                ),
            )
        )
        right = _success(
            await engine.execute(
                principal,
                _remember(
                    "retrieval-finch-right",
                    "Synthetic service Finch listens on port 4200.",
                ),
            )
        )
        retired = _success(
            await engine.execute(
                principal,
                _remember(
                    "retrieval-retired-seed",
                    "RETIRED_MEMORY_CANARY is no longer current.",
                ),
            )
        )
        forgotten = _success(
            await engine.execute(
                principal,
                _remember(
                    "retrieval-forgotten-seed",
                    "TOMBSTONED_MEMORY_CANARY is no longer retrievable.",
                ),
            )
        )
        assert all(result.memory_id is not None for result in (left, right, retired, forgotten))
        left_id = left.memory_id
        right_id = right.memory_id
        retired_id = retired.memory_id
        forgotten_id = forgotten.memory_id
        assert left_id is not None
        assert right_id is not None
        assert retired_id is not None
        assert forgotten_id is not None

        # The write transaction has committed, but no worker has run and no vector exists.
        async with database.tenant_session(principal.tenant_id) as session:
            repository = RetrievalRepository(session)
            immediate = await repository.lexical_candidates(_filters(), "Finch 4100", 10)
            assert immediate
            assert immediate[0].memory_id == left_id
            assert {item.channel for item in immediate} == {"lexical"}
            assert await session.scalar(select(func.count()).select_from(MemoryEmbeddingV1)) == 0

            fuzzy = await repository.trigram_candidates(
                _filters(),
                "Synthetik servis Finsh listens port 4100",
                10,
            )
            assert fuzzy
            assert fuzzy[0].memory_id == left_id
            assert fuzzy[0].channel == "trigram"

        opened = _success(
            await engine.execute(
                principal,
                OpenConflictCommand(
                    **_base_command("retrieval-open-conflict"),
                    subject_id=_seed_identifier("subjects", "subject_id"),
                    members=(
                        MemoryRevisionExpectation(memory_id=left_id, expected_revision=1),
                        MemoryRevisionExpectation(memory_id=right_id, expected_revision=1),
                    ),
                    conflict_reason="Synthetic Finch port claims disagree.",
                    metadata={"fixture": True},
                ),
            )
        )
        assert opened.conflict_id is not None

        _success(
            await engine.execute(
                principal,
                RetireCommand(
                    **_base_command("retrieval-retire"),
                    memory_id=retired_id,
                    expected_revision=1,
                ),
            )
        )
        _success(
            await engine.execute(
                principal,
                ForgetCommand(
                    **_base_command("retrieval-forget"),
                    memory_id=forgotten_id,
                    expected_revision=1,
                    mode="logical",
                    confirmation="confirm_logical_forget",
                ),
            )
        )

        child_branch_id = new_uuid7()
        async with database.tenant_session(principal.tenant_id) as session:
            fork_sequence = await session.scalar(
                select(MemoryEvent.sequence).where(MemoryEvent.event_id == opened.event_id)
            )
            assert fork_sequence is not None
            session.add(
                Branch(
                    branch_id=child_branch_id,
                    tenant_id=principal.tenant_id,
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    parent_branch_id=_seed_identifier("branches", "branch_id"),
                    fork_event_sequence=fork_sequence,
                    name="synthetic-retrieval-child",
                    visibility_ceiling=MemoryVisibility.PRIVATE_ROOT.value,
                    created_at=_NOW,
                    sealed_at=None,
                )
            )
        child = _success(
            await engine.execute(
                principal,
                _remember(
                    "retrieval-child-canary",
                    "CHILD_BRANCH_PRIVATE_CANARY Finch branch isolation.",
                    branch_id=child_branch_id,
                ),
            )
        )
        assert child.memory_id is not None

        maximum_members = [
            _success(
                await engine.execute(
                    principal,
                    _remember(
                        f"retrieval-max-conflict-seed-{ordinal}",
                        f"Synthetic maximum conflict claim {ordinal}.",
                    ),
                )
            )
            for ordinal in range(32)
        ]
        maximum_member_ids = tuple(result.memory_id for result in maximum_members)
        assert all(memory_id is not None for memory_id in maximum_member_ids)
        maximum_conflict = _success(
            await engine.execute(
                principal,
                OpenConflictCommand(
                    **_base_command("retrieval-max-conflict"),
                    subject_id=_seed_identifier("subjects", "subject_id"),
                    members=tuple(
                        MemoryRevisionExpectation(
                            memory_id=cast(UUID, memory_id),
                            expected_revision=1,
                        )
                        for memory_id in maximum_member_ids
                    ),
                    conflict_reason="Exercise the maximum bounded conflict member count.",
                    metadata={"fixture": True},
                ),
            )
        )
        assert maximum_conflict.conflict_id is not None
        async with database.tenant_session(principal.tenant_id) as session:
            jobs = (
                await session.scalars(
                    select(OutboxJob).where(
                        OutboxJob.job_type == "embed_memory",
                        OutboxJob.aggregate_id.in_(maximum_member_ids),
                    )
                )
            ).all()
            revision_two_jobs = [
                job
                for job in jobs
                if job.payload.get("memory_version") == 2
                and job.payload.get("event_id") == str(maximum_conflict.event_id)
            ]
            assert len(revision_two_jobs) == 32
            assert {job.aggregate_id for job in revision_two_jobs} == set(maximum_member_ids)

        before_reads = await _canonical_counts(database)
        async with database.tenant_session(principal.tenant_id) as session:
            repository = RetrievalRepository(session)
            conflict_candidates = await repository.lexical_candidates(_filters(), "Finch", 10)
            conflict_ids = {item.memory_id for item in conflict_candidates}
            assert conflict_ids == {left_id, right_id}
            groups = await repository.open_conflict_members(_filters(), tuple(conflict_ids))
            assert set(groups) == {opened.conflict_id}
            group = groups[opened.conflict_id]
            assert set(group.visible_memory_ids) == {left_id, right_id}
            assert group.total_member_count == 2
            assert group.is_partial is False

            assert not await repository.lexical_candidates(_filters(), "RETIRED_MEMORY_CANARY", 10)
            assert not await repository.lexical_candidates(
                _filters(), "TOMBSTONED_MEMORY_CANARY", 10
            )
            assert not await repository.lexical_candidates(
                _filters(), "CHILD_BRANCH_PRIVATE_CANARY", 10
            )
            child_hits = await repository.lexical_candidates(
                _filters(branch_id=child_branch_id), "CHILD_BRANCH_PRIVATE_CANARY", 10
            )
            assert [item.memory_id for item in child_hits] == [child.memory_id]

            assert not await repository.lexical_candidates(
                _filters(tenant_id=retrieval_uuid(900)), "Finch", 10
            )
            assert not await repository.lexical_candidates(
                _filters(lineage_id=retrieval_uuid(901)), "Finch", 10
            )
            assert not await repository.lexical_candidates(
                _filters(subjects=frozenset({retrieval_uuid(902)})), "Finch", 10
            )
            assert not await repository.lexical_candidates(
                RetrievalFilters(
                    tenant_id=principal.tenant_id,
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    branch_id=_seed_identifier("branches", "branch_id"),
                    allowed_scopes=frozenset({MemoryScope.PROJECT}),
                    allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
                    allowed_statuses=frozenset({MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}),
                    max_sensitivity=0,
                ),
                "Finch",
                10,
            )
            assert not await repository.lexical_candidates(
                RetrievalFilters(
                    tenant_id=principal.tenant_id,
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    branch_id=_seed_identifier("branches", "branch_id"),
                    allowed_scopes=frozenset({MemoryScope.GLOBAL}),
                    allowed_visibilities=frozenset({MemoryVisibility.PUBLIC_SEED}),
                    allowed_statuses=frozenset({MemoryStatus.ACTIVE, MemoryStatus.DISPUTED}),
                    max_sensitivity=0,
                ),
                "Finch",
                10,
            )
        after_reads = await _canonical_counts(database)
        assert after_reads == before_reads
