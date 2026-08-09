"""PostgreSQL acceptance coverage for concurrent GitHub proposal ingestion."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.application.github_ingress import GitHubIngressOrchestrator
from kivra_memory.application.selection import SelectionEngine
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import AuthorityClass, IngressState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.ingress.github_client import GitHubProposalObject
from kivra_memory.policy import EvidenceKind, EvidenceTrust, SelectionBasis
from kivra_memory.storage.database import Database
from kivra_memory.storage.github_heads import (
    GITHUB_INGRESS_BOOTSTRAP_COMMIT,
    GITHUB_INGRESS_BOOTSTRAP_TREE,
    GitHubHeadStorageError,
    GitHubProviderHeadRepository,
    GitHubProviderIdentity,
)
from kivra_memory.storage.models import (
    CommandReceipt,
    IngressItem,
    Memory,
    MemoryEvent,
    MemoryEvidence,
    OutboxJob,
    SelectionDecision,
    Subject,
)
from kivra_memory.workers.github_ingress import (
    GitHubIngressIdentity,
    GitHubIngressWorker,
    GitHubIngressWorkItem,
    work_item_from_proposal,
)
from kivra_memory.workers.github_ingress_main import (
    GitHubIngressSettings,
    PinnedGitHubNominationResolver,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

from .conftest import AlembicRunner, PostgreSQLTestServer

_NOW = datetime(2026, 8, 9, 12, tzinfo=UTC)
_UUID_TIMESTAMP_MS = 1_786_276_800_000
_PROPOSAL_COUNT = 50


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _identifier(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_UUID_TIMESTAMP_MS, random_bits=ordinal)


def _identity() -> GitHubIngressIdentity:
    binding = seed_rows()["transport_bindings"][2]
    return GitHubIngressIdentity(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        installation_id=_seed_identifier("transport_installations", "installation_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        repository_id=12_345_678,
        branch_name="main",
    )


def _settings() -> GitHubIngressSettings:
    return GitHubIngressSettings(
        ingress_database_url="postgresql+psycopg://ingress@127.0.0.1/memory",
        command_database_url="postgresql+psycopg://api@127.0.0.1/memory",
        identity=_identity(),
        repository_owner="JTM-rootstorm",
        repository_name="scalevault-memory-ingress",
        ingress_prefix="ingress/v2",
        token="synthetic-not-a-token",
        allowed_selection_basis=SelectionBasis.ASSISTANT_OBSERVATION,
        authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
        evidence_kind=EvidenceKind.ASSISTANT_OBSERVATION,
        evidence_trust=EvidenceTrust.TRUSTED,
        bootstrap_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
        bootstrap_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
        promotion_actor_id=_identifier(950),
        promotion_client_id=_identifier(951),
        promotion_transport_binding_id=_identifier(952),
    )


def _source_evidence_key() -> str:
    identity = _identity()
    material = {
        "tenant_id": identity.tenant_id,
        "actor_id": identity.actor_id,
        "client_id": identity.client_id,
        "transport_binding_id": identity.transport_binding_id,
        "repository_id": identity.repository_id,
    }
    return f"github-proposal-source-v1:{hashlib.sha256(canonical_json_bytes(material)).hexdigest()}"


def _proposal_payload(
    ordinal: int,
    *,
    project_subject_id: UUID,
    sensitivity: int = 0,
    statement: str | None = None,
) -> dict[str, object]:
    proposal_id = _identifier(1_000 + ordinal)
    return {
        "schema_version": 2,
        "proposal_id": str(proposal_id),
        "installation_id": str(_identity().installation_id),
        "idempotency_key": f"github-acceptance:{ordinal}",
        "operation": "nominate",
        "persona_id": str(_seed_identifier("personas", "persona_id")),
        "branch_id": str(_seed_identifier("branches", "branch_id")),
        "subject_id": str(project_subject_id),
        "subject_kind": "project",
        "category": "emergent_tendency",
        "ontological_status": "observed_assistant_behavior",
        "scope": "project",
        # The shared synthetic root branch has the strict private-root ceiling.
        "visibility": "private_root",
        "statement": statement or f"Synthetic concurrent project observation {ordinal}.",
        "reason_to_remember": "Exercise the concurrent GitHub ingress acceptance gate.",
        "interpretation_limits": ["Synthetic integration-test data only."],
        "confidence": 0.9,
        "salience": 0.8,
        "durability": 0.7,
        "sensitivity": sensitivity,
        "valid_from": None,
        "valid_to": None,
        "observed_at": _NOW.isoformat().replace("+00:00", "Z"),
        "origin_session_id": None,
        "selection_basis": "assistant_observation",
        "epistemic_qualifiers": [],
        "evidence_references": [
            {
                "evidence_key": f"synthetic-project-source:{ordinal}",
                "opaque_reference": f"synthetic:project-source:{ordinal}",
            }
        ],
        "created_at": _NOW.isoformat().replace("+00:00", "Z"),
    }


def _work_item(
    ordinal: int,
    *,
    project_subject_id: UUID,
    sensitivity: int = 0,
    statement: str | None = None,
) -> GitHubIngressWorkItem:
    payload = _proposal_payload(
        ordinal,
        project_subject_id=project_subject_id,
        sensitivity=sensitivity,
        statement=statement,
    )
    raw_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    proposal_id = str(payload["proposal_id"])
    identity = _identity()
    proposal = GitHubProposalObject(
        repository_id=identity.repository_id,
        commit_id=f"{ordinal + 1:040x}",
        path=(f"ingress/v2/{identity.installation_id}/2026/08/{proposal_id}.json"),
        blob_id=f"{ordinal + 10_000:040x}",
        raw_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        raw_bytes=raw_bytes,
    )
    return work_item_from_proposal(proposal, identity=identity, discovered_at=_NOW)


def test_proposal_fixture_respects_the_seeded_branch_visibility_ceiling() -> None:
    payload = _proposal_payload(0, project_subject_id=_identifier(900))

    assert payload["visibility"] == seed_rows()["branches"][0]["visibility_ceiling"]


async def _seed(database: Database, *, project_subject_id: UUID) -> None:
    tenant_id = _seed_identifier("tenants", "tenant_id")
    async with database.tenant_session(tenant_id) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            await session.flush()
        session.add(
            Subject(
                subject_id=project_subject_id,
                tenant_id=tenant_id,
                lineage_id=_seed_identifier("lineages", "lineage_id"),
                kind="project",
                canonical_key="synthetic-ingress-acceptance-project",
                display_name="Synthetic Ingress Acceptance Project",
                persona_id=None,
                relationship_actor_id=None,
                project_ref="synthetic-ingress-acceptance",
                episode_ref=None,
                origin_session_id=None,
                metadata_={"fixture": True},
                created_at=_NOW,
            )
        )
        await session.flush()


async def _count(session: AsyncSession, model: type[object]) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


async def _canonical_counts(session: AsyncSession) -> dict[str, int]:
    return {
        "ingress": await _count(session, IngressItem),
        "events": await _count(session, MemoryEvent),
        "memories": await _count(session, Memory),
        "receipts": await _count(session, CommandReceipt),
        "decisions": await _count(session, SelectionDecision),
        "outbox": await _count(session, OutboxJob),
    }


async def test_fifty_proposals_are_atomic_idempotent_and_reject_sensitive_transport(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    """Exercise one real polled batch, duplicate delivery, and the sensitivity boundary."""

    _ = migrated_database
    database = Database(postgresql_server.database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    project_subject_id = _identifier(900)
    await _seed(database, project_subject_id=project_subject_id)
    factory = async_sessionmaker(database.engine, expire_on_commit=False)
    selection = SelectionEngine(factory, PinnedGitHubNominationResolver(_settings()))
    orchestrator = GitHubIngressOrchestrator(factory, selection, clock=lambda: _NOW)
    worker = GitHubIngressWorker(orchestrator, concurrency=8)
    items = tuple(
        _work_item(ordinal, project_subject_id=project_subject_id)
        for ordinal in range(_PROPOSAL_COUNT)
    )

    try:
        results = await worker.process_batch(items)
        assert len(results) == _PROPOSAL_COUNT
        safe_outcomes = Counter(
            (result.state.value, result.disposition, result.code) for result in results
        )
        assert {result.state for result in results} == {IngressState.ACCEPTED}, safe_outcomes
        assert {result.disposition for result in results} == {"terminal"}

        async with database.tenant_session(tenant_id) as session:
            accepted = (
                await session.scalars(
                    select(IngressItem)
                    .where(IngressItem.state == IngressState.ACCEPTED.value)
                    .order_by(IngressItem.immutable_path)
                )
            ).all()
            assert len(accepted) == _PROPOSAL_COUNT
            assert len({row.ingress_id for row in accepted}) == _PROPOSAL_COUNT
            assert len({row.result_event_id for row in accepted}) == _PROPOSAL_COUNT
            assert len({row.result_memory_id for row in accepted}) == _PROPOSAL_COUNT
            assert all(row.result_event_id is not None for row in accepted)
            assert all(row.result_memory_id is not None for row in accepted)

            decisions = (await session.scalars(select(SelectionDecision))).all()
            assert len(decisions) == _PROPOSAL_COUNT
            assert {row.source_kind for row in decisions} == {"github_proposal"}
            assert {row.outcome for row in decisions} == {"candidate"}
            assert {row.sensitivity for row in decisions} == {0}

            memories = (await session.scalars(select(Memory))).all()
            assert {row.status for row in memories} == {"candidate"}
            evidence = (await session.scalars(select(MemoryEvidence))).all()
            assert len(evidence) == _PROPOSAL_COUNT
            assert {cast(str, row.source_reference["evidence_key"]) for row in evidence} == {
                _source_evidence_key()
            }
            persisted_evidence = b"\n".join(
                json.dumps(row.source_reference, sort_keys=True).encode() for row in evidence
            )
            assert b"synthetic-project-source:" not in persisted_evidence
            assert b"synthetic:project-source:" not in persisted_evidence

            jobs = (await session.scalars(select(OutboxJob))).all()
            assert Counter(job.job_type for job in jobs) == {
                "embed_memory": _PROPOSAL_COUNT,
                "check_duplicates": _PROPOSAL_COUNT,
                "expire_candidate": _PROPOSAL_COUNT,
                "export_git_batch": _PROPOSAL_COUNT,
            }
            committed_counts = await _canonical_counts(session)
            assert committed_counts == {
                "ingress": _PROPOSAL_COUNT,
                "events": _PROPOSAL_COUNT,
                "memories": _PROPOSAL_COUNT,
                "receipts": _PROPOSAL_COUNT,
                "decisions": _PROPOSAL_COUNT,
                "outbox": _PROPOSAL_COUNT * 4,
            }

        first_replay, second_replay = await asyncio.gather(
            worker.process_batch(items),
            worker.process_batch(items),
        )
        for replay in (first_replay, second_replay):
            assert len(replay) == _PROPOSAL_COUNT
            assert {result.state for result in replay} == {IngressState.ACCEPTED}
            assert {result.disposition for result in replay} == {"unchanged"}

        async with database.tenant_session(tenant_id) as session:
            assert await _canonical_counts(session) == committed_counts

        sensitive = _work_item(
            999,
            project_subject_id=project_subject_id,
            sensitivity=1,
        )
        sensitive_result = (await worker.process_batch((sensitive,)))[0]
        assert sensitive_result.state is IngressState.QUARANTINED
        assert sensitive_result.disposition == "terminal"
        assert sensitive_result.code == "schema_invalid"

        async with database.tenant_session(tenant_id) as session:
            after_sensitive = await _canonical_counts(session)
            assert after_sensitive == {**committed_counts, "ingress": _PROPOSAL_COUNT + 1}
            sensitive_row = await session.get(IngressItem, sensitive.discovery.ingress_id)
            assert sensitive_row is not None
            assert sensitive_row.state == IngressState.QUARANTINED.value
            assert sensitive_row.error_code == "schema_invalid"
            assert sensitive_row.result_event_id is None
            assert sensitive_row.result_memory_id is None
    finally:
        await database.dispose()


async def test_repeated_same_source_candidate_does_not_self_promote_or_persist_hostile_refs(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    project_subject_id = _identifier(901)
    await _seed(database, project_subject_id=project_subject_id)
    factory = async_sessionmaker(database.engine, expire_on_commit=False)
    selection = SelectionEngine(factory, PinnedGitHubNominationResolver(_settings()))
    worker = GitHubIngressWorker(
        GitHubIngressOrchestrator(factory, selection, clock=lambda: _NOW),
        concurrency=2,
    )
    statement = "Synthetic repeated observation from one pinned GitHub source."
    items = tuple(
        _work_item(
            ordinal,
            project_subject_id=project_subject_id,
            statement=statement,
        )
        for ordinal in (701, 702)
    )

    try:
        first = (await worker.process_batch((items[0],)))[0]
        second = (await worker.process_batch((items[1],)))[0]

        assert first.state is IngressState.ACCEPTED
        assert second.state is IngressState.DUPLICATE
        assert first.ingress_id != second.ingress_id
        async with database.tenant_session(tenant_id) as session:
            memories = (await session.scalars(select(Memory))).all()
            evidence = (await session.scalars(select(MemoryEvidence))).all()
            events = (await session.scalars(select(MemoryEvent))).all()
            receipts = (await session.scalars(select(CommandReceipt))).all()
            ingress = (
                await session.scalars(select(IngressItem).order_by(IngressItem.immutable_path))
            ).all()

        assert len(memories) == 1
        assert memories[0].status == "candidate"
        assert memories[0].revision == 1
        assert len(evidence) == 1
        assert evidence[0].source_reference == {"evidence_key": _source_evidence_key()}
        assert [event.operation for event in events] == ["observed"]
        assert all(event.operation != "candidate_promoted" for event in events)
        assert {row.state for row in ingress} == {"accepted", "duplicate"}
        assert len({row.result_memory_id for row in ingress}) == 1
        persisted = b"\n".join(
            [
                *(json.dumps(row.source_reference, sort_keys=True).encode() for row in evidence),
                *(bytes(event.payload_canonical) for event in events),
                *(bytes(receipt.result_canonical) for receipt in receipts),
            ]
        )
        assert b"synthetic-project-source:" not in persisted
        assert b"synthetic:project-source:" not in persisted
    finally:
        await database.dispose()


async def test_checkpoint_cas_failure_after_terminalization_replays_without_duplicates(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: AlembicRunner,
) -> None:
    _ = migrated_database
    database = Database(postgresql_server.database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    project_subject_id = _identifier(902)
    await _seed(database, project_subject_id=project_subject_id)
    factory = async_sessionmaker(database.engine, expire_on_commit=False)
    selection = SelectionEngine(factory, PinnedGitHubNominationResolver(_settings()))
    worker = GitHubIngressWorker(GitHubIngressOrchestrator(factory, selection, clock=lambda: _NOW))
    item = _work_item(801, project_subject_id=project_subject_id)
    identity = _identity()
    provider_identity = GitHubProviderIdentity(
        tenant_id=identity.tenant_id,
        installation_id=identity.installation_id,
        transport_binding_id=identity.transport_binding_id,
        repository_id=identity.repository_id,
        branch_name=identity.branch_name,
    )
    heads = GitHubProviderHeadRepository()

    try:
        terminal = (await worker.process_batch((item,)))[0]
        assert terminal.state is IngressState.ACCEPTED
        assert terminal.disposition == "terminal"

        async with database.tenant_session(tenant_id) as session:
            await heads.load_or_create(session, provider_identity)
            committed_counts = await _canonical_counts(session)
        async with database.tenant_session(tenant_id) as session:
            await heads.advance(
                session,
                provider_identity,
                expected_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                expected_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                commit_id="a" * 40,
                tree_id="b" * 40,
                etag='"winner"',
            )
        with pytest.raises(GitHubHeadStorageError, match="verified_head_race"):
            async with database.tenant_session(tenant_id) as session:
                await heads.advance(
                    session,
                    provider_identity,
                    expected_commit_id=GITHUB_INGRESS_BOOTSTRAP_COMMIT,
                    expected_tree_id=GITHUB_INGRESS_BOOTSTRAP_TREE,
                    commit_id="c" * 40,
                    tree_id="d" * 40,
                    etag='"stale"',
                )

        replay = (await worker.process_batch((item,)))[0]
        assert replay.state is IngressState.ACCEPTED
        assert replay.disposition == "unchanged"
        async with database.tenant_session(tenant_id) as session:
            assert await _canonical_counts(session) == committed_counts
    finally:
        await database.dispose()
