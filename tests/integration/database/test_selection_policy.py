"""PostgreSQL acceptance coverage for policy-gated memory selection."""

from __future__ import annotations

import shutil
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.api.mcp import NominationWireRequest
from kivra_memory.application import (
    CandidateLifecycleEngine,
    CandidateLifecycleExecutionError,
    CommandPrincipal,
    MutationEngine,
    ResolvedNominationContext,
    SelectionEngine,
    SelectionExecutionError,
)
from kivra_memory.application.sealed_content import (
    HmacSha256SealedDigestBinder,
    SealedContentRequest,
)
from kivra_memory.domain.commands import CandidateExpiryCommand, ForgetCommand, MutationResult
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
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import (
    EvidenceKind,
    EvidenceSummary,
    EvidenceTrust,
    NominationEvidenceReference,
    NominationProposal,
    SelectionBasis,
)
from kivra_memory.security.destruction_ledger import (
    LocalDestructionLedger,
    initialize_empty_destruction_ledger_anchor,
)
from kivra_memory.security.keys import ContentKeyReference, KeyProviderError
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyProvider,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    Actor,
    Client,
    CommandReceipt,
    Memory,
    MemoryContentKey,
    MemoryEvent,
    MemoryEvidence,
    OutboxJob,
    SelectionDecision,
    TransportBinding,
)
from kivra_memory.storage.outbox_worker import claim_outbox_jobs
from kivra_memory.storage.selection_history import (
    SelectionHistoryFilters,
    SelectionHistoryRepository,
)
from kivra_memory.workers.sealed_content import handle_purge_payload_job
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 8, 18, tzinfo=UTC)
_UUID_TIMESTAMP_MS = 1_786_000_000_000


class PostgreSQLTestServer(Protocol):
    database_url: str


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _identifier(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_UUID_TIMESTAMP_MS, random_bits=ordinal)


def _principal(*, binding_index: int = 0) -> CommandPrincipal:
    binding = seed_rows()["transport_bindings"][binding_index]
    return CommandPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=frozenset({"memory:write"}),
    )


def _proposal(
    *,
    statement: str,
    basis: SelectionBasis,
    category: MemoryCategory,
    ontology: OntologicalStatus,
) -> NominationProposal:
    return NominationProposal(
        subject_id=_seed_identifier("subjects", "subject_id"),
        subject_kind=SubjectKind.GLOBAL,
        category=category,
        ontological_status=ontology,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        statement=statement,
        reason_to_remember="Synthetic database acceptance coverage for selection policy.",
        interpretation_limits=(),
        confidence=Decimal("0.9"),
        salience=Decimal("0.8"),
        durability=Decimal("0.8"),
        sensitivity=0,
        observed_at=_NOW,
        metadata={"fixture": True},
        selection_basis=basis,
        epistemic_qualifiers=(),
        evidence_references=(
            NominationEvidenceReference(
                evidence_key="opaque-fixture-evidence",
                opaque_reference="synthetic:opaque-reference",
            ),
        ),
    )


def _command(
    key: str,
    proposal: NominationProposal,
) -> NominationWireRequest:
    return NominationWireRequest(
        contract_version="mcp-mutation-v2",
        idempotency_key=key,
        persona_id=_seed_identifier("personas", "persona_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        reason="Exercise a synthetic selection-policy transaction.",
        proposal=proposal,
    )


def _active_context() -> ResolvedNominationContext:
    return ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.EXPLICIT_USER_CORRECTION,
        evidence=(
            EvidenceSummary(
                evidence_key="correction:one",
                kind=EvidenceKind.USER_CORRECTION,
                trust=EvidenceTrust.TRUSTED,
            ),
        ),
    )


def _candidate_context(key: str) -> ResolvedNominationContext:
    return ResolvedNominationContext(
        source_kind="live_interaction",
        effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
        evidence=(
            EvidenceSummary(
                evidence_key=key,
                kind=EvidenceKind.ASSISTANT_OBSERVATION,
                trust=EvidenceTrust.TRUSTED,
            ),
        ),
    )


async def _count(session: AsyncSession, model: type[object]) -> int:
    return int(await session.scalar(select(func.count()).select_from(model)) or 0)


@asynccontextmanager
async def _seeded_database(database_url: str) -> AsyncIterator[Database]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_principal().tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
        yield database
    finally:
        await database.dispose()


async def _internal_principal(database: Database) -> CommandPrincipal:
    """Seed a test-local internal service identity; shared fixtures stay generic."""

    tenant_id = _principal().tenant_id
    actor_id = _identifier(700)
    client_id = _identifier(701)
    binding_id = _identifier(702)
    async with database.tenant_session(tenant_id) as session:
        session.add_all(
            (
                Actor(
                    actor_id=actor_id,
                    tenant_id=tenant_id,
                    handle="synthetic-policy-worker",
                    display_name="Synthetic Policy Worker",
                    kind="service",
                    metadata_={"fixture": True},
                    created_at=_NOW,
                    revoked_at=None,
                ),
                Client(
                    client_id=client_id,
                    tenant_id=tenant_id,
                    public_id="synthetic-policy-worker",
                    display_name="Synthetic Policy Worker",
                    kind="worker",
                    transport_kind="internal_service",
                    scopes=["memory.lifecycle.promote", "memory.lifecycle.expire"],
                    capability_profile={"fixture": True},
                    created_at=_NOW,
                    revoked_at=None,
                ),
                TransportBinding(
                    transport_binding_id=binding_id,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    client_id=client_id,
                    transport_kind="internal_service",
                    disclosure_boundary="internal",
                    installation_id=None,
                    authorized_operations={
                        "operations": [
                            EventOperation.CANDIDATE_PROMOTED.value,
                            EventOperation.CANDIDATE_EXPIRED.value,
                        ]
                    },
                    created_at=_NOW,
                    valid_until=None,
                ),
            )
        )
        await session.flush()
    return CommandPrincipal(
        tenant_id=tenant_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        scopes=frozenset({"memory.lifecycle.promote", "memory.lifecycle.expire"}),
    )


async def test_selection_persists_atomic_active_candidate_and_omit_receipts(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    principal = _principal()
    active = _command(
        "selection-active",
        _proposal(
            statement="Synthetic active correction.",
            basis=SelectionBasis.EXPLICIT_USER_CORRECTION,
            category=MemoryCategory.STABLE_FACT,
            ontology=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        ),
    )
    candidate = _command(
        "selection-candidate",
        _proposal(
            statement="Synthetic candidate observation.",
            basis=SelectionBasis.ASSISTANT_OBSERVATION,
            category=MemoryCategory.EMERGENT_TENDENCY,
            ontology=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
        ),
    )
    omit = _command(
        "selection-omit",
        _proposal(
            statement="Synthetic routine banter.",
            basis=SelectionBasis.ROUTINE_BANTER,
            category=MemoryCategory.EMERGENT_TENDENCY,
            ontology=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
        ),
    )

    async with _seeded_database(postgresql_server.database_url) as database:
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        active_engine = SelectionEngine(factory, lambda *_: _return(_active_context()))
        candidate_engine = SelectionEngine(
            factory, lambda *_: _return(_candidate_context("observation:one"))
        )
        omit_engine = SelectionEngine(
            factory,
            lambda *_: _return(
                ResolvedNominationContext(
                    source_kind="live_interaction",
                    effective_authority_class=AuthorityClass.ASSISTANT_OBSERVATION,
                )
            ),
        )

        active_result = await active_engine.execute(principal, active)
        candidate_result = await candidate_engine.execute(principal, candidate)
        omit_result = await omit_engine.execute(principal, omit)
        replay = await omit_engine.execute(principal, omit)

        assert active_result.outcome == "active"
        assert candidate_result.outcome == "candidate"
        assert omit_result.outcome == "omit"
        assert omit_result.event_id is None
        assert omit_result.memory_id is None
        assert omit_result.revision is None
        assert replay.idempotent_replay is True
        assert replay.receipt_id == omit_result.receipt_id
        with pytest.raises(SelectionExecutionError, match="idempotency_key_reused"):
            await omit_engine.execute(
                principal,
                omit.model_copy(update={"reason": "Changed command under the same key."}),
            )

        async with database.tenant_session(principal.tenant_id) as session:
            assert await _count(session, MemoryEvent) == 2
            assert await _count(session, Memory) == 2
            assert await _count(session, MemoryEvidence) == 2
            assert await _count(session, SelectionDecision) == 3
            assert await _count(session, CommandReceipt) == 3
            assert await _count(session, OutboxJob) == 7
            stored_candidate = await session.scalar(
                select(Memory).where(Memory.memory_id == candidate_result.memory_id)
            )
            assert stored_candidate is not None
            assert stored_candidate.status == MemoryStatus.CANDIDATE.value
            assert stored_candidate.candidate_expires_at is not None


async def test_duplicate_candidate_promotion_uses_internal_identity_and_rolls_back_bad_provider(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    principal = _principal()
    proposal = _proposal(
        statement="Synthetic duplicate candidate for policy promotion.",
        basis=SelectionBasis.ASSISTANT_OBSERVATION,
        category=MemoryCategory.EMERGENT_TENDENCY,
        ontology=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
    )

    async with _seeded_database(postgresql_server.database_url) as database:
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        internal = await _internal_principal(database)
        first = _command("promotion-candidate", proposal)
        second = _command("promotion-second-evidence", proposal)
        initial_engine = SelectionEngine(
            factory, lambda *_: _return(_candidate_context("observation:one"))
        )
        initial = await initial_engine.execute(principal, first)
        assert initial.outcome == "candidate"

        no_provider = SelectionEngine(
            factory, lambda *_: _return(_candidate_context("observation:two"))
        )
        with pytest.raises(SelectionExecutionError, match="authority_unavailable"):
            await no_provider.execute(principal, second)
        bad_provider = SelectionEngine(
            factory,
            lambda *_: _return(_candidate_context("observation:two")),
            promotion_principal_provider=lambda *_: _return(principal),
        )
        with pytest.raises(SelectionExecutionError, match="authority_unavailable"):
            await bad_provider.execute(principal, second)

        promoting = SelectionEngine(
            factory,
            lambda *_: _return(_candidate_context("observation:two")),
            promotion_principal_provider=lambda *_: _return(
                internal.model_copy(update={"scopes": frozenset({"memory.lifecycle.promote"})})
            ),
        )
        promoted = await promoting.execute(principal, second)
        assert promoted.outcome == "promoted"
        assert promoted.memory_id == initial.memory_id

        async with database.tenant_session(principal.tenant_id) as session:
            assert await _count(session, MemoryEvent) == 2
            assert await _count(session, MemoryEvidence) == 2
            assert await _count(session, SelectionDecision) == 2
            assert await _count(session, CommandReceipt) == 2
            event = await session.scalar(
                select(MemoryEvent).where(MemoryEvent.event_id == promoted.event_id)
            )
            assert event is not None
            assert event.operation == EventOperation.CANDIDATE_PROMOTED.value
            assert (event.actor_id, event.client_id, event.transport_binding_id) == (
                internal.actor_id,
                internal.client_id,
                internal.transport_binding_id,
            )
            assert event.session_id is None
            assert event.ingress_id is None
            receipt = await session.scalar(
                select(CommandReceipt).where(CommandReceipt.receipt_id == promoted.receipt_id)
            )
            decision = await session.scalar(
                select(SelectionDecision).where(
                    SelectionDecision.decision_id == promoted.decision_id
                )
            )
            assert receipt is not None and decision is not None
            assert receipt.client_id == principal.client_id
            assert decision.actor_id == principal.actor_id
            assert decision.client_id == principal.client_id
            jobs = (await session.scalars(select(OutboxJob).order_by(OutboxJob.job_id))).all()
            assert Counter(job.job_type for job in jobs) == Counter(
                {
                    "embed_memory": 2,
                    "check_duplicates": 1,
                    "expire_candidate": 1,
                    "export_git_batch": 2,
                }
            )


async def test_expiry_is_internal_idempotent_and_keeps_authorized_audit_history(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    nominator = _principal()
    proposal = _proposal(
        statement="Synthetic expiry candidate.",
        basis=SelectionBasis.ASSISTANT_OBSERVATION,
        category=MemoryCategory.EMERGENT_TENDENCY,
        ontology=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
    )
    async with _seeded_database(postgresql_server.database_url) as database:
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        internal = await _internal_principal(database)
        candidate = await SelectionEngine(
            factory, lambda *_: _return(_candidate_context("expiry-observation"))
        ).execute(nominator, _command("expiry-candidate", proposal))
        assert candidate.memory_id is not None and candidate.revision is not None
        async with database.tenant_session(nominator.tenant_id) as session:
            candidate_deadline = await session.scalar(
                select(Memory.candidate_expires_at).where(Memory.memory_id == candidate.memory_id)
            )
        assert candidate_deadline is not None
        lifecycle = CandidateLifecycleEngine(factory)
        command = CandidateExpiryCommand(
            memory_id=candidate.memory_id,
            expected_revision=candidate.revision,
            selection_decision_id=candidate.decision_id,
            policy_rule_code="candidate_expired",
        )
        expired = await lifecycle.expire(
            internal.model_copy(update={"scopes": frozenset({"memory.lifecycle.expire"})}),
            command,
            now=candidate_deadline,
        )
        assert expired.action == "expired"
        replay = await lifecycle.expire(
            internal.model_copy(update={"scopes": frozenset({"memory.lifecycle.expire"})}),
            command,
            now=candidate_deadline,
        )
        assert replay.action == "no_op"
        assert replay.reason_code == "stale_revision"

        async with database.tenant_session(nominator.tenant_id) as session:
            memory = await session.scalar(
                select(Memory).where(Memory.memory_id == candidate.memory_id)
            )
            assert memory is not None
            assert memory.status == MemoryStatus.RETIRED.value
            assert memory.candidate_expires_at is None
            assert await _count(session, MemoryEvent) == 2
            assert await _count(session, SelectionDecision) == 2
            assert await _count(session, OutboxJob) == 6
            history = await SelectionHistoryRepository(session).list_decisions(
                SelectionHistoryFilters(
                    tenant_id=nominator.tenant_id,
                    persona_id=_seed_identifier("personas", "persona_id"),
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    branch_id=_seed_identifier("branches", "branch_id"),
                    allowed_scopes=frozenset({MemoryScope.GLOBAL}),
                    allowed_visibilities=frozenset({MemoryVisibility.PRIVATE_ROOT}),
                    max_sensitivity=0,
                )
            )
            assert [record.outcome for record in history] == ["expired", "candidate"]
            assert all(record.memory_id == candidate.memory_id for record in history)


async def test_lifecycle_rejects_direct_relay_and_cross_tenant_principals(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    nominator = _principal()
    proposal = _proposal(
        statement="Synthetic lifecycle authorization candidate.",
        basis=SelectionBasis.ASSISTANT_OBSERVATION,
        category=MemoryCategory.EMERGENT_TENDENCY,
        ontology=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
    )
    async with _seeded_database(postgresql_server.database_url) as database:
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        candidate = await SelectionEngine(
            factory, lambda *_: _return(_candidate_context("authorization-observation"))
        ).execute(nominator, _command("authorization-candidate", proposal))
        assert candidate.memory_id is not None and candidate.revision is not None
        command = CandidateExpiryCommand(
            memory_id=candidate.memory_id,
            expected_revision=candidate.revision,
            selection_decision_id=candidate.decision_id,
            policy_rule_code="candidate_expired",
        )
        lifecycle = CandidateLifecycleEngine(factory)
        direct = nominator.model_copy(update={"scopes": frozenset({"memory.lifecycle.expire"})})
        relay = _principal(binding_index=1).model_copy(
            update={"scopes": frozenset({"memory.lifecycle.expire"})}
        )
        foreign = direct.model_copy(update={"tenant_id": _identifier(900)})
        for principal in (direct, relay, foreign):
            with pytest.raises(CandidateLifecycleExecutionError, match="forbidden"):
                await lifecycle.expire(principal, command, now=_NOW + timedelta(days=181))

        async with database.tenant_session(nominator.tenant_id) as session:
            assert await _count(session, MemoryEvent) == 1
            assert await _count(session, SelectionDecision) == 1
            stored = await session.scalar(
                select(Memory).where(Memory.memory_id == candidate.memory_id)
            )
            assert stored is not None
            assert stored.status == MemoryStatus.CANDIDATE.value


async def _return(value: Any) -> Any:
    return value


def _sealed_provider_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    provider_root = tmp_path / "keys"
    provider_root.mkdir(mode=0o710)
    provider_root.chmod(0o2710)
    for name in (CONTROL_DIRECTORY_NAME, MATERIAL_DIRECTORY_NAME):
        directory = provider_root / name
        directory.mkdir(mode=0o770)
        directory.chmod(0o2770)
    ledger_root = tmp_path / "destruction-ledger"
    ledger_root.mkdir(mode=0o770)
    ledger_root.chmod(0o2770)
    anchor_parent = tmp_path / "destruction-anchor"
    anchor_parent.mkdir(mode=0o770)
    anchor_parent.chmod(0o2770)
    anchor_path = anchor_parent / "current.json"
    initialize_empty_destruction_ledger_anchor(ledger_root, anchor_path)
    return provider_root, ledger_root, anchor_path


async def test_real_sealed_purge_and_stale_key_backup_restore_never_resurrects_dek(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
    tmp_path: Path,
) -> None:
    """Exercise PostgreSQL lifecycle, real purge, and backup-dominating ledger."""

    _ = migrated_database
    principal = _principal()
    canary = "synthetic-private-canary-never-in-plaintext-columns"
    proposal = _proposal(
        statement=canary,
        basis=SelectionBasis.EXPLICIT_USER_CORRECTION,
        category=MemoryCategory.STABLE_FACT,
        ontology=OntologicalStatus.LITERAL_TECHNICAL_FACT,
    ).model_copy(update={"sensitivity": 4})
    command = _command("sealed-hard-forget-backup-recovery", proposal).model_copy(
        update={
            "sealed_content": SealedContentRequest(
                safe_summary="A reviewed synthetic private record."
            )
        }
    )
    provider_root, ledger_root, anchor_path = _sealed_provider_layout(tmp_path / "live")
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )

    async with _seeded_database(postgresql_server.database_url) as database:
        factory = async_sessionmaker(database.engine, expire_on_commit=False)
        selection = SelectionEngine(
            factory,
            lambda *_: _return(_active_context()),
            key_provider=provider,
            sealed_digest_binder=HmacSha256SealedDigestBinder(b"b" * 32),
        )
        selected = await selection.execute(principal, command)
        assert selected.outcome == "active"
        assert selected.memory_id is not None

        async with database.tenant_session(principal.tenant_id) as session:
            row = await session.get(Memory, selected.memory_id)
            assert row is not None
            assert row.statement is None
            assert row.reason_to_remember is None
            assert row.content_key_id is not None
            content_key_id = row.content_key_id
            key_row = await session.get(MemoryContentKey, content_key_id)
            assert key_row is not None
            provider_reference = (
                key_row.provider_name,
                key_row.provider_key_reference,
            )
            event_payloads = (await session.scalars(select(MemoryEvent.payload))).all()
            assert canary not in str(event_payloads)

        backup_root = tmp_path / "pre-forget-backup" / "keys"
        backup_root.parent.mkdir()
        shutil.copytree(provider_root, backup_root)

        mutation = MutationEngine(factory)
        forgotten = await mutation.execute(
            principal,
            ForgetCommand(
                contract_version="mcp-mutation-v1",
                idempotency_key="sealed-hard-forget-backup-recovery:forget",
                logical_session_id=None,
                persona_id=_seed_identifier("personas", "persona_id"),
                branch_id=_seed_identifier("branches", "branch_id"),
                reason="Exercise real sealed hard forget and backup recovery.",
                memory_id=selected.memory_id,
                expected_revision=1,
                mode="hard",
                confirmation="confirm_hard_forget",
            ),
        )
        assert isinstance(forgotten, MutationResult)
        assert forgotten.forget_state == "purge_pending"

        purge_principal = principal.model_copy(
            update={"scopes": frozenset({"memory.lifecycle.purge"})}
        )
        async with database.tenant_session(principal.tenant_id) as session:
            jobs = await claim_outbox_jobs(
                session,
                tenant_id=principal.tenant_id,
                worker_owner="sealed-backup-acceptance",
                job_types=("purge_payload",),
            )
            assert len(jobs) == 1
            purged = await handle_purge_payload_job(
                session,
                job=jobs[0],
                principal=purge_principal,
                key_destroyer=provider,
            )
            assert purged.outcome == "purged"

        async with database.tenant_session(principal.tenant_id) as session:
            row = await session.get(Memory, selected.memory_id)
            key_row = await session.get(MemoryContentKey, content_key_id)
            assert row is not None and row.content_protection == "cryptographically_erased"
            assert key_row is not None and key_row.state == "destroyed"
            assert key_row.destruction_receipt_sha256 is not None
            event_payloads = (await session.scalars(select(MemoryEvent.payload))).all()
            assert canary not in str(event_payloads)

        restored_root = tmp_path / "restore" / "keys"
        restored_root.parent.mkdir()
        shutil.copytree(backup_root, restored_root)
        stale_material = restored_root / MATERIAL_DIRECTORY_NAME / f"key-{content_key_id}.bin"
        assert stale_material.is_file()
        ledger = LocalDestructionLedger(ledger_root, anchor_path=anchor_path)
        current_anchor = ledger.anchor()
        ledger.require_anchor(current_anchor)
        restored = LocalDirectoryKeyProvider(
            restored_root,
            destruction_ledger_root=ledger_root,
            destruction_ledger_anchor_path=anchor_path,
        )
        assert not stale_material.exists()
        restored_reference = ContentKeyReference(
            content_key_id=content_key_id,
            provider_name=provider_reference[0],
            provider_key_reference=provider_reference[1],
        )
        with pytest.raises(KeyProviderError):
            await restored.get_key(restored_reference)
