from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.admin import CredentialAdminService, IssuedBearerCredential
from kivra_memory.api.mcp import NominationWireRequest
from kivra_memory.application import (
    CommandPrincipal,
    MutationEngine,
    SelectionEngine,
    SelectionResult,
)
from kivra_memory.application.authentication import BearerAuthenticator
from kivra_memory.auth import (
    AuthenticatedRequestIdentity,
    BearerAuthenticationError,
    BearerTokenCodec,
    BearerTokenHasher,
    ClientCapabilityProfile,
    RequestTransportIdentity,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.commands import (
    MemoryChanges,
    MutationError,
    MutationResult,
    ReviseCommand,
    StaleRevisionDetails,
)
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
    TransportKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.policy import NominationEvidenceReference, NominationProposal, SelectionBasis
from kivra_memory.runtime import DirectNominationResolver
from kivra_memory.storage.credentials import (
    CredentialAdminStorageRepository,
    CredentialRepository,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    CommandReceipt,
    LogicalSession,
    Memory,
    MemoryEvent,
    MemoryEvidence,
    OutboxJob,
    SelectionDecision,
    Subject,
    TransportBinding,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_NOW = datetime(2026, 8, 9, 15, tzinfo=UTC)
_AUTHENTICATED_AT = _NOW + timedelta(minutes=1)
_REVOKED_AT = _NOW + timedelta(minutes=2)
_UUID_TIMESTAMP_MS = 1_786_291_200_000
_HASH_KEY_ID = "synthetic-m7-pepper-v1"
_TOKEN_PEPPER = bytes(range(32))
_DIRECT_TRANSPORT = RequestTransportIdentity(
    transport_kind=TransportKind.DIRECT_PRIVATE,
    installation_id=None,
)


class PostgreSQLTestServer(Protocol):
    database_url: str


@dataclass(frozen=True, slots=True)
class _CodexRuntime:
    database: Database
    session_factory: async_sessionmaker[AsyncSession]
    admin_repository: CredentialAdminStorageRepository
    credentials: tuple[IssuedBearerCredential, IssuedBearerCredential]
    identities: tuple[AuthenticatedRequestIdentity, AuthenticatedRequestIdentity]
    subject_ids: tuple[UUID, UUID]


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _identifier(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_UUID_TIMESTAMP_MS, random_bits=ordinal)


def _attestation_evidence_key(identity: AuthenticatedRequestIdentity) -> str:
    status = identity.status_identity
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "tenant_id": status.tenant_id,
                "actor_id": status.actor_id,
                "client_id": status.client_id,
                "transport_binding_id": status.transport_binding_id,
            }
        )
    ).hexdigest()
    return f"direct-client-observation-v1:{digest}"


def _subject(subject_id: UUID, ordinal: int) -> Subject:
    return Subject(
        subject_id=subject_id,
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        lineage_id=_seed_identifier("lineages", "lineage_id"),
        kind=SubjectKind.PERSONA.value,
        canonical_key=f"synthetic-codex-m7-subject-{ordinal}",
        display_name=f"Synthetic Codex M7 Subject {ordinal}",
        persona_id=_seed_identifier("personas", "persona_id"),
        relationship_actor_id=None,
        project_ref=None,
        episode_ref=None,
        origin_session_id=None,
        metadata_={"fixture": True},
        created_at=_NOW,
    )


def _nomination(
    *,
    key: str,
    subject_id: UUID,
    statement: str,
    logical_session_id: UUID | None = None,
) -> NominationWireRequest:
    return NominationWireRequest(
        contract_version="mcp-mutation-v2",
        idempotency_key=key,
        logical_session_id=logical_session_id,
        persona_id=_seed_identifier("personas", "persona_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        reason="Exercise synthetic Codex Milestone 7 acceptance behavior.",
        proposal=NominationProposal(
            subject_id=subject_id,
            subject_kind=SubjectKind.PERSONA,
            category=MemoryCategory.EMERGENT_TENDENCY,
            ontological_status=OntologicalStatus.OBSERVED_ASSISTANT_BEHAVIOR,
            scope=MemoryScope.PERSONA,
            visibility=MemoryVisibility.PRIVATE_ROOT,
            statement=statement,
            reason_to_remember="Retain a synthetic candidate only for acceptance testing.",
            interpretation_limits=("Synthetic integration-test data only.",),
            confidence=Decimal("0.800000"),
            salience=Decimal("0.700000"),
            durability=Decimal("0.600000"),
            sensitivity=0,
            observed_at=_NOW,
            metadata={"fixture": True},
            selection_basis=SelectionBasis.ASSISTANT_OBSERVATION,
            epistemic_qualifiers=(),
            evidence_references=(),
        ),
    )


def _routine_banter_nomination(*, key: str, subject_id: UUID, canary: str) -> NominationWireRequest:
    candidate = _nomination(
        key=key,
        subject_id=subject_id,
        statement=canary,
    )
    return candidate.model_copy(
        update={
            "proposal": candidate.proposal.model_copy(
                update={
                    "selection_basis": SelectionBasis.ROUTINE_BANTER,
                    "evidence_references": (),
                }
            )
        }
    )


def _hostile_evidence_nomination(
    *, key: str, subject_id: UUID, evidence_key: str, opaque_reference: str
) -> NominationWireRequest:
    candidate = _nomination(
        key=key,
        subject_id=subject_id,
        statement="Synthetic candidate with an untrusted evidence assertion.",
    )
    return candidate.model_copy(
        update={
            "proposal": candidate.proposal.model_copy(
                update={
                    "evidence_references": (
                        NominationEvidenceReference(
                            evidence_key=evidence_key,
                            opaque_reference=opaque_reference,
                        ),
                    )
                }
            )
        }
    )


def _legacy_revision_principal() -> CommandPrincipal:
    """Use the explicit test-only legacy binding until policy-safe revision exists."""

    binding = seed_rows()["transport_bindings"][0]
    return CommandPrincipal(
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        actor_id=cast(UUID, binding["actor_id"]),
        client_id=cast(UUID, binding["client_id"]),
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        scopes=frozenset({"memory.write.legacy_v1", "memory.write.revise"}),
        ingress_id=None,
    )


def _revision(memory_id: UUID, *, key: str, statement: str) -> ReviseCommand:
    return ReviseCommand(
        contract_version="mcp-mutation-v1",
        idempotency_key=key,
        logical_session_id=None,
        persona_id=_seed_identifier("personas", "persona_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        reason="Compete for one synthetic expected revision.",
        memory_id=memory_id,
        expected_revision=1,
        changes=MemoryChanges(statement=statement),
    )


@asynccontextmanager
async def _seeded_codex_runtime(database_url: str) -> AsyncIterator[_CodexRuntime]:
    database = Database(database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    subject_ids = (_identifier(101), _identifier(102))
    try:
        async with database.tenant_session(tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            session.add_all(
                (_subject(subject_ids[0], 1), _subject(subject_ids[1], 2))
            )
            await session.flush()

        session_factory = database.session_factory
        admin_repository = CredentialAdminStorageRepository(session_factory)
        admin = CredentialAdminService(
            admin_repository,
            token_pepper=_TOKEN_PEPPER,
            secret_hash_key_id=_HASH_KEY_ID,
            now=lambda: _NOW,
        )
        capability = ClientCapabilityProfile(
            contract_version="scalevault-client-capability-v1",
            read=None,
        )
        first, second = await asyncio.gather(
            admin.create(
                tenant_id=tenant_id,
                host_label="host-a",
                environment_label="integration",
                scopes=("memory.write.nominate",),
                capability_profile=capability,
            ),
            admin.create(
                tenant_id=tenant_id,
                host_label="host-b",
                environment_label="integration",
                scopes=("memory.write.nominate",),
                capability_profile=capability,
            ),
        )
        authenticator = BearerAuthenticator(
            CredentialRepository(session_factory),
            hashers={_HASH_KEY_ID: BearerTokenHasher(_TOKEN_PEPPER)},
            clock=lambda: _AUTHENTICATED_AT,
        )
        identities = await asyncio.gather(
            authenticator.authenticate(f"Bearer {first.token}", _DIRECT_TRANSPORT),
            authenticator.authenticate(f"Bearer {second.token}", _DIRECT_TRANSPORT),
        )
        yield _CodexRuntime(
            database=database,
            session_factory=session_factory,
            admin_repository=admin_repository,
            credentials=(first, second),
            identities=(identities[0], identities[1]),
            subject_ids=subject_ids,
        )
    finally:
        await database.dispose()


def _selection_engine(runtime: _CodexRuntime) -> SelectionEngine:
    return SelectionEngine(runtime.session_factory, DirectNominationResolver())


async def _seed_logical_sessions(
    runtime: _CodexRuntime,
    identity: AuthenticatedRequestIdentity,
    session_ids: tuple[UUID, UUID],
    *,
    namespace: str,
) -> None:
    status = identity.status_identity
    async with runtime.database.tenant_session(status.tenant_id) as session:
        session.add_all(
            tuple(
                LogicalSession(
                    session_id=session_id,
                    tenant_id=status.tenant_id,
                    actor_id=status.actor_id,
                    client_id=status.client_id,
                    lineage_id=_seed_identifier("lineages", "lineage_id"),
                    branch_id=_seed_identifier("branches", "branch_id"),
                    transport_binding_id=status.transport_binding_id,
                    conversation_ref=f"synthetic-m7-{namespace}-{ordinal}",
                    project_ref="synthetic-m7",
                    content_mode="technical",
                    started_at=_NOW,
                    last_seen_at=_NOW,
                )
                for ordinal, session_id in enumerate(session_ids, start=1)
            )
        )
        await session.flush()


async def test_distinct_authenticated_codex_clients_write_concurrently_with_provenance(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        engine = _selection_engine(runtime)
        commands = (
            _nomination(
                key="codex-m7-distinct-a",
                subject_id=runtime.subject_ids[0],
                statement="Synthetic candidate observed independently by Codex host A.",
            ),
            _nomination(
                key="codex-m7-distinct-b",
                subject_id=runtime.subject_ids[1],
                statement="Synthetic candidate observed independently by Codex host B.",
            ),
        )
        results = await asyncio.gather(
            *(engine.execute(identity.command_principal, command) for identity, command in zip(
                runtime.identities, commands, strict=True
            ))
        )

        assert {result.outcome for result in results} == {"candidate"}
        assert all(result.memory_id is not None for result in results)
        assert len({result.memory_id for result in results}) == 2
        status_by_client = {
            identity.status_identity.client_id: identity.status_identity
            for identity in runtime.identities
        }
        assert len(status_by_client) == 2
        assert len({status.credential_id for status in status_by_client.values()}) == 2

        tenant_id = runtime.identities[0].status_identity.tenant_id
        async with runtime.database.tenant_session(tenant_id) as session:
            receipts = (
                await session.scalars(
                    select(CommandReceipt).where(
                        CommandReceipt.receipt_id.in_([result.receipt_id for result in results])
                    )
                )
            ).all()
            events = (
                await session.scalars(
                    select(MemoryEvent).where(
                        MemoryEvent.event_id.in_(
                            [cast(UUID, result.event_id) for result in results]
                        )
                    )
                )
            ).all()
            decisions = (
                await session.scalars(
                    select(SelectionDecision).where(
                        SelectionDecision.decision_id.in_(
                            [result.decision_id for result in results]
                        )
                    )
                )
            ).all()
            evidence = (
                await session.scalars(
                    select(MemoryEvidence).where(
                        MemoryEvidence.memory_id.in_(
                            [cast(UUID, result.memory_id) for result in results]
                        )
                    )
                )
            ).all()
            bindings = (
                await session.scalars(
                    select(TransportBinding).where(
                        TransportBinding.transport_binding_id.in_(
                            [status.transport_binding_id for status in status_by_client.values()]
                        )
                    )
                )
            ).all()

        assert len(receipts) == len(events) == len(decisions) == len(evidence) == len(bindings) == 2
        assert {row.client_id for row in receipts} == set(status_by_client)
        assert all(
            event.ingress_id is None
            and event.client_id in status_by_client
            and event.transport_binding_id
            == status_by_client[event.client_id].transport_binding_id
            for event in events
        )
        assert all(
            decision.source_kind == "live_interaction"
            and decision.client_id in status_by_client
            and decision.transport_binding_id
            == status_by_client[decision.client_id].transport_binding_id
            for decision in decisions
        )
        evidence_keys = {
            cast(str, item.source_reference["evidence_key"]) for item in evidence
        }
        expected_evidence = {
            cast(UUID, result.memory_id): _attestation_evidence_key(identity)
            for result, identity in zip(results, runtime.identities, strict=True)
        }
        assert {
            item.memory_id: cast(str, item.source_reference["evidence_key"])
            for item in evidence
        } == expected_evidence
        assert all(
            item.source_type == "assistant_observation"
            and item.trust_classification == "trusted"
            and set(item.source_reference) == {"evidence_key"}
            for item in evidence
        )
        assert all(
            re.fullmatch(r"direct-client-observation-v1:[0-9a-f]{64}", key) is not None
            for key in evidence_keys
        )
        assert all(
            binding.transport_kind == TransportKind.DIRECT_PRIVATE.value
            and binding.disclosure_boundary == "private_node"
            and binding.installation_id is None
            for binding in bindings
        )


async def test_legacy_revision_engine_returns_actionable_stale_conflict_without_lost_update(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        initial = await _selection_engine(runtime).execute(
            runtime.identities[0].command_principal,
            _nomination(
                key="codex-m7-revision-seed",
                subject_id=runtime.subject_ids[0],
                statement="Synthetic candidate before concurrent revision.",
            ),
        )
        assert initial.outcome == "candidate"
        assert initial.memory_id is not None

        # ADR 0013 intentionally denies legacy_v1 to M7 bearer credentials. The
        # frozen seed binding exercises the shared optimistic-concurrency engine.
        mutation_engine = MutationEngine(runtime.session_factory)
        responses = await asyncio.gather(
            mutation_engine.execute(
                _legacy_revision_principal(),
                _revision(
                    initial.memory_id,
                    key="codex-m7-revision-a",
                    statement="Synthetic concurrent revision from Codex host A.",
                ),
            ),
            mutation_engine.execute(
                _legacy_revision_principal(),
                _revision(
                    initial.memory_id,
                    key="codex-m7-revision-b",
                    statement="Synthetic concurrent revision from Codex host B.",
                ),
            ),
        )

        winners = [response for response in responses if isinstance(response, MutationResult)]
        losers = [response for response in responses if isinstance(response, MutationError)]
        assert len(winners) == len(losers) == 1
        assert winners[0].revision == 2
        assert losers[0].error.code == "stale_revision"
        details = losers[0].error.details
        assert isinstance(details, StaleRevisionDetails)
        assert details.memory_id == initial.memory_id
        assert details.expected_revision == 1
        assert details.current_revision == 2
        assert details.suggested_action == "read_then_retry_or_open_conflict"

        tenant_id = runtime.identities[0].status_identity.tenant_id
        async with runtime.database.tenant_session(tenant_id) as session:
            memory = await session.get(Memory, initial.memory_id)
            events = (
                await session.scalars(
                    select(MemoryEvent)
                    .where(MemoryEvent.memory_id == initial.memory_id)
                    .order_by(MemoryEvent.sequence)
                )
            ).all()
            receipt_count = int(
                await session.scalar(
                    select(func.count())
                    .select_from(CommandReceipt)
                    .where(CommandReceipt.event_id.in_([event.event_id for event in events]))
                )
                or 0
            )

        assert memory is not None
        assert memory.revision == 2
        assert memory.statement in {
            "Synthetic concurrent revision from Codex host A.",
            "Synthetic concurrent revision from Codex host B.",
        }
        assert [event.operation for event in events] == ["observed", "revised"]
        assert receipt_count == 2


async def test_exact_authenticated_retry_replays_one_atomic_nomination(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        engine = _selection_engine(runtime)
        command = _nomination(
            key="codex-m7-exact-retry",
            subject_id=runtime.subject_ids[0],
            statement="Synthetic exact retry candidate.",
        )
        responses = await asyncio.gather(
            *(engine.execute(runtime.identities[0].command_principal, command) for _ in range(8))
        )

        assert all(isinstance(response, SelectionResult) for response in responses)
        assert len({response.receipt_id for response in responses}) == 1
        assert len({response.decision_id for response in responses}) == 1
        assert len({response.event_id for response in responses}) == 1
        assert len({response.memory_id for response in responses}) == 1
        assert [response.idempotent_replay for response in responses].count(False) == 1
        assert [response.idempotent_replay for response in responses].count(True) == 7

        tenant_id = runtime.identities[0].status_identity.tenant_id
        async with runtime.database.tenant_session(tenant_id) as session:
            counts = []
            for model in (CommandReceipt, MemoryEvent, SelectionDecision, Memory):
                counts.append(
                    int(await session.scalar(select(func.count()).select_from(model)) or 0)
                )
        assert counts == [1, 1, 1, 1]


async def test_subagent_sessions_share_credential_identity_but_keep_session_provenance(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        identity = runtime.identities[0]
        status = identity.status_identity
        session_ids = (_identifier(201), _identifier(202))
        await _seed_logical_sessions(
            runtime,
            identity,
            session_ids,
            namespace="subagent",
        )

        engine = _selection_engine(runtime)
        commands = tuple(
            _nomination(
                key=f"codex-m7-subagent-{ordinal}",
                subject_id=subject_id,
                statement=f"Synthetic candidate from logical subagent session {ordinal}.",
                logical_session_id=session_id,
            )
            for ordinal, (subject_id, session_id) in enumerate(
                zip(runtime.subject_ids, session_ids, strict=True), start=1
            )
        )
        results = await asyncio.gather(
            *(engine.execute(identity.command_principal, command) for command in commands)
        )

        assert {result.outcome for result in results} == {"candidate"}
        assert len({command.idempotency_key for command in commands}) == 2
        async with runtime.database.tenant_session(status.tenant_id) as session:
            events = (
                await session.scalars(
                    select(MemoryEvent).where(
                        MemoryEvent.event_id.in_(
                            [cast(UUID, result.event_id) for result in results]
                        )
                    )
                )
            ).all()
            receipts = (
                await session.scalars(
                    select(CommandReceipt).where(
                        CommandReceipt.receipt_id.in_([result.receipt_id for result in results])
                    )
                )
            ).all()

        assert {event.session_id for event in events} == set(session_ids)
        assert {event.client_id for event in events} == {status.client_id}
        assert {event.transport_binding_id for event in events} == {
            status.transport_binding_id
        }
        assert {receipt.client_id for receipt in receipts} == {status.client_id}


async def test_same_authenticated_source_cannot_self_promote_candidate(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        identity = runtime.identities[0]
        session_ids = (_identifier(301), _identifier(302))
        await _seed_logical_sessions(
            runtime,
            identity,
            session_ids,
            namespace="self-promotion",
        )
        statement = "Synthetic identical candidate from one authenticated Codex source."
        commands = tuple(
            _nomination(
                key=f"codex-m7-self-promotion-{ordinal}",
                subject_id=runtime.subject_ids[0],
                statement=statement,
                logical_session_id=session_id,
            )
            for ordinal, session_id in enumerate(session_ids, start=1)
        )

        engine = _selection_engine(runtime)
        first = await engine.execute(identity.command_principal, commands[0])
        second = await engine.execute(identity.command_principal, commands[1])

        assert first.outcome == "candidate"
        assert first.memory_id is not None
        assert second.outcome == "omit"
        assert second.reason_codes == ("already_candidate",)
        assert second.memory_id is None
        status = identity.status_identity
        async with runtime.database.tenant_session(status.tenant_id) as session:
            memories = (await session.scalars(select(Memory))).all()
            evidence = (await session.scalars(select(MemoryEvidence))).all()
            events = (
                await session.scalars(select(MemoryEvent).order_by(MemoryEvent.sequence))
            ).all()
            receipt_count = int(
                await session.scalar(select(func.count()).select_from(CommandReceipt)) or 0
            )
            decision_count = int(
                await session.scalar(select(func.count()).select_from(SelectionDecision)) or 0
            )

        assert len(memories) == 1
        assert memories[0].memory_id == first.memory_id
        assert memories[0].status == "candidate"
        assert memories[0].revision == 1
        assert len(evidence) == 1
        assert evidence[0].source_reference == {
            "evidence_key": _attestation_evidence_key(identity)
        }
        assert [event.operation for event in events] == ["observed"]
        assert all(event.operation != "candidate_promoted" for event in events)
        assert receipt_count == decision_count == 2


async def test_routine_banter_canary_persists_only_content_free_audit_receipts(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    canary = "SYNTHETIC_M7_ROUTINE_BANTER_CANARY_8f8ef8"
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        result = await _selection_engine(runtime).execute(
            runtime.identities[0].command_principal,
            _routine_banter_nomination(
                key="codex-m7-routine-banter",
                subject_id=runtime.subject_ids[0],
                canary=canary,
            ),
        )

        assert result.outcome == "omit"
        assert result.event_id is None
        assert result.memory_id is None
        assert result.revision is None
        tenant_id = runtime.identities[0].status_identity.tenant_id
        async with runtime.database.tenant_session(tenant_id) as session:
            receipt = await session.get(CommandReceipt, result.receipt_id)
            decision = await session.scalar(
                select(SelectionDecision).where(
                    SelectionDecision.decision_id == result.decision_id
                )
            )
            counts = {
                model.__tablename__: int(
                    await session.scalar(select(func.count()).select_from(model)) or 0
                )
                for model in (
                    CommandReceipt,
                    SelectionDecision,
                    MemoryEvent,
                    MemoryEvidence,
                    Memory,
                    OutboxJob,
                )
            }

        assert receipt is not None
        assert decision is not None
        assert counts == {
            "command_receipts": 1,
            "selection_decisions": 1,
            "memory_events": 0,
            "memory_evidence": 0,
            "memories": 0,
            "outbox_jobs": 0,
        }
        assert canary not in json.dumps(receipt.result, sort_keys=True)
        assert canary.encode() not in bytes(receipt.result_canonical)
        assert canary not in " ".join(
            (
                decision.policy_rule_code,
                decision.source_kind,
                decision.requested_operation,
                decision.outcome,
                decision.selection_basis,
                decision.scope,
                decision.visibility,
                decision.subject_kind,
            )
        )


async def test_caller_supplied_direct_evidence_is_ignored_for_server_attestation(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    hostile_key = "hostile-caller-evidence-key"
    hostile_reference = "SYNTHETIC_M7_HOSTILE_EVIDENCE_REFERENCE_1dd654"
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        result = await _selection_engine(runtime).execute(
            runtime.identities[0].command_principal,
            _hostile_evidence_nomination(
                key="codex-m7-hostile-evidence",
                subject_id=runtime.subject_ids[0],
                evidence_key=hostile_key,
                opaque_reference=hostile_reference,
            ),
        )

        assert result.outcome == "candidate"
        assert result.event_id is not None
        assert result.memory_id is not None
        tenant_id = runtime.identities[0].status_identity.tenant_id
        async with runtime.database.tenant_session(tenant_id) as session:
            receipt = await session.get(CommandReceipt, result.receipt_id)
            evidence = (
                await session.scalars(
                    select(MemoryEvidence).where(MemoryEvidence.memory_id == result.memory_id)
                )
            ).all()
            event = await session.get(MemoryEvent, result.event_id)
            memory = await session.get(Memory, result.memory_id)

        assert receipt is not None
        assert event is not None
        assert memory is not None
        assert len(evidence) == 1
        server_key = cast(str, evidence[0].source_reference["evidence_key"])
        assert (
            re.fullmatch(r"direct-client-observation-v1:[0-9a-f]{64}", server_key)
            is not None
        )
        assert server_key == _attestation_evidence_key(runtime.identities[0])
        assert evidence[0].source_type == "assistant_observation"
        assert evidence[0].trust_classification == "trusted"
        persisted_documents = (
            json.dumps(receipt.result, sort_keys=True),
            json.dumps(event.payload, sort_keys=True),
            json.dumps(evidence[0].source_reference, sort_keys=True),
            memory.statement or "",
        )
        persisted_bytes = (
            bytes(receipt.result_canonical),
            bytes(event.payload_canonical),
        )
        assert all(
            hostile_key not in document and hostile_reference not in document
            for document in persisted_documents
        )
        assert all(
            hostile_key.encode() not in document and hostile_reference.encode() not in document
            for document in persisted_bytes
        )


async def test_wrong_and_revoked_credentials_fail_closed_on_the_next_request(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    async with _seeded_codex_runtime(postgresql_server.database_url) as runtime:
        credential = runtime.credentials[0]
        metadata = credential.metadata
        authenticator = BearerAuthenticator(
            CredentialRepository(runtime.session_factory),
            hashers={_HASH_KEY_ID: BearerTokenHasher(_TOKEN_PEPPER)},
            clock=lambda: _REVOKED_AT,
        )
        wrong = BearerTokenCodec.issue(
            metadata.tenant_id,
            metadata.credential_id,
            BearerTokenHasher(_TOKEN_PEPPER),
            random_bytes=lambda size: bytes([0xA5]) * size,
        )

        with pytest.raises(BearerAuthenticationError) as wrong_error:
            await authenticator.authenticate(f"Bearer {wrong.token}", _DIRECT_TRANSPORT)

        revoke_service = CredentialAdminService(
            runtime.admin_repository,
            token_pepper=_TOKEN_PEPPER,
            secret_hash_key_id=_HASH_KEY_ID,
            now=lambda: _REVOKED_AT,
        )
        await revoke_service.revoke(
            tenant_id=metadata.tenant_id,
            credential_id=metadata.credential_id,
        )
        with pytest.raises(BearerAuthenticationError) as revoked_error:
            await authenticator.authenticate(f"Bearer {credential.token}", _DIRECT_TRANSPORT)

        assert str(wrong_error.value) == str(revoked_error.value) == "authentication failed"
        assert repr(wrong_error.value) == repr(revoked_error.value)
        assert credential.token not in str(revoked_error.value)
