"""Transport-neutral, concurrency-safe memory mutation command engine."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal, Never
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import and_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.commands import (
    CommandHashBinding,
    DirectMutationCommand,
    ForgetCommand,
    LinkCommand,
    MutationError,
    MutationErrorBody,
    MutationResult,
    ObserveCommand,
    OpenConflictCommand,
    RememberCommand,
    ResolveConflictCommand,
    RetireCommand,
    ReviseCommand,
    StaleRevisionDetails,
)
from kivra_memory.domain.enums import EventOperation, MemoryScope, MemoryStatus, MemoryVisibility
from kivra_memory.domain.events import (
    AffectedMemory,
    BranchState,
    ConflictMemberState,
    ConflictOpenedPayload,
    ConflictResolvedPayload,
    ConflictState,
    LinkedPayload,
    LinkState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    MemoryTransitionPayload,
    OperationPayload,
    TombstonedPayload,
    event_hash_fields,
)
from kivra_memory.domain.fingerprints import exact_memory_fingerprint
from kivra_memory.domain.folding import FoldError
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.storage.event_store import EventStoreError, append_memory_event
from kivra_memory.storage.live_projection import (
    load_projection_state_for_update,
    stage_live_projection,
    validate_live_event,
)
from kivra_memory.storage.locks import (
    acquire_advisory_xact_lock,
    acquire_advisory_xact_locks,
    advisory_lock_key,
    idempotency_advisory_lock_key,
)
from kivra_memory.storage.models import (
    Branch,
    CommandReceipt,
    Lineage,
    LogicalSession,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    Persona,
    Subject,
)
from kivra_memory.storage.models import (
    MemoryEvent as MemoryEventRow,
)
from kivra_memory.storage.models import (
    MemoryLink as MemoryLinkRow,
)
from kivra_memory.storage.outbox import enqueue_outbox_job
from kivra_memory.storage.projector import ProjectionPersistenceError, memory_row_to_state
from kivra_memory.storage.transactions import (
    SerializableTransactionError,
    run_serializable_transaction,
)


class CommandPrincipal(BaseModel):
    """Authenticated immutable context supplied by any mutation adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID
    scopes: Annotated[
        frozenset[Annotated[str, Field(min_length=1, max_length=255)]], Field(max_length=64)
    ]
    ingress_id: UUID | None = None

    @field_validator("tenant_id", "actor_id", "client_id", "transport_binding_id", "ingress_id")
    @classmethod
    def validate_identifier(cls, value: UUID | None, info: object) -> UUID | None:
        if value is not None:
            require_uuid7(value, field_name=str(getattr(info, "field_name", "identifier")))
        return value


_SCOPES = {
    "observe": "memory.write.observe",
    "remember": "memory.write.remember",
    "revise": "memory.write.revise",
    "link": "memory.write.link",
    "open_conflict": "memory.write.conflict.open",
    "resolve_conflict": "memory.write.conflict.resolve",
    "retire": "memory.write.retire",
    "forget": "memory.write.forget",
}

_EVENT_OPERATIONS = {
    "observe": EventOperation.OBSERVED,
    "remember": EventOperation.REMEMBERED,
    "revise": EventOperation.REVISED,
    "link": EventOperation.LINKED,
    "open_conflict": EventOperation.CONFLICT_OPENED,
    "resolve_conflict": EventOperation.CONFLICT_RESOLVED,
    "retire": EventOperation.RETIRED,
    "forget": EventOperation.TOMBSTONED,
}


def _principal_authorized(principal: CommandPrincipal, command: DirectMutationCommand) -> bool:
    """Apply exact mutation scopes, including the narrow proposal-ingress seam."""

    required_scope = _SCOPES[command.OPERATION]
    if required_scope in principal.scopes or "memory:write" in principal.scopes:
        return True
    return (
        "memory:propose" in principal.scopes
        and principal.ingress_id is not None
        and isinstance(command, ObserveCommand | RememberCommand)
    )


class _SafeFailure(Exception):
    def __init__(self, response: MutationError) -> None:
        super().__init__(response.error.code)
        self.response = response


def _error(
    code: Literal[
        "invalid_input",
        "unauthenticated",
        "forbidden",
        "not_found",
        "stale_revision",
        "idempotency_key_reused",
        "conflict_state_changed",
        "hard_forget_unavailable",
        "serialization_exhausted",
        "dependency_unavailable",
        "internal_error",
    ],
    *,
    retryable: bool = False,
    retry_after_ms: int | None = None,
    details: StaleRevisionDetails | None = None,
) -> MutationError:
    return MutationError(
        contract_version="mcp-mutation-v1",
        error=MutationErrorBody(
            code=code,
            message=MutationErrorBody.SAFE_MESSAGES[code],
            retryable=retryable,
            retry_after_ms=retry_after_ms,
            details=details,
        ),
    )


def _fail(code: str, **kwargs: object) -> Never:
    raise _SafeFailure(_error(code, **kwargs))  # type: ignore[arg-type]


def _branch_state(row: Branch) -> BranchState:
    return BranchState(
        branch_id=row.branch_id,
        tenant_id=row.tenant_id,
        lineage_id=row.lineage_id,
        parent_branch_id=row.parent_branch_id,
        fork_event_sequence=row.fork_event_sequence,
        name=row.name,
        visibility_ceiling=MemoryVisibility(row.visibility_ceiling),
        created_at=row.created_at,
        sealed_at=row.sealed_at,
    )


def _fingerprint(state: MemoryState) -> str:
    if state.normalized_fingerprint is None:
        _fail("invalid_input")
    return state.normalized_fingerprint


def _updated_memory(current: MemoryState, now: datetime, **updates: object) -> MemoryState:
    return current.model_copy(
        update={"revision": current.revision + 1, "updated_at": now, **updates}
    )


def _revised_memory(current: MemoryState, command: ReviseCommand, now: datetime) -> MemoryState:
    changes = command.changes.model_dump(mode="python", exclude_unset=True)
    candidate = _updated_memory(current, now, **changes)
    fingerprint = exact_memory_fingerprint(
        statement=candidate.statement or "",
        category=candidate.category,
        ontological_status=candidate.ontological_status,
        scope=candidate.scope,
        interpretation_limits=candidate.interpretation_limits,
    )
    return candidate.model_copy(
        update={
            "fingerprint_version": 1,
            "normalized_fingerprint": fingerprint.sha256_hex,
        }
    )


def _reject_disputed_terminal_mutation(memory: MemoryState) -> None:
    if memory.status is MemoryStatus.DISPUTED:
        _fail("conflict_state_changed")


async def _reject_duplicate_active_link(
    session: AsyncSession,
    *,
    principal: CommandPrincipal,
    lineage_id: UUID,
    command: LinkCommand,
) -> None:
    existing = await session.scalar(
        select(MemoryLinkRow.link_id)
        .where(
            MemoryLinkRow.tenant_id == principal.tenant_id,
            MemoryLinkRow.lineage_id == lineage_id,
            MemoryLinkRow.branch_id == command.branch_id,
            MemoryLinkRow.source_memory_id == command.source_memory_id,
            MemoryLinkRow.target_memory_id == command.target_memory_id,
            MemoryLinkRow.link_type == command.link_type.value,
            MemoryLinkRow.status == "active",
        )
        .with_for_update()
    )
    if existing is not None:
        _fail("invalid_input")


def _event(
    *,
    sequence: int,
    principal: CommandPrincipal,
    command: DirectMutationCommand,
    lineage_id: UUID,
    payload: OperationPayload,
    event_id: UUID,
    correlation_id: UUID,
    created_at: datetime,
    memory_id: UUID | None,
    expected_revision: int | None,
) -> MemoryEvent:
    operation = _EVENT_OPERATIONS[command.OPERATION]
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=command.branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=command.causation_event_id,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=event_id,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=command.branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        transport_binding_id=principal.transport_binding_id,
        session_id=command.logical_session_id,
        ingress_id=principal.ingress_id,
        operation=operation,
        memory_id=memory_id,
        expected_revision=expected_revision,
        causation_event_id=command.causation_event_id,
        correlation_id=correlation_id,
        idempotency_key=command.idempotency_key,
        policy_version=1,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


class MutationEngine:
    """Execute all v1 direct and synthetic-ingress commands through one seam."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def execute(
        self, principal: CommandPrincipal, command: DirectMutationCommand
    ) -> MutationResult | MutationError:
        event_id = new_uuid7()
        receipt_id = new_uuid7()
        aggregate_id = new_uuid7()
        correlation_id = new_uuid7()
        created_at = datetime.now(UTC)
        job_ids = tuple(new_uuid7() for _ in range(4))

        async def attempt(session: AsyncSession) -> MutationResult:
            return await self._attempt(
                session,
                principal=principal,
                command=command,
                event_id=event_id,
                receipt_id=receipt_id,
                aggregate_id=aggregate_id,
                correlation_id=correlation_id,
                created_at=created_at,
                job_ids=job_ids,
            )

        try:
            return await run_serializable_transaction(
                self._session_factory, principal.tenant_id, attempt
            )
        except _SafeFailure as failure:
            return failure.response
        except SerializableTransactionError as error:
            return _error(
                "serialization_exhausted",
                retryable=True,
                retry_after_ms=max(100, min(1000, error.retry_after_ms)),
            )
        except EventStoreError as error:
            if error.code in {"operation_not_authorized", "github_operation_forbidden"}:
                return _error("forbidden")
            if error.code == "binding_not_found":
                return _error("not_found")
            if error.code in {"binding_revoked", "binding_expired"}:
                return _error("forbidden")
            if error.code in {
                "event_counter_unavailable",
                "event_store_unavailable",
                "binding_installation_unavailable",
            }:
                return _error("dependency_unavailable", retryable=True)
            return _error("invalid_input")
        except (FoldError, ValidationError, ValueError):
            return _error("invalid_input")
        except ProjectionPersistenceError:
            return _error("dependency_unavailable", retryable=True)
        except SQLAlchemyError:
            return _error("dependency_unavailable", retryable=True)
        except Exception:
            return _error("internal_error")

    async def _attempt(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: DirectMutationCommand,
        event_id: UUID,
        receipt_id: UUID,
        aggregate_id: UUID,
        correlation_id: UUID,
        created_at: datetime,
        job_ids: tuple[UUID, ...],
    ) -> MutationResult:
        if not _principal_authorized(principal, command):
            _fail("forbidden")

        identity_result = await session.execute(
            select(Lineage.lineage_id, Lineage.sealed_at, Persona.retired_at, Branch)
            .join(
                Persona,
                and_(
                    Persona.tenant_id == Lineage.tenant_id,
                    Persona.persona_id == Lineage.persona_id,
                ),
            )
            .join(
                Branch,
                and_(
                    Branch.tenant_id == Lineage.tenant_id,
                    Branch.lineage_id == Lineage.lineage_id,
                ),
            )
            .where(
                Persona.tenant_id == principal.tenant_id,
                Persona.persona_id == command.persona_id,
                Branch.branch_id == command.branch_id,
            )
        )
        identity = identity_result.one_or_none()
        if identity is None:
            _fail("not_found")
        lineage_id, lineage_sealed_at, persona_retired_at, branch_row = identity
        branch = _branch_state(branch_row)

        if command.logical_session_id is not None:
            logical_session = await session.scalar(
                select(LogicalSession.session_id).where(
                    LogicalSession.tenant_id == principal.tenant_id,
                    LogicalSession.session_id == command.logical_session_id,
                    LogicalSession.actor_id == principal.actor_id,
                    LogicalSession.client_id == principal.client_id,
                    LogicalSession.lineage_id == lineage_id,
                    LogicalSession.branch_id == command.branch_id,
                    LogicalSession.transport_binding_id == principal.transport_binding_id,
                )
            )
            if logical_session is None:
                _fail("not_found")
        if command.causation_event_id is not None:
            cause = await session.scalar(
                select(MemoryEventRow.event_id).where(
                    MemoryEventRow.tenant_id == principal.tenant_id,
                    MemoryEventRow.lineage_id == lineage_id,
                    MemoryEventRow.event_id == command.causation_event_id,
                )
            )
            if cause is None:
                _fail("not_found")

        await acquire_advisory_xact_lock(
            session,
            idempotency_advisory_lock_key(
                tenant_id=principal.tenant_id,
                client_id=principal.client_id,
                idempotency_key=command.idempotency_key,
            ),
        )
        binding = CommandHashBinding(
            tenant_id=principal.tenant_id,
            lineage_id=lineage_id,
            actor_id=principal.actor_id,
            client_id=principal.client_id,
        )
        command_digest = bytes.fromhex(command.bound_canonical_hash(binding))
        receipt = await session.scalar(
            select(CommandReceipt).where(
                CommandReceipt.tenant_id == principal.tenant_id,
                CommandReceipt.client_id == principal.client_id,
                CommandReceipt.idempotency_key == command.idempotency_key,
            )
        )
        if receipt is not None:
            if bytes(receipt.command_sha256) != command_digest:
                _fail("idempotency_key_reused")
            canonical = canonical_json_bytes(receipt.result)
            if canonical != bytes(receipt.result_canonical) or hashlib.sha256(
                canonical
            ).digest() != bytes(receipt.result_sha256):
                _fail("dependency_unavailable")
            persisted = MutationResult.model_validate(receipt.result, strict=False)
            return persisted.model_copy(update={"idempotent_replay": True})
        if (
            persona_retired_at is not None
            or lineage_sealed_at is not None
            or branch_row.sealed_at is not None
        ):
            _fail("forbidden")

        (
            payload,
            memory_id,
            expected_revision,
            result_memory_id,
            result_revision,
            conflict_id,
        ) = await self._prepare_payload(
            session,
            principal=principal,
            command=command,
            lineage_id=lineage_id,
            aggregate_id=aggregate_id,
            created_at=created_at,
        )
        proposed = _event(
            sequence=1,
            principal=principal,
            command=command,
            lineage_id=lineage_id,
            payload=payload,
            event_id=event_id,
            correlation_id=correlation_id,
            created_at=created_at,
            memory_id=memory_id,
            expected_revision=expected_revision,
        )
        event = await append_memory_event(
            session, lambda sequence: proposed.model_copy(update={"sequence": sequence})
        )
        before = await load_projection_state_for_update(session, event=event, branch=branch)
        after = validate_live_event(before, event)
        await stage_live_projection(session, before=before, after=after, event=event)

        forget_state = None
        conflict_state = None
        if isinstance(command, ForgetCommand):
            forget_state = "purge_pending" if command.mode == "hard" else "logically_forgotten"
        elif isinstance(command, OpenConflictCommand):
            conflict_state = "open"
        elif isinstance(command, ResolveConflictCommand):
            conflict_state = "resolved"
        result = MutationResult(
            contract_version="mcp-mutation-v1",
            operation=command.OPERATION,  # type: ignore[arg-type]
            receipt_id=receipt_id,
            event_id=event.event_id,
            memory_id=result_memory_id,
            revision=result_revision,
            conflict_id=conflict_id,
            conflict_state=conflict_state,  # type: ignore[arg-type]
            forget_state=forget_state,  # type: ignore[arg-type]
        )

        await self._enqueue_jobs(
            session,
            principal=principal,
            command=command,
            event=event,
            result=result,
            job_ids=job_ids,
        )
        result_value = result.model_dump(mode="json")
        result_canonical = canonical_json_bytes(result_value)
        session.add(
            CommandReceipt(
                receipt_id=receipt_id,
                tenant_id=principal.tenant_id,
                client_id=principal.client_id,
                idempotency_key=command.idempotency_key,
                command_sha256=command_digest,
                event_id=event.event_id,
                memory_id=result.memory_id,
                memory_revision=result.revision,
                result=result_value,
                result_canonical=result_canonical,
                result_sha256=hashlib.sha256(result_canonical).digest(),
                created_at=created_at,
            )
        )
        await session.flush()
        return result

    async def _load_memories(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        lineage_id: UUID,
        branch_id: UUID,
        memory_ids: tuple[UUID, ...],
        for_update: bool,
    ) -> dict[UUID, MemoryState]:
        statement = (
            select(Memory)
            .where(
                Memory.tenant_id == principal.tenant_id,
                Memory.lineage_id == lineage_id,
                Memory.branch_id == branch_id,
                Memory.memory_id.in_(memory_ids),
            )
            .order_by(Memory.memory_id)
        )
        if for_update:
            statement = statement.with_for_update()
        rows = (await session.scalars(statement)).all()
        states = {row.memory_id: memory_row_to_state(row) for row in rows}
        if len(states) != len(set(memory_ids)):
            _fail("not_found")
        return states

    @staticmethod
    def _check_revision(memory: MemoryState, expected: int) -> None:
        if memory.revision != expected:
            _fail(
                "stale_revision",
                details=StaleRevisionDetails(
                    memory_id=memory.memory_id,
                    expected_revision=expected,
                    current_revision=memory.revision,
                ),
            )

    async def _prepare_payload(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: DirectMutationCommand,
        lineage_id: UUID,
        aggregate_id: UUID,
        created_at: datetime,
    ) -> tuple[OperationPayload, UUID | None, int | None, UUID | None, int | None, UUID | None]:
        if isinstance(command, ObserveCommand | RememberCommand):
            memory = command.memory
            subject = (
                await session.execute(
                    select(Subject.subject_id, Subject.origin_session_id).where(
                        Subject.tenant_id == principal.tenant_id,
                        Subject.lineage_id == lineage_id,
                        Subject.subject_id == memory.subject_id,
                        Subject.kind == memory.subject_kind.value,
                    )
                )
            ).one_or_none()
            if subject is None:
                _fail("not_found")
            _, subject_origin_session_id = subject
            if memory.scope in {MemoryScope.EPISODIC, MemoryScope.SCENE_LOCAL} and (
                command.logical_session_id is None
                or memory.origin_session_id != command.logical_session_id
                or subject_origin_session_id != command.logical_session_id
            ):
                _fail("invalid_input")
            fingerprint = exact_memory_fingerprint(
                statement=memory.statement,
                category=memory.category,
                ontological_status=memory.ontological_status,
                scope=memory.scope,
                interpretation_limits=memory.interpretation_limits,
            )
            await acquire_advisory_xact_locks(
                session,
                (
                    advisory_lock_key(
                        tenant_id=principal.tenant_id,
                        lineage_id=lineage_id,
                        branch_id=command.branch_id,
                        subject_id=memory.subject_id,
                        normalized_fingerprint=fingerprint.sha256_hex,
                    ),
                ),
            )
            duplicate = await session.scalar(
                select(Memory.memory_id).where(
                    Memory.tenant_id == principal.tenant_id,
                    Memory.lineage_id == lineage_id,
                    Memory.branch_id == command.branch_id,
                    Memory.subject_id == memory.subject_id,
                    Memory.normalized_fingerprint == bytes.fromhex(fingerprint.sha256_hex),
                    Memory.status.notin_(
                        [
                            MemoryStatus.SUPERSEDED.value,
                            MemoryStatus.RETIRED.value,
                            MemoryStatus.TOMBSTONED.value,
                        ]
                    ),
                )
            )
            if duplicate is not None:
                _fail("invalid_input")
            status = (
                MemoryStatus.CANDIDATE
                if isinstance(command, ObserveCommand)
                else MemoryStatus.ACTIVE
            )
            state = MemoryState(
                memory_id=aggregate_id,
                tenant_id=principal.tenant_id,
                lineage_id=lineage_id,
                branch_id=command.branch_id,
                revision=1,
                status=status,
                publication_approved_at=None,
                publication_approved_by_actor_id=None,
                content_protection="plaintext",
                content_key_id=None,
                created_at=created_at,
                updated_at=created_at,
                fingerprint_version=1,
                normalized_fingerprint=fingerprint.sha256_hex,
                **memory.model_dump(mode="python"),
            )
            return MemoryCreatedPayload(memory=state), aggregate_id, None, aggregate_id, 1, None

        ids: tuple[UUID, ...]
        if isinstance(command, LinkCommand):
            ids = (command.source_memory_id, command.target_memory_id)
        elif isinstance(command, OpenConflictCommand | ResolveConflictCommand):
            ids = tuple(member.memory_id for member in command.members)
        else:
            ids = (command.memory_id,)
        unlocked_memories = await self._load_memories(
            session,
            principal=principal,
            lineage_id=lineage_id,
            branch_id=command.branch_id,
            memory_ids=ids,
            for_update=False,
        )
        lock_keys = [
            advisory_lock_key(
                tenant_id=principal.tenant_id,
                lineage_id=lineage_id,
                branch_id=command.branch_id,
                subject_id=memory.subject_id,
                normalized_fingerprint=_fingerprint(memory),
            )
            for memory in unlocked_memories.values()
        ]
        if isinstance(command, ReviseCommand):
            revised = _revised_memory(unlocked_memories[command.memory_id], command, created_at)
            lock_keys.append(
                advisory_lock_key(
                    tenant_id=principal.tenant_id,
                    lineage_id=lineage_id,
                    branch_id=command.branch_id,
                    subject_id=revised.subject_id,
                    normalized_fingerprint=_fingerprint(revised),
                )
            )
        await acquire_advisory_xact_locks(session, lock_keys)
        memories = await self._load_memories(
            session,
            principal=principal,
            lineage_id=lineage_id,
            branch_id=command.branch_id,
            memory_ids=ids,
            for_update=True,
        )
        for memory_id, unlocked in unlocked_memories.items():
            locked = memories[memory_id]
            if (
                locked.revision != unlocked.revision
                or locked.subject_id != unlocked.subject_id
                or locked.normalized_fingerprint != unlocked.normalized_fingerprint
            ):
                _fail(
                    "stale_revision",
                    details=StaleRevisionDetails(
                        memory_id=memory_id,
                        expected_revision=unlocked.revision,
                        current_revision=locked.revision,
                    ),
                )

        if isinstance(command, ReviseCommand):
            current = memories[command.memory_id]
            self._check_revision(current, command.expected_revision)
            revised = _revised_memory(current, command, created_at)
            collision = await session.scalar(
                select(Memory.memory_id).where(
                    Memory.tenant_id == principal.tenant_id,
                    Memory.lineage_id == lineage_id,
                    Memory.branch_id == command.branch_id,
                    Memory.subject_id == revised.subject_id,
                    Memory.memory_id != revised.memory_id,
                    Memory.normalized_fingerprint == bytes.fromhex(_fingerprint(revised)),
                    Memory.status.notin_(
                        [
                            MemoryStatus.SUPERSEDED.value,
                            MemoryStatus.RETIRED.value,
                            MemoryStatus.TOMBSTONED.value,
                        ]
                    ),
                )
            )
            if collision is not None:
                _fail("invalid_input")
            return (
                MemoryTransitionPayload(previous_revision=current.revision, memory=revised),
                current.memory_id,
                current.revision,
                current.memory_id,
                revised.revision,
                None,
            )
        if isinstance(command, LinkCommand):
            source, target = memories[command.source_memory_id], memories[command.target_memory_id]
            self._check_revision(source, command.source_expected_revision)
            self._check_revision(target, command.target_expected_revision)
            await _reject_duplicate_active_link(
                session,
                principal=principal,
                lineage_id=lineage_id,
                command=command,
            )
            link = LinkState(
                link_id=aggregate_id,
                tenant_id=principal.tenant_id,
                lineage_id=lineage_id,
                branch_id=command.branch_id,
                source_memory_id=source.memory_id,
                target_memory_id=target.memory_id,
                link_type=command.link_type,
                status="active",
                created_at=created_at,
                metadata=command.metadata,
            )
            return LinkedPayload(link=link), None, None, None, None, None
        if isinstance(command, OpenConflictCommand):
            if any(memory.subject_id != command.subject_id for memory in memories.values()):
                _fail("invalid_input")
            affected = []
            members = []
            expectations = {item.memory_id: item.expected_revision for item in command.members}
            for memory_id in sorted(memories, key=str):
                current = memories[memory_id]
                self._check_revision(current, expectations[memory_id])
                affected.append(
                    AffectedMemory(
                        previous_revision=current.revision,
                        memory=_updated_memory(current, created_at, status=MemoryStatus.DISPUTED),
                    )
                )
                members.append(
                    ConflictMemberState(
                        conflict_id=aggregate_id,
                        memory_id=memory_id,
                        disposition="disputed",
                        joined_at=created_at,
                    )
                )
            conflict = ConflictState(
                conflict_id=aggregate_id,
                tenant_id=principal.tenant_id,
                lineage_id=lineage_id,
                branch_id=command.branch_id,
                subject_id=command.subject_id,
                status="open",
                reason=command.conflict_reason,
                opened_at=created_at,
                metadata=command.metadata,
            )
            return (
                ConflictOpenedPayload(
                    conflict=conflict, members=tuple(members), affected_memories=tuple(affected)
                ),
                None,
                None,
                None,
                None,
                aggregate_id,
            )
        if isinstance(command, ResolveConflictCommand):
            if not command.user_confirmed and any(
                memory.scope in {MemoryScope.PERSONA, MemoryScope.RELATIONSHIP}
                for memory in memories.values()
            ):
                _fail("invalid_input")
            conflict_row = await session.scalar(
                select(MemoryConflict)
                .where(
                    MemoryConflict.tenant_id == principal.tenant_id,
                    MemoryConflict.lineage_id == lineage_id,
                    MemoryConflict.branch_id == command.branch_id,
                    MemoryConflict.conflict_id == command.conflict_id,
                )
                .with_for_update()
            )
            if conflict_row is None:
                _fail("not_found")
            stored_members = (
                await session.scalars(
                    select(MemoryConflictMember)
                    .where(
                        MemoryConflictMember.tenant_id == principal.tenant_id,
                        MemoryConflictMember.lineage_id == lineage_id,
                        MemoryConflictMember.conflict_id == command.conflict_id,
                    )
                    .order_by(MemoryConflictMember.memory_id)
                    .with_for_update()
                )
            ).all()
            requested = {item.memory_id: item for item in command.members}
            if conflict_row.status != "open" or {row.memory_id for row in stored_members} != set(
                requested
            ):
                _fail("conflict_state_changed")
            affected = []
            members = []
            for stored in stored_members:
                resolution = requested[stored.memory_id]
                current = memories[stored.memory_id]
                self._check_revision(current, resolution.expected_revision)
                affected.append(
                    AffectedMemory(
                        previous_revision=current.revision,
                        memory=_updated_memory(
                            current, created_at, status=MemoryStatus(resolution.resulting_status)
                        ),
                    )
                )
                members.append(
                    ConflictMemberState(
                        conflict_id=command.conflict_id,
                        memory_id=stored.memory_id,
                        disposition=resolution.disposition,
                        joined_at=stored.joined_at,
                    )
                )
            conflict = ConflictState(
                conflict_id=conflict_row.conflict_id,
                tenant_id=conflict_row.tenant_id,
                lineage_id=conflict_row.lineage_id,
                branch_id=conflict_row.branch_id,
                subject_id=conflict_row.subject_id,
                status="resolved",
                reason=conflict_row.reason,
                resolution_kind=command.resolution_kind,
                resolution_rationale=command.resolution_rationale,
                opened_at=conflict_row.opened_at,
                resolved_at=created_at,
                metadata=dict(conflict_row.metadata_),
            )
            return (
                ConflictResolvedPayload(
                    conflict=conflict, members=tuple(members), affected_memories=tuple(affected)
                ),
                None,
                None,
                None,
                None,
                command.conflict_id,
            )
        current = memories[command.memory_id]
        self._check_revision(current, command.expected_revision)
        if isinstance(command, RetireCommand):
            _reject_disputed_terminal_mutation(current)
            after = _updated_memory(current, created_at, status=MemoryStatus.RETIRED)
            return (
                MemoryTransitionPayload(previous_revision=current.revision, memory=after),
                current.memory_id,
                current.revision,
                current.memory_id,
                after.revision,
                None,
            )
        assert isinstance(command, ForgetCommand)
        _reject_disputed_terminal_mutation(current)
        if command.mode == "hard":
            if current.content_protection != "envelope_encrypted" or current.content_key_id is None:
                _fail("hard_forget_unavailable")
            key = await session.scalar(
                select(MemoryContentKey.content_key_id).where(
                    MemoryContentKey.tenant_id == principal.tenant_id,
                    MemoryContentKey.lineage_id == lineage_id,
                    MemoryContentKey.memory_id == current.memory_id,
                    MemoryContentKey.content_key_id == current.content_key_id,
                    MemoryContentKey.state == "active",
                )
            )
            if key is None:
                _fail("hard_forget_unavailable")
        tombstone = _updated_memory(
            current,
            created_at,
            status=MemoryStatus.TOMBSTONED,
            statement=None,
            reason_to_remember=None,
            interpretation_limits=(),
            normalized_fingerprint=None,
            metadata={},
        )
        return (
            TombstonedPayload(
                previous_revision=current.revision, memory=tombstone, forget_mode=command.mode
            ),
            current.memory_id,
            current.revision,
            current.memory_id,
            tombstone.revision,
            None,
        )

    async def _enqueue_jobs(
        self,
        session: AsyncSession,
        *,
        principal: CommandPrincipal,
        command: DirectMutationCommand,
        event: MemoryEvent,
        result: MutationResult,
        job_ids: tuple[UUID, ...],
    ) -> None:
        jobs: list[tuple[str, str, UUID | None, dict[str, UUID | int]]] = []
        if isinstance(command, ObserveCommand | RememberCommand):
            assert result.memory_id is not None and result.revision is not None
            references: dict[str, UUID | int] = {
                "memory_id": result.memory_id,
                "memory_version": result.revision,
                "event_id": event.event_id,
            }
            jobs.extend(
                (
                    ("embed_memory", "memory", result.memory_id, references),
                    ("check_duplicates", "memory", result.memory_id, references),
                )
            )
        jobs.append(
            (
                "export_git_batch",
                "event",
                event.event_id,
                {"event_id": event.event_id, "event_sequence": event.sequence},
            )
        )
        if isinstance(command, ForgetCommand) and command.mode == "hard":
            assert result.memory_id is not None and result.revision is not None
            jobs.append(
                (
                    "purge_payload",
                    "memory",
                    result.memory_id,
                    {
                        "memory_id": result.memory_id,
                        "memory_version": result.revision,
                        "event_id": event.event_id,
                    },
                )
            )
        for job_id, (job_type, aggregate_type, aggregate_id, references) in zip(
            job_ids, jobs, strict=False
        ):
            await enqueue_outbox_job(
                session,
                tenant_id=principal.tenant_id,
                job_type=job_type,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                references=references,
                job_uuid=job_id,
            )
