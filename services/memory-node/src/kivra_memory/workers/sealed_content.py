"""Hard-forget handler for sealed canonical memory payloads."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.enums import EventOperation, MemoryVisibility
from kivra_memory.domain.events import (
    BranchState,
    MemoryEvent,
    MemoryStateV3,
    PayloadPurgeCompletedPayloadV3,
    event_hash_fields,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.keys import ContentKeyReference, KeyDestroyer, KeyProviderError
from kivra_memory.storage.event_store import append_memory_event
from kivra_memory.storage.live_projection import (
    load_projection_state_for_update,
    validate_live_event,
)
from kivra_memory.storage.models import (
    Branch,
    Memory,
    MemoryContentKey,
    MemoryEmbeddingV1,
)
from kivra_memory.storage.outbox import enqueue_outbox_job
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob
from kivra_memory.storage.projector import memory_row_to_state


class SealedContentPurgeError(RuntimeError):
    """Content-free hard-forget worker failure."""

    def __init__(self, code: Literal["invalid_job", "dependency_unavailable"]):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class SealedContentPurgeResult:
    outcome: Literal["purged", "already_purged"]
    memory_id: UUID
    revision: int
    event_id: UUID


def _job_target(job: ClaimedOutboxJob) -> tuple[UUID, int, UUID]:
    if (
        job.job_type != "purge_payload"
        or job.aggregate_type != "memory"
        or set(job.payload) != {"event_id", "memory_id", "memory_version"}
    ):
        raise SealedContentPurgeError("invalid_job")
    try:
        memory_id = UUID(str(job.payload["memory_id"]))
        source_event_id = UUID(str(job.payload["event_id"]))
    except (TypeError, ValueError):
        raise SealedContentPurgeError("invalid_job") from None
    revision = job.payload["memory_version"]
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or job.aggregate_id != memory_id
    ):
        raise SealedContentPurgeError("invalid_job")
    return memory_id, revision, source_event_id


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


def _purge_event(
    *,
    sequence: int,
    principal: CommandPrincipal,
    branch_id: UUID,
    lineage_id: UUID,
    payload: PayloadPurgeCompletedPayloadV3,
    event_id: UUID,
    correlation_id: UUID,
    source_event_id: UUID,
    created_at: datetime,
) -> MemoryEvent:
    memory_id = payload.memory.memory_id
    payload_value, payload_canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=EventOperation.PAYLOAD_PURGE_COMPLETED,
        payload=payload,
        payload_version=3,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        memory_id=memory_id,
        expected_revision=payload.previous_revision,
        causation_event_id=source_event_id,
    )
    return MemoryEvent(
        schema_version=3,
        payload_version=3,
        sequence=sequence,
        event_id=event_id,
        tenant_id=principal.tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=principal.actor_id,
        client_id=principal.client_id,
        transport_binding_id=principal.transport_binding_id,
        session_id=None,
        ingress_id=None,
        operation=EventOperation.PAYLOAD_PURGE_COMPLETED,
        memory_id=memory_id,
        expected_revision=payload.previous_revision,
        causation_event_id=source_event_id,
        correlation_id=correlation_id,
        idempotency_key=f"payload-purge:{memory_id}:{payload.previous_revision}",
        policy_version=3,
        normalization_version=1,
        payload=payload_value,
        payload_canonical=payload_canonical,
        payload_sha256=payload_sha256,
        command_sha256=command_sha256,
        created_at=created_at,
    )


async def handle_purge_payload_job(
    session: AsyncSession,
    *,
    job: ClaimedOutboxJob,
    principal: CommandPrincipal,
    key_destroyer: KeyDestroyer,
    now: datetime | None = None,
) -> SealedContentPurgeResult:
    """Destroy one per-memory key and atomically record cryptographic erasure."""

    memory_id, expected_revision, source_event_id = _job_target(job)
    if (
        principal.tenant_id != job.tenant_id
        or principal.ingress_id is not None
        or "memory.lifecycle.purge" not in principal.scopes
    ):
        raise SealedContentPurgeError("invalid_job")
    memory_row = await session.scalar(
        select(Memory)
        .where(Memory.tenant_id == job.tenant_id, Memory.memory_id == memory_id)
        .with_for_update()
    )
    if memory_row is None:
        raise SealedContentPurgeError("invalid_job")
    if memory_row.content_protection == "cryptographically_erased":
        return SealedContentPurgeResult(
            outcome="already_purged",
            memory_id=memory_id,
            revision=memory_row.revision,
            event_id=memory_row.last_event_id,
        )
    if (
        memory_row.revision != expected_revision
        or memory_row.last_event_id != source_event_id
        or memory_row.status != "tombstoned"
        or memory_row.content_protection != "envelope_encrypted"
        or memory_row.content_key_id is None
    ):
        raise SealedContentPurgeError("invalid_job")
    state = memory_row_to_state(memory_row)
    if not isinstance(state, MemoryStateV3):
        raise SealedContentPurgeError("invalid_job")
    key_row = await session.scalar(
        select(MemoryContentKey)
        .where(
            MemoryContentKey.tenant_id == job.tenant_id,
            MemoryContentKey.lineage_id == state.lineage_id,
            MemoryContentKey.memory_id == memory_id,
            MemoryContentKey.content_key_id == state.content_key_id,
        )
        .with_for_update()
    )
    if key_row is None or key_row.state != "destruction_requested":
        raise SealedContentPurgeError("invalid_job")
    reference = ContentKeyReference(
        content_key_id=key_row.content_key_id,
        provider_name=key_row.provider_name,
        provider_key_reference=key_row.provider_key_reference,
    )
    try:
        if key_destroyer.name != reference.provider_name:
            raise KeyProviderError()
        receipt = await key_destroyer.destroy_key(reference)
        receipt_sha256 = hashlib.sha256(receipt.receipt).digest()
    except Exception:
        raise SealedContentPurgeError("dependency_unavailable") from None

    completed_at = now or datetime.now(UTC)
    event_id = new_uuid7()
    after = MemoryStateV3.model_validate(
        {
            **state.model_dump(mode="python"),
            "revision": state.revision + 1,
            "content_protection": "cryptographically_erased",
            "updated_at": completed_at,
        }
    )
    payload = PayloadPurgeCompletedPayloadV3(
        previous_revision=state.revision,
        memory=after,
        content_key_id=state.content_key_id,
        key_destroyed_at=completed_at,
        destruction_receipt_sha256=receipt_sha256.hex(),
    )
    proposed = _purge_event(
        sequence=1,
        principal=principal,
        branch_id=state.branch_id,
        lineage_id=state.lineage_id,
        payload=payload,
        event_id=event_id,
        correlation_id=new_uuid7(),
        source_event_id=source_event_id,
        created_at=completed_at,
    )
    event = await append_memory_event(
        session, lambda sequence: proposed.model_copy(update={"sequence": sequence})
    )
    branch_row = await session.scalar(
        select(Branch).where(
            Branch.tenant_id == state.tenant_id,
            Branch.lineage_id == state.lineage_id,
            Branch.branch_id == state.branch_id,
        )
    )
    if branch_row is None:
        raise SealedContentPurgeError("invalid_job")
    before = await load_projection_state_for_update(
        session, event=event, branch=_branch_state(branch_row)
    )
    projection_after = validate_live_event(before, event)
    if projection_after.memories.get(memory_id) != after:
        raise SealedContentPurgeError("invalid_job")
    projection_update = cast(
        CursorResult[object],
        await session.execute(
            update(Memory)
            .where(
                Memory.tenant_id == state.tenant_id,
                Memory.lineage_id == state.lineage_id,
                Memory.branch_id == state.branch_id,
                Memory.memory_id == state.memory_id,
                Memory.revision == state.revision,
                Memory.last_event_id == source_event_id,
                Memory.status == "tombstoned",
                Memory.content_protection == "envelope_encrypted",
                Memory.content_key_id == state.content_key_id,
            )
            .values(
                revision=after.revision,
                content_protection="cryptographically_erased",
                updated_at=completed_at,
                last_event_id=event.event_id,
            )
        ),
    )
    if projection_update.rowcount != 1:
        raise SealedContentPurgeError("invalid_job")
    key_row.state = "destroyed"
    key_row.destroyed_at = completed_at
    key_row.destruction_receipt_sha256 = receipt_sha256
    await session.execute(
        delete(MemoryEmbeddingV1).where(
            MemoryEmbeddingV1.tenant_id == state.tenant_id,
            MemoryEmbeddingV1.memory_id == state.memory_id,
        )
    )
    await enqueue_outbox_job(
        session,
        tenant_id=state.tenant_id,
        job_type="export_git_batch",
        aggregate_type="event",
        aggregate_id=event.event_id,
        references={"event_id": event.event_id, "event_sequence": event.sequence},
    )
    await session.flush()
    return SealedContentPurgeResult(
        outcome="purged",
        memory_id=state.memory_id,
        revision=after.revision,
        event_id=event.event_id,
    )


__all__ = [
    "SealedContentPurgeError",
    "SealedContentPurgeResult",
    "handle_purge_payload_job",
]
