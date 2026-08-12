"""Fail-closed clean-database restore orchestration."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.archive.restore import RestorePlan as CoreRestorePlan
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.storage.archive import RestorePlan, restore_archive_rows
from kivra_memory.storage.models import Memory
from kivra_memory.storage.outbox import enqueue_outbox_job
from kivra_memory.storage.projector import rebuild_semantic_projections


@dataclass(frozen=True, slots=True)
class ArchiveRestoreResult:
    """Content-free result returned after restored-state verification."""

    tenant_id: UUID
    final_high_water_sequence: int
    embedding_jobs_queued: int = 0


class ValidatedRestoreDecoder[VerifiedPlanT](Protocol):
    """Decode a plan already produced by archive signature/content preflight."""

    def decode(self, verified_plan: VerifiedPlanT) -> RestorePlan: ...


class RestoredStateVerifier(Protocol):
    """Compare reconstructed aggregate identity with the verified archive."""

    async def verify(self, session: AsyncSession, plan: RestorePlan) -> None: ...


class CoreRestoreDecoder:
    """Translate the archive core's verified plan into reversible database rows."""

    def decode(self, verified_plan: CoreRestorePlan) -> RestorePlan:
        tables = {table.name: table.rows for table in verified_plan.snapshot_tables}
        tenant_rows = tables.get("tenants", ())
        if len(tenant_rows) != 1:
            raise ValueError("restore snapshot must contain exactly one tenant")
        try:
            tenant_id = UUID(str(tenant_rows[0]["tenant_id"]))
        except (KeyError, TypeError, ValueError):
            raise ValueError("restore snapshot tenant identity is invalid") from None

        later_events: list[dict[str, object]] = []
        for event in verified_plan.events_to_replay:
            try:
                payload_canonical = base64.b64decode(event.payload_canonical, validate=True)
                payload_sha256 = bytes.fromhex(event.payload_sha256)
                command_sha256 = bytes.fromhex(event.command_sha256)
            except ValueError:
                raise ValueError("verified restore event encoding is invalid") from None
            later_events.append(
                {
                    "sequence": event.sequence,
                    "event_id": event.event_id,
                    "tenant_id": event.tenant_id,
                    "lineage_id": event.lineage_id,
                    "branch_id": event.branch_id,
                    "actor_id": event.actor_id,
                    "client_id": event.client_id,
                    "transport_binding_id": event.transport_binding_id,
                    "session_id": event.session_id,
                    "ingress_id": event.ingress_id,
                    "operation": event.operation.value,
                    "memory_id": event.memory_id,
                    "expected_revision": event.expected_revision,
                    "causation_event_id": event.causation_event_id,
                    "correlation_id": event.correlation_id,
                    "idempotency_key": event.idempotency_key,
                    "schema_version": event.schema_version,
                    "payload_version": event.payload_version,
                    "policy_version": event.policy_version,
                    "normalization_version": event.normalization_version,
                    # Snapshot JSON columns are canonical JSON bytes so the CBOR
                    # archive remains float-free and restore can reverse the DTO.
                    # Later events must use that exact storage boundary too.
                    "payload": canonical_json_bytes(event.payload),
                    "payload_canonical": payload_canonical,
                    "payload_sha256": payload_sha256,
                    "command_sha256": command_sha256,
                    "created_at": event.created_at,
                }
            )
        return RestorePlan(
            tenant_id=tenant_id,
            snapshot_high_water_sequence=verified_plan.snapshot_high_water_sequence,
            final_high_water_sequence=verified_plan.final_high_water_sequence,
            rows=tables,
            later_events=tuple(later_events),
        )


async def restore_validated_archive[VerifiedPlanT](
    session: AsyncSession,
    *,
    verified_plan: VerifiedPlanT,
    decoder: ValidatedRestoreDecoder[VerifiedPlanT],
    verifier: RestoredStateVerifier,
    requeue_embeddings: bool = False,
) -> ArchiveRestoreResult:
    """Decode before mutation, restore once, then verify in the same transaction.

    The caller supplies only the result of archive preflight (commit signatures,
    manifest chain, hashes, schemas, limits, and snapshot boundary). A verifier
    failure aborts the caller-owned transaction and never leaves a partial restore.
    """

    plan = decoder.decode(verified_plan)
    await restore_archive_rows(session, plan)
    await rebuild_semantic_projections(session, tenant_id=plan.tenant_id)
    await verifier.verify(session, plan)
    queued = (
        await requeue_restored_embeddings(session, tenant_id=plan.tenant_id)
        if requeue_embeddings
        else 0
    )
    return ArchiveRestoreResult(
        tenant_id=plan.tenant_id,
        final_high_water_sequence=plan.final_high_water_sequence,
        embedding_jobs_queued=queued,
    )


async def requeue_restored_embeddings(
    session: AsyncSession,
    *,
    tenant_id: UUID,
) -> int:
    """Queue one idempotent content-free embedding rebuild job per restored memory."""

    if not session.in_transaction():
        raise ValueError("embedding recovery requires an active transaction")
    memories = tuple(
        (
            await session.execute(
                select(Memory).where(Memory.tenant_id == tenant_id).order_by(Memory.memory_id)
            )
        )
        .scalars()
        .all()
    )
    for memory in memories:
        await enqueue_outbox_job(
            session,
            tenant_id=tenant_id,
            job_type="embed_memory",
            aggregate_type="memory",
            aggregate_id=memory.memory_id,
            references={
                "memory_id": memory.memory_id,
                "memory_version": memory.revision,
                "event_id": memory.last_event_id,
            },
        )
    return len(memories)
