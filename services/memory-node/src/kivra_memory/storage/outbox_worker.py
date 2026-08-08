"""Tenant-bound claiming and completion primitives for transactional outbox workers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, cast
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.models.operations import OutboxJob

_SAFE_ERROR_SUMMARIES: Final[dict[str, str]] = {
    "dependency_unavailable": "A required local dependency is unavailable.",
    "embedding_failed": "The local embedding operation failed.",
    "internal_error": "The worker could not complete the operation.",
    "invalid_job": "The queued operation is invalid.",
    "lease_expired": "The previous worker lease expired.",
    "model_unavailable": "The configured local embedding model is unavailable.",
}
_OWNER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,74}$")


class OutboxWorkerError(RuntimeError):
    """Stable, content-free base error for outbox worker operations."""


class LeaseLostError(OutboxWorkerError):
    """A guarded lease mutation no longer owns the target job."""


@dataclass(frozen=True, slots=True)
class ClaimedOutboxJob:
    job_id: int
    job_uuid: UUID
    tenant_id: UUID
    job_type: str
    aggregate_type: str
    aggregate_id: UUID | None
    payload: dict[str, object]
    attempt_count: int
    max_attempts: int
    lease_token: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validate_owner(worker_owner: str) -> None:
    if _OWNER_PATTERN.fullmatch(worker_owner) is None:
        raise ValueError("worker owner must be a bounded opaque identifier")


def _validate_timing(*, batch_size: int, lease_seconds: int) -> None:
    if not 1 <= batch_size <= 100:
        raise ValueError("batch_size must be between 1 and 100")
    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600")


async def claim_outbox_jobs(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    worker_owner: str,
    job_types: tuple[str, ...],
    batch_size: int = 8,
    lease_seconds: int = 120,
    now: datetime | None = None,
) -> tuple[ClaimedOutboxJob, ...]:
    """Lock and lease a disjoint tenant-scoped batch with ``SKIP LOCKED``."""

    if not session.in_transaction():
        raise OutboxWorkerError("active_transaction_required")
    _validate_owner(worker_owner)
    _validate_timing(batch_size=batch_size, lease_seconds=lease_seconds)
    if not job_types or len(set(job_types)) != len(job_types):
        raise ValueError("job_types must be a non-empty unique tuple")

    claimed_at = now or _utc_now()
    rows = (
        await session.scalars(
            select(OutboxJob)
            .where(
                OutboxJob.tenant_id == tenant_id,
                OutboxJob.state == "pending",
                OutboxJob.available_at <= claimed_at,
                OutboxJob.attempt_count < OutboxJob.max_attempts,
                OutboxJob.job_type.in_(job_types),
            )
            .order_by(OutboxJob.available_at, OutboxJob.job_id)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
    ).all()

    claimed: list[ClaimedOutboxJob] = []
    expires_at = claimed_at + timedelta(seconds=lease_seconds)
    for row in rows:
        token = f"{worker_owner}:{new_uuid7()}"
        row.state = "leased"
        row.lease_owner = token
        row.lease_expires_at = expires_at
        row.attempt_count += 1
        row.updated_at = claimed_at
        claimed.append(
            ClaimedOutboxJob(
                job_id=row.job_id,
                job_uuid=row.job_uuid,
                tenant_id=row.tenant_id,
                job_type=row.job_type,
                aggregate_type=row.aggregate_type,
                aggregate_id=row.aggregate_id,
                payload=dict(row.payload),
                attempt_count=row.attempt_count,
                max_attempts=row.max_attempts,
                lease_token=token,
            )
        )
    await session.flush()
    return tuple(claimed)


async def heartbeat_outbox_job(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    job_id: int,
    lease_token: str,
    lease_seconds: int = 120,
    now: datetime | None = None,
) -> None:
    """Extend exactly one still-owned lease."""

    _validate_timing(batch_size=1, lease_seconds=lease_seconds)
    heartbeat_at = now or _utc_now()
    result = cast(
        CursorResult[Any],
        await session.execute(
            update(OutboxJob)
            .where(
                OutboxJob.tenant_id == tenant_id,
                OutboxJob.job_id == job_id,
                OutboxJob.state == "leased",
                OutboxJob.lease_owner == lease_token,
                OutboxJob.lease_expires_at > heartbeat_at,
            )
            .values(
                lease_expires_at=heartbeat_at + timedelta(seconds=lease_seconds),
                updated_at=heartbeat_at,
            )
        ),
    )
    if result.rowcount != 1:
        raise LeaseLostError("outbox_lease_lost")


async def acknowledge_outbox_job(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    job_id: int,
    lease_token: str,
    now: datetime | None = None,
) -> None:
    """Mark a still-owned, unexpired job as succeeded."""

    completed_at = now or _utc_now()
    result = cast(
        CursorResult[Any],
        await session.execute(
            update(OutboxJob)
            .where(
                OutboxJob.tenant_id == tenant_id,
                OutboxJob.job_id == job_id,
                OutboxJob.state == "leased",
                OutboxJob.lease_owner == lease_token,
                OutboxJob.lease_expires_at > completed_at,
            )
            .values(
                state="succeeded",
                lease_owner=None,
                lease_expires_at=None,
                last_error_code=None,
                last_error_summary=None,
                completed_at=completed_at,
                updated_at=completed_at,
            )
        ),
    )
    if result.rowcount != 1:
        raise LeaseLostError("outbox_lease_lost")


async def fail_outbox_job(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    job_id: int,
    lease_token: str,
    error_code: str,
    retryable: bool,
    retry_delay_seconds: int = 30,
    now: datetime | None = None,
) -> str:
    """Record a sanitized failure, returning the resulting pending/dead state."""

    summary = _SAFE_ERROR_SUMMARIES.get(error_code)
    if summary is None:
        raise ValueError("error_code is not allowlisted")
    if not 0 <= retry_delay_seconds <= 86400:
        raise ValueError("retry_delay_seconds must be between zero and one day")
    failed_at = now or _utc_now()
    row = await session.scalar(
        select(OutboxJob)
        .where(
            OutboxJob.tenant_id == tenant_id,
            OutboxJob.job_id == job_id,
            OutboxJob.state == "leased",
            OutboxJob.lease_owner == lease_token,
            OutboxJob.lease_expires_at > failed_at,
        )
        .with_for_update()
    )
    if row is None:
        raise LeaseLostError("outbox_lease_lost")

    terminal = not retryable or row.attempt_count >= row.max_attempts
    row.state = "dead" if terminal else "pending"
    row.lease_owner = None
    row.lease_expires_at = None
    row.last_error_code = error_code
    row.last_error_summary = summary
    row.completed_at = failed_at if terminal else None
    row.available_at = failed_at + timedelta(seconds=retry_delay_seconds)
    row.updated_at = failed_at
    await session.flush()
    return row.state


async def recover_expired_outbox_leases(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    job_types: tuple[str, ...],
    batch_size: int = 100,
    retry_delay_seconds: int = 30,
    now: datetime | None = None,
) -> tuple[int, int]:
    """Return expired leases to pending or mark exhausted jobs dead."""

    if not 1 <= batch_size <= 1000:
        raise ValueError("batch_size must be between 1 and 1000")
    if not 0 <= retry_delay_seconds <= 86400:
        raise ValueError("retry_delay_seconds must be between zero and one day")
    if not job_types:
        raise ValueError("job_types must not be empty")
    recovered_at = now or _utc_now()
    rows = (
        await session.scalars(
            select(OutboxJob)
            .where(
                OutboxJob.tenant_id == tenant_id,
                OutboxJob.state == "leased",
                OutboxJob.lease_expires_at <= recovered_at,
                OutboxJob.job_type.in_(job_types),
            )
            .order_by(OutboxJob.lease_expires_at, OutboxJob.job_id)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
    ).all()
    pending = 0
    dead = 0
    for row in rows:
        terminal = row.attempt_count >= row.max_attempts
        row.state = "dead" if terminal else "pending"
        row.lease_owner = None
        row.lease_expires_at = None
        row.last_error_code = "lease_expired"
        row.last_error_summary = _SAFE_ERROR_SUMMARIES["lease_expired"]
        row.completed_at = recovered_at if terminal else None
        row.available_at = recovered_at + timedelta(seconds=retry_delay_seconds)
        row.updated_at = recovered_at
        dead += int(terminal)
        pending += int(not terminal)
    await session.flush()
    return pending, dead
