"""Transactional outbox enqueue primitives with content-free job payloads."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.models.operations import OutboxJob

OutboxReferenceValue = UUID | int | tuple[UUID, ...]

_REFERENCE_SUFFIXES = ("_id", "_ids", "_version", "_sequence")


def _reference_bytes(key: str, value: OutboxReferenceValue) -> bytes:
    if isinstance(value, UUID):
        rendered = f"uuid:{value}"
    elif isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        rendered = f"int:{value}"
    elif (
        isinstance(value, tuple)
        and key.endswith("_ids")
        and all(isinstance(item, UUID) for item in value)
    ):
        rendered = "uuids:" + ",".join(str(item) for item in value)
    else:
        raise TypeError("outbox references must be UUIDs, non-negative integers, or UUID tuples")
    return rendered.encode("ascii")


def validate_outbox_references(
    references: Mapping[str, OutboxReferenceValue],
) -> dict[str, object]:
    """Validate and JSON-normalize an IDs-and-versions-only payload."""

    payload: dict[str, object] = {}
    for key in sorted(references):
        if not key or not key.isascii() or not key.endswith(_REFERENCE_SUFFIXES):
            raise ValueError("outbox reference names must identify an ID, version, or sequence")
        value = references[key]
        _reference_bytes(key, value)
        if isinstance(value, tuple):
            payload[key] = [str(item) for item in value]
        elif isinstance(value, UUID):
            payload[key] = str(value)
        else:
            payload[key] = value
    return payload


def outbox_deduplication_key(
    *,
    tenant_id: UUID,
    job_type: str,
    aggregate_type: str,
    aggregate_id: UUID | None,
    references: Mapping[str, OutboxReferenceValue],
) -> str:
    """Build the stable v1 identity for a logical outbox side effect."""

    if not job_type or not aggregate_type:
        raise ValueError("job_type and aggregate_type must not be empty")
    validate_outbox_references(references)
    digest = hashlib.sha256()
    fields: list[tuple[str, bytes]] = [
        ("tenant_id", tenant_id.bytes),
        ("job_type", job_type.encode("utf-8")),
        ("aggregate_type", aggregate_type.encode("utf-8")),
        ("aggregate_id", aggregate_id.bytes if aggregate_id is not None else b""),
    ]
    fields.extend((key, _reference_bytes(key, references[key])) for key in sorted(references))
    for key, value in fields:
        key_bytes = key.encode("ascii")
        digest.update(len(key_bytes).to_bytes(2, "big"))
        digest.update(key_bytes)
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return f"v1:{digest.hexdigest()}"


async def enqueue_outbox_job(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    job_type: str,
    aggregate_type: str,
    aggregate_id: UUID | None,
    references: Mapping[str, OutboxReferenceValue],
    priority: int = 0,
    max_attempts: int = 8,
    available_at: datetime | None = None,
    job_uuid: UUID | None = None,
) -> OutboxJob:
    """Stage a job in the caller-owned transaction and return its ORM row."""

    if not -(2**15) <= priority < 2**15:
        raise ValueError("priority must fit a signed 16-bit integer")
    if not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    payload = validate_outbox_references(references)
    job = OutboxJob(
        job_uuid=job_uuid or new_uuid7(),
        tenant_id=tenant_id,
        job_type=job_type,
        deduplication_key=outbox_deduplication_key(
            tenant_id=tenant_id,
            job_type=job_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            references=references,
        ),
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload,
        priority=priority,
        max_attempts=max_attempts,
        **({"available_at": available_at} if available_at is not None else {}),
    )
    session.add(job)
    await session.flush()
    return job
