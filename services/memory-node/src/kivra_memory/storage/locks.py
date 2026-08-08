"""Deterministic, content-free PostgreSQL advisory lock primitives."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.identifiers import require_uuid7

_AGGREGATE_LOCK_DOMAIN = b"sv-aggregate-v1"
_IDEMPOTENCY_LOCK_DOMAIN = b"sv-idempotency1"


def _framed(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def advisory_lock_key(
    *,
    tenant_id: UUID,
    lineage_id: UUID,
    branch_id: UUID,
    subject_id: UUID,
    normalized_fingerprint: str | bytes,
) -> int:
    """Derive a stable signed 64-bit key without retaining the source values.

    Length framing makes the derivation unambiguous. The returned signed integer
    spans PostgreSQL's complete ``bigint`` advisory-lock key space.
    """

    if isinstance(normalized_fingerprint, str):
        if len(normalized_fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in normalized_fingerprint
        ):
            raise ValueError("normalized_fingerprint must be exactly 64 lowercase hex characters")
        fingerprint_bytes = bytes.fromhex(normalized_fingerprint)
    elif isinstance(normalized_fingerprint, bytes) and len(normalized_fingerprint) == 32:
        fingerprint_bytes = normalized_fingerprint
    else:
        raise ValueError("normalized_fingerprint must be exactly 32 bytes")

    digest = hashlib.blake2b(digest_size=8, person=_AGGREGATE_LOCK_DOMAIN)
    for identifier in (tenant_id, lineage_id, branch_id, subject_id):
        if not isinstance(identifier, UUID):
            raise TypeError("advisory lock identifiers must be UUID values")
        require_uuid7(identifier, field_name="advisory lock identifier")
        digest.update(_framed(identifier.bytes))
    digest.update(_framed(fingerprint_bytes))
    return int.from_bytes(digest.digest(), "big", signed=True)


def idempotency_advisory_lock_key(*, tenant_id: UUID, client_id: UUID, idempotency_key: str) -> int:
    """Derive a separate lock namespace for one command idempotency scope."""

    if not 1 <= len(idempotency_key) <= 255:
        raise ValueError("idempotency_key must contain between 1 and 255 characters")
    digest = hashlib.blake2b(digest_size=8, person=_IDEMPOTENCY_LOCK_DOMAIN)
    for identifier in (tenant_id, client_id):
        if not isinstance(identifier, UUID):
            raise TypeError("idempotency lock identifiers must be UUID values")
        require_uuid7(identifier, field_name="idempotency lock identifier")
        digest.update(_framed(identifier.bytes))
    digest.update(_framed(idempotency_key.encode("utf-8")))
    return int.from_bytes(digest.digest(), "big", signed=True)


def ordered_lock_keys(keys: Iterable[int]) -> tuple[int, ...]:
    """Return unique PostgreSQL bigint lock keys in deterministic order."""

    unique = set(keys)
    if any(key < -(2**63) or key >= 2**63 for key in unique):
        raise ValueError("advisory lock key must fit a signed 64-bit integer")
    return tuple(sorted(unique))


async def acquire_advisory_xact_lock(session: AsyncSession, key: int) -> None:
    """Acquire one transaction-scoped advisory lock."""

    if key < -(2**63) or key >= 2**63:
        raise ValueError("advisory lock key must fit a signed 64-bit integer")
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": key},
    )


async def acquire_advisory_xact_locks(session: AsyncSession, keys: Iterable[int]) -> None:
    """Acquire a set of transaction locks in a process-independent order."""

    for key in ordered_lock_keys(keys):
        await acquire_advisory_xact_lock(session, key)
