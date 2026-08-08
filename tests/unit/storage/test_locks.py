from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.locks import (
    acquire_advisory_xact_locks,
    advisory_lock_key,
    idempotency_advisory_lock_key,
    ordered_lock_keys,
)
from sqlalchemy.ext.asyncio import AsyncSession


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def lock_key(**overrides: object) -> int:
    values: dict[str, object] = {
        "tenant_id": uid(1),
        "lineage_id": uid(2),
        "branch_id": uid(3),
        "subject_id": uid(4),
        "normalized_fingerprint": "ab" * 32,
    }
    values.update(overrides)
    return advisory_lock_key(**values)  # type: ignore[arg-type]


def test_advisory_key_is_stable_signed_64_bit_and_sensitive_to_every_scope() -> None:
    expected = lock_key()

    assert lock_key() == expected
    assert -(2**63) <= expected < 2**63
    assert lock_key(tenant_id=uid(10)) != expected
    assert lock_key(lineage_id=uid(20)) != expected
    assert lock_key(branch_id=uid(30)) != expected
    assert lock_key(subject_id=uid(40)) != expected
    assert lock_key(normalized_fingerprint="cd" * 32) != expected


def test_advisory_key_rejects_ambiguous_or_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="64 lowercase hex"):
        lock_key(normalized_fingerprint="")
    with pytest.raises(ValueError, match="64 lowercase hex"):
        lock_key(normalized_fingerprint="AB" * 32)
    with pytest.raises(TypeError, match="UUID"):
        lock_key(subject_id="not-a-uuid")


def test_advisory_key_accepts_equivalent_binary_fingerprint() -> None:
    assert lock_key(normalized_fingerprint="ab" * 32) == lock_key(
        normalized_fingerprint=bytes.fromhex("ab" * 32)
    )


def test_idempotency_lock_has_a_separate_stable_namespace() -> None:
    key = idempotency_advisory_lock_key(
        tenant_id=uid(1), client_id=uid(2), idempotency_key="client:session:request"
    )

    assert key == idempotency_advisory_lock_key(
        tenant_id=uid(1), client_id=uid(2), idempotency_key="client:session:request"
    )
    assert key != idempotency_advisory_lock_key(
        tenant_id=uid(1), client_id=uid(2), idempotency_key="client:session:other"
    )
    assert key != lock_key()
    with pytest.raises(ValueError, match="1 and 255"):
        idempotency_advisory_lock_key(tenant_id=uid(1), client_id=uid(2), idempotency_key="")


def test_ordered_lock_keys_sorts_and_deduplicates() -> None:
    assert ordered_lock_keys([5, -2, 5, 0]) == (-2, 0, 5)

    with pytest.raises(ValueError, match="64-bit"):
        ordered_lock_keys([2**63])


async def test_multiple_locks_are_acquired_in_deterministic_order() -> None:
    raw = Mock(spec=AsyncSession)
    raw.execute = AsyncMock()
    session = cast(AsyncSession, raw)

    await acquire_advisory_xact_locks(session, [9, -3, 2, 9])

    assert [call.args[1] for call in raw.execute.await_args_list] == [
        {"lock_key": -3},
        {"lock_key": 2},
        {"lock_key": 9},
    ]
    assert all(
        str(call.args[0]) == "SELECT pg_advisory_xact_lock(:lock_key)"
        for call in raw.execute.await_args_list
    )
