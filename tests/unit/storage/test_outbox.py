from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.storage.models.operations import OutboxJob
from kivra_memory.storage.outbox import (
    enqueue_outbox_job,
    outbox_deduplication_key,
    validate_outbox_references,
)
from sqlalchemy.ext.asyncio import AsyncSession


def uid(value: int) -> UUID:
    return UUID(int=value)


def dedup(**overrides: object) -> str:
    values: dict[str, object] = {
        "tenant_id": uid(1),
        "job_type": "embed_memory",
        "aggregate_type": "memory",
        "aggregate_id": uid(2),
        "references": {"memory_id": uid(2), "memory_version": 3},
    }
    values.update(overrides)
    return outbox_deduplication_key(**values)  # type: ignore[arg-type]


def test_deduplication_key_is_stable_order_independent_and_versioned() -> None:
    first = dedup()
    reordered = dedup(references={"memory_version": 3, "memory_id": uid(2)})

    assert first == reordered
    assert first.startswith("v1:")
    assert len(first) == 67
    assert dedup(references={"memory_id": uid(2), "memory_version": 4}) != first
    assert dedup(job_type="check_duplicates") != first


def test_outbox_references_reject_content_bearing_names_and_values() -> None:
    with pytest.raises(ValueError, match="ID, version, or sequence"):
        validate_outbox_references({"statement": 1})
    with pytest.raises(TypeError, match="UUIDs"):
        validate_outbox_references({"memory_id": "private content"})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="UUIDs"):
        validate_outbox_references({"memory_version": -1})


def test_outbox_references_normalize_uuid_values_for_json() -> None:
    assert validate_outbox_references(
        {"memory_id": uid(2), "event_ids": (uid(4), uid(3)), "memory_version": 7}
    ) == {
        "event_ids": [str(uid(4)), str(uid(3))],
        "memory_id": str(uid(2)),
        "memory_version": 7,
    }


async def test_enqueue_stages_and_flushes_job_in_callers_transaction() -> None:
    raw = Mock(spec=AsyncSession)
    raw.add = Mock()
    raw.flush = AsyncMock()
    session = cast(AsyncSession, raw)
    available_at = datetime(2026, 8, 8, tzinfo=UTC)

    result = await enqueue_outbox_job(
        session,
        tenant_id=uid(1),
        job_type="embed_memory",
        aggregate_type="memory",
        aggregate_id=uid(2),
        references={"event_id": uid(3), "memory_version": 4},
        available_at=available_at,
        job_uuid=uid(5),
    )

    assert isinstance(result, OutboxJob)
    assert result.job_uuid == uid(5)
    assert result.payload == {"event_id": str(uid(3)), "memory_version": 4}
    assert result.available_at == available_at
    assert result.deduplication_key == dedup(references={"event_id": uid(3), "memory_version": 4})
    raw.add.assert_called_once_with(result)
    raw.flush.assert_awaited_once_with()


@pytest.mark.parametrize(
    "field,value", [("priority", 2**15), ("max_attempts", 0), ("max_attempts", 101)]
)
async def test_enqueue_validates_database_bounds_before_staging(field: str, value: int) -> None:
    raw = Mock(spec=AsyncSession)
    raw.add = Mock()
    raw.flush = AsyncMock()
    arguments = {field: value}

    with pytest.raises(ValueError):
        await enqueue_outbox_job(
            cast(AsyncSession, raw),
            tenant_id=uid(1),
            job_type="embed_memory",
            aggregate_type="memory",
            aggregate_id=uid(2),
            references={"memory_version": 1},
            **arguments,  # type: ignore[arg-type]
        )
    raw.add.assert_not_called()
    raw.flush.assert_not_awaited()
