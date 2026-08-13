from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

import pytest
from kivra_memory.observability.collectors import (
    AggregateSnapshot,
    ArchiveAggregate,
    CredentialAggregate,
    DatabasePoolAggregate,
    ObservabilitySnapshotRepository,
    QueueAggregate,
    apply_snapshot,
)
from kivra_memory.observability.metrics import MetricRegistry
from prometheus_client import generate_latest


class _Mappings:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Result:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> _Mappings:
        return _Mappings(self._rows)


class _Session:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def execute(
        self, statement: object, parameters: dict[str, object] | None = None
    ) -> _Result:
        self.calls.append((" ".join(str(statement).split()), parameters or {}))
        return _Result(self.rows if "scalevault_observability_snapshot" in str(statement) else [])


class _Database:
    def __init__(self, session: _Session) -> None:
        self.session = session

    @asynccontextmanager
    async def tenant_session(self, _tenant_id: object) -> AsyncIterator[Any]:
        yield self.session


def test_aggregate_snapshot_publishes_only_fixed_labels_and_numbers() -> None:
    registry = MetricRegistry()
    apply_snapshot(
        AggregateSnapshot(
            queues=(QueueAggregate("embedding", "pending", 4, 12.5),),
            credentials=(CredentialAggregate("direct_private", "le_7d", "active", 2),),
            archive=(ArchiveAggregate("push", 7, 30.0),),
            database_pool=DatabasePoolAggregate(2, 3, 0, 0.6),
        ),
        registry,
    )
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert 'kivra_memory_queue_depth{queue="embedding",state="pending"} 4.0' in rendered
    assert "direct_private" in rendered
    assert "SYNTHETIC_PRIVATE_CANARY" not in rendered


def test_aggregate_snapshot_rejects_unbounded_labels_before_publishing() -> None:
    registry = MetricRegistry()
    snapshot = AggregateSnapshot(
        queues=(QueueAggregate("SYNTHETIC_PRIVATE_CANARY", "pending", 1, 1),)
    )
    with pytest.raises(ValueError, match="invalid_label_value"):
        apply_snapshot(snapshot, registry)
    assert "SYNTHETIC_PRIVATE_CANARY" not in generate_latest(registry.prometheus).decode("ascii")


def test_aggregate_types_reject_negative_counts() -> None:
    with pytest.raises(ValueError, match="negative_aggregate"):
        QueueAggregate("embedding", "pending", -1, 0)
    with pytest.raises(ValueError, match="negative_aggregate"):
        CredentialAggregate("direct_private", "le_7d", "active", -1)
    with pytest.raises(ValueError, match="negative_aggregate"):
        ArchiveAggregate("push", -1, 0)


@pytest.mark.asyncio
async def test_database_snapshot_uses_only_capability_function() -> None:
    tenant_id = UUID("01970000-0000-7000-8000-000000000001")
    session = _Session(
        [
            {
                "metric_name": "queue_depth",
                "label_one": "embedding",
                "label_two": "pending",
                "label_three": None,
                "metric_value": 4.0,
            },
            {
                "metric_name": "queue_oldest_age",
                "label_one": "embedding",
                "label_two": None,
                "label_three": None,
                "metric_value": 12.5,
            },
        ]
    )
    snapshot = await ObservabilitySnapshotRepository(_Database(session)).collect(tenant_id)
    assert snapshot.queues == (QueueAggregate("embedding", "pending", 4, 12.5),)
    assert session.calls == [
        ("SET LOCAL ROLE kivra_memory_observability", {}),
        (
            "SELECT metric_name, label_one, label_two, label_three, metric_value "
            "FROM public.scalevault_observability_snapshot(:tenant_id)",
            {"tenant_id": tenant_id},
        ),
    ]
    assert "outbox_jobs" not in inspect.getsource(ObservabilitySnapshotRepository)


@pytest.mark.asyncio
async def test_database_snapshot_rejects_unreviewed_metric_name() -> None:
    session = _Session(
        [
            {
                "metric_name": "SYNTHETIC_PRIVATE_CANARY",
                "label_one": "embedding",
                "label_two": None,
                "label_three": None,
                "metric_value": 1,
            }
        ]
    )
    with pytest.raises(ValueError, match="unknown_observability_metric"):
        await ObservabilitySnapshotRepository(_Database(session)).collect(
            UUID("01970000-0000-7000-8000-000000000001")
        )
