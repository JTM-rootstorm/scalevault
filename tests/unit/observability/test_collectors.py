from __future__ import annotations

import pytest
from kivra_memory.observability.collectors import (
    AggregateSnapshot,
    ArchiveAggregate,
    CredentialAggregate,
    DatabasePoolAggregate,
    QueueAggregate,
    apply_snapshot,
)
from kivra_memory.observability.metrics import MetricRegistry
from prometheus_client import generate_latest


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
