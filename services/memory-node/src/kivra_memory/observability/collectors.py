"""Content-free aggregate snapshot ingestion for M10 operational metrics.

Storage and worker code may construct these value objects only after performing
its own tenant-safe aggregate query.  This module deliberately has no database
session and cannot read payload-bearing columns; a live database collector must
wait for the reviewed least-privilege SQL boundary required by the M10 ADR.
"""

from __future__ import annotations

from dataclasses import dataclass

from kivra_memory.observability.metrics import REGISTRY, MetricRegistry


def _nonnegative(value: float, field: str) -> None:
    if value < 0:
        raise ValueError(f"negative_aggregate:{field}")


@dataclass(frozen=True, slots=True)
class QueueAggregate:
    queue: str
    state: str
    depth: int
    oldest_age_seconds: float

    def __post_init__(self) -> None:
        _nonnegative(self.depth, "queue_depth")
        _nonnegative(self.oldest_age_seconds, "queue_oldest_age")


@dataclass(frozen=True, slots=True)
class CredentialAggregate:
    profile: str
    expiry: str
    state: str
    count: int

    def __post_init__(self) -> None:
        _nonnegative(self.count, "credential_count")


@dataclass(frozen=True, slots=True)
class ArchiveAggregate:
    stage: str
    lag_events: int
    lag_seconds: float

    def __post_init__(self) -> None:
        _nonnegative(self.lag_events, "archive_lag_events")
        _nonnegative(self.lag_seconds, "archive_lag_seconds")


@dataclass(frozen=True, slots=True)
class DatabasePoolAggregate:
    idle: int
    in_use: int
    overflow: int
    saturation_ratio: float

    def __post_init__(self) -> None:
        for field, value in (
            ("idle", self.idle),
            ("in_use", self.in_use),
            ("overflow", self.overflow),
            ("saturation_ratio", self.saturation_ratio),
        ):
            _nonnegative(value, field)
        if self.saturation_ratio > 1:
            raise ValueError("invalid_saturation_ratio")


@dataclass(frozen=True, slots=True)
class AggregateSnapshot:
    queues: tuple[QueueAggregate, ...] = ()
    credentials: tuple[CredentialAggregate, ...] = ()
    archive: tuple[ArchiveAggregate, ...] = ()
    database_pool: DatabasePoolAggregate | None = None


def apply_snapshot(
    snapshot: AggregateSnapshot,
    registry: MetricRegistry = REGISTRY,
) -> None:
    """Atomically validate, then publish one aggregate-only snapshot."""

    # Validate closed labels before changing any gauge.
    for queue_item in snapshot.queues:
        registry["kivra_memory_queue_depth"].validate_labels(
            queue=queue_item.queue, state=queue_item.state
        )
        registry["kivra_memory_queue_oldest_age_seconds"].validate_labels(queue=queue_item.queue)
    for credential_item in snapshot.credentials:
        registry["kivra_memory_credentials_total"].validate_labels(
            profile=credential_item.profile,
            expiry=credential_item.expiry,
            state=credential_item.state,
        )
    for archive_item in snapshot.archive:
        registry["kivra_memory_archive_lag_events"].validate_labels(stage=archive_item.stage)
        registry["kivra_memory_archive_lag_seconds"].validate_labels(stage=archive_item.stage)

    for queue_item in snapshot.queues:
        registry["kivra_memory_queue_depth"].set(
            queue_item.depth, queue=queue_item.queue, state=queue_item.state
        )
        registry["kivra_memory_queue_oldest_age_seconds"].set(
            queue_item.oldest_age_seconds, queue=queue_item.queue
        )
    for credential_item in snapshot.credentials:
        registry["kivra_memory_credentials_total"].set(
            credential_item.count,
            profile=credential_item.profile,
            expiry=credential_item.expiry,
            state=credential_item.state,
        )
    for archive_item in snapshot.archive:
        registry["kivra_memory_archive_lag_events"].set(
            archive_item.lag_events, stage=archive_item.stage
        )
        registry["kivra_memory_archive_lag_seconds"].set(
            archive_item.lag_seconds, stage=archive_item.stage
        )
    if snapshot.database_pool is not None:
        pool = snapshot.database_pool
        for state, value in (
            ("idle", pool.idle),
            ("in_use", pool.in_use),
            ("overflow", pool.overflow),
        ):
            registry["kivra_memory_database_pool_connections"].set(value, state=state)
        registry["kivra_memory_database_pool_saturation_ratio"].set(pool.saturation_ratio)


__all__ = [
    "AggregateSnapshot",
    "ArchiveAggregate",
    "CredentialAggregate",
    "DatabasePoolAggregate",
    "QueueAggregate",
    "apply_snapshot",
]
