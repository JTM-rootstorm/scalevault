"""Content-free database snapshots through the reviewed observability function."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

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


class TenantDatabase(Protocol):
    def tenant_session(self, tenant_id: UUID) -> AbstractAsyncContextManager[AsyncSession]: ...


_SNAPSHOT_QUERY = text(
    """
    SELECT metric_name, label_one, label_two, label_three, metric_value
      FROM public.scalevault_observability_snapshot(:tenant_id)
    """
)
_SNAPSHOT_METRICS = frozenset(
    {"queue_depth", "queue_oldest_age", "credential_count", "archive_lag_events"}
)


class ObservabilitySnapshotRepository:
    """Read only bounded metric rows while running as the NOLOGIN capability role."""

    def __init__(self, database: TenantDatabase) -> None:
        self._database = database

    async def collect(self, tenant_id: UUID) -> AggregateSnapshot:
        async with self._database.tenant_session(tenant_id) as session:
            await session.execute(text("SET LOCAL ROLE kivra_memory_observability"))
            result = await session.execute(_SNAPSHOT_QUERY, {"tenant_id": tenant_id})
            rows = [cast(Mapping[str, object], row) for row in result.mappings().all()]
        return _snapshot_from_rows(rows)


def clear_snapshot(registry: MetricRegistry = REGISTRY) -> None:
    """Remove every database-derived aggregate sample after a failed refresh."""

    for metric_name in (
        "kivra_memory_queue_depth",
        "kivra_memory_queue_oldest_age_seconds",
        "kivra_memory_credentials_total",
        "kivra_memory_archive_lag_events",
        "kivra_memory_archive_lag_seconds",
    ):
        registry[metric_name].clear()


def _snapshot_from_rows(rows: list[Mapping[str, object]]) -> AggregateSnapshot:
    queue_depths: dict[tuple[str, str], int] = {}
    queue_ages: dict[str, float] = {}
    credentials: list[CredentialAggregate] = []
    archive_events: dict[str, int] = {}
    for row in rows:
        metric = str(row["metric_name"])
        if metric not in _SNAPSHOT_METRICS:
            raise ValueError("unknown_observability_metric")
        one = str(row["label_one"])
        raw_value = row["metric_value"]
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            raise ValueError("invalid_observability_metric_value")
        value = float(raw_value)
        _nonnegative(value, metric)
        if metric == "queue_depth":
            two = str(row["label_two"])
            queue_depths[(one, two)] = int(value)
        elif metric == "queue_oldest_age":
            queue_ages[one] = value
        elif metric == "credential_count":
            credentials.append(
                CredentialAggregate(one, str(row["label_two"]), str(row["label_three"]), int(value))
            )
        else:
            archive_events[one] = int(value)
    queues = tuple(
        QueueAggregate(queue, state, depth, queue_ages.get(queue, 0.0))
        for (queue, state), depth in sorted(queue_depths.items())
    )
    archive = tuple(
        ArchiveAggregate(stage, lag, 0.0) for stage, lag in sorted(archive_events.items())
    )
    return AggregateSnapshot(queues, tuple(credentials), archive)


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

    # Successful snapshots are complete. Clear prior labelled samples only
    # after validating the replacement, so disappeared rows cannot remain stale.
    clear_snapshot(registry)

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
    "ObservabilitySnapshotRepository",
    "QueueAggregate",
    "apply_snapshot",
    "clear_snapshot",
]
