"""Content-free database snapshots through the reviewed observability function."""

from __future__ import annotations

import math
import os
import time
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.canonical_json import parse_json_strict
from kivra_memory.observability.metrics import REGISTRY, MetricRegistry
from kivra_memory.security.credential_files import read_protected_file

OPERATIONAL_STATUS_PATH = Path("/run/kivra-memory-metrics/status.json")
MAXIMUM_OPERATIONAL_STATUS_BYTES = 4096
MAXIMUM_OPERATIONAL_STATUS_AGE_SECONDS = 120.0
MAXIMUM_OPERATIONAL_STATUS_FUTURE_SKEW_SECONDS = 5.0
STORAGE_COMPONENTS = ("backup", "database", "monitoring", "wal")
OPERATIONAL_COUNTERS = (
    "base_backup_failure",
    "base_backup_success",
    "backup_verification_failure",
    "backup_verification_success",
    "wal_archive_failure_command",
    "wal_archive_failure_storage",
    "wal_archive_failure_timeout",
    "wal_archive_failure_unavailable",
    "wal_archive_success",
)


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


@dataclass(frozen=True, slots=True)
class OperationalSnapshot:
    backup_age_seconds: float
    wal_oldest_age_seconds: float
    storage_free_bytes: tuple[tuple[str, int], ...]
    storage_free_ratio: tuple[tuple[str, float], ...]
    result_counters: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        _nonnegative(self.backup_age_seconds, "backup_age_seconds")
        _nonnegative(self.wal_oldest_age_seconds, "wal_oldest_age_seconds")
        if tuple(component for component, _value in self.storage_free_bytes) != STORAGE_COMPONENTS:
            raise ValueError("invalid_storage_components")
        if tuple(component for component, _value in self.storage_free_ratio) != STORAGE_COMPONENTS:
            raise ValueError("invalid_storage_components")
        if tuple(name for name, _value in self.result_counters) != OPERATIONAL_COUNTERS:
            raise ValueError("invalid_operational_counters")
        for _component, byte_value in self.storage_free_bytes:
            if isinstance(byte_value, bool) or not isinstance(byte_value, int) or byte_value < 0:
                raise ValueError("invalid_storage_free_bytes")
        for _component, ratio_value in self.storage_free_ratio:
            if (
                isinstance(ratio_value, bool)
                or not isinstance(ratio_value, (int, float))
                or not math.isfinite(ratio_value)
                or not 0 <= ratio_value <= 1
            ):
                raise ValueError("invalid_storage_free_ratio")
        for _name, counter_value in self.result_counters:
            if (
                isinstance(counter_value, bool)
                or not isinstance(counter_value, int)
                or not 0 <= counter_value <= (1 << 53) - 1
            ):
                raise ValueError("invalid_operational_counter")


class TenantDatabase(Protocol):
    def tenant_session(self, tenant_id: UUID) -> AbstractAsyncContextManager[AsyncSession]: ...


def _strict_number(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"invalid_operational_status:{field}")
    return float(value)


class OperationalStatusRepository:
    """Read the one-way, content-free publisher seam without backup-store access."""

    def __init__(self, path: Path = OPERATIONAL_STATUS_PATH) -> None:
        self._path = path
        self._last_counters: tuple[tuple[str, int], ...] | None = None

    def collect(self, *, now: float | None = None) -> OperationalSnapshot:
        raw = read_protected_file(
            self._path,
            minimum_bytes=1,
            maximum_bytes=MAXIMUM_OPERATIONAL_STATUS_BYTES,
            required_owner_uid=0,
            required_group_gid=os.getegid(),
            allowed_modes=frozenset({0o640}),
        )
        parsed = parse_json_strict(raw)
        if not isinstance(parsed, dict) or set(parsed) != {
            "generated_at_unixtime",
            "latest_base_unixtime",
            "result_counters",
            "storage_free_bytes",
            "storage_free_ratio",
            "version",
            "wal_oldest_ready_unixtime",
        }:
            raise ValueError("invalid_operational_status:schema")
        if parsed["version"] != 1:
            raise ValueError("invalid_operational_status:version")
        selected_now = time.time() if now is None else now
        generated_at = _strict_number(parsed["generated_at_unixtime"], "generated_at")
        latest_base = _strict_number(parsed["latest_base_unixtime"], "latest_base")
        wal_oldest = _strict_number(parsed["wal_oldest_ready_unixtime"], "wal_oldest")
        if (
            generated_at > selected_now + MAXIMUM_OPERATIONAL_STATUS_FUTURE_SKEW_SECONDS
            or selected_now - generated_at > MAXIMUM_OPERATIONAL_STATUS_AGE_SECONDS
            or latest_base > generated_at
            or wal_oldest > generated_at
        ):
            raise ValueError("invalid_operational_status:freshness")
        byte_values = parsed["storage_free_bytes"]
        ratio_values = parsed["storage_free_ratio"]
        counter_values = parsed["result_counters"]
        if (
            not isinstance(byte_values, dict)
            or tuple(sorted(byte_values)) != STORAGE_COMPONENTS
            or not isinstance(ratio_values, dict)
            or tuple(sorted(ratio_values)) != STORAGE_COMPONENTS
            or not isinstance(counter_values, dict)
            or set(counter_values) != set(OPERATIONAL_COUNTERS)
        ):
            raise ValueError("invalid_operational_status:storage")
        storage_bytes: list[tuple[str, int]] = []
        storage_ratios: list[tuple[str, float]] = []
        counters: list[tuple[str, int]] = []
        for component in STORAGE_COMPONENTS:
            byte_value = byte_values[component]
            if isinstance(byte_value, bool) or not isinstance(byte_value, int) or byte_value < 0:
                raise ValueError("invalid_operational_status:storage_bytes")
            ratio_value = _strict_number(ratio_values[component], "storage_ratio")
            if ratio_value > 1:
                raise ValueError("invalid_operational_status:storage_ratio")
            storage_bytes.append((component, byte_value))
            storage_ratios.append((component, ratio_value))
        for name in OPERATIONAL_COUNTERS:
            counter_value = counter_values[name]
            if (
                isinstance(counter_value, bool)
                or not isinstance(counter_value, int)
                or not 0 <= counter_value <= (1 << 53) - 1
            ):
                raise ValueError("invalid_operational_status:counters")
            counters.append((name, counter_value))
        snapshot = OperationalSnapshot(
            backup_age_seconds=max(0.0, selected_now - latest_base),
            wal_oldest_age_seconds=max(0.0, selected_now - wal_oldest),
            storage_free_bytes=tuple(storage_bytes),
            storage_free_ratio=tuple(storage_ratios),
            result_counters=tuple(counters),
        )
        if self._last_counters is not None and any(
            current < previous
            for (_name, current), (_prior_name, previous) in zip(
                snapshot.result_counters, self._last_counters, strict=True
            )
        ):
            raise ValueError("invalid_operational_status:counter_regression")
        self._last_counters = snapshot.result_counters
        return snapshot


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


def clear_operational_snapshot(registry: MetricRegistry = REGISTRY) -> None:
    """Remove every sample sourced from the privileged metadata publisher."""

    for metric_name in (
        "kivra_memory_backup_age_seconds",
        "kivra_memory_wal_oldest_age_seconds",
        "kivra_memory_storage_free_bytes",
        "kivra_memory_storage_free_ratio",
        "kivra_memory_backup_results_total",
        "kivra_memory_backup_verification_results_total",
        "kivra_memory_wal_archive_failures_total",
    ):
        registry[metric_name].clear()


def apply_operational_snapshot(
    snapshot: OperationalSnapshot,
    registry: MetricRegistry = REGISTRY,
) -> None:
    """Publish one complete fixed-label operational snapshot."""

    for byte_component, _byte_value in snapshot.storage_free_bytes:
        registry["kivra_memory_storage_free_bytes"].validate_labels(component=byte_component)
    for ratio_component, _ratio_value in snapshot.storage_free_ratio:
        registry["kivra_memory_storage_free_ratio"].validate_labels(component=ratio_component)
    clear_operational_snapshot(registry)
    registry["kivra_memory_backup_age_seconds"].set(snapshot.backup_age_seconds, kind="base")
    registry["kivra_memory_wal_oldest_age_seconds"].set(snapshot.wal_oldest_age_seconds)
    for byte_component, byte_value in snapshot.storage_free_bytes:
        registry["kivra_memory_storage_free_bytes"].set(byte_value, component=byte_component)
    for ratio_component, ratio_value in snapshot.storage_free_ratio:
        registry["kivra_memory_storage_free_ratio"].set(ratio_value, component=ratio_component)
    counters = dict(snapshot.result_counters)
    for result in ("failure", "success"):
        registry["kivra_memory_backup_results_total"].set_counter_absolute(
            counters[f"base_backup_{result}"], kind="base", result=result
        )
        registry["kivra_memory_backup_verification_results_total"].set_counter_absolute(
            counters[f"backup_verification_{result}"], kind="base", result=result
        )
    for reason in ("command", "storage", "timeout", "unavailable"):
        registry["kivra_memory_wal_archive_failures_total"].set_counter_absolute(
            counters[f"wal_archive_failure_{reason}"], reason=reason
        )


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
    "OperationalSnapshot",
    "OperationalStatusRepository",
    "QueueAggregate",
    "apply_operational_snapshot",
    "apply_snapshot",
    "clear_operational_snapshot",
    "clear_snapshot",
]
