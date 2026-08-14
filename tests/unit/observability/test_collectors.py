from __future__ import annotations

import inspect
import json
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from kivra_memory.observability.collectors import (
    OPERATIONAL_COUNTERS,
    AggregateSnapshot,
    ArchiveAggregate,
    CredentialAggregate,
    DatabasePoolAggregate,
    ObservabilitySnapshotRepository,
    OperationalSnapshot,
    OperationalStatusRepository,
    QueueAggregate,
    apply_operational_snapshot,
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


def test_operational_status_is_fixed_fresh_and_content_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kivra_memory.observability import collectors

    captured: dict[str, object] = {}

    def reader(path: Path, **options: object) -> bytes:
        captured["path"] = path
        captured.update(options)
        return (
            b'{"generated_at_unixtime":1000,"latest_base_unixtime":900,'
            b'"result_counters":{"base_backup_failure":0,"base_backup_success":1,'
            b'"backup_verification_failure":0,"backup_verification_success":1,'
            b'"wal_archive_failure_command":0,"wal_archive_failure_storage":0,'
            b'"wal_archive_failure_timeout":0,"wal_archive_failure_unavailable":0,'
            b'"wal_archive_success":1},'
            b'"storage_free_bytes":{"backup":1,"database":2,"monitoring":3,"wal":4},'
            b'"storage_free_ratio":{"backup":0.1,"database":0.2,"monitoring":0.3,'
            b'"wal":0.4},"version":1,"wal_oldest_ready_unixtime":990}'
        )

    monkeypatch.setattr(collectors, "read_protected_file", reader)
    snapshot = OperationalStatusRepository(tmp_path / "status.json").collect(now=1005)

    assert snapshot.backup_age_seconds == 105
    assert snapshot.wal_oldest_age_seconds == 15
    assert snapshot.storage_free_bytes == (
        ("backup", 1),
        ("database", 2),
        ("monitoring", 3),
        ("wal", 4),
    )
    assert captured["required_owner_uid"] == 0
    assert captured["required_group_gid"] == os.getegid()
    assert captured["allowed_modes"] == frozenset({0o640})


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: {**value, "generated_at_unixtime": 800},
        lambda value: {**value, "private_path": "/private"},
        lambda value: {**value, "storage_free_ratio": {"backup": 2}},
    ),
)
def test_operational_status_rejects_stale_or_malformed_input(
    monkeypatch: pytest.MonkeyPatch,
    mutation: Callable[[dict[str, object]], dict[str, object]],
) -> None:
    from kivra_memory.observability import collectors

    value = {
        "generated_at_unixtime": 1000,
        "latest_base_unixtime": 900,
        "result_counters": {name: 0 for name in collectors.OPERATIONAL_COUNTERS},
        "storage_free_bytes": {component: 1 for component in collectors.STORAGE_COMPONENTS},
        "storage_free_ratio": {component: 0.5 for component in collectors.STORAGE_COMPONENTS},
        "version": 1,
        "wal_oldest_ready_unixtime": 1000,
    }
    changed = mutation(value)
    monkeypatch.setattr(
        collectors,
        "read_protected_file",
        lambda *_args, **_kwargs: json.dumps(changed).encode(),
    )
    with pytest.raises(ValueError, match="invalid_operational_status"):
        OperationalStatusRepository().collect(now=1001)


def test_operational_snapshot_publishes_complete_fixed_label_set() -> None:
    registry = MetricRegistry()
    snapshot = OperationalSnapshot(
        100,
        10,
        (("backup", 1), ("database", 2), ("monitoring", 3), ("wal", 4)),
        (("backup", 0.1), ("database", 0.2), ("monitoring", 0.3), ("wal", 0.4)),
        tuple((name, 1) for name in OPERATIONAL_COUNTERS),
    )
    apply_operational_snapshot(snapshot, registry)
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert 'kivra_memory_backup_age_seconds{kind="base"} 100.0' in rendered
    assert "kivra_memory_wal_oldest_age_seconds 10.0" in rendered
    assert 'kivra_memory_storage_free_ratio{component="monitoring"} 0.3' in rendered
    assert 'kivra_memory_backup_results_total{kind="base",result="success"} 1.0' in rendered
    assert 'kivra_memory_wal_archive_failures_total{reason="storage"} 1.0' in rendered


def test_operational_status_rejects_counter_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kivra_memory.observability import collectors

    counter = 2

    def reader(*_args: object, **_kwargs: object) -> bytes:
        value = {
            "generated_at_unixtime": 1000,
            "latest_base_unixtime": 900,
            "result_counters": {name: counter for name in OPERATIONAL_COUNTERS},
            "storage_free_bytes": {name: 1 for name in collectors.STORAGE_COMPONENTS},
            "storage_free_ratio": {name: 0.5 for name in collectors.STORAGE_COMPONENTS},
            "version": 1,
            "wal_oldest_ready_unixtime": 1000,
        }
        return json.dumps(value).encode()

    monkeypatch.setattr(collectors, "read_protected_file", reader)
    repository = OperationalStatusRepository()
    repository.collect(now=1001)
    counter = 1

    with pytest.raises(ValueError, match="counter_regression"):
        repository.collect(now=1001)


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
