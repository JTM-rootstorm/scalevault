from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import UUID

import pytest
from kivra_memory.observability.collectors import (
    OPERATIONAL_COUNTERS,
    AggregateSnapshot,
    OperationalSnapshot,
    QueueAggregate,
)
from kivra_memory.observability.metrics import MetricRegistry
from kivra_memory.observability.metrics_exporter import (
    _collect_once,
    _collect_operational_once,
    _credentials,
)
from prometheus_client import generate_latest

TENANT_ID = UUID("01970000-0000-7000-8000-000000000001")


class Repository:
    def __init__(self, result: AggregateSnapshot | Exception) -> None:
        self.result = result
        self.tenant_ids: list[UUID] = []

    async def collect(self, tenant_id: UUID) -> AggregateSnapshot:
        self.tenant_ids.append(tenant_id)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class OperationalRepository:
    def __init__(self, result: OperationalSnapshot | Exception) -> None:
        self.result = result

    def collect(self, *, now: float | None = None) -> OperationalSnapshot:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _credential_directory(monkeypatch: pytest.MonkeyPatch, path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(path))
    return path


def _write_credential(directory: Path, name: str, value: str) -> None:
    selected = directory / name
    selected.write_text(value)
    selected.chmod(0o600)


def test_credentials_require_local_metrics_role_and_uuid7(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = _credential_directory(monkeypatch, tmp_path / "credentials")
    _write_credential(
        directory,
        "database-url",
        "postgresql+psycopg://kivra_memory_metrics:secret@127.0.0.1/kivra_memory",
    )
    _write_credential(directory, "tenant-id", str(TENANT_ID))
    assert _credentials()[1] == TENANT_ID

    _write_credential(
        directory,
        "database-url",
        "postgresql+psycopg://kivra_memory_api:secret@127.0.0.1/kivra_memory",
    )
    with pytest.raises(ValueError, match="credential_invalid"):
        _credentials()


@pytest.mark.asyncio
async def test_collection_success_replaces_samples_and_marks_up() -> None:
    registry = MetricRegistry()
    repository = Repository(
        AggregateSnapshot(queues=(QueueAggregate("embedding", "pending", 2, 4),))
    )
    assert await _collect_once(repository, TENANT_ID, registry)
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert "kivra_memory_database_collector_up 1.0" in rendered
    assert 'queue="embedding",state="pending"} 2.0' in rendered
    assert repository.tenant_ids == [TENANT_ID]


@pytest.mark.asyncio
async def test_collection_failure_is_bounded_and_removes_stale_snapshot() -> None:
    registry = MetricRegistry()
    good = Repository(AggregateSnapshot(queues=(QueueAggregate("archive", "pending", 3, 5),)))
    assert await _collect_once(good, TENANT_ID, registry)
    failed = Repository(RuntimeError("SYNTHETIC_PRIVATE_CANARY"))
    assert not await _collect_once(failed, TENANT_ID, registry)
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert "kivra_memory_database_collector_up 0.0" in rendered
    assert "kivra_memory_database_collector_failures_total 1.0" in rendered
    assert 'queue="archive",state="pending"} 3.0' not in rendered
    assert "SYNTHETIC_PRIVATE_CANARY" not in rendered


@pytest.mark.asyncio
async def test_collection_timeout_fails_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from kivra_memory.observability import metrics_exporter

    class StalledRepository:
        async def collect(self, _tenant_id: UUID) -> AggregateSnapshot:
            await asyncio.Event().wait()
            raise AssertionError

    monkeypatch.setattr(metrics_exporter, "COLLECTION_TIMEOUT_SECONDS", 0.001)
    registry = MetricRegistry()
    assert not await metrics_exporter._collect_once(StalledRepository(), TENANT_ID, registry)
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert "kivra_memory_database_collector_up 0.0" in rendered
    assert "kivra_memory_database_collector_failures_total 1.0" in rendered


def test_operational_collection_failure_clears_stale_samples_without_error_text() -> None:
    registry = MetricRegistry()
    snapshot = OperationalSnapshot(
        100,
        10,
        (("backup", 1), ("database", 2), ("monitoring", 3), ("wal", 4)),
        (("backup", 0.1), ("database", 0.2), ("monitoring", 0.3), ("wal", 0.4)),
        tuple((name, 1) for name in OPERATIONAL_COUNTERS),
    )
    assert _collect_operational_once(OperationalRepository(snapshot), registry, now=1000)
    assert not _collect_operational_once(
        OperationalRepository(RuntimeError("SYNTHETIC_PRIVATE_CANARY")), registry, now=1001
    )
    rendered = generate_latest(registry.prometheus).decode("ascii")
    assert "kivra_memory_operational_collector_up 0.0" in rendered
    assert "kivra_memory_operational_collector_failures_total 1.0" in rendered
    assert 'kivra_memory_backup_age_seconds{kind="base"}' not in rendered
    assert 'kivra_memory_storage_free_ratio{component="backup"}' not in rendered
    assert "SYNTHETIC_PRIVATE_CANARY" not in rendered


def test_exporter_refuses_root_before_credential_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from kivra_memory.observability import metrics_exporter

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as raised:
        metrics_exporter.main()
    assert raised.value.code == 77
    assert capsys.readouterr().err == "ScaleVault metrics exporter refuses root\n"
