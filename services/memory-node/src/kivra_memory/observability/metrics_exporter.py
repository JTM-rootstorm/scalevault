"""Dedicated loopback exporter for least-privilege database aggregates."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from contextlib import suppress
from typing import Final, Protocol
from uuid import UUID

from prometheus_client import start_http_server
from sqlalchemy.engine import make_url

from kivra_memory.domain.identifiers import is_uuid7
from kivra_memory.observability.collectors import (
    AggregateSnapshot,
    ObservabilitySnapshotRepository,
    apply_snapshot,
    clear_snapshot,
)
from kivra_memory.observability.metrics import MetricRegistry
from kivra_memory.security.credential_files import read_systemd_credential_text
from kivra_memory.storage.database import Database

DATABASE_CREDENTIAL_NAME: Final = "database-url"
TENANT_CREDENTIAL_NAME: Final = "tenant-id"
LISTEN_ADDRESS: Final = "127.0.0.1"
LISTEN_PORT: Final = 9098
REFRESH_SECONDS: Final = 30.0
COLLECTION_TIMEOUT_SECONDS: Final = 10.0


class SnapshotCollector(Protocol):
    async def collect(self, tenant_id: UUID) -> AggregateSnapshot: ...


def _credentials() -> tuple[str, UUID]:
    try:
        database_url = read_systemd_credential_text(
            DATABASE_CREDENTIAL_NAME, minimum_bytes=1, maximum_bytes=4096
        )
        url = make_url(database_url)
        tenant_value = read_systemd_credential_text(
            TENANT_CREDENTIAL_NAME, minimum_bytes=36, maximum_bytes=36
        )
        tenant_id = UUID(tenant_value)
        if (
            url.drivername not in {"postgresql", "postgresql+psycopg"}
            or url.username != "kivra_memory_metrics"
            or url.database != "kivra_memory"
            or url.host not in {None, "localhost", "127.0.0.1", "::1"}
            or set(url.query) & {"host", "hostaddr", "service", "servicefile"}
            or str(tenant_id) != tenant_value
            or not is_uuid7(tenant_id)
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("metrics_exporter_credential_invalid") from None
    return database_url, tenant_id


async def _collect_once(
    repository: SnapshotCollector,
    tenant_id: UUID,
    registry: MetricRegistry,
) -> bool:
    try:
        snapshot = await asyncio.wait_for(
            repository.collect(tenant_id), timeout=COLLECTION_TIMEOUT_SECONDS
        )
        apply_snapshot(snapshot, registry)
    except Exception:
        clear_snapshot(registry)
        registry["kivra_memory_database_collector_up"].set(0)
        registry["kivra_memory_database_collector_failures_total"].inc()
        return False
    registry["kivra_memory_database_collector_up"].set(1)
    registry["kivra_memory_database_collector_last_success_unixtime"].set(time.time())
    return True


async def _run(database_url: str, tenant_id: UUID, registry: MetricRegistry) -> None:
    database = Database(database_url)
    repository = ObservabilitySnapshotRepository(database)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected, stop.set)
    try:
        while not stop.is_set():
            await _collect_once(repository, tenant_id, registry)
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=REFRESH_SECONDS)
    finally:
        await database.dispose()


def main() -> None:
    if os.geteuid() == 0:
        print("ScaleVault metrics exporter refuses root", file=sys.stderr)
        raise SystemExit(77)
    try:
        database_url, tenant_id = _credentials()
        registry = MetricRegistry()
        server, _thread = start_http_server(
            LISTEN_PORT, addr=LISTEN_ADDRESS, registry=registry.prometheus
        )
        asyncio.run(_run(database_url, tenant_id, registry))
    except Exception:
        print("ScaleVault metrics exporter failed", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if "server" in locals():
            server.shutdown()
            server.server_close()


__all__ = [
    "COLLECTION_TIMEOUT_SECONDS",
    "LISTEN_ADDRESS",
    "LISTEN_PORT",
    "REFRESH_SECONDS",
    "main",
]
