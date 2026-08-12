"""Runnable local embedding worker and query-embedding socket service."""

from __future__ import annotations

import asyncio
import os
import re
import signal
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy import select

from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.security.credential_files import read_systemd_credential_text
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import EmbeddingModel
from kivra_memory.storage.outbox_worker import (
    LeaseLostError,
    acknowledge_outbox_job,
    claim_outbox_jobs,
    fail_outbox_job,
    recover_expired_outbox_leases,
)
from kivra_memory.workers.embedding_jobs import EmbeddingJobError, handle_embed_memory_job
from kivra_memory.workers.embedding_runtime import (
    EmbeddingRuntime,
    EmbeddingRuntimeError,
    OnnxEmbeddingRuntime,
)
from kivra_memory.workers.query_socket import QueryEmbeddingProtocolError, QueryEmbeddingServer

_DIGEST_DIRECTORY = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    database_url: str
    tenant_ids: tuple[UUID, ...]
    model_root: Path
    query_socket: Path
    poll_interval_seconds: float = 1.0
    lease_seconds: int = 120
    batch_size: int = 8

    @classmethod
    def from_environment(cls) -> WorkerSettings:
        database_value = os.environ.get("KIVRA_MEMORY_DATABASE_URL", "")
        if os.environ.get("CREDENTIALS_DIRECTORY") or not database_value:
            with suppress(OSError, ValueError):
                database_value = read_systemd_credential_text(
                    "database-url", minimum_bytes=1, maximum_bytes=4096
                )
        tenant_value = os.environ.get("KIVRA_MEMORY_WORKER_TENANT_IDS", "")
        try:
            database_url = str(TypeAdapter(PostgresDsn).validate_python(database_value))
            tenant_ids = tuple(
                UUID(item.strip()) for item in tenant_value.split(",") if item.strip()
            )
            if not tenant_ids or len(set(tenant_ids)) != len(tenant_ids):
                raise ValueError("tenant IDs must be a non-empty unique list")
            for tenant_id in tenant_ids:
                require_uuid7(tenant_id, field_name="tenant_id")
        except (ValidationError, ValueError):
            raise RuntimeError("invalid_worker_configuration") from None
        model_root = Path(
            os.environ.get("KIVRA_MEMORY_EMBEDDING_MODEL_ROOT", "/mnt/memory/kivra-memory/models")
        )
        query_socket = Path(
            os.environ.get(
                "KIVRA_MEMORY_QUERY_EMBEDDING_SOCKET",
                "/run/kivra-memory-worker/query-embedding.sock",
            )
        )
        if not model_root.is_absolute() or not query_socket.is_absolute():
            raise RuntimeError("invalid_worker_configuration")
        return cls(
            database_url=database_url,
            tenant_ids=tenant_ids,
            model_root=model_root,
            query_socket=query_socket,
        )


def load_runtime_catalog(model_root: Path) -> dict[bytes, EmbeddingRuntime]:
    """Load only digest-addressed, completely verified bundles from the mounted root."""

    if not Path("/mnt/memory").is_mount() or not model_root.is_dir():
        raise EmbeddingRuntimeError("embedding_model_mount_unavailable")
    runtimes: dict[bytes, EmbeddingRuntime] = {}
    for child in sorted(model_root.iterdir(), key=lambda path: path.name):
        if (
            not child.is_dir()
            or child.is_symlink()
            or _DIGEST_DIRECTORY.fullmatch(child.name) is None
        ):
            raise EmbeddingRuntimeError("invalid_model_bundle_directory")
        runtime = OnnxEmbeddingRuntime(child)
        if runtime.contract.artifact_sha256 != child.name:
            raise EmbeddingRuntimeError("model_bundle_directory_hash_mismatch")
        runtimes[bytes.fromhex(child.name)] = runtime
    if not runtimes:
        raise EmbeddingRuntimeError("embedding_model_unavailable")
    return runtimes


class EmbeddingWorker:
    def __init__(
        self,
        settings: WorkerSettings,
        database: Database,
        runtimes: dict[bytes, EmbeddingRuntime],
    ) -> None:
        self._settings = settings
        self._database = database
        self._runtimes = runtimes
        self._active_runtimes: dict[UUID, EmbeddingRuntime] = {}
        self._owner = f"embedding-worker:{new_uuid7()}"

    def runtime_for_tenant(self, tenant_id: UUID) -> EmbeddingRuntime:
        try:
            return self._active_runtimes[tenant_id]
        except KeyError:
            raise QueryEmbeddingProtocolError("semantic_retrieval_unavailable") from None

    async def refresh_active_models(self) -> None:
        active: dict[UUID, EmbeddingRuntime] = {}
        for tenant_id in self._settings.tenant_ids:
            async with self._database.tenant_session(tenant_id) as session:
                model = await session.scalar(
                    select(EmbeddingModel).where(
                        EmbeddingModel.tenant_id == tenant_id,
                        EmbeddingModel.state == "approved",
                        EmbeddingModel.retired_at.is_(None),
                    )
                )
            if model is None:
                raise EmbeddingRuntimeError("approved_embedding_model_unavailable")
            runtime = self._runtimes.get(bytes(model.artifact_sha256))
            if runtime is None:
                raise EmbeddingRuntimeError("approved_embedding_model_unavailable")
            active[tenant_id] = runtime
        self._active_runtimes = active

    async def run_once(self) -> int:
        processed = 0
        for tenant_id in self._settings.tenant_ids:
            async with self._database.tenant_session(tenant_id) as session:
                await recover_expired_outbox_leases(
                    session, tenant_id=tenant_id, job_types=("embed_memory",)
                )
                jobs = await claim_outbox_jobs(
                    session,
                    tenant_id=tenant_id,
                    worker_owner=self._owner,
                    job_types=("embed_memory",),
                    batch_size=self._settings.batch_size,
                    lease_seconds=self._settings.lease_seconds,
                )
            for job in jobs:
                try:
                    async with self._database.tenant_session(tenant_id) as session:
                        result = await handle_embed_memory_job(
                            session, job=job, runtimes_by_artifact=self._runtimes
                        )
                        if result.outcome == "no_model":
                            raise EmbeddingJobError("model_unavailable")
                        await acknowledge_outbox_job(
                            session,
                            tenant_id=tenant_id,
                            job_id=job.job_id,
                            lease_token=job.lease_token,
                        )
                    processed += 1
                except LeaseLostError:
                    continue
                except EmbeddingJobError as error:
                    async with self._database.tenant_session(tenant_id) as session:
                        await fail_outbox_job(
                            session,
                            tenant_id=tenant_id,
                            job_id=job.job_id,
                            lease_token=job.lease_token,
                            error_code=error.code,
                            retryable=error.code != "invalid_job",
                        )
        return processed


async def run_worker(settings: WorkerSettings) -> None:
    runtimes = load_runtime_catalog(settings.model_root)
    database = Database(settings.database_url)
    worker = EmbeddingWorker(settings, database, runtimes)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)
    server = QueryEmbeddingServer(settings.query_socket, worker.runtime_for_tenant)
    try:
        await worker.refresh_active_models()
        await server.start()
        while not stop.is_set():
            await worker.run_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=settings.poll_interval_seconds)
            except TimeoutError:
                await worker.refresh_active_models()
    finally:
        await server.close()
        await database.dispose()


def main() -> None:
    """Run the embedding worker without reflecting private failures to stdout."""

    settings = WorkerSettings.from_environment()
    asyncio.run(run_worker(settings))
