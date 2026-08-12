"""Dedicated least-privilege worker for sealed-content key destruction."""

from __future__ import annotations

import asyncio
import os
import pwd
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import unquote
from uuid import UUID

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy import and_, select
from sqlalchemy.engine import make_url

from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.security.credential_files import read_systemd_credential_text
from kivra_memory.security.destruction_ledger import LOCAL_DESTRUCTION_LEDGER_ROOT
from kivra_memory.security.keys import KeyDestroyer
from kivra_memory.security.local_key_provider import (
    LOCAL_KEY_PROVIDER_ROOT,
    LocalDirectoryKeyDestroyer,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import Actor, Client, TransportBinding
from kivra_memory.storage.outbox_worker import (
    LeaseLostError,
    acknowledge_outbox_job,
    claim_outbox_jobs,
    fail_outbox_job,
    heartbeat_outbox_job,
    recover_expired_outbox_leases,
)
from kivra_memory.workers.sealed_content import (
    SealedContentPurgeError,
    handle_purge_payload_job,
)

_PURGE_JOB_TYPES = ("purge_payload",)
_PURGE_SCOPE = "memory.lifecycle.purge"
_POLL_INTERVAL_SECONDS = 1.0
_LEASE_SECONDS = 120
_BATCH_SIZE = 8


class SealedWorkerConfigurationError(RuntimeError):
    """Safe startup failure for an unavailable purge authority or provider."""


@dataclass(frozen=True, slots=True)
class SealedWorkerSettings:
    database_url: str = field(repr=False)
    tenant_id: UUID
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID

    @classmethod
    def from_environment(cls) -> SealedWorkerSettings:
        database_value = os.environ.get("KIVRA_MEMORY_PURGE_DATABASE_URL", "")
        if os.environ.get("CREDENTIALS_DIRECTORY") or not database_value:
            with suppress(OSError, ValueError):
                database_value = read_systemd_credential_text(
                    "database-url", minimum_bytes=1, maximum_bytes=4096
                )
        values = (
            os.environ.get("KIVRA_MEMORY_PURGE_TENANT_ID", ""),
            os.environ.get("KIVRA_MEMORY_PURGE_ACTOR_ID", ""),
            os.environ.get("KIVRA_MEMORY_PURGE_CLIENT_ID", ""),
            os.environ.get("KIVRA_MEMORY_PURGE_TRANSPORT_BINDING_ID", ""),
        )
        try:
            database_url = str(TypeAdapter(PostgresDsn).validate_python(database_value))
            parsed_url = TypeAdapter(PostgresDsn).validate_python(database_url)
            allowed_hosts = {
                "localhost",
                "127.0.0.1",
                "::1",
                "/run/postgresql",
                "/var/run/postgresql",
            }
            if (
                make_url(database_url).username != "kivra_memory_purge"
                or parsed_url.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}
                or {key for key, _value in parsed_url.query_params()}
                & {"host", "hostaddr", "service", "servicefile"}
                or any(
                    host["host"] is None
                    or unquote(str(host["host"])).removeprefix("[").removesuffix("]")
                    not in allowed_hosts
                    for host in parsed_url.hosts()
                )
            ):
                raise ValueError
            tenant_id, actor_id, client_id, transport_binding_id = (UUID(value) for value in values)
            for identifier, field_name in (
                (tenant_id, "tenant_id"),
                (actor_id, "actor_id"),
                (client_id, "client_id"),
                (transport_binding_id, "transport_binding_id"),
            ):
                require_uuid7(identifier, field_name=field_name)
        except (ValidationError, ValueError):
            raise SealedWorkerConfigurationError("invalid_sealed_worker_configuration") from None
        return cls(
            database_url=database_url,
            tenant_id=tenant_id,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=transport_binding_id,
        )


class SealedContentWorker:
    """Claim only purge jobs and bind each event to one pinned service identity."""

    def __init__(
        self,
        settings: SealedWorkerSettings,
        database: Database,
        key_destroyer: KeyDestroyer,
    ) -> None:
        self._settings = settings
        self._database = database
        self._key_destroyer = key_destroyer
        self._owner = f"sealed-content-purge:{new_uuid7()}"

    def _principal(self) -> CommandPrincipal:
        return CommandPrincipal(
            tenant_id=self._settings.tenant_id,
            actor_id=self._settings.actor_id,
            client_id=self._settings.client_id,
            transport_binding_id=self._settings.transport_binding_id,
            scopes=frozenset({_PURGE_SCOPE}),
        )

    async def verify_identity(self) -> None:
        async with self._database.tenant_session(self._settings.tenant_id) as session:
            row = (
                await session.execute(
                    select(
                        TransportBinding.transport_kind,
                        TransportBinding.disclosure_boundary,
                        TransportBinding.valid_until,
                        TransportBinding.authorized_operations,
                        Actor.kind,
                        Actor.revoked_at,
                        Client.kind,
                        Client.revoked_at,
                        Client.scopes,
                    )
                    .join(
                        Actor,
                        and_(
                            Actor.tenant_id == TransportBinding.tenant_id,
                            Actor.actor_id == TransportBinding.actor_id,
                        ),
                    )
                    .join(
                        Client,
                        and_(
                            Client.tenant_id == TransportBinding.tenant_id,
                            Client.client_id == TransportBinding.client_id,
                        ),
                    )
                    .where(
                        TransportBinding.tenant_id == self._settings.tenant_id,
                        TransportBinding.transport_binding_id
                        == self._settings.transport_binding_id,
                        TransportBinding.actor_id == self._settings.actor_id,
                        TransportBinding.client_id == self._settings.client_id,
                    )
                )
            ).one_or_none()
        if row is None:
            raise SealedWorkerConfigurationError("sealed_worker_identity_unavailable")
        (
            transport_kind,
            disclosure_boundary,
            valid_until,
            authorized_operations,
            actor_kind,
            actor_revoked_at,
            client_kind,
            client_revoked_at,
            scopes,
        ) = row
        if (
            transport_kind != "internal_service"
            or disclosure_boundary != "internal"
            or (valid_until is not None and valid_until <= datetime.now(UTC))
            or authorized_operations != {"operations": ["payload_purge_completed"]}
            or actor_kind != "service"
            or actor_revoked_at is not None
            or client_kind != "worker"
            or client_revoked_at is not None
            or frozenset(scopes) != frozenset({_PURGE_SCOPE})
        ):
            raise SealedWorkerConfigurationError("sealed_worker_identity_unavailable")

    async def run_once(self) -> int:
        await self.verify_identity()
        tenant_id = self._settings.tenant_id
        async with self._database.tenant_session(tenant_id) as session:
            await recover_expired_outbox_leases(
                session,
                tenant_id=tenant_id,
                job_types=_PURGE_JOB_TYPES,
            )
            jobs = await claim_outbox_jobs(
                session,
                tenant_id=tenant_id,
                worker_owner=self._owner,
                job_types=_PURGE_JOB_TYPES,
                batch_size=_BATCH_SIZE,
                lease_seconds=_LEASE_SECONDS,
            )
        processed = 0
        for job in jobs:
            try:
                async with self._database.tenant_session(tenant_id) as session:
                    await heartbeat_outbox_job(
                        session,
                        tenant_id=tenant_id,
                        job_id=job.job_id,
                        lease_token=job.lease_token,
                        lease_seconds=_LEASE_SECONDS,
                    )
                async with self._database.tenant_session(tenant_id) as session:
                    await handle_purge_payload_job(
                        session,
                        job=job,
                        principal=self._principal(),
                        key_destroyer=self._key_destroyer,
                    )
                    await acknowledge_outbox_job(
                        session,
                        tenant_id=tenant_id,
                        job_id=job.job_id,
                        lease_token=job.lease_token,
                    )
                processed += 1
            except LeaseLostError:
                continue
            except SealedContentPurgeError as error:
                await self._fail_job(
                    job_id=job.job_id,
                    lease_token=job.lease_token,
                    error_code=error.code,
                )
            except Exception:
                await self._fail_job(
                    job_id=job.job_id,
                    lease_token=job.lease_token,
                    error_code="internal_error",
                )
        return processed

    async def _fail_job(self, *, job_id: int, lease_token: str, error_code: str) -> None:
        safe_code, retryable = (
            ("dependency_unavailable", True)
            if error_code == "dependency_unavailable"
            else ("internal_error", True)
            if error_code == "internal_error"
            else ("invalid_job", False)
        )
        try:
            async with self._database.tenant_session(self._settings.tenant_id) as session:
                await fail_outbox_job(
                    session,
                    tenant_id=self._settings.tenant_id,
                    job_id=job_id,
                    lease_token=lease_token,
                    error_code=safe_code,
                    retryable=retryable,
                )
        except LeaseLostError:
            return


async def run_sealed_worker(settings: SealedWorkerSettings, destroyer: KeyDestroyer) -> None:
    database = Database(settings.database_url)
    worker = SealedContentWorker(settings, database, destroyer)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)
    try:
        await worker.verify_identity()
        while not stop.is_set():
            await worker.run_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=_POLL_INTERVAL_SECONDS)
            except TimeoutError:
                continue
    finally:
        await database.dispose()


def main() -> None:
    try:
        settings = SealedWorkerSettings.from_environment()
        destroyer = LocalDirectoryKeyDestroyer(
            LOCAL_KEY_PROVIDER_ROOT,
            destruction_ledger_root=LOCAL_DESTRUCTION_LEDGER_ROOT,
            required_owner_uid=0,
            material_file_owner_uid=pwd.getpwnam("memory-api").pw_uid,
        )
        asyncio.run(run_sealed_worker(settings, destroyer))
    except Exception:
        print("ScaleVault sealed worker is unavailable", file=sys.stderr)
        raise SystemExit(2) from None


__all__ = [
    "SealedContentWorker",
    "SealedWorkerConfigurationError",
    "SealedWorkerSettings",
    "main",
    "run_sealed_worker",
]
