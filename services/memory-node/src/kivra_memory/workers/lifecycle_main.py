"""Dedicated, least-privilege outbox worker for candidate expiry only."""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy import and_, select
from sqlalchemy.engine import make_url

from kivra_memory.application.candidate_lifecycle import CandidateLifecycleEngine
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.domain.identifiers import new_uuid7, require_uuid7
from kivra_memory.security.credential_files import read_systemd_credential_text
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
from kivra_memory.workers.candidate_lifecycle import (
    CandidateLifecycleJobError,
    handle_candidate_lifecycle_job,
)

_EXPIRE_CANDIDATE_JOB_TYPES = ("expire_candidate",)
_EXPIRE_SCOPE = "memory.lifecycle.expire"
_POLL_INTERVAL_SECONDS = 1.0
_LEASE_SECONDS = 120
_BATCH_SIZE = 8


class LifecycleWorkerConfigurationError(RuntimeError):
    """Safe startup failure for an unavailable lifecycle authority."""


@dataclass(frozen=True, slots=True)
class LifecycleWorkerSettings:
    """Fixed policy identity and tenant scope read from the protected unit environment."""

    database_url: str
    tenant_ids: tuple[UUID, ...]
    actor_id: UUID
    client_id: UUID
    transport_binding_id: UUID

    @classmethod
    def from_environment(cls) -> LifecycleWorkerSettings:
        database_value = os.environ.get("KIVRA_MEMORY_DATABASE_URL", "")
        if os.environ.get("CREDENTIALS_DIRECTORY") or not database_value:
            with suppress(OSError, ValueError):
                database_value = read_systemd_credential_text(
                    "database-url", minimum_bytes=1, maximum_bytes=4096
                )
        tenant_value = os.environ.get("KIVRA_MEMORY_LIFECYCLE_TENANT_IDS", "")
        identifier_values = (
            os.environ.get("KIVRA_MEMORY_LIFECYCLE_ACTOR_ID", ""),
            os.environ.get("KIVRA_MEMORY_LIFECYCLE_CLIENT_ID", ""),
            os.environ.get("KIVRA_MEMORY_LIFECYCLE_TRANSPORT_BINDING_ID", ""),
        )
        try:
            database_url = str(TypeAdapter(PostgresDsn).validate_python(database_value))
            if make_url(database_url).username != "kivra_memory_policy":
                raise ValueError("lifecycle worker requires the policy database role")
            tenant_ids = tuple(
                UUID(item.strip()) for item in tenant_value.split(",") if item.strip()
            )
            actor_id, client_id, transport_binding_id = (UUID(value) for value in identifier_values)
            if len(tenant_ids) != 1 or len(set(tenant_ids)) != 1:
                raise ValueError("exactly one tenant is required for one lifecycle identity")
            for identifier, field_name in (
                (tenant_ids[0], "tenant_id"),
                (actor_id, "actor_id"),
                (client_id, "client_id"),
                (transport_binding_id, "transport_binding_id"),
            ):
                require_uuid7(identifier, field_name=field_name)
        except (ValidationError, ValueError):
            raise LifecycleWorkerConfigurationError(
                "invalid_lifecycle_worker_configuration"
            ) from None
        return cls(
            database_url=database_url,
            tenant_ids=tenant_ids,
            actor_id=actor_id,
            client_id=client_id,
            transport_binding_id=transport_binding_id,
        )


class CandidateLifecycleWorker:
    """Claim and resolve only policy-scheduled candidate-expiry jobs."""

    def __init__(self, settings: LifecycleWorkerSettings, database: Database) -> None:
        self._settings = settings
        self._database = database
        self._owner = f"candidate-lifecycle:{new_uuid7()}"
        self._engine = CandidateLifecycleEngine(database.session_factory)

    def _principal(self, tenant_id: UUID) -> CommandPrincipal:
        if tenant_id not in self._settings.tenant_ids:
            raise LifecycleWorkerConfigurationError("lifecycle_tenant_not_allowed")
        return CommandPrincipal(
            tenant_id=tenant_id,
            actor_id=self._settings.actor_id,
            client_id=self._settings.client_id,
            transport_binding_id=self._settings.transport_binding_id,
            scopes=frozenset({_EXPIRE_SCOPE}),
        )

    async def _verify_identity(self, tenant_id: UUID) -> None:
        """Resolve the protected IDs against the current internal-service binding."""

        async with self._database.tenant_session(tenant_id) as session:
            row = (
                await session.execute(
                    select(
                        TransportBinding.transport_kind,
                        TransportBinding.disclosure_boundary,
                        TransportBinding.valid_until,
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
                        TransportBinding.tenant_id == tenant_id,
                        TransportBinding.transport_binding_id
                        == self._settings.transport_binding_id,
                        TransportBinding.actor_id == self._settings.actor_id,
                        TransportBinding.client_id == self._settings.client_id,
                    )
                )
            ).one_or_none()
        if row is None:
            raise LifecycleWorkerConfigurationError("lifecycle_identity_unavailable")
        (
            transport_kind,
            disclosure_boundary,
            valid_until,
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
            or actor_kind != "service"
            or actor_revoked_at is not None
            or client_kind != "worker"
            or client_revoked_at is not None
            or frozenset(scopes) != frozenset({_EXPIRE_SCOPE})
        ):
            raise LifecycleWorkerConfigurationError("lifecycle_identity_unavailable")

    async def verify_identities(self) -> None:
        for tenant_id in self._settings.tenant_ids:
            await self._verify_identity(tenant_id)

    async def run_once(self) -> int:
        """Recover, claim, and fence a bounded batch without generic dispatch."""

        await self.verify_identities()
        processed = 0
        for tenant_id in self._settings.tenant_ids:
            principal = self._principal(tenant_id)
            async with self._database.tenant_session(tenant_id) as session:
                await recover_expired_outbox_leases(
                    session,
                    tenant_id=tenant_id,
                    job_types=_EXPIRE_CANDIDATE_JOB_TYPES,
                )
                jobs = await claim_outbox_jobs(
                    session,
                    tenant_id=tenant_id,
                    worker_owner=self._owner,
                    job_types=_EXPIRE_CANDIDATE_JOB_TYPES,
                    batch_size=_BATCH_SIZE,
                    lease_seconds=_LEASE_SECONDS,
                )
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
                    await handle_candidate_lifecycle_job(
                        job=job,
                        principal=principal,
                        engine=self._engine,
                    )
                    async with self._database.tenant_session(tenant_id) as session:
                        await acknowledge_outbox_job(
                            session,
                            tenant_id=tenant_id,
                            job_id=job.job_id,
                            lease_token=job.lease_token,
                        )
                    processed += 1
                except LeaseLostError:
                    continue
                except CandidateLifecycleJobError as error:
                    await self._fail_job(
                        tenant_id=tenant_id,
                        job_id=job.job_id,
                        lease_token=job.lease_token,
                        error_code=error.code,
                    )
                except Exception:
                    await self._fail_job(
                        tenant_id=tenant_id,
                        job_id=job.job_id,
                        lease_token=job.lease_token,
                        error_code="internal_error",
                    )
        return processed

    async def _fail_job(
        self,
        *,
        tenant_id: UUID,
        job_id: int,
        lease_token: str,
        error_code: str,
    ) -> None:
        # The outbox stores only its predeclared safe codes. Lifecycle failures
        # outside that vocabulary are terminal invalid work, not reflected detail.
        safe_code, retryable = (
            ("dependency_unavailable", True)
            if error_code == "dependency_unavailable"
            else ("internal_error", True)
            if error_code == "internal_error"
            else ("invalid_job", False)
        )
        try:
            async with self._database.tenant_session(tenant_id) as session:
                await fail_outbox_job(
                    session,
                    tenant_id=tenant_id,
                    job_id=job_id,
                    lease_token=lease_token,
                    error_code=safe_code,
                    retryable=retryable,
                )
        except LeaseLostError:
            return


async def run_lifecycle_worker(settings: LifecycleWorkerSettings) -> None:
    """Run the expiry worker until systemd requests a clean shutdown."""

    database = Database(settings.database_url)
    worker = CandidateLifecycleWorker(settings, database)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)
    try:
        while not stop.is_set():
            await worker.run_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=_POLL_INTERVAL_SECONDS)
            except TimeoutError:
                continue
    finally:
        await database.dispose()


def main() -> None:
    """Start only after strict configuration and identity checks succeed."""

    asyncio.run(run_lifecycle_worker(LifecycleWorkerSettings.from_environment()))
