from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.application.candidate_lifecycle import CandidateLifecycleResult
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob
from kivra_memory.workers import lifecycle_main
from kivra_memory.workers.candidate_lifecycle import CandidateLifecycleJobError
from kivra_memory.workers.lifecycle_main import (
    CandidateLifecycleWorker,
    LifecycleWorkerConfigurationError,
    LifecycleWorkerSettings,
)


class _DatabaseStub:
    def __init__(self, session: object | None = None) -> None:
        self.session_factory = MagicMock()
        self._session = session if session is not None else MagicMock()

    @asynccontextmanager
    async def tenant_session(self, _tenant_id: object) -> AsyncIterator[object]:
        yield self._session


def _settings() -> LifecycleWorkerSettings:
    return LifecycleWorkerSettings(
        database_url="postgresql+psycopg://kivra_memory_policy@example.invalid/kivra_memory",
        tenant_ids=(new_uuid7(),),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
    )


def _job(tenant_id: UUID) -> ClaimedOutboxJob:
    memory_id = new_uuid7()
    decision_id = new_uuid7()
    return ClaimedOutboxJob(
        job_id=1,
        job_uuid=new_uuid7(),
        tenant_id=tenant_id,
        job_type="expire_candidate",
        aggregate_type="memory",
        aggregate_id=memory_id,
        payload={
            "event_id": str(new_uuid7()),
            "memory_id": str(memory_id),
            "memory_version": 1,
            "selection_decision_id": str(decision_id),
        },
        attempt_count=1,
        max_attempts=8,
        lease_token="candidate-lifecycle:test",
    )


def test_settings_require_one_uuid7_tenant_and_all_preprovisioned_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    monkeypatch.setenv("KIVRA_MEMORY_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KIVRA_MEMORY_LIFECYCLE_TENANT_IDS", str(settings.tenant_ids[0]))
    monkeypatch.setenv("KIVRA_MEMORY_LIFECYCLE_ACTOR_ID", str(settings.actor_id))
    monkeypatch.setenv("KIVRA_MEMORY_LIFECYCLE_CLIENT_ID", str(settings.client_id))
    monkeypatch.setenv(
        "KIVRA_MEMORY_LIFECYCLE_TRANSPORT_BINDING_ID", str(settings.transport_binding_id)
    )

    assert LifecycleWorkerSettings.from_environment() == settings

    monkeypatch.setenv(
        "KIVRA_MEMORY_LIFECYCLE_TENANT_IDS", f"{settings.tenant_ids[0]},{new_uuid7()}"
    )
    with pytest.raises(LifecycleWorkerConfigurationError, match="invalid_lifecycle"):
        LifecycleWorkerSettings.from_environment()

    monkeypatch.setenv(
        "KIVRA_MEMORY_DATABASE_URL",
        "postgresql+psycopg://kivra_memory_api@example.invalid/kivra_memory",
    )
    monkeypatch.setenv("KIVRA_MEMORY_LIFECYCLE_TENANT_IDS", str(settings.tenant_ids[0]))
    with pytest.raises(LifecycleWorkerConfigurationError, match="invalid_lifecycle"):
        LifecycleWorkerSettings.from_environment()


@pytest.mark.asyncio
async def test_worker_claims_only_expiry_jobs_and_acknowledges_policy_noops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    worker = CandidateLifecycleWorker(settings, _DatabaseStub())  # type: ignore[arg-type]
    job = _job(settings.tenant_ids[0])
    assert job.aggregate_id is not None
    selection_decision_id = UUID(str(job.payload["selection_decision_id"]))
    recover = AsyncMock()
    claim = AsyncMock(return_value=(job,))
    heartbeat = AsyncMock()
    handle = AsyncMock(
        return_value=CandidateLifecycleResult(
            operation="expire",
            action="no_op",
            decision_id=selection_decision_id,
            source_decision_id=selection_decision_id,
            memory_id=job.aggregate_id,
            revision=1,
            policy_sha256="a" * 64,
            reason_code="stale_revision",
        )
    )
    acknowledge = AsyncMock()
    monkeypatch.setattr(worker, "verify_identities", AsyncMock())
    monkeypatch.setattr(lifecycle_main, "recover_expired_outbox_leases", recover)
    monkeypatch.setattr(lifecycle_main, "claim_outbox_jobs", claim)
    monkeypatch.setattr(lifecycle_main, "heartbeat_outbox_job", heartbeat)
    monkeypatch.setattr(lifecycle_main, "handle_candidate_lifecycle_job", handle)
    monkeypatch.setattr(lifecycle_main, "acknowledge_outbox_job", acknowledge)

    assert await worker.run_once() == 1
    assert claim.await_args is not None
    assert recover.await_args is not None
    assert handle.await_args is not None
    assert claim.await_args.kwargs["job_types"] == ("expire_candidate",)
    assert recover.await_args.kwargs["job_types"] == ("expire_candidate",)
    assert handle.await_args.kwargs["principal"].scopes == frozenset({"memory.lifecycle.expire"})
    assert acknowledge.await_count == 1


@pytest.mark.asyncio
async def test_worker_records_only_allowlisted_content_free_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    worker = CandidateLifecycleWorker(settings, _DatabaseStub())  # type: ignore[arg-type]
    job = _job(settings.tenant_ids[0])
    fail = AsyncMock()
    monkeypatch.setattr(worker, "verify_identities", AsyncMock())
    monkeypatch.setattr(lifecycle_main, "recover_expired_outbox_leases", AsyncMock())
    monkeypatch.setattr(lifecycle_main, "claim_outbox_jobs", AsyncMock(return_value=(job,)))
    monkeypatch.setattr(lifecycle_main, "heartbeat_outbox_job", AsyncMock())
    monkeypatch.setattr(
        lifecycle_main,
        "handle_candidate_lifecycle_job",
        AsyncMock(side_effect=CandidateLifecycleJobError("forbidden")),
    )
    monkeypatch.setattr(lifecycle_main, "fail_outbox_job", fail)

    assert await worker.run_once() == 0
    assert fail.await_args is not None
    assert fail.await_args.kwargs["error_code"] == "invalid_job"
    assert fail.await_args.kwargs["retryable"] is False


class _Result:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def one_or_none(self) -> tuple[object, ...]:
        return self._row


class _IdentitySession:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    async def execute(self, _statement: object) -> _Result:
        return _Result(self._row)


@pytest.mark.asyncio
async def test_worker_resolves_only_a_live_exactly_scoped_internal_binding() -> None:
    settings = _settings()
    valid_row = (
        "internal_service",
        "internal",
        None,
        "service",
        None,
        "worker",
        None,
        ["memory.lifecycle.expire"],
    )
    worker = CandidateLifecycleWorker(
        settings,
        _DatabaseStub(_IdentitySession(valid_row)),  # type: ignore[arg-type]
    )

    await worker.verify_identities()

    invalid_row = (*valid_row[:-1], ["memory.lifecycle.expire", "memory.lifecycle.promote"])
    invalid_worker = CandidateLifecycleWorker(
        settings,
        _DatabaseStub(_IdentitySession(invalid_row)),  # type: ignore[arg-type]
    )
    with pytest.raises(LifecycleWorkerConfigurationError, match="lifecycle_identity_unavailable"):
        await invalid_worker.verify_identities()
