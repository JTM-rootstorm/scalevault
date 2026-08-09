from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.outbox_worker import ClaimedOutboxJob
from kivra_memory.workers import sealed_main
from kivra_memory.workers.sealed_content import (
    SealedContentPurgeError,
    SealedContentPurgeResult,
)
from kivra_memory.workers.sealed_main import (
    SealedContentWorker,
    SealedWorkerConfigurationError,
    SealedWorkerSettings,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class _DatabaseStub:
    def __init__(self, session: object | None = None) -> None:
        self._session = session if session is not None else MagicMock()

    @asynccontextmanager
    async def tenant_session(self, _tenant_id: object) -> AsyncIterator[object]:
        yield self._session


def _settings() -> SealedWorkerSettings:
    return SealedWorkerSettings(
        database_url="postgresql+psycopg://kivra_memory_purge@127.0.0.1/kivra_memory",
        tenant_id=new_uuid7(),
        actor_id=new_uuid7(),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
    )


def _job(tenant_id: UUID) -> ClaimedOutboxJob:
    memory_id = new_uuid7()
    return ClaimedOutboxJob(
        job_id=1,
        job_uuid=new_uuid7(),
        tenant_id=tenant_id,
        job_type="purge_payload",
        aggregate_type="memory",
        aggregate_id=memory_id,
        payload={
            "event_id": str(new_uuid7()),
            "memory_id": str(memory_id),
            "memory_version": 2,
        },
        attempt_count=1,
        max_attempts=8,
        lease_token="sealed:test",
    )


def test_settings_require_dedicated_role_and_pinned_uuid7_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    monkeypatch.setenv("KIVRA_MEMORY_PURGE_DATABASE_URL", settings.database_url)
    monkeypatch.setenv("KIVRA_MEMORY_PURGE_TENANT_ID", str(settings.tenant_id))
    monkeypatch.setenv("KIVRA_MEMORY_PURGE_ACTOR_ID", str(settings.actor_id))
    monkeypatch.setenv("KIVRA_MEMORY_PURGE_CLIENT_ID", str(settings.client_id))
    monkeypatch.setenv(
        "KIVRA_MEMORY_PURGE_TRANSPORT_BINDING_ID",
        str(settings.transport_binding_id),
    )

    assert SealedWorkerSettings.from_environment() == settings
    monkeypatch.setenv(
        "KIVRA_MEMORY_PURGE_DATABASE_URL",
        "postgresql+psycopg://kivra_memory_worker@example.invalid/kivra_memory",
    )
    with pytest.raises(SealedWorkerConfigurationError, match="invalid_sealed"):
        SealedWorkerSettings.from_environment()

    sentinel = "SENTINEL-PASSWORD-MUST-NOT-APPEAR"
    monkeypatch.setenv(
        "KIVRA_MEMORY_PURGE_DATABASE_URL",
        f"postgresql+psycopg://kivra_memory_purge:{sentinel}@127.0.0.1/kivra_memory",
    )
    parsed = SealedWorkerSettings.from_environment()
    assert sentinel not in repr(parsed)

    monkeypatch.setenv(
        "KIVRA_MEMORY_PURGE_DATABASE_URL",
        "postgresql+psycopg://kivra_memory_purge:secret@database.example/kivra_memory",
    )
    with pytest.raises(SealedWorkerConfigurationError, match="invalid_sealed"):
        SealedWorkerSettings.from_environment()


def test_main_sanitizes_startup_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "SENTINEL-STARTUP-DETAIL"
    monkeypatch.setattr(
        sealed_main.SealedWorkerSettings,
        "from_environment",
        MagicMock(side_effect=RuntimeError(sentinel)),
    )

    with pytest.raises(SystemExit) as caught:
        sealed_main.main()

    captured = capsys.readouterr()
    assert caught.value.code == 2
    assert captured.out == ""
    assert captured.err == "ScaleVault sealed worker is unavailable\n"
    assert sentinel not in captured.err


@pytest.mark.asyncio
async def test_worker_claims_only_purge_and_acknowledges_with_exact_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    provider = MagicMock()
    worker = SealedContentWorker(settings, _DatabaseStub(), provider)  # type: ignore[arg-type]
    job = _job(settings.tenant_id)
    recover = AsyncMock()
    claim = AsyncMock(return_value=(job,))
    handle = AsyncMock(
        return_value=SealedContentPurgeResult(
            outcome="purged",
            memory_id=job.aggregate_id,
            revision=3,
            event_id=new_uuid7(),
        )
    )
    acknowledge = AsyncMock()
    monkeypatch.setattr(worker, "verify_identity", AsyncMock())
    monkeypatch.setattr(sealed_main, "recover_expired_outbox_leases", recover)
    monkeypatch.setattr(sealed_main, "claim_outbox_jobs", claim)
    monkeypatch.setattr(sealed_main, "heartbeat_outbox_job", AsyncMock())
    monkeypatch.setattr(sealed_main, "handle_purge_payload_job", handle)
    monkeypatch.setattr(sealed_main, "acknowledge_outbox_job", acknowledge)

    assert await worker.run_once() == 1
    assert claim.await_args.kwargs["job_types"] == ("purge_payload",)
    assert recover.await_args.kwargs["job_types"] == ("purge_payload",)
    assert handle.await_args.kwargs["key_provider"] is provider
    assert handle.await_args.kwargs["principal"].scopes == frozenset({"memory.lifecycle.purge"})
    assert acknowledge.await_count == 1


@pytest.mark.asyncio
async def test_worker_records_only_content_free_allowlisted_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    worker = SealedContentWorker(settings, _DatabaseStub(), MagicMock())  # type: ignore[arg-type]
    job = _job(settings.tenant_id)
    fail = AsyncMock()
    monkeypatch.setattr(worker, "verify_identity", AsyncMock())
    monkeypatch.setattr(sealed_main, "recover_expired_outbox_leases", AsyncMock())
    monkeypatch.setattr(sealed_main, "claim_outbox_jobs", AsyncMock(return_value=(job,)))
    monkeypatch.setattr(sealed_main, "heartbeat_outbox_job", AsyncMock())
    monkeypatch.setattr(
        sealed_main,
        "handle_purge_payload_job",
        AsyncMock(side_effect=SealedContentPurgeError("dependency_unavailable")),
    )
    monkeypatch.setattr(sealed_main, "fail_outbox_job", fail)

    assert await worker.run_once() == 0
    assert fail.await_args.kwargs["error_code"] == "dependency_unavailable"
    assert fail.await_args.kwargs["retryable"] is True


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
async def test_worker_requires_exact_internal_binding_operation_and_scope() -> None:
    settings = _settings()
    valid = (
        "internal_service",
        "internal",
        None,
        {"operations": ["payload_purge_completed"]},
        "service",
        None,
        "worker",
        None,
        ["memory.lifecycle.purge"],
    )
    worker = SealedContentWorker(
        settings,
        _DatabaseStub(_IdentitySession(valid)),  # type: ignore[arg-type]
        MagicMock(),
    )
    await worker.verify_identity()

    invalid = (*valid[:-1], ["memory.lifecycle.purge", "memory:write"])
    invalid_worker = SealedContentWorker(
        settings,
        _DatabaseStub(_IdentitySession(invalid)),  # type: ignore[arg-type]
        MagicMock(),
    )
    with pytest.raises(SealedWorkerConfigurationError, match="identity_unavailable"):
        await invalid_worker.verify_identity()


def test_systemd_profile_is_local_separate_and_least_privilege() -> None:
    unit = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/kivra-memory-sealed-worker.service"
    ).read_text()
    drop_in = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/sealed-content/"
        "kivra-memory-api.service.d/20-sealed-content.conf"
    ).read_text()

    assert "User=memory-purge" in unit
    assert "Group=memory-purge" in unit
    assert "SupplementaryGroups=kivra-memory kivra-sealed" in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys" in unit
    assert "/mnt/memory" not in unit
    assert "LoadCredential=sealed-digest-binding:" in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys" in drop_in
