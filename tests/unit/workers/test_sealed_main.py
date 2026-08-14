from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.destruction_ledger import (
    LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
    LOCAL_DESTRUCTION_LEDGER_ROOT,
    DestructionLedgerAnchor,
)
from kivra_memory.security.local_key_provider import (
    LOCAL_DESTRUCTION_REQUEST_ROOT,
    LOCAL_KEY_PROVIDER_ROOT,
)
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


def test_main_composes_only_destruction_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    destroyer = MagicMock(spec=["name", "destroy_key"])
    constructor = MagicMock(return_value=destroyer)
    run_worker = AsyncMock()
    monkeypatch.setattr(
        sealed_main.SealedWorkerSettings,
        "from_environment",
        MagicMock(return_value=settings),
    )
    anchor = DestructionLedgerAnchor(
        entry_count=0,
        aggregate_sha256="a" * 64,
    )
    monkeypatch.setattr(
        sealed_main,
        "read_systemd_credential",
        MagicMock(return_value=anchor.canonical_bytes()),
    )
    monkeypatch.setattr(sealed_main, "LocalDirectoryKeyPurgeRequester", constructor)
    monkeypatch.setattr(sealed_main, "run_sealed_worker", run_worker)

    sealed_main.main()

    constructor.assert_called_once_with(
        LOCAL_KEY_PROVIDER_ROOT,
        destruction_request_root=LOCAL_DESTRUCTION_REQUEST_ROOT,
        destruction_ledger_root=LOCAL_DESTRUCTION_LEDGER_ROOT,
        destruction_ledger_anchor_path=LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
        expected_destruction_ledger_anchor=anchor,
        required_owner_uid=0,
    )
    run_worker.assert_awaited_once_with(settings, destroyer)
    assert not hasattr(destroyer, "get_key")


@pytest.mark.asyncio
async def test_worker_claims_only_purge_and_acknowledges_with_exact_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings()
    provider = MagicMock()
    worker = SealedContentWorker(settings, _DatabaseStub(), provider)  # type: ignore[arg-type]
    job = _job(settings.tenant_id)
    assert job.aggregate_id is not None
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
    claim_call = claim.await_args
    recover_call = recover.await_args
    handle_call = handle.await_args
    assert claim_call is not None
    assert recover_call is not None
    assert handle_call is not None
    assert claim_call.kwargs["job_types"] == ("purge_payload",)
    assert recover_call.kwargs["job_types"] == ("purge_payload",)
    assert handle_call.kwargs["key_destroyer"] is provider
    assert handle_call.kwargs["principal"].scopes == frozenset({"memory.lifecycle.purge"})
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
    fail_call = fail.await_args
    assert fail_call is not None
    assert fail_call.kwargs["error_code"] == "dependency_unavailable"
    assert fail_call.kwargs["retryable"] is True


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
    operator_documentation = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/README.md"
    ).read_text()

    assert "User=memory-purge" in unit
    assert "Group=memory-purge" in unit
    assert (
        "SupplementaryGroups=kivra-memory kivra-sealed kivra-destruction-ledger "
        "kivra-destruction-request"
    ) in unit
    assert "ReadOnlyPaths=/var/lib/kivra-memory-sealed/keys/control" in unit
    assert "ReadOnlyPaths=/var/lib/kivra-memory-sealed/keys/material" in unit
    assert "ReadOnlyPaths=/var/lib/kivra-memory-sealed/destruction-ledger" in unit
    assert "ConditionPathIsReadWrite=/var/lib/kivra-memory-destruction-anchor" not in unit
    assert "ReadOnlyPaths=/var/lib/kivra-memory-destruction-anchor" in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/purge-requests" in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys" not in unit.splitlines()
    assert unit.count("LoadCredential=") == 2
    assert "LoadCredential=database-url:" in unit
    assert "LoadCredential=sealed-digest-binding:" not in unit
    assert "/mnt/memory" not in unit
    assert "LoadCredential=sealed-digest-binding:" in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/control" in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/material" in drop_in
    assert "ReadOnlyPaths=/var/lib/kivra-memory-sealed/destruction-ledger" in drop_in
    assert "ReadOnlyPaths=/var/lib/kivra-memory-destruction-anchor" in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/destruction-ledger" not in drop_in
    assert "ReadWritePaths=/var/lib/kivra-memory-destruction-anchor" not in drop_in
    assert (
        "KIVRA_MEMORY_SEALED_DESTRUCTION_LEDGER_ROOT="
        "/var/lib/kivra-memory-sealed/destruction-ledger"
    ) in drop_in
    assert (
        "KIVRA_MEMORY_SEALED_DESTRUCTION_LEDGER_ANCHOR_PATH="
        "/var/lib/kivra-memory-destruction-anchor/current.json"
    ) in drop_in
    assert "DEK files in `material` as `memory-api` mode `0600`" in operator_documentation
    assert "Do not make material files group-readable" in operator_documentation


def test_destruction_broker_unit_is_non_root_bounded_and_hardened() -> None:
    unit = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/kivra-memory-destruction-broker.service"
    ).read_text()
    path_unit = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/kivra-memory-destruction-broker.path"
    ).read_text()

    assert "User=memory-destruction" in unit
    assert "User=root" not in unit
    assert (
        "LoadCredential=destruction-ledger-anchor:/etc/kivra-memory/destruction-ledger-anchor"
    ) in unit
    assert "ConditionFileNotEmpty=/etc/kivra-memory/destruction-ledger-anchor" in unit
    assert "ConditionPathIsRegularFile=" not in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/purge-requests" in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/destruction-ledger" in unit
    assert "ReadWritePaths=/var/lib/kivra-memory-destruction-anchor" in unit
    assert "TimeoutStartSec=60s" in unit
    assert "DirectoryNotEmpty=/var/lib/kivra-memory-sealed/purge-requests" in path_unit
    for directive in (
        "NoNewPrivileges=true",
        "PrivateMounts=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RemoveIPC=true",
        "RestrictNamespaces=true",
        "RestrictRealtime=true",
        "KeyringMode=private",
        "LimitCORE=0",
        "CapabilityBoundingSet=",
    ):
        assert directive in unit


def test_api_activation_requires_offline_restore_reconciliation() -> None:
    reconcile = REPOSITORY_ROOT.joinpath(
        "deploy/memory-node/systemd/kivra-memory-sealed-restore-reconcile.service"
    ).read_text()
    for service in ("kivra-memory-api", "kivra-memory-codex-ingress"):
        drop_in = REPOSITORY_ROOT.joinpath(
            "deploy/memory-node/systemd/sealed-content",
            f"{service}.service.d/20-sealed-content.conf",
        ).read_text()
        assert "Requires=kivra-memory-sealed-restore-reconcile.service" in drop_in
        assert "After=kivra-memory-sealed-restore-reconcile.service" in drop_in

    assert "User=memory-destruction" in reconcile
    assert "LoadCredential=destruction-ledger-anchor:" in reconcile
    assert "ConditionFileNotEmpty=/etc/kivra-memory/destruction-ledger-anchor" in reconcile
    assert "ConditionPathIsRegularFile=" not in reconcile
    assert "ReadOnlyPaths=/var/lib/kivra-memory-sealed/destruction-ledger" in reconcile
    assert "ReadOnlyPaths=/var/lib/kivra-memory-destruction-anchor" in reconcile
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/control" in reconcile
    assert "ReadWritePaths=/var/lib/kivra-memory-sealed/keys/material" in reconcile
