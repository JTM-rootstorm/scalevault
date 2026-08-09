from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import (
    ArchiveBatchSource,
    ArchiveStorageError,
    _require_single_tenant_global_prefix,
    archive_row_dto,
    archive_target_advisory_lock_key,
    commit_archive_checkpoint,
    prepare_archive_checkpoint,
    push_archive_checkpoint,
    recovery_table_names,
    try_acquire_archive_target_lock,
)
from kivra_memory.storage.models import Actor, ArchiveExportCheckpoint, Tenant
from sqlalchemy.ext.asyncio import AsyncSession

_WHEN = datetime(2026, 8, 9, 12, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


def source() -> ArchiveBatchSource:
    return ArchiveBatchSource(
        tenant_id=str(uid(1)),
        archive_target_id=str(uid(2)),
        previous_checkpoint_id=None,
        previous_manifest_sha256=None,
        previous_git_commit_sha=None,
        source_high_water_sequence=2,
        first_event_sequence=1,
        last_event_sequence=2,
        event_count=2,
        export_timestamp="2026-08-09T12:00:00Z",
        events=(),
        recovery_primary_keys={},
        recovery_rows={},
    )


def test_target_lock_key_is_stable_scoped_and_signed() -> None:
    first = archive_target_advisory_lock_key(tenant_id=uid(1), archive_target_id=uid(2))

    assert first == archive_target_advisory_lock_key(tenant_id=uid(1), archive_target_id=uid(2))
    assert -(2**63) <= first < 2**63
    assert first != archive_target_advisory_lock_key(tenant_id=uid(1), archive_target_id=uid(3))
    assert first != archive_target_advisory_lock_key(tenant_id=uid(4), archive_target_id=uid(2))


async def test_try_target_lock_uses_nonblocking_transaction_lock() -> None:
    raw = Mock(spec=AsyncSession)
    result = Mock()
    result.scalar_one.return_value = True
    raw.execute = AsyncMock(return_value=result)

    acquired = await try_acquire_archive_target_lock(
        cast(AsyncSession, raw), tenant_id=uid(1), archive_target_id=uid(2)
    )

    assert acquired is True
    statement, parameters = raw.execute.await_args.args
    assert str(statement) == "SELECT pg_try_advisory_xact_lock(:lock_key)"
    assert parameters == {
        "lock_key": archive_target_advisory_lock_key(tenant_id=uid(1), archive_target_id=uid(2))
    }


def test_row_dto_uses_database_names_and_canonical_primitives() -> None:
    tenant = Tenant(
        tenant_id=uid(1),
        slug="synthetic",
        display_name="Synthetic",
        state="active",
        created_at=_WHEN,
        updated_at=_WHEN,
    )

    assert archive_row_dto(tenant) == {
        "created_at": "2026-08-09T12:00:00.000000Z",
        "display_name": "Synthetic",
        "slug": "synthetic",
        "state": "active",
        "tenant_id": str(uid(1)),
        "updated_at": "2026-08-09T12:00:00.000000Z",
    }


def test_row_dto_encodes_json_as_canonical_bytes_for_float_free_cbor() -> None:
    actor = Actor(
        actor_id=uid(2),
        tenant_id=uid(1),
        handle="synthetic",
        display_name="Synthetic",
        kind="user",
        metadata_={"ratio": 0.5},
        created_at=_WHEN,
        revoked_at=None,
    )

    assert archive_row_dto(actor)["metadata"] == b'{"ratio":0.5}'


def test_recovery_allowlist_excludes_secrets_jobs_and_archive_state() -> None:
    names = set(recovery_table_names())

    assert {
        "memory_events",
        "memories",
        "memory_content_keys",
        "ingress_items",
        "ingress_provider_heads",
        "ingress_provider_violations",
    } <= names
    assert "client_credentials" not in names
    assert "memory_embeddings_v1" not in names
    assert "outbox_jobs" not in names
    assert "archive_targets" not in names
    assert "archive_export_checkpoints" not in names


def test_single_tenant_archive_requires_the_complete_global_event_prefix() -> None:
    assert (
        _require_single_tenant_global_prefix(
            next_global_sequence=3,
            tenant_event_count=2,
            tenant_min_sequence=1,
            tenant_max_sequence=2,
        )
        == 2
    )


@pytest.mark.parametrize(
    ("event_count", "minimum", "maximum"),
    [
        pytest.param(1, 1, 1, id="foreign-tenant-or-missing-sequence"),
        pytest.param(2, 2, 3, id="non-prefix-sequences"),
    ],
)
def test_single_tenant_archive_rejects_global_sequence_mismatch(
    event_count: int, minimum: int, maximum: int
) -> None:
    with pytest.raises(ArchiveStorageError, match="archive_multitenant_unsupported"):
        _require_single_tenant_global_prefix(
            next_global_sequence=3,
            tenant_event_count=event_count,
            tenant_min_sequence=minimum,
            tenant_max_sequence=maximum,
        )


async def test_checkpoint_state_machine_is_idempotent_and_fail_closed() -> None:
    raw = Mock(spec=AsyncSession)
    raw.add = Mock()
    raw.flush = AsyncMock()
    session = cast(AsyncSession, raw)

    checkpoint = await prepare_archive_checkpoint(
        session,
        source=source(),
        checkpoint_id=uid(3),
        manifest_sha256=b"m" * 32,
        manifest_path="manifest.json",
        exporter_version="test-v1",
        started_at=_WHEN,
    )
    assert isinstance(checkpoint, ArchiveExportCheckpoint)
    assert checkpoint.state == "preparing"
    raw.add.assert_called_once_with(checkpoint)

    commit_sha = "a" * 40
    await commit_archive_checkpoint(
        session, checkpoint, git_commit_sha=commit_sha, committed_at=_WHEN
    )
    await commit_archive_checkpoint(
        session, checkpoint, git_commit_sha=commit_sha, committed_at=_WHEN
    )
    assert checkpoint.state == "committed"

    with pytest.raises(ArchiveStorageError, match="archive_checkpoint_state"):
        await push_archive_checkpoint(
            session,
            checkpoint,
            remote_git_commit_sha="b" * 40,
            pushed_at=_WHEN,
        )

    await push_archive_checkpoint(
        session,
        checkpoint,
        remote_git_commit_sha=commit_sha,
        pushed_at=_WHEN,
    )
    await push_archive_checkpoint(
        session,
        checkpoint,
        remote_git_commit_sha=commit_sha,
        pushed_at=_WHEN,
    )
    assert checkpoint.state == "pushed"
    assert checkpoint.remote_git_commit_sha == commit_sha
    assert raw.flush.await_count == 3
