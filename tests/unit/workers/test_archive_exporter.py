from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest
from kivra_memory.archive.codec import SnapshotTable
from kivra_memory.archive.restore import RestorePlan as CoreRestorePlan
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import ArchiveBatchSource, ArchiveStorageError, RestorePlan
from kivra_memory.storage.models import ArchiveExportCheckpoint
from kivra_memory.workers import archive_exporter, archive_restore
from kivra_memory.workers.archive_exporter import (
    BuiltArchive,
    ReconciledCommit,
    export_archive_target,
)
from kivra_memory.workers.archive_restore import CoreRestoreDecoder, restore_validated_archive
from sqlalchemy.ext.asyncio import AsyncSession

_WHEN = datetime(2026, 8, 9, 12, tzinfo=UTC)
_COMMIT = "a" * 40


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


def built() -> BuiltArchive:
    return BuiltArchive(
        manifest_sha256=b"m" * 32,
        manifest_path="manifest.json",
        commit_message="memory-export: events 1..2",
        commit_timestamp=_WHEN,
        payload=object(),
    )


async def test_export_reconciles_existing_remote_commit_without_new_git_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = ArchiveExportCheckpoint(state="preparing")
    monkeypatch.setattr(
        archive_exporter, "load_archive_batch_source", AsyncMock(return_value=source())
    )
    prepare = AsyncMock(return_value=checkpoint)
    commit_checkpoint = AsyncMock()
    push_checkpoint = AsyncMock()
    monkeypatch.setattr(archive_exporter, "prepare_archive_checkpoint", prepare)
    monkeypatch.setattr(archive_exporter, "commit_archive_checkpoint", commit_checkpoint)
    monkeypatch.setattr(archive_exporter, "push_archive_checkpoint", push_checkpoint)
    builder = Mock()
    builder.build.return_value = built()
    repository = Mock()
    repository.reconcile = AsyncMock(
        return_value=ReconciledCommit(local_commit_sha=_COMMIT, remote_commit_sha=_COMMIT)
    )
    repository.commit = AsyncMock()
    repository.push = AsyncMock()

    result = await export_archive_target(
        cast(AsyncSession, Mock(spec=AsyncSession)),
        tenant_id=uid(1),
        archive_target_id=uid(2),
        exporter_version="test-v1",
        builder=builder,
        repository=repository,
        checkpoint_id_factory=lambda: uid(3),
        clock=lambda: _WHEN,
    )

    assert result is not None
    assert result.reconciled is True
    assert result.git_commit_sha == _COMMIT
    repository.commit.assert_not_awaited()
    repository.push.assert_not_awaited()
    commit_checkpoint.assert_awaited_once()
    push_checkpoint.assert_awaited_once()


async def test_export_creates_and_pushes_exactly_one_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = ArchiveExportCheckpoint(state="preparing")
    monkeypatch.setattr(
        archive_exporter, "load_archive_batch_source", AsyncMock(return_value=source())
    )
    monkeypatch.setattr(
        archive_exporter, "prepare_archive_checkpoint", AsyncMock(return_value=checkpoint)
    )
    monkeypatch.setattr(archive_exporter, "commit_archive_checkpoint", AsyncMock())
    monkeypatch.setattr(archive_exporter, "push_archive_checkpoint", AsyncMock())
    builder = Mock()
    builder.build.return_value = built()
    repository = Mock()
    repository.reconcile = AsyncMock(return_value=ReconciledCommit())
    repository.commit = AsyncMock(return_value=_COMMIT)
    repository.push = AsyncMock(return_value=_COMMIT)

    result = await export_archive_target(
        cast(AsyncSession, Mock(spec=AsyncSession)),
        tenant_id=uid(1),
        archive_target_id=uid(2),
        exporter_version="test-v1",
        builder=builder,
        repository=repository,
        checkpoint_id_factory=lambda: uid(3),
        clock=lambda: _WHEN,
    )

    assert result is not None
    assert result.reconciled is False
    repository.commit.assert_awaited_once()
    repository.push.assert_awaited_once_with(git_commit_sha=_COMMIT)


async def test_export_rejects_remote_identity_divergence_before_checkpoint_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = ArchiveExportCheckpoint(state="preparing")
    monkeypatch.setattr(
        archive_exporter, "load_archive_batch_source", AsyncMock(return_value=source())
    )
    monkeypatch.setattr(
        archive_exporter, "prepare_archive_checkpoint", AsyncMock(return_value=checkpoint)
    )
    commit_checkpoint = AsyncMock()
    monkeypatch.setattr(archive_exporter, "commit_archive_checkpoint", commit_checkpoint)
    builder = Mock()
    builder.build.return_value = built()
    repository = Mock()
    repository.reconcile = AsyncMock(
        return_value=ReconciledCommit(local_commit_sha=_COMMIT, remote_commit_sha="b" * 40)
    )

    with pytest.raises(ArchiveStorageError, match="archive_reconciliation_mismatch"):
        await export_archive_target(
            cast(AsyncSession, Mock(spec=AsyncSession)),
            tenant_id=uid(1),
            archive_target_id=uid(2),
            exporter_version="test-v1",
            builder=builder,
            repository=repository,
            checkpoint_id_factory=lambda: uid(3),
            clock=lambda: _WHEN,
        )
    commit_checkpoint.assert_not_awaited()


async def test_restore_decodes_before_mutation_and_verifies_in_same_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = RestorePlan(
        tenant_id=uid(1),
        snapshot_high_water_sequence=2,
        final_high_water_sequence=3,
        rows={},
    )
    order: list[str] = []
    decoder = Mock()

    def decode(_: object) -> RestorePlan:
        order.append("decode")
        return plan

    decoder.decode.side_effect = decode

    async def restore(_: AsyncSession, received: RestorePlan) -> None:
        assert received is plan
        order.append("restore")

    verifier = Mock()

    async def verify(_: AsyncSession, received: RestorePlan) -> None:
        assert received is plan
        order.append("verify")

    def replay(_: AsyncSession, *, tenant_id: UUID) -> None:
        assert tenant_id == uid(1)
        order.append("replay")

    verifier.verify = AsyncMock(side_effect=verify)
    monkeypatch.setattr(archive_restore, "restore_archive_rows", restore)
    monkeypatch.setattr(
        archive_restore, "rebuild_semantic_projections", AsyncMock(side_effect=replay)
    )

    result = await restore_validated_archive(
        cast(AsyncSession, Mock(spec=AsyncSession)),
        verified_plan=object(),
        decoder=decoder,
        verifier=verifier,
    )

    assert order == ["decode", "restore", "replay", "verify"]
    assert result.final_high_water_sequence == 3


def test_core_restore_decoder_preserves_verified_snapshot_rows() -> None:
    core_plan = CoreRestorePlan(
        manifest_sha256s=("a" * 64,),
        snapshot_high_water_sequence=2,
        snapshot_tables=(
            SnapshotTable(
                name="tenants",
                primary_key=("tenant_id",),
                rows=({"tenant_id": str(uid(1))},),
            ),
        ),
        events_to_replay=(),
        final_high_water_sequence=2,
    )

    decoded = CoreRestoreDecoder().decode(core_plan)

    assert decoded.tenant_id == uid(1)
    assert decoded.rows["tenants"] == ({"tenant_id": str(uid(1))},)
    assert decoded.later_events == ()
