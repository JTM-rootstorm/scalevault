"""Single-writer archive export orchestration over injected archive and Git seams."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import (
    ArchiveBatchSource,
    ArchiveStorageError,
    commit_archive_checkpoint,
    load_archive_batch_source,
    prepare_archive_checkpoint,
    push_archive_checkpoint,
)


@dataclass(frozen=True, slots=True)
class BuiltArchive:
    """Opaque verified archive output plus checkpoint and commit identity."""

    manifest_sha256: bytes
    manifest_path: str
    commit_message: str
    commit_timestamp: datetime
    payload: object


@dataclass(frozen=True, slots=True)
class ReconciledCommit:
    """Exact local/remote archive identity found before creating new history."""

    local_commit_sha: str | None = None
    remote_commit_sha: str | None = None


@dataclass(frozen=True, slots=True)
class ArchiveExportResult:
    """Safe exporter result containing identifiers but no archive content."""

    checkpoint_id: UUID
    first_event_sequence: int
    last_event_sequence: int
    git_commit_sha: str
    reconciled: bool


class ArchiveBuilder(Protocol):
    """Adapter implemented by the deterministic archive core."""

    def build(self, source: ArchiveBatchSource) -> BuiltArchive: ...


class ArchiveRepository(Protocol):
    """Fixed-target signed Git operations; implementations bind all configuration."""

    async def reconcile(
        self,
        archive: BuiltArchive,
        *,
        expected_parent_sha: str | None,
    ) -> ReconciledCommit: ...

    async def commit(
        self,
        archive: BuiltArchive,
        *,
        expected_parent_sha: str | None,
    ) -> str: ...

    async def push(self, *, git_commit_sha: str) -> str: ...


Clock = Callable[[], datetime]
CheckpointIdFactory = Callable[[], UUID]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validate_commit_sha(value: str) -> str:
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ArchiveStorageError("archive_commit_identity_invalid")
    return value


async def export_archive_target(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    archive_target_id: UUID,
    exporter_version: str,
    builder: ArchiveBuilder,
    repository: ArchiveRepository,
    postgres_timeline_id: int | None = None,
    checkpoint_id_factory: CheckpointIdFactory = new_uuid7,
    clock: Clock = _utc_now,
) -> ArchiveExportResult | None:
    """Export one complete source prefix while holding the target transaction lock.

    ``repository.reconcile`` must match manifest hash and exact parent/tree/message
    identity. This lets a retry adopt a commit produced before a database rollback
    without amending or duplicating published history.
    """

    source = await load_archive_batch_source(
        session,
        tenant_id=tenant_id,
        archive_target_id=archive_target_id,
    )
    if source is None:
        return None

    archive = builder.build(source)
    if len(archive.manifest_sha256) != 32:
        raise ArchiveStorageError("archive_manifest_identity_invalid")
    if (
        archive.commit_timestamp.isoformat()
        != datetime.fromisoformat(source.export_timestamp.replace("Z", "+00:00")).isoformat()
    ):
        raise ArchiveStorageError("archive_commit_timestamp_mismatch")

    checkpoint_id = checkpoint_id_factory()
    checkpoint = await prepare_archive_checkpoint(
        session,
        source=source,
        checkpoint_id=checkpoint_id,
        manifest_sha256=archive.manifest_sha256,
        manifest_path=archive.manifest_path,
        exporter_version=exporter_version,
        postgres_timeline_id=postgres_timeline_id,
        started_at=clock(),
    )

    state = await repository.reconcile(archive, expected_parent_sha=source.previous_git_commit_sha)
    if state.remote_commit_sha is not None and state.local_commit_sha != state.remote_commit_sha:
        raise ArchiveStorageError("archive_reconciliation_mismatch")

    reconciled = state.local_commit_sha is not None
    git_commit_sha = (
        _validate_commit_sha(state.local_commit_sha)
        if state.local_commit_sha is not None
        else _validate_commit_sha(
            await repository.commit(archive, expected_parent_sha=source.previous_git_commit_sha)
        )
    )
    committed_at = clock()
    await commit_archive_checkpoint(
        session,
        checkpoint,
        git_commit_sha=git_commit_sha,
        committed_at=committed_at,
    )

    remote_sha = (
        _validate_commit_sha(state.remote_commit_sha)
        if state.remote_commit_sha is not None
        else _validate_commit_sha(await repository.push(git_commit_sha=git_commit_sha))
    )
    if remote_sha != git_commit_sha:
        raise ArchiveStorageError("archive_push_identity_mismatch")
    await push_archive_checkpoint(
        session,
        checkpoint,
        remote_git_commit_sha=remote_sha,
        pushed_at=clock(),
    )
    return ArchiveExportResult(
        checkpoint_id=checkpoint_id,
        first_event_sequence=source.first_event_sequence,
        last_event_sequence=source.last_event_sequence,
        git_commit_sha=git_commit_sha,
        reconciled=reconciled,
    )
