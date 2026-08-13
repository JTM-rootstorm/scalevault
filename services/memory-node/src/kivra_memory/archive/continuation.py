"""Safe new-target archive continuation and post-append proof seams."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.archive.git import (
    GitSigningError,
    ProcessResult,
    ProcessRunner,
    SubprocessRunner,
)
from kivra_memory.archive.models import MANIFEST_PATH, require_sha256
from kivra_memory.archive.recovery import GitRecoverySource, ReadOnlyGitArchive
from kivra_memory.archive.verification import (
    ArchiveSignerEpoch,
    VerifiedArchive,
    verify_signed_archive_epochs,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.storage.archive import (
    ArchiveBatchSource,
    ArchiveStorageError,
    archive_event_dto,
    commit_archive_checkpoint,
    prepare_archive_checkpoint,
    try_acquire_archive_target_lock,
)
from kivra_memory.storage.models import (
    ArchiveExportCheckpoint,
    ArchiveTarget,
    MemoryEvent,
    MemoryEventCounter,
)

_REF_NAME = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")
_COUNT_OBJECT_KEYS = {
    "count",
    "size",
    "in-pack",
    "packs",
    "size-pack",
    "prune-packable",
    "garbage",
    "size-garbage",
}
_MAX_OBJECT_CLOSURE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _PinnedDirectory:
    device: int
    inode: int
    owner: int


class ArchiveContinuationError(RuntimeError):
    """Content-free failure while preparing or proving archive continuation."""


@dataclass(frozen=True, slots=True)
class ContinuationCheckpointPlan:
    """Exact final accepted checkpoint state for a new immutable target."""

    archive_target_id: str
    source_high_water_sequence: int
    first_event_sequence: int
    last_event_sequence: int
    event_count: int
    previous_manifest_sha256: str | None
    manifest_sha256: str
    manifest_path: str
    exporter_version: str
    postgres_timeline_id: int | None
    exported_at: str
    git_commit_sha: str

    @classmethod
    def from_verified(
        cls,
        archive: VerifiedArchive,
        *,
        archive_target_id: str,
    ) -> ContinuationCheckpointPlan:
        if not archive_target_id or len(archive_target_id) > 128:
            raise ArchiveContinuationError("new archive target identity is invalid")
        commit = archive.commits[-1]
        manifest = commit.batch.manifest
        return cls(
            archive_target_id=archive_target_id,
            source_high_water_sequence=manifest.source_high_water_sequence,
            first_event_sequence=manifest.first_event_sequence,
            last_event_sequence=manifest.last_event_sequence,
            event_count=manifest.event_count,
            previous_manifest_sha256=manifest.previous_manifest_sha256,
            manifest_sha256=commit.batch.manifest_sha256,
            manifest_path=MANIFEST_PATH,
            exporter_version=manifest.exporter_version,
            postgres_timeline_id=manifest.postgres_timeline_id,
            exported_at=manifest.exported_at,
            git_commit_sha=commit.git.commit_sha,
        )

    def __post_init__(self) -> None:
        if not self.archive_target_id or len(self.archive_target_id) > 128:
            raise ArchiveContinuationError("new archive target identity is invalid")
        if self.manifest_path != MANIFEST_PATH:
            raise ArchiveContinuationError("continuation manifest path is invalid")
        try:
            require_sha256(self.manifest_sha256, "continuation manifest")
            if self.previous_manifest_sha256 is not None:
                require_sha256(self.previous_manifest_sha256, "previous continuation manifest")
        except ValueError:
            raise ArchiveContinuationError("continuation manifest identity is invalid") from None
        if (
            isinstance(self.source_high_water_sequence, bool)
            or self.source_high_water_sequence != self.last_event_sequence
            or self.first_event_sequence < 1
            or self.last_event_sequence < self.first_event_sequence
            or self.event_count != self.last_event_sequence - self.first_event_sequence + 1
        ):
            raise ArchiveContinuationError("continuation checkpoint range is invalid")
        if len(self.git_commit_sha) not in {40, 64} or any(
            character not in "0123456789abcdef" for character in self.git_commit_sha
        ):
            raise ArchiveContinuationError("continuation checkpoint head is invalid")


@dataclass(slots=True)
class DatabaseCheckpointReconstructor:
    """Reconstruct one local committed checkpoint through existing handlers."""

    session: AsyncSession
    verified_archive: VerifiedArchive
    tenant_id: UUID
    checkpoint_id: UUID
    target_name: str
    local_repository: Path
    repository_reference: str
    branch_name: str

    async def reconstruct_checkpoint(self, plan: ContinuationCheckpointPlan) -> None:
        if plan != ContinuationCheckpointPlan.from_verified(
            self.verified_archive,
            archive_target_id=plan.archive_target_id,
        ):
            raise ArchiveContinuationError("checkpoint plan does not match verified archive")
        try:
            target_id = UUID(plan.archive_target_id)
        except ValueError:
            raise ArchiveContinuationError("new archive target identity is invalid") from None
        if not self.session.in_transaction():
            raise ArchiveContinuationError("checkpoint reconstruction requires a transaction")
        try:
            expected_reference = self.local_repository.resolve(strict=True).as_uri()
        except OSError:
            raise ArchiveContinuationError("local continuation target is unavailable") from None
        if (
            not self.local_repository.is_absolute()
            or self.local_repository.is_symlink()
            or self.repository_reference != expected_reference
        ):
            raise ArchiveContinuationError("local continuation target binding does not match")
        if not await try_acquire_archive_target_lock(
            self.session,
            tenant_id=self.tenant_id,
            archive_target_id=target_id,
        ):
            raise ArchiveContinuationError("new archive target is busy")
        existing_target = await self.session.scalar(
            select(ArchiveTarget).where(
                ArchiveTarget.tenant_id == self.tenant_id,
                or_(
                    ArchiveTarget.archive_target_id == target_id,
                    ArchiveTarget.name == self.target_name,
                    ArchiveTarget.repository_reference == self.repository_reference,
                ),
            )
        )
        existing_checkpoint = await self.session.scalar(
            select(ArchiveExportCheckpoint).where(
                ArchiveExportCheckpoint.tenant_id == self.tenant_id,
                ArchiveExportCheckpoint.archive_target_id == target_id,
            )
        )
        if existing_target is not None or existing_checkpoint is not None:
            raise ArchiveContinuationError("new archive target is not database-empty")
        prefix = (
            await self.session.execute(
                select(
                    func.count(MemoryEvent.sequence),
                    func.min(MemoryEvent.sequence),
                    func.max(MemoryEvent.sequence),
                ).where(MemoryEvent.tenant_id == self.tenant_id)
            )
        ).one()
        next_sequence = await self.session.scalar(
            select(MemoryEventCounter.next_sequence)
            .where(MemoryEventCounter.counter_id == 1)
            .with_for_update()
        )
        if (
            prefix
            != (
                plan.source_high_water_sequence,
                1,
                plan.source_high_water_sequence,
            )
            or next_sequence != plan.source_high_water_sequence + 1
        ):
            raise ArchiveContinuationError("canonical database prefix does not match archive")
        expected_events = tuple(
            canonical_json_bytes(event.model_dump(mode="json"))
            for commit in self.verified_archive.commits
            for event in commit.batch.events
        )
        stored_events = tuple(
            canonical_json_bytes(archive_event_dto(row))
            for row in (
                await self.session.execute(
                    select(MemoryEvent)
                    .where(MemoryEvent.tenant_id == self.tenant_id)
                    .order_by(MemoryEvent.sequence)
                )
            )
            .scalars()
            .all()
        )
        if (
            len(expected_events) != plan.source_high_water_sequence
            or stored_events != expected_events
        ):
            raise ArchiveContinuationError("canonical database events do not match archive")
        target = ArchiveTarget(
            archive_target_id=target_id,
            tenant_id=self.tenant_id,
            name=self.target_name,
            target_kind="forgejo_git",
            repository_reference=self.repository_reference,
            branch_name=self.branch_name,
            state="disabled",
        )
        self.session.add(target)
        try:
            await self.session.flush()
        except SQLAlchemyError:
            raise ArchiveContinuationError("continuation target creation failed") from None
        try:
            exported_at = datetime.fromisoformat(plan.exported_at.replace("Z", "+00:00"))
            source = ArchiveBatchSource(
                tenant_id=str(self.tenant_id),
                archive_target_id=str(target_id),
                previous_checkpoint_id=None,
                previous_manifest_sha256=plan.previous_manifest_sha256,
                previous_git_commit_sha=None,
                source_high_water_sequence=plan.source_high_water_sequence,
                first_event_sequence=plan.first_event_sequence,
                last_event_sequence=plan.last_event_sequence,
                event_count=plan.event_count,
                export_timestamp=plan.exported_at,
                events=(),
                recovery_primary_keys={},
                recovery_rows={},
            )
            checkpoint = await prepare_archive_checkpoint(
                self.session,
                source=source,
                checkpoint_id=self.checkpoint_id,
                manifest_sha256=bytes.fromhex(plan.manifest_sha256),
                manifest_path=plan.manifest_path,
                exporter_version=plan.exporter_version,
                postgres_timeline_id=plan.postgres_timeline_id,
                started_at=exported_at,
            )
        except (ArchiveStorageError, ValueError):
            raise ArchiveContinuationError("checkpoint reconstruction prepare failed") from None
        try:
            await commit_archive_checkpoint(
                self.session,
                checkpoint,
                git_commit_sha=plan.git_commit_sha,
                committed_at=exported_at,
            )
        except (ArchiveStorageError, ValueError):
            raise ArchiveContinuationError("checkpoint reconstruction commit failed") from None


class CheckpointReconstructor(Protocol):
    """Privileged database seam for one exact pushed-checkpoint reconstruction."""

    async def reconstruct_checkpoint(self, plan: ContinuationCheckpointPlan) -> None:
        """Create only the supplied checkpoint under normal storage locking."""


class NormalArchiveAppender(Protocol):
    """Existing single-writer exporter seam used for the continuation proof."""

    async def append_once(
        self,
        *,
        expected_parent_head: str,
        expected_next_event_sequence: int,
    ) -> str:
        """Perform one ordinary export/push and return its accepted remote head."""


class NewTargetHistoryCopier:
    """Copy one pinned history into an operator-created, empty local bare target."""

    def __init__(self, *, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or SubprocessRunner()

    def copy(self, source: GitRecoverySource, *, target_repository: Path) -> GitRecoverySource:
        identity = self._require_safe_directory(target_repository)
        self._require_empty_bare_target(source, target_repository, identity)
        zero = "0" * len(source.expected_head)
        reference = f"refs/heads/{source.branch_name}"
        if _REF_NAME.fullmatch(reference) is None:
            raise ArchiveContinuationError("new archive target reference is invalid")
        self._git(
            source,
            target_repository,
            (
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.file.allow=always",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                "--",
                str(source.repository),
                source.expected_head,
            ),
            stdout_limit_bytes=64 * 1024,
            identity=identity,
        )
        self._git(
            source,
            target_repository,
            ("fsck", "--strict", "--no-reflogs", "--no-dangling", source.expected_head),
            stdout_limit_bytes=64 * 1024,
            identity=identity,
        )
        self._git(
            source,
            target_repository,
            ("update-ref", reference, source.expected_head, zero),
            stdout_limit_bytes=128,
            identity=identity,
        )
        refs = self._git(
            source,
            target_repository,
            ("for-each-ref", "--format=%(refname)", "--sort=refname"),
            stdout_limit_bytes=64 * 1024,
            identity=identity,
        ).stdout
        if refs != f"{reference}\n".encode("ascii"):
            raise ArchiveContinuationError("new archive target contains unexpected references")
        head = self._git(
            source,
            target_repository,
            ("symbolic-ref", "HEAD"),
            stdout_limit_bytes=512,
            identity=identity,
        ).stdout
        if head != f"{reference}\n".encode("ascii"):
            raise ArchiveContinuationError("new archive target HEAD topology does not match")
        source_objects = self._git(
            source,
            source.repository,
            ("rev-list", "--objects", "--no-object-names", source.expected_head),
            stdout_limit_bytes=_MAX_OBJECT_CLOSURE_BYTES,
            identity=None,
        ).stdout
        target_objects = self._git(
            source,
            target_repository,
            ("rev-list", "--objects", "--no-object-names", source.expected_head),
            stdout_limit_bytes=_MAX_OBJECT_CLOSURE_BYTES,
            identity=identity,
        ).stdout
        if target_objects != source_objects:
            raise ArchiveContinuationError("new archive target object closure does not match")
        unreachable = self._git(
            source,
            target_repository,
            (
                "fsck",
                "--strict",
                "--no-reflogs",
                "--unreachable",
                "--no-dangling",
                source.expected_head,
            ),
            stdout_limit_bytes=_MAX_OBJECT_CLOSURE_BYTES,
            identity=identity,
        ).stdout
        if unreachable:
            raise ArchiveContinuationError("new archive target contains extra Git objects")
        self._revalidate_directory(target_repository, identity)
        return GitRecoverySource(
            repository=target_repository,
            branch_name=source.branch_name,
            expected_head=source.expected_head,
            git_executable=source.git_executable,
        )

    def _require_empty_bare_target(
        self,
        source: GitRecoverySource,
        target_repository: Path,
        identity: _PinnedDirectory,
    ) -> None:
        bare = self._git(
            source,
            target_repository,
            ("rev-parse", "--is-bare-repository"),
            stdout_limit_bytes=16,
            identity=identity,
        ).stdout
        if bare != b"true\n":
            raise ArchiveContinuationError("new archive target is not bare")
        refs = self._git(
            source,
            target_repository,
            ("for-each-ref", "--format=%(refname)"),
            stdout_limit_bytes=64 * 1024,
            identity=identity,
        ).stdout
        if refs:
            raise ArchiveContinuationError("new archive target is not empty")
        counts = self._git(
            source,
            target_repository,
            ("count-objects", "-v"),
            stdout_limit_bytes=4 * 1024,
            identity=identity,
        ).stdout
        try:
            values = {
                key.decode("ascii"): int(value)
                for line in counts.splitlines()
                for key, value in (line.split(b": ", 1),)
            }
        except (UnicodeDecodeError, ValueError):
            raise ArchiveContinuationError("new archive target object state is invalid") from None
        if set(values) != _COUNT_OBJECT_KEYS or any(values.values()):
            raise ArchiveContinuationError("new archive target contains Git objects")
        self._require_no_alternates(target_repository)

    @staticmethod
    def _require_safe_directory(repository: Path) -> _PinnedDirectory:
        try:
            if (
                not repository.is_absolute()
                or not repository.is_dir()
                or repository.is_symlink()
                or repository.resolve(strict=True) != repository
            ):
                raise ArchiveContinuationError("new archive target path is unsafe")
            details = repository.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_mode & 0o022
            ):
                raise ArchiveContinuationError("new archive target ownership is unsafe")
            for ancestor in repository.parents:
                ancestor_details = ancestor.stat(follow_symlinks=False)
                if not stat.S_ISDIR(ancestor_details.st_mode):
                    raise ArchiveContinuationError("new archive target ancestry is unsafe")
                if ancestor_details.st_mode & 0o022 and not (
                    ancestor_details.st_mode & stat.S_ISVTX
                ):
                    raise ArchiveContinuationError("new archive target ancestry is writable")
            return _PinnedDirectory(details.st_dev, details.st_ino, details.st_uid)
        except OSError:
            raise ArchiveContinuationError("new archive target path is unavailable") from None

    @staticmethod
    def _require_no_alternates(repository: Path) -> None:
        alternates = repository / "objects" / "info" / "alternates"
        if alternates.exists() or alternates.is_symlink():
            raise ArchiveContinuationError("new archive target has object alternates")

    @classmethod
    def _revalidate_directory(
        cls,
        repository: Path,
        identity: _PinnedDirectory,
    ) -> None:
        try:
            details = repository.stat(follow_symlinks=False)
        except OSError:
            raise ArchiveContinuationError("new archive target changed during operation") from None
        if (
            not stat.S_ISDIR(details.st_mode)
            or repository.is_symlink()
            or details.st_dev != identity.device
            or details.st_ino != identity.inode
            or details.st_uid != identity.owner
            or details.st_mode & 0o022
        ):
            raise ArchiveContinuationError("new archive target changed during operation")
        cls._require_no_alternates(repository)

    def _git(
        self,
        source: GitRecoverySource,
        target_repository: Path,
        arguments: tuple[str, ...],
        *,
        stdout_limit_bytes: int,
        identity: _PinnedDirectory | None,
    ) -> ProcessResult:
        if identity is not None:
            self._revalidate_directory(target_repository, identity)
        try:
            result = self._runner.run(
                (
                    str(source.git_executable),
                    "--no-pager",
                    "--literal-pathspecs",
                    "-C",
                    str(target_repository),
                    "-c",
                    "core.hooksPath=/dev/null",
                    *arguments,
                ),
                stdin=b"",
                environment={
                    "LC_ALL": "C",
                    "LANG": "C",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_PROTOCOL_FROM_USER": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_NO_LAZY_FETCH": "1",
                },
                timeout_seconds=120,
                stdout_limit_bytes=stdout_limit_bytes,
                stderr_limit_bytes=256 * 1024,
            )
        except GitSigningError:
            raise ArchiveContinuationError("new archive target Git operation failed") from None
        if identity is not None:
            self._revalidate_directory(target_repository, identity)
        if result.returncode != 0:
            raise ArchiveContinuationError("new archive target Git operation failed")
        return result


def copy_and_verify_new_target(
    source_archive: VerifiedArchive,
    source: GitRecoverySource,
    *,
    target_repository: Path,
    signer_epochs: tuple[ArchiveSignerEpoch, ...],
    copier: NewTargetHistoryCopier | None = None,
) -> tuple[GitRecoverySource, VerifiedArchive]:
    """Copy a pinned prefix, reverify its signatures, and prove byte equality."""

    target_source = (copier or NewTargetHistoryCopier()).copy(
        source,
        target_repository=target_repository,
    )
    candidates = ReadOnlyGitArchive(target_source).read()
    copied_archive = verify_signed_archive_epochs(candidates, signer_epochs)
    require_exact_archive_equality(source_archive, copied_archive)
    return target_source, copied_archive


async def reconstruct_new_target_checkpoint(
    source_archive: VerifiedArchive,
    copied_archive: VerifiedArchive,
    *,
    archive_target_id: str,
    reconstructor: CheckpointReconstructor,
) -> ContinuationCheckpointPlan:
    """Prove an exact copy before reconstructing its minimal final checkpoint."""

    require_exact_archive_equality(source_archive, copied_archive)
    plan = ContinuationCheckpointPlan.from_verified(
        copied_archive,
        archive_target_id=archive_target_id,
    )
    await reconstructor.reconstruct_checkpoint(plan)
    return plan


async def append_and_prove_continuation(
    before: VerifiedArchive,
    *,
    target_source: GitRecoverySource,
    signer_epochs: tuple[ArchiveSignerEpoch, ...],
    appender: NormalArchiveAppender,
) -> VerifiedArchive:
    """Invoke the normal writer once, then prove one strict first-parent append."""

    old_head = before.commits[-1].git.commit_sha
    old_high_water = before.commits[-1].batch.manifest.source_high_water_sequence
    new_head = await appender.append_once(
        expected_parent_head=old_head,
        expected_next_event_sequence=old_high_water + 1,
    )
    updated_source = GitRecoverySource(
        repository=target_source.repository,
        branch_name=target_source.branch_name,
        expected_head=new_head,
        git_executable=target_source.git_executable,
    )
    candidates = ReadOnlyGitArchive(updated_source).read()
    after = verify_signed_archive_epochs(candidates, signer_epochs)
    prove_one_normal_append(before, after)
    return after


def require_exact_archive_equality(expected: VerifiedArchive, actual: VerifiedArchive) -> None:
    """Reject any commit, tree, manifest, or file-byte difference."""

    if len(expected.commits) != len(actual.commits):
        raise ArchiveContinuationError("copied archive history does not match source")
    for left, right in zip(expected.commits, actual.commits, strict=True):
        if (
            left.git != right.git
            or left.batch.manifest_bytes != right.batch.manifest_bytes
            or left.batch.manifest_sha256 != right.batch.manifest_sha256
            or dict(left.batch.files) != dict(right.batch.files)
        ):
            raise ArchiveContinuationError("copied archive history does not match source")


def prove_one_normal_append(before: VerifiedArchive, after: VerifiedArchive) -> None:
    """Prove an unchanged prefix followed by exactly one ordinary archive batch."""

    if len(after.commits) != len(before.commits) + 1:
        raise ArchiveContinuationError("continuation did not append exactly one commit")
    prefix = VerifiedArchive(commits=after.commits[:-1])
    require_exact_archive_equality(before, prefix)
    previous = before.commits[-1]
    appended = after.commits[-1]
    previous_manifest = previous.batch.manifest
    appended_manifest = appended.batch.manifest
    if (
        appended.git.parent_sha != previous.git.commit_sha
        or appended_manifest.previous_manifest_sha256 != previous.batch.manifest_sha256
        or appended_manifest.first_event_sequence
        != previous_manifest.source_high_water_sequence + 1
    ):
        raise ArchiveContinuationError("continuation append does not extend the accepted prefix")
