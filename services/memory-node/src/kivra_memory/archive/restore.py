"""Zero-write restore preflight and immutable recovery-plan construction."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from kivra_memory.archive.codec import SnapshotData, SnapshotLimits, SnapshotTable
from kivra_memory.archive.verification import (
    ArchiveCommitBatch,
    ArchiveCommitVerifier,
    ArchiveVerificationError,
    VerifiedArchive,
    verify_manifest_chain,
    verify_signed_archive,
)
from kivra_memory.domain.events import MemoryEvent


class RestorePreflightError(ValueError):
    """Raised before database work when an archive or destination is unsafe."""


@dataclass(frozen=True, slots=True)
class RestoreDestinationState:
    """Content-free database state sampled before restore begins."""

    migrations_current: bool
    canonical_row_count: int
    active_worker_count: int
    is_disposable_recovery_database: bool
    has_pending_transaction: bool = False
    is_freshly_created: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.canonical_row_count, bool) or self.canonical_row_count < 0:
            raise ValueError("canonical row count must be non-negative")
        if isinstance(self.active_worker_count, bool) or self.active_worker_count < 0:
            raise ValueError("active worker count must be non-negative")

    def require_safe(self) -> None:
        """Fail closed unless the destination is migrated, isolated, and empty."""

        if not self.migrations_current:
            raise RestorePreflightError("restore destination migrations are not current")
        if self.canonical_row_count != 0:
            raise RestorePreflightError("restore destination is not empty")
        if self.active_worker_count != 0:
            raise RestorePreflightError("restore destination has active workers")
        if self.has_pending_transaction:
            raise RestorePreflightError("restore destination already has a transaction")
        if not (self.is_freshly_created or self.is_disposable_recovery_database):
            raise RestorePreflightError("restore destination is neither fresh nor disposable")


@dataclass(frozen=True, slots=True)
class RestorePlan:
    """Fully validated snapshot rows and later events in fixed recovery order."""

    manifest_sha256s: tuple[str, ...]
    snapshot_high_water_sequence: int
    snapshot_tables: tuple[SnapshotTable, ...]
    events_to_replay: tuple[MemoryEvent, ...]
    final_high_water_sequence: int

    def __post_init__(self) -> None:
        if not self.manifest_sha256s:
            raise ValueError("restore plan must cite at least one manifest")
        if not 0 <= self.snapshot_high_water_sequence <= self.final_high_water_sequence:
            raise ValueError("restore plan snapshot boundary is invalid")
        expected = self.snapshot_high_water_sequence + 1
        for event in self.events_to_replay:
            if event.sequence != expected:
                raise ValueError("restore plan events are not gap-free after the snapshot")
            expected += 1
        if expected - 1 != self.final_high_water_sequence:
            raise ValueError("restore plan does not reach the final high-water sequence")


def preflight_restore(
    commits: Sequence[ArchiveCommitBatch],
    destination: RestoreDestinationState,
    *,
    signer: ArchiveCommitVerifier,
    snapshot_limits: SnapshotLimits | None = None,
) -> RestorePlan:
    """Verify signed Git history, all bytes, and destination before a transaction."""

    destination.require_safe()
    try:
        verified = verify_signed_archive(
            commits,
            signer,
            snapshot_limits=snapshot_limits,
        )
        return build_restore_plan(verified)
    except ArchiveVerificationError:
        raise RestorePreflightError("archive restore input failed verification") from None


def build_restore_plan(archive: VerifiedArchive) -> RestorePlan:
    """Select the latest validated snapshot and only the events that follow it."""

    if not isinstance(archive, VerifiedArchive):
        raise RestorePreflightError("restore planning requires a signed verified archive")
    batches = archive.batches
    if not batches:
        raise RestorePreflightError("archive restore input is empty")
    verify_manifest_chain(batches)
    snapshots = [
        (batch.snapshot.high_water_sequence, batch.snapshot)
        for batch in batches
        if batch.snapshot is not None
    ]
    if not snapshots:
        raise RestorePreflightError("archive chain contains no recovery snapshot")
    snapshot_high_water, snapshot = max(snapshots, key=lambda item: item[0])
    final_high_water = batches[-1].manifest.source_high_water_sequence
    if snapshot_high_water > final_high_water:
        raise RestorePreflightError("archive snapshot is beyond the final event prefix")
    all_events = tuple(event for batch in batches for event in batch.events)
    if snapshot_high_water and not any(
        event.sequence == snapshot_high_water for event in all_events
    ):
        raise RestorePreflightError("snapshot boundary is not present in the event chain")
    later_events = tuple(event for event in all_events if event.sequence > snapshot_high_water)
    assert isinstance(snapshot, SnapshotData)
    try:
        return RestorePlan(
            manifest_sha256s=tuple(batch.manifest_sha256 for batch in batches),
            snapshot_high_water_sequence=snapshot_high_water,
            snapshot_tables=snapshot.tables,
            events_to_replay=later_events,
            final_high_water_sequence=final_high_water,
        )
    except ValueError:
        raise RestorePreflightError("archive snapshot and event boundary is inconsistent") from None
