"""Fixed Git invocation and restore boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from kivra_memory.archive.codec import SnapshotData, SnapshotTable
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitSigningConfig,
    GitSigningError,
    ProcessResult,
    archive_commit_message,
)
from kivra_memory.archive.restore import (
    RestoreDestinationState,
    RestorePreflightError,
    build_restore_plan,
)
from kivra_memory.archive.verification import VerifiedArchiveBatch
from kivra_memory.domain.events import MemoryEvent

from .test_manifest import manifest

SHA = "a" * 40
TREE = "b" * 40


class RecordingRunner:
    def __init__(self, results: list[ProcessResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], bytes, dict[str, str], int]] = []

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        self.calls.append((arguments, stdin, environment, timeout_seconds))
        return self.results.pop(0)


def signer(runner: RecordingRunner) -> GitCommitSigner:
    return GitCommitSigner(
        GitSigningConfig(
            repository=Path("/archive"),
            signing_key=Path("/run/credentials/archive.key"),
            allowed_signers_file=Path("/etc/scalevault/allowed_signers"),
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        ),
        runner,
    )


def test_signer_uses_fixed_argv_stdin_and_isolated_environment() -> None:
    runner = RecordingRunner([ProcessResult(0, stdout=(SHA + "\n").encode())])
    timestamp = "2026-08-09T12:30:45.123456Z"

    assert (
        signer(runner).sign_commit(
            tree_sha=TREE,
            parent_sha=SHA,
            message=archive_commit_message(1, 2),
            timestamp=timestamp,
        )
        == SHA
    )

    arguments, stdin, environment, timeout = runner.calls[0]
    assert arguments[0] == "/usr/bin/git"
    assert arguments[-5:] == ("-p", SHA, "-S/run/credentials/archive.key", "-F", "-")
    assert stdin == b"memory-export: events 1..2\n"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_AUTHOR_DATE"] == timestamp
    assert "HOME" not in environment and "SSH_AUTH_SOCK" not in environment
    assert timeout == 30


def test_signature_verification_requires_pinned_signer_identity() -> None:
    good = b'Good "git" signature for archive@scalevault with ED25519 key SHA256:test\n'
    runner = RecordingRunner([ProcessResult(0, stderr=good)])
    signer(runner).verify_commit(SHA)
    assert "gpg.ssh.allowedSignersFile=/etc/scalevault/allowed_signers" in runner.calls[0][0]

    runner = RecordingRunner([ProcessResult(0, stderr=b'Good "git" signature for other')])
    with pytest.raises(GitSigningError, match="identity"):
        signer(runner).verify_commit(SHA)


@pytest.mark.parametrize("dirty", ["rows", "workers", "transaction", "live"])
def test_restore_destination_rejects_dirty_or_live_targets(dirty: str) -> None:
    state = RestoreDestinationState(
        migrations_current=True,
        canonical_row_count=1 if dirty == "rows" else 0,
        active_worker_count=1 if dirty == "workers" else 0,
        is_disposable_recovery_database=dirty != "live",
        has_pending_transaction=dirty == "transaction",
    )
    with pytest.raises(RestorePreflightError):
        state.require_safe()


def test_restore_plan_uses_latest_snapshot_and_only_later_events() -> None:
    first_manifest = manifest(1, 2)
    second_manifest = manifest(3, 4, first_manifest.sha256)
    events = tuple(MemoryEvent.model_construct(sequence=sequence) for sequence in range(1, 5))
    older = SnapshotData(
        high_water_sequence=2,
        tables=(SnapshotTable(name="memory_events", primary_key=("sequence",), rows=()),),
    )
    first = VerifiedArchiveBatch(
        manifest=first_manifest,
        manifest_bytes=first_manifest.canonical_bytes,
        manifest_sha256=first_manifest.sha256,
        files={},
        events=events[:2],
        snapshot=older,
    )
    second = VerifiedArchiveBatch(
        manifest=second_manifest,
        manifest_bytes=second_manifest.canonical_bytes,
        manifest_sha256=second_manifest.sha256,
        files={},
        events=events[2:],
        snapshot=None,
    )

    plan = build_restore_plan((first, second))

    assert plan.snapshot_high_water_sequence == 2
    assert [event.sequence for event in plan.events_to_replay] == [3, 4]
    assert plan.final_high_water_sequence == 4
