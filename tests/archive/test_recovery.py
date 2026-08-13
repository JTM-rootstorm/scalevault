"""Read-only Git archive recovery and external signer epoch tests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from kivra_memory.archive.git import ProcessResult, VerifiedGitCommit
from kivra_memory.archive.recovery import (
    ArchiveRecoveryError,
    GitRecoveryLimits,
    GitRecoverySource,
    ReadOnlyGitArchive,
)
from kivra_memory.archive.verification import (
    ArchiveBatch,
    ArchiveCommitBatch,
    ArchiveSignerEpoch,
    ArchiveVerificationError,
    VerifiedArchiveBatch,
    parse_manifest,
    verify_signed_archive_epochs,
)

from .test_manifest import SCHEMA_BYTES, SCHEMA_PATH, event_path, manifest

SHA = "a" * 40
OTHER_SHA = "b" * 40


class RecordingRunner:
    def __init__(self, results: list[ProcessResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
        stdout_limit_bytes: int = 8 * 1024 * 1024,
        stderr_limit_bytes: int = 256 * 1024,
    ) -> ProcessResult:
        assert stdin == b""
        assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_NO_LAZY_FETCH"] == "1"
        assert timeout_seconds == 60
        assert stdout_limit_bytes > 0
        assert stderr_limit_bytes > 0
        self.calls.append(arguments)
        return self.results.pop(0)


def _tree_entry(path: str, object_id: str, size: int) -> bytes:
    return f"100644 blob {object_id} {size}\t{path}\0".encode()


def test_read_only_adapter_pins_head_and_reads_exact_blobs(tmp_path: Path) -> None:
    repository = tmp_path / "archive.git"
    repository.mkdir()
    manifest_bytes = b"manifest"
    event_bytes = b"event"
    runner = RecordingRunner(
        [
            ProcessResult(0, b"true\n"),
            ProcessResult(0, f"{SHA}\n".encode()),
            ProcessResult(0, f"{SHA}\n".encode()),
            ProcessResult(
                0,
                _tree_entry("manifest.json", OTHER_SHA, len(manifest_bytes))
                + _tree_entry(event_path(1), "c" * 40, len(event_bytes)),
            ),
            ProcessResult(0, manifest_bytes),
            ProcessResult(0, event_bytes),
        ]
    )

    batches = ReadOnlyGitArchive(
        GitRecoverySource(repository=repository, branch_name="main", expected_head=SHA),
        runner=runner,
    ).read()

    assert batches == (
        ArchiveCommitBatch(
            commit_sha=SHA,
            batch=ArchiveBatch(
                manifest_bytes=manifest_bytes,
                files={event_path(1): event_bytes},
            ),
        ),
    )
    arguments = [argument for call in runner.calls for argument in call]
    assert "update-ref" not in arguments
    assert "checkout" not in arguments
    assert "push" not in arguments


def test_read_only_adapter_rejects_rollback_oversize_and_extra_path(tmp_path: Path) -> None:
    repository = tmp_path / "archive.git"
    repository.mkdir()
    rolled_back = RecordingRunner(
        [ProcessResult(0, b"true\n"), ProcessResult(0, f"{OTHER_SHA}\n".encode())]
    )
    reader = ReadOnlyGitArchive(
        GitRecoverySource(repository=repository, branch_name="main", expected_head=SHA),
        runner=rolled_back,
    )
    with pytest.raises(ArchiveRecoveryError, match="external anchor"):
        reader.read()

    oversized = RecordingRunner(
        [
            ProcessResult(0, b"true\n"),
            ProcessResult(0, f"{SHA}\n".encode()),
            ProcessResult(0, f"{SHA}\n{OTHER_SHA}\n".encode()),
        ]
    )
    reader = ReadOnlyGitArchive(
        GitRecoverySource(repository=repository, branch_name="main", expected_head=SHA),
        limits=GitRecoveryLimits(max_commits=1),
        runner=oversized,
    )
    with pytest.raises(ArchiveRecoveryError, match="oversized"):
        reader.read()

    bad_path = RecordingRunner(
        [
            ProcessResult(0, b"true\n"),
            ProcessResult(0, f"{SHA}\n".encode()),
            ProcessResult(0, f"{SHA}\n".encode()),
            ProcessResult(0, _tree_entry("secret.txt", OTHER_SHA, 1)),
        ]
    )
    reader = ReadOnlyGitArchive(
        GitRecoverySource(repository=repository, branch_name="main", expected_head=SHA),
        runner=bad_path,
    )
    with pytest.raises(ArchiveRecoveryError, match="closed layout"):
        reader.read()


class EpochVerifier:
    def __init__(self, expected: tuple[str, ...]) -> None:
        self.expected = list(expected)

    def verify_archive_commit(
        self,
        commit_sha: str,
        *,
        expected_parent_sha: str | None,
        expected_message: str,
        expected_timestamp: str,
        expected_files: Mapping[str, bytes],
    ) -> VerifiedGitCommit:
        del expected_message, expected_timestamp, expected_files
        assert commit_sha == self.expected.pop(0)
        return VerifiedGitCommit(commit_sha, "c" * 40, expected_parent_sha)


def _batch(first: int, last: int, previous: str | None = None) -> ArchiveBatch:
    item = manifest(first, last, previous)
    files = {SCHEMA_PATH: SCHEMA_BYTES}
    files.update((event_path(sequence), b"{}") for sequence in range(first, last + 1))
    return ArchiveBatch(manifest_bytes=item.canonical_bytes, files=files)


def test_signer_epochs_apply_exact_bounded_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    first = _batch(1, 1)
    first_manifest = manifest(1, 1)
    second = _batch(2, 2, first_manifest.sha256)

    def verified(batch: ArchiveBatch, **kwargs: object) -> VerifiedArchiveBatch:
        del kwargs
        item = parse_manifest(batch.manifest_bytes)
        return VerifiedArchiveBatch(
            manifest=item,
            manifest_bytes=item.canonical_bytes,
            manifest_sha256=item.sha256,
            files=batch.files,
            events=(),
            snapshot=None,
        )

    monkeypatch.setattr(
        "kivra_memory.archive.verification.verify_archive_batch",
        verified,
    )
    archive = verify_signed_archive_epochs(
        (
            ArchiveCommitBatch(SHA, first),
            ArchiveCommitBatch(OTHER_SHA, second),
        ),
        (
            ArchiveSignerEpoch(1, 1, EpochVerifier((SHA,))),
            ArchiveSignerEpoch(2, None, EpochVerifier((OTHER_SHA,))),
        ),
    )
    assert archive.commits[-1].git.commit_sha == OTHER_SHA

    with pytest.raises(ArchiveVerificationError, match="crosses or misses"):
        verify_signed_archive_epochs(
            (ArchiveCommitBatch(SHA, _batch(1, 2)),),
            (
                ArchiveSignerEpoch(1, 1, EpochVerifier((SHA,))),
                ArchiveSignerEpoch(2, None, EpochVerifier((SHA,))),
            ),
        )

    with pytest.raises(ArchiveVerificationError, match="beyond its compromise cutoff"):
        verify_signed_archive_epochs(
            (
                ArchiveCommitBatch(SHA, first),
                ArchiveCommitBatch(OTHER_SHA, second),
            ),
            (
                ArchiveSignerEpoch(
                    1,
                    None,
                    EpochVerifier((SHA,)),
                    epoch_id="compromised",
                    compromised_last_commit=SHA,
                    compromised_last_event_sequence=1,
                ),
            ),
        )

    with pytest.raises(ArchiveVerificationError, match="cutoff commit does not match"):
        verify_signed_archive_epochs(
            (ArchiveCommitBatch(SHA, first),),
            (
                ArchiveSignerEpoch(
                    1,
                    None,
                    EpochVerifier(()),
                    epoch_id="compromised",
                    compromised_last_commit=OTHER_SHA,
                    compromised_last_event_sequence=1,
                ),
            ),
        )

    with pytest.raises(ArchiveVerificationError, match="cutoff anchor is absent"):
        verify_signed_archive_epochs(
            (ArchiveCommitBatch(SHA, first),),
            (
                ArchiveSignerEpoch(
                    1,
                    None,
                    EpochVerifier((SHA,)),
                    epoch_id="compromised",
                    compromised_last_commit=OTHER_SHA,
                    compromised_last_event_sequence=2,
                ),
            ),
        )
