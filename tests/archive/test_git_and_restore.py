"""Fixed Git invocation and restore boundary tests."""

from __future__ import annotations

import hashlib
import sys
from datetime import datetime
from pathlib import Path
from typing import cast

import pytest
from kivra_memory.archive.codec import SnapshotData, SnapshotTable
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitSigningConfig,
    GitSigningError,
    ProcessResult,
    SubprocessRunner,
    VerifiedGitCommit,
    archive_commit_message,
)
from kivra_memory.archive.restore import (
    RestoreDestinationState,
    RestorePreflightError,
    build_restore_plan,
)
from kivra_memory.archive.verification import (
    VerifiedArchive,
    VerifiedArchiveBatch,
    VerifiedArchiveCommit,
)
from kivra_memory.domain.events import MemoryEvent

from .test_manifest import manifest

SHA = "a" * 40
TREE = "b" * 40
OTHER_SHA = "c" * 40
TIMESTAMP = "2026-08-09T12:30:45.123456Z"


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
        stdout_limit_bytes: int = 8 * 1024 * 1024,
        stderr_limit_bytes: int = 256 * 1024,
    ) -> ProcessResult:
        del stdout_limit_bytes, stderr_limit_bytes
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


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_subprocess_runner_kills_oversized_fake_git_output(stream: str) -> None:
    descriptor = "1" if stream == "stdout" else "2"
    command = (
        sys.executable,
        "-c",
        f"import os; os.write({descriptor}, b'x' * 131072)",
    )
    with pytest.raises(GitSigningError, match="resource limit"):
        SubprocessRunner().run(
            command,
            stdin=b"",
            environment={"LC_ALL": "C", "LANG": "C"},
            timeout_seconds=5,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )


def test_subprocess_runner_kills_and_reaps_timeout() -> None:
    with pytest.raises(GitSigningError, match="resource limit"):
        SubprocessRunner().run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            stdin=b"",
            environment={"LC_ALL": "C", "LANG": "C"},
            timeout_seconds=1,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )


def test_signer_uses_fixed_argv_stdin_and_isolated_environment() -> None:
    runner = RecordingRunner([ProcessResult(0, stdout=(SHA + "\n").encode())])

    assert (
        signer(runner).sign_commit(
            tree_sha=TREE,
            parent_sha=SHA,
            message=archive_commit_message(1, 2),
            timestamp=TIMESTAMP,
        )
        == SHA
    )

    arguments, stdin, environment, timeout = runner.calls[0]
    assert arguments[0] == "/usr/bin/git"
    assert arguments[-5:] == ("-p", SHA, "-S/run/credentials/archive.key", "-F", "-")
    assert stdin == b"memory-export: events 1..2\n"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_AUTHOR_DATE"] == TIMESTAMP
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

    prefix = b'Good "git" signature for archive@scalevault.evil with ED25519 key SHA256:test\n'
    runner = RecordingRunner([ProcessResult(0, stderr=prefix)])
    with pytest.raises(GitSigningError, match="identity"):
        signer(runner).verify_commit(SHA)


def _raw_commit(
    *,
    parent: str | None = None,
    message: bytes = b"memory-export: events 1..1\n",
) -> bytes:
    epoch = int(datetime.fromisoformat(TIMESTAMP.replace("Z", "+00:00")).timestamp())
    parent_header = b"" if parent is None else f"parent {parent}\n".encode()
    identity = f"ScaleVault Archive <archive@scalevault.invalid> {epoch} +0000".encode()
    return b"".join(
        (
            f"tree {TREE}\n".encode(),
            parent_header,
            b"author " + identity + b"\n",
            b"committer " + identity + b"\n",
            b"gpgsig -----BEGIN SSH SIGNATURE-----\n",
            b" fake\n",
            b" -----END SSH SIGNATURE-----\n",
            b"\n" + message,
        )
    )


def _blob_entry(path: str, content: bytes) -> bytes:
    digest = hashlib.sha1(
        b"blob " + str(len(content)).encode() + b"\0" + content,
        usedforsecurity=False,
    ).hexdigest()
    return f"100644 blob {digest}\t{path}\0".encode()


def _tree_output(files: dict[str, bytes]) -> bytes:
    return b"".join(_blob_entry(path, content) for path, content in sorted(files.items()))


def test_archive_commit_verification_rejects_unsigned_and_forged_chain() -> None:
    unsigned = RecordingRunner([ProcessResult(1)])
    with pytest.raises(GitSigningError, match="signature verification"):
        signer(unsigned).verify_archive_commit(
            SHA,
            expected_parent_sha=None,
            expected_message="memory-export: events 1..1\n",
            expected_timestamp=TIMESTAMP,
            expected_files={"manifest.json": b"{}"},
        )

    good_signature = b'Good "git" signature for archive@scalevault with ED25519 key SHA256:test\n'
    forged = RecordingRunner(
        [
            ProcessResult(0, stderr=good_signature),
            ProcessResult(0, stdout=_raw_commit(parent=OTHER_SHA)),
        ]
    )
    with pytest.raises(GitSigningError, match="first-parent"):
        signer(forged).verify_archive_commit(
            SHA,
            expected_parent_sha=None,
            expected_message="memory-export: events 1..1\n",
            expected_timestamp=TIMESTAMP,
            expected_files={"manifest.json": b"{}"},
        )


def test_archive_commit_verification_binds_exact_batch_blob() -> None:
    signature = b'Good "git" signature for archive@scalevault with ED25519 key SHA256:test\n'
    runner = RecordingRunner(
        [
            ProcessResult(0, stderr=signature),
            ProcessResult(0, stdout=_raw_commit()),
            ProcessResult(0, stdout=_tree_output({"manifest.json": b"forged"})),
        ]
    )
    with pytest.raises(GitSigningError, match="batch bytes"):
        signer(runner).verify_archive_commit(
            SHA,
            expected_parent_sha=None,
            expected_message="memory-export: events 1..1\n",
            expected_timestamp=TIMESTAMP,
            expected_files={"manifest.json": b"{}"},
        )


def test_archive_commit_verification_accepts_exact_signed_identity() -> None:
    signature = b'Good "git" signature for archive@scalevault with ED25519 key SHA256:test\n'
    manifest_bytes = b"{}"
    runner = RecordingRunner(
        [
            ProcessResult(0, stderr=signature),
            ProcessResult(0, stdout=_raw_commit()),
            ProcessResult(0, stdout=_tree_output({"manifest.json": manifest_bytes})),
        ]
    )

    verified = signer(runner).verify_archive_commit(
        SHA,
        expected_parent_sha=None,
        expected_message="memory-export: events 1..1\n",
        expected_timestamp=TIMESTAMP,
        expected_files={"manifest.json": manifest_bytes},
    )

    assert verified == VerifiedGitCommit(commit_sha=SHA, tree_sha=TREE, parent_sha=None)


def test_archive_commit_chain_accepts_exact_second_batch_tree_with_prior_files_removed() -> None:
    signature = b'Good "git" signature for archive@scalevault with ED25519 key SHA256:test\n'
    first_files = {
        "events/first.json": b"first",
        "manifest.json": b"manifest-one",
    }
    second_files = {
        "events/second.json": b"second",
        "manifest.json": b"manifest-two",
    }
    runner = RecordingRunner(
        [
            ProcessResult(0, stderr=signature),
            ProcessResult(0, stdout=_raw_commit()),
            ProcessResult(0, stdout=_tree_output(first_files)),
            ProcessResult(0, stderr=signature),
            ProcessResult(
                0,
                stdout=_raw_commit(
                    parent=SHA,
                    message=b"memory-export: events 2..2\n",
                ),
            ),
            ProcessResult(0, stdout=_tree_output(second_files)),
        ]
    )
    verifier = signer(runner)

    first = verifier.verify_archive_commit(
        SHA,
        expected_parent_sha=None,
        expected_message="memory-export: events 1..1\n",
        expected_timestamp=TIMESTAMP,
        expected_files=first_files,
    )
    second = verifier.verify_archive_commit(
        OTHER_SHA,
        expected_parent_sha=SHA,
        expected_message="memory-export: events 2..2\n",
        expected_timestamp=TIMESTAMP,
        expected_files=second_files,
    )

    assert first.parent_sha is None
    assert second.parent_sha == SHA
    assert "events/first.json" not in second_files


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

    archive = VerifiedArchive(
        commits=(
            VerifiedArchiveCommit(
                git=VerifiedGitCommit(commit_sha=SHA, tree_sha=TREE, parent_sha=None),
                batch=first,
            ),
            VerifiedArchiveCommit(
                git=VerifiedGitCommit(commit_sha=OTHER_SHA, tree_sha=TREE, parent_sha=SHA),
                batch=second,
            ),
        )
    )
    plan = build_restore_plan(archive)

    assert plan.snapshot_high_water_sequence == 2
    assert [event.sequence for event in plan.events_to_replay] == [3, 4]
    assert plan.final_high_water_sequence == 4

    with pytest.raises(RestorePreflightError, match="signed verified archive"):
        build_restore_plan(cast(VerifiedArchive, (first, second)))
