"""Real local Git acceptance for pinned new-target history copying."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from kivra_memory.archive.adapters import ArchivePayload, DeterministicArchiveBuilder
from kivra_memory.archive.continuation import (
    ArchiveContinuationError,
    NewTargetHistoryCopier,
    append_and_prove_continuation,
    copy_and_verify_new_target,
)
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitCommitVerifier,
    GitSigningConfig,
    GitVerificationConfig,
    archive_commit_message,
)
from kivra_memory.archive.models import MANIFEST_PATH
from kivra_memory.archive.recovery import GitRecoverySource, ReadOnlyGitArchive
from kivra_memory.archive.verification import ArchiveSignerEpoch, verify_signed_archive_epochs

from tests.integration.database.test_archive_restore_acceptance import (
    _branch_event,
    _later_event_batch,
    _memory_state,
    _remembered_event,
    _snapshot_source,
)

_ROOT = Path(__file__).resolve().parents[3]


def _run(
    *arguments: str,
    stdin: bytes = b"",
    extra_environment: dict[str, str] | None = None,
) -> bytes:
    environment = {
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }
    environment.update(extra_environment or {})
    return subprocess.run(
        arguments,
        input=stdin,
        capture_output=True,
        check=True,
        shell=False,
        env=environment,
        timeout=30,
    ).stdout


def _bare_history(repository: Path) -> str:
    _run("/usr/bin/git", "init", "--bare", "--initial-branch=main", str(repository))
    blob = (
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "hash-object",
            "-w",
            "--stdin",
            stdin=b"accepted archive bytes",
        )
        .decode("ascii")
        .strip()
    )
    tree = (
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "mktree",
            stdin=f"100644 blob {blob}\tmanifest.json\n".encode("ascii"),
        )
        .decode("ascii")
        .strip()
    )
    commit = (
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "-c",
            "user.name=Continuation Test",
            "-c",
            "user.email=continuation@test.invalid",
            "commit-tree",
            tree,
            stdin=b"accepted\n",
        )
        .decode("ascii")
        .strip()
    )
    _run(
        "/usr/bin/git",
        "-C",
        str(repository),
        "update-ref",
        "refs/heads/main",
        commit,
    )
    return commit


def _tree(repository: Path, files: dict[str, bytes], index: Path) -> str:
    environment = {"GIT_INDEX_FILE": str(index)}
    _run(
        "/usr/bin/git",
        "-C",
        str(repository),
        "read-tree",
        "--empty",
        extra_environment=environment,
    )
    for path, content in sorted(files.items()):
        blob = (
            _run(
                "/usr/bin/git",
                "-C",
                str(repository),
                "hash-object",
                "-w",
                "--stdin",
                stdin=content,
            )
            .decode("ascii")
            .strip()
        )
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "update-index",
            "--add",
            "--cacheinfo",
            f"100644,{blob},{path}",
            extra_environment=environment,
        )
    return (
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "write-tree",
            extra_environment=environment,
        )
        .decode("ascii")
        .strip()
    )


class _RealNormalAppender:
    def __init__(
        self,
        repository: Path,
        signer: GitCommitSigner,
        files: dict[str, bytes],
        *,
        timestamp: str,
    ) -> None:
        self.repository = repository
        self.signer = signer
        self.files = files
        self.timestamp = timestamp

    async def append_once(
        self,
        *,
        expected_parent_head: str,
        expected_next_event_sequence: int,
    ) -> str:
        tree = _tree(self.repository, self.files, self.repository.parent / "append.index")
        head = self.signer.sign_commit(
            tree_sha=tree,
            parent_sha=expected_parent_head,
            message=archive_commit_message(
                expected_next_event_sequence,
                expected_next_event_sequence,
            ),
            timestamp=self.timestamp,
        )
        _run(
            "/usr/bin/git",
            "-C",
            str(self.repository),
            "update-ref",
            "refs/heads/main",
            head,
            expected_parent_head,
        )
        return head


def test_pinned_history_is_copied_only_to_a_new_empty_bare_target(tmp_path: Path) -> None:
    source_repository = tmp_path / "source.git"
    target_repository = tmp_path / "target.git"
    head = _bare_history(source_repository)
    _run("/usr/bin/git", "init", "--bare", "--initial-branch=main", str(target_repository))
    source = GitRecoverySource(source_repository, "main", head)

    copied = NewTargetHistoryCopier().copy(source, target_repository=target_repository)

    assert copied.expected_head == head
    assert (
        _run("/usr/bin/git", "-C", str(target_repository), "rev-parse", "refs/heads/main")
        .decode("ascii")
        .strip()
        == head
    )
    source_objects = _run(
        "/usr/bin/git", "-C", str(source_repository), "rev-list", "--objects", head
    )
    target_objects = _run(
        "/usr/bin/git", "-C", str(target_repository), "rev-list", "--objects", head
    )
    assert target_objects == source_objects

    with pytest.raises(ArchiveContinuationError, match="not empty"):
        NewTargetHistoryCopier().copy(source, target_repository=target_repository)


@pytest.mark.asyncio
async def test_real_signed_copy_reverify_and_one_normal_append(tmp_path: Path) -> None:
    source_repository = tmp_path / "signed-source.git"
    target_repository = tmp_path / "signed-target.git"
    _run("/usr/bin/git", "init", "--bare", "--initial-branch=main", str(source_repository))
    _run("/usr/bin/git", "init", "--bare", "--initial-branch=main", str(target_repository))
    private_key = tmp_path / "signing-key"
    _run(
        "/usr/bin/ssh-keygen",
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        str(private_key),
    )
    public_key = private_key.with_suffix(".pub")
    allowed_signers = tmp_path / "allowed-signers"
    allowed_signers.write_text(f"archive@scalevault {public_key.read_text().strip()}\n")
    fingerprint = (
        _run("/usr/bin/ssh-keygen", "-E", "sha256", "-lf", str(public_key))
        .decode("ascii")
        .split()[1]
    )
    first_source = _snapshot_source(_branch_event())
    first = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="test-v1",
    ).build(first_source)
    assert isinstance(first.payload, ArchivePayload)
    source_signer = GitCommitSigner(
        GitSigningConfig(
            repository=source_repository,
            signing_key=private_key,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        )
    )
    first_tree = _tree(
        source_repository,
        dict(first.payload.files),
        tmp_path / "source.index",
    )
    first_head = source_signer.sign_commit(
        tree_sha=first_tree,
        parent_sha=None,
        message=first.commit_message,
        timestamp=first_source.export_timestamp,
    )
    _run(
        "/usr/bin/git",
        "-C",
        str(source_repository),
        "update-ref",
        "refs/heads/main",
        first_head,
    )
    source = GitRecoverySource(source_repository, "main", first_head)
    verifier = GitCommitVerifier(
        GitVerificationConfig(
            repository=source_repository,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
            expected_key_fingerprint=fingerprint,
        )
    )
    epoch = ArchiveSignerEpoch(
        1,
        None,
        verifier,
        epoch_id="epoch-1",
        public_key_fingerprint=fingerprint,
    )
    source_archive = verify_signed_archive_epochs(ReadOnlyGitArchive(source).read(), (epoch,))
    target_epoch = ArchiveSignerEpoch(
        1,
        None,
        GitCommitVerifier(
            GitVerificationConfig(
                repository=target_repository,
                allowed_signers_file=allowed_signers,
                signer_principal="archive@scalevault",
                author_name="ScaleVault Archive",
                author_email="archive@scalevault.invalid",
                expected_key_fingerprint=fingerprint,
            )
        ),
        epoch_id="epoch-1",
        public_key_fingerprint=fingerprint,
    )
    target_source, copied = copy_and_verify_new_target(
        source_archive,
        source,
        target_repository=target_repository,
        signer_epochs=(target_epoch,),
    )
    second_event = _remembered_event(_memory_state())
    second = _later_event_batch(
        first_files=first.payload.files,
        first_manifest_sha256=copied.commits[-1].batch.manifest_sha256,
        event=second_event,
    )
    target_signer = GitCommitSigner(
        GitSigningConfig(
            repository=target_repository,
            signing_key=private_key,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        )
    )
    appended = await append_and_prove_continuation(
        copied,
        target_source=target_source,
        signer_epochs=(target_epoch,),
        appender=_RealNormalAppender(
            target_repository,
            target_signer,
            {MANIFEST_PATH: second.manifest_bytes, **second.files},
            timestamp=second_event.created_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
        ),
    )
    assert len(appended.commits) == 2
    assert appended.commits[-1].git.parent_sha == first_head
