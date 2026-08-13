"""Real Git and ephemeral SSH-key archive recovery acceptance."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from kivra_memory.archive.adapters import ArchivePayload, DeterministicArchiveBuilder
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitCommitVerifier,
    GitSigningConfig,
    GitVerificationConfig,
)
from kivra_memory.archive.recovery import (
    ArchiveRecoveryError,
    GitRecoveryLimits,
    GitRecoverySource,
    ReadOnlyGitArchive,
)
from kivra_memory.archive.verification import ArchiveSignerEpoch, verify_signed_archive_epochs

from tests.integration.database.test_archive_restore_acceptance import (
    _branch_event,
    _snapshot_source,
)

_ROOT = Path(__file__).resolve().parents[3]


def _run(*arguments: str, stdin: bytes = b"") -> bytes:
    completed = subprocess.run(
        arguments,
        input=stdin,
        capture_output=True,
        check=True,
        shell=False,
        env={
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        timeout=30,
    )
    return completed.stdout


def _commit_tree(
    repository: Path,
    files: dict[str, bytes],
    *,
    parent: str | None = None,
) -> str:
    entries: list[bytes] = []
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
        entries.append(f"100644 blob {blob}\t{path}\n".encode())
    tree = (
        _run(
            "/usr/bin/git",
            "-C",
            str(repository),
            "mktree",
            stdin=b"".join(entries),
        )
        .decode("ascii")
        .strip()
    )
    arguments = [
        "/usr/bin/git",
        "-C",
        str(repository),
        "-c",
        "user.name=Recovery Test",
        "-c",
        "user.email=recovery@test.invalid",
        "commit-tree",
        tree,
    ]
    if parent is not None:
        arguments.extend(("-p", parent))
    return _run(*arguments, stdin=b"test\n").decode("ascii").strip()


def test_real_signed_git_history_is_read_and_verified_without_private_key(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "archive"
    _run("/usr/bin/git", "init", "--initial-branch=main", str(repository))
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
    public_key = private_key.with_suffix(".pub").read_text().strip()
    allowed_signers = tmp_path / "allowed-signers"
    allowed_signers.write_text(f"archive@scalevault {public_key}\n")

    source = _snapshot_source(_branch_event())
    built = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="test-v1",
    ).build(source)
    assert isinstance(built.payload, ArchivePayload)
    environment = {
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    for path, content in built.payload.files.items():
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
        subprocess.run(
            (
                "/usr/bin/git",
                "-C",
                str(repository),
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{blob},{path}",
            ),
            check=True,
            capture_output=True,
            env=environment,
        )
    tree = _run("/usr/bin/git", "-C", str(repository), "write-tree").decode("ascii").strip()
    signer = GitCommitSigner(
        GitSigningConfig(
            repository=repository,
            signing_key=private_key,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        )
    )
    commit = signer.sign_commit(
        tree_sha=tree,
        parent_sha=None,
        message=built.commit_message,
        timestamp=source.export_timestamp,
    )
    _run(
        "/usr/bin/git",
        "-C",
        str(repository),
        "update-ref",
        "refs/heads/main",
        commit,
    )
    private_key.unlink()
    recovery_source = GitRecoverySource(repository, "main", commit)
    commits = ReadOnlyGitArchive(recovery_source).read()
    verifier = GitCommitVerifier(
        GitVerificationConfig(
            repository=repository,
            allowed_signers_file=allowed_signers,
            signer_principal="archive@scalevault",
            author_name="ScaleVault Archive",
            author_email="archive@scalevault.invalid",
        )
    )
    verified = verify_signed_archive_epochs(
        commits,
        (ArchiveSignerEpoch(1, None, verifier),),
    )

    assert verified.commits[-1].git.commit_sha == commit
    assert not hasattr(verifier, "sign_commit")
    assert not private_key.exists()


def test_real_git_history_and_tree_output_caps_fail_before_allocation(tmp_path: Path) -> None:
    repository = tmp_path / "bounded.git"
    _run("/usr/bin/git", "init", "--bare", str(repository))
    first = _commit_tree(repository, {"manifest.json": b"one"})
    second = _commit_tree(repository, {"manifest.json": b"two"}, parent=first)
    _run("/usr/bin/git", "-C", str(repository), "update-ref", "refs/heads/main", second)

    with pytest.raises(ArchiveRecoveryError, match="oversized"):
        ReadOnlyGitArchive(
            GitRecoverySource(repository, "main", second),
            limits=GitRecoveryLimits(max_commits=1),
        ).read()

    with pytest.raises(ArchiveRecoveryError, match="operation failed"):
        ReadOnlyGitArchive(
            GitRecoverySource(repository, "main", second),
            limits=GitRecoveryLimits(max_tree_bytes=16),
        ).read()


def test_real_git_replace_ref_is_ignored_by_recovery_reader(tmp_path: Path) -> None:
    repository = tmp_path / "replace.git"
    _run("/usr/bin/git", "init", "--bare", str(repository))
    accepted = _commit_tree(repository, {"manifest.json": b"accepted"})
    replacement = _commit_tree(repository, {"secret.txt": b"malicious"})
    _run("/usr/bin/git", "-C", str(repository), "update-ref", "refs/heads/main", accepted)
    _run(
        "/usr/bin/git",
        "-C",
        str(repository),
        "update-ref",
        f"refs/replace/{accepted}",
        replacement,
    )

    batches = ReadOnlyGitArchive(GitRecoverySource(repository, "main", accepted)).read()

    assert batches[0].batch.manifest_bytes == b"accepted"
    assert batches[0].batch.files == {}
