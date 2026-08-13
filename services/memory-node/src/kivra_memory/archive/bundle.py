"""Encrypted full-history Git bundle creation and recovery helpers."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from kivra_memory.archive.git import (
    GitSigningError,
    ProcessResult,
    ProcessRunner,
    SubprocessRunner,
)
from kivra_memory.archive.recovery import GitRecoverySource, ReadOnlyGitArchive
from kivra_memory.archive.verification import ArchiveSignerEpoch, verify_signed_archive_epochs

_AGE_RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{40,100}")
_MAX_CIPHERTEXT_SIZE = 32 * 1024 * 1024 * 1024


class ArchiveBundleError(RuntimeError):
    """Content-free encrypted secondary-bundle failure."""


@dataclass(frozen=True, slots=True)
class ArchiveBundleResult:
    """Content-free immutable identity of a published encrypted bundle."""

    source_head: str
    plaintext_sha256: str = field(repr=False)
    ciphertext_sha256: str
    ciphertext_size: int


@dataclass(frozen=True, slots=True)
class BundleToolConfig:
    """External tools used without shells, ambient configuration, or secrets."""

    git_executable: Path = Path("/usr/bin/git")
    age_executable: Path = Path("/usr/bin/age")
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if not self.git_executable.is_absolute() or not self.age_executable.is_absolute():
            raise ValueError("bundle tool paths must be absolute")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 1800:
            raise ValueError("bundle tool timeout is outside the accepted range")


class EncryptedArchiveBundle:
    """Replicate verified history without authoring any archive commit or ref."""

    def __init__(
        self,
        config: BundleToolConfig | None = None,
        *,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._config = config or BundleToolConfig()
        self._runner = runner or SubprocessRunner()

    def create(
        self,
        *,
        source: GitRecoverySource,
        destination: Path,
        scratch_directory: Path,
        recipient: str,
        signer_epochs: tuple[ArchiveSignerEpoch, ...],
    ) -> ArchiveBundleResult:
        """Create, verify, encrypt, and atomically publish one accepted history."""

        if _AGE_RECIPIENT.fullmatch(recipient) is None:
            raise ArchiveBundleError("archive bundle recipient is invalid")
        _require_safe_directory(scratch_directory)
        _require_new_output(destination)

        # This structural read pins the branch to its external head and applies
        # history/object/path bounds before Git is allowed to create the bundle.
        commits = ReadOnlyGitArchive(source).read()
        verify_signed_archive_epochs(commits, signer_epochs)
        reference = f"refs/heads/{source.branch_name}"
        with tempfile.TemporaryDirectory(
            prefix="scalevault-archive-bundle-",
            dir=scratch_directory,
        ) as temporary_name:
            temporary = Path(temporary_name)
            os.chmod(temporary, 0o700)
            staging_repository = temporary / "staging.git"
            plaintext = temporary / "archive.bundle"
            ciphertext = temporary / "archive.bundle.age"
            self._run(
                (
                    str(self._config.git_executable),
                    "--no-pager",
                    "-c",
                    "init.templateDir=/dev/null",
                    "init",
                    "--bare",
                    str(staging_repository),
                )
            )
            self._git(
                staging_repository,
                (
                    "fetch",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--",
                    str(source.repository),
                    source.expected_head,
                ),
            )
            fetched = (
                self._git(
                    staging_repository,
                    ("rev-parse", "--verify", f"{source.expected_head}^{{commit}}"),
                )
                .stdout.decode("ascii")
                .strip()
            )
            if fetched != source.expected_head:
                raise ArchiveBundleError("archive bundle exact head fetch failed")
            self._git(
                staging_repository,
                ("update-ref", reference, source.expected_head),
            )
            self._git(
                staging_repository,
                ("bundle", "create", str(plaintext), reference),
            )
            self._git(staging_repository, ("bundle", "verify", str(plaintext)))
            self._require_bundle_head(staging_repository, plaintext, source)
            plaintext_digest, _ = _hash_regular_file(plaintext)
            self._run(
                (
                    str(self._config.age_executable),
                    "--encrypt",
                    "--recipient",
                    recipient,
                    "--output",
                    str(ciphertext),
                    str(plaintext),
                )
            )
            ciphertext_digest, ciphertext_size = _hash_regular_file(ciphertext)
            _publish_new_file(
                ciphertext,
                destination,
                expected_sha256=ciphertext_digest,
                expected_size=ciphertext_size,
            )
        return ArchiveBundleResult(
            source_head=source.expected_head,
            plaintext_sha256=plaintext_digest,
            ciphertext_sha256=ciphertext_digest,
            ciphertext_size=ciphertext_size,
        )

    def materialize(
        self,
        *,
        encrypted_bundle: Path,
        expected_ciphertext_sha256: str,
        identity_file: Path,
        output_repository: Path,
        scratch_directory: Path,
        branch_name: str,
        expected_head: str,
        signer_epochs_for_repository: Callable[[Path], tuple[ArchiveSignerEpoch, ...]],
    ) -> GitRecoverySource:
        """Decrypt a bundle with separately supplied identity and clone exact history."""

        if re.fullmatch(r"[0-9a-f]{64}", expected_ciphertext_sha256) is None:
            raise ArchiveBundleError("archive bundle ciphertext identity is invalid")
        ciphertext_digest, _ciphertext_size = _hash_regular_file(encrypted_bundle)
        if not secrets.compare_digest(ciphertext_digest, expected_ciphertext_sha256):
            raise ArchiveBundleError("archive bundle ciphertext identity does not match")
        _require_regular_secret(identity_file)
        _require_safe_directory(scratch_directory)
        _require_new_directory(output_repository)
        with (
            tempfile.TemporaryDirectory(
                prefix="scalevault-archive-recovery-",
                dir=scratch_directory,
            ) as temporary_name,
            tempfile.TemporaryDirectory(
                prefix=".scalevault-archive-repository-",
                dir=output_repository.parent,
            ) as publication_name,
        ):
            temporary = Path(temporary_name)
            publication = Path(publication_name)
            os.chmod(temporary, 0o700)
            os.chmod(publication, 0o700)
            plaintext = temporary / "archive.bundle"
            self._run(
                (
                    str(self._config.age_executable),
                    "--decrypt",
                    "--identity",
                    str(identity_file),
                    "--output",
                    str(plaintext),
                    str(encrypted_bundle),
                )
            )
            _hash_regular_file(plaintext)
            verifier_repository = temporary / "verify.git"
            self._run(
                (
                    str(self._config.git_executable),
                    "--no-pager",
                    "-c",
                    "init.templateDir=/dev/null",
                    "init",
                    "--bare",
                    str(verifier_repository),
                )
            )
            self._git(verifier_repository, ("bundle", "verify", str(plaintext)))
            materialized = publication / "repository"
            self._run(
                (
                    str(self._config.git_executable),
                    "--no-pager",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "init.templateDir=/dev/null",
                    "clone",
                    "--no-checkout",
                    "--single-branch",
                    "--branch",
                    branch_name,
                    "--",
                    str(plaintext),
                    str(materialized),
                )
            )
            source = GitRecoverySource(
                repository=materialized,
                branch_name=branch_name,
                expected_head=expected_head,
                git_executable=self._config.git_executable,
            )
            commits = ReadOnlyGitArchive(source).read()
            verify_signed_archive_epochs(
                commits,
                signer_epochs_for_repository(materialized),
            )
            try:
                os.rename(materialized, output_repository)
            except OSError:
                raise ArchiveBundleError("archive recovery publication failed") from None
        return GitRecoverySource(
            repository=output_repository,
            branch_name=branch_name,
            expected_head=expected_head,
            git_executable=self._config.git_executable,
        )

    def _git(self, repository: Path, arguments: tuple[str, ...]) -> ProcessResult:
        return self._run(
            (
                str(self._config.git_executable),
                "--no-pager",
                "--literal-pathspecs",
                "-C",
                str(repository),
                "-c",
                "core.hooksPath=/dev/null",
                *arguments,
            )
        )

    def _require_bundle_head(
        self,
        repository: Path,
        bundle: Path,
        source: GitRecoverySource,
    ) -> None:
        result = self._git(repository, ("bundle", "list-heads", str(bundle)))
        try:
            lines = tuple(line for line in result.stdout.decode("ascii").splitlines() if line)
        except UnicodeDecodeError:
            raise ArchiveBundleError("archive bundle advertised head is invalid") from None
        expected = f"{source.expected_head} refs/heads/{source.branch_name}"
        if lines != (expected,):
            raise ArchiveBundleError("archive bundle advertised head does not match")

    def _run(self, arguments: tuple[str, ...]) -> ProcessResult:
        try:
            result = self._runner.run(
                arguments,
                stdin=b"",
                environment={
                    "LC_ALL": "C",
                    "LANG": "C",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_NO_LAZY_FETCH": "1",
                },
                timeout_seconds=self._config.timeout_seconds,
            )
        except GitSigningError:
            raise ArchiveBundleError("archive bundle command failed") from None
        if result.returncode != 0:
            raise ArchiveBundleError("archive bundle command failed")
        return result


def _require_safe_directory(path: Path) -> None:
    if not path.is_absolute() or path in {Path("/"), Path("/tmp")}:
        raise ArchiveBundleError("archive bundle directory is too broad")
    try:
        if not path.is_dir() or path.is_symlink() or path.resolve(strict=True) != path:
            raise ArchiveBundleError("archive bundle directory is unsafe")
    except OSError:
        raise ArchiveBundleError("archive bundle directory is unavailable") from None


def _require_new_output(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ArchiveBundleError("archive bundle output path is invalid")
    _require_safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise ArchiveBundleError("archive bundle output already exists")


def _require_new_directory(path: Path) -> None:
    if not path.is_absolute() or path in {Path("/"), Path("/tmp")}:
        raise ArchiveBundleError("archive recovery output is too broad")
    _require_safe_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise ArchiveBundleError("archive recovery output already exists")


def _require_regular_secret(path: Path) -> None:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError:
        raise ArchiveBundleError("archive recovery identity is unavailable") from None
    if (
        not path.is_absolute()
        or not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_mode & 0o077
    ):
        raise ArchiveBundleError("archive recovery identity is unsafe")


def _hash_regular_file(path: Path) -> tuple[str, int]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise ArchiveBundleError("archive bundle file is unavailable") from None
    digest = hashlib.sha256()
    size = 0
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ArchiveBundleError("archive bundle file is unsafe")
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > _MAX_CIPHERTEXT_SIZE:
                raise ArchiveBundleError("archive bundle exceeds the accepted limit")
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (
            final.st_dev != details.st_dev
            or final.st_ino != details.st_ino
            or final.st_mode != details.st_mode
            or final.st_nlink != details.st_nlink
            or final.st_size != details.st_size
            or final.st_mtime_ns != details.st_mtime_ns
            or final.st_ctime_ns != details.st_ctime_ns
            or size != details.st_size
        ):
            raise ArchiveBundleError("archive bundle changed while reading")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _publish_new_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    source_descriptor = -1
    destination_descriptor = -1
    published = False
    try:
        source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        source_details = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_details.st_mode) or source_details.st_nlink != 1:
            raise ArchiveBundleError("archive bundle publication source is unsafe")
        destination_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while chunk := os.read(source_descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > expected_size:
                raise ArchiveBundleError("archive bundle changed before publication")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written < 1:
                    raise ArchiveBundleError("archive bundle publication write failed")
                view = view[written:]
        final_source = os.fstat(source_descriptor)
        if (
            copied != expected_size
            or not secrets.compare_digest(digest.hexdigest(), expected_sha256)
            or final_source.st_dev != source_details.st_dev
            or final_source.st_ino != source_details.st_ino
            or final_source.st_size != source_details.st_size
            or final_source.st_mtime_ns != source_details.st_mtime_ns
            or final_source.st_ctime_ns != source_details.st_ctime_ns
        ):
            raise ArchiveBundleError("archive bundle changed before publication")
        os.fsync(destination_descriptor)
        os.link(temporary, destination, follow_symlinks=False)
        published = True
        temporary.unlink()
        directory_descriptor = os.open(
            destination.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        published_digest, published_size = _hash_regular_file(destination)
        if published_digest != expected_sha256 or published_size != expected_size:
            with suppress(OSError):
                destination.unlink()
            raise ArchiveBundleError("published archive bundle identity changed")
    except ArchiveBundleError:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        if published:
            with suppress(OSError):
                destination.unlink(missing_ok=True)
        raise
    except OSError:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        if published:
            with suppress(OSError):
                destination.unlink(missing_ok=True)
        raise ArchiveBundleError("archive bundle publication failed") from None
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
