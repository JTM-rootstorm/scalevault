"""Narrow fixed-argument Git SSH signing and verification process seam."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Protocol

from kivra_memory.domain.values import format_utc_datetime

_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_SIGNATURE_STATUS = re.compile(
    rb'Good "git" signature for ([A-Za-z0-9][A-Za-z0-9_.@+\-]{0,127}) '
    rb"with [A-Z0-9][A-Z0-9_-]{0,31} key (SHA256:[A-Za-z0-9+/=]{4,128})"
)
_KEY_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/=]{4,128}")
_DEFAULT_STDOUT_LIMIT = 8 * 1024 * 1024
_DEFAULT_STDERR_LIMIT = 256 * 1024
_MAX_STDOUT_LIMIT = 64 * 1024 * 1024 + 1
_MAX_STDERR_LIMIT = 1024 * 1024
_MAX_STDIN_SIZE = 16 * 1024 * 1024
_PROCESS_CHUNK_SIZE = 64 * 1024


class GitSigningError(RuntimeError):
    """Raised without subprocess output when archive signing fails closed."""


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Bounded process result returned by the injectable command seam."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True, slots=True)
class VerifiedGitCommit:
    """Signed commit identity proven against pinned trust and exact batch bytes."""

    commit_sha: str
    tree_sha: str
    parent_sha: str | None


class ProcessRunner(Protocol):
    """Execute one argv-only command with a completely supplied environment."""

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
        stdout_limit_bytes: int = _DEFAULT_STDOUT_LIMIT,
        stderr_limit_bytes: int = _DEFAULT_STDERR_LIMIT,
    ) -> ProcessResult:
        """Return captured process output without invoking a shell."""


class SubprocessRunner:
    """Production argv-only subprocess implementation with bounded pipe drains."""

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
        stdout_limit_bytes: int = _DEFAULT_STDOUT_LIMIT,
        stderr_limit_bytes: int = _DEFAULT_STDERR_LIMIT,
    ) -> ProcessResult:
        _validate_process_limits(
            stdin,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=environment,
                start_new_session=True,
            )
        except OSError:
            raise GitSigningError("isolated Git command failed") from None
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process_stdin = process.stdin
        process_stdout = process.stdout
        process_stderr = process.stderr
        exceeded = threading.Event()
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_size = [0]
        stderr_size = [0]

        def drain(
            stream: BinaryIO,
            chunks: list[bytes],
            size: list[int],
            limit: int,
        ) -> None:
            try:
                while True:
                    chunk = stream.read(_PROCESS_CHUNK_SIZE)
                    if not chunk:
                        return
                    if size[0] + len(chunk) > limit:
                        exceeded.set()
                        _kill_process_group(process)
                        return
                    chunks.append(chunk)
                    size[0] += len(chunk)
            except OSError:
                exceeded.set()
                _kill_process_group(process)

        stdout_thread = threading.Thread(
            target=drain,
            args=(process_stdout, stdout_chunks, stdout_size, stdout_limit_bytes),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=drain,
            args=(process_stderr, stderr_chunks, stderr_size, stderr_limit_bytes),
            daemon=True,
        )

        def write_stdin() -> None:
            try:
                process_stdin.write(stdin)
            except (BrokenPipeError, OSError):
                pass
            finally:
                with suppress(OSError):
                    process_stdin.close()

        stdin_thread = threading.Thread(target=write_stdin, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        stdin_thread.start()
        try:
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                exceeded.set()
                _kill_process_group(process)
                returncode = process.wait()
            stdin_thread.join()
            stdout_thread.join()
            stderr_thread.join()
        finally:
            _kill_process_group(process)
            with suppress(OSError):
                process.wait()
            for stream in (process_stdin, process_stdout, process_stderr):
                with suppress(OSError):
                    stream.close()
        if exceeded.is_set():
            raise GitSigningError("isolated Git command exceeded a resource limit")
        return ProcessResult(returncode, b"".join(stdout_chunks), b"".join(stderr_chunks))


def _validate_process_limits(
    stdin: bytes,
    *,
    stdout_limit_bytes: int,
    stderr_limit_bytes: int,
) -> None:
    if len(stdin) > _MAX_STDIN_SIZE:
        raise GitSigningError("isolated Git command exceeded a resource limit")
    for value, maximum in (
        (stdout_limit_bytes, _MAX_STDOUT_LIMIT),
        (stderr_limit_bytes, _MAX_STDERR_LIMIT),
    ):
        if isinstance(value, bool) or not 1 <= value <= maximum:
            raise GitSigningError("isolated Git command has an invalid resource limit")


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)
        return
    with suppress(OSError):
        process.kill()


@dataclass(frozen=True, slots=True)
class GitSigningConfig:
    """Externally provisioned trust and signing paths plus deterministic identity."""

    repository: Path
    signing_key: Path
    allowed_signers_file: Path
    signer_principal: str
    author_name: str
    author_email: str
    git_executable: Path = Path("/usr/bin/git")
    ssh_keygen_executable: Path = Path("/usr/bin/ssh-keygen")
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        for path in (
            self.repository,
            self.signing_key,
            self.allowed_signers_file,
            self.git_executable,
            self.ssh_keygen_executable,
        ):
            if not path.is_absolute():
                raise ValueError("Git archive paths must be absolute")
        _validate_identity_fields(
            self.signer_principal,
            self.author_name,
            self.author_email,
        )
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 120:
            raise ValueError("Git timeout is outside the accepted range")


@dataclass(frozen=True, slots=True)
class GitVerificationConfig:
    """Verification-only Git configuration with no signing-key field."""

    repository: Path
    allowed_signers_file: Path
    signer_principal: str
    author_name: str
    author_email: str
    expected_key_fingerprint: str | None = None
    git_executable: Path = Path("/usr/bin/git")
    ssh_keygen_executable: Path = Path("/usr/bin/ssh-keygen")
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        for path in (
            self.repository,
            self.allowed_signers_file,
            self.git_executable,
            self.ssh_keygen_executable,
        ):
            if not path.is_absolute():
                raise ValueError("Git archive paths must be absolute")
        _validate_identity_fields(
            self.signer_principal,
            self.author_name,
            self.author_email,
        )
        if (
            self.expected_key_fingerprint is not None
            and _KEY_FINGERPRINT.fullmatch(self.expected_key_fingerprint) is None
        ):
            raise ValueError("Git signer fingerprint is invalid")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 120:
            raise ValueError("Git timeout is outside the accepted range")


class GitCommitVerifier:
    """Verify archive commits using public trust material only."""

    def __init__(
        self,
        config: GitVerificationConfig,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()

    def verify_commit(self, commit_sha: str) -> None:
        """Verify a commit against only the externally pinned allowed-signers file."""

        _require_object_id(commit_sha, "commit")
        result = self._run_git(
            ("verify-commit", "--raw", commit_sha),
            stdout_limit_bytes=64 * 1024,
            stderr_limit_bytes=64 * 1024,
        )
        identities = {
            (match.group(1).decode("ascii"), match.group(2).decode("ascii"))
            for line in (*result.stderr.splitlines(), *result.stdout.splitlines())
            if (match := _SIGNATURE_STATUS.fullmatch(line)) is not None
        }
        if {principal for principal, _fingerprint in identities} != {self._config.signer_principal}:
            raise GitSigningError("Git commit signer identity did not match the trust anchor")
        if self._config.expected_key_fingerprint is not None and identities != {
            (self._config.signer_principal, self._config.expected_key_fingerprint)
        }:
            raise GitSigningError("Git commit signer key did not match the trust anchor")

    def verify_archive_commit(
        self,
        commit_sha: str,
        *,
        expected_parent_sha: str | None,
        expected_message: str,
        expected_timestamp: str,
        expected_files: Mapping[str, bytes],
    ) -> VerifiedGitCommit:
        """Verify one signed commit's parent, metadata, changed paths, and exact blobs."""

        _require_object_id(commit_sha, "commit")
        if expected_parent_sha is not None:
            _require_object_id(expected_parent_sha, "parent")
        _validate_message(expected_message)
        normalized_timestamp = _validate_timestamp(expected_timestamp)
        if not expected_files:
            raise GitSigningError("archive commit expected file set is empty")
        self.verify_commit(commit_sha)

        commit_result = self._run_git(
            ("cat-file", "commit", commit_sha),
            stdout_limit_bytes=64 * 1024,
        )
        tree_sha, parent_sha, author, committer, message = _parse_commit_object(
            commit_result.stdout
        )
        if parent_sha != expected_parent_sha:
            raise GitSigningError("Git archive first-parent chain is invalid")
        if message != expected_message.encode("utf-8"):
            raise GitSigningError("Git archive commit message does not match its batch")
        expected_identity = _expected_identity_line(self._config, normalized_timestamp)
        if author != expected_identity or committer != expected_identity:
            raise GitSigningError("Git archive commit identity does not match its batch")

        expected_tree: dict[str, str] = {}
        for path, content in expected_files.items():
            _validate_git_path(path)
            expected_tree[path] = _git_object_id(b"blob", content, len(commit_sha))
        tree_result = self._run_git(
            ("ls-tree", "-r", "-z", "--full-tree", commit_sha),
            stdout_limit_bytes=_tree_output_limit(expected_files),
        )
        actual_tree = _parse_tree_entries(tree_result.stdout, max_entries=len(expected_tree))
        if actual_tree != expected_tree:
            raise GitSigningError("Git archive tree does not exactly match its batch bytes")

        return VerifiedGitCommit(
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            parent_sha=parent_sha,
        )

    def _run_git(
        self,
        arguments: tuple[str, ...],
        *,
        stdout_limit_bytes: int = _DEFAULT_STDOUT_LIMIT,
        stderr_limit_bytes: int = _DEFAULT_STDERR_LIMIT,
    ) -> ProcessResult:
        result = self._runner.run(
            (*self._git_prefix(), *arguments),
            stdin=b"",
            environment=self._environment(),
            timeout_seconds=self._config.timeout_seconds,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        if result.returncode != 0:
            raise GitSigningError("Git archive object verification failed")
        return result

    def _git_prefix(self) -> tuple[str, ...]:
        return (
            str(self._config.git_executable),
            "--no-pager",
            "--literal-pathspecs",
            "-C",
            str(self._config.repository),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.program={self._config.ssh_keygen_executable}",
            "-c",
            f"gpg.ssh.allowedSignersFile={self._config.allowed_signers_file}",
        )

    def _environment(self) -> dict[str, str]:
        return {
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
        }


class GitCommitSigner:
    """Create and verify signed commit objects without mutable Git configuration."""

    def __init__(
        self,
        config: GitSigningConfig,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()

    def sign_commit(
        self,
        *,
        tree_sha: str,
        parent_sha: str | None,
        message: str,
        timestamp: str,
    ) -> str:
        """Create one deterministic signed commit object and return its object ID."""

        _require_object_id(tree_sha, "tree")
        if parent_sha is not None:
            _require_object_id(parent_sha, "parent")
        _validate_message(message)
        normalized_timestamp = _validate_timestamp(timestamp)
        arguments = [
            *self._git_prefix(signing=True),
            "commit-tree",
            tree_sha,
        ]
        if parent_sha is not None:
            arguments.extend(("-p", parent_sha))
        arguments.extend((f"-S{self._config.signing_key}", "-F", "-"))
        result = self._runner.run(
            tuple(arguments),
            stdin=message.encode("utf-8"),
            environment=self._environment(normalized_timestamp),
            timeout_seconds=self._config.timeout_seconds,
            stdout_limit_bytes=128,
            stderr_limit_bytes=64 * 1024,
        )
        if result.returncode != 0:
            raise GitSigningError("Git commit signing failed")
        try:
            commit_sha = result.stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            raise GitSigningError("Git returned an invalid commit object ID") from None
        _require_object_id(commit_sha, "signed commit")
        return commit_sha

    def verify_commit(self, commit_sha: str) -> None:
        """Verify a commit against only the externally pinned allowed-signers file."""

        _require_object_id(commit_sha, "commit")
        arguments = (
            *self._git_prefix(signing=False),
            "verify-commit",
            "--raw",
            commit_sha,
        )
        result = self._runner.run(
            arguments,
            stdin=b"",
            environment=self._environment(None),
            timeout_seconds=self._config.timeout_seconds,
            stdout_limit_bytes=64 * 1024,
            stderr_limit_bytes=64 * 1024,
        )
        if result.returncode != 0:
            raise GitSigningError("Git commit signature verification failed")
        principals = {
            match.group(1).decode("ascii")
            for line in (*result.stderr.splitlines(), *result.stdout.splitlines())
            if (match := _SIGNATURE_STATUS.fullmatch(line)) is not None
        }
        if principals != {self._config.signer_principal}:
            raise GitSigningError("Git commit signer identity did not match the trust anchor")

    def verify_archive_commit(
        self,
        commit_sha: str,
        *,
        expected_parent_sha: str | None,
        expected_message: str,
        expected_timestamp: str,
        expected_files: Mapping[str, bytes],
    ) -> VerifiedGitCommit:
        """Verify one signed commit's parent, metadata, changed paths, and exact blobs."""

        _require_object_id(commit_sha, "commit")
        if expected_parent_sha is not None:
            _require_object_id(expected_parent_sha, "parent")
        _validate_message(expected_message)
        normalized_timestamp = _validate_timestamp(expected_timestamp)
        if not expected_files:
            raise GitSigningError("archive commit expected file set is empty")
        self.verify_commit(commit_sha)

        commit_result = self._run_git(
            ("cat-file", "commit", commit_sha),
            stdout_limit_bytes=64 * 1024,
        )
        tree_sha, parent_sha, author, committer, message = _parse_commit_object(
            commit_result.stdout
        )
        if parent_sha != expected_parent_sha:
            raise GitSigningError("Git archive first-parent chain is invalid")
        if message != expected_message.encode("utf-8"):
            raise GitSigningError("Git archive commit message does not match its batch")
        expected_identity = _expected_identity_line(
            self._config,
            normalized_timestamp,
        )
        if author != expected_identity or committer != expected_identity:
            raise GitSigningError("Git archive commit identity does not match its batch")

        expected_tree: dict[str, str] = {}
        for path, content in expected_files.items():
            _validate_git_path(path)
            expected_tree[path] = _git_object_id(b"blob", content, len(commit_sha))
        tree_result = self._run_git(
            ("ls-tree", "-r", "-z", "--full-tree", commit_sha),
            stdout_limit_bytes=_tree_output_limit(expected_files),
        )
        actual_tree = _parse_tree_entries(tree_result.stdout, max_entries=len(expected_tree))
        if actual_tree != expected_tree:
            raise GitSigningError("Git archive tree does not exactly match its batch bytes")

        return VerifiedGitCommit(
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            parent_sha=parent_sha,
        )

    def _run_git(
        self,
        arguments: tuple[str, ...],
        *,
        stdout_limit_bytes: int = _DEFAULT_STDOUT_LIMIT,
        stderr_limit_bytes: int = _DEFAULT_STDERR_LIMIT,
    ) -> ProcessResult:
        result = self._runner.run(
            (*self._git_prefix(signing=False), *arguments),
            stdin=b"",
            environment=self._environment(None),
            timeout_seconds=self._config.timeout_seconds,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        if result.returncode != 0:
            raise GitSigningError("Git archive object verification failed")
        return result

    def _git_prefix(self, *, signing: bool) -> tuple[str, ...]:
        arguments = [
            str(self._config.git_executable),
            "--no-pager",
            "-C",
            str(self._config.repository),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.program={self._config.ssh_keygen_executable}",
        ]
        if signing:
            arguments.extend(("-c", f"user.signingKey={self._config.signing_key}"))
        else:
            arguments.extend(
                ("-c", f"gpg.ssh.allowedSignersFile={self._config.allowed_signers_file}")
            )
        return tuple(arguments)

    def _environment(self, timestamp: str | None) -> dict[str, str]:
        environment = {
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": self._config.author_name,
            "GIT_AUTHOR_EMAIL": self._config.author_email,
            "GIT_COMMITTER_NAME": self._config.author_name,
            "GIT_COMMITTER_EMAIL": self._config.author_email,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
        }
        if timestamp is not None:
            environment["GIT_AUTHOR_DATE"] = timestamp
            environment["GIT_COMMITTER_DATE"] = timestamp
        return environment


def archive_commit_message(first_event_sequence: int, last_event_sequence: int) -> str:
    """Return the versioned deterministic archive commit message."""

    if (
        isinstance(first_event_sequence, bool)
        or isinstance(last_event_sequence, bool)
        or first_event_sequence < 1
        or last_event_sequence < first_event_sequence
    ):
        raise ValueError("archive commit event range is invalid")
    return f"memory-export: events {first_event_sequence}..{last_event_sequence}\n"


def _require_object_id(value: str, name: str) -> None:
    if _OBJECT_ID.fullmatch(value) is None:
        raise GitSigningError(f"{name} object ID is invalid")


def _validate_message(message: str) -> None:
    if not message or len(message.encode("utf-8")) > 4096 or "\x00" in message:
        raise GitSigningError("Git commit message is invalid")
    if not message.endswith("\n") or message.endswith("\n\n"):
        raise GitSigningError("Git commit message must have one terminal newline")


def _validate_timestamp(timestamp: str) -> str:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise GitSigningError("Git commit timestamp is invalid") from None
    if format_utc_datetime(parsed) != timestamp:
        raise GitSigningError("Git commit timestamp is not canonical UTC")
    return timestamp


def _parse_commit_object(document: bytes) -> tuple[str, str | None, bytes, bytes, bytes]:
    try:
        header_bytes, message = document.split(b"\n\n", 1)
    except ValueError:
        raise GitSigningError("Git returned an invalid commit object") from None
    headers: dict[bytes, list[bytes]] = {}
    current: bytes | None = None
    for line in header_bytes.splitlines():
        if line.startswith(b" "):
            if current not in {b"gpgsig", b"gpgsig-sha256"}:
                raise GitSigningError("Git returned an invalid commit header")
            continue
        try:
            name, value = line.split(b" ", 1)
        except ValueError:
            raise GitSigningError("Git returned an invalid commit header") from None
        if name not in {b"tree", b"parent", b"author", b"committer", b"gpgsig", b"gpgsig-sha256"}:
            raise GitSigningError("Git archive commit contains an unexpected header")
        headers.setdefault(name, []).append(value)
        current = name

    tree_values = headers.get(b"tree", [])
    parent_values = headers.get(b"parent", [])
    author_values = headers.get(b"author", [])
    committer_values = headers.get(b"committer", [])
    signature_count = len(headers.get(b"gpgsig", [])) + len(headers.get(b"gpgsig-sha256", []))
    if (
        len(tree_values) != 1
        or len(parent_values) > 1
        or len(author_values) != 1
        or len(committer_values) != 1
        or signature_count != 1
    ):
        raise GitSigningError("Git archive commit structure is invalid")
    try:
        tree_sha = tree_values[0].decode("ascii")
        parent_sha = parent_values[0].decode("ascii") if parent_values else None
    except UnicodeDecodeError:
        raise GitSigningError("Git archive commit object ID is invalid") from None
    _require_object_id(tree_sha, "tree")
    if parent_sha is not None:
        _require_object_id(parent_sha, "parent")
    return tree_sha, parent_sha, author_values[0], committer_values[0], message


def _validate_identity_fields(principal: str, author_name: str, author_email: str) -> None:
    if _IDENTITY.fullmatch(principal) is None:
        raise ValueError("signer principal is invalid")
    if not author_name or "\n" in author_name or "\r" in author_name:
        raise ValueError("Git author name is invalid")
    if _EMAIL.fullmatch(author_email) is None:
        raise ValueError("Git author email is invalid")


def _expected_identity_line(
    config: GitSigningConfig | GitVerificationConfig,
    timestamp: str,
) -> bytes:
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    epoch_seconds = int(parsed.timestamp())
    return f"{config.author_name} <{config.author_email}> {epoch_seconds} +0000".encode()


def _parse_tree_entries(document: bytes, *, max_entries: int) -> dict[str, str]:
    if not document or not document.endswith(b"\0"):
        raise GitSigningError("Git returned an invalid archive tree")
    records = document[:-1].split(b"\0")
    if len(records) > max_entries:
        raise GitSigningError("Git archive tree contains extra entries")
    entries: dict[str, str] = {}
    for record in records:
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode, object_type, object_id_bytes = metadata.split(b" ", 2)
            path = path_bytes.decode("utf-8")
            object_id = object_id_bytes.decode("ascii")
        except (UnicodeDecodeError, ValueError):
            raise GitSigningError("Git returned an invalid archive tree entry") from None
        _validate_git_path(path)
        _require_object_id(object_id, "tree entry")
        if mode != b"100644" or object_type != b"blob":
            raise GitSigningError("Git archive tree contains a non-regular entry")
        if path in entries:
            raise GitSigningError("Git archive tree contains duplicate paths")
        entries[path] = object_id
    return entries


def _validate_git_path(path: str) -> None:
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(component in {"", ".", ".."} for component in path.split("/"))
    ):
        raise GitSigningError("Git archive path is invalid")


def _tree_output_limit(expected_files: Mapping[str, bytes]) -> int:
    # ``git ls-tree -rz`` adds mode, type, object ID, separators, and NUL.
    estimate = sum(len(path.encode("utf-8")) + 160 for path in expected_files)
    if not 1 <= estimate <= _MAX_STDOUT_LIMIT:
        raise GitSigningError("Git archive tree exceeds the verification output limit")
    return estimate


def _git_object_id(kind: bytes, content: bytes, object_id_length: int) -> str:
    import hashlib

    if object_id_length == 40:
        digest = hashlib.sha1(usedforsecurity=False)
    elif object_id_length == 64:
        digest = hashlib.sha256()
    else:
        raise GitSigningError("Git object ID format is unsupported")
    digest.update(kind + b" " + str(len(content)).encode("ascii") + b"\0" + content)
    return digest.hexdigest()
