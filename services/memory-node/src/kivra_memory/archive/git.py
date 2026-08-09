"""Narrow fixed-argument Git SSH signing and verification process seam."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from kivra_memory.domain.values import format_utc_datetime

_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")


class GitSigningError(RuntimeError):
    """Raised without subprocess output when archive signing fails closed."""


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Bounded process result returned by the injectable command seam."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class ProcessRunner(Protocol):
    """Execute one argv-only command with a completely supplied environment."""

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        """Return captured process output without invoking a shell."""


class SubprocessRunner:
    """Production argv-only subprocess implementation."""

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        try:
            completed = subprocess.run(
                arguments,
                input=stdin,
                capture_output=True,
                check=False,
                shell=False,
                env=environment,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError):
            raise GitSigningError("isolated Git command failed") from None
        return ProcessResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


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
        if _IDENTITY.fullmatch(self.signer_principal) is None:
            raise ValueError("signer principal is invalid")
        if not self.author_name or "\n" in self.author_name or "\r" in self.author_name:
            raise ValueError("Git author name is invalid")
        if _EMAIL.fullmatch(self.author_email) is None:
            raise ValueError("Git author email is invalid")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 120:
            raise ValueError("Git timeout is outside the accepted range")


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
        )
        if result.returncode != 0:
            raise GitSigningError("Git commit signature verification failed")
        expected = f'Good "git" signature for {self._config.signer_principal}'.encode()
        if expected not in result.stderr and expected not in result.stdout:
            raise GitSigningError("Git commit signer identity did not match the trust anchor")

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
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise GitSigningError("Git commit timestamp is invalid") from None
    if format_utc_datetime(parsed) != timestamp:
        raise GitSigningError("Git commit timestamp is not canonical UTC")
    return timestamp
