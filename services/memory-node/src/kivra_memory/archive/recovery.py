"""Bounded read-only Git object adapter for archive recovery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from kivra_memory.archive.git import ProcessResult, ProcessRunner, SubprocessRunner
from kivra_memory.archive.models import (
    MANIFEST_PATH,
    MAX_ARCHIVE_FILE_SIZE,
    MAX_ARCHIVE_FILES,
    validate_archive_path,
)
from kivra_memory.archive.verification import ArchiveBatch, ArchiveCommitBatch

_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")


class ArchiveRecoveryError(RuntimeError):
    """Content-free failure while reading untrusted Git recovery objects."""


@dataclass(frozen=True, slots=True)
class GitRecoveryLimits:
    """Whole-history and per-object allocation bounds."""

    max_commits: int = 100_000
    max_files_per_commit: int = MAX_ARCHIVE_FILES + 1
    max_blob_size: int = MAX_ARCHIVE_FILE_SIZE
    max_history_bytes: int = 8 * 1024 * 1024 * 1024
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        for value in (
            self.max_commits,
            self.max_files_per_commit,
            self.max_blob_size,
            self.max_history_bytes,
            self.timeout_seconds,
        ):
            if isinstance(value, bool) or value < 1:
                raise ValueError("Git recovery limits must be positive")
        if self.timeout_seconds > 300:
            raise ValueError("Git recovery timeout is outside the accepted range")


@dataclass(frozen=True, slots=True)
class GitRecoverySource:
    """Pinned local recovery repository and accepted external head anchor."""

    repository: Path
    branch_name: str
    expected_head: str
    git_executable: Path = Path("/usr/bin/git")

    def __post_init__(self) -> None:
        if not self.repository.is_absolute() or not self.git_executable.is_absolute():
            raise ValueError("Git recovery paths must be absolute")
        if (
            _BRANCH.fullmatch(self.branch_name) is None
            or self.branch_name.startswith("-")
            or ".." in self.branch_name
            or "//" in self.branch_name
            or self.branch_name.endswith(("/", ".lock"))
        ):
            raise ValueError("Git recovery branch is invalid")
        _require_object_id(self.expected_head)


class ReadOnlyGitArchive:
    """Read exact commit trees without a worktree or mutable Git operation."""

    def __init__(
        self,
        source: GitRecoverySource,
        *,
        limits: GitRecoveryLimits | None = None,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._source = source
        self._limits = limits or GitRecoveryLimits()
        self._runner = runner or SubprocessRunner()

    def read(self) -> tuple[ArchiveCommitBatch, ...]:
        """Return the exact genesis-to-anchor first-parent archive batches."""

        self._require_repository()
        reference = f"refs/heads/{self._source.branch_name}"
        actual_head = self._git_text(("rev-parse", "--verify", reference))
        if actual_head != self._source.expected_head:
            raise ArchiveRecoveryError("archive head does not match the external anchor")
        history = self._git(
            (
                "rev-list",
                "--first-parent",
                "--reverse",
                f"--max-count={self._limits.max_commits + 1}",
                self._source.expected_head,
            )
        ).stdout
        try:
            commits = tuple(line for line in history.decode("ascii").splitlines() if line)
        except UnicodeDecodeError:
            raise ArchiveRecoveryError("Git returned an invalid history") from None
        if not commits or len(commits) > self._limits.max_commits:
            raise ArchiveRecoveryError("archive history is empty or oversized")
        if any(_OBJECT_ID.fullmatch(commit) is None for commit in commits):
            raise ArchiveRecoveryError("Git returned an invalid history")
        if commits[-1] != self._source.expected_head:
            raise ArchiveRecoveryError("archive history does not reach the external anchor")

        consumed = 0
        result: list[ArchiveCommitBatch] = []
        for commit in commits:
            batch, consumed = self._read_commit(commit, consumed=consumed)
            result.append(ArchiveCommitBatch(commit_sha=commit, batch=batch))
        return tuple(result)

    def _read_commit(self, commit: str, *, consumed: int) -> tuple[ArchiveBatch, int]:
        tree = self._git(("ls-tree", "-r", "-z", "--long", "--full-tree", commit)).stdout
        if not tree.endswith(b"\0"):
            raise ArchiveRecoveryError("Git returned an invalid archive tree")
        records = tree[:-1].split(b"\0") if tree[:-1] else []
        if not records or len(records) > self._limits.max_files_per_commit:
            raise ArchiveRecoveryError("archive tree is empty or oversized")
        objects: list[tuple[str, str, int]] = []
        for record in records:
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, kind, raw_object_id, raw_size = metadata.split()
                path = raw_path.decode("utf-8")
                object_id = raw_object_id.decode("ascii")
                size = int(raw_size)
            except (UnicodeDecodeError, ValueError):
                raise ArchiveRecoveryError("Git returned an invalid archive tree") from None
            if mode != b"100644" or kind != b"blob":
                raise ArchiveRecoveryError("archive tree contains a non-regular object")
            _require_object_id(object_id)
            if path == MANIFEST_PATH:
                pass
            else:
                try:
                    validate_archive_path(path)
                except ValueError:
                    raise ArchiveRecoveryError(
                        "archive tree path is outside the closed layout"
                    ) from None
            if isinstance(size, bool) or not 0 <= size <= self._limits.max_blob_size:
                raise ArchiveRecoveryError("archive blob exceeds the accepted limit")
            consumed += size
            if consumed > self._limits.max_history_bytes:
                raise ArchiveRecoveryError("archive history exceeds the accepted byte limit")
            objects.append((path, object_id, size))
        if len({path for path, _object_id, _size in objects}) != len(objects):
            raise ArchiveRecoveryError("archive tree contains duplicate paths")

        files: dict[str, bytes] = {}
        for path, object_id, size in objects:
            content = self._git(("cat-file", "blob", object_id)).stdout
            if len(content) != size:
                raise ArchiveRecoveryError("archive blob size changed while reading")
            files[path] = content
        try:
            manifest = files.pop(MANIFEST_PATH)
        except KeyError:
            raise ArchiveRecoveryError("archive manifest is missing") from None
        return ArchiveBatch(manifest_bytes=manifest, files=files), consumed

    def _require_repository(self) -> None:
        repository = self._source.repository
        try:
            if (
                not repository.is_dir()
                or repository.is_symlink()
                or repository.resolve(strict=True) != repository
            ):
                raise ArchiveRecoveryError("archive repository is unsafe")
        except OSError:
            raise ArchiveRecoveryError("archive repository is unavailable") from None
        if self._git_text(("rev-parse", "--is-bare-repository")) not in {"true", "false"}:
            raise ArchiveRecoveryError("archive repository is invalid")

    def _git_text(self, arguments: tuple[str, ...]) -> str:
        try:
            return self._git(arguments).stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ArchiveRecoveryError("Git returned invalid text") from None

    def _git(self, arguments: tuple[str, ...]) -> ProcessResult:
        result = self._runner.run(
            (
                str(self._source.git_executable),
                "--no-pager",
                "--literal-pathspecs",
                "-C",
                str(self._source.repository),
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
            },
            timeout_seconds=self._limits.timeout_seconds,
        )
        if result.returncode != 0:
            raise ArchiveRecoveryError("read-only Git recovery operation failed")
        return result


def _require_object_id(value: str) -> None:
    if _OBJECT_ID.fullmatch(value) is None:
        raise ValueError("Git recovery object ID is invalid")
