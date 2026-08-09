"""Concrete deterministic builder and fixed-target Git worktree adapter."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from kivra_memory.archive.codec import (
    SnapshotCodec,
    SnapshotData,
    SnapshotTable,
    canonical_cbor_bytes,
)
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitSigningConfig,
    GitSigningError,
    ProcessResult,
    ProcessRunner,
    SubprocessRunner,
    archive_commit_message,
)
from kivra_memory.archive.models import ARCHIVE_FORMAT, MANIFEST_PATH, build_manifest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.values import format_utc_datetime
from kivra_memory.storage.archive import ArchiveBatchSource, ArchiveStorageError
from kivra_memory.workers.archive_exporter import BuiltArchive, ReconciledCommit

_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")
_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}")
_SAFE_EXECUTABLE_PATH = re.compile(r"/[A-Za-z0-9_./+-]+")
_SCHEMA_FILES = (
    "export-manifest-v2.schema.json",
    "memory-event.schema.json",
    "memory-projection.schema.json",
)


@dataclass(frozen=True, slots=True)
class ArchivePayload:
    """Complete immutable file set materialized by the Git adapter."""

    files: Mapping[str, bytes]
    tree_sha: str | None = None


class DeterministicArchiveBuilder:
    """Convert a database batch DTO into the closed archive file layout."""

    def __init__(self, *, schema_root: Path, exporter_version: str) -> None:
        if not schema_root.is_absolute() or not schema_root.is_dir() or schema_root.is_symlink():
            raise ValueError("archive schema root is unavailable")
        self._exporter_version = exporter_version
        schemas: dict[str, tuple[str, bytes]] = {}
        for filename in _SCHEMA_FILES:
            path = schema_root / filename
            if not path.is_file() or path.is_symlink():
                raise ValueError("archive schema file is unavailable")
            content = path.read_bytes()
            try:
                document = json.loads(content)
                schema_id = document["$id"]
            except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("archive schema identity is invalid") from None
            if not isinstance(schema_id, str):
                raise ValueError("archive schema identity is invalid")
            schemas[schema_id] = (f"schemas/{filename}", content)
        if len(schemas) != len(_SCHEMA_FILES):
            raise ValueError("archive schema identities are not unique")
        self._schemas = MappingProxyType(schemas)

    def build(self, source: ArchiveBatchSource) -> BuiltArchive:
        try:
            exported_at = datetime.fromisoformat(source.export_timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise ArchiveStorageError("archive_export_timestamp_invalid") from None
        if format_utc_datetime(exported_at) != source.export_timestamp:
            raise ArchiveStorageError("archive_export_timestamp_invalid")

        files: dict[str, bytes] = {
            "archive-format.json": canonical_json_bytes(
                {"archive_format": ARCHIVE_FORMAT, "manifest_schema_version": 2}
            )
        }
        schema_ids: dict[str, str] = {}
        for schema_id, (path, content) in self._schemas.items():
            files[path] = content
            schema_ids[schema_id] = path

        for event in source.events:
            try:
                sequence = event["sequence"]
                event_id = event["event_id"]
                created_at = event["created_at"]
            except KeyError:
                raise ArchiveStorageError("archive_event_invalid") from None
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or not isinstance(event_id, str)
                or not isinstance(created_at, str)
            ):
                raise ArchiveStorageError("archive_event_invalid")
            try:
                event_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except ValueError:
                raise ArchiveStorageError("archive_event_invalid") from None
            path = f"events/{event_time:%Y/%m/%d}/{sequence:012d}-{event_id}.json"
            if path in files:
                raise ArchiveStorageError("archive_event_invalid")
            files[path] = canonical_json_bytes(event)

        tables = tuple(
            SnapshotTable(
                name=name,
                primary_key=source.recovery_primary_keys[name],
                rows=tuple(
                    sorted(
                        rows,
                        key=lambda row: canonical_cbor_bytes(
                            tuple(row[key] for key in source.recovery_primary_keys[name])
                        ),
                    )
                ),
            )
            for name, rows in sorted(source.recovery_rows.items())
        )
        snapshot = SnapshotData(
            high_water_sequence=source.source_high_water_sequence,
            tables=tables,
        )
        snapshot_cbor = canonical_cbor_bytes(snapshot.value)
        snapshot_path = f"snapshots/snapshot-{source.source_high_water_sequence:012d}.cbor.zst"
        files[snapshot_path] = SnapshotCodec().encode(snapshot)
        manifest = build_manifest(
            files=files,
            first_event_sequence=source.first_event_sequence,
            last_event_sequence=source.last_event_sequence,
            previous_manifest_sha256=source.previous_manifest_sha256,
            schema_ids=schema_ids,
            exporter_version=self._exporter_version,
            exported_at=exported_at,
            snapshot_high_water_sequence=source.source_high_water_sequence,
            snapshot_uncompressed_size=len(snapshot_cbor),
        )
        files[MANIFEST_PATH] = manifest.canonical_bytes
        return BuiltArchive(
            manifest_sha256=bytes.fromhex(manifest.sha256),
            manifest_path=MANIFEST_PATH,
            commit_message=archive_commit_message(
                source.first_event_sequence, source.last_event_sequence
            ),
            commit_timestamp=exported_at,
            payload=ArchivePayload(files=MappingProxyType(dict(sorted(files.items())))),
        )


@dataclass(frozen=True, slots=True)
class GitWorktreeConfig:
    """Fixed archive repository, branch, remote, and SSH trust configuration."""

    repository: Path
    repository_reference: str
    branch_name: str
    deploy_key: Path
    known_hosts_file: Path
    signing: GitSigningConfig
    ssh_executable: Path = Path("/usr/bin/ssh")
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        memory_root = Path("/mnt/memory")
        normalized_repository = self.repository.resolve(strict=False)
        if (
            not self.repository.is_absolute()
            or ".." in self.repository.parts
            or self.repository != normalized_repository
            or not normalized_repository.is_relative_to(memory_root.resolve(strict=False))
        ):
            raise ValueError("archive repository must be below /mnt/memory")
        if self.repository != self.signing.repository:
            raise ValueError("archive repository and signing repository must match")
        for path in (self.deploy_key, self.known_hosts_file, self.ssh_executable):
            if not path.is_absolute() or _SAFE_EXECUTABLE_PATH.fullmatch(str(path)) is None:
                raise ValueError("archive SSH path is invalid")
        parsed = urlsplit(self.repository_reference)
        if parsed.scheme != "ssh" or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("archive remote must be an explicit SSH URL")
        components = self.branch_name.split("/")
        if (
            _BRANCH.fullmatch(self.branch_name) is None
            or ".." in self.branch_name
            or "@{" in self.branch_name
            or self.branch_name.endswith(("/", ".", ".lock"))
            or any(not component or component.startswith(".") for component in components)
        ):
            raise ValueError("archive branch is invalid")
        if isinstance(self.timeout_seconds, bool) or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("archive Git timeout is invalid")


class GitWorktreeArchiveRepository:
    """Single-writer repository adapter with isolated Git and pinned SSH inputs."""

    def __init__(
        self,
        config: GitWorktreeConfig,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()
        self._signer = GitCommitSigner(config.signing, self._runner)
        self._prepared: tuple[bytes, str] | None = None

    async def reconcile(
        self, archive: BuiltArchive, *, expected_parent_sha: str | None
    ) -> ReconciledCommit:
        return await asyncio.to_thread(self._reconcile, archive, expected_parent_sha)

    async def commit(self, archive: BuiltArchive, *, expected_parent_sha: str | None) -> str:
        return await asyncio.to_thread(self._commit, archive, expected_parent_sha)

    async def push(self, *, git_commit_sha: str) -> str:
        return await asyncio.to_thread(self._push, git_commit_sha)

    def _reconcile(
        self, archive: BuiltArchive, expected_parent_sha: str | None
    ) -> ReconciledCommit:
        payload = self._payload(archive)
        self._require_repository()
        self._require_clean_worktree()
        local = self._local_head()
        remote = self._remote_head()
        self._empty_worktree()
        self._materialize(payload)
        tree_sha = self._git_object_id(("write-tree",), name="archive tree")
        self._require_object_id(tree_sha)
        self._prepared = (archive.manifest_sha256, tree_sha)

        if local == expected_parent_sha:
            if remote != expected_parent_sha:
                raise ArchiveStorageError("archive_remote_parent_mismatch")
            return ReconciledCommit()
        if local is None or not self._commit_matches(
            local,
            archive=archive,
            expected_parent_sha=expected_parent_sha,
            expected_tree_sha=tree_sha,
        ):
            raise ArchiveStorageError("archive_local_history_mismatch")
        if remote not in {expected_parent_sha, local}:
            raise ArchiveStorageError("archive_remote_history_mismatch")
        return ReconciledCommit(
            local_commit_sha=local,
            remote_commit_sha=local if remote == local else None,
        )

    def _commit(self, archive: BuiltArchive, expected_parent_sha: str | None) -> str:
        prepared = self._prepared
        if prepared is None or prepared[0] != archive.manifest_sha256:
            raise ArchiveStorageError("archive_tree_not_prepared")
        tree_sha = prepared[1]
        if self._local_head() != expected_parent_sha:
            raise ArchiveStorageError("archive_local_parent_mismatch")
        commit_sha = self._signer.sign_commit(
            tree_sha=tree_sha,
            parent_sha=expected_parent_sha,
            message=archive.commit_message,
            timestamp=format_utc_datetime(archive.commit_timestamp),
        )
        self._signer.verify_commit(commit_sha)
        ref = f"refs/heads/{self._config.branch_name}"
        arguments = ["update-ref", ref, commit_sha]
        if expected_parent_sha is not None:
            arguments.append(expected_parent_sha)
        elif self._local_head() is not None:
            raise ArchiveStorageError("archive_local_parent_mismatch")
        self._git(tuple(arguments))
        self._prepared = None
        return commit_sha

    def _push(self, git_commit_sha: str) -> str:
        self._require_object_id(git_commit_sha)
        if self._local_head() != git_commit_sha:
            raise ArchiveStorageError("archive_local_commit_mismatch")
        self._signer.verify_commit(git_commit_sha)
        refspec = f"{git_commit_sha}:refs/heads/{self._config.branch_name}"
        self._git(("push", "--porcelain", self._config.repository_reference, refspec))
        remote = self._remote_head()
        if remote is None:
            raise ArchiveStorageError("archive_remote_commit_unavailable")
        return remote

    def _commit_matches(
        self,
        commit_sha: str,
        *,
        archive: BuiltArchive,
        expected_parent_sha: str | None,
        expected_tree_sha: str,
    ) -> bool:
        try:
            self._signer.verify_commit(commit_sha)
            tree = self._git_object_id(("rev-parse", f"{commit_sha}^{{tree}}"), name="tree")
            parents = self._git_text(("show", "-s", "--format=%P", commit_sha))
            details = self._git(("show", "-s", "--format=%B%x00%aI", commit_sha)).stdout
            message_bytes, timestamp_bytes = details.rsplit(b"\x00", 1)
            timestamp = datetime.fromisoformat(timestamp_bytes.decode("ascii").strip())
            message = message_bytes.decode("utf-8")
        except (ArchiveStorageError, GitSigningError, ValueError, UnicodeDecodeError):
            return False
        expected_parents = "" if expected_parent_sha is None else expected_parent_sha
        return bool(
            tree == expected_tree_sha
            and parents == expected_parents
            and message == archive.commit_message
            and timestamp == archive.commit_timestamp
        )

    def _materialize(self, payload: ArchivePayload) -> None:
        for relative, content in payload.files.items():
            if relative != MANIFEST_PATH:
                from kivra_memory.archive.models import validate_archive_path

                validate_archive_path(relative)
            destination = self._config.repository / relative
            if not destination.resolve(strict=False).is_relative_to(
                self._config.repository.resolve(strict=True)
            ):
                raise ArchiveStorageError("archive_worktree_path_invalid")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink() or any(
                parent.is_symlink()
                for parent in destination.parents
                if parent.is_relative_to(self._config.repository)
            ):
                raise ArchiveStorageError("archive_worktree_path_invalid")
            temporary = destination.with_name(f".{destination.name}.scalevault.tmp")
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
            except OSError:
                with suppress(OSError):
                    temporary.unlink(missing_ok=True)
                raise ArchiveStorageError("archive_worktree_write_failed") from None
        self._git(("add", "--", *payload.files.keys()))

    def _empty_worktree(self) -> None:
        result = self._git(("ls-files", "-z"))
        try:
            tracked = tuple(item.decode("utf-8") for item in result.stdout.split(b"\x00") if item)
        except UnicodeDecodeError:
            raise ArchiveStorageError("archive_worktree_path_invalid") from None
        for relative in tracked:
            if relative != MANIFEST_PATH:
                from kivra_memory.archive.models import validate_archive_path

                try:
                    validate_archive_path(relative)
                except ValueError:
                    raise ArchiveStorageError("archive_worktree_path_invalid") from None
            path = self._config.repository / relative
            if path.is_symlink() or not path.is_file():
                raise ArchiveStorageError("archive_worktree_path_invalid")
        try:
            for relative in tracked:
                (self._config.repository / relative).unlink()
            parents = {
                parent
                for relative in tracked
                for parent in (self._config.repository / relative).parents
                if parent != self._config.repository
                and parent.is_relative_to(self._config.repository)
            }
            for parent in sorted(parents, key=lambda path: len(path.parts), reverse=True):
                with suppress(OSError):
                    parent.rmdir()
        except OSError:
            raise ArchiveStorageError("archive_worktree_write_failed") from None
        self._git(("read-tree", "--empty"))

    def _require_repository(self) -> None:
        repository = self._config.repository
        if (
            not repository.is_dir()
            or repository.is_symlink()
            or repository.resolve(strict=True) != repository
            or not (repository / ".git").is_dir()
            or (repository / ".git").is_symlink()
        ):
            raise ArchiveStorageError("archive_repository_unavailable")
        symbolic = self._git_text(("symbolic-ref", "HEAD"))
        if symbolic != f"refs/heads/{self._config.branch_name}":
            raise ArchiveStorageError("archive_branch_mismatch")

    def _require_clean_worktree(self) -> None:
        status = self._git(("status", "--porcelain=v1", "--untracked-files=all"))
        if status.stdout:
            raise ArchiveStorageError("archive_worktree_not_clean")

    def _local_head(self) -> str | None:
        result = self._git(
            ("rev-parse", "--verify", f"refs/heads/{self._config.branch_name}"),
            ok=(0, 1),
        )
        if result.returncode == 1:
            return None
        value = self._decode_object_id(result.stdout, "local head")
        return value

    def _remote_head(self) -> str | None:
        ref = f"refs/heads/{self._config.branch_name}"
        result = self._git(("ls-remote", "--heads", self._config.repository_reference, ref))
        if not result.stdout:
            return None
        try:
            line = result.stdout.decode("ascii").strip()
            value, returned_ref = line.split("\t", 1)
        except (UnicodeDecodeError, ValueError):
            raise ArchiveStorageError("archive_remote_identity_invalid") from None
        if returned_ref != ref:
            raise ArchiveStorageError("archive_remote_identity_invalid")
        self._require_object_id(value)
        return value

    def _git_object_id(self, arguments: tuple[str, ...], *, name: str) -> str:
        return self._decode_object_id(self._git(arguments).stdout, name)

    def _git_text(self, arguments: tuple[str, ...]) -> str:
        try:
            return self._git(arguments).stdout.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise ArchiveStorageError("archive_git_output_invalid") from None

    def _git(self, arguments: tuple[str, ...], *, ok: tuple[int, ...] = (0,)) -> ProcessResult:
        prefix = (
            str(self._config.signing.git_executable),
            "--no-pager",
            "--literal-pathspecs",
            "-C",
            str(self._config.repository),
            "-c",
            "core.hooksPath=/dev/null",
        )
        result = self._runner.run(
            (*prefix, *arguments),
            stdin=b"",
            environment=self._environment(),
            timeout_seconds=self._config.timeout_seconds,
        )
        if result.returncode not in ok:
            raise ArchiveStorageError("archive_git_operation_failed")
        return result

    def _environment(self) -> dict[str, str]:
        ssh_command = " ".join(
            (
                str(self._config.ssh_executable),
                "-F /dev/null",
                f"-i {self._config.deploy_key}",
                "-o IdentitiesOnly=yes",
                "-o BatchMode=yes",
                "-o StrictHostKeyChecking=yes",
                f"-o UserKnownHostsFile={self._config.known_hosts_file}",
            )
        )
        return {
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_SSH_COMMAND": ssh_command,
        }

    @staticmethod
    def _payload(archive: BuiltArchive) -> ArchivePayload:
        if not isinstance(archive.payload, ArchivePayload):
            raise ArchiveStorageError("archive_payload_invalid")
        manifest = archive.payload.files.get(archive.manifest_path)
        if manifest is None or hashlib.sha256(manifest).digest() != archive.manifest_sha256:
            raise ArchiveStorageError("archive_payload_invalid")
        return archive.payload

    @staticmethod
    def _require_object_id(value: str) -> None:
        if _OBJECT_ID.fullmatch(value) is None:
            raise ArchiveStorageError("archive_commit_identity_invalid")

    @classmethod
    def _decode_object_id(cls, value: bytes, name: str) -> str:
        try:
            decoded = value.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ArchiveStorageError(f"archive_{name.replace(' ', '_')}_invalid") from None
        cls._require_object_id(decoded)
        return decoded


__all__ = [
    "ArchivePayload",
    "DeterministicArchiveBuilder",
    "GitWorktreeArchiveRepository",
    "GitWorktreeConfig",
]
