"""Content, filesystem, and manifest-chain verification for recovery archives."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator, SchemaError  # type: ignore[import-untyped]

from kivra_memory.archive.codec import SnapshotCodec, SnapshotData, SnapshotLimits
from kivra_memory.archive.git import (
    GitCommitSigner,
    GitSigningError,
    VerifiedGitCommit,
    archive_commit_message,
)
from kivra_memory.archive.models import (
    MANIFEST_PATH,
    MAX_ARCHIVE_FILE_SIZE,
    MAX_ARCHIVE_FILES,
    MAX_ARCHIVE_TOTAL_SIZE,
    ArchiveManifest,
    ArchiveValidationError,
    event_sequence_from_path,
)
from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.errors import CanonicalJsonError
from kivra_memory.domain.events import MemoryEvent


class ArchiveVerificationError(ValueError):
    """Raised when untrusted archive bytes fail closed verification."""


@dataclass(frozen=True, slots=True)
class ArchiveBatch:
    """Untrusted manifest bytes and the exact file set claimed by one batch."""

    manifest_bytes: bytes
    files: Mapping[str, bytes]


@dataclass(frozen=True, slots=True)
class ArchiveCommitBatch:
    """Untrusted association between one Git commit and its claimed archive batch."""

    commit_sha: str
    batch: ArchiveBatch


@dataclass(frozen=True, slots=True)
class VerifiedArchiveBatch:
    """Fully byte-verified immutable inputs safe to use for restore planning."""

    manifest: ArchiveManifest
    manifest_bytes: bytes
    manifest_sha256: str
    files: Mapping[str, bytes]
    events: tuple[MemoryEvent, ...]
    snapshot: SnapshotData | None


@dataclass(frozen=True, slots=True)
class VerifiedArchiveCommit:
    """One exact signed Git commit paired with its byte-verified archive batch."""

    git: VerifiedGitCommit
    batch: VerifiedArchiveBatch


@dataclass(frozen=True, slots=True)
class VerifiedArchive:
    """Complete signed first-parent archive chain accepted for restore planning."""

    commits: tuple[VerifiedArchiveCommit, ...]

    def __post_init__(self) -> None:
        if not self.commits:
            raise ValueError("verified archive chain must not be empty")
        expected_parent_sha: str | None = None
        for commit in self.commits:
            if commit.git.parent_sha != expected_parent_sha:
                raise ValueError("verified archive Git chain is inconsistent")
            expected_parent_sha = commit.git.commit_sha
        try:
            verify_manifest_chain(self.batches)
        except ArchiveVerificationError:
            raise ValueError("verified archive manifest chain is inconsistent") from None

    @property
    def batches(self) -> tuple[VerifiedArchiveBatch, ...]:
        """Return byte-verified batches in signed first-parent order."""

        return tuple(commit.batch for commit in self.commits)


@dataclass(frozen=True, slots=True)
class ArchiveReadLimits:
    """Resource ceilings applied before untrusted directory file allocation."""

    max_files: int = MAX_ARCHIVE_FILES + 1
    max_file_size: int = MAX_ARCHIVE_FILE_SIZE
    max_total_size: int = MAX_ARCHIVE_TOTAL_SIZE
    max_depth: int = 16
    max_entries: int = MAX_ARCHIVE_FILES * 2 + 64

    def __post_init__(self) -> None:
        for name, value in (
            ("max_files", self.max_files),
            ("max_file_size", self.max_file_size),
            ("max_total_size", self.max_total_size),
            ("max_depth", self.max_depth),
            ("max_entries", self.max_entries),
        ):
            if isinstance(value, bool) or value < 1:
                raise ValueError(f"archive read {name} must be positive")


def parse_manifest(document: bytes) -> ArchiveManifest:
    """Parse and prove the exact canonical bytes of an archive manifest."""

    try:
        value = parse_json_strict(document)
        manifest = ArchiveManifest.from_value(value)
    except (CanonicalJsonError, ArchiveValidationError):
        raise ArchiveVerificationError("archive manifest is invalid") from None
    if manifest.canonical_bytes != document:
        raise ArchiveVerificationError("archive manifest bytes are not canonical")
    return manifest


def verify_archive_batch(
    batch: ArchiveBatch,
    *,
    snapshot_limits: SnapshotLimits | None = None,
) -> VerifiedArchiveBatch:
    """Verify every claimed byte, schema, event, and snapshot in one batch."""

    manifest = parse_manifest(batch.manifest_bytes)
    expected_paths = {entry.path for entry in manifest.files}
    if set(batch.files) != expected_paths:
        raise ArchiveVerificationError("archive file set has missing or extra paths")

    indexed = {entry.path: entry for entry in manifest.files}
    for path, content in batch.files.items():
        try:
            entry = indexed[path]
        except (KeyError, TypeError):
            raise ArchiveVerificationError("archive contains an unmanifested path") from None
        if not isinstance(content, bytes):
            raise ArchiveVerificationError("archive file content must be immutable bytes")
        if len(content) != entry.size:
            raise ArchiveVerificationError("archive file size mismatch")
        digest = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(digest, entry.sha256):
            raise ArchiveVerificationError("archive file SHA-256 mismatch")

    schemas = _verify_schemas(manifest, batch.files)
    event_schema = next(
        (
            schema
            for schema_id, schema in schemas.items()
            if schema_id.endswith("/memory-event.schema.json")
        ),
        None,
    )
    events: list[MemoryEvent] = []
    for path in sorted(expected_paths):
        if (
            path.startswith(("events/", "projections/", "lineages/"))
            or path == "archive-format.json"
        ):
            parsed = _canonical_json_file(batch.files[path], path)
            if path.startswith("events/"):
                if event_schema is not None:
                    try:
                        Draft202012Validator(event_schema).validate(parsed)
                    except Exception as error:
                        if error.__class__.__module__.startswith("referencing"):
                            pass
                        else:
                            raise ArchiveVerificationError(
                                "archive event failed its checked-in JSON schema"
                            ) from None
                try:
                    event = MemoryEvent.model_validate(parsed)
                except (TypeError, ValueError):
                    raise ArchiveVerificationError("archive event contract is invalid") from None
                if event_sequence_from_path(path) != event.sequence:
                    raise ArchiveVerificationError("event path and envelope sequence disagree")
                events.append(event)

    expected_sequences = list(
        range(manifest.first_event_sequence, manifest.last_event_sequence + 1)
    )
    if [event.sequence for event in events] != expected_sequences:
        raise ArchiveVerificationError("archive event envelopes are not gap-free")

    snapshot: SnapshotData | None = None
    if manifest.snapshot is not None:
        codec = SnapshotCodec(snapshot_limits)
        snapshot_bytes = batch.files[manifest.snapshot.path]
        snapshot = codec.decode(snapshot_bytes)
        if snapshot.high_water_sequence != manifest.snapshot.high_water_sequence:
            raise ArchiveVerificationError("snapshot and manifest high-water sequences disagree")
        try:
            import zstandard as zstd

            actual_size = zstd.frame_content_size(snapshot_bytes)
        except zstd.ZstdError:
            raise ArchiveVerificationError("snapshot frame size is invalid") from None
        if actual_size != manifest.snapshot.uncompressed_size:
            raise ArchiveVerificationError("snapshot uncompressed size does not match manifest")

    return VerifiedArchiveBatch(
        manifest=manifest,
        manifest_bytes=batch.manifest_bytes,
        manifest_sha256=hashlib.sha256(batch.manifest_bytes).hexdigest(),
        files=dict(batch.files),
        events=tuple(events),
        snapshot=snapshot,
    )


def verify_manifest_chain(
    batches: Sequence[VerifiedArchiveBatch],
    *,
    require_genesis: bool = True,
    expected_previous_manifest_sha256: str | None = None,
    expected_first_event_sequence: int | None = None,
) -> None:
    """Verify manifest hash links and exact inclusive event-range continuity."""

    if not batches:
        raise ArchiveVerificationError("archive manifest chain is empty")
    first = batches[0].manifest
    if require_genesis:
        if first.previous_manifest_sha256 is not None or first.first_event_sequence != 1:
            raise ArchiveVerificationError("archive chain does not begin at genesis")
    else:
        if first.previous_manifest_sha256 != expected_previous_manifest_sha256:
            raise ArchiveVerificationError("archive chain starts from the wrong manifest")
        if (
            expected_first_event_sequence is not None
            and first.first_event_sequence != expected_first_event_sequence
        ):
            raise ArchiveVerificationError("archive chain starts from the wrong event sequence")

    previous = batches[0]
    for current in batches[1:]:
        if current.manifest.previous_manifest_sha256 != previous.manifest_sha256:
            raise ArchiveVerificationError("archive manifest hash chain is broken")
        if current.manifest.first_event_sequence != previous.manifest.last_event_sequence + 1:
            raise ArchiveVerificationError("archive event ranges contain a gap or overlap")
        if (
            current.manifest.source_high_water_sequence
            <= previous.manifest.source_high_water_sequence
        ):
            raise ArchiveVerificationError("archive source high-water sequence did not advance")
        previous = current


def verify_signed_archive(
    commits: Sequence[ArchiveCommitBatch],
    signer: GitCommitSigner,
    *,
    snapshot_limits: SnapshotLimits | None = None,
) -> VerifiedArchive:
    """Verify the complete signed first-parent chain and every batch identity."""

    candidates = tuple(commits)
    if not candidates:
        raise ArchiveVerificationError("signed archive chain is empty")
    verified_commits: list[VerifiedArchiveCommit] = []
    expected_parent_sha: str | None = None
    try:
        for candidate in candidates:
            verified_batch = verify_archive_batch(
                candidate.batch,
                snapshot_limits=snapshot_limits,
            )
            expected_files = {
                MANIFEST_PATH: verified_batch.manifest_bytes,
                **verified_batch.files,
            }
            verified_git = signer.verify_archive_commit(
                candidate.commit_sha,
                expected_parent_sha=expected_parent_sha,
                expected_message=archive_commit_message(
                    verified_batch.manifest.first_event_sequence,
                    verified_batch.manifest.last_event_sequence,
                ),
                expected_timestamp=verified_batch.manifest.exported_at,
                expected_files=expected_files,
            )
            verified_commits.append(VerifiedArchiveCommit(git=verified_git, batch=verified_batch))
            expected_parent_sha = verified_git.commit_sha
    except GitSigningError:
        raise ArchiveVerificationError("archive Git chain failed verification") from None

    verified_batches = tuple(commit.batch for commit in verified_commits)
    verify_manifest_chain(verified_batches)
    return VerifiedArchive(commits=tuple(verified_commits))


def read_archive_directory(
    root: Path,
    *,
    manifest_name: str = MANIFEST_PATH,
    limits: ArchiveReadLimits | None = None,
) -> ArchiveBatch:
    """Read one bounded batch through pinned directory and file descriptors."""

    _validate_manifest_name(manifest_name)
    active_limits = limits or ArchiveReadLimits()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_descriptor = os.open(root, flags)
    except OSError:
        raise ArchiveVerificationError("archive root must be a real directory") from None
    discovered: dict[str, bytes] = {}
    state = _DirectoryReadState()
    try:
        root_stat = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ArchiveVerificationError("archive root must be a real directory")
        _read_directory_descriptor(
            root_descriptor,
            prefix=(),
            depth=0,
            limits=active_limits,
            state=state,
            discovered=discovered,
        )
    finally:
        os.close(root_descriptor)
    try:
        manifest_bytes = discovered.pop(manifest_name)
    except KeyError:
        raise ArchiveVerificationError("archive manifest file is missing") from None
    return ArchiveBatch(manifest_bytes=manifest_bytes, files=discovered)


def _verify_schemas(
    manifest: ArchiveManifest,
    files: Mapping[str, bytes],
) -> dict[str, object]:
    schemas: dict[str, object] = {}
    for identity in manifest.schemas:
        try:
            value = parse_json_strict(files[identity.path])
        except CanonicalJsonError:
            raise ArchiveVerificationError("checked-in archive schema is invalid JSON") from None
        if not isinstance(value, Mapping) or value.get("$id") != identity.schema_id:
            raise ArchiveVerificationError("checked-in archive schema identity mismatch")
        try:
            Draft202012Validator.check_schema(value)
        except SchemaError:
            raise ArchiveVerificationError("checked-in archive JSON schema is invalid") from None
        schemas[identity.schema_id] = value
    return schemas


def _canonical_json_file(document: bytes, path: str) -> object:
    try:
        value = parse_json_strict(document)
        canonical = canonical_json_bytes(value)
    except CanonicalJsonError:
        raise ArchiveVerificationError(f"archive JSON file is invalid: {path}") from None
    if canonical != document:
        raise ArchiveVerificationError(f"archive JSON file is not canonical: {path}")
    return value


@dataclass(slots=True)
class _DirectoryReadState:
    entry_count: int = 0
    file_count: int = 0
    total_size: int = 0


def _read_directory_descriptor(
    directory_descriptor: int,
    *,
    prefix: tuple[str, ...],
    depth: int,
    limits: ArchiveReadLimits,
    state: _DirectoryReadState,
    discovered: dict[str, bytes],
) -> None:
    if depth > limits.max_depth:
        raise ArchiveVerificationError("archive directory depth exceeds the accepted limit")
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                name = entry.name
                if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                    raise ArchiveVerificationError("archive directory entry name is invalid")
                _read_directory_entry(
                    directory_descriptor,
                    name=name,
                    prefix=prefix,
                    depth=depth,
                    limits=limits,
                    state=state,
                    discovered=discovered,
                )
    except ArchiveVerificationError:
        raise
    except OSError:
        raise ArchiveVerificationError("archive directory could not be enumerated") from None


def _read_directory_entry(
    directory_descriptor: int,
    *,
    name: str,
    prefix: tuple[str, ...],
    depth: int,
    limits: ArchiveReadLimits,
    state: _DirectoryReadState,
    discovered: dict[str, bytes],
) -> None:
    state.entry_count += 1
    if state.entry_count > limits.max_entries:
        raise ArchiveVerificationError("archive entry count exceeds the accepted limit")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError:
        raise ArchiveVerificationError(
            "archive contains a symbolic link or unreadable entry"
        ) from None
    try:
        initial = os.fstat(descriptor)
        if stat.S_ISDIR(initial.st_mode):
            _read_directory_descriptor(
                descriptor,
                prefix=(*prefix, name),
                depth=depth + 1,
                limits=limits,
                state=state,
                discovered=discovered,
            )
            return
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise ArchiveVerificationError("archive contains a link or special file")
        state.file_count += 1
        if state.file_count > limits.max_files:
            raise ArchiveVerificationError("archive file count exceeds the accepted limit")
        if initial.st_size < 0 or initial.st_size > limits.max_file_size:
            raise ArchiveVerificationError("archive file size exceeds the accepted limit")
        if state.total_size + initial.st_size > limits.max_total_size:
            raise ArchiveVerificationError("archive total size exceeds the accepted limit")
        content = _read_regular_file(descriptor, initial.st_size)
        final = os.fstat(descriptor)
        if (
            final.st_dev != initial.st_dev
            or final.st_ino != initial.st_ino
            or final.st_mode != initial.st_mode
            or final.st_nlink != initial.st_nlink
            or final.st_size != initial.st_size
            or final.st_mtime_ns != initial.st_mtime_ns
            or final.st_ctime_ns != initial.st_ctime_ns
        ):
            raise ArchiveVerificationError("archive file changed while it was read")
        state.total_size += len(content)
        relative = "/".join((*prefix, name))
        discovered[relative] = content
    finally:
        os.close(descriptor)


def _read_regular_file(descriptor: int, expected_size: int) -> bytes:
    content = bytearray()
    try:
        while len(content) < expected_size:
            chunk = os.read(descriptor, min(64 * 1024, expected_size - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        extra = os.read(descriptor, 1)
    except OSError:
        raise ArchiveVerificationError("archive file could not be read") from None
    if len(content) != expected_size or extra:
        raise ArchiveVerificationError("archive file changed while it was read")
    return bytes(content)


def _validate_manifest_name(manifest_name: str) -> None:
    if (
        not manifest_name
        or manifest_name in {".", ".."}
        or "/" in manifest_name
        or "\\" in manifest_name
        or "\x00" in manifest_name
    ):
        raise ValueError("archive manifest name must be one relative path component")
