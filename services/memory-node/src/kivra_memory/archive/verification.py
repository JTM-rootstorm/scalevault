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
from kivra_memory.archive.models import (
    MANIFEST_PATH,
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
class VerifiedArchiveBatch:
    """Fully byte-verified immutable inputs safe to use for restore planning."""

    manifest: ArchiveManifest
    manifest_bytes: bytes
    manifest_sha256: str
    files: Mapping[str, bytes]
    events: tuple[MemoryEvent, ...]
    snapshot: SnapshotData | None


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


def read_archive_directory(root: Path, *, manifest_name: str = MANIFEST_PATH) -> ArchiveBatch:
    """Read an exact batch directory without following or accepting links."""

    try:
        root_stat = root.lstat()
    except OSError:
        raise ArchiveVerificationError("archive directory is unavailable") from None
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ArchiveVerificationError("archive root must be a real directory")

    discovered: dict[str, bytes] = {}
    for path, path_stat in _walk_without_links(root):
        relative = path.relative_to(root).as_posix()
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
            raise ArchiveVerificationError("archive contains a link or special file")
        try:
            discovered[relative] = path.read_bytes()
        except OSError:
            raise ArchiveVerificationError("archive file could not be read") from None
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


def _walk_without_links(root: Path) -> list[tuple[Path, os.stat_result]]:
    pending = [root]
    files: list[tuple[Path, os.stat_result]] = []
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            raise ArchiveVerificationError("archive directory could not be enumerated") from None
        for entry in entries:
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                raise ArchiveVerificationError("archive entry could not be inspected") from None
            path = Path(entry.path)
            if stat.S_ISLNK(entry_stat.st_mode):
                raise ArchiveVerificationError("archive contains a symbolic link")
            if stat.S_ISDIR(entry_stat.st_mode):
                pending.append(path)
            else:
                files.append((path, entry_stat))
    return files
