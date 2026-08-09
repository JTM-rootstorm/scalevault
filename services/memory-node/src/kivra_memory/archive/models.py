"""Canonical data contracts for deterministic archive batches."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Self

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.values import format_utc_datetime

ARCHIVE_FORMAT = "scalevault-archive-v1"
MANIFEST_SCHEMA_VERSION = 2
MANIFEST_PATH = "manifest.json"
MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_FILE_SIZE = 512 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 4 * 1024 * 1024 * 1024
MAX_SNAPSHOT_UNCOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
_SCHEMA_ID = re.compile(r"https://schemas\.scalevault\.dev/[A-Za-z0-9._-]{1,128}")
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_ARCHIVE_PATHS = (
    re.compile(r"archive-format\.json"),
    re.compile(
        rf"events/[0-9]{{4}}/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{{12}}-{_UUID}\.json"
    ),
    re.compile(r"projections/[a-z][a-z0-9_-]{0,63}(?:/[A-Za-z0-9._-]{1,128})*\.json"),
    re.compile(rf"lineages/{_UUID}/(?:lineage\.json|branches/{_UUID}\.json)"),
    re.compile(r"snapshots/snapshot-[0-9]{12}\.cbor\.zst"),
    re.compile(r"schemas/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json"),
)


class ArchiveValidationError(ValueError):
    """Raised when archive metadata is ambiguous, unsafe, or inconsistent."""


def require_sha256(value: str, field: str) -> str:
    """Validate a lowercase hexadecimal SHA-256 value."""

    if _SHA256.fullmatch(value) is None:
        raise ArchiveValidationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def validate_archive_path(path: str) -> str:
    """Validate one normalized relative path in the closed archive layout."""

    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ArchiveValidationError("archive path is not a normalized relative POSIX path")
    components = path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ArchiveValidationError("archive path contains a forbidden component")
    if not any(pattern.fullmatch(path) for pattern in _ARCHIVE_PATHS):
        raise ArchiveValidationError("archive path is outside the closed layout")
    return path


def event_sequence_from_path(path: str) -> int | None:
    """Return the event sequence encoded in an event path, if applicable."""

    validate_archive_path(path)
    if not path.startswith("events/"):
        return None
    sequence = int(path.rsplit("/", 1)[1].split("-", 1)[0])
    if sequence < 1:
        raise ArchiveValidationError("event sequence must be positive")
    return sequence


@dataclass(frozen=True, slots=True)
class ArchiveFile:
    """Identity and bounded size of one file covered by a manifest."""

    path: str
    sha256: str
    size: int
    media_type: str

    def __post_init__(self) -> None:
        validate_archive_path(self.path)
        require_sha256(self.sha256, "file sha256")
        if isinstance(self.size, bool) or not 0 <= self.size <= MAX_ARCHIVE_FILE_SIZE:
            raise ArchiveValidationError("archive file size is outside the accepted limit")
        if self.media_type != media_type_for_path(self.path):
            raise ArchiveValidationError("archive file media type does not match its path")

    def value(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
        }

    @classmethod
    def from_value(cls, value: object) -> Self:
        item = _strict_mapping(value, {"path", "sha256", "size", "media_type"}, "file")
        return cls(
            path=_string(item["path"], "file path"),
            sha256=_string(item["sha256"], "file sha256"),
            size=_integer(item["size"], "file size"),
            media_type=_string(item["media_type"], "file media type"),
        )


@dataclass(frozen=True, slots=True)
class SnapshotReference:
    """Manifest pointer to a deterministic recovery snapshot."""

    path: str
    high_water_sequence: int
    uncompressed_size: int

    def __post_init__(self) -> None:
        validate_archive_path(self.path)
        if not self.path.startswith("snapshots/"):
            raise ArchiveValidationError("snapshot path is outside the snapshot layout")
        if isinstance(self.high_water_sequence, bool) or self.high_water_sequence < 0:
            raise ArchiveValidationError("snapshot high-water sequence must be non-negative")
        encoded = int(self.path.removeprefix("snapshots/snapshot-").removesuffix(".cbor.zst"))
        if encoded != self.high_water_sequence:
            raise ArchiveValidationError("snapshot path and high-water sequence disagree")
        if (
            isinstance(self.uncompressed_size, bool)
            or not 1 <= self.uncompressed_size <= MAX_SNAPSHOT_UNCOMPRESSED_SIZE
        ):
            raise ArchiveValidationError("snapshot uncompressed size is outside the accepted limit")

    def value(self) -> dict[str, object]:
        return {
            "path": self.path,
            "high_water_sequence": self.high_water_sequence,
            "uncompressed_size": self.uncompressed_size,
        }

    @classmethod
    def from_value(cls, value: object) -> Self:
        item = _strict_mapping(
            value, {"path", "high_water_sequence", "uncompressed_size"}, "snapshot"
        )
        return cls(
            path=_string(item["path"], "snapshot path"),
            high_water_sequence=_integer(
                item["high_water_sequence"], "snapshot high-water sequence"
            ),
            uncompressed_size=_integer(item["uncompressed_size"], "snapshot uncompressed size"),
        )


@dataclass(frozen=True, slots=True)
class SchemaIdentity:
    """Exact checked-in schema identity used to validate a batch."""

    schema_id: str
    path: str
    sha256: str

    def __post_init__(self) -> None:
        if _SCHEMA_ID.fullmatch(self.schema_id) is None:
            raise ArchiveValidationError("schema identity is not a ScaleVault schema URI")
        validate_archive_path(self.path)
        if not self.path.startswith("schemas/"):
            raise ArchiveValidationError("schema path is outside the schema layout")
        require_sha256(self.sha256, "schema sha256")

    def value(self) -> dict[str, object]:
        return {"schema_id": self.schema_id, "path": self.path, "sha256": self.sha256}

    @classmethod
    def from_value(cls, value: object) -> Self:
        item = _strict_mapping(value, {"schema_id", "path", "sha256"}, "schema")
        return cls(
            schema_id=_string(item["schema_id"], "schema id"),
            path=_string(item["path"], "schema path"),
            sha256=_string(item["sha256"], "schema sha256"),
        )


@dataclass(frozen=True, slots=True)
class ArchiveManifest:
    """Validated canonical manifest for one gap-free event batch."""

    source_high_water_sequence: int
    first_event_sequence: int
    last_event_sequence: int
    event_count: int
    previous_manifest_sha256: str | None
    files: tuple[ArchiveFile, ...]
    schemas: tuple[SchemaIdentity, ...]
    exporter_version: str
    exported_at: str
    snapshot: SnapshotReference | None = None
    postgres_timeline_id: int | None = None
    archive_format: str = ARCHIVE_FORMAT
    schema_version: int = MANIFEST_SCHEMA_VERSION
    git_commit_sha: None = None

    def __post_init__(self) -> None:
        if self.archive_format != ARCHIVE_FORMAT or self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ArchiveValidationError("archive format or manifest schema version is unsupported")
        for name, value in (
            ("source high-water sequence", self.source_high_water_sequence),
            ("first event sequence", self.first_event_sequence),
            ("last event sequence", self.last_event_sequence),
            ("event count", self.event_count),
        ):
            if isinstance(value, bool) or value < 1:
                raise ArchiveValidationError(f"{name} must be positive")
        if self.last_event_sequence < self.first_event_sequence:
            raise ArchiveValidationError("event range is reversed")
        if self.event_count != self.last_event_sequence - self.first_event_sequence + 1:
            raise ArchiveValidationError("event count does not match the inclusive event range")
        if self.source_high_water_sequence != self.last_event_sequence:
            raise ArchiveValidationError("source high-water sequence must equal the final event")
        if self.previous_manifest_sha256 is not None:
            require_sha256(self.previous_manifest_sha256, "previous manifest sha256")
        if self.postgres_timeline_id is not None and (
            isinstance(self.postgres_timeline_id, bool)
            or not 1 <= self.postgres_timeline_id <= 0xFFFFFFFF
        ):
            raise ArchiveValidationError("PostgreSQL timeline ID is invalid")
        if not 1 <= len(self.files) <= MAX_ARCHIVE_FILES:
            raise ArchiveValidationError("archive file count is outside the accepted limit")
        if tuple(sorted(self.files, key=lambda item: item.path)) != self.files:
            raise ArchiveValidationError("archive files must be sorted by path")
        paths = [item.path for item in self.files]
        if len(paths) != len(set(paths)):
            raise ArchiveValidationError("archive manifest contains duplicate file paths")
        if sum(item.size for item in self.files) > MAX_ARCHIVE_TOTAL_SIZE:
            raise ArchiveValidationError("archive batch exceeds the total size limit")
        if (
            tuple(sorted(self.schemas, key=lambda item: (item.schema_id, item.path)))
            != self.schemas
        ):
            raise ArchiveValidationError("schema identities must be sorted")
        if not self.schemas:
            raise ArchiveValidationError("archive manifest must identify its checked-in schemas")
        schema_ids = [item.schema_id for item in self.schemas]
        schema_paths = [item.path for item in self.schemas]
        if len(schema_ids) != len(set(schema_ids)) or len(schema_paths) != len(set(schema_paths)):
            raise ArchiveValidationError("archive manifest contains duplicate schema identities")
        indexed_files = {item.path: item for item in self.files}
        for schema in self.schemas:
            file = indexed_files.get(schema.path)
            if file is None or file.sha256 != schema.sha256:
                raise ArchiveValidationError("schema identity is not backed by the same file hash")
        if self.snapshot is not None:
            file = indexed_files.get(self.snapshot.path)
            if file is None:
                raise ArchiveValidationError("snapshot reference is not present in the file list")
            if self.snapshot.high_water_sequence > self.source_high_water_sequence:
                raise ArchiveValidationError("snapshot is beyond the source high-water sequence")
        expected_events = set(range(self.first_event_sequence, self.last_event_sequence + 1))
        actual_events = {
            sequence
            for item in self.files
            if (sequence := event_sequence_from_path(item.path)) is not None
        }
        if actual_events != expected_events:
            raise ArchiveValidationError("event file paths do not exactly cover the manifest range")
        if _VERSION.fullmatch(self.exporter_version) is None:
            raise ArchiveValidationError("exporter version is invalid")
        try:
            parsed_exported_at = datetime.fromisoformat(self.exported_at.replace("Z", "+00:00"))
        except ValueError:
            raise ArchiveValidationError("export timestamp is invalid") from None
        if format_utc_datetime(parsed_exported_at) != self.exported_at:
            raise ArchiveValidationError("export timestamp is not in canonical UTC form")
        if self.git_commit_sha is not None:
            raise ArchiveValidationError("containing Git commit must be null in a manifest")

    @property
    def value(self) -> dict[str, object]:
        return {
            "archive_format": self.archive_format,
            "schema_version": self.schema_version,
            "source_high_water_sequence": self.source_high_water_sequence,
            "first_event_sequence": self.first_event_sequence,
            "last_event_sequence": self.last_event_sequence,
            "event_count": self.event_count,
            "previous_manifest_sha256": self.previous_manifest_sha256,
            "snapshot": None if self.snapshot is None else self.snapshot.value(),
            "files": [item.value() for item in self.files],
            "schemas": [item.value() for item in self.schemas],
            "exporter_version": self.exporter_version,
            "exported_at": self.exported_at,
            "postgres_timeline_id": self.postgres_timeline_id,
            "git_commit_sha": None,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.value)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def from_value(cls, value: object) -> Self:
        required = {
            "archive_format",
            "schema_version",
            "source_high_water_sequence",
            "first_event_sequence",
            "last_event_sequence",
            "event_count",
            "previous_manifest_sha256",
            "snapshot",
            "files",
            "schemas",
            "exporter_version",
            "exported_at",
            "postgres_timeline_id",
            "git_commit_sha",
        }
        item = _strict_mapping(value, required, "manifest")
        files = _sequence(item["files"], "files")
        schemas = _sequence(item["schemas"], "schemas")
        previous = item["previous_manifest_sha256"]
        if previous is not None and not isinstance(previous, str):
            raise ArchiveValidationError("previous manifest sha256 must be a string or null")
        snapshot = item["snapshot"]
        postgres_timeline_id = item["postgres_timeline_id"]
        if postgres_timeline_id is not None and (
            isinstance(postgres_timeline_id, bool) or not isinstance(postgres_timeline_id, int)
        ):
            raise ArchiveValidationError("PostgreSQL timeline ID must be an integer or null")
        if item["git_commit_sha"] is not None:
            raise ArchiveValidationError("git commit sha must be null")
        return cls(
            archive_format=_string(item["archive_format"], "archive format"),
            schema_version=_integer(item["schema_version"], "schema version"),
            source_high_water_sequence=_integer(
                item["source_high_water_sequence"], "source high-water sequence"
            ),
            first_event_sequence=_integer(item["first_event_sequence"], "first event sequence"),
            last_event_sequence=_integer(item["last_event_sequence"], "last event sequence"),
            event_count=_integer(item["event_count"], "event count"),
            previous_manifest_sha256=previous,
            snapshot=None if snapshot is None else SnapshotReference.from_value(snapshot),
            files=tuple(ArchiveFile.from_value(entry) for entry in files),
            schemas=tuple(SchemaIdentity.from_value(entry) for entry in schemas),
            exporter_version=_string(item["exporter_version"], "exporter version"),
            exported_at=_string(item["exported_at"], "export timestamp"),
            postgres_timeline_id=postgres_timeline_id,
        )


def build_manifest(
    *,
    files: Mapping[str, bytes],
    first_event_sequence: int,
    last_event_sequence: int,
    previous_manifest_sha256: str | None,
    schema_ids: Mapping[str, str],
    exporter_version: str,
    exported_at: datetime,
    snapshot_high_water_sequence: int | None = None,
    snapshot_uncompressed_size: int | None = None,
    postgres_timeline_id: int | None = None,
) -> ArchiveManifest:
    """Build a manifest solely from explicit deterministic export inputs."""

    records = tuple(
        ArchiveFile(
            path=path,
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            media_type=media_type_for_path(path),
        )
        for path, content in sorted(files.items())
    )
    indexed = {item.path: item for item in records}
    schemas = tuple(
        sorted(
            (
                SchemaIdentity(schema_id=schema_id, path=path, sha256=indexed[path].sha256)
                for schema_id, path in schema_ids.items()
                if path in indexed
            ),
            key=lambda item: (item.schema_id, item.path),
        )
    )
    if len(schemas) != len(schema_ids):
        raise ArchiveValidationError("schema identity references a missing archive file")
    snapshot: SnapshotReference | None = None
    if snapshot_high_water_sequence is not None or snapshot_uncompressed_size is not None:
        if snapshot_high_water_sequence is None or snapshot_uncompressed_size is None:
            raise ArchiveValidationError("snapshot metadata must be supplied together")
        snapshot = SnapshotReference(
            path=f"snapshots/snapshot-{snapshot_high_water_sequence:012d}.cbor.zst",
            high_water_sequence=snapshot_high_water_sequence,
            uncompressed_size=snapshot_uncompressed_size,
        )
    return ArchiveManifest(
        source_high_water_sequence=last_event_sequence,
        first_event_sequence=first_event_sequence,
        last_event_sequence=last_event_sequence,
        event_count=last_event_sequence - first_event_sequence + 1,
        previous_manifest_sha256=previous_manifest_sha256,
        files=records,
        schemas=schemas,
        exporter_version=exporter_version,
        exported_at=format_utc_datetime(exported_at),
        snapshot=snapshot,
        postgres_timeline_id=postgres_timeline_id,
    )


def media_type_for_path(path: str) -> str:
    """Return the single accepted media type for a closed-layout path."""

    validate_archive_path(path)
    if path.startswith("schemas/"):
        return "application/schema+json"
    if path.startswith("snapshots/"):
        return "application/cbor+zstd"
    return "application/json"


def _strict_mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ArchiveValidationError(f"{name} must be an object")
    if set(value) != fields:
        raise ArchiveValidationError(f"{name} fields are incomplete or unknown")
    return value


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ArchiveValidationError(f"{name} must be an array")
    return value


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ArchiveValidationError(f"{name} must be a string")
    return value


def _integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArchiveValidationError(f"{name} must be an integer")
    return value
