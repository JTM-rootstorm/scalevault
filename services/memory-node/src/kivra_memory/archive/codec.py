"""Canonical CBOR and fixed-profile Zstandard snapshot encoding."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Self

import cbor2
import zstandard as zstd

SNAPSHOT_FORMAT: Final = "scalevault-snapshot-v1"
ZSTD_LEVEL: Final = 19
MAX_CBOR_DEPTH: Final = 64
MAX_CBOR_ITEMS: Final = 1_000_000
DEFAULT_MAX_COMPRESSED_SIZE: Final = 64 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_SIZE: Final = 512 * 1024 * 1024
_MAX_INT = (1 << 63) - 1
_MIN_INT = -(1 << 63)


class SnapshotCodecError(ValueError):
    """Raised when snapshot bytes violate the deterministic codec profile."""


@dataclass(frozen=True, slots=True)
class SnapshotLimits:
    """Allocation and structural ceilings applied before restore planning."""

    max_compressed_size: int = DEFAULT_MAX_COMPRESSED_SIZE
    max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE
    max_depth: int = MAX_CBOR_DEPTH
    max_items: int = MAX_CBOR_ITEMS

    def __post_init__(self) -> None:
        for field, value in (
            ("max_compressed_size", self.max_compressed_size),
            ("max_decompressed_size", self.max_decompressed_size),
            ("max_depth", self.max_depth),
            ("max_items", self.max_items),
        ):
            if isinstance(value, bool) or value < 1:
                raise ValueError(f"{field} must be a positive integer")


@dataclass(frozen=True, slots=True)
class SnapshotTable:
    """Rows sorted by an explicitly named primary-key tuple."""

    name: str
    primary_key: tuple[str, ...]
    rows: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "a").isalnum() or not self.name[0].isalpha():
            raise SnapshotCodecError("snapshot table name is invalid")
        if not self.primary_key or len(set(self.primary_key)) != len(self.primary_key):
            raise SnapshotCodecError("snapshot table primary key is empty or duplicated")
        for key in self.primary_key:
            if not key or not key.replace("_", "a").isalnum() or not key[0].isalpha():
                raise SnapshotCodecError("snapshot primary-key field is invalid")
        previous: bytes | None = None
        seen: set[bytes] = set()
        for row in self.rows:
            if not isinstance(row, Mapping) or any(not isinstance(key, str) for key in row):
                raise SnapshotCodecError("snapshot row must be an object with string field names")
            try:
                identity = tuple(row[key] for key in self.primary_key)
            except KeyError:
                raise SnapshotCodecError("snapshot row is missing a primary-key field") from None
            identity_bytes = canonical_cbor_bytes(identity)
            if identity_bytes in seen:
                raise SnapshotCodecError("snapshot table contains a duplicate primary key")
            if previous is not None and identity_bytes <= previous:
                raise SnapshotCodecError("snapshot rows are not sorted by primary key")
            seen.add(identity_bytes)
            previous = identity_bytes

    def value(self) -> dict[str, object]:
        return {
            "name": self.name,
            "primary_key": list(self.primary_key),
            "rows": [dict(row) for row in self.rows],
        }

    @classmethod
    def from_value(cls, value: object) -> Self:
        if not isinstance(value, Mapping) or set(value) != {"name", "primary_key", "rows"}:
            raise SnapshotCodecError("snapshot table fields are incomplete or unknown")
        name = value["name"]
        primary_key = value["primary_key"]
        rows = value["rows"]
        if not isinstance(name, str):
            raise SnapshotCodecError("snapshot table name must be a string")
        if not _array(primary_key) or any(not isinstance(item, str) for item in primary_key):
            raise SnapshotCodecError("snapshot primary key must be a non-empty string array")
        if not _array(rows):
            raise SnapshotCodecError("snapshot rows must be an array")
        normalized_rows: list[Mapping[str, object]] = []
        for row in rows:
            if not isinstance(row, Mapping) or any(not isinstance(key, str) for key in row):
                raise SnapshotCodecError("snapshot row must be an object")
            normalized_rows.append(row)
        return cls(name=name, primary_key=tuple(primary_key), rows=tuple(normalized_rows))


@dataclass(frozen=True, slots=True)
class SnapshotData:
    """Versioned deterministic recovery data at one committed event prefix."""

    high_water_sequence: int
    tables: tuple[SnapshotTable, ...]
    format: str = SNAPSHOT_FORMAT

    def __post_init__(self) -> None:
        if self.format != SNAPSHOT_FORMAT:
            raise SnapshotCodecError("snapshot format is unsupported")
        if isinstance(self.high_water_sequence, bool) or self.high_water_sequence < 0:
            raise SnapshotCodecError("snapshot high-water sequence must be non-negative")
        if tuple(sorted(self.tables, key=lambda table: table.name)) != self.tables:
            raise SnapshotCodecError("snapshot tables must be sorted by name")
        names = [table.name for table in self.tables]
        if len(names) != len(set(names)):
            raise SnapshotCodecError("snapshot contains duplicate table names")
        forbidden = {
            "archive_export_checkpoints",
            "archive_targets",
            "embeddings",
            "outbox",
            "credentials",
            "service_bindings",
        }
        if forbidden.intersection(names):
            raise SnapshotCodecError("snapshot contains an excluded operational table")

    @property
    def value(self) -> dict[str, object]:
        return {
            "format": self.format,
            "high_water_sequence": self.high_water_sequence,
            "tables": [table.value() for table in self.tables],
        }

    @classmethod
    def from_value(cls, value: object) -> Self:
        if not isinstance(value, Mapping) or set(value) != {
            "format",
            "high_water_sequence",
            "tables",
        }:
            raise SnapshotCodecError("snapshot fields are incomplete or unknown")
        format_value = value["format"]
        high_water = value["high_water_sequence"]
        tables = value["tables"]
        if not isinstance(format_value, str):
            raise SnapshotCodecError("snapshot format must be a string")
        if isinstance(high_water, bool) or not isinstance(high_water, int):
            raise SnapshotCodecError("snapshot high-water sequence must be an integer")
        if not _array(tables):
            raise SnapshotCodecError("snapshot tables must be an array")
        return cls(
            format=format_value,
            high_water_sequence=high_water,
            tables=tuple(SnapshotTable.from_value(table) for table in tables),
        )


def canonical_cbor_bytes(value: object, *, limits: SnapshotLimits | None = None) -> bytes:
    """Encode a value using the closed deterministic CBOR profile."""

    active_limits = limits or SnapshotLimits()
    _validate_cbor_value(value, active_limits)
    try:
        return cbor2.dumps(value, canonical=True)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise SnapshotCodecError("canonical CBOR encoding failed") from None


def decode_canonical_cbor(data: bytes, *, limits: SnapshotLimits | None = None) -> object:
    """Decode CBOR only when its original bytes are already canonical."""

    active_limits = limits or SnapshotLimits()
    if len(data) > active_limits.max_decompressed_size:
        raise SnapshotCodecError("CBOR data exceeds the decompressed size limit")
    try:
        value = cbor2.loads(data)
    except (ValueError, TypeError, RecursionError, cbor2.CBORDecodeError):
        raise SnapshotCodecError("CBOR data is invalid") from None
    _validate_cbor_value(value, active_limits)
    if canonical_cbor_bytes(value, limits=active_limits) != data:
        raise SnapshotCodecError("CBOR data is not in canonical deterministic form")
    return value


class SnapshotCodec:
    """Encode and verify the one accepted deterministic Zstandard profile."""

    def __init__(self, limits: SnapshotLimits | None = None) -> None:
        self._limits = limits or SnapshotLimits()

    def encode(self, snapshot: SnapshotData) -> bytes:
        """Encode one typed snapshot into canonical CBOR and fixed Zstandard bytes."""

        canonical = canonical_cbor_bytes(snapshot.value, limits=self._limits)
        if len(canonical) > self._limits.max_decompressed_size:
            raise SnapshotCodecError("snapshot exceeds the decompressed size limit")
        compressed = self._compress(canonical)
        if len(compressed) > self._limits.max_compressed_size:
            raise SnapshotCodecError("snapshot exceeds the compressed size limit")
        return compressed

    def decode(self, compressed: bytes) -> SnapshotData:
        """Verify frame limits/profile and return typed canonical snapshot data."""

        if len(compressed) > self._limits.max_compressed_size:
            raise SnapshotCodecError("snapshot exceeds the compressed size limit")
        if not compressed:
            raise SnapshotCodecError("snapshot is empty")
        try:
            parameters = zstd.get_frame_parameters(compressed)
        except zstd.ZstdError:
            raise SnapshotCodecError("snapshot is not a valid Zstandard frame") from None
        if parameters.content_size in {zstd.CONTENTSIZE_UNKNOWN, zstd.CONTENTSIZE_ERROR}:
            raise SnapshotCodecError("snapshot frame omits a valid content size")
        if parameters.content_size > self._limits.max_decompressed_size:
            raise SnapshotCodecError("snapshot declares excessive decompressed content")
        if not parameters.has_checksum or parameters.dict_id != 0:
            raise SnapshotCodecError("snapshot uses an unsupported Zstandard frame profile")
        try:
            canonical = zstd.ZstdDecompressor().decompress(
                compressed,
                max_output_size=self._limits.max_decompressed_size,
            )
        except zstd.ZstdError:
            raise SnapshotCodecError("snapshot decompression failed") from None
        if len(canonical) != parameters.content_size:
            raise SnapshotCodecError("snapshot content size does not match its frame")
        value = decode_canonical_cbor(canonical, limits=self._limits)
        snapshot = SnapshotData.from_value(value)
        if self._compress(canonical) != compressed:
            raise SnapshotCodecError("snapshot was not compressed with the fixed profile")
        return snapshot

    @staticmethod
    def _compress(canonical: bytes) -> bytes:
        compressor = zstd.ZstdCompressor(
            level=ZSTD_LEVEL,
            threads=0,
            write_checksum=True,
            write_content_size=True,
            write_dict_id=False,
        )
        return compressor.compress(canonical)


def _validate_cbor_value(value: object, limits: SnapshotLimits) -> None:
    active: set[int] = set()
    items = 0

    def visit(item: object, depth: int) -> None:
        nonlocal items
        items += 1
        if items > limits.max_items:
            raise SnapshotCodecError("CBOR value exceeds the item limit")
        if depth > limits.max_depth:
            raise SnapshotCodecError("CBOR value exceeds the nesting limit")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if not _MIN_INT <= item <= _MAX_INT:
                raise SnapshotCodecError("CBOR integer is outside the signed 64-bit profile")
            return
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise SnapshotCodecError("CBOR string contains a lone surrogate")
            return
        if isinstance(item, bytes):
            return
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                raise SnapshotCodecError("cyclic CBOR mappings are forbidden")
            if any(not isinstance(key, str) for key in item):
                raise SnapshotCodecError("CBOR map names must be strings")
            active.add(identity)
            try:
                for key, child in item.items():
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            identity = id(item)
            if identity in active:
                raise SnapshotCodecError("cyclic CBOR arrays are forbidden")
            active.add(identity)
            try:
                for child in item:
                    visit(child, depth + 1)
            finally:
                active.remove(identity)
            return
        raise SnapshotCodecError("CBOR value contains an unsupported type")

    visit(value, 0)


def _array(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
