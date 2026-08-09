"""Determinism and hostile-input tests for archive snapshot encoding."""

from __future__ import annotations

import cbor2
import pytest
import zstandard as zstd
from kivra_memory.archive.codec import (
    SnapshotCodec,
    SnapshotCodecError,
    SnapshotData,
    SnapshotLimits,
    SnapshotTable,
    canonical_cbor_bytes,
    decode_canonical_cbor,
)


def snapshot() -> SnapshotData:
    return SnapshotData(
        high_water_sequence=2,
        tables=(
            SnapshotTable(
                name="memory_events",
                primary_key=("sequence",),
                rows=(
                    {"sequence": 1, "payload": b"one"},
                    {"payload": b"two", "sequence": 2},
                ),
            ),
        ),
    )


def test_snapshot_codec_is_byte_deterministic_and_round_trips() -> None:
    codec = SnapshotCodec()

    first = codec.encode(snapshot())
    second = codec.encode(snapshot())

    assert first == second
    assert codec.decode(first) == snapshot()
    parameters = zstd.get_frame_parameters(first)
    assert parameters.has_checksum
    assert parameters.content_size > 0
    assert parameters.dict_id == 0


def test_canonical_cbor_orders_maps_and_rejects_noncanonical_bytes() -> None:
    assert canonical_cbor_bytes({"z": 1, "a": 2}) == canonical_cbor_bytes({"a": 2, "z": 1})
    noncanonical = cbor2.dumps({"z": 1, "a": 2}, canonical=False)

    with pytest.raises(SnapshotCodecError, match="not in canonical"):
        decode_canonical_cbor(noncanonical)


@pytest.mark.parametrize("value", [1.5, cbor2.CBORTag(1, 0), {1: "integer key"}])
def test_canonical_cbor_rejects_floats_tags_and_non_string_map_keys(value: object) -> None:
    with pytest.raises(SnapshotCodecError, match=r"unsupported|names must be strings"):
        canonical_cbor_bytes(value)


def test_snapshot_codec_rejects_corruption_wrong_profile_and_limits() -> None:
    encoded = SnapshotCodec().encode(snapshot())
    corrupted = encoded[:-1] + bytes([encoded[-1] ^ 1])
    wrong_profile = zstd.ZstdCompressor(level=1, write_checksum=True).compress(
        canonical_cbor_bytes(snapshot().value)
    )

    with pytest.raises(SnapshotCodecError, match="decompression failed"):
        SnapshotCodec().decode(corrupted)
    with pytest.raises(SnapshotCodecError, match="fixed profile"):
        SnapshotCodec().decode(wrong_profile)
    with pytest.raises(SnapshotCodecError, match="compressed size limit"):
        SnapshotCodec(SnapshotLimits(max_compressed_size=len(encoded) - 1)).decode(encoded)
    with pytest.raises(SnapshotCodecError, match="declares excessive"):
        SnapshotCodec(SnapshotLimits(max_decompressed_size=1)).decode(encoded)


def test_snapshot_model_rejects_unsorted_or_duplicate_primary_keys() -> None:
    with pytest.raises(SnapshotCodecError, match="not sorted"):
        SnapshotTable(
            name="memory_events",
            primary_key=("sequence",),
            rows=({"sequence": 2}, {"sequence": 1}),
        )
    with pytest.raises(SnapshotCodecError, match="duplicate"):
        SnapshotTable(
            name="memory_events",
            primary_key=("sequence",),
            rows=({"sequence": 1}, {"sequence": 1}),
        )
