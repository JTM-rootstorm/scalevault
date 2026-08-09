"""Manifest, file-set, and chain integrity tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from kivra_memory.archive.models import (
    ArchiveManifest,
    ArchiveValidationError,
    build_manifest,
    validate_archive_path,
)
from kivra_memory.archive.verification import (
    ArchiveBatch,
    ArchiveVerificationError,
    VerifiedArchiveBatch,
    parse_manifest,
    read_archive_directory,
    verify_manifest_chain,
)

SCHEMA_ID = "https://schemas.scalevault.dev/test.schema.json"
SCHEMA_PATH = "schemas/test.schema.json"
SCHEMA_BYTES = (
    b'{"$id":"https://schemas.scalevault.dev/test.schema.json",'
    b'"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}'
)
EXPORTED_AT = datetime(2026, 8, 9, 12, 30, 45, 123456, tzinfo=UTC)


def event_path(sequence: int) -> str:
    return f"events/2026/08/09/{sequence:012d}-019c0000-0000-7000-8000-{sequence:012x}.json"


def manifest(first: int, last: int, previous: str | None = None) -> ArchiveManifest:
    files = {SCHEMA_PATH: SCHEMA_BYTES}
    files.update((event_path(sequence), b"{}") for sequence in range(first, last + 1))
    return build_manifest(
        files=files,
        first_event_sequence=first,
        last_event_sequence=last,
        previous_manifest_sha256=previous,
        schema_ids={SCHEMA_ID: SCHEMA_PATH},
        exporter_version="1.0.0",
        exported_at=EXPORTED_AT,
    )


def verified(value: ArchiveManifest) -> VerifiedArchiveBatch:
    return VerifiedArchiveBatch(
        manifest=value,
        manifest_bytes=value.canonical_bytes,
        manifest_sha256=value.sha256,
        files={},
        events=(),
        snapshot=None,
    )


@pytest.mark.parametrize(
    "path",
    ["../events/a.json", "/events/a.json", "events//a.json", "events/./a.json", "x\\y"],
)
def test_archive_paths_reject_traversal_and_non_normalized_forms(path: str) -> None:
    with pytest.raises(ArchiveValidationError):
        validate_archive_path(path)


def test_manifest_bytes_are_deterministic_and_parser_requires_canonical_form() -> None:
    first = manifest(1, 1)
    second = manifest(1, 1)

    assert first.canonical_bytes == second.canonical_bytes
    assert first.sha256 == second.sha256
    assert parse_manifest(first.canonical_bytes) == first
    with pytest.raises(ArchiveVerificationError, match="not canonical"):
        parse_manifest(b" " + first.canonical_bytes)


def test_manifest_chain_rejects_hash_breaks_gaps_and_overlaps() -> None:
    first = manifest(1, 2)
    valid_second = manifest(3, 4, first.sha256)
    verify_manifest_chain((verified(first), verified(valid_second)))

    with pytest.raises(ArchiveVerificationError, match="hash chain"):
        verify_manifest_chain((verified(first), verified(manifest(3, 4, "0" * 64))))
    with pytest.raises(ArchiveVerificationError, match="gap or overlap"):
        verify_manifest_chain((verified(first), verified(manifest(4, 5, first.sha256))))
    with pytest.raises(ArchiveVerificationError, match="gap or overlap"):
        verify_manifest_chain((verified(first), verified(manifest(2, 3, first.sha256))))


def test_directory_reader_rejects_symlinks_and_hardlinks(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_bytes(b"{}")
    target = tmp_path / "target"
    target.write_bytes(b"x")
    (tmp_path / "linked").symlink_to(target)
    with pytest.raises(ArchiveVerificationError, match="symbolic link"):
        read_archive_directory(tmp_path)

    (tmp_path / "linked").unlink()
    (tmp_path / "hard").hardlink_to(target)
    with pytest.raises(ArchiveVerificationError, match="link or special"):
        read_archive_directory(tmp_path)


def test_archive_batch_is_an_exact_file_set() -> None:
    value = manifest(1, 1)
    batch = ArchiveBatch(manifest_bytes=value.canonical_bytes, files={})
    from kivra_memory.archive.verification import verify_archive_batch

    with pytest.raises(ArchiveVerificationError, match="missing or extra"):
        verify_archive_batch(batch)
