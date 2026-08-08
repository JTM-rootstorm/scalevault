"""Tests for exact Genesis snapshot provenance and manifest determinism."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from kivra_memory.ingress.snapshot import (
    GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT,
    GENESIS_SOURCE_REPOSITORY,
    GENESIS_SOURCE_SNAPSHOT_COMMIT,
    GenesisSnapshotSource,
    GitTreeEntry,
    ImportPlanManifest,
    LocalGitObjectReader,
    ManifestError,
    PlannedImportRecord,
    SnapshotError,
    SnapshotSourceItem,
    SourceContract,
    build_import_plan_manifest,
)

PROPOSAL_PATH = (
    "ingress/v1/019c0000-0000-7000-8000-000000000001/2026/08/"
    "019c0000-0000-7000-8000-000000000002.json"
)
CHECKPOINT_V1_PATH = "ingress/checkpoints/v1/genesis/2026/08/genesis-v1-001.json"
CHECKPOINT_V2_PATH = "ingress/checkpoints/v2/genesis/2026/08/genesis-v2-001.json"
POST_PIN_PATH = "ingress/checkpoints/v2/genesis/2026/08/post-freeze-authorization.json"


def _blob_sha(raw: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()


@dataclass
class StubReader:
    trees: dict[str, tuple[GitTreeEntry, ...]]
    blobs: dict[str, bytes]
    resolved: str = GENESIS_SOURCE_SNAPSHOT_COMMIT
    calls: list[tuple[str, str]] = field(default_factory=list)

    def resolve_commit(self, commit: str) -> str:
        self.calls.append(("resolve_commit", commit))
        return self.resolved

    def list_tree(self, commit: str) -> tuple[GitTreeEntry, ...]:
        self.calls.append(("list_tree", commit))
        return self.trees[commit]

    def read_blob(self, blob_sha: str) -> bytes:
        self.calls.append(("read_blob", blob_sha))
        return self.blobs[blob_sha]


def _reader(entries: dict[str, bytes]) -> StubReader:
    tree = tuple(GitTreeEntry(path=path, blob_sha=_blob_sha(raw)) for path, raw in entries.items())
    return StubReader(
        trees={GENESIS_SOURCE_SNAPSHOT_COMMIT: tree},
        blobs={_blob_sha(raw): raw for raw in entries.values()},
    )


def test_enumerates_only_live_contract_paths_from_literal_authorized_commit() -> None:
    raw_proposal = b'{"proposal":"synthetic"}\n'
    raw_v1 = b'{"checkpoint":"synthetic-v1"}\n'
    raw_v2 = b'{"checkpoint":"synthetic-v2"}\n'
    reader = _reader(
        {
            "README.md": b"not source input",
            "docs/GENESIS_CHECKPOINT_V2.md": b"not source input",
            "schemas/genesis-checkpoint-v2.schema.json": b"{}",
            "examples/checkpoint.json": b"{}",
            "fixtures/checkpoint.json": b"{}",
            PROPOSAL_PATH: raw_proposal,
            CHECKPOINT_V1_PATH: raw_v1,
            CHECKPOINT_V2_PATH: raw_v2,
        }
    )

    items = GenesisSnapshotSource(reader).enumerate()

    assert [item.source_path for item in items] == [
        CHECKPOINT_V1_PATH,
        CHECKPOINT_V2_PATH,
        PROPOSAL_PATH,
    ]
    assert [item.source_contract for item in items] == [
        SourceContract.CHECKPOINT_V1,
        SourceContract.CHECKPOINT_V2,
        SourceContract.PROPOSAL_V1,
    ]
    assert all(item.source_repository == GENESIS_SOURCE_REPOSITORY for item in items)
    assert all(item.source_snapshot_commit == GENESIS_SOURCE_SNAPSHOT_COMMIT for item in items)
    assert {item.source_path: item.raw_bytes for item in items}[CHECKPOINT_V2_PATH] == raw_v2
    assert reader.calls[:2] == [
        ("resolve_commit", GENESIS_SOURCE_SNAPSHOT_COMMIT),
        ("list_tree", GENESIS_SOURCE_SNAPSHOT_COMMIT),
    ]
    assert all(GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT not in call for call in reader.calls)


def test_post_pin_tree_cannot_widen_the_authorized_import_set() -> None:
    pinned_raw = b'{"checkpoint":"pinned"}'
    post_pin_raw = b'{"authorization":"not-source"}'
    reader = StubReader(
        trees={
            GENESIS_SOURCE_SNAPSHOT_COMMIT: (
                GitTreeEntry(CHECKPOINT_V2_PATH, _blob_sha(pinned_raw)),
            ),
            GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT: (
                GitTreeEntry(CHECKPOINT_V2_PATH, _blob_sha(pinned_raw)),
                GitTreeEntry(POST_PIN_PATH, _blob_sha(post_pin_raw)),
            ),
        },
        blobs={_blob_sha(pinned_raw): pinned_raw, _blob_sha(post_pin_raw): post_pin_raw},
    )

    items = GenesisSnapshotSource(reader).enumerate()

    assert [item.source_path for item in items] == [CHECKPOINT_V2_PATH]
    assert ("list_tree", GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT) not in reader.calls
    assert _blob_sha(post_pin_raw) not in {item.source_git_blob_sha for item in items}


def test_rejects_resolved_commit_other_than_the_authorized_pin_before_tree_read() -> None:
    reader = StubReader(trees={}, blobs={}, resolved=GENESIS_POST_FREEZE_AUTHORIZATION_COMMIT)

    with pytest.raises(SnapshotError, match="authorized pin"):
        GenesisSnapshotSource(reader).enumerate()

    assert reader.calls == [("resolve_commit", GENESIS_SOURCE_SNAPSHOT_COMMIT)]


def test_rejects_blob_bytes_that_do_not_match_tree_provenance() -> None:
    declared = b'{"checkpoint":"declared"}'
    substituted = b'{"checkpoint":"substituted"}'
    declared_sha = _blob_sha(declared)
    reader = StubReader(
        trees={
            GENESIS_SOURCE_SNAPSHOT_COMMIT: (GitTreeEntry(CHECKPOINT_V2_PATH, declared_sha),)
        },
        blobs={declared_sha: substituted},
    )

    with pytest.raises(SnapshotError, match="did not match Git provenance"):
        GenesisSnapshotSource(reader).enumerate()


def test_rejects_unknown_path_inside_ingress_tree_instead_of_silent_omission() -> None:
    reader = _reader({"ingress/checkpoints/v3/genesis/2026/08/unknown.json": b"{}"})

    with pytest.raises(SnapshotError, match="unknown ingress source path"):
        GenesisSnapshotSource(reader).enumerate()


def test_local_git_reader_reads_an_exact_commit_not_head(tmp_path: Path) -> None:
    repository = tmp_path / "source"
    repository.mkdir()

    def git(*arguments: str) -> bytes:
        return subprocess.run(
            ("git", "-C", str(repository), *arguments),
            check=True,
            capture_output=True,
        ).stdout

    git("init", "-q")
    git("config", "user.name", "Synthetic Test")
    git("config", "user.email", "synthetic@example.invalid")
    git("config", "commit.gpgsign", "false")
    source = repository / "source.json"
    pinned_raw = b'{"synthetic":"pinned"}\n'
    source.write_bytes(pinned_raw)
    git("add", "source.json")
    git("commit", "-q", "-m", "pinned")
    pinned_commit = git("rev-parse", "HEAD").decode().strip()

    source.write_bytes(b'{"synthetic":"post-pin"}\n')
    git("commit", "-q", "-am", "post-pin")

    reader = LocalGitObjectReader(repository)
    entries = reader.list_tree(pinned_commit)

    assert reader.resolve_commit(pinned_commit) == pinned_commit
    assert entries == (GitTreeEntry(path="source.json", blob_sha=_blob_sha(pinned_raw)),)
    assert reader.read_blob(entries[0].blob_sha) == pinned_raw


def _source_item(
    path: str = CHECKPOINT_V2_PATH, raw: bytes = b'{"synthetic":true}'
) -> SnapshotSourceItem:
    contract = SourceContract.CHECKPOINT_V2
    source_id = "genesis-v2-001"
    return SnapshotSourceItem(
        source_repository=GENESIS_SOURCE_REPOSITORY,
        source_snapshot_commit=GENESIS_SOURCE_SNAPSHOT_COMMIT,
        source_path=path,
        source_git_blob_sha=_blob_sha(raw),
        source_raw_sha256=hashlib.sha256(raw).hexdigest(),
        source_contract=contract,
        source_id=source_id,
        raw_bytes=raw,
    )


def _record(source_path: str = CHECKPOINT_V2_PATH) -> PlannedImportRecord:
    return PlannedImportRecord(
        source_path=source_path,
        record_kind="candidate",
        source_record_id="candidate-001",
        owner_actor_id="kivra:genesis",
        derived_record_sha256="2" * 64,
        idempotency_key="genesis-import-v1:candidate-001",
    )


def _manifest(
    items: list[SnapshotSourceItem], records: list[PlannedImportRecord]
) -> ImportPlanManifest:
    return build_import_plan_manifest(
        items,
        records,
        parser_schema_versions={SourceContract.CHECKPOINT_V2: "checkpoint-v2.schema.1"},
        mapping_version="genesis-mapping-v1",
        selection_policy_version="selection-v1",
        selection_policy_sha256="1" * 64,
    )


def test_manifest_is_content_free_canonical_and_order_independent() -> None:
    second_path = "ingress/checkpoints/v2/genesis/2026/08/genesis-v2-002.json"
    first = _source_item()
    second_raw = b'{"synthetic":"different"}'
    second = SnapshotSourceItem(
        source_repository=GENESIS_SOURCE_REPOSITORY,
        source_snapshot_commit=GENESIS_SOURCE_SNAPSHOT_COMMIT,
        source_path=second_path,
        source_git_blob_sha=_blob_sha(second_raw),
        source_raw_sha256=hashlib.sha256(second_raw).hexdigest(),
        source_contract=SourceContract.CHECKPOINT_V2,
        source_id="genesis-v2-002",
        raw_bytes=second_raw,
    )
    second_record = PlannedImportRecord(
        source_path=second_path,
        record_kind="exclusion",
        source_record_id="exclusion-001",
        owner_actor_id=None,
        derived_record_sha256="3" * 64,
        idempotency_key="genesis-import-v1:exclusion-001",
    )

    forward = _manifest([first, second], [_record(), second_record])
    reverse = _manifest([second, first], [second_record, _record()])

    assert forward.canonical_bytes == reverse.canonical_bytes
    assert forward.digest == hashlib.sha256(forward.canonical_bytes).hexdigest()
    assert first.raw_bytes not in forward.canonical_bytes
    assert second.raw_bytes not in forward.canonical_bytes
    assert b"source_raw_sha256" in forward.canonical_bytes
    assert b"derived_record_sha256" in forward.canonical_bytes


def test_manifest_digest_binds_raw_hash_mapping_parser_policy_and_derived_plan() -> None:
    baseline = _manifest([_source_item()], [_record()])

    changed_plan = PlannedImportRecord(
        source_path=CHECKPOINT_V2_PATH,
        record_kind="candidate",
        source_record_id="candidate-001",
        owner_actor_id="kivra:genesis",
        derived_record_sha256="4" * 64,
        idempotency_key="genesis-import-v1:candidate-001",
    )
    changed = _manifest([_source_item()], [changed_plan])

    assert baseline.digest != changed.digest
    assert baseline.value["source_snapshot_commit"] == GENESIS_SOURCE_SNAPSHOT_COMMIT
    assert baseline.value["mapping_version"] == "genesis-mapping-v1"
    assert baseline.value["parser_schema_versions"] == {
        SourceContract.CHECKPOINT_V2.value: "checkpoint-v2.schema.1"
    }


def test_manifest_rejects_unknown_source_path_and_mutated_raw_bytes() -> None:
    with pytest.raises(ManifestError, match="unenumerated source path"):
        _manifest([_source_item()], [_record("ingress/checkpoints/v2/genesis/2026/08/other.json")])

    valid = _source_item()
    mutated = SnapshotSourceItem(
        source_repository=valid.source_repository,
        source_snapshot_commit=valid.source_snapshot_commit,
        source_path=valid.source_path,
        source_git_blob_sha=valid.source_git_blob_sha,
        source_raw_sha256=valid.source_raw_sha256,
        source_contract=valid.source_contract,
        source_id=valid.source_id,
        raw_bytes=b"post-plan mutation",
    )
    with pytest.raises(ManifestError, match="raw bytes did not match"):
        _manifest([mutated], [_record()])


def test_manifest_requires_exact_parser_schema_coverage() -> None:
    with pytest.raises(ManifestError, match="exactly cover"):
        build_import_plan_manifest(
            [_source_item()],
            [_record()],
            parser_schema_versions={},
            mapping_version="genesis-mapping-v1",
            selection_policy_version="selection-v1",
            selection_policy_sha256="1" * 64,
        )
