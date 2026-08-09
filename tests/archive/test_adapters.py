"""Focused deterministic archive runtime adapter tests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID

import pytest
from kivra_memory.archive.adapters import (
    ArchivePayload,
    DeterministicArchiveBuilder,
    GitWorktreeArchiveRepository,
    GitWorktreeConfig,
)
from kivra_memory.archive.git import GitSigningConfig, ProcessResult
from kivra_memory.archive.models import ArchiveManifest
from kivra_memory.domain.canonical_json import parse_json_strict
from kivra_memory.storage.archive import ArchiveBatchSource

_ROOT = Path(__file__).resolve().parents[2]
_TENANT_ID = UUID("019c0000-0000-7000-8000-000000000001")
_TARGET_ID = UUID("019c0000-0000-7000-8000-000000000002")
_EVENT_ID = UUID("019c0000-0000-7000-8000-000000000003")


def _source() -> ArchiveBatchSource:
    return ArchiveBatchSource(
        tenant_id=str(_TENANT_ID),
        archive_target_id=str(_TARGET_ID),
        previous_checkpoint_id=None,
        previous_manifest_sha256=None,
        previous_git_commit_sha=None,
        source_high_water_sequence=1,
        first_event_sequence=1,
        last_event_sequence=1,
        event_count=1,
        export_timestamp="2026-08-09T12:00:00.000000Z",
        events=(
            {
                "sequence": 1,
                "event_id": str(_EVENT_ID),
                "created_at": "2026-08-09T12:00:00.000000Z",
                "payload": {"safe": True},
            },
        ),
        recovery_primary_keys={"tenants": ("tenant_id",)},
        recovery_rows={"tenants": ({"tenant_id": str(_TENANT_ID)},)},
    )


def test_builder_is_deterministic_and_binds_manifest_payload() -> None:
    builder = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="test-v1",
    )

    first = builder.build(_source())
    second = builder.build(_source())

    assert first.manifest_sha256 == second.manifest_sha256
    assert first.commit_message == "memory-export: events 1..1\n"
    assert isinstance(first.payload, ArchivePayload)
    assert isinstance(second.payload, ArchivePayload)
    first_payload = first.payload
    second_payload = second.payload
    assert first_payload.files == second_payload.files
    manifest_bytes = first_payload.files["manifest.json"]
    assert hashlib.sha256(manifest_bytes).digest() == first.manifest_sha256
    manifest = ArchiveManifest.from_value(parse_json_strict(manifest_bytes))
    assert manifest.snapshot is not None
    assert manifest.snapshot.high_water_sequence == 1
    assert "events/2026/08/09/000000000001-019c0000-0000-7000-8000-000000000003.json" in (
        item.path for item in manifest.files
    )


def _signing(repository: Path) -> GitSigningConfig:
    return GitSigningConfig(
        repository=repository,
        signing_key=Path("/run/credentials/archive-signing-key"),
        allowed_signers_file=Path("/etc/kivra-memory/archive-allowed-signers"),
        signer_principal="archive@scalevault",
        author_name="ScaleVault Archive",
        author_email="archive@scalevault.invalid",
    )


def test_git_worktree_config_requires_mounted_root_and_explicit_ssh_remote() -> None:
    with pytest.raises(ValueError, match="below /mnt/memory"):
        GitWorktreeConfig(
            repository=Path("/tmp/archive"),
            repository_reference="ssh://git@forgejo.example/owner/archive.git",
            branch_name="main",
            deploy_key=Path("/run/credentials/archive-deploy-key"),
            known_hosts_file=Path("/etc/kivra-memory/archive-known-hosts"),
            signing=_signing(Path("/tmp/archive")),
        )

    repository = Path("/mnt/memory/kivra-memory/archive")
    with pytest.raises(ValueError, match="explicit SSH URL"):
        GitWorktreeConfig(
            repository=repository,
            repository_reference="https://forgejo.example/owner/archive.git",
            branch_name="main",
            deploy_key=Path("/run/credentials/archive-deploy-key"),
            known_hosts_file=Path("/etc/kivra-memory/archive-known-hosts"),
            signing=_signing(repository),
        )


def test_repository_rebuilds_index_from_an_exact_batch_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous_event = tmp_path / (
        "events/2026/08/08/000000000001-019c0000-0000-7000-8000-000000000003.json"
    )
    previous_event.parent.mkdir(parents=True)
    previous_event.write_bytes(b"old")
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"old-manifest")
    calls: list[tuple[str, ...]] = []

    repository = cast(Any, object.__new__(GitWorktreeArchiveRepository))
    repository._config = SimpleNamespace(repository=tmp_path)

    def fake_git(arguments: tuple[str, ...]) -> ProcessResult:
        calls.append(arguments)
        if arguments == ("ls-files", "-z"):
            return ProcessResult(
                0,
                stdout=(
                    b"events/2026/08/08/000000000001-"
                    b"019c0000-0000-7000-8000-000000000003.json\x00manifest.json\x00"
                ),
            )
        return ProcessResult(0)

    monkeypatch.setattr(repository, "_git", fake_git)
    repository._empty_worktree()

    assert not previous_event.exists()
    assert not manifest.exists()
    assert calls[-1] == ("read-tree", "--empty")
