from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import TypedDict
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerEntry,
    LocalDestructionLedger,
    LocalDestructionLedgerWriter,
    initialize_empty_destruction_ledger_anchor,
    recover_authorized_pending_append,
)
from kivra_memory.security.keys import KeyProviderError
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyProvider,
    reconcile_restored_local_key_provider,
)


def _directory(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o770)
    path.chmod(0o2770)
    return path


def _provider_layout(parent: Path) -> tuple[Path, Path, Path]:
    root = _directory(parent / "keys")
    _directory(root / CONTROL_DIRECTORY_NAME)
    _directory(root / MATERIAL_DIRECTORY_NAME)
    ledger_root = _directory(parent / "destruction-ledger")
    anchor_path = _directory(parent / "destruction-anchor") / "current.json"
    initialize_empty_destruction_ledger_anchor(ledger_root, anchor_path)
    return root, ledger_root, anchor_path


class _Identity(TypedDict):
    content_key_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    memory_id: UUID


def _identity() -> _Identity:
    return {
        "content_key_id": new_uuid7(),
        "tenant_id": new_uuid7(),
        "lineage_id": new_uuid7(),
        "memory_id": new_uuid7(),
    }


def _entry() -> DestructionLedgerEntry:
    return DestructionLedgerEntry(**_identity(), receipt=b"r" * 32)


def test_ledger_records_are_immutable_idempotent_and_content_safe(tmp_path: Path) -> None:
    _root, ledger_root, anchor_path = _provider_layout(tmp_path)
    ledger = LocalDestructionLedgerWriter(ledger_root, anchor_path=anchor_path)
    identity = _identity()
    receipt = b"r" * 32
    entry = DestructionLedgerEntry(**identity, receipt=receipt)

    empty_anchor = ledger.anchor()
    assert empty_anchor.entry_count == 0
    assert ledger.record(entry) == entry
    assert ledger.record(entry) == entry
    assert ledger.lookup(entry.content_key_id) == entry
    assert ledger.entries() == (entry,)
    assert ledger.anchor().entry_count == 1
    ledger.require_anchor(ledger.anchor())
    with pytest.raises(KeyProviderError):
        ledger.require_anchor(empty_anchor)

    document = json.loads(
        ledger_root.joinpath(f"destroyed-{entry.content_key_id}.json").read_text()
    )
    assert document["state"] == "destroyed"
    assert base64.b64decode(document["receipt"]) == receipt
    assert "key" not in document


def test_ledger_rejects_conflicting_republication_and_corruption(tmp_path: Path) -> None:
    _root, ledger_root, anchor_path = _provider_layout(tmp_path)
    ledger = LocalDestructionLedgerWriter(ledger_root, anchor_path=anchor_path)
    identity = _identity()
    entry = DestructionLedgerEntry(**identity, receipt=b"a" * 32)
    ledger.record(entry)

    with pytest.raises(KeyProviderError):
        ledger.record(DestructionLedgerEntry(**identity, receipt=b"b" * 32))

    record = ledger_root / f"destroyed-{entry.content_key_id}.json"
    damaged = json.loads(record.read_text())
    damaged["memory_id"] = str(new_uuid7())
    record.write_text(json.dumps(damaged))
    record.chmod(0o640)
    with pytest.raises(KeyProviderError):
        LocalDestructionLedger(ledger_root, anchor_path=anchor_path)


@pytest.mark.asyncio
async def test_authoritative_ledger_dominates_stale_provider_backup(tmp_path: Path) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path / "live")
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)
    secret = (await provider.get_key(reference))._bytes_for_crypto()
    backup_root = tmp_path / "backup" / "keys"
    backup_root.parent.mkdir()
    shutil.copytree(provider_root, backup_root)

    receipt = await provider.destroy_key(reference)
    restored_root = tmp_path / "restore" / "keys"
    restored_root.parent.mkdir()
    shutil.copytree(backup_root, restored_root)
    restored_material = (
        restored_root / MATERIAL_DIRECTORY_NAME / f"key-{reference.content_key_id}.bin"
    )
    assert restored_material.read_bytes() == secret

    restored = LocalDirectoryKeyProvider(
        restored_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )

    assert not restored_material.exists()
    assert json.loads(
        restored_root.joinpath(
            CONTROL_DIRECTORY_NAME,
            f"destroyed-{reference.content_key_id}.json",
        ).read_text()
    )["receipt"] == base64.b64encode(receipt.receipt).decode("ascii")
    with pytest.raises(KeyProviderError):
        await restored.get_key(reference)
    with pytest.raises(KeyProviderError):
        await restored.provision_key(**identity)


@pytest.mark.asyncio
async def test_offline_restore_gate_applies_current_accepted_destruction(
    tmp_path: Path,
) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path / "live")
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)
    backup_root = tmp_path / "backup" / "keys"
    backup_root.parent.mkdir()
    shutil.copytree(provider_root, backup_root)
    receipt = await provider.destroy_key(reference)
    accepted = LocalDestructionLedger(ledger_root, anchor_path=anchor_path).anchor()
    restored_root = tmp_path / "restored" / "keys"
    restored_root.parent.mkdir()
    shutil.copytree(backup_root, restored_root)

    reconcile_restored_local_key_provider(
        restored_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=accepted,
    )

    assert not restored_root.joinpath(
        MATERIAL_DIRECTORY_NAME, f"key-{reference.content_key_id}.bin"
    ).exists()
    assert not restored_root.joinpath(
        CONTROL_DIRECTORY_NAME, f"active-{reference.content_key_id}.json"
    ).exists()
    tombstone = json.loads(
        restored_root.joinpath(
            CONTROL_DIRECTORY_NAME,
            f"destroyed-{reference.content_key_id}.json",
        ).read_text()
    )
    assert tombstone["receipt"] == base64.b64encode(receipt.receipt).decode("ascii")


def test_missing_or_nested_ledger_fails_closed(tmp_path: Path) -> None:
    provider_root, _ledger_root, _anchor_path = _provider_layout(tmp_path)
    shutil.rmtree(tmp_path / "destruction-ledger")

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(provider_root)

    nested = _directory(provider_root / "destruction-ledger")
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(provider_root, destruction_ledger_root=nested)


@pytest.mark.asyncio
async def test_provider_tombstone_unknown_to_ledger_fails_closed(tmp_path: Path) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path)
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)
    await provider.destroy_key(reference)
    ledger_root.joinpath(f"destroyed-{reference.content_key_id}.json").unlink()

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(
            provider_root,
            destruction_ledger_root=ledger_root,
            destruction_ledger_anchor_path=anchor_path,
        )


def test_external_anchor_must_be_an_authenticated_chain_prefix(tmp_path: Path) -> None:
    _root_a, ledger_a, anchor_a = _provider_layout(tmp_path / "a")
    _root_b, ledger_b, anchor_b = _provider_layout(tmp_path / "b")
    common = _entry()
    writer_a = LocalDestructionLedgerWriter(ledger_a, anchor_path=anchor_a)
    writer_b = LocalDestructionLedgerWriter(ledger_b, anchor_path=anchor_b)
    writer_a.record(common)
    writer_b.record(common)
    writer_a.record(_entry())
    writer_b.record(_entry())
    writer_b.record(_entry())

    with pytest.raises(KeyProviderError):
        LocalDestructionLedger(
            ledger_b,
            anchor_path=anchor_b,
            expected_anchor=writer_a.anchor(),
        )


@pytest.mark.parametrize("failure_phase", ["entry", "history"])
def test_authorized_pending_append_repair_is_narrow_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    from kivra_memory.security import destruction_ledger as ledger_module

    _root, ledger_root, anchor_path = _provider_layout(tmp_path)
    writer = LocalDestructionLedgerWriter(ledger_root, anchor_path=anchor_path)
    accepted = writer.anchor()
    entry = _entry()
    target = "_publish_anchor_history_once" if failure_phase == "entry" else "_replace_anchor"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(ledger_module, target, fail)
    with pytest.raises(KeyProviderError):
        writer.record(entry)
    monkeypatch.undo()

    recover_authorized_pending_append(
        ledger_root,
        anchor_path,
        expected_anchor=accepted,
        authorized_entries=(entry,),
    )
    restarted = LocalDestructionLedgerWriter(
        ledger_root,
        anchor_path=anchor_path,
        expected_anchor=accepted,
    )
    assert restarted.lookup(entry.content_key_id) == entry


@pytest.mark.asyncio
async def test_rolled_back_empty_ledger_cannot_enable_restored_key(
    tmp_path: Path,
) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path / "live")
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)
    stale_provider = tmp_path / "stale-provider"
    shutil.copytree(provider_root, stale_provider)
    await provider.destroy_key(reference)

    rolled_back_ledger = _directory(tmp_path / "rolled-back-ledger")
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(
            stale_provider,
            destruction_ledger_root=rolled_back_ledger,
            destruction_ledger_anchor_path=anchor_path,
        )


def test_missing_external_anchor_never_means_empty_ledger(tmp_path: Path) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path)
    anchor_path.unlink()

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(
            provider_root,
            destruction_ledger_root=ledger_root,
            destruction_ledger_anchor_path=anchor_path,
        )


@pytest.mark.asyncio
async def test_rolled_back_anchor_rejects_current_ledger(tmp_path: Path) -> None:
    provider_root, ledger_root, anchor_path = _provider_layout(tmp_path)
    empty_anchor = anchor_path.read_bytes()
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)
    await provider.destroy_key(reference)
    anchor_path.write_bytes(empty_anchor)
    anchor_path.chmod(0o640)

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(
            provider_root,
            destruction_ledger_root=ledger_root,
            destruction_ledger_anchor_path=anchor_path,
        )
