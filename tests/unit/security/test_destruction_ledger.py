from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerEntry,
    LocalDestructionLedger,
)
from kivra_memory.security.keys import KeyProviderError
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyProvider,
)


def _directory(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o770)
    path.chmod(0o2770)
    return path


def _provider_layout(parent: Path) -> tuple[Path, Path]:
    root = _directory(parent / "keys")
    _directory(root / CONTROL_DIRECTORY_NAME)
    _directory(root / MATERIAL_DIRECTORY_NAME)
    return root, _directory(parent / "destruction-ledger")


def _identity() -> dict[str, object]:
    return {
        "content_key_id": new_uuid7(),
        "tenant_id": new_uuid7(),
        "lineage_id": new_uuid7(),
        "memory_id": new_uuid7(),
    }


def test_ledger_records_are_immutable_idempotent_and_content_safe(tmp_path: Path) -> None:
    _root, ledger_root = _provider_layout(tmp_path)
    ledger = LocalDestructionLedger(ledger_root)
    identity = _identity()
    receipt = b"r" * 32
    entry = DestructionLedgerEntry(**identity, receipt=receipt)  # type: ignore[arg-type]

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
    _root, ledger_root = _provider_layout(tmp_path)
    ledger = LocalDestructionLedger(ledger_root)
    identity = _identity()
    entry = DestructionLedgerEntry(**identity, receipt=b"a" * 32)  # type: ignore[arg-type]
    ledger.record(entry)

    with pytest.raises(KeyProviderError):
        ledger.record(
            DestructionLedgerEntry(**identity, receipt=b"b" * 32)  # type: ignore[arg-type]
        )

    record = ledger_root / f"destroyed-{entry.content_key_id}.json"
    damaged = json.loads(record.read_text())
    damaged["memory_id"] = str(new_uuid7())
    record.write_text(json.dumps(damaged))
    record.chmod(0o660)
    with pytest.raises(KeyProviderError):
        LocalDestructionLedger(ledger_root)


@pytest.mark.asyncio
async def test_authoritative_ledger_dominates_stale_provider_backup(tmp_path: Path) -> None:
    provider_root, ledger_root = _provider_layout(tmp_path / "live")
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
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
        await restored.provision_key(**identity)  # type: ignore[arg-type]


def test_missing_or_nested_ledger_fails_closed(tmp_path: Path) -> None:
    provider_root, _ledger_root = _provider_layout(tmp_path)
    shutil.rmtree(tmp_path / "destruction-ledger")

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(provider_root)

    nested = _directory(provider_root / "destruction-ledger")
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(provider_root, destruction_ledger_root=nested)


@pytest.mark.asyncio
async def test_provider_tombstone_unknown_to_ledger_fails_closed(tmp_path: Path) -> None:
    provider_root, ledger_root = _provider_layout(tmp_path)
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    await provider.destroy_key(reference)
    ledger_root.joinpath(f"destroyed-{reference.content_key_id}.json").unlink()

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(
            provider_root,
            destruction_ledger_root=ledger_root,
        )
