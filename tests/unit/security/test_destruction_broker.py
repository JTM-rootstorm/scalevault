from __future__ import annotations

from pathlib import Path

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.destruction_broker import reconcile_destruction_requests
from kivra_memory.security.destruction_ledger import (
    LocalDestructionLedger,
    initialize_empty_destruction_ledger_anchor,
)
from kivra_memory.security.keys import KeyProviderError
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyProvider,
    LocalDirectoryKeyPurgeRequester,
    _canonical_base64,
    _control_record,
    _record_identity,
)


def _directory(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o770)
    path.chmod(0o2770)
    return path


def _layout(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    provider = _directory(tmp_path / "keys")
    _directory(provider / CONTROL_DIRECTORY_NAME)
    _directory(provider / MATERIAL_DIRECTORY_NAME)
    ledger = _directory(tmp_path / "ledger")
    anchor = _directory(tmp_path / "anchor") / "current.json"
    initialize_empty_destruction_ledger_anchor(ledger, anchor)
    requests = _directory(tmp_path / "requests")
    return provider, ledger, anchor, requests


def _identity() -> dict[str, object]:
    return {
        "content_key_id": new_uuid7(),
        "tenant_id": new_uuid7(),
        "lineage_id": new_uuid7(),
        "memory_id": new_uuid7(),
    }


@pytest.mark.asyncio
async def test_broker_append_requires_independent_anchor_ack_before_completion(
    tmp_path: Path,
) -> None:
    provider_root, ledger_root, anchor_path, request_root = _layout(tmp_path)
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    accepted_empty = LocalDestructionLedger(
        ledger_root,
        anchor_path=anchor_path,
    ).anchor()
    requester = LocalDirectoryKeyPurgeRequester(
        provider_root,
        destruction_request_root=request_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=accepted_empty,
    )

    with pytest.raises(KeyProviderError):
        await requester.destroy_key(reference)
    await reconcile_destruction_requests(
        provider_root=provider_root,
        request_root=request_root,
        ledger_root=ledger_root,
        anchor_path=anchor_path,
        expected_anchor=accepted_empty,
    )
    with pytest.raises(KeyProviderError):
        await requester.destroy_key(reference)

    accepted_current = LocalDestructionLedger(
        ledger_root,
        anchor_path=anchor_path,
    ).anchor()
    restarted = LocalDirectoryKeyPurgeRequester(
        provider_root,
        destruction_request_root=request_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=accepted_current,
    )
    receipt = await restarted.destroy_key(reference)
    assert receipt.receipt


@pytest.mark.asyncio
@pytest.mark.parametrize("forgery", ["identity", "receipt"])
async def test_broker_rejects_forged_request_before_any_destruction(
    tmp_path: Path,
    forgery: str,
) -> None:
    provider_root, ledger_root, anchor_path, request_root = _layout(tmp_path)
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    requester = LocalDirectoryKeyPurgeRequester(
        provider_root,
        destruction_request_root=request_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=LocalDestructionLedger(
            ledger_root, anchor_path=anchor_path
        ).anchor(),
    )
    with pytest.raises(KeyProviderError):
        await requester.destroy_key(reference)
    request_path = request_root / f"destroyed-{reference.content_key_id}.json"
    document = parse_json_strict(request_path.read_bytes())
    assert isinstance(document, dict)
    request_identity = _record_identity(document)
    receipt = _canonical_base64(document.get("receipt"), expected_bytes=32)
    if forgery == "identity":
        request_identity["memory_id"] = str(new_uuid7())
    else:
        receipt = b"x" * 32
    forged = _control_record(
        state="destroyed",
        identity=request_identity,
        receipt=receipt,
    )
    request_path.write_bytes(canonical_json_bytes(forged))
    request_path.chmod(0o660)

    with pytest.raises(KeyProviderError):
        await reconcile_destruction_requests(
            provider_root=provider_root,
            request_root=request_root,
            ledger_root=ledger_root,
            anchor_path=anchor_path,
            expected_anchor=LocalDestructionLedger(ledger_root, anchor_path=anchor_path).anchor(),
        )
    assert provider_root.joinpath(
        MATERIAL_DIRECTORY_NAME,
        f"key-{reference.content_key_id}.bin",
    ).is_file()
    assert (
        LocalDestructionLedger(ledger_root, anchor_path=anchor_path).lookup(
            reference.content_key_id
        )
        is None
    )
    assert provider_root.joinpath(
        CONTROL_DIRECTORY_NAME,
        f"active-{reference.content_key_id}.json",
    ).is_file()


@pytest.mark.asyncio
async def test_anchor_stays_bounded_after_more_than_one_hundred_brokered_facts(
    tmp_path: Path,
) -> None:
    provider_root, ledger_root, anchor_path, request_root = _layout(tmp_path)
    provider = LocalDirectoryKeyProvider(
        provider_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
    )
    accepted_empty = LocalDestructionLedger(
        ledger_root,
        anchor_path=anchor_path,
    ).anchor()
    requester = LocalDirectoryKeyPurgeRequester(
        provider_root,
        destruction_request_root=request_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=accepted_empty,
    )
    references = []
    for _ in range(101):
        identity = _identity()
        reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
        references.append(reference)
        with pytest.raises(KeyProviderError):
            await requester.destroy_key(reference)

    applied = 0
    while any(request_root.iterdir()):
        applied += await reconcile_destruction_requests(
            provider_root=provider_root,
            request_root=request_root,
            ledger_root=ledger_root,
            anchor_path=anchor_path,
            expected_anchor=accepted_empty,
        )
    assert applied == 101
    assert len(anchor_path.read_bytes()) < 160

    accepted_current = LocalDestructionLedger(
        ledger_root,
        anchor_path=anchor_path,
    ).anchor()
    assert accepted_current.entry_count == 101
    assert len(accepted_current.canonical_bytes()) < 160
    restarted_reader = LocalDestructionLedger(
        ledger_root,
        anchor_path=anchor_path,
        expected_anchor=accepted_current,
    )
    assert len(restarted_reader.entries()) == 101
    restarted_requester = LocalDirectoryKeyPurgeRequester(
        provider_root,
        destruction_request_root=request_root,
        destruction_ledger_root=ledger_root,
        destruction_ledger_anchor_path=anchor_path,
        expected_destruction_ledger_anchor=accepted_current,
    )
    assert (await restarted_requester.destroy_key(references[-1])).receipt
