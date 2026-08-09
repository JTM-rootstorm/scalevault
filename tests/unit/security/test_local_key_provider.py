from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.keys import ContentKeyReference, KeyProviderError
from kivra_memory.security.local_key_provider import LocalDirectoryKeyProvider


def _provider(tmp_path: Path) -> tuple[LocalDirectoryKeyProvider, Path]:
    root = tmp_path / "keys"
    root.mkdir(mode=0o770)
    root.chmod(0o2770)
    return LocalDirectoryKeyProvider(root), root


def _identity() -> dict[str, object]:
    return {
        "content_key_id": new_uuid7(),
        "tenant_id": new_uuid7(),
        "lineage_id": new_uuid7(),
        "memory_id": new_uuid7(),
    }


@pytest.mark.asyncio
async def test_provision_and_get_are_idempotent_without_reflecting_key_material(
    tmp_path: Path,
) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()

    first = await provider.provision_key(**identity)  # type: ignore[arg-type]
    first_key = await provider.get_key(first)
    second = await provider.provision_key(**identity)  # type: ignore[arg-type]
    second_key = await provider.get_key(second)

    assert first == second
    assert first_key._bytes_for_crypto() == second_key._bytes_for_crypto()
    assert repr(first_key) == "ContentKeyMaterial(<redacted>)"
    assert str(first_key) == "<redacted content key>"
    assert tuple(path.name for path in root.iterdir()) == (
        f"active-{identity['content_key_id']}.json",
    )

    different_identity = {**identity, "memory_id": new_uuid7()}
    with pytest.raises(KeyProviderError) as caught:
        await provider.provision_key(**different_identity)  # type: ignore[arg-type]
    assert str(caught.value) == "sealed content key is unavailable"
    assert first_key._bytes_for_crypto().hex() not in str(caught.value)


@pytest.mark.asyncio
async def test_destroy_is_idempotent_and_never_resurrects_key(tmp_path: Path) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]

    first = await provider.destroy_key(reference)
    second = await provider.destroy_key(reference)

    assert first.receipt == second.receipt
    assert not root.joinpath(f"active-{identity['content_key_id']}.json").exists()
    assert root.joinpath(f"destroyed-{identity['content_key_id']}.json").is_file()
    with pytest.raises(KeyProviderError):
        await provider.get_key(reference)
    with pytest.raises(KeyProviderError):
        await provider.provision_key(**identity)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_destroy_retry_finishes_removal_after_interrupted_unlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active_name = f"active-{identity['content_key_id']}.json"
    original_unlink = os.unlink
    interrupted = False

    def fail_active_once(path: str | bytes, *args: object, **kwargs: object) -> None:
        nonlocal interrupted
        if path == active_name and not interrupted:
            interrupted = True
            raise OSError("synthetic interruption")
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "unlink", fail_active_once)
    with pytest.raises(KeyProviderError):
        await provider.destroy_key(reference)

    assert root.joinpath(active_name).is_file()
    assert root.joinpath(f"destroyed-{identity['content_key_id']}.json").is_file()
    with pytest.raises(KeyProviderError):
        await provider.get_key(reference)

    receipt = await provider.destroy_key(reference)
    assert receipt.receipt
    assert not root.joinpath(active_name).exists()


@pytest.mark.asyncio
async def test_record_tamper_and_symlink_are_content_free_failures(tmp_path: Path) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = root / f"active-{identity['content_key_id']}.json"
    document = json.loads(active.read_text())
    secret = document["key"]
    document["memory_id"] = str(new_uuid7())
    active.write_text(json.dumps(document))
    active.chmod(0o660)

    with pytest.raises(KeyProviderError) as caught:
        await provider.get_key(reference)
    assert str(caught.value) == "sealed content key is unavailable"
    assert secret not in str(caught.value)

    active.unlink()
    target = root / "outside.json"
    target.write_text("{}")
    active.symlink_to(target)
    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_hard_link_retention_fails_closed(tmp_path: Path) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = root / f"active-{identity['content_key_id']}.json"
    retained = root / "retained.json"
    os.link(active, retained)

    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_duplicate_record_fields_fail_closed(tmp_path: Path) -> None:
    provider, root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = root / f"active-{identity['content_key_id']}.json"
    active.write_bytes(b'{"version":1,"version":1}')
    active.chmod(0o660)

    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_reference_cannot_select_another_path(tmp_path: Path) -> None:
    provider, _root = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    forged = ContentKeyReference(
        content_key_id=reference.content_key_id,
        provider_name=reference.provider_name,
        provider_key_reference="local-directory-v1:../outside",
    )

    with pytest.raises(KeyProviderError):
        await provider.get_key(forged)


def test_root_must_be_absolute_setgid_directory_without_symlink(tmp_path: Path) -> None:
    relative = Path("relative-keys")
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(relative)

    root = tmp_path / "keys"
    root.mkdir(mode=0o770)
    root.chmod(0o770)
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(root)

    root.chmod(0o2770)
    link = tmp_path / "key-link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(link)
