from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.security.keys import (
    ContentKeyReference,
    KeyDestroyer,
    KeyProvider,
    KeyProviderError,
)
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyDestroyer,
    LocalDirectoryKeyProvider,
)


def _key_root(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "keys"
    root.mkdir(mode=0o710)
    root.chmod(0o2710)
    control = root / CONTROL_DIRECTORY_NAME
    control.mkdir(mode=0o770)
    control.chmod(0o2770)
    material = root / MATERIAL_DIRECTORY_NAME
    material.mkdir(mode=0o770)
    material.chmod(0o2770)
    return root, control, material


def _provider(
    tmp_path: Path,
) -> tuple[LocalDirectoryKeyProvider, Path, Path, Path]:
    root, control, material = _key_root(tmp_path)
    return LocalDirectoryKeyProvider(root), root, control, material


def _identity() -> dict[str, object]:
    return {
        "content_key_id": new_uuid7(),
        "tenant_id": new_uuid7(),
        "lineage_id": new_uuid7(),
        "memory_id": new_uuid7(),
    }


@pytest.mark.asyncio
async def test_provision_and_get_are_idempotent_without_secret_control_data(
    tmp_path: Path,
) -> None:
    provider, _root, control, material = _provider(tmp_path)
    identity = _identity()

    first = await provider.provision_key(**identity)  # type: ignore[arg-type]
    first_key = await provider.get_key(first)
    second = await provider.provision_key(**identity)  # type: ignore[arg-type]
    second_key = await provider.get_key(second)

    assert first == second
    assert first_key._bytes_for_crypto() == second_key._bytes_for_crypto()
    assert repr(first_key) == "ContentKeyMaterial(<redacted>)"
    assert str(first_key) == "<redacted content key>"
    active = control / f"active-{identity['content_key_id']}.json"
    key_file = material / f"key-{identity['content_key_id']}.bin"
    assert active.is_file()
    assert key_file.is_file()
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert first_key._bytes_for_crypto() == key_file.read_bytes()
    assert first_key._bytes_for_crypto() not in active.read_bytes()
    assert "key" not in json.loads(active.read_text())

    different_identity = {**identity, "memory_id": new_uuid7()}
    with pytest.raises(KeyProviderError) as caught:
        await provider.provision_key(**different_identity)  # type: ignore[arg-type]
    assert str(caught.value) == "sealed content key is unavailable"
    assert first_key._bytes_for_crypto().hex() not in str(caught.value)


@pytest.mark.asyncio
async def test_provision_retry_completes_partial_control_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider, _root, control, material = _provider(tmp_path)
    identity = _identity()
    material_name = f"key-{identity['content_key_id']}.bin"
    original_link = os.link
    interrupted = False

    def fail_material_publish_once(
        source: str | bytes,
        destination: str | bytes,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal interrupted
        if destination == material_name and not interrupted:
            interrupted = True
            raise OSError("synthetic interruption")
        original_link(source, destination, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "link", fail_material_publish_once)
    with pytest.raises(KeyProviderError):
        await provider.provision_key(**identity)  # type: ignore[arg-type]

    active = control / f"active-{identity['content_key_id']}.json"
    assert active.is_file()
    stable_receipt = json.loads(active.read_text())["receipt"]
    assert not (material / material_name).exists()

    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    assert json.loads(active.read_text())["receipt"] == stable_receipt
    assert len((await provider.get_key(reference))._bytes_for_crypto()) == 32


@pytest.mark.asyncio
async def test_destroy_is_idempotent_and_never_resurrects_key(tmp_path: Path) -> None:
    provider, _root, control, material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]

    first = await provider.destroy_key(reference)
    second = await provider.destroy_key(reference)

    assert first.receipt == second.receipt
    assert not control.joinpath(f"active-{identity['content_key_id']}.json").exists()
    assert control.joinpath(f"destroyed-{identity['content_key_id']}.json").is_file()
    assert not material.joinpath(f"key-{identity['content_key_id']}.bin").exists()
    with pytest.raises(KeyProviderError):
        await provider.get_key(reference)
    with pytest.raises(KeyProviderError):
        await provider.provision_key(**identity)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_destroy_retry_preserves_tombstone_before_material_removal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider, root, control, material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active_name = f"active-{identity['content_key_id']}.json"
    material_name = f"key-{identity['content_key_id']}.bin"
    destroyed = control / f"destroyed-{identity['content_key_id']}.json"
    original_unlink = os.unlink
    interrupted = False

    def fail_material_once(path: str | bytes, *args: object, **kwargs: object) -> None:
        nonlocal interrupted
        if path == material_name and not interrupted:
            interrupted = True
            raise OSError("synthetic interruption")
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "unlink", fail_material_once)
    with pytest.raises(KeyProviderError):
        await provider.destroy_key(reference)

    assert control.joinpath(active_name).is_file()
    assert destroyed.is_file()
    assert material.joinpath(material_name).is_file()
    tombstone_receipt = base64.b64decode(json.loads(destroyed.read_text())["receipt"])
    with pytest.raises(KeyProviderError):
        await provider.get_key(reference)

    receipt = await LocalDirectoryKeyDestroyer(root).destroy_key(reference)
    assert receipt.receipt == tombstone_receipt
    assert not control.joinpath(active_name).exists()
    assert not material.joinpath(material_name).exists()


@pytest.mark.asyncio
async def test_destruction_capability_cannot_read_or_open_material_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider, root, _control, _material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    material_name = f"key-{identity['content_key_id']}.bin"
    destroyer = LocalDirectoryKeyDestroyer(root)

    assert isinstance(destroyer, KeyDestroyer)
    assert not isinstance(destroyer, KeyProvider)
    assert not hasattr(destroyer, "get_key")
    assert not hasattr(destroyer, "provision_key")

    original_open = os.open
    opened: list[str] = []

    def record_open(path: str | bytes | Path, *args: object, **kwargs: object) -> int:
        opened.append(os.fsdecode(path))
        return original_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", record_open)
    receipt = await destroyer.destroy_key(reference)

    assert receipt.receipt
    assert material_name not in opened


def test_destroyer_requires_a_distinct_material_file_owner(tmp_path: Path) -> None:
    root, _control, _material = _key_root(tmp_path)

    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyDestroyer(root, material_file_owner_uid=os.geteuid())

    destroyer = LocalDirectoryKeyDestroyer(
        root,
        material_file_owner_uid=os.geteuid() + 1,
    )
    assert not hasattr(destroyer, "get_key")


@pytest.mark.asyncio
async def test_control_tamper_and_symlink_are_content_free_failures(tmp_path: Path) -> None:
    provider, _root, control, material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = control / f"active-{identity['content_key_id']}.json"
    secret = material.joinpath(f"key-{identity['content_key_id']}.bin").read_bytes()
    document = json.loads(active.read_text())
    document["memory_id"] = str(new_uuid7())
    active.write_text(json.dumps(document))
    active.chmod(0o660)

    with pytest.raises(KeyProviderError) as caught:
        await provider.get_key(reference)
    assert str(caught.value) == "sealed content key is unavailable"
    assert secret.hex() not in str(caught.value)

    active.unlink()
    target = control / "outside.json"
    target.write_text("{}")
    active.symlink_to(target)
    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_material_symlink_and_wrong_owner_fail_closed(tmp_path: Path) -> None:
    provider, _root, _control, material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    key_file = material / f"key-{identity['content_key_id']}.bin"
    key_file.unlink()
    target = material / "outside.bin"
    target.write_bytes(os.urandom(32))
    target.chmod(0o600)
    key_file.symlink_to(target)

    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_hard_link_retention_fails_closed(tmp_path: Path) -> None:
    provider, _root, control, _material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = control / f"active-{identity['content_key_id']}.json"
    retained = control / "retained.json"
    os.link(active, retained)

    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_duplicate_control_fields_fail_closed(tmp_path: Path) -> None:
    provider, _root, control, _material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    active = control / f"active-{identity['content_key_id']}.json"
    active.write_bytes(b'{"version":1,"version":1}')
    active.chmod(0o660)

    with pytest.raises(KeyProviderError, match="sealed content key is unavailable"):
        await provider.get_key(reference)


@pytest.mark.asyncio
async def test_reference_cannot_select_another_path(tmp_path: Path) -> None:
    provider, _root, _control, _material = _provider(tmp_path)
    identity = _identity()
    reference = await provider.provision_key(**identity)  # type: ignore[arg-type]
    forged = ContentKeyReference(
        content_key_id=reference.content_key_id,
        provider_name=reference.provider_name,
        provider_key_reference="local-directory-v1:../outside",
    )

    with pytest.raises(KeyProviderError):
        await provider.get_key(forged)


def test_root_must_be_absolute_setgid_layout_without_symlink(tmp_path: Path) -> None:
    relative = Path("relative-keys")
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(relative)

    root = tmp_path / "keys"
    root.mkdir(mode=0o710)
    root.chmod(0o2710)
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(root)

    control = root / CONTROL_DIRECTORY_NAME
    control.mkdir(mode=0o770)
    control.chmod(0o2770)
    material = root / MATERIAL_DIRECTORY_NAME
    material.mkdir(mode=0o770)
    material.chmod(0o2770)
    link = tmp_path / "key-link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(link)
