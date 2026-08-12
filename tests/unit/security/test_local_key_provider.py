from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import multiprocessing
import os
import time
from collections.abc import Callable, Coroutine, Sequence
from multiprocessing.process import BaseProcess
from pathlib import Path
from queue import Empty
from typing import Any, Protocol, cast
from uuid import UUID

import kivra_memory.security.local_key_provider as local_key_provider_module
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
    LOCAL_KEY_PROVIDER_NAME,
    MATERIAL_DIRECTORY_NAME,
    LocalDirectoryKeyDestroyer,
    LocalDirectoryKeyProvider,
)

type _ProcessIdentity = tuple[UUID, UUID, UUID, UUID]
type _ProcessResult = tuple[str, str, str, str, str]


class _ProcessEvent(Protocol):
    def set(self) -> None: ...

    def wait(self, timeout: float | None = None) -> bool: ...


class _ProcessResultQueue(Protocol):
    def put(self, value: object) -> None: ...

    def get(self, *, timeout: float | None = None) -> object: ...


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
    ledger = root.parent / "destruction-ledger"
    ledger.mkdir(mode=0o770)
    ledger.chmod(0o2770)
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


def _process_identity(identity: dict[str, object]) -> _ProcessIdentity:
    return (
        cast(UUID, identity["content_key_id"]),
        cast(UUID, identity["tenant_id"]),
        cast(UUID, identity["lineage_id"]),
        cast(UUID, identity["memory_id"]),
    )


def _reference(content_key_id: UUID) -> ContentKeyReference:
    return ContentKeyReference(
        content_key_id=content_key_id,
        provider_name=LOCAL_KEY_PROVIDER_NAME,
        provider_key_reference=f"{LOCAL_KEY_PROVIDER_NAME}:{content_key_id}",
    )


def _run_process_operation(
    label: str,
    result_queue: _ProcessResultQueue,
    operation: Callable[[], Coroutine[Any, Any, object]],
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    status = "ok"
    exception_name = ""
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            asyncio.run(operation())
        except KeyProviderError as error:
            status = "key_error"
            exception_name = type(error).__name__
        except Exception as error:
            status = "unexpected_error"
            exception_name = type(error).__name__
    result_queue.put((label, status, exception_name, stdout.getvalue(), stderr.getvalue()))


def _provision_process(
    root: Path,
    identity: _ProcessIdentity,
    label: str,
    result_queue: _ProcessResultQueue,
    *,
    wait_before: _ProcessEvent | None = None,
    material_link_entered: _ProcessEvent | None = None,
    material_link_release: _ProcessEvent | None = None,
    fail_material_link: bool = False,
    signal_after: _ProcessEvent | None = None,
) -> None:
    content_key_id, tenant_id, lineage_id, memory_id = identity
    material_name = f"key-{content_key_id}.bin"
    original_link = os.link

    def coordinated_link(
        src: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        dst: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        if os.fsdecode(dst) == material_name and material_link_entered is not None:
            material_link_entered.set()
            if material_link_release is None or not material_link_release.wait(timeout=10):
                raise RuntimeError("material publication coordination timed out")
            if fail_material_link:
                raise OSError("synthetic interrupted publication")
        original_link(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    async def operation() -> object:
        if wait_before is not None and not wait_before.wait(timeout=10):
            raise RuntimeError("provision coordination timed out")
        provider = LocalDirectoryKeyProvider(root)
        result = await provider.provision_key(
            content_key_id=content_key_id,
            tenant_id=tenant_id,
            lineage_id=lineage_id,
            memory_id=memory_id,
        )
        if signal_after is not None:
            signal_after.set()
        return result

    if material_link_entered is not None:
        os.link = coordinated_link
    try:
        _run_process_operation(label, result_queue, operation)
    finally:
        os.link = original_link


def _destroy_process(
    root: Path,
    content_key_id: UUID,
    label: str,
    result_queue: _ProcessResultQueue,
    *,
    wait_before: _ProcessEvent | None = None,
    signal_after: _ProcessEvent | None = None,
) -> None:
    async def operation() -> object:
        if wait_before is not None and not wait_before.wait(timeout=10):
            raise RuntimeError("destroy coordination timed out")
        result = await LocalDirectoryKeyDestroyer(root).destroy_key(_reference(content_key_id))
        if signal_after is not None:
            signal_after.set()
        return result

    _run_process_operation(label, result_queue, operation)


def _get_process(
    root: Path,
    content_key_id: UUID,
    label: str,
    result_queue: _ProcessResultQueue,
    *,
    material_read: _ProcessEvent,
    material_read_release: _ProcessEvent,
) -> None:
    original_read_material = local_key_provider_module._read_material

    def coordinated_read_material(
        material_fd: int,
        name: str,
        *,
        expected_owner_uid: int,
    ) -> bytes:
        material = original_read_material(
            material_fd,
            name,
            expected_owner_uid=expected_owner_uid,
        )
        material_read.set()
        if not material_read_release.wait(timeout=10):
            raise RuntimeError("get coordination timed out")
        return material

    async def operation() -> object:
        provider = LocalDirectoryKeyProvider(root)
        return await provider.get_key(_reference(content_key_id))

    local_key_provider_module._read_material = coordinated_read_material
    try:
        _run_process_operation(label, result_queue, operation)
    finally:
        local_key_provider_module._read_material = original_read_material


def _join_processes(processes: Sequence[BaseProcess]) -> None:
    deadline = time.monotonic() + 15
    try:
        for process in processes:
            process.join(max(0.0, deadline - time.monotonic()))
        assert all(not process.is_alive() for process in processes)
        assert [process.exitcode for process in processes] == [0] * len(processes)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)


def _collect_process_results(
    result_queue: _ProcessResultQueue,
    count: int,
) -> dict[str, _ProcessResult]:
    results: dict[str, _ProcessResult] = {}
    try:
        for _ in range(count):
            raw = result_queue.get(timeout=5)
            assert isinstance(raw, tuple) and len(raw) == 5
            result = cast(_ProcessResult, raw)
            results[result[0]] = result
    except Empty:
        pytest.fail("child process did not report a result")
    assert len(results) == count
    for _label, _status, _exception_name, stdout, stderr in results.values():
        assert stdout == ""
        assert stderr == ""
    return results


def _assert_destroyed_without_remnants(
    control: Path,
    material: Path,
    content_key_id: UUID,
    secret: bytes | None,
    process_results: dict[str, _ProcessResult],
) -> None:
    active = control / f"active-{content_key_id}.json"
    destroyed = control / f"destroyed-{content_key_id}.json"
    key_file = material / f"key-{content_key_id}.bin"

    assert not active.exists()
    assert destroyed.is_file()
    assert not key_file.exists()
    assert not list(control.glob(".tmp-*"))
    assert not list(material.glob(".tmp-*"))
    destroyed_bytes = destroyed.read_bytes()
    serialized_results = repr(process_results).encode("utf-8")
    assert "key" not in json.loads(destroyed_bytes)
    if secret is not None:
        assert secret not in destroyed_bytes
        assert secret.hex().encode("ascii") not in destroyed_bytes
        assert base64.b64encode(secret) not in destroyed_bytes
        assert secret not in serialized_results
        assert secret.hex().encode("ascii") not in serialized_results
        assert base64.b64encode(secret) not in serialized_results


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
async def test_two_process_provision_race_is_idempotent_and_cleans_publication_files(
    tmp_path: Path,
) -> None:
    root, control, material = _key_root(tmp_path)
    identity_document = _identity()
    identity = _process_identity(identity_document)
    content_key_id = identity[0]
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_provision_process,
            args=(root, identity, label, result_queue),
            kwargs={"wait_before": start},
        )
        for label in ("first", "second")
    ]

    for process in processes:
        process.start()
    start.set()
    _join_processes(processes)
    results = _collect_process_results(result_queue, 2)

    assert {result[1] for result in results.values()} == {"ok"}
    provider = LocalDirectoryKeyProvider(root)
    reference = _reference(content_key_id)
    secret = (await provider.get_key(reference))._bytes_for_crypto()
    await provider.destroy_key(reference)
    _assert_destroyed_without_remnants(
        control,
        material,
        content_key_id,
        secret,
        results,
    )


def test_two_process_provision_destroy_race_cannot_resurrect_material(
    tmp_path: Path,
) -> None:
    root, control, material = _key_root(tmp_path)
    identity = _process_identity(_identity())
    content_key_id = identity[0]
    context = multiprocessing.get_context("spawn")
    material_link_entered = context.Event()
    destruction_finished = context.Event()
    result_queue = context.Queue()
    provision = context.Process(
        target=_provision_process,
        args=(root, identity, "provision", result_queue),
        kwargs={
            "material_link_entered": material_link_entered,
            "material_link_release": destruction_finished,
        },
    )
    destroy = context.Process(
        target=_destroy_process,
        args=(root, content_key_id, "destroy", result_queue),
        kwargs={
            "wait_before": material_link_entered,
            "signal_after": destruction_finished,
        },
    )

    provision.start()
    destroy.start()
    _join_processes([provision, destroy])
    results = _collect_process_results(result_queue, 2)

    assert results["destroy"][1] == "ok"
    assert results["provision"][1:3] == ("key_error", "KeyProviderError")
    _assert_destroyed_without_remnants(
        control,
        material,
        content_key_id,
        None,
        results,
    )


@pytest.mark.asyncio
async def test_two_process_get_destroy_race_returns_no_destroyed_material(
    tmp_path: Path,
) -> None:
    provider, root, control, material = _provider(tmp_path)
    identity = _process_identity(_identity())
    content_key_id, tenant_id, lineage_id, memory_id = identity
    reference = await provider.provision_key(
        content_key_id=content_key_id,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        memory_id=memory_id,
    )
    secret = (await provider.get_key(reference))._bytes_for_crypto()
    context = multiprocessing.get_context("spawn")
    material_read = context.Event()
    destruction_finished = context.Event()
    result_queue = context.Queue()
    get = context.Process(
        target=_get_process,
        args=(root, content_key_id, "get", result_queue),
        kwargs={
            "material_read": material_read,
            "material_read_release": destruction_finished,
        },
    )
    destroy = context.Process(
        target=_destroy_process,
        args=(root, content_key_id, "destroy", result_queue),
        kwargs={
            "wait_before": material_read,
            "signal_after": destruction_finished,
        },
    )

    get.start()
    destroy.start()
    _join_processes([get, destroy])
    results = _collect_process_results(result_queue, 2)

    assert results["destroy"][1] == "ok"
    assert results["get"][1:3] == ("key_error", "KeyProviderError")
    _assert_destroyed_without_remnants(
        control,
        material,
        content_key_id,
        secret,
        results,
    )


@pytest.mark.asyncio
async def test_two_process_retry_after_interrupted_publication_leaves_no_temp_remnants(
    tmp_path: Path,
) -> None:
    root, control, material = _key_root(tmp_path)
    identity = _process_identity(_identity())
    content_key_id = identity[0]
    context = multiprocessing.get_context("spawn")
    interrupted_link_entered = context.Event()
    retry_finished = context.Event()
    result_queue = context.Queue()
    interrupted = context.Process(
        target=_provision_process,
        args=(root, identity, "interrupted", result_queue),
        kwargs={
            "material_link_entered": interrupted_link_entered,
            "material_link_release": retry_finished,
            "fail_material_link": True,
        },
    )
    retry = context.Process(
        target=_provision_process,
        args=(root, identity, "retry", result_queue),
        kwargs={
            "wait_before": interrupted_link_entered,
            "signal_after": retry_finished,
        },
    )

    interrupted.start()
    retry.start()
    _join_processes([interrupted, retry])
    results = _collect_process_results(result_queue, 2)

    assert results["retry"][1] == "ok"
    assert results["interrupted"][1:3] == ("key_error", "KeyProviderError")
    provider = LocalDirectoryKeyProvider(root)
    reference = _reference(content_key_id)
    secret = (await provider.get_key(reference))._bytes_for_crypto()
    await provider.destroy_key(reference)
    _assert_destroyed_without_remnants(
        control,
        material,
        content_key_id,
        secret,
        results,
    )


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
    ledger = root.parent / "destruction-ledger"
    ledger.mkdir(mode=0o770)
    ledger.chmod(0o2770)
    link = tmp_path / "key-link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(KeyProviderError):
        LocalDirectoryKeyProvider(link)
