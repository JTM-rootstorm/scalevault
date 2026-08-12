"""Descriptor-relative local key provider for optional sealed content."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final, Literal, cast
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerEntry,
    LocalDestructionLedger,
)
from kivra_memory.security.keys import (
    CONTENT_KEY_BYTES,
    ContentKeyMaterial,
    ContentKeyReference,
    KeyDestructionReceipt,
    KeyProviderError,
)

LOCAL_KEY_PROVIDER_NAME: Final = "local-directory-v1"
LOCAL_KEY_PROVIDER_ROOT: Final = Path("/var/lib/kivra-memory-sealed/keys")
CONTROL_DIRECTORY_NAME: Final = "control"
MATERIAL_DIRECTORY_NAME: Final = "material"
_REFERENCE_PREFIX: Final = f"{LOCAL_KEY_PROVIDER_NAME}:"
_RECORD_VERSION: Final = 1
_RECEIPT_BYTES: Final = 32
_MAX_RECORD_BYTES: Final = 2_048
_CONTROL_FILE_MODE: Final = 0o660
_MATERIAL_FILE_MODE: Final = 0o600


class _RecordMissing(Exception):
    pass


class LocalDirectoryKeyDestroyer:
    """Destroy keys without exposing provision or key-read capabilities.

    The process may read only non-secret control records. It opens the material
    directory solely to remove a UUID-derived filename after publishing a
    durable tombstone, and never opens a material file descriptor.
    """

    name = LOCAL_KEY_PROVIDER_NAME

    def __init__(
        self,
        root: Path,
        *,
        destruction_ledger_root: Path | None = None,
        required_owner_uid: int | None = None,
        material_file_owner_uid: int | None = None,
    ) -> None:
        self._root = Path(root)
        self._control = self._root / CONTROL_DIRECTORY_NAME
        self._material = self._root / MATERIAL_DIRECTORY_NAME
        self._ledger_root = Path(
            destruction_ledger_root or self._root.parent / "destruction-ledger"
        )
        try:
            _require_separate_recovery_roots(self._root, self._ledger_root)
            _validate_layout(
                self._root,
                self._control,
                self._material,
                required_owner_uid=required_owner_uid,
                material_file_owner_uid=material_file_owner_uid,
                destruction_only=True,
            )
            self._ledger = LocalDestructionLedger(
                self._ledger_root,
                required_owner_uid=required_owner_uid,
            )
            _reconcile_destruction_ledger(
                control=self._control,
                material=self._material,
                ledger=self._ledger,
            )
            _validate_provider_destruction_consistency(
                control=self._control,
                ledger=self._ledger,
            )
        except Exception:
            raise KeyProviderError() from None

    async def destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        try:
            content_key_id = _reference_id(reference)
            active_name = _active_name(content_key_id)
            destroyed_name = _destroyed_name(content_key_id)
            with (
                _directory_fd(self._control) as control_fd,
                _directory_fd(self._material) as material_fd,
            ):
                ledger_entry = self._ledger.lookup(content_key_id)
                if ledger_entry is not None:
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=ledger_entry,
                    )
                    return KeyDestructionReceipt(ledger_entry.receipt)
                destroyed = _try_control_record(control_fd, destroyed_name)
                if destroyed is not None:
                    identity = _record_identity(destroyed)
                    _require_control_record(destroyed, state="destroyed", identity=identity)
                    entry = self._ledger.lookup(content_key_id)
                    if entry is None:
                        raise ValueError
                    if _entry_identity(entry) != identity or entry.receipt != _canonical_base64(
                        destroyed.get("receipt"), expected_bytes=_RECEIPT_BYTES
                    ):
                        raise ValueError
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=entry,
                    )
                    return KeyDestructionReceipt(entry.receipt)

                active = _read_control_record(control_fd, active_name)
                identity = _record_identity(active)
                _require_control_record(active, state="active", identity=identity)
                receipt = _canonical_base64(active.get("receipt"), expected_bytes=_RECEIPT_BYTES)
                entry = self._ledger.record(_ledger_entry(identity=identity, receipt=receipt))
                tombstone = _control_record(
                    state="destroyed",
                    identity=identity,
                    receipt=receipt,
                )
                _publish_once(
                    control_fd,
                    destroyed_name,
                    canonical_json_bytes(tombstone),
                    mode=_CONTROL_FILE_MODE,
                )
                published = _read_control_record(control_fd, destroyed_name)
                _require_control_record(published, state="destroyed", identity=identity)
                if published["receipt"] != active["receipt"]:
                    raise ValueError
                _apply_ledger_entry(
                    control_fd=control_fd,
                    material_fd=material_fd,
                    entry=entry,
                )
                return KeyDestructionReceipt(receipt)
        except Exception:
            raise KeyProviderError() from None


class LocalDirectoryKeyProvider:
    """Provision and read DEKs while keeping secret material out of control records."""

    name = LOCAL_KEY_PROVIDER_NAME

    def __init__(
        self,
        root: Path,
        *,
        destruction_ledger_root: Path | None = None,
        required_owner_uid: int | None = None,
    ) -> None:
        self._root = Path(root)
        self._control = self._root / CONTROL_DIRECTORY_NAME
        self._material = self._root / MATERIAL_DIRECTORY_NAME
        self._ledger_root = Path(
            destruction_ledger_root or self._root.parent / "destruction-ledger"
        )
        self._material_file_owner_uid = os.geteuid()
        try:
            _require_separate_recovery_roots(self._root, self._ledger_root)
            _validate_layout(
                self._root,
                self._control,
                self._material,
                required_owner_uid=required_owner_uid,
                material_file_owner_uid=self._material_file_owner_uid,
                destruction_only=False,
            )
            self._ledger = LocalDestructionLedger(
                self._ledger_root,
                required_owner_uid=required_owner_uid,
            )
            _reconcile_destruction_ledger(
                control=self._control,
                material=self._material,
                ledger=self._ledger,
            )
            _validate_provider_destruction_consistency(
                control=self._control,
                ledger=self._ledger,
            )
            self._destroyer = LocalDirectoryKeyDestroyer(
                self._root,
                destruction_ledger_root=self._ledger_root,
                required_owner_uid=required_owner_uid,
                material_file_owner_uid=None,
            )
        except Exception:
            raise KeyProviderError() from None

    async def provision_key(
        self,
        *,
        content_key_id: UUID,
        tenant_id: UUID,
        lineage_id: UUID,
        memory_id: UUID,
    ) -> ContentKeyReference:
        try:
            for identifier, field_name in (
                (content_key_id, "content_key_id"),
                (tenant_id, "tenant_id"),
                (lineage_id, "lineage_id"),
                (memory_id, "memory_id"),
            ):
                require_uuid7(identifier, field_name=field_name)
            reference = _reference(content_key_id)
            identity = _identity_document(
                content_key_id=content_key_id,
                tenant_id=tenant_id,
                lineage_id=lineage_id,
                memory_id=memory_id,
            )
            active_name = _active_name(content_key_id)
            destroyed_name = _destroyed_name(content_key_id)
            material_name = _material_name(content_key_id)
            with (
                _directory_fd(self._control) as control_fd,
                _directory_fd(self._material) as material_fd,
            ):
                ledger_entry = self._ledger.lookup(content_key_id)
                if ledger_entry is not None:
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=ledger_entry,
                    )
                    raise ValueError
                if _try_control_record(control_fd, destroyed_name) is not None:
                    raise ValueError
                active = _try_control_record(control_fd, active_name)
                if active is None:
                    proposed = _control_record(
                        state="active",
                        identity=identity,
                        receipt=os.urandom(_RECEIPT_BYTES),
                    )
                    _publish_once(
                        control_fd,
                        active_name,
                        canonical_json_bytes(proposed),
                        mode=_CONTROL_FILE_MODE,
                    )
                    active = _read_control_record(control_fd, active_name)
                _require_control_record(active, state="active", identity=identity)
                if _try_control_record(control_fd, destroyed_name) is not None:
                    raise ValueError
                try:
                    _read_material(
                        material_fd,
                        material_name,
                        expected_owner_uid=self._material_file_owner_uid,
                    )
                except _RecordMissing:
                    _publish_once(
                        material_fd,
                        material_name,
                        os.urandom(CONTENT_KEY_BYTES),
                        mode=_MATERIAL_FILE_MODE,
                    )
                    _read_material(
                        material_fd,
                        material_name,
                        expected_owner_uid=self._material_file_owner_uid,
                    )
                if _try_control_record(control_fd, destroyed_name) is not None:
                    _finish_destruction(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        active_name=active_name,
                        material_name=material_name,
                    )
                    raise ValueError
                ledger_entry = self._ledger.lookup(content_key_id)
                if ledger_entry is not None:
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=ledger_entry,
                    )
                    raise ValueError
                return reference
        except Exception:
            raise KeyProviderError() from None

    async def get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        try:
            content_key_id = _reference_id(reference)
            active_name = _active_name(content_key_id)
            destroyed_name = _destroyed_name(content_key_id)
            material_name = _material_name(content_key_id)
            with (
                _directory_fd(self._control) as control_fd,
                _directory_fd(self._material) as material_fd,
            ):
                ledger_entry = self._ledger.lookup(content_key_id)
                if ledger_entry is not None:
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=ledger_entry,
                    )
                    raise ValueError
                if _try_control_record(control_fd, destroyed_name) is not None:
                    raise ValueError
                active = _read_control_record(control_fd, active_name)
                identity = _record_identity(active)
                _require_control_record(active, state="active", identity=identity)
                key = _read_material(
                    material_fd,
                    material_name,
                    expected_owner_uid=self._material_file_owner_uid,
                )
                if _try_control_record(control_fd, destroyed_name) is not None:
                    raise ValueError
                ledger_entry = self._ledger.lookup(content_key_id)
                if ledger_entry is not None:
                    _apply_ledger_entry(
                        control_fd=control_fd,
                        material_fd=material_fd,
                        entry=ledger_entry,
                    )
                    raise ValueError
                return ContentKeyMaterial(key)
        except Exception:
            raise KeyProviderError() from None

    async def destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        return await self._destroyer.destroy_key(reference)


def _require_separate_recovery_roots(provider_root: Path, ledger_root: Path) -> None:
    provider = provider_root.resolve(strict=True)
    ledger = ledger_root.resolve(strict=True)
    if provider == ledger or provider.is_relative_to(ledger) or ledger.is_relative_to(provider):
        raise ValueError


def _ledger_entry(*, identity: Mapping[str, object], receipt: bytes) -> DestructionLedgerEntry:
    identifiers: dict[str, UUID] = {}
    for field_name in ("content_key_id", "tenant_id", "lineage_id", "memory_id"):
        value = identity.get(field_name)
        if not isinstance(value, str):
            raise ValueError
        identifiers[field_name] = UUID(value)
    return DestructionLedgerEntry(
        content_key_id=identifiers["content_key_id"],
        tenant_id=identifiers["tenant_id"],
        lineage_id=identifiers["lineage_id"],
        memory_id=identifiers["memory_id"],
        receipt=receipt,
    )


def _entry_identity(entry: DestructionLedgerEntry) -> dict[str, object]:
    return _identity_document(
        content_key_id=entry.content_key_id,
        tenant_id=entry.tenant_id,
        lineage_id=entry.lineage_id,
        memory_id=entry.memory_id,
    )


def _apply_ledger_entry(
    *, control_fd: int, material_fd: int, entry: DestructionLedgerEntry
) -> None:
    """Merge one authoritative ledger fact into rollback-prone provider state."""

    identity = _entry_identity(entry)
    active_name = _active_name(entry.content_key_id)
    destroyed_name = _destroyed_name(entry.content_key_id)
    material_name = _material_name(entry.content_key_id)
    # The ledger is already the durable tombstone. Remove restored material
    # before trusting rollback-prone provider identity/control metadata.
    with suppress(FileNotFoundError):
        os.unlink(material_name, dir_fd=material_fd)
    os.fsync(material_fd)
    active = _try_control_record(control_fd, active_name)
    if active is not None:
        _require_control_record(active, state="active", identity=identity)
        if _canonical_base64(active.get("receipt"), expected_bytes=_RECEIPT_BYTES) != entry.receipt:
            raise ValueError
    destroyed = _try_control_record(control_fd, destroyed_name)
    if destroyed is None:
        _publish_once(
            control_fd,
            destroyed_name,
            canonical_json_bytes(
                _control_record(state="destroyed", identity=identity, receipt=entry.receipt)
            ),
            mode=_CONTROL_FILE_MODE,
        )
        destroyed = _read_control_record(control_fd, destroyed_name)
    _require_control_record(destroyed, state="destroyed", identity=identity)
    if _canonical_base64(destroyed.get("receipt"), expected_bytes=_RECEIPT_BYTES) != entry.receipt:
        raise ValueError
    _finish_destruction(
        control_fd=control_fd,
        material_fd=material_fd,
        active_name=active_name,
        material_name=material_name,
    )


def _reconcile_destruction_ledger(
    *, control: Path, material: Path, ledger: LocalDestructionLedger
) -> None:
    """Apply all destruction facts after startup or provider-backup restore."""

    with _directory_fd(control) as control_fd, _directory_fd(material) as material_fd:
        for entry in ledger.entries():
            _apply_ledger_entry(
                control_fd=control_fd,
                material_fd=material_fd,
                entry=entry,
            )


def _validate_provider_destruction_consistency(
    *, control: Path, ledger: LocalDestructionLedger
) -> None:
    """Reject provider tombstones that are absent or different in authority."""

    with _directory_fd(control) as control_fd:
        for name in sorted(os.listdir(control_fd)):
            if not isinstance(name, str) or not name.startswith("destroyed-"):
                continue
            record = _read_control_record(control_fd, name)
            identity = _record_identity(record)
            _require_control_record(record, state="destroyed", identity=identity)
            content_key_id = UUID(cast(str, identity["content_key_id"]))
            entry = ledger.lookup(content_key_id)
            if entry is None or _entry_identity(entry) != identity:
                raise ValueError
            if (
                _canonical_base64(record.get("receipt"), expected_bytes=_RECEIPT_BYTES)
                != entry.receipt
            ):
                raise ValueError


def _validate_layout(
    root: Path,
    control: Path,
    material: Path,
    *,
    required_owner_uid: int | None,
    material_file_owner_uid: int | None,
    destruction_only: bool,
) -> None:
    if (
        destruction_only
        and material_file_owner_uid is not None
        and material_file_owner_uid == os.geteuid()
    ):
        raise ValueError
    _validate_directory(
        root,
        required_owner_uid=required_owner_uid,
        required_access=os.X_OK,
    )
    _validate_directory(
        control,
        required_owner_uid=required_owner_uid,
        required_access=os.R_OK | os.W_OK | os.X_OK,
    )
    _validate_directory(
        material,
        required_owner_uid=required_owner_uid,
        required_access=os.R_OK | os.W_OK | os.X_OK,
    )


def _validate_directory(
    path: Path,
    *,
    required_owner_uid: int | None,
    required_access: int,
) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    path_lstat = path.lstat()
    if stat.S_ISLNK(path_lstat.st_mode) or path.resolve(strict=True) != path:
        raise ValueError
    if not os.access(
        path,
        required_access,
        effective_ids=True,
        follow_symlinks=False,
    ):
        raise ValueError
    with _directory_fd(path) as directory_fd:
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_mode & 0o007
            or not directory_stat.st_mode & stat.S_ISGID
            or (required_owner_uid is not None and directory_stat.st_uid != required_owner_uid)
        ):
            raise ValueError


def _finish_destruction(
    *,
    control_fd: int,
    material_fd: int,
    active_name: str,
    material_name: str,
) -> None:
    with suppress(FileNotFoundError):
        os.unlink(material_name, dir_fd=material_fd)
    os.fsync(material_fd)
    with suppress(FileNotFoundError):
        os.unlink(active_name, dir_fd=control_fd)
    os.fsync(control_fd)


def _publish_once(directory_fd: int, destination: str, payload: bytes, *, mode: int) -> None:
    temporary = f".tmp-{os.urandom(16).hex()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary,
                destination,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return
        finally:
            os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)


def _try_control_record(control_fd: int, name: str) -> dict[str, object] | None:
    try:
        return _read_control_record(control_fd, name)
    except _RecordMissing:
        return None


def _read_control_record(control_fd: int, name: str) -> dict[str, object]:
    raw = _read_bounded_file(
        control_fd,
        name,
        expected_mode=_CONTROL_FILE_MODE,
        maximum_bytes=_MAX_RECORD_BYTES,
    )
    parsed = parse_json_strict(raw)
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != raw:
        raise ValueError
    return cast(dict[str, object], parsed)


def _read_material(material_fd: int, name: str, *, expected_owner_uid: int) -> bytes:
    raw = _read_bounded_file(
        material_fd,
        name,
        expected_mode=_MATERIAL_FILE_MODE,
        maximum_bytes=CONTENT_KEY_BYTES,
        expected_owner_uid=expected_owner_uid,
    )
    if len(raw) != CONTENT_KEY_BYTES:
        raise ValueError
    return raw


def _read_bounded_file(
    directory_fd: int,
    name: str,
    *,
    expected_mode: int,
    maximum_bytes: int,
    expected_owner_uid: int | None = None,
) -> bytes:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        raise _RecordMissing from None
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        file_stat = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != expected_mode
            or (expected_owner_uid is not None and file_stat.st_uid != expected_owner_uid)
            or file_stat.st_nlink != 1
            or not 1 <= file_stat.st_size <= maximum_bytes
        ):
            raise ValueError
        raw = handle.read(maximum_bytes + 1)
    if len(raw) != file_stat.st_size or len(raw) > maximum_bytes:
        raise ValueError
    return raw


class _directory_fd:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._fd = -1

    def __enter__(self) -> int:
        self._fd = os.open(
            self._path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        return self._fd

    def __exit__(self, *_args: object) -> None:
        os.close(self._fd)


def _identity_document(
    *, content_key_id: UUID, tenant_id: UUID, lineage_id: UUID, memory_id: UUID
) -> dict[str, object]:
    return {
        "content_key_id": str(content_key_id),
        "tenant_id": str(tenant_id),
        "lineage_id": str(lineage_id),
        "memory_id": str(memory_id),
    }


def _record_identity(record: Mapping[str, object]) -> dict[str, object]:
    identity = {
        "content_key_id": record.get("content_key_id"),
        "tenant_id": record.get("tenant_id"),
        "lineage_id": record.get("lineage_id"),
        "memory_id": record.get("memory_id"),
    }
    for field_name, value in identity.items():
        if not isinstance(value, str):
            raise ValueError
        parsed = UUID(value)
        require_uuid7(parsed, field_name=field_name)
        if str(parsed) != value:
            raise ValueError
    return identity


def _control_record(
    *,
    state: Literal["active", "destroyed"],
    identity: Mapping[str, object],
    receipt: bytes,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "version": _RECORD_VERSION,
        "state": state,
        **identity,
        "receipt": base64.b64encode(receipt).decode("ascii"),
    }
    return {
        **unsigned,
        "record_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _require_control_record(
    record: Mapping[str, object],
    *,
    state: Literal["active", "destroyed"],
    identity: Mapping[str, object],
) -> None:
    expected_fields = {
        "version",
        "state",
        "content_key_id",
        "tenant_id",
        "lineage_id",
        "memory_id",
        "receipt",
        "record_sha256",
    }
    if set(record) != expected_fields or record.get("version") != _RECORD_VERSION:
        raise ValueError
    if record.get("state") != state or _record_identity(record) != dict(identity):
        raise ValueError
    _canonical_base64(record.get("receipt"), expected_bytes=_RECEIPT_BYTES)
    digest = record.get("record_sha256")
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or digest != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    ):
        raise ValueError


def _active_name(content_key_id: UUID) -> str:
    return f"active-{content_key_id}.json"


def _destroyed_name(content_key_id: UUID) -> str:
    return f"destroyed-{content_key_id}.json"


def _material_name(content_key_id: UUID) -> str:
    return f"key-{content_key_id}.bin"


def _reference(content_key_id: UUID) -> ContentKeyReference:
    return ContentKeyReference(
        content_key_id=content_key_id,
        provider_name=LOCAL_KEY_PROVIDER_NAME,
        provider_key_reference=f"{_REFERENCE_PREFIX}{content_key_id}",
    )


def _reference_id(reference: ContentKeyReference) -> UUID:
    if reference.provider_name != LOCAL_KEY_PROVIDER_NAME:
        raise ValueError
    expected = f"{_REFERENCE_PREFIX}{reference.content_key_id}"
    if reference.provider_key_reference != expected:
        raise ValueError
    return reference.content_key_id


def _canonical_base64(value: object, *, expected_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError from None
    if len(decoded) != expected_bytes or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError
    return decoded


__all__ = [
    "CONTROL_DIRECTORY_NAME",
    "LOCAL_KEY_PROVIDER_NAME",
    "LOCAL_KEY_PROVIDER_ROOT",
    "MATERIAL_DIRECTORY_NAME",
    "LocalDirectoryKeyDestroyer",
    "LocalDirectoryKeyProvider",
]
