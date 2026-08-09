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
from kivra_memory.security.keys import (
    CONTENT_KEY_BYTES,
    ContentKeyMaterial,
    ContentKeyReference,
    KeyDestructionReceipt,
    KeyProviderError,
)

LOCAL_KEY_PROVIDER_NAME: Final = "local-directory-v1"
LOCAL_KEY_PROVIDER_ROOT: Final = Path("/var/lib/kivra-memory-sealed/keys")
_REFERENCE_PREFIX: Final = f"{LOCAL_KEY_PROVIDER_NAME}:"
_RECORD_VERSION: Final = 1
_RECEIPT_BYTES: Final = 32
_MAX_RECORD_BYTES: Final = 2_048
_FILE_MODE: Final = 0o660


class _RecordMissing(Exception):
    pass


class LocalDirectoryKeyProvider:
    """Keep independent DEKs in a fixed, non-symlinked local directory.

    Active records and destruction tombstones use separate descriptor-relative
    names. Publishing a tombstone precedes removal of key material, so a crash
    cannot make a destroyed key readable or allow it to be reprovisioned.
    """

    name = LOCAL_KEY_PROVIDER_NAME

    def __init__(self, root: Path, *, required_owner_uid: int | None = None) -> None:
        self._root = Path(root)
        self._required_owner_uid = required_owner_uid
        try:
            self._validate_root()
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
        return self._provision_key(
            content_key_id=content_key_id,
            tenant_id=tenant_id,
            lineage_id=lineage_id,
            memory_id=memory_id,
        )

    async def get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        return self._get_key(reference)

    async def destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        return self._destroy_key(reference)

    def _validate_root(self) -> None:
        if not self._root.is_absolute() or ".." in self._root.parts:
            raise ValueError
        root_lstat = self._root.lstat()
        if stat.S_ISLNK(root_lstat.st_mode) or self._root.resolve(strict=True) != self._root:
            raise ValueError
        if not os.access(
            self._root,
            os.R_OK | os.W_OK | os.X_OK,
            effective_ids=True,
            follow_symlinks=False,
        ):
            raise ValueError
        with _directory_fd(self._root) as root_fd:
            root_stat = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_stat.st_mode)
                or root_stat.st_mode & 0o007
                or not root_stat.st_mode & stat.S_ISGID
                or (
                    self._required_owner_uid is not None
                    and root_stat.st_uid != self._required_owner_uid
                )
            ):
                raise ValueError

    def _provision_key(
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
            reference = self._reference(content_key_id)
            identity = _identity_document(
                content_key_id=content_key_id,
                tenant_id=tenant_id,
                lineage_id=lineage_id,
                memory_id=memory_id,
            )
            with _directory_fd(self._root) as root_fd:
                if self._try_record(root_fd, self._destroyed_name(content_key_id)) is not None:
                    raise ValueError
                existing = self._try_record(root_fd, self._active_name(content_key_id))
                if existing is not None:
                    self._require_record(existing, state="active", identity=identity)
                    return reference
                record = _record(
                    state="active",
                    identity=identity,
                    key=os.urandom(CONTENT_KEY_BYTES),
                    receipt=os.urandom(_RECEIPT_BYTES),
                )
                self._publish_once(root_fd, self._active_name(content_key_id), record)
                if self._try_record(root_fd, self._destroyed_name(content_key_id)) is not None:
                    os.unlink(self._active_name(content_key_id), dir_fd=root_fd)
                    os.fsync(root_fd)
                    raise ValueError
                published = self._read_record(root_fd, self._active_name(content_key_id))
                self._require_record(published, state="active", identity=identity)
                return reference
        except Exception:
            raise KeyProviderError() from None

    def _get_key(self, reference: ContentKeyReference) -> ContentKeyMaterial:
        try:
            content_key_id = self._reference_id(reference)
            with _directory_fd(self._root) as root_fd:
                if self._try_record(root_fd, self._destroyed_name(content_key_id)) is not None:
                    raise ValueError
                record = self._read_record(root_fd, self._active_name(content_key_id))
            identity = _record_identity(record)
            self._require_record(record, state="active", identity=identity)
            key = _canonical_base64(record.get("key"), expected_bytes=CONTENT_KEY_BYTES)
            return ContentKeyMaterial(key)
        except Exception:
            raise KeyProviderError() from None

    def _destroy_key(self, reference: ContentKeyReference) -> KeyDestructionReceipt:
        try:
            content_key_id = self._reference_id(reference)
            active_name = self._active_name(content_key_id)
            destroyed_name = self._destroyed_name(content_key_id)
            with _directory_fd(self._root) as root_fd:
                destroyed = self._try_record(root_fd, destroyed_name)
                if destroyed is not None:
                    identity = _record_identity(destroyed)
                    self._require_record(destroyed, state="destroyed", identity=identity)
                    active = self._try_record(root_fd, active_name)
                    if active is not None:
                        self._require_record(active, state="active", identity=identity)
                        if active["receipt"] != destroyed["receipt"]:
                            raise ValueError
                        with suppress(FileNotFoundError):
                            os.unlink(active_name, dir_fd=root_fd)
                        os.fsync(root_fd)
                    receipt = _canonical_base64(
                        destroyed.get("receipt"), expected_bytes=_RECEIPT_BYTES
                    )
                    return KeyDestructionReceipt(receipt)

                active = self._read_record(root_fd, active_name)
                identity = _record_identity(active)
                self._require_record(active, state="active", identity=identity)
                receipt = _canonical_base64(active.get("receipt"), expected_bytes=_RECEIPT_BYTES)
                tombstone = _record(
                    state="destroyed",
                    identity=identity,
                    key=None,
                    receipt=receipt,
                )
                self._publish_once(root_fd, destroyed_name, tombstone)
                published = self._read_record(root_fd, destroyed_name)
                self._require_record(published, state="destroyed", identity=identity)
                if published["receipt"] != active["receipt"]:
                    raise ValueError
                with suppress(FileNotFoundError):
                    os.unlink(active_name, dir_fd=root_fd)
                os.fsync(root_fd)
                return KeyDestructionReceipt(receipt)
        except Exception:
            raise KeyProviderError() from None

    def _publish_once(self, root_fd: int, destination: str, document: Mapping[str, object]) -> None:
        temporary = f".tmp-{os.urandom(16).hex()}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                _FILE_MODE,
                dir_fd=root_fd,
            )
            os.fchmod(descriptor, _FILE_MODE)
            payload = canonical_json_bytes(document)
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
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                return
            finally:
                os.unlink(temporary, dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=root_fd)

    def _try_record(self, root_fd: int, name: str) -> dict[str, object] | None:
        try:
            return self._read_record(root_fd, name)
        except _RecordMissing:
            return None

    @staticmethod
    def _read_record(root_fd: int, name: str) -> dict[str, object]:
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            raise _RecordMissing from None
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            file_stat = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or stat.S_IMODE(file_stat.st_mode) != _FILE_MODE
                or file_stat.st_nlink != 1
                or not 1 <= file_stat.st_size <= _MAX_RECORD_BYTES
            ):
                raise ValueError
            raw = handle.read(_MAX_RECORD_BYTES + 1)
        if len(raw) != file_stat.st_size or len(raw) > _MAX_RECORD_BYTES:
            raise ValueError
        parsed = parse_json_strict(raw)
        if not isinstance(parsed, dict):
            raise ValueError
        if canonical_json_bytes(parsed) != raw:
            raise ValueError
        return cast(dict[str, object], parsed)

    @staticmethod
    def _require_record(
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
            "key",
            "receipt",
            "record_sha256",
        }
        if set(record) != expected_fields or record.get("version") != _RECORD_VERSION:
            raise ValueError
        if record.get("state") != state or _record_identity(record) != dict(identity):
            raise ValueError
        _canonical_base64(record.get("receipt"), expected_bytes=_RECEIPT_BYTES)
        if state == "active":
            _canonical_base64(record.get("key"), expected_bytes=CONTENT_KEY_BYTES)
        elif record.get("key") is not None:
            raise ValueError
        digest = record.get("record_sha256")
        unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
        ):
            raise ValueError

    @staticmethod
    def _active_name(content_key_id: UUID) -> str:
        return f"active-{content_key_id}.json"

    @staticmethod
    def _destroyed_name(content_key_id: UUID) -> str:
        return f"destroyed-{content_key_id}.json"

    def _reference(self, content_key_id: UUID) -> ContentKeyReference:
        return ContentKeyReference(
            content_key_id=content_key_id,
            provider_name=self.name,
            provider_key_reference=f"{_REFERENCE_PREFIX}{content_key_id}",
        )

    def _reference_id(self, reference: ContentKeyReference) -> UUID:
        if reference.provider_name != self.name:
            raise ValueError
        expected = f"{_REFERENCE_PREFIX}{reference.content_key_id}"
        if reference.provider_key_reference != expected:
            raise ValueError
        return reference.content_key_id


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


def _record(
    *,
    state: Literal["active", "destroyed"],
    identity: Mapping[str, object],
    key: bytes | None,
    receipt: bytes,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "version": _RECORD_VERSION,
        "state": state,
        **identity,
        "key": None if key is None else base64.b64encode(key).decode("ascii"),
        "receipt": base64.b64encode(receipt).decode("ascii"),
    }
    return {
        **unsigned,
        "record_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


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
    "LOCAL_KEY_PROVIDER_NAME",
    "LOCAL_KEY_PROVIDER_ROOT",
    "LocalDirectoryKeyProvider",
]
