"""Rollback-resistant destruction authority for sealed content keys."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import hmac
import os
import stat
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.security.keys import KeyProviderError

LOCAL_DESTRUCTION_LEDGER_ROOT: Final = Path("/var/lib/kivra-memory-sealed/destruction-ledger")
_RECORD_VERSION: Final = 1
_RECEIPT_BYTES: Final = 32
_MAX_RECORD_BYTES: Final = 2_048
_RECORD_MODE: Final = 0o660


@dataclass(frozen=True, slots=True)
class DestructionLedgerEntry:
    """One immutable destruction fact held outside key-provider backups."""

    content_key_id: UUID
    tenant_id: UUID
    lineage_id: UUID
    memory_id: UUID
    receipt: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for identifier, field_name in (
            (self.content_key_id, "content_key_id"),
            (self.tenant_id, "tenant_id"),
            (self.lineage_id, "lineage_id"),
            (self.memory_id, "memory_id"),
        ):
            require_uuid7(identifier, field_name=field_name)
        if not isinstance(self.receipt, bytes) or len(self.receipt) != _RECEIPT_BYTES:
            raise ValueError("destruction ledger entry is invalid")


@dataclass(frozen=True, slots=True)
class DestructionLedgerAnchor:
    """Content-free exact freshness anchor retained outside the ledger copy."""

    entry_count: int
    aggregate_sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.entry_count, bool)
            or not isinstance(self.entry_count, int)
            or self.entry_count < 0
            or not isinstance(self.aggregate_sha256, str)
            or len(self.aggregate_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.aggregate_sha256)
        ):
            raise ValueError("destruction ledger anchor is invalid")


class LocalDestructionLedger:
    """Append-only local destruction ledger with no deletion operation.

    The directory is a separate recovery object from the key-provider root. A
    provider backup may be restored, but this authority is never rolled back or
    overlaid by that restore. Its immutable facts therefore dominate restored
    active control and material files.
    """

    def __init__(self, root: Path, *, required_owner_uid: int | None = None) -> None:
        self._root = Path(root)
        try:
            _validate_directory(self._root, required_owner_uid=required_owner_uid)
            self.entries()
        except Exception:
            raise KeyProviderError() from None

    def lookup(self, content_key_id: UUID) -> DestructionLedgerEntry | None:
        """Return the authoritative destruction fact, failing closed on damage."""

        try:
            require_uuid7(content_key_id, field_name="content_key_id")
            with _directory_fd(self._root) as ledger_fd:
                try:
                    return _read_entry(ledger_fd, _entry_name(content_key_id))
                except FileNotFoundError:
                    return None
        except Exception:
            raise KeyProviderError() from None

    def record(self, entry: DestructionLedgerEntry) -> DestructionLedgerEntry:
        """Durably publish a destruction fact once and return the stored fact."""

        try:
            payload = canonical_json_bytes(_entry_document(entry))
            with _directory_fd(self._root) as ledger_fd:
                _publish_once(ledger_fd, _entry_name(entry.content_key_id), payload)
                stored = _read_entry(ledger_fd, _entry_name(entry.content_key_id))
            if stored != entry:
                raise ValueError
            return stored
        except Exception:
            raise KeyProviderError() from None

    def entries(self) -> tuple[DestructionLedgerEntry, ...]:
        """Validate and return every immutable entry in deterministic order."""

        try:
            with _directory_fd(self._root) as ledger_fd:
                names = sorted(os.listdir(ledger_fd))
                entries: list[DestructionLedgerEntry] = []
                for name in names:
                    if not isinstance(name, str) or not name.startswith("destroyed-"):
                        raise ValueError
                    entries.append(_read_entry(ledger_fd, name))
                if len({entry.content_key_id for entry in entries}) != len(entries):
                    raise ValueError
                return tuple(entries)
        except Exception:
            raise KeyProviderError() from None

    def anchor(self) -> DestructionLedgerAnchor:
        """Return the exact content-free head retained by recovery custody."""

        entries = self.entries()
        material = {
            "version": _RECORD_VERSION,
            "entry_sha256": [
                hashlib.sha256(canonical_json_bytes(_entry_document(entry))).hexdigest()
                for entry in entries
            ],
        }
        return DestructionLedgerAnchor(
            entry_count=len(entries),
            aggregate_sha256=hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        )

    def require_anchor(self, expected: DestructionLedgerAnchor) -> None:
        """Fail closed unless this ledger is the exact independently anchored head."""

        try:
            actual = self.anchor()
            if actual.entry_count != expected.entry_count or not hmac.compare_digest(
                actual.aggregate_sha256,
                expected.aggregate_sha256,
            ):
                raise ValueError
        except Exception:
            raise KeyProviderError() from None


def _validate_directory(path: Path, *, required_owner_uid: int | None) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    path_lstat = path.lstat()
    if stat.S_ISLNK(path_lstat.st_mode) or path.resolve(strict=True) != path:
        raise ValueError
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK, effective_ids=True, follow_symlinks=False):
        raise ValueError
    with _directory_fd(path) as ledger_fd:
        metadata = os.fstat(ledger_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o007
            or not metadata.st_mode & stat.S_ISGID
            or (required_owner_uid is not None and metadata.st_uid != required_owner_uid)
        ):
            raise ValueError


def _entry_document(entry: DestructionLedgerEntry) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "version": _RECORD_VERSION,
        "state": "destroyed",
        "content_key_id": str(entry.content_key_id),
        "tenant_id": str(entry.tenant_id),
        "lineage_id": str(entry.lineage_id),
        "memory_id": str(entry.memory_id),
        "receipt": base64.b64encode(entry.receipt).decode("ascii"),
    }
    return {
        **unsigned,
        "record_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


def _read_entry(ledger_fd: int, name: str) -> DestructionLedgerEntry:
    raw = _read_bounded_file(ledger_fd, name)
    parsed = parse_json_strict(raw)
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != raw:
        raise ValueError
    record = cast(dict[str, object], parsed)
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
    if (
        set(record) != expected_fields
        or record.get("version") != _RECORD_VERSION
        or record.get("state") != "destroyed"
    ):
        raise ValueError
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    digest = record.get("record_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or digest != hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    ):
        raise ValueError
    identifiers: dict[str, UUID] = {}
    for field_name in ("content_key_id", "tenant_id", "lineage_id", "memory_id"):
        value = record.get(field_name)
        if not isinstance(value, str):
            raise ValueError
        identifier = UUID(value)
        require_uuid7(identifier, field_name=field_name)
        if str(identifier) != value:
            raise ValueError
        identifiers[field_name] = identifier
    entry = DestructionLedgerEntry(
        content_key_id=identifiers["content_key_id"],
        tenant_id=identifiers["tenant_id"],
        lineage_id=identifiers["lineage_id"],
        memory_id=identifiers["memory_id"],
        receipt=_canonical_base64(record.get("receipt")),
    )
    if name != _entry_name(entry.content_key_id):
        raise ValueError
    return entry


def _read_bounded_file(directory_fd: int, name: str) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != _RECORD_MODE
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_RECORD_BYTES
        ):
            raise ValueError
        raw = handle.read(_MAX_RECORD_BYTES + 1)
    if len(raw) != metadata.st_size or len(raw) > _MAX_RECORD_BYTES:
        raise ValueError
    return raw


def _publish_once(directory_fd: int, destination: str, payload: bytes) -> None:
    temporary = f".tmp-{os.urandom(16).hex()}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            _RECORD_MODE,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, _RECORD_MODE)
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


def _entry_name(content_key_id: UUID) -> str:
    return f"destroyed-{content_key_id}.json"


def _canonical_base64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError from None
    if len(decoded) != _RECEIPT_BYTES or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError
    return decoded


__all__ = [
    "LOCAL_DESTRUCTION_LEDGER_ROOT",
    "DestructionLedgerAnchor",
    "DestructionLedgerEntry",
    "LocalDestructionLedger",
]
