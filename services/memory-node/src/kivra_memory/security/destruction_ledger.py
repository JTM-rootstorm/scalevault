"""Rollback-resistant destruction authority for sealed content keys."""

from __future__ import annotations

import base64
import binascii
import errno
import fcntl
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
LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH: Final = Path(
    "/var/lib/kivra-memory-destruction-anchor/current.json"
)
_RECORD_VERSION: Final = 1
_RECEIPT_BYTES: Final = 32
_MAX_RECORD_BYTES: Final = 2_048
_RECORD_MODE: Final = 0o640
_ANCHOR_MODE: Final = 0o640


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

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "version": _RECORD_VERSION,
                "entry_count": self.entry_count,
                "aggregate_sha256": self.aggregate_sha256,
            }
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> DestructionLedgerAnchor:
        document = parse_json_strict(raw)
        if (
            not isinstance(document, dict)
            or set(document) != {"version", "entry_count", "aggregate_sha256"}
            or document.get("version") != _RECORD_VERSION
            or canonical_json_bytes(document) != raw
        ):
            raise ValueError("destruction ledger anchor is invalid")
        return cls(
            entry_count=cast(int, document["entry_count"]),
            aggregate_sha256=cast(str, document["aggregate_sha256"]),
        )


class LocalDestructionLedger:
    """Append-only local destruction ledger with no deletion operation.

    The directory is a separate recovery object from the key-provider root. A
    provider backup may be restored, but this authority is never rolled back or
    overlaid by that restore. Its immutable facts therefore dominate restored
    active control and material files.
    """

    def __init__(
        self,
        root: Path,
        *,
        anchor_path: Path,
        expected_anchor: DestructionLedgerAnchor | None = None,
        required_owner_uid: int | None = None,
    ) -> None:
        self._root = Path(root)
        self._anchor_path = Path(anchor_path)
        self._expected_anchor = expected_anchor
        try:
            _validate_directory(
                self._root,
                required_owner_uid=required_owner_uid,
                required_access=os.R_OK | os.X_OK,
            )
            _validate_anchor_path(
                self._anchor_path,
                ledger_root=self._root,
                required_owner_uid=required_owner_uid,
            )
            self.require_current_anchor()
        except Exception:
            raise KeyProviderError() from None

    def lookup(self, content_key_id: UUID) -> DestructionLedgerEntry | None:
        """Return the authoritative destruction fact, failing closed on damage."""

        try:
            require_uuid7(content_key_id, field_name="content_key_id")
            with _directory_fd(self._root) as ledger_fd:
                fcntl.flock(ledger_fd, fcntl.LOCK_SH)
                self._require_current_anchor_locked(ledger_fd)
                try:
                    return _read_entry(ledger_fd, _entry_name(content_key_id))
                except FileNotFoundError:
                    return None
        except Exception:
            raise KeyProviderError() from None

    def entries(self) -> tuple[DestructionLedgerEntry, ...]:
        """Validate and return every immutable entry in deterministic order."""

        try:
            with _directory_fd(self._root) as ledger_fd:
                fcntl.flock(ledger_fd, fcntl.LOCK_SH)
                self._require_current_anchor_locked(ledger_fd)
                return _entries(ledger_fd)
        except Exception:
            raise KeyProviderError() from None

    def anchor(self) -> DestructionLedgerAnchor:
        """Return the exact content-free head retained by recovery custody."""

        entries = self.entries()
        return _anchor_for_entries(entries)

    def require_current_anchor(self) -> None:
        """Require the exact external anchor before any ledger-dependent use."""

        try:
            with _directory_fd(self._root) as ledger_fd:
                fcntl.flock(ledger_fd, fcntl.LOCK_SH)
                self._require_current_anchor_locked(ledger_fd)
        except Exception:
            raise KeyProviderError() from None

    def _require_current_anchor_locked(self, ledger_fd: int) -> None:
        expected = _read_anchor(self._anchor_path)
        records = _records(ledger_fd)
        actual = _anchor_for_records(records)
        if actual.entry_count != expected.entry_count or not hmac.compare_digest(
            actual.aggregate_sha256,
            expected.aggregate_sha256,
        ):
            raise ValueError
        accepted = self._expected_anchor
        if accepted is not None and not _anchor_is_prefix(accepted, records):
            raise ValueError

    def require_anchor(self, expected: DestructionLedgerAnchor) -> None:
        """Fail closed unless both ledger and external anchor match expected."""

        self.require_current_anchor()
        actual = self.anchor()
        if actual.entry_count != expected.entry_count or not hmac.compare_digest(
            actual.aggregate_sha256,
            expected.aggregate_sha256,
        ):
            raise KeyProviderError() from None


class LocalDestructionLedgerWriter(LocalDestructionLedger):
    """Privileged append capability used only by the root reconciliation broker."""

    def __init__(
        self,
        root: Path,
        *,
        anchor_path: Path,
        expected_anchor: DestructionLedgerAnchor | None = None,
        required_owner_uid: int | None = None,
    ) -> None:
        super().__init__(
            root,
            anchor_path=anchor_path,
            expected_anchor=expected_anchor,
            required_owner_uid=required_owner_uid,
        )
        if not os.access(self._root, os.W_OK, effective_ids=True, follow_symlinks=False):
            raise KeyProviderError()
        if not os.access(
            self._anchor_path.parent,
            os.W_OK,
            effective_ids=True,
            follow_symlinks=False,
        ):
            raise KeyProviderError()

    def record(self, entry: DestructionLedgerEntry) -> DestructionLedgerEntry:
        try:
            with _directory_fd(self._root) as ledger_fd:
                fcntl.flock(ledger_fd, fcntl.LOCK_EX)
                self._require_current_anchor_locked(ledger_fd)
                records = _records(ledger_fd)
                existing = next(
                    (
                        record.entry
                        for record in records
                        if record.entry.content_key_id == entry.content_key_id
                    ),
                    None,
                )
                if existing is not None:
                    if existing != entry:
                        raise ValueError
                    return existing
                current = _anchor_for_records(records)
                payload = canonical_json_bytes(
                    _entry_document(
                        entry,
                        generation=current.entry_count + 1,
                        previous_sha256=current.aggregate_sha256,
                    )
                )
                _publish_once(ledger_fd, _entry_name(entry.content_key_id), payload)
                stored = _read_entry(ledger_fd, _entry_name(entry.content_key_id))
                next_anchor = _anchor_for_records(_records(ledger_fd))
                _publish_anchor_history_once(self._anchor_path.parent, next_anchor)
                _replace_anchor(self._anchor_path, next_anchor)
            if stored != entry:
                raise ValueError
            return stored
        except Exception:
            raise KeyProviderError() from None


@dataclass(frozen=True, slots=True)
class _LedgerRecord:
    entry: DestructionLedgerEntry
    generation: int
    previous_sha256: str
    record_sha256: str


def _empty_head() -> str:
    return hashlib.sha256(canonical_json_bytes({"version": _RECORD_VERSION})).hexdigest()


def _anchor_for_records(records: tuple[_LedgerRecord, ...]) -> DestructionLedgerAnchor:
    return DestructionLedgerAnchor(
        entry_count=len(records),
        aggregate_sha256=records[-1].record_sha256 if records else _empty_head(),
    )


def _anchor_for_entries(entries: tuple[DestructionLedgerEntry, ...]) -> DestructionLedgerAnchor:
    previous = _empty_head()
    records: list[_LedgerRecord] = []
    for generation, entry in enumerate(entries, start=1):
        document = _entry_document(
            entry,
            generation=generation,
            previous_sha256=previous,
        )
        previous = cast(str, document["record_sha256"])
        records.append(
            _LedgerRecord(
                entry,
                generation,
                cast(str, document["previous_sha256"]),
                previous,
            )
        )
    return _anchor_for_records(tuple(records))


def initialize_empty_destruction_ledger_anchor(
    ledger_root: Path,
    anchor_path: Path,
    *,
    required_owner_uid: int | None = None,
) -> None:
    """Provision the initial exact anchor; never bless a non-empty ledger."""

    try:
        _validate_directory(Path(ledger_root), required_owner_uid=required_owner_uid)
        anchor = Path(anchor_path)
        _validate_anchor_parent(
            anchor,
            ledger_root=Path(ledger_root),
            required_owner_uid=required_owner_uid,
        )
        with _directory_fd(Path(ledger_root)) as ledger_fd:
            fcntl.flock(ledger_fd, fcntl.LOCK_EX)
            if _entries(ledger_fd):
                raise ValueError
            empty = _anchor_for_entries(())
            _publish_anchor_history_once(anchor.parent, empty)
            _publish_anchor_once(anchor, empty)
    except Exception:
        raise KeyProviderError() from None


def recover_authorized_pending_append(
    ledger_root: Path,
    anchor_path: Path,
    *,
    expected_anchor: DestructionLedgerAnchor,
    authorized_entries: tuple[DestructionLedgerEntry, ...],
    required_owner_uid: int | None = None,
) -> None:
    """Repair one interrupted broker append, never an unauthorised extension."""

    try:
        root = Path(ledger_root)
        anchor = Path(anchor_path)
        _validate_directory(root, required_owner_uid=required_owner_uid)
        _validate_anchor_path(
            anchor,
            ledger_root=root,
            required_owner_uid=required_owner_uid,
        )
        with _directory_fd(root) as ledger_fd:
            fcntl.flock(ledger_fd, fcntl.LOCK_EX)
            local = _read_anchor(anchor)
            records = _records(ledger_fd)
            if not _anchor_is_prefix(expected_anchor, records):
                raise ValueError
            actual = _anchor_for_records(records)
            if local == actual:
                return
            if (
                len(records) != local.entry_count + 1
                or not _anchor_is_prefix(local, records)
                or records[-1].entry not in authorized_entries
            ):
                raise ValueError
            _publish_anchor_history_once(anchor.parent, actual)
            _replace_anchor(anchor, actual)
    except Exception:
        raise KeyProviderError() from None


def _records(ledger_fd: int) -> tuple[_LedgerRecord, ...]:
    names = sorted(os.listdir(ledger_fd))
    records: list[_LedgerRecord] = []
    for name in names:
        if not isinstance(name, str) or not name.startswith("destroyed-"):
            raise ValueError
        records.append(_read_record(ledger_fd, name))
    records.sort(key=lambda record: record.generation)
    previous = _empty_head()
    for generation, record in enumerate(records, start=1):
        if record.generation != generation or record.previous_sha256 != previous:
            raise ValueError
        previous = record.record_sha256
    if len({record.entry.content_key_id for record in records}) != len(records):
        raise ValueError
    return tuple(records)


def _entries(ledger_fd: int) -> tuple[DestructionLedgerEntry, ...]:
    return tuple(record.entry for record in _records(ledger_fd))


def _anchor_is_prefix(
    accepted: DestructionLedgerAnchor,
    records: tuple[_LedgerRecord, ...],
) -> bool:
    if accepted.entry_count > len(records):
        return False
    digest = (
        _empty_head()
        if accepted.entry_count == 0
        else records[accepted.entry_count - 1].record_sha256
    )
    return hmac.compare_digest(accepted.aggregate_sha256, digest)


def _validate_anchor_parent(
    anchor_path: Path,
    *,
    ledger_root: Path,
    required_owner_uid: int | None,
) -> None:
    if not anchor_path.is_absolute() or ".." in anchor_path.parts:
        raise ValueError
    anchor_parent = anchor_path.parent
    _validate_directory(
        anchor_parent,
        required_owner_uid=required_owner_uid,
        required_access=os.R_OK | os.X_OK,
    )
    resolved_ledger = ledger_root.resolve(strict=True)
    resolved_parent = anchor_parent.resolve(strict=True)
    if (
        resolved_ledger == resolved_parent
        or resolved_ledger.is_relative_to(resolved_parent)
        or resolved_parent.is_relative_to(resolved_ledger)
    ):
        raise ValueError


def _validate_anchor_path(
    anchor_path: Path,
    *,
    ledger_root: Path,
    required_owner_uid: int | None,
) -> None:
    _validate_anchor_parent(
        anchor_path,
        ledger_root=ledger_root,
        required_owner_uid=required_owner_uid,
    )
    if anchor_path.resolve(strict=True) != anchor_path:
        raise ValueError
    _read_anchor(anchor_path)


def _read_anchor(anchor_path: Path) -> DestructionLedgerAnchor:
    descriptor = os.open(anchor_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb", closefd=True) as handle:
        metadata = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != _ANCHOR_MODE
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_RECORD_BYTES
        ):
            raise ValueError
        raw = handle.read(_MAX_RECORD_BYTES + 1)
    if len(raw) != metadata.st_size or len(raw) > _MAX_RECORD_BYTES:
        raise ValueError
    return DestructionLedgerAnchor.from_bytes(raw)


def _publish_anchor_once(
    anchor_path: Path,
    anchor: DestructionLedgerAnchor,
) -> None:
    with _directory_fd(anchor_path.parent) as parent_fd:
        _publish_once(
            parent_fd,
            anchor_path.name,
            anchor.canonical_bytes(),
            mode=_ANCHOR_MODE,
        )
    if _read_anchor(anchor_path) != anchor:
        raise ValueError


def _anchor_history_name(anchor: DestructionLedgerAnchor) -> str:
    return f"accepted-{anchor.entry_count:020d}-{anchor.aggregate_sha256}.json"


def _publish_anchor_history_once(
    anchor_parent: Path,
    anchor: DestructionLedgerAnchor,
) -> None:
    with _directory_fd(anchor_parent) as parent_fd:
        _publish_once(
            parent_fd,
            _anchor_history_name(anchor),
            anchor.canonical_bytes(),
            mode=_ANCHOR_MODE,
        )


def _read_anchor_history(
    anchor_parent: Path,
    anchor: DestructionLedgerAnchor,
) -> DestructionLedgerAnchor:
    return _read_anchor(anchor_parent / _anchor_history_name(anchor))


def _replace_anchor(anchor_path: Path, anchor: DestructionLedgerAnchor) -> None:
    with _directory_fd(anchor_path.parent) as parent_fd:
        temporary = f".tmp-anchor-{os.urandom(16).hex()}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                _ANCHOR_MODE,
                dir_fd=parent_fd,
            )
            os.fchmod(descriptor, _ANCHOR_MODE)
            payload = anchor.canonical_bytes()
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, anchor_path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=parent_fd)
    if _read_anchor(anchor_path) != anchor:
        raise ValueError


def _validate_directory(
    path: Path,
    *,
    required_owner_uid: int | None,
    required_access: int = os.R_OK | os.W_OK | os.X_OK,
) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError
    path_lstat = path.lstat()
    if stat.S_ISLNK(path_lstat.st_mode) or path.resolve(strict=True) != path:
        raise ValueError
    if not os.access(path, required_access, effective_ids=True, follow_symlinks=False):
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


def _entry_document(
    entry: DestructionLedgerEntry,
    *,
    generation: int,
    previous_sha256: str,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "version": _RECORD_VERSION,
        "generation": generation,
        "previous_sha256": previous_sha256,
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


def _read_record(ledger_fd: int, name: str) -> _LedgerRecord:
    raw = _read_bounded_file(ledger_fd, name)
    parsed = parse_json_strict(raw)
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != raw:
        raise ValueError
    record = cast(dict[str, object], parsed)
    expected_fields = {
        "version",
        "generation",
        "previous_sha256",
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
    generation = record.get("generation")
    previous_sha256 = record.get("previous_sha256")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
        or not isinstance(previous_sha256, str)
        or len(previous_sha256) != 64
        or any(character not in "0123456789abcdef" for character in previous_sha256)
        or not isinstance(digest, str)
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
    return _LedgerRecord(entry, generation, previous_sha256, digest)


def _read_entry(ledger_fd: int, name: str) -> DestructionLedgerEntry:
    return _read_record(ledger_fd, name).entry


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


def _publish_once(
    directory_fd: int,
    destination: str,
    payload: bytes,
    *,
    mode: int = _RECORD_MODE,
) -> None:
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
    "LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH",
    "LOCAL_DESTRUCTION_LEDGER_ROOT",
    "DestructionLedgerAnchor",
    "DestructionLedgerEntry",
    "LocalDestructionLedger",
    "LocalDestructionLedgerWriter",
    "initialize_empty_destruction_ledger_anchor",
    "recover_authorized_pending_append",
]
