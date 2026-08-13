"""Least-privilege reconciliation broker for sealed-key destruction requests."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from kivra_memory.security.credential_files import read_systemd_credential
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerAnchor,
    DestructionLedgerEntry,
    LocalDestructionLedgerWriter,
    recover_authorized_pending_append,
)
from kivra_memory.security.keys import ContentKeyReference, KeyProviderError
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    LOCAL_KEY_PROVIDER_NAME,
    LocalDirectoryKeyDestroyer,
    _canonical_base64,
    _directory_fd,
    _ledger_entry,
    _read_control_record,
    _record_identity,
    _require_control_record,
    reconcile_restored_local_key_provider,
)

_MAX_REQUESTS = 1024
_MAX_REQUEST_NAME_BYTES = 128
_MAX_WORK_PER_RUN = 32


@dataclass(frozen=True, slots=True)
class _Request:
    name: str
    entry: DestructionLedgerEntry


async def reconcile_destruction_requests(
    *,
    provider_root: Path,
    request_root: Path,
    ledger_root: Path,
    anchor_path: Path,
    expected_anchor: DestructionLedgerAnchor,
    required_owner_uid: int | None = None,
) -> int:
    """Apply immutable requests through the full privileged destruction path."""

    try:
        requests: list[_Request] = []
        with _directory_fd(Path(request_root)) as request_fd:
            names = sorted(os.listdir(request_fd))
            if len(names) > _MAX_REQUESTS:
                raise ValueError
            for name in names:
                if not isinstance(name, str) or len(name.encode("utf-8")) > _MAX_REQUEST_NAME_BYTES:
                    raise ValueError
                record = _read_control_record(request_fd, name)
                identity = _record_identity(record)
                _require_control_record(record, state="destroyed", identity=identity)
                content_key_id = UUID(str(identity["content_key_id"]))
                if name != f"destroyed-{content_key_id}.json":
                    raise ValueError
                receipt = _canonical_base64(record.get("receipt"), expected_bytes=32)
                requests.append(_Request(name, _ledger_entry(identity=identity, receipt=receipt)))

        recover_authorized_pending_append(
            ledger_root,
            anchor_path,
            expected_anchor=expected_anchor,
            authorized_entries=tuple(request.entry for request in requests),
            required_owner_uid=required_owner_uid,
        )
        writer = LocalDestructionLedgerWriter(
            ledger_root,
            anchor_path=anchor_path,
            expected_anchor=expected_anchor,
            required_owner_uid=required_owner_uid,
        )
        destroyer = LocalDirectoryKeyDestroyer(
            provider_root,
            destruction_ledger_root=ledger_root,
            destruction_ledger_anchor_path=anchor_path,
            required_owner_uid=required_owner_uid,
        )
        ledger_entries = {entry.content_key_id: entry for entry in writer.entries()}
        for request in requests:
            existing = ledger_entries.get(request.entry.content_key_id)
            if existing is not None:
                if existing != request.entry:
                    raise ValueError
                continue
            with _directory_fd(Path(provider_root) / CONTROL_DIRECTORY_NAME) as control_fd:
                active = _read_control_record(
                    control_fd,
                    f"active-{request.entry.content_key_id}.json",
                )
                identity = _record_identity(active)
                _require_control_record(active, state="active", identity=identity)
                receipt = _canonical_base64(active.get("receipt"), expected_bytes=32)
            if _ledger_entry(identity=identity, receipt=receipt) != request.entry:
                raise ValueError

        applied = 0
        with _directory_fd(Path(request_root)) as request_fd:
            for request in requests[:_MAX_WORK_PER_RUN]:
                existing = ledger_entries.get(request.entry.content_key_id)
                if existing is None:
                    reference = ContentKeyReference(
                        content_key_id=request.entry.content_key_id,
                        provider_name=LOCAL_KEY_PROVIDER_NAME,
                        provider_key_reference=(
                            f"{LOCAL_KEY_PROVIDER_NAME}:{request.entry.content_key_id}"
                        ),
                    )
                    result = await destroyer.destroy_requested_key(reference, request.entry)
                    if result.receipt != request.entry.receipt:
                        raise ValueError
                if writer.lookup(request.entry.content_key_id) != request.entry:
                    raise ValueError
                ledger_entries[request.entry.content_key_id] = request.entry
                os.unlink(request.name, dir_fd=request_fd)
                os.fsync(request_fd)
                applied += 1
        return applied
    except Exception:
        raise KeyProviderError() from None


def main() -> None:
    import asyncio

    try:
        from kivra_memory.security.destruction_ledger import (
            LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
            LOCAL_DESTRUCTION_LEDGER_ROOT,
        )
        from kivra_memory.security.local_key_provider import (
            LOCAL_DESTRUCTION_REQUEST_ROOT,
            LOCAL_KEY_PROVIDER_ROOT,
        )

        anchor_bytes = read_systemd_credential(
            "destruction-ledger-anchor",
            minimum_bytes=1,
            maximum_bytes=512,
        )
        if not isinstance(anchor_bytes, bytes):
            raise ValueError

        asyncio.run(
            reconcile_destruction_requests(
                provider_root=LOCAL_KEY_PROVIDER_ROOT,
                request_root=LOCAL_DESTRUCTION_REQUEST_ROOT,
                ledger_root=LOCAL_DESTRUCTION_LEDGER_ROOT,
                anchor_path=LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
                expected_anchor=DestructionLedgerAnchor.from_bytes(anchor_bytes),
                required_owner_uid=0,
            )
        )
    except Exception:
        print("ScaleVault destruction broker is unavailable", file=sys.stderr)
        raise SystemExit(2) from None


def restore_reconcile_main() -> None:
    """Reconcile a restored provider before API or ingress activation."""

    try:
        from kivra_memory.security.destruction_ledger import (
            LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
            LOCAL_DESTRUCTION_LEDGER_ROOT,
        )
        from kivra_memory.security.local_key_provider import LOCAL_KEY_PROVIDER_ROOT

        anchor_bytes = read_systemd_credential(
            "destruction-ledger-anchor",
            minimum_bytes=1,
            maximum_bytes=512,
        )
        if not isinstance(anchor_bytes, bytes):
            raise ValueError
        reconcile_restored_local_key_provider(
            LOCAL_KEY_PROVIDER_ROOT,
            destruction_ledger_root=LOCAL_DESTRUCTION_LEDGER_ROOT,
            destruction_ledger_anchor_path=LOCAL_DESTRUCTION_LEDGER_ANCHOR_PATH,
            expected_destruction_ledger_anchor=DestructionLedgerAnchor.from_bytes(anchor_bytes),
            required_owner_uid=0,
        )
    except Exception:
        print("ScaleVault sealed restore reconciliation is unavailable", file=sys.stderr)
        raise SystemExit(2) from None


__all__ = ["main", "reconcile_destruction_requests", "restore_reconcile_main"]
