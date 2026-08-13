"""Content-free binding for the synthetic hard-forget recovery drill.

The helper inventories an already-created, drill-owned local key-provider copy.
It never creates, restores, activates, or removes provider state.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast
from uuid import UUID

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.security.keys import CONTENT_KEY_BYTES
from kivra_memory.security.local_key_provider import (
    CONTROL_DIRECTORY_NAME,
    MATERIAL_DIRECTORY_NAME,
    _record_identity,
    _require_control_record,
)

_MANIFEST_VERSION: Final = 1
_MAX_CONTROL_BYTES: Final = 2_048
_MAX_MANIFEST_BYTES: Final = 4_096
_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")


class HardForgetDrillError(RuntimeError):
    """Stable, content-free rejection for drill inventory or correlation."""


@dataclass(frozen=True, slots=True)
class ProviderBackupInventory:
    """Bounded inventory of one synthetic provider control/material pair."""

    active_control_count: int
    material_count: int
    byte_count: int
    aggregate_sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.active_control_count, bool)
            or not isinstance(self.active_control_count, int)
            or self.active_control_count != 1
            or isinstance(self.material_count, bool)
            or not isinstance(self.material_count, int)
            or self.material_count != 1
            or isinstance(self.byte_count, bool)
            or not isinstance(self.byte_count, int)
            or not CONTENT_KEY_BYTES < self.byte_count <= _MAX_CONTROL_BYTES + CONTENT_KEY_BYTES
            or not isinstance(self.aggregate_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.aggregate_sha256) is None
        ):
            raise ValueError("provider backup inventory is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "active_control_count": self.active_control_count,
            "material_count": self.material_count,
            "byte_count": self.byte_count,
            "aggregate_sha256": self.aggregate_sha256,
        }


@dataclass(frozen=True, slots=True)
class HardForgetDrillManifest:
    """Protected Phase 2 binding consumed unchanged by the Phase 5 drill."""

    provider_backup: ProviderBackupInventory
    base_backup_sha256: str
    wal_window_sha256: str
    recovery_target_sha256: str
    synthetic_correlation_sha256: str

    def __post_init__(self) -> None:
        for value in (
            self.base_backup_sha256,
            self.wal_window_sha256,
            self.recovery_target_sha256,
            self.synthetic_correlation_sha256,
        ):
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError("hard-forget drill manifest is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "version": _MANIFEST_VERSION,
            "provider_backup": self.provider_backup.as_dict(),
            "base_backup_sha256": self.base_backup_sha256,
            "wal_window_sha256": self.wal_window_sha256,
            "recovery_target_sha256": self.recovery_target_sha256,
            "synthetic_correlation_sha256": self.synthetic_correlation_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.as_dict())

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, raw: bytes) -> HardForgetDrillManifest:
        try:
            if len(raw) > _MAX_MANIFEST_BYTES:
                raise ValueError
            document = parse_json_strict(raw)
            if (
                not isinstance(document, dict)
                or set(document)
                != {
                    "version",
                    "provider_backup",
                    "base_backup_sha256",
                    "wal_window_sha256",
                    "recovery_target_sha256",
                    "synthetic_correlation_sha256",
                }
                or document.get("version") != _MANIFEST_VERSION
                or canonical_json_bytes(document) != raw
            ):
                raise ValueError
            provider = document["provider_backup"]
            if not isinstance(provider, dict) or set(provider) != {
                "active_control_count",
                "material_count",
                "byte_count",
                "aggregate_sha256",
            }:
                raise ValueError
            return cls(
                provider_backup=ProviderBackupInventory(
                    active_control_count=cast(int, provider["active_control_count"]),
                    material_count=cast(int, provider["material_count"]),
                    byte_count=cast(int, provider["byte_count"]),
                    aggregate_sha256=cast(str, provider["aggregate_sha256"]),
                ),
                base_backup_sha256=cast(str, document["base_backup_sha256"]),
                wal_window_sha256=cast(str, document["wal_window_sha256"]),
                recovery_target_sha256=cast(str, document["recovery_target_sha256"]),
                synthetic_correlation_sha256=cast(str, document["synthetic_correlation_sha256"]),
            )
        except Exception:
            raise HardForgetDrillError("hard_forget_drill_invalid") from None


def _regular_file_bytes(path: Path, *, expected_bytes: int | None, maximum_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ValueError
        if details.st_size > maximum_bytes or (
            expected_bytes is not None and details.st_size != expected_bytes
        ):
            raise ValueError
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        final_details = os.fstat(descriptor)
        if len(raw) != details.st_size or (
            final_details.st_dev,
            final_details.st_ino,
            final_details.st_size,
            final_details.st_mtime_ns,
            final_details.st_ctime_ns,
            final_details.st_nlink,
        ) != (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
            details.st_nlink,
        ):
            raise ValueError
        return bytes(raw)
    finally:
        os.close(descriptor)


def _directory_entries(path: Path) -> tuple[os.DirEntry[str], ...]:
    if not stat.S_ISDIR(path.stat(follow_symlinks=False).st_mode) or path.is_symlink():
        raise ValueError
    with os.scandir(path) as entries:
        return tuple(sorted(entries, key=lambda entry: entry.name))


def inventory_provider_backup(root: Path) -> ProviderBackupInventory:
    """Inventory exactly one inactive synthetic provider backup, read-only."""

    try:
        provider_root = Path(root)
        root_entries = _directory_entries(provider_root)
        if tuple(entry.name for entry in root_entries) != (
            CONTROL_DIRECTORY_NAME,
            MATERIAL_DIRECTORY_NAME,
        ):
            raise ValueError
        if any(not entry.is_dir(follow_symlinks=False) for entry in root_entries):
            raise ValueError

        control_root = provider_root / CONTROL_DIRECTORY_NAME
        material_root = provider_root / MATERIAL_DIRECTORY_NAME
        controls = _directory_entries(control_root)
        materials = _directory_entries(material_root)
        if len(controls) != 1 or len(materials) != 1:
            raise ValueError
        control_name = controls[0].name
        material_name = materials[0].name
        if not control_name.startswith("active-") or not control_name.endswith(".json"):
            raise ValueError
        content_key_id = UUID(control_name.removeprefix("active-").removesuffix(".json"))
        require_uuid7(content_key_id, field_name="content_key_id")
        if material_name != f"key-{content_key_id}.bin":
            raise ValueError

        control_bytes = _regular_file_bytes(
            control_root / control_name,
            expected_bytes=None,
            maximum_bytes=_MAX_CONTROL_BYTES,
        )
        material_bytes = _regular_file_bytes(
            material_root / material_name,
            expected_bytes=CONTENT_KEY_BYTES,
            maximum_bytes=CONTENT_KEY_BYTES,
        )
        control = parse_json_strict(control_bytes)
        if not isinstance(control, dict) or canonical_json_bytes(control) != control_bytes:
            raise ValueError
        identity = _record_identity(control)
        _require_control_record(control, state="active", identity=identity)
        if identity.get("content_key_id") != str(content_key_id):
            raise ValueError

        digest_document = {
            "version": _MANIFEST_VERSION,
            "entries": [
                {
                    "kind": "active_control",
                    "byte_count": len(control_bytes),
                    "sha256": hashlib.sha256(control_bytes).hexdigest(),
                },
                {
                    "kind": "key_material",
                    "byte_count": len(material_bytes),
                    "sha256": hashlib.sha256(material_bytes).hexdigest(),
                },
            ],
        }
        return ProviderBackupInventory(
            active_control_count=1,
            material_count=1,
            byte_count=len(control_bytes) + len(material_bytes),
            aggregate_sha256=hashlib.sha256(canonical_json_bytes(digest_document)).hexdigest(),
        )
    except Exception:
        raise HardForgetDrillError("provider_backup_inventory_invalid") from None


def synthetic_correlation_digest(
    *, ciphertext: bytes, provider_key_reference: str, drill_generation: str
) -> str:
    """Bind exact synthetic ciphertext, provider reference, and drill generation."""

    try:
        if (
            not isinstance(ciphertext, bytes)
            or not ciphertext
            or len(ciphertext) > 1_048_576
            or not isinstance(provider_key_reference, str)
            or not 1 <= len(provider_key_reference.encode("utf-8")) <= 512
            or not isinstance(drill_generation, str)
            or not 1 <= len(drill_generation.encode("utf-8")) <= 128
        ):
            raise ValueError
        binding = {
            "purpose": "scalevault-hard-forget-synthetic-correlation-v1",
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "provider_key_reference_sha256": hashlib.sha256(
                provider_key_reference.encode("utf-8")
            ).hexdigest(),
            "drill_generation_sha256": hashlib.sha256(drill_generation.encode("utf-8")).hexdigest(),
        }
        return hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
    except Exception:
        raise HardForgetDrillError("synthetic_correlation_invalid") from None


def create_hard_forget_drill_manifest(
    provider_root: Path,
    *,
    base_backup_sha256: str,
    wal_window_sha256: str,
    recovery_target_sha256: str,
    synthetic_correlation_sha256: str,
) -> HardForgetDrillManifest:
    """Create the immutable content-free Phase 2 drill binding."""

    try:
        return HardForgetDrillManifest(
            provider_backup=inventory_provider_backup(provider_root),
            base_backup_sha256=base_backup_sha256,
            wal_window_sha256=wal_window_sha256,
            recovery_target_sha256=recovery_target_sha256,
            synthetic_correlation_sha256=synthetic_correlation_sha256,
        )
    except HardForgetDrillError:
        raise
    except Exception:
        raise HardForgetDrillError("hard_forget_drill_invalid") from None


def verify_hard_forget_drill_manifest(
    manifest: HardForgetDrillManifest,
    provider_root: Path,
    *,
    base_backup_sha256: str,
    wal_window_sha256: str,
    recovery_target_sha256: str,
    synthetic_correlation_sha256: str,
) -> ProviderBackupInventory:
    """Require exact Phase 2/5 correlation before a stale-copy restore."""

    try:
        inventory = inventory_provider_backup(provider_root)
        if inventory != manifest.provider_backup:
            raise ValueError
        for actual, expected in (
            (base_backup_sha256, manifest.base_backup_sha256),
            (wal_window_sha256, manifest.wal_window_sha256),
            (recovery_target_sha256, manifest.recovery_target_sha256),
            (synthetic_correlation_sha256, manifest.synthetic_correlation_sha256),
        ):
            if (
                not isinstance(actual, str)
                or _SHA256_PATTERN.fullmatch(actual) is None
                or not hmac.compare_digest(actual, expected)
            ):
                raise ValueError
        return inventory
    except Exception:
        raise HardForgetDrillError("hard_forget_drill_mismatch") from None


def _read_manifest(path: Path) -> HardForgetDrillManifest:
    return HardForgetDrillManifest.from_bytes(
        _regular_file_bytes(path, expected_bytes=None, maximum_bytes=_MAX_MANIFEST_BYTES)
    )


def _publish_manifest_once(path: Path, manifest: HardForgetDrillManifest) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        payload = manifest.canonical_bytes()
        if os.write(descriptor, payload) != len(payload):
            raise OSError
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _report(mode: str, manifest: HardForgetDrillManifest) -> None:
    print(
        json.dumps(
            {
                "ok": True,
                "mode": mode,
                "manifest_sha256": manifest.manifest_sha256,
                "provider_backup": manifest.provider_backup.as_dict(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Bind or verify a synthetic hard-forget drill")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        subcommand = subcommands.add_parser(command)
        subcommand.add_argument("--provider-root", type=Path, required=True)
        subcommand.add_argument("--base-backup-sha256", required=True)
        subcommand.add_argument("--wal-window-sha256", required=True)
        subcommand.add_argument("--recovery-target-sha256", required=True)
        subcommand.add_argument("--synthetic-correlation-sha256", required=True)
        subcommand.add_argument(
            "--manifest" if command == "verify" else "--output",
            type=Path,
            required=True,
        )
    arguments = parser.parse_args()
    try:
        if arguments.command == "create":
            manifest = create_hard_forget_drill_manifest(
                arguments.provider_root,
                base_backup_sha256=arguments.base_backup_sha256,
                wal_window_sha256=arguments.wal_window_sha256,
                recovery_target_sha256=arguments.recovery_target_sha256,
                synthetic_correlation_sha256=arguments.synthetic_correlation_sha256,
            )
            _publish_manifest_once(arguments.output, manifest)
        else:
            manifest = _read_manifest(arguments.manifest)
            verify_hard_forget_drill_manifest(
                manifest,
                arguments.provider_root,
                base_backup_sha256=arguments.base_backup_sha256,
                wal_window_sha256=arguments.wal_window_sha256,
                recovery_target_sha256=arguments.recovery_target_sha256,
                synthetic_correlation_sha256=arguments.synthetic_correlation_sha256,
            )
        _report(arguments.command, manifest)
    except Exception:
        print("ScaleVault hard-forget drill binding failed", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()


__all__ = [
    "HardForgetDrillError",
    "HardForgetDrillManifest",
    "ProviderBackupInventory",
    "create_hard_forget_drill_manifest",
    "inventory_provider_backup",
    "main",
    "synthetic_correlation_digest",
    "verify_hard_forget_drill_manifest",
]
