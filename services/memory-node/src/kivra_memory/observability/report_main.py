"""Protected root-local CLI for tenant-scoped metadata-only operator reports."""

from __future__ import annotations

import argparse
import asyncio
import errno
import os
import stat
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Final
from uuid import UUID

from sqlalchemy.engine import make_url

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.observability.reports import OperatorReportRepository
from kivra_memory.security.credential_files import read_systemd_credential_text
from kivra_memory.storage.database import Database

DATABASE_CREDENTIAL_NAME: Final = "database-url"
_DATABASE_URL_MAXIMUM_BYTES: Final = 4_096


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kivra-memory-operator-report",
        description="Write a protected tenant-scoped metadata report.",
    )
    parser.add_argument("--tenant-id", type=UUID, required=True)
    parser.add_argument("--window-days", type=int, choices=range(1, 91), default=30)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _database_url_from_systemd_credential() -> str:
    """Load only the local, dedicated operator-report login credential."""

    try:
        value = read_systemd_credential_text(
            DATABASE_CREDENTIAL_NAME,
            minimum_bytes=1,
            maximum_bytes=_DATABASE_URL_MAXIMUM_BYTES,
        )
        url = make_url(value)
        if (
            url.drivername not in {"postgresql", "postgresql+psycopg"}
            or url.username != "kivra_memory_operator_report_login"
            or url.database != "kivra_memory"
            or url.host not in {None, "localhost", "127.0.0.1", "::1"}
            or set(url.query) & {"host", "hostaddr", "service", "servicefile"}
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("operator_report_database_credential_invalid") from None
    return value


async def _render(arguments: argparse.Namespace, database_url: str) -> bytes:
    database = Database(database_url)
    try:
        report = await OperatorReportRepository(database).collect(
            arguments.tenant_id,
            window_days=arguments.window_days,
        )
        return canonical_json_bytes(report.as_dict()) + b"\n"
    finally:
        await database.dispose()


def _publish_report(path: Path, payload: bytes) -> None:
    """Atomically publish one new mode-0600 report in a protected directory."""

    directory_fd = -1
    descriptor = -1
    temporary_name: str | None = None
    destination_reserved = False
    destination = Path(path)
    try:
        if not destination.is_absolute() or ".." in destination.parts or not destination.name:
            raise ValueError
        parent = destination.parent
        if parent.resolve(strict=True) != parent or stat.S_ISLNK(parent.lstat().st_mode):
            raise ValueError
        directory_fd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        directory_status = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_status.st_mode)
            or directory_status.st_uid != os.geteuid()
            or stat.S_IMODE(directory_status.st_mode) & 0o077
        ):
            raise ValueError

        descriptor = os.open(
            destination.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o000,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o000)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        destination_reserved = True
        os.fsync(directory_fd)

        temporary_name = f".operator-report-{os.urandom(16).hex()}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None
        destination_reserved = False
        os.fsync(directory_fd)
    except Exception:
        raise ValueError("operator_report_output_failed") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)
            if destination_reserved:
                with suppress(FileNotFoundError):
                    os.unlink(destination.name, dir_fd=directory_fd)
            os.close(directory_fd)


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _parser().parse_args(argv)
    if os.geteuid() != 0:
        print("ScaleVault operator report requires root", file=sys.stderr)
        raise SystemExit(77)
    try:
        database_url = _database_url_from_systemd_credential()
        rendered = asyncio.run(_render(arguments, database_url))
        _publish_report(arguments.output, rendered)
    except Exception:
        print("ScaleVault operator report failed", file=sys.stderr)
        raise SystemExit(1) from None


__all__ = ["DATABASE_CREDENTIAL_NAME", "main"]
