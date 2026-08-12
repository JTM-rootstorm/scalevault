"""Dedicated single-target archive exporter process."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote
from uuid import UUID

from pydantic import PostgresDsn, TypeAdapter, ValidationError

from kivra_memory import __version__
from kivra_memory.archive.adapters import (
    DeterministicArchiveBuilder,
    GitWorktreeArchiveRepository,
    GitWorktreeConfig,
)
from kivra_memory.archive.git import GitSigningConfig
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.security.credential_files import read_systemd_credential_text
from kivra_memory.storage.archive import ArchiveExportBusy
from kivra_memory.storage.database import Database
from kivra_memory.workers.archive_exporter import export_archive_target


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or any(character in value for character in "\r\n\x00"):
        raise RuntimeError("invalid_archive_exporter_configuration")
    return value


def _positive_float(name: str, default: str, *, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        raise RuntimeError("invalid_archive_exporter_configuration") from None
    if not 0.1 <= value <= maximum:
        raise RuntimeError("invalid_archive_exporter_configuration")
    return value


def _local_database_url(name: str) -> str:
    try:
        raw_value = os.environ.get(name, "")
        if os.environ.get("CREDENTIALS_DIRECTORY") or not raw_value:
            raw_value = read_systemd_credential_text(
                "database-url", minimum_bytes=1, maximum_bytes=4096
            )
        value = TypeAdapter(PostgresDsn).validate_python(raw_value)
        if value.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}:
            raise ValueError
        if {key for key, _item in value.query_params()} & {
            "host",
            "hostaddr",
            "service",
            "servicefile",
        }:
            raise ValueError
        allowed = {"localhost", "127.0.0.1", "::1", "/run/postgresql", "/var/run/postgresql"}
        if any(
            host["host"] is None
            or unquote(str(host["host"])).removeprefix("[").removesuffix("]") not in allowed
            for host in value.hosts()
        ):
            raise ValueError
    except (OSError, ValidationError, ValueError):
        raise RuntimeError("invalid_archive_exporter_configuration") from None
    return str(value)


@dataclass(frozen=True, slots=True)
class ArchiveExporterSettings:
    database_url: str = field(repr=False)
    tenant_id: UUID
    archive_target_id: UUID
    repository: Path
    repository_reference: str
    branch_name: str
    schema_root: Path
    signing_key: Path
    deploy_key: Path
    allowed_signers_file: Path
    known_hosts_file: Path
    signer_principal: str
    author_name: str
    author_email: str
    poll_interval_seconds: float = 60.0

    @classmethod
    def from_environment(cls) -> ArchiveExporterSettings:
        try:
            database_url = _local_database_url("KIVRA_MEMORY_ARCHIVE_DATABASE_URL")
            tenant_id = UUID(_required("KIVRA_MEMORY_ARCHIVE_TENANT_ID"))
            archive_target_id = UUID(_required("KIVRA_MEMORY_ARCHIVE_TARGET_ID"))
            require_uuid7(tenant_id, field_name="tenant_id")
            require_uuid7(archive_target_id, field_name="archive_target_id")
            credentials = Path(_required("CREDENTIALS_DIRECTORY"))
            if not credentials.is_absolute():
                raise ValueError
        except ValueError:
            raise RuntimeError("invalid_archive_exporter_configuration") from None
        repository = Path(_required("KIVRA_MEMORY_ARCHIVE_REPOSITORY"))
        schema_root = Path(
            os.environ.get("KIVRA_MEMORY_ARCHIVE_SCHEMA_ROOT", "/opt/kivra-memory/app/schemas")
        )
        signing_key = credentials / "archive-signing-key"
        deploy_key = credentials / "archive-deploy-key"
        paths = (
            repository,
            schema_root,
            signing_key,
            deploy_key,
            Path(_required("KIVRA_MEMORY_ARCHIVE_ALLOWED_SIGNERS_FILE")),
            Path(_required("KIVRA_MEMORY_ARCHIVE_KNOWN_HOSTS_FILE")),
        )
        if any(not path.is_absolute() for path in paths):
            raise RuntimeError("invalid_archive_exporter_configuration")
        if not repository.is_relative_to(Path("/mnt/memory")):
            raise RuntimeError("invalid_archive_exporter_configuration")
        return cls(
            database_url=database_url,
            tenant_id=tenant_id,
            archive_target_id=archive_target_id,
            repository=repository,
            repository_reference=_required("KIVRA_MEMORY_ARCHIVE_REPOSITORY_REFERENCE"),
            branch_name=_required("KIVRA_MEMORY_ARCHIVE_BRANCH"),
            schema_root=schema_root,
            signing_key=signing_key,
            deploy_key=deploy_key,
            allowed_signers_file=paths[4],
            known_hosts_file=paths[5],
            signer_principal=_required("KIVRA_MEMORY_ARCHIVE_SIGNER_PRINCIPAL"),
            author_name=_required("KIVRA_MEMORY_ARCHIVE_AUTHOR_NAME"),
            author_email=_required("KIVRA_MEMORY_ARCHIVE_AUTHOR_EMAIL"),
            poll_interval_seconds=_positive_float(
                "KIVRA_MEMORY_ARCHIVE_POLL_INTERVAL_SECONDS", "60", maximum=3600
            ),
        )


class ArchiveExporterLoop:
    def __init__(self, settings: ArchiveExporterSettings) -> None:
        self._settings = settings
        self._database = Database(settings.database_url)
        signing = GitSigningConfig(
            repository=settings.repository,
            signing_key=settings.signing_key,
            allowed_signers_file=settings.allowed_signers_file,
            signer_principal=settings.signer_principal,
            author_name=settings.author_name,
            author_email=settings.author_email,
        )
        self._builder = DeterministicArchiveBuilder(
            schema_root=settings.schema_root,
            exporter_version=__version__,
        )
        self._repository = GitWorktreeArchiveRepository(
            GitWorktreeConfig(
                repository=settings.repository,
                repository_reference=settings.repository_reference,
                branch_name=settings.branch_name,
                deploy_key=settings.deploy_key,
                known_hosts_file=settings.known_hosts_file,
                signing=signing,
            )
        )

    async def run_once(self) -> bool:
        try:
            async with self._database.tenant_session(self._settings.tenant_id) as session:
                result = await export_archive_target(
                    session,
                    tenant_id=self._settings.tenant_id,
                    archive_target_id=self._settings.archive_target_id,
                    exporter_version=__version__,
                    builder=self._builder,
                    repository=self._repository,
                )
        except ArchiveExportBusy:
            return False
        return result is not None

    async def close(self) -> None:
        await self._database.dispose()


async def run_exporter(settings: ArchiveExporterSettings) -> None:
    exporter = ArchiveExporterLoop(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(selected_signal, stop.set)
    try:
        while not stop.is_set():
            await exporter.run_once()
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.poll_interval_seconds)
    finally:
        await exporter.close()


def main() -> None:
    """Run without reflecting archive paths, payloads, or subprocess output."""

    try:
        settings = ArchiveExporterSettings.from_environment()
        asyncio.run(run_exporter(settings))
    except Exception:
        print("ScaleVault archive exporter failed safely", file=sys.stderr)
        raise SystemExit(2) from None


__all__ = ["ArchiveExporterLoop", "ArchiveExporterSettings", "main", "run_exporter"]
