"""Content-safe operator CLI for signed archive and secondary-bundle recovery."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Never
from urllib.parse import unquote

from pydantic import PostgresDsn, TypeAdapter, ValidationError
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory import __version__
from kivra_memory.archive.bundle import EncryptedArchiveBundle
from kivra_memory.archive.git import GitCommitVerifier, GitVerificationConfig
from kivra_memory.archive.models import require_sha256
from kivra_memory.archive.recovery import GitRecoverySource, ReadOnlyGitArchive
from kivra_memory.archive.restore import build_restore_plan
from kivra_memory.archive.verification import (
    ArchiveSignerEpoch,
    VerifiedArchive,
    verify_signed_archive_epochs,
)
from kivra_memory.storage.archive import RestorePlan as DatabaseRestorePlan
from kivra_memory.storage.base import Base
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    MemoryEvent,
    MemoryEventCounter,
    SelectionDecisionCounter,
)
from kivra_memory.storage.readiness import EXPECTED_ALEMBIC_HEAD
from kivra_memory.workers.archive_restore import (
    CoreRestoreDecoder,
    restore_validated_archive,
)

_RESTORE_CONFIRMATION = "restore-into-disposable-empty-database"


class RecoveryConfigurationError(ValueError):
    """A content-free recovery configuration failure."""


@dataclass(frozen=True, slots=True)
class SignerEpochSettings:
    first_event_sequence: int
    last_event_sequence: int | None
    allowed_signers_file: Path
    signer_principal: str
    author_name: str
    author_email: str

    def build(self, repository: Path) -> ArchiveSignerEpoch:
        return ArchiveSignerEpoch(
            first_event_sequence=self.first_event_sequence,
            last_event_sequence=self.last_event_sequence,
            verifier=GitCommitVerifier(
                GitVerificationConfig(
                    repository=repository,
                    allowed_signers_file=self.allowed_signers_file,
                    signer_principal=self.signer_principal,
                    author_name=self.author_name,
                    author_email=self.author_email,
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class ArchiveRecoverySettings:
    repository: Path
    branch_name: str
    expected_head: str
    expected_manifest_sha256: str
    expected_high_water_sequence: int
    expected_application_version: str
    expected_alembic_revision: str
    signer_epochs: tuple[SignerEpochSettings, ...]
    database_url_file: Path | None = None
    disposable_database_name: str | None = None

    @classmethod
    def load(cls, path: Path) -> ArchiveRecoverySettings:
        document = _read_regular_file(path, secret=False)
        try:
            value = json.loads(document)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RecoveryConfigurationError("invalid recovery configuration") from None
        if not isinstance(value, Mapping):
            raise RecoveryConfigurationError("invalid recovery configuration")
        required = {
            "repository",
            "branch_name",
            "expected_head",
            "expected_manifest_sha256",
            "expected_high_water_sequence",
            "expected_application_version",
            "expected_alembic_revision",
            "signer_epochs",
        }
        optional = {"database_url_file", "disposable_database_name"}
        if set(value) != required | (set(value) & optional):
            raise RecoveryConfigurationError("invalid recovery configuration")
        epochs_value = value["signer_epochs"]
        if not isinstance(epochs_value, list) or not epochs_value:
            raise RecoveryConfigurationError("invalid recovery signer epochs")
        epochs: list[SignerEpochSettings] = []
        high_water = value["expected_high_water_sequence"]
        if isinstance(high_water, bool) or not isinstance(high_water, int) or high_water < 1:
            raise RecoveryConfigurationError("invalid recovery configuration")
        for item in epochs_value:
            if not isinstance(item, Mapping) or set(item) != {
                "first_event_sequence",
                "last_event_sequence",
                "allowed_signers_file",
                "signer_principal",
                "author_name",
                "author_email",
            }:
                raise RecoveryConfigurationError("invalid recovery signer epochs")
            first = item["first_event_sequence"]
            last = item["last_event_sequence"]
            if (
                isinstance(first, bool)
                or not isinstance(first, int)
                or (last is not None and (isinstance(last, bool) or not isinstance(last, int)))
                or not all(
                    isinstance(item[name], str)
                    for name in (
                        "allowed_signers_file",
                        "signer_principal",
                        "author_name",
                        "author_email",
                    )
                )
            ):
                raise RecoveryConfigurationError("invalid recovery signer epochs")
            epochs.append(
                SignerEpochSettings(
                    first_event_sequence=first,
                    last_event_sequence=last,
                    allowed_signers_file=Path(str(item["allowed_signers_file"])),
                    signer_principal=str(item["signer_principal"]),
                    author_name=str(item["author_name"]),
                    author_email=str(item["author_email"]),
                )
            )
        try:
            settings = cls(
                repository=Path(_string(value, "repository")),
                branch_name=_string(value, "branch_name"),
                expected_head=_string(value, "expected_head"),
                expected_manifest_sha256=_string(value, "expected_manifest_sha256"),
                expected_high_water_sequence=high_water,
                expected_application_version=_string(value, "expected_application_version"),
                expected_alembic_revision=_string(value, "expected_alembic_revision"),
                signer_epochs=tuple(epochs),
                database_url_file=(
                    Path(_string(value, "database_url_file"))
                    if "database_url_file" in value
                    else None
                ),
                disposable_database_name=(
                    _string(value, "disposable_database_name")
                    if "disposable_database_name" in value
                    else None
                ),
            )
            settings.source()
            settings.epochs_for(settings.repository)
            require_sha256(settings.expected_manifest_sha256, "external manifest anchor")
            _validate_epoch_settings(settings.signer_epochs)
            for epoch in settings.signer_epochs:
                _read_regular_file(epoch.allowed_signers_file, secret=False)
        except (TypeError, ValueError):
            raise RecoveryConfigurationError("invalid recovery configuration") from None
        return settings

    def source(self, *, repository: Path | None = None) -> GitRecoverySource:
        return GitRecoverySource(
            repository=repository or self.repository,
            branch_name=self.branch_name,
            expected_head=self.expected_head,
        )

    def epochs_for(self, repository: Path) -> tuple[ArchiveSignerEpoch, ...]:
        return tuple(epoch.build(repository) for epoch in self.signer_epochs)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        self.print_usage(sys.stderr)
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(prog="kivra-memory-archive-recovery")
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify")
    bundle = commands.add_parser("bundle-create")
    bundle.add_argument("--destination", type=Path, required=True)
    bundle.add_argument("--scratch-directory", type=Path, required=True)
    bundle.add_argument("--recipient", required=True)
    materialize = commands.add_parser("bundle-materialize")
    materialize.add_argument("--encrypted-bundle", type=Path, required=True)
    materialize.add_argument("--expected-ciphertext-sha256", required=True)
    materialize.add_argument("--identity-file", type=Path, required=True)
    materialize.add_argument("--output-repository", type=Path, required=True)
    materialize.add_argument("--scratch-directory", type=Path, required=True)
    restore = commands.add_parser("restore-database")
    restore.add_argument("--confirmation", required=True)
    return parser


def _verified(
    settings: ArchiveRecoverySettings,
    *,
    repository: Path | None = None,
) -> VerifiedArchive:
    source = settings.source(repository=repository)
    commits = ReadOnlyGitArchive(source).read()
    verified = verify_signed_archive_epochs(commits, settings.epochs_for(source.repository))
    if any(
        commit.batch.manifest.exporter_version != settings.expected_application_version
        for commit in verified.commits
    ):
        raise RecoveryConfigurationError("archive application release is incompatible")
    final_manifest = verified.commits[-1].batch
    if (
        final_manifest.manifest_sha256 != settings.expected_manifest_sha256
        or final_manifest.manifest.source_high_water_sequence
        != settings.expected_high_water_sequence
    ):
        raise RecoveryConfigurationError("archive prefix does not match the external anchor")
    if settings.expected_application_version != __version__:
        raise RecoveryConfigurationError("recovery application release is incompatible")
    if settings.expected_alembic_revision != EXPECTED_ALEMBIC_HEAD:
        raise RecoveryConfigurationError("recovery migration revision is incompatible")
    return verified


def _summary(verified: VerifiedArchive) -> dict[str, object]:
    first = verified.commits[0].batch.manifest
    last = verified.commits[-1].batch.manifest
    return {
        "ok": True,
        "commit_count": len(verified.commits),
        "first_event_sequence": first.first_event_sequence,
        "final_high_water_sequence": last.source_high_water_sequence,
        "head": verified.commits[-1].git.commit_sha,
    }


async def _restore_database(
    settings: ArchiveRecoverySettings,
    verified: VerifiedArchive,
    confirmation: str,
) -> dict[str, object]:
    if confirmation != _RESTORE_CONFIRMATION:
        raise RecoveryConfigurationError("restore confirmation is invalid")
    if settings.database_url_file is None or settings.disposable_database_name is None:
        raise RecoveryConfigurationError("restore database configuration is incomplete")
    if not settings.disposable_database_name.startswith("scalevault_recovery_"):
        raise RecoveryConfigurationError("restore database is not explicitly disposable")
    database_url = _local_database_url(
        _read_regular_file(settings.database_url_file, secret=True).decode("utf-8").strip()
    )
    core_plan = build_restore_plan(verified)
    decoded = CoreRestoreDecoder().decode(core_plan)
    database = Database(database_url)
    try:
        async with database.tenant_session(decoded.tenant_id) as session:
            await _require_clean_database(
                session,
                database_name=settings.disposable_database_name,
                expected_revision=settings.expected_alembic_revision,
            )
            result = await restore_validated_archive(
                session,
                verified_plan=core_plan,
                decoder=CoreRestoreDecoder(),
                verifier=_HighWaterVerifier(),
                requeue_embeddings=True,
            )
    finally:
        await database.dispose()
    return {
        "ok": True,
        "final_high_water_sequence": result.final_high_water_sequence,
        "embedding_jobs_queued": result.embedding_jobs_queued,
        "continuation": "new_immutable_archive_target_required",
    }


class _HighWaterVerifier:
    async def verify(self, session: AsyncSession, plan: DatabaseRestorePlan) -> None:
        count = await session.scalar(
            select(func.count())
            .select_from(MemoryEvent)
            .where(MemoryEvent.tenant_id == plan.tenant_id)
        )
        high_water = await session.scalar(
            select(func.max(MemoryEvent.sequence)).where(MemoryEvent.tenant_id == plan.tenant_id)
        )
        if count != plan.final_high_water_sequence or high_water != plan.final_high_water_sequence:
            raise RecoveryConfigurationError("restored canonical event prefix is inconsistent")


async def _require_clean_database(
    session: AsyncSession,
    *,
    database_name: str,
    expected_revision: str,
) -> None:
    actual_name = await session.scalar(text("SELECT current_database()"))
    version = await session.scalar(text("SELECT version_num FROM public.alembic_version"))
    row_security = await session.scalar(text("SELECT row_security_active('tenants'::regclass)"))
    if actual_name != database_name or version != expected_revision or row_security is not False:
        raise RecoveryConfigurationError("restore database preflight failed")
    if (
        await session.scalar(select(MemoryEventCounter.next_sequence)) != 1
        or await session.scalar(select(SelectionDecisionCounter.next_sequence)) != 1
    ):
        raise RecoveryConfigurationError("restore database counters are not clean")
    counter_tables = {
        MemoryEventCounter.__table__,
        SelectionDecisionCounter.__table__,
    }
    for table in Base.metadata.sorted_tables:
        if table in counter_tables:
            continue
        present = await session.scalar(select(table).limit(1))
        if present is not None:
            raise RecoveryConfigurationError("restore database is not empty")


def _read_regular_file(path: Path, *, secret: bool) -> bytes:
    if not path.is_absolute():
        raise RecoveryConfigurationError("recovery file path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise RecoveryConfigurationError("recovery file is unavailable") from None
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise RecoveryConfigurationError("recovery file is unsafe")
        if secret and details.st_mode & 0o077:
            raise RecoveryConfigurationError("recovery secret file permissions are unsafe")
        if details.st_size > 1024 * 1024:
            raise RecoveryConfigurationError("recovery file is oversized")
        content = os.read(descriptor, details.st_size + 1)
        if len(content) != details.st_size:
            raise RecoveryConfigurationError("recovery file changed while reading")
        return content
    finally:
        os.close(descriptor)


def _local_database_url(value: str) -> str:
    try:
        parsed = TypeAdapter(PostgresDsn).validate_python(value)
        hosts = {
            unquote(str(host["host"])).removeprefix("[").removesuffix("]")
            for host in parsed.hosts()
            if host["host"] is not None
        }
        forbidden_query = {"host", "hostaddr", "service", "servicefile"}
        if (
            parsed.scheme not in {"postgres", "postgresql", "postgresql+psycopg"}
            or len(hosts) != len(parsed.hosts())
            or not hosts
            or not hosts
            <= {
                "localhost",
                "127.0.0.1",
                "::1",
                "/run/postgresql",
                "/var/run/postgresql",
            }
            or {key for key, _value in parsed.query_params()} & forbidden_query
        ):
            raise ValueError
    except (ValidationError, ValueError):
        raise RecoveryConfigurationError("restore database URL is invalid") from None
    return str(parsed)


def _string(mapping: Mapping[object, object], name: str) -> str:
    value = mapping[name]
    if (
        not isinstance(value, str)
        or not value
        or any(character in value for character in "\r\n\x00")
    ):
        raise RecoveryConfigurationError("invalid recovery configuration")
    return value


def _validate_epoch_settings(epochs: Sequence[SignerEpochSettings]) -> None:
    expected = 1
    for index, epoch in enumerate(epochs):
        if epoch.first_event_sequence != expected:
            raise RecoveryConfigurationError("invalid recovery signer epochs")
        if epoch.last_event_sequence is None:
            if index != len(epochs) - 1:
                raise RecoveryConfigurationError("invalid recovery signer epochs")
        else:
            expected = epoch.last_event_sequence + 1


def main(arguments: Sequence[str] | None = None) -> None:
    """Run recovery commands with fixed JSON output and sanitized failures."""

    try:
        parsed = _parser().parse_args(arguments)
        settings = ArchiveRecoverySettings.load(parsed.config)
        if parsed.command == "verify":
            output = _summary(_verified(settings))
        elif parsed.command == "bundle-create":
            result = EncryptedArchiveBundle().create(
                source=settings.source(),
                destination=parsed.destination,
                scratch_directory=parsed.scratch_directory,
                recipient=parsed.recipient,
                signer_epochs=settings.epochs_for(settings.repository),
            )
            output = {
                "ok": True,
                "head": result.source_head,
                "ciphertext_sha256": result.ciphertext_sha256,
                "ciphertext_size": result.ciphertext_size,
            }
        elif parsed.command == "bundle-materialize":
            source = EncryptedArchiveBundle().materialize(
                encrypted_bundle=parsed.encrypted_bundle,
                expected_ciphertext_sha256=parsed.expected_ciphertext_sha256,
                identity_file=parsed.identity_file,
                output_repository=parsed.output_repository,
                scratch_directory=parsed.scratch_directory,
                branch_name=settings.branch_name,
                expected_head=settings.expected_head,
                signer_epochs=settings.epochs_for(parsed.output_repository),
            )
            output = _summary(_verified(settings, repository=source.repository))
        elif parsed.command == "restore-database":
            output = asyncio.run(
                _restore_database(settings, _verified(settings), parsed.confirmation)
            )
        else:
            raise RecoveryConfigurationError("unsupported recovery command")
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    except Exception:
        print("ScaleVault archive recovery failed safely", file=sys.stderr)
        raise SystemExit(2) from None
