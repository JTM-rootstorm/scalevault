"""Database boundary for deterministic archive export and clean restore."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from types import MappingProxyType
from typing import cast
from uuid import UUID

from sqlalchemy import (
    JSON,
    DateTime,
    LargeBinary,
    Numeric,
    Uuid,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import DeclarativeBase

from kivra_memory.domain.canonical_json import (
    canonical_json_bytes,
    normalize_json_value,
    parse_json_strict,
)
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.domain.values import format_utc_datetime
from kivra_memory.storage.models import (
    Actor,
    ArchiveExportCheckpoint,
    ArchiveTarget,
    Branch,
    Client,
    CommandReceipt,
    GenesisImportExclusion,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportRunResult,
    GenesisImportSource,
    GenesisImportSupersession,
    IngressItem,
    IngressProviderViolation,
    Lineage,
    LogicalSession,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    MemoryEvent,
    MemoryEventCounter,
    MemoryEvidence,
    MemoryLink,
    Persona,
    SelectionDecision,
    SelectionDecisionCounter,
    Subject,
    SubjectAlias,
    Tenant,
    TransportBinding,
    TransportInstallation,
)
from kivra_memory.storage.projector import ProjectionPersistenceError, event_row_to_domain

type ArchiveScalar = bool | int | float | str | bytes | None
type ArchiveValue = ArchiveScalar | list[ArchiveValue] | dict[str, ArchiveValue]
type ArchiveRecord = dict[str, ArchiveValue]

_ARCHIVE_LOCK_DOMAIN = b"sv-archive-v1"


class ArchiveStorageError(RuntimeError):
    """A content-free archive persistence failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


class ArchiveExportBusy(ArchiveStorageError):
    """The target already has an exporter holding its transaction lock."""

    def __init__(self) -> None:
        super().__init__("archive_export_busy")


@dataclass(frozen=True, slots=True)
class ArchiveBatchSource:
    """Committed source prefix represented without ORM instances."""

    tenant_id: str
    archive_target_id: str
    previous_checkpoint_id: str | None
    previous_manifest_sha256: str | None
    previous_git_commit_sha: str | None
    source_high_water_sequence: int
    first_event_sequence: int
    last_event_sequence: int
    event_count: int
    export_timestamp: str
    events: tuple[ArchiveRecord, ...]
    recovery_primary_keys: Mapping[str, tuple[str, ...]]
    recovery_rows: Mapping[str, tuple[ArchiveRecord, ...]]


@dataclass(frozen=True, slots=True)
class RestorePlan:
    """Database rows decoded only after archive preflight verification."""

    tenant_id: UUID
    snapshot_high_water_sequence: int
    final_high_water_sequence: int
    rows: Mapping[str, Sequence[Mapping[str, object]]]
    later_events: Sequence[Mapping[str, object]] = ()


# Fixed dependency order is part of the restore contract. Credential material,
# derived embeddings, outbox leases, archive configuration, and checkpoints are
# intentionally absent.
_RECOVERY_MODELS: tuple[type[DeclarativeBase], ...] = (
    Tenant,
    Actor,
    Client,
    TransportInstallation,
    TransportBinding,
    Persona,
    Lineage,
    Branch,
    LogicalSession,
    Subject,
    SubjectAlias,
    GenesisImportRun,
    GenesisImportSource,
    GenesisImportExclusion,
    IngressItem,
    IngressProviderViolation,
    MemoryEvent,
    Memory,
    MemoryEvidence,
    MemoryLink,
    MemoryConflict,
    MemoryConflictMember,
    SelectionDecision,
    CommandReceipt,
    MemoryContentKey,
    GenesisImportRecord,
    GenesisImportSupersession,
    GenesisImportRunResult,
)
_RECOVERY_MODEL_BY_TABLE = MappingProxyType(
    {model.__tablename__: model for model in _RECOVERY_MODELS}
)
_RECOVERY_PRIMARY_KEYS = MappingProxyType(
    {
        model.__tablename__: tuple(column.name for column in inspect(model).primary_key)
        for model in _RECOVERY_MODELS
    }
)


def archive_target_advisory_lock_key(*, tenant_id: UUID, archive_target_id: UUID) -> int:
    """Derive a stable target-scoped signed PostgreSQL advisory lock key."""

    for name, identifier in (
        ("tenant_id", tenant_id),
        ("archive_target_id", archive_target_id),
    ):
        if not isinstance(identifier, UUID):
            raise TypeError(f"{name} must be a UUID")
        require_uuid7(identifier, field_name=name)
    digest = hashlib.blake2b(digest_size=8, person=_ARCHIVE_LOCK_DOMAIN)
    digest.update(tenant_id.bytes)
    digest.update(archive_target_id.bytes)
    return int.from_bytes(digest.digest(), "big", signed=True)


async def try_acquire_archive_target_lock(
    session: AsyncSession, *, tenant_id: UUID, archive_target_id: UUID
) -> bool:
    """Try to elect this transaction as the target's sole exporter."""

    key = archive_target_advisory_lock_key(tenant_id=tenant_id, archive_target_id=archive_target_id)
    result = await session.execute(
        text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
        {"lock_key": key},
    )
    return bool(result.scalar_one())


def _archive_value(value: object) -> ArchiveValue:
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value)
    normalized = normalize_json_value(value)
    return cast(ArchiveValue, normalized)


def archive_row_dto(row: DeclarativeBase) -> ArchiveRecord:
    """Extract one ORM row with stable names and reversible CBOR-safe values."""

    mapper = inspect(type(row))
    fields: list[tuple[str, ArchiveValue]] = []
    for attribute in mapper.column_attrs:
        column = attribute.columns[0]
        value = getattr(row, attribute.key)
        if value is not None and isinstance(column.type, JSON):
            encoded: ArchiveValue = canonical_json_bytes(value)
        elif value is not None and isinstance(column.type, Numeric):
            decimal_value = Decimal(value)
            if not decimal_value.is_finite():
                raise ArchiveStorageError("archive_row_value_invalid")
            encoded = format(decimal_value, "f")
        else:
            encoded = _archive_value(value)
        fields.append((column.name, encoded))
    return dict(sorted(fields))


def archive_event_dto(row: MemoryEvent) -> ArchiveRecord:
    """Verify an event row and expose its canonical public event contract."""

    try:
        value = event_row_to_domain(row).model_dump(mode="json")
    except ProjectionPersistenceError:
        raise ArchiveStorageError("archive_event_invalid") from None
    return cast(ArchiveRecord, value)


def _require_single_tenant_global_prefix(
    *,
    next_global_sequence: object,
    tenant_event_count: object,
    tenant_min_sequence: object,
    tenant_max_sequence: object,
) -> int:
    """Prove the visible tenant owns the canonical node's complete event prefix."""

    if (
        isinstance(next_global_sequence, bool)
        or not isinstance(next_global_sequence, int)
        or next_global_sequence < 1
        or isinstance(tenant_event_count, bool)
        or not isinstance(tenant_event_count, int)
        or tenant_event_count < 0
    ):
        raise ArchiveStorageError("archive_multitenant_unsupported")
    high_water = next_global_sequence - 1
    if high_water == 0:
        if (
            tenant_event_count != 0
            or tenant_min_sequence is not None
            or tenant_max_sequence is not None
        ):
            raise ArchiveStorageError("archive_multitenant_unsupported")
        return high_water
    if (
        tenant_event_count != high_water
        or tenant_min_sequence != 1
        or tenant_max_sequence != high_water
    ):
        raise ArchiveStorageError("archive_multitenant_unsupported")
    return high_water


async def _load_model_rows(
    session: AsyncSession, model: type[DeclarativeBase], tenant_id: UUID
) -> tuple[ArchiveRecord, ...]:
    mapper = inspect(model)
    statement = select(model)
    tenant_column = model.__table__.columns.get("tenant_id")
    if tenant_column is not None:
        statement = statement.where(tenant_column == tenant_id)
    statement = statement.order_by(*mapper.primary_key)
    result = await session.execute(statement)
    return tuple(archive_row_dto(row) for row in result.scalars().all())


async def load_recovery_rows(
    session: AsyncSession, *, tenant_id: UUID
) -> Mapping[str, tuple[ArchiveRecord, ...]]:
    """Load allowlisted recovery tables in deterministic table and row order."""

    try:
        rows = {
            model.__tablename__: await _load_model_rows(session, model, tenant_id)
            for model in _RECOVERY_MODELS
        }
    except SQLAlchemyError:
        raise ArchiveStorageError("archive_row_load_failed") from None
    return MappingProxyType(rows)


async def load_archive_batch_source(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    archive_target_id: UUID,
) -> ArchiveBatchSource | None:
    """Elect one exporter and load the next complete committed tenant prefix.

    The caller must keep this transaction open through local commit, push, and
    checkpoint reconciliation so the transaction-scoped lock remains held.
    """

    if not session.in_transaction():
        raise ArchiveStorageError("active_transaction_required")
    if not await try_acquire_archive_target_lock(
        session, tenant_id=tenant_id, archive_target_id=archive_target_id
    ):
        raise ArchiveExportBusy()

    try:
        target = (
            await session.execute(
                select(ArchiveTarget).where(
                    ArchiveTarget.tenant_id == tenant_id,
                    ArchiveTarget.archive_target_id == archive_target_id,
                    ArchiveTarget.state == "active",
                )
            )
        ).scalar_one_or_none()
        if target is None:
            raise ArchiveStorageError("archive_target_unavailable")

        previous = (
            await session.execute(
                select(ArchiveExportCheckpoint)
                .where(
                    ArchiveExportCheckpoint.tenant_id == tenant_id,
                    ArchiveExportCheckpoint.archive_target_id == archive_target_id,
                    ArchiveExportCheckpoint.state == "pushed",
                )
                .order_by(
                    ArchiveExportCheckpoint.last_event_sequence.desc(),
                    ArchiveExportCheckpoint.checkpoint_id.desc(),
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        previous_last = 0 if previous is None else previous.last_event_sequence

        # Event sequence allocation is global in v1, while archives are bound to
        # one tenant. Lock the counter so the source cannot advance while the
        # snapshot is loaded, then prove this tenant owns exactly 1..high-water.
        # Any missing sequence can represent another tenant and is therefore not
        # safely restorable by the v1 single-tenant format.
        next_global_sequence = await session.scalar(
            select(MemoryEventCounter.next_sequence)
            .where(MemoryEventCounter.counter_id == 1)
            .with_for_update()
        )
        tenant_prefix_result = await session.execute(
            select(
                func.count(MemoryEvent.sequence),
                func.min(MemoryEvent.sequence),
                func.max(MemoryEvent.sequence),
            ).where(MemoryEvent.tenant_id == tenant_id)
        )
        tenant_event_count, tenant_min_sequence, tenant_max_sequence = (
            tenant_prefix_result.one()
        )
        global_high_water = _require_single_tenant_global_prefix(
            next_global_sequence=next_global_sequence,
            tenant_event_count=tenant_event_count,
            tenant_min_sequence=tenant_min_sequence,
            tenant_max_sequence=tenant_max_sequence,
        )
        if previous_last > global_high_water:
            raise ArchiveStorageError("archive_source_changed")

        event_result = await session.execute(
            select(MemoryEvent)
            .where(
                MemoryEvent.tenant_id == tenant_id,
                MemoryEvent.sequence > previous_last,
            )
            .order_by(MemoryEvent.sequence)
        )
        event_rows = tuple(event_result.scalars().all())
        if not event_rows:
            return None

        source_high_water = global_high_water
        sequences = tuple(row.sequence for row in event_rows)
        if sequences != tuple(range(previous_last + 1, source_high_water + 1)):
            raise ArchiveStorageError("archive_multitenant_unsupported")
        recovery_rows = await load_recovery_rows(session, tenant_id=tenant_id)
    except ArchiveStorageError:
        raise
    except SQLAlchemyError:
        raise ArchiveStorageError("archive_source_load_failed") from None

    events = tuple(archive_event_dto(row) for row in event_rows)
    return ArchiveBatchSource(
        tenant_id=str(tenant_id),
        archive_target_id=str(archive_target_id),
        previous_checkpoint_id=None if previous is None else str(previous.checkpoint_id),
        previous_manifest_sha256=(
            None if previous is None else bytes(previous.manifest_sha256).hex()
        ),
        previous_git_commit_sha=(None if previous is None else previous.remote_git_commit_sha),
        source_high_water_sequence=source_high_water,
        first_event_sequence=event_rows[0].sequence,
        last_event_sequence=source_high_water,
        event_count=len(event_rows),
        export_timestamp=format_utc_datetime(event_rows[-1].created_at),
        events=events,
        recovery_primary_keys=_RECOVERY_PRIMARY_KEYS,
        recovery_rows=recovery_rows,
    )


def _require_digest(value: bytes, field: str) -> bytes:
    digest = bytes(value)
    if len(digest) != 32:
        raise ValueError(f"{field} must be exactly 32 bytes")
    return digest


def _require_git_commit_sha(value: str) -> str:
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("git commit SHA must be 40 or 64 lowercase hexadecimal characters")
    return value


async def prepare_archive_checkpoint(
    session: AsyncSession,
    *,
    source: ArchiveBatchSource,
    checkpoint_id: UUID,
    manifest_sha256: bytes,
    manifest_path: str,
    exporter_version: str,
    postgres_timeline_id: int | None = None,
    started_at: datetime | None = None,
) -> ArchiveExportCheckpoint:
    """Stage a preparing checkpoint in the caller's locked transaction."""

    require_uuid7(checkpoint_id, field_name="checkpoint_id")
    if not manifest_path or len(manifest_path) > 4096:
        raise ValueError("manifest_path must contain between 1 and 4096 characters")
    if not 1 <= len(exporter_version) <= 64:
        raise ValueError("exporter_version must contain between 1 and 64 characters")
    checkpoint = ArchiveExportCheckpoint(
        checkpoint_id=checkpoint_id,
        tenant_id=UUID(source.tenant_id),
        archive_target_id=UUID(source.archive_target_id),
        previous_checkpoint_id=(
            None if source.previous_checkpoint_id is None else UUID(source.previous_checkpoint_id)
        ),
        state="preparing",
        source_high_water_sequence=source.source_high_water_sequence,
        first_event_sequence=source.first_event_sequence,
        last_event_sequence=source.last_event_sequence,
        event_count=source.event_count,
        previous_manifest_sha256=(
            None
            if source.previous_manifest_sha256 is None
            else bytes.fromhex(source.previous_manifest_sha256)
        ),
        manifest_sha256=_require_digest(manifest_sha256, "manifest_sha256"),
        manifest_path=manifest_path,
        exporter_version=exporter_version,
        postgres_timeline_id=postgres_timeline_id,
        started_at=started_at,
    )
    session.add(checkpoint)
    try:
        await session.flush()
    except SQLAlchemyError:
        raise ArchiveStorageError("archive_checkpoint_prepare_failed") from None
    return checkpoint


async def commit_archive_checkpoint(
    session: AsyncSession,
    checkpoint: ArchiveExportCheckpoint,
    *,
    git_commit_sha: str,
    committed_at: datetime,
) -> None:
    """Record a verified local commit, idempotently for reconciliation."""

    git_commit_sha = _require_git_commit_sha(git_commit_sha)
    if checkpoint.state == "committed" and checkpoint.git_commit_sha == git_commit_sha:
        return
    if checkpoint.state != "preparing":
        raise ArchiveStorageError("archive_checkpoint_state")
    checkpoint.state = "committed"
    checkpoint.git_commit_sha = git_commit_sha
    checkpoint.committed_at = committed_at
    try:
        await session.flush()
    except SQLAlchemyError:
        raise ArchiveStorageError("archive_checkpoint_commit_failed") from None


async def push_archive_checkpoint(
    session: AsyncSession,
    checkpoint: ArchiveExportCheckpoint,
    *,
    remote_git_commit_sha: str,
    pushed_at: datetime,
) -> None:
    """Record a verified remote commit without amending published history."""

    remote_git_commit_sha = _require_git_commit_sha(remote_git_commit_sha)
    if checkpoint.state == "pushed" and checkpoint.remote_git_commit_sha == remote_git_commit_sha:
        return
    if checkpoint.state != "committed" or checkpoint.git_commit_sha != remote_git_commit_sha:
        raise ArchiveStorageError("archive_checkpoint_state")
    checkpoint.state = "pushed"
    checkpoint.remote_git_commit_sha = remote_git_commit_sha
    checkpoint.pushed_at = pushed_at
    try:
        await session.flush()
    except SQLAlchemyError:
        raise ArchiveStorageError("archive_checkpoint_push_failed") from None


async def assert_clean_restore_destination(session: AsyncSession) -> None:
    """Fail before mutation unless every recovery table is empty."""

    try:
        for model in _RECOVERY_MODELS:
            present = await session.scalar(select(model).limit(1))
            if present is not None:
                raise ArchiveStorageError("restore_destination_not_empty")
    except ArchiveStorageError:
        raise
    except SQLAlchemyError:
        raise ArchiveStorageError("restore_preflight_failed") from None


def _restore_rows_for_model(
    model: type[DeclarativeBase],
    rows: Sequence[Mapping[str, object]],
    *,
    tenant_id: UUID,
) -> tuple[dict[str, object], ...]:
    expected = {column.name for column in model.__table__.columns}
    converted: list[dict[str, object]] = []
    previous_key: tuple[tuple[int, int] | tuple[int, str], ...] | None = None
    primary_key_names = tuple(column.name for column in inspect(model).primary_key)
    for row in rows:
        if set(row) != expected:
            raise ArchiveStorageError("restore_row_shape")
        row_tenant_id = row.get("tenant_id")
        if row_tenant_id is not None and str(row_tenant_id) != str(tenant_id):
            raise ArchiveStorageError("restore_tenant_mismatch")
        key = tuple(_restore_sort_component(row[name]) for name in primary_key_names)
        if previous_key is not None and key <= previous_key:
            raise ArchiveStorageError("restore_row_order")
        previous_key = key
        converted.append(
            {
                column.name: _restore_column_value(column.type, row[column.name])
                for column in model.__table__.columns
            }
        )
    return tuple(converted)


def _restore_sort_component(value: object) -> tuple[int, int] | tuple[int, str]:
    if isinstance(value, bool):
        raise ArchiveStorageError("restore_row_shape")
    if isinstance(value, int):
        return (0, value)
    if isinstance(value, UUID):
        return (1, str(value))
    if isinstance(value, str):
        return (1, value)
    if isinstance(value, bytes | bytearray | memoryview):
        return (2, bytes(value).hex())
    raise ArchiveStorageError("restore_row_shape")


def _restore_column_value(column_type: object, value: object) -> object:
    if value is None:
        return None
    if isinstance(column_type, JSON):
        if not isinstance(value, bytes):
            raise ArchiveStorageError("restore_row_shape")
        try:
            return parse_json_strict(value)
        except ValueError:
            raise ArchiveStorageError("restore_row_shape") from None
    if isinstance(column_type, Uuid):
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except (TypeError, ValueError):
            raise ArchiveStorageError("restore_row_shape") from None
    if isinstance(column_type, DateTime):
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            raise ArchiveStorageError("restore_row_shape")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ArchiveStorageError("restore_row_shape") from None
        if format_utc_datetime(parsed) != value:
            raise ArchiveStorageError("restore_row_shape")
        return parsed
    if isinstance(column_type, Numeric):
        if not isinstance(value, str):
            raise ArchiveStorageError("restore_row_shape")
        try:
            parsed_decimal = Decimal(value)
        except ValueError:
            raise ArchiveStorageError("restore_row_shape") from None
        if not parsed_decimal.is_finite() or format(parsed_decimal, "f") != value:
            raise ArchiveStorageError("restore_row_shape")
        return parsed_decimal
    if isinstance(column_type, LargeBinary):
        if not isinstance(value, bytes):
            raise ArchiveStorageError("restore_row_shape")
        return value
    return value


async def restore_archive_rows(session: AsyncSession, plan: RestorePlan) -> None:
    """Load a verified recovery row plan into a clean database transaction."""

    if not session.in_transaction():
        raise ArchiveStorageError("active_transaction_required")
    if plan.snapshot_high_water_sequence < 0:
        raise ArchiveStorageError("restore_high_water_invalid")
    if plan.final_high_water_sequence < plan.snapshot_high_water_sequence:
        raise ArchiveStorageError("restore_high_water_invalid")
    if set(plan.rows) - set(_RECOVERY_MODEL_BY_TABLE):
        raise ArchiveStorageError("restore_table_not_allowed")

    await assert_clean_restore_destination(session)
    try:
        await session.execute(text("SET CONSTRAINTS ALL DEFERRED"))
        for model in _RECOVERY_MODELS:
            table_rows = _restore_rows_for_model(
                model,
                tuple(plan.rows.get(model.__tablename__, ())),
                tenant_id=plan.tenant_id,
            )
            if table_rows:
                await session.execute(insert(model), table_rows)
        later_events = _restore_rows_for_model(
            MemoryEvent, tuple(plan.later_events), tenant_id=plan.tenant_id
        )
        if later_events:
            sequence_values = tuple(row["sequence"] for row in later_events)
            if any(
                isinstance(value, bool) or not isinstance(value, int) for value in sequence_values
            ):
                raise ArchiveStorageError("restore_event_order")
            sequences = cast(tuple[int, ...], sequence_values)
            if sequences != tuple(sorted(sequences)) or sequences != tuple(
                range(
                    plan.snapshot_high_water_sequence + 1,
                    plan.final_high_water_sequence + 1,
                )
            ):
                raise ArchiveStorageError("restore_event_order")
            await session.execute(insert(MemoryEvent), later_events)
        high_water = await session.scalar(select(func.max(MemoryEvent.sequence)))
        if high_water != plan.final_high_water_sequence:
            raise ArchiveStorageError("restore_high_water_mismatch")
        await session.execute(
            update(MemoryEventCounter)
            .where(MemoryEventCounter.counter_id == 1)
            .values(next_sequence=plan.final_high_water_sequence + 1)
        )
        selection_high_water = await session.scalar(
            select(func.max(SelectionDecision.selection_sequence))
        )
        await session.execute(
            update(SelectionDecisionCounter)
            .where(SelectionDecisionCounter.counter_id == 1)
            .values(next_sequence=(selection_high_water or 0) + 1)
        )
        await session.flush()
    except ArchiveStorageError:
        raise
    except (SQLAlchemyError, TypeError, ValueError):
        raise ArchiveStorageError("restore_write_failed") from None


def recovery_table_names() -> tuple[str, ...]:
    """Expose the frozen allowlist for archive adapters and tests."""

    return tuple(_RECOVERY_MODEL_BY_TABLE)
