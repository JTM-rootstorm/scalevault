"""Read-only, content-free verification for an isolated PostgreSQL PITR drill."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final, Literal
from urllib.parse import unquote
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.canonical_json import canonical_json_bytes, parse_json_strict
from kivra_memory.domain.events import MemoryEvent as DomainMemoryEvent
from kivra_memory.domain.folding import rebuild
from kivra_memory.domain.values import format_utc_datetime
from kivra_memory.security.credential_files import read_protected_file, read_protected_text
from kivra_memory.security.destruction_ledger import (
    DestructionLedgerAnchor,
    LocalDestructionLedger,
)
from kivra_memory.security.hard_forget_drill import synthetic_correlation_digest
from kivra_memory.storage.base import Base
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    AlembicCompatibility,
    Branch,
    Memory,
    MemoryConflict,
    MemoryConflictMember,
    MemoryContentKey,
    MemoryEvidence,
    MemoryLink,
)
from kivra_memory.storage.projector import (
    ProjectionRows,
    build_projection_rows,
    load_verified_events,
)
from kivra_memory.storage.readiness import REQUIRED_EXTENSIONS

_MAX_MANIFEST_BYTES: Final = 65_536
_MAX_URL_BYTES: Final = 4_096
_RPO_LIMIT_SECONDS: Final = 900
_RTO_LIMIT_SECONDS: Final = 14_400
_CHECK_NAMES: Final = (
    "database_runtime",
    "recovery_isolation",
    "recovery_target",
    "destruction_authority",
    "compatibility",
    "events",
    "projections",
    "pitr_markers",
    "synthetic_correlation",
    "provider_attachment",
    "embedding_requeue",
    "objectives",
)
_CHECK_CODES: Final = {
    "database_runtime": ("postgresql_17_runtime_verified", "database_runtime_mismatch"),
    "recovery_isolation": ("recovery_isolation_verified", "recovery_isolation_mismatch"),
    "recovery_target": ("recovery_target_verified", "recovery_target_mismatch"),
    "destruction_authority": ("destruction_anchor_verified", "destruction_anchor_mismatch"),
    "compatibility": ("compatibility_verified", "compatibility_mismatch"),
    "events": ("event_prefix_verified", "event_prefix_mismatch"),
    "projections": ("projection_rebuild_verified", "projection_rebuild_mismatch"),
    "pitr_markers": ("a_b_not_c_verified", "a_b_not_c_mismatch"),
    "synthetic_correlation": (
        "synthetic_correlation_verified",
        "synthetic_correlation_mismatch",
    ),
    "provider_attachment": ("provider_attachment_absent", "provider_attachment_present"),
    "embedding_requeue": (
        "embedding_requeue_plan_verified",
        "embedding_requeue_plan_mismatch",
    ),
    "objectives": ("rpo_rto_verified", "rpo_rto_exceeded"),
}
_PROJECTION_NAMES: Final = (
    "branches",
    "memories",
    "evidence",
    "links",
    "conflicts",
    "conflict_members",
)
_PROJECTION_MODELS: Final = (
    Branch,
    Memory,
    MemoryEvidence,
    MemoryLink,
    MemoryConflict,
    MemoryConflictMember,
)
_PROJECTION_FIELDS: Final = {
    Branch: (
        "branch_id",
        "tenant_id",
        "lineage_id",
        "parent_branch_id",
        "fork_event_sequence",
        "name",
        "visibility_ceiling",
        "created_at",
        "sealed_at",
    ),
    Memory: (
        "memory_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "subject_id",
        "subject_kind",
        "origin_session_id",
        "revision",
        "category",
        "ontological_status",
        "scope",
        "visibility",
        "status",
        "statement",
        "reason_to_remember",
        "interpretation_limits",
        "confidence",
        "salience",
        "durability",
        "sensitivity",
        "authority_class",
        "valid_from",
        "valid_to",
        "observed_at",
        "created_at",
        "updated_at",
        "candidate_expires_at",
        "normalized_fingerprint",
        "fingerprint_version",
        "metadata_",
        "publication_approved_at",
        "publication_approved_by_actor_id",
        "content_protection",
        "content_key_id",
        "sealed_envelope_version",
        "sealed_algorithm",
        "sealed_nonce",
        "sealed_ciphertext",
        "sealed_aad_sha256",
        "safe_summary",
        "last_event_id",
    ),
    MemoryEvidence: (
        "evidence_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "memory_id",
        "source_event_id",
        "source_type",
        "source_reference",
        "excerpt",
        "occurred_at",
        "content_sha256",
        "trust_classification",
        "status",
        "created_at",
        "metadata_",
    ),
    MemoryLink: (
        "link_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "source_memory_id",
        "target_memory_id",
        "link_type",
        "status",
        "created_event_id",
        "unlinked_event_id",
        "created_at",
        "unlinked_at",
        "metadata_",
    ),
    MemoryConflict: (
        "conflict_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "subject_id",
        "status",
        "reason",
        "resolution_kind",
        "resolution_rationale",
        "opened_event_id",
        "resolution_event_id",
        "opened_at",
        "resolved_at",
        "metadata_",
    ),
    MemoryConflictMember: (
        "tenant_id",
        "lineage_id",
        "conflict_id",
        "memory_id",
        "disposition",
        "joined_at",
        "last_event_id",
    ),
}

HexDigest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
BoundedCount = Annotated[int, Field(ge=0, le=10_000_000)]
PositiveCount = Annotated[int, Field(ge=1, le=10_000_000)]
CheckStatus = Literal["pass", "fail", "not_run"]


class PitrConfigurationError(ValueError):
    """A protected verifier input is absent, unsafe, or invalid."""


class PitrDatabaseError(RuntimeError):
    """The isolated database could not provide bounded verification evidence."""


class PitrVerificationError(RuntimeError):
    """Recovered application state is structurally invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RecoveryTarget(_StrictModel):
    kind: Literal["name", "time", "lsn"]
    value: Annotated[str, Field(min_length=1, max_length=256)]
    sha256: HexDigest

    @model_validator(mode="after")
    def require_binding(self) -> RecoveryTarget:
        if not hmac.compare_digest(self.sha256, _target_sha256(self.kind, self.value)):
            raise ValueError
        return self


class Compatibility(_StrictModel):
    component: Literal["memory_node"]
    contract_version: Literal[11]
    minimum_reader_revision: Literal["0011_observability_aggregates"]
    minimum_writer_revision: Literal["0011_observability_aggregates"]


class ProjectionCounts(_StrictModel):
    branches: BoundedCount
    memories: BoundedCount
    evidence: BoundedCount
    links: BoundedCount
    conflicts: BoundedCount
    conflict_members: BoundedCount


class ProjectionExpectation(_StrictModel):
    counts: ProjectionCounts
    sha256: HexDigest


class EventMarker(_StrictModel):
    sequence: PositiveCount
    command_sha256: HexDigest


class EventMarkers(_StrictModel):
    a: EventMarker
    b: EventMarker
    c: EventMarker


class SyntheticExpectation(_StrictModel):
    tenant_id: str
    memory_id: str
    drill_generation: Annotated[str, Field(min_length=1, max_length=128)]
    correlation_sha256: HexDigest

    @field_validator("tenant_id", "memory_id")
    @classmethod
    def require_uuid7(cls, value: str) -> str:
        parsed = UUID(value)
        if str(parsed) != value or parsed.version != 7:
            raise ValueError
        return value


class DigestCount(_StrictModel):
    count: BoundedCount
    sha256: HexDigest


class DestructionExpectation(_StrictModel):
    root: str
    anchor_path: str
    accepted_entry_count: BoundedCount
    accepted_aggregate_sha256: HexDigest

    @field_validator("root", "anchor_path")
    @classmethod
    def require_absolute_path(cls, value: str) -> str:
        return str(_absolute_path(value))


class PitrManifest(_StrictModel):
    """Exact protected Phase 2/3 binding. Values never enter the result."""

    version: Literal[1]
    system_identifier_sha256: HexDigest
    timeline_id: PositiveCount
    recovery_target: RecoveryTarget
    migration_revision: Literal["0011_observability_aggregates"]
    compatibility: Compatibility
    extension_versions: dict[str, str]
    event_count: BoundedCount
    event_prefix_sha256: HexDigest
    projection: ProjectionExpectation
    markers: EventMarkers
    synthetic: SyntheticExpectation
    embedding_requeue: DigestCount
    provider_attachment_paths: Annotated[list[str], Field(min_length=1, max_length=8)]
    destruction_ledger: DestructionExpectation
    drill_started_at: str
    rpo_reference_at: str

    @field_validator("extension_versions")
    @classmethod
    def require_extensions(cls, value: dict[str, str]) -> dict[str, str]:
        if set(value) != REQUIRED_EXTENSIONS or any(not item for item in value.values()):
            raise ValueError
        return value

    @field_validator("provider_attachment_paths")
    @classmethod
    def require_attachment_paths(cls, value: list[str]) -> list[str]:
        normalized = [str(_absolute_path(item)) for item in value]
        if len(set(normalized)) != len(normalized):
            raise ValueError
        return normalized

    @field_validator("drill_started_at", "rpo_reference_at")
    @classmethod
    def require_timestamp(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def require_order(self) -> PitrManifest:
        if not (
            self.markers.a.sequence
            < self.markers.b.sequence
            <= self.event_count
            < self.markers.c.sequence
        ):
            raise ValueError
        if len(
            {
                self.markers.a.command_sha256,
                self.markers.b.command_sha256,
                self.markers.c.command_sha256,
            }
        ) != 3 or _timestamp(self.drill_started_at) < _timestamp(self.rpo_reference_at):
            raise ValueError
        return self

    @classmethod
    def load(cls, path: Path) -> PitrManifest:
        try:
            raw = read_protected_file(
                path,
                minimum_bytes=2,
                maximum_bytes=_MAX_MANIFEST_BYTES,
                required_owner_uid=os.geteuid(),
            )
            value = parse_json_strict(raw)
            if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
                raise ValueError
            return cls.model_validate(value)
        except Exception:
            raise PitrConfigurationError("manifest_invalid") from None


@dataclass(frozen=True, slots=True)
class ServerSnapshot:
    server_version_num: int
    system_identifier_sha256: str
    timeline_id: int
    in_recovery: bool
    replay_paused: bool
    transaction_read_only: bool
    listen_addresses: str
    socket_connection: bool
    archive_mode: str
    recovery_target_action: str
    recovery_target_value: str
    recovery_target_sha256: str
    replay_timestamp: datetime | None


@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    migration_revision: str
    compatibility: tuple[int, str, str]
    extension_versions: Mapping[str, str]
    event_count: int
    event_prefix_sha256: str
    projection_counts: Mapping[str, int]
    projection_sha256: str
    rebuilt_projection_counts: Mapping[str, int]
    rebuilt_projection_sha256: str
    marker_a_present: bool
    marker_b_present: bool
    marker_c_absent: bool
    synthetic_correlation_sha256: str
    embedding_requeue_count: int
    embedding_requeue_sha256: str


@dataclass(frozen=True, slots=True)
class VerificationCheck:
    name: str
    status: CheckStatus
    code: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "code": self.code}


@dataclass(frozen=True, slots=True)
class VerificationReport:
    ok: bool
    result_code: str
    checks: tuple[VerificationCheck, ...]
    application: ApplicationSnapshot | None = None
    server: ServerSnapshot | None = None
    rpo_seconds: int | None = None
    rto_seconds: int | None = None

    @classmethod
    def unavailable(cls, code: str) -> VerificationReport:
        return cls(
            False,
            code,
            tuple(VerificationCheck(name, "not_run", code) for name in _CHECK_NAMES),
        )

    def as_dict(self) -> dict[str, object]:
        app = self.application
        projection = app.projection_counts if app else _nulls(_PROJECTION_NAMES)
        rebuilt = app.rebuilt_projection_counts if app else _nulls(_PROJECTION_NAMES)
        return {
            "schema_version": 1,
            "ok": self.ok,
            "result_code": self.result_code,
            "checks": [item.as_dict() for item in self.checks],
            "counts": {
                "events": app.event_count if app else None,
                "projection": projection,
                "rebuilt_projection": rebuilt,
            },
            "digests": {
                "event_prefix_sha256": app.event_prefix_sha256 if app else None,
                "projection_sha256": app.projection_sha256 if app else None,
                "rebuilt_projection_sha256": app.rebuilt_projection_sha256 if app else None,
                "synthetic_correlation_sha256": (app.synthetic_correlation_sha256 if app else None),
                "embedding_requeue_sha256": app.embedding_requeue_sha256 if app else None,
                "recovery_target_sha256": (
                    self.server.recovery_target_sha256 if self.server else None
                ),
            },
            "timings": {
                "rpo_seconds": self.rpo_seconds,
                "rto_seconds": self.rto_seconds,
                "rpo_limit_seconds": _RPO_LIMIT_SECONDS,
                "rto_limit_seconds": _RTO_LIMIT_SECONDS,
            },
        }


class PostgresPitrProbe:
    """Read-only live database adapter."""

    def __init__(self, database_url: str) -> None:
        self._database = Database(database_url)

    async def close(self) -> None:
        await self._database.dispose()

    async def server_snapshot(self, manifest: PitrManifest) -> ServerSnapshot:
        try:
            async with self._database.session_factory() as session, session.begin():
                target_name = f"recovery_target_{manifest.recovery_target.kind}"
                target_value = str(
                    await _scalar(
                        session,
                        "SELECT current_setting(:name)",
                        {"name": target_name},
                    )
                )
                system_id = str(
                    await _scalar(
                        session,
                        "SELECT system_identifier::text FROM pg_catalog.pg_control_system()",
                    )
                )
                replayed_at = await _scalar(
                    session, "SELECT pg_catalog.pg_last_xact_replay_timestamp()"
                )
                return ServerSnapshot(
                    server_version_num=int(str(await _scalar(session, "SHOW server_version_num"))),
                    system_identifier_sha256=hashlib.sha256(system_id.encode("ascii")).hexdigest(),
                    timeline_id=int(
                        str(
                            await _scalar(
                                session,
                                "SELECT timeline_id FROM pg_catalog.pg_control_checkpoint()",
                            )
                        )
                    ),
                    in_recovery=bool(await _scalar(session, "SELECT pg_is_in_recovery()")),
                    replay_paused=bool(await _scalar(session, "SELECT pg_is_wal_replay_paused()")),
                    transaction_read_only=str(await _scalar(session, "SHOW transaction_read_only"))
                    == "on",
                    listen_addresses=str(await _scalar(session, "SHOW listen_addresses")),
                    socket_connection=bool(
                        await _scalar(session, "SELECT inet_server_addr() IS NULL")
                    ),
                    archive_mode=str(await _scalar(session, "SHOW archive_mode")),
                    recovery_target_action=str(
                        await _scalar(session, "SHOW recovery_target_action")
                    ),
                    recovery_target_value=target_value,
                    recovery_target_sha256=_target_sha256(
                        manifest.recovery_target.kind, target_value
                    ),
                    replay_timestamp=(
                        replayed_at.astimezone(UTC) if isinstance(replayed_at, datetime) else None
                    ),
                )
        except SQLAlchemyError:
            raise PitrDatabaseError from None
        except Exception:
            raise PitrVerificationError from None

    async def application_snapshot(self, manifest: PitrManifest) -> ApplicationSnapshot:
        try:
            async with self._database.session_factory() as session, session.begin():
                migration = str(
                    await _scalar(session, "SELECT version_num FROM public.alembic_version")
                )
                compatibility = (
                    (
                        await session.execute(
                            select(AlembicCompatibility).where(
                                AlembicCompatibility.component == "memory_node"
                            )
                        )
                    )
                    .scalars()
                    .one()
                )
                extensions = {
                    str(row[0]): str(row[1])
                    for row in (
                        await session.execute(
                            text(
                                "SELECT extname, extversion FROM pg_catalog.pg_extension "
                                "WHERE extname = ANY(:names) ORDER BY extname"
                            ),
                            {"names": sorted(REQUIRED_EXTENSIONS)},
                        )
                    ).all()
                }
                events = await load_verified_events(session)
                state = rebuild(events)
                rebuilt_rows = build_projection_rows(state, events)
                persisted_rows = await _load_projection_rows(session)
                projection_counts, projection_hash = _projection_summary(
                    persisted_rows, state.sequence
                )
                rebuilt_counts, rebuilt_hash = _projection_summary(rebuilt_rows, state.sequence)
                by_sequence = {event.sequence: event.command_sha256 for event in events}
                commands = {event.command_sha256 for event in events}
                embedding_count, embedding_hash = _embedding_plan(rebuilt_rows.memories)
                return ApplicationSnapshot(
                    migration_revision=migration,
                    compatibility=(
                        compatibility.contract_version,
                        compatibility.minimum_reader_revision,
                        compatibility.minimum_writer_revision,
                    ),
                    extension_versions=extensions,
                    event_count=len(events),
                    event_prefix_sha256=_event_prefix_sha256(events),
                    projection_counts=projection_counts,
                    projection_sha256=projection_hash,
                    rebuilt_projection_counts=rebuilt_counts,
                    rebuilt_projection_sha256=rebuilt_hash,
                    marker_a_present=(
                        by_sequence.get(manifest.markers.a.sequence)
                        == manifest.markers.a.command_sha256
                    ),
                    marker_b_present=(
                        by_sequence.get(manifest.markers.b.sequence)
                        == manifest.markers.b.command_sha256
                    ),
                    marker_c_absent=manifest.markers.c.command_sha256 not in commands,
                    synthetic_correlation_sha256=await _synthetic_correlation(
                        session, manifest.synthetic
                    ),
                    embedding_requeue_count=embedding_count,
                    embedding_requeue_sha256=embedding_hash,
                )
        except SQLAlchemyError:
            raise PitrDatabaseError from None
        except PitrVerificationError:
            raise
        except Exception:
            raise PitrVerificationError from None


async def verify_pitr(
    manifest: PitrManifest,
    probe: PostgresPitrProbe,
    *,
    now: datetime | None = None,
) -> VerificationReport:
    """Check the independent ledger before reading any application relation."""

    server = await probe.server_snapshot(manifest)
    failed = next(
        (name for name, passed in _server_decisions(manifest, server).items() if not passed),
        None,
    )
    if failed is not None:
        return _early_failure(server, failed, _CHECK_CODES[failed][1])
    destruction_ok = _verify_destruction_authority(manifest)
    attachment_ok = _provider_attachments_absent(manifest.provider_attachment_paths)
    if not destruction_ok or not attachment_ok:
        failed_name = "destruction_authority" if not destruction_ok else "provider_attachment"
        failed_code = (
            "destruction_anchor_mismatch" if not destruction_ok else "provider_attachment_present"
        )
        return _early_failure(server, failed_name, failed_code)
    application = await probe.application_snapshot(manifest)
    return verify_snapshots(
        manifest,
        server,
        application,
        destruction_verified=destruction_ok,
        provider_attachments_absent=attachment_ok,
        finished_at=(now or datetime.now(UTC)).astimezone(UTC),
    )


def verify_snapshots(
    manifest: PitrManifest,
    server: ServerSnapshot,
    app: ApplicationSnapshot,
    *,
    destruction_verified: bool,
    provider_attachments_absent: bool,
    finished_at: datetime,
) -> VerificationReport:
    """Compare bounded evidence against the protected manifest."""

    expected_compatibility = (
        manifest.compatibility.contract_version,
        manifest.compatibility.minimum_reader_revision,
        manifest.compatibility.minimum_writer_revision,
    )
    expected_projection = manifest.projection.counts.model_dump()
    rpo = _elapsed(server.replay_timestamp, _timestamp(manifest.rpo_reference_at))
    rto = _elapsed(_timestamp(manifest.drill_started_at), finished_at)
    decisions = {
        **_server_decisions(manifest, server),
        "destruction_authority": destruction_verified,
        "compatibility": (
            app.migration_revision == manifest.migration_revision
            and app.compatibility == expected_compatibility
            and dict(app.extension_versions) == manifest.extension_versions
        ),
        "events": (
            app.event_count == manifest.event_count
            and hmac.compare_digest(app.event_prefix_sha256, manifest.event_prefix_sha256)
        ),
        "projections": (
            dict(app.projection_counts) == expected_projection
            and dict(app.rebuilt_projection_counts) == expected_projection
            and hmac.compare_digest(app.projection_sha256, manifest.projection.sha256)
            and hmac.compare_digest(app.rebuilt_projection_sha256, manifest.projection.sha256)
        ),
        "pitr_markers": (app.marker_a_present and app.marker_b_present and app.marker_c_absent),
        "synthetic_correlation": hmac.compare_digest(
            app.synthetic_correlation_sha256,
            manifest.synthetic.correlation_sha256,
        ),
        "provider_attachment": provider_attachments_absent,
        "embedding_requeue": (
            app.embedding_requeue_count == manifest.embedding_requeue.count
            and hmac.compare_digest(app.embedding_requeue_sha256, manifest.embedding_requeue.sha256)
        ),
        "objectives": (
            rpo is not None
            and rto is not None
            and rpo <= _RPO_LIMIT_SECONDS
            and rto <= _RTO_LIMIT_SECONDS
        ),
    }
    checks = tuple(
        VerificationCheck(
            name,
            "pass" if decisions[name] else "fail",
            _CHECK_CODES[name][0 if decisions[name] else 1],
        )
        for name in _CHECK_NAMES
    )
    ok = all(item.status == "pass" for item in checks)
    return VerificationReport(
        ok,
        "verified" if ok else "verification_failed",
        checks,
        application=app,
        server=server,
        rpo_seconds=rpo,
        rto_seconds=rto,
    )


def _server_decisions(manifest: PitrManifest, server: ServerSnapshot) -> dict[str, bool]:
    return {
        "database_runtime": (
            170000 <= server.server_version_num < 180000
            and hmac.compare_digest(
                server.system_identifier_sha256, manifest.system_identifier_sha256
            )
            and server.timeline_id == manifest.timeline_id
        ),
        "recovery_isolation": (
            server.in_recovery
            and server.replay_paused
            and server.transaction_read_only
            and server.listen_addresses == ""
            and server.socket_connection
            and server.archive_mode == "off"
            and server.recovery_target_action == "pause"
        ),
        "recovery_target": (
            server.recovery_target_value == manifest.recovery_target.value
            and hmac.compare_digest(server.recovery_target_sha256, manifest.recovery_target.sha256)
        ),
    }


def _early_failure(server: ServerSnapshot, name: str, code: str) -> VerificationReport:
    checks = tuple(
        VerificationCheck(
            item,
            "fail" if item == name else "not_run",
            code if item == name else "precondition_failed",
        )
        for item in _CHECK_NAMES
    )
    return VerificationReport(False, "verification_failed", checks, server=server)


async def _load_projection_rows(session: AsyncSession) -> ProjectionRows:
    rows: list[tuple[object, ...]] = []
    for model in _PROJECTION_MODELS:
        result = await session.execute(select(model))
        rows.append(tuple(result.scalars().all()))
    return ProjectionRows(*rows)  # type: ignore[arg-type]


def _projection_summary(rows: ProjectionRows, sequence: int) -> tuple[dict[str, int], str]:
    _require_projection_contract()
    groups = (
        rows.branches,
        rows.memories,
        rows.evidence,
        rows.links,
        rows.conflicts,
        rows.conflict_members,
    )
    counts = {name: len(group) for name, group in zip(_PROJECTION_NAMES, groups, strict=True)}
    document = {
        "version": 1,
        "sequence": sequence,
        "rows": {
            name: sorted((_row_value(row) for row in group), key=canonical_json_bytes)
            for name, group in zip(_PROJECTION_NAMES, groups, strict=True)
        },
    }
    return counts, hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _require_projection_contract() -> None:
    for model in _PROJECTION_MODELS:
        fields = _PROJECTION_FIELDS.get(model)
        mapped = {item.key for item in model.__mapper__.column_attrs}
        excluded = {"search_document"} if model is Memory else set()
        if fields is None or set(fields) != mapped - excluded:
            raise PitrVerificationError


def _row_value(row: Base) -> dict[str, object]:
    fields = _PROJECTION_FIELDS.get(type(row))
    if fields is None:
        raise PitrVerificationError
    return {
        ("metadata" if field == "metadata_" else field): _json_value(getattr(row, field))
        for field in fields
    }


def _json_value(value: object) -> object:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _event_prefix_sha256(events: Sequence[DomainMemoryEvent]) -> str:
    entries = []
    for expected, event in enumerate(events, 1):
        if event.sequence != expected:
            raise PitrVerificationError
        entries.append(
            {
                "sequence": event.sequence,
                "event_id": event.event_id,
                "tenant_id": event.tenant_id,
                "lineage_id": event.lineage_id,
                "branch_id": event.branch_id,
                "actor_id": event.actor_id,
                "client_id": event.client_id,
                "transport_binding_id": event.transport_binding_id,
                "session_id": event.session_id,
                "ingress_id": event.ingress_id,
                "operation": event.operation,
                "memory_id": event.memory_id,
                "expected_revision": event.expected_revision,
                "causation_event_id": event.causation_event_id,
                "correlation_id": event.correlation_id,
                "idempotency_key": event.idempotency_key,
                "schema_version": event.schema_version,
                "payload_version": event.payload_version,
                "policy_version": event.policy_version,
                "normalization_version": event.normalization_version,
                "payload_sha256": event.payload_sha256,
                "command_sha256": event.command_sha256,
                "created_at": event.created_at,
            }
        )
    return hashlib.sha256(
        canonical_json_bytes({"purpose": "scalevault-pitr-event-prefix-v1", "events": entries})
    ).hexdigest()


def _embedding_plan(memories: Sequence[Memory]) -> tuple[int, str]:
    jobs = [
        {
            "job_type": "embed_memory",
            "tenant_id": str(row.tenant_id),
            "memory_id": str(row.memory_id),
            "memory_version": row.revision,
            "event_id": str(row.last_event_id),
        }
        for row in sorted(memories, key=lambda item: (str(item.tenant_id), str(item.memory_id)))
    ]
    return len(jobs), hashlib.sha256(canonical_json_bytes({"version": 1, "jobs": jobs})).hexdigest()


async def _synthetic_correlation(session: AsyncSession, expected: SyntheticExpectation) -> str:
    tenant_id, memory_id = UUID(expected.tenant_id), UUID(expected.memory_id)
    memory = (
        (
            await session.execute(
                select(Memory).where(
                    Memory.tenant_id == tenant_id,
                    Memory.memory_id == memory_id,
                )
            )
        )
        .scalars()
        .one_or_none()
    )
    key = (
        (
            await session.execute(
                select(MemoryContentKey).where(
                    MemoryContentKey.tenant_id == tenant_id,
                    MemoryContentKey.memory_id == memory_id,
                )
            )
        )
        .scalars()
        .one_or_none()
    )
    if (
        memory is None
        or key is None
        or memory.content_protection != "envelope_encrypted"
        or memory.content_key_id != key.content_key_id
        or memory.sealed_ciphertext is None
    ):
        raise PitrVerificationError
    return synthetic_correlation_digest(
        ciphertext=bytes(memory.sealed_ciphertext),
        provider_key_reference=key.provider_key_reference,
        drill_generation=expected.drill_generation,
    )


def _verify_destruction_authority(manifest: PitrManifest) -> bool:
    expected = DestructionLedgerAnchor(
        manifest.destruction_ledger.accepted_entry_count,
        manifest.destruction_ledger.accepted_aggregate_sha256,
    )
    try:
        ledger = LocalDestructionLedger(
            Path(manifest.destruction_ledger.root),
            anchor_path=Path(manifest.destruction_ledger.anchor_path),
            expected_anchor=expected,
        )
        ledger.require_anchor(expected)
        return True
    except Exception:
        return False


def _provider_attachments_absent(paths: Sequence[str]) -> bool:
    for raw in paths:
        try:
            Path(raw).lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        return False
    return True


async def _scalar(
    session: AsyncSession, statement: str, parameters: Mapping[str, object] | None = None
) -> object:
    return (await session.execute(text(statement), parameters or {})).scalar_one()


def _target_sha256(kind: str, value: str) -> str:
    document = {
        "purpose": "scalevault-postgresql-pitr-target-v1",
        "kind": kind,
        "value": value,
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError from None
    if value != format_utc_datetime(parsed):
        raise ValueError
    return parsed


def _elapsed(start: datetime | None, finish: datetime) -> int | None:
    if start is None:
        return None
    seconds = (finish.astimezone(UTC) - start.astimezone(UTC)).total_seconds()
    return math.ceil(seconds) if seconds >= 0 else None


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path == Path("/")
        or len(value.encode()) > 4096
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise ValueError
    return path


def _read_database_url(path: Path) -> str:
    try:
        value = read_protected_text(
            path,
            minimum_bytes=1,
            maximum_bytes=_MAX_URL_BYTES,
            required_owner_uid=os.geteuid(),
        )
        url = make_url(value)
        host = unquote(url.host or "")
        if (
            url.drivername not in {"postgresql", "postgresql+psycopg"}
            or not host.startswith("/")
            or host == "/"
            or not url.database
            or not url.username
            or url.query
        ):
            raise ValueError
        return value
    except Exception:
        raise PitrConfigurationError("database_connection_invalid") from None


def _parse_arguments(arguments: Sequence[str]) -> tuple[Path, Path]:
    if len(arguments) != 4:
        raise PitrConfigurationError("arguments_invalid")
    values = {arguments[index]: Path(arguments[index + 1]) for index in (0, 2)}
    if set(values) != {"--manifest", "--database-connection-file"}:
        raise PitrConfigurationError("arguments_invalid")
    return values["--manifest"], values["--database-connection-file"]


async def _run(arguments: Sequence[str]) -> tuple[VerificationReport, int]:
    probe: PostgresPitrProbe | None = None
    try:
        manifest_path, connection_path = _parse_arguments(arguments)
        manifest = PitrManifest.load(manifest_path)
        probe = PostgresPitrProbe(_read_database_url(connection_path))
        report = await verify_pitr(manifest, probe)
        return report, 0 if report.ok else 4
    except PitrConfigurationError:
        return VerificationReport.unavailable("configuration_invalid"), 2
    except PitrDatabaseError:
        return VerificationReport.unavailable("database_unavailable"), 3
    except PitrVerificationError:
        return VerificationReport.unavailable("verification_failed"), 4
    except Exception:
        return VerificationReport.unavailable("internal_error"), 5
    finally:
        if probe:
            with suppress(Exception):
                await probe.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Emit exactly one bounded JSON report and return a fixed exit class."""

    report, exit_code = asyncio.run(_run(tuple(sys.argv[1:] if argv is None else argv)))
    sys.stdout.write(json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":")) + "\n")
    return exit_code


def _nulls(names: Sequence[str]) -> dict[str, None]:
    return dict.fromkeys(names)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ApplicationSnapshot",
    "PitrConfigurationError",
    "PitrManifest",
    "PostgresPitrProbe",
    "ServerSnapshot",
    "VerificationReport",
    "main",
    "verify_pitr",
    "verify_snapshots",
]
