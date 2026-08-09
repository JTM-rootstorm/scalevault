from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from kivra_memory.archive.adapters import ArchivePayload, DeterministicArchiveBuilder
from kivra_memory.archive.git import GitCommitSigner, GitSigningError, VerifiedGitCommit
from kivra_memory.archive.models import MANIFEST_PATH, build_manifest
from kivra_memory.archive.restore import RestoreDestinationState, preflight_restore
from kivra_memory.archive.verification import ArchiveBatch, ArchiveCommitBatch
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import (
    AuthorityClass,
    EventOperation,
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.events import (
    BranchCreatedPayload,
    BranchState,
    MemoryCreatedPayload,
    MemoryEvent,
    MemoryState,
    OperationPayload,
    event_hash_fields,
)
from kivra_memory.domain.folding import canonical_aggregate_bytes, rebuild_tenant
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import (
    ArchiveBatchSource,
    ArchiveRecord,
    RestorePlan,
    archive_event_dto,
    archive_row_dto,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import MemoryEvent as MemoryEventRow
from kivra_memory.storage.models import MemoryEventCounter
from kivra_memory.storage.projector import (
    load_canonical_aggregate_bytes,
    load_verified_events,
)
from kivra_memory.workers.archive_restore import (
    CoreRestoreDecoder,
    restore_validated_archive,
)
from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.fixtures.database_seed import seed_model_layers, seed_rows

_ROOT = Path(__file__).resolve().parents[3]
_EVENT_TIME = datetime(2026, 8, 9, 12, tzinfo=UTC)
_EVENT_TIMESTAMP_MS = 1_786_276_800_000
_FIRST_COMMIT = "a" * 40
_SECOND_COMMIT = "b" * 40


class PostgreSQLTestServer(Protocol):
    database_url: str


def _event_uuid(ordinal: int) -> UUID:
    return new_uuid7(timestamp_ms=_EVENT_TIMESTAMP_MS, random_bits=ordinal)


def _seed_identifier(table: str, column: str, index: int = 0) -> UUID:
    return cast(UUID, seed_rows()[table][index][column])


def _branch_state() -> BranchState:
    branch = seed_rows()["branches"][0]
    return BranchState(
        branch_id=cast(UUID, branch["branch_id"]),
        tenant_id=cast(UUID, branch["tenant_id"]),
        lineage_id=cast(UUID, branch["lineage_id"]),
        parent_branch_id=None,
        fork_event_sequence=None,
        name=cast(str, branch["name"]),
        visibility_ceiling=MemoryVisibility(cast(str, branch["visibility_ceiling"])),
        created_at=cast(datetime, branch["created_at"]),
    )


def _memory_state() -> MemoryState:
    return MemoryState(
        memory_id=_event_uuid(10),
        tenant_id=_seed_identifier("tenants", "tenant_id"),
        lineage_id=_seed_identifier("lineages", "lineage_id"),
        branch_id=_seed_identifier("branches", "branch_id"),
        subject_id=_seed_identifier("subjects", "subject_id"),
        subject_kind=SubjectKind.GLOBAL,
        revision=1,
        category=MemoryCategory.STABLE_FACT,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.GLOBAL,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=MemoryStatus.ACTIVE,
        statement="The archive restore acceptance record is stable.",
        reason_to_remember="It verifies snapshot recovery followed by event replay.",
        interpretation_limits=("Synthetic integration-test data only.",),
        confidence=Decimal("0.900000"),
        salience=Decimal("0.800000"),
        durability=Decimal("0.700000"),
        sensitivity=0,
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=_EVENT_TIME,
        content_protection="plaintext",
        created_at=_EVENT_TIME,
        updated_at=_EVENT_TIME,
        fingerprint_version=1,
        normalized_fingerprint="ab" * 32,
        metadata={"fixture": True},
    )


def _event(
    sequence: int,
    *,
    operation: EventOperation,
    payload: OperationPayload,
    memory_id: UUID | None,
    created_at: datetime,
) -> MemoryEvent:
    tenant_id = _seed_identifier("tenants", "tenant_id")
    lineage_id = _seed_identifier("lineages", "lineage_id")
    branch_id = _seed_identifier("branches", "branch_id")
    binding = seed_rows()["transport_bindings"][0]
    actor_id = cast(UUID, binding["actor_id"])
    client_id = cast(UUID, binding["client_id"])
    values, canonical, payload_hash, command_hash = event_hash_fields(
        operation=operation,
        payload=payload,
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
    )
    return MemoryEvent(
        schema_version=1,
        payload_version=1,
        sequence=sequence,
        event_id=_event_uuid(100 + sequence),
        tenant_id=tenant_id,
        lineage_id=lineage_id,
        branch_id=branch_id,
        actor_id=actor_id,
        client_id=client_id,
        transport_binding_id=cast(UUID, binding["transport_binding_id"]),
        session_id=None,
        ingress_id=None,
        operation=operation,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
        correlation_id=_event_uuid(20),
        idempotency_key=f"archive-restore-acceptance:{sequence}",
        policy_version=1,
        normalization_version=1,
        payload=values,
        payload_canonical=canonical,
        payload_sha256=payload_hash,
        command_sha256=command_hash,
        created_at=created_at,
    )


def _branch_event() -> MemoryEvent:
    branch = _branch_state()
    return _event(
        1,
        operation=EventOperation.BRANCH_CREATED,
        payload=BranchCreatedPayload(branch=branch),
        memory_id=None,
        created_at=branch.created_at,
    )


def _remembered_event(memory: MemoryState) -> MemoryEvent:
    return _event(
        2,
        operation=EventOperation.REMEMBERED,
        payload=MemoryCreatedPayload(memory=memory),
        memory_id=memory.memory_id,
        created_at=_EVENT_TIME,
    )


def _event_row(event: MemoryEvent) -> MemoryEventRow:
    return MemoryEventRow(
        sequence=event.sequence,
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        lineage_id=event.lineage_id,
        branch_id=event.branch_id,
        actor_id=event.actor_id,
        client_id=event.client_id,
        transport_binding_id=event.transport_binding_id,
        session_id=event.session_id,
        ingress_id=event.ingress_id,
        operation=event.operation.value,
        memory_id=event.memory_id,
        expected_revision=event.expected_revision,
        causation_event_id=event.causation_event_id,
        correlation_id=event.correlation_id,
        idempotency_key=event.idempotency_key,
        schema_version=event.schema_version,
        payload_version=event.payload_version,
        policy_version=event.policy_version,
        normalization_version=event.normalization_version,
        payload=dict(event.payload),
        payload_canonical=base64.b64decode(event.payload_canonical, validate=True),
        payload_sha256=bytes.fromhex(event.payload_sha256),
        command_sha256=bytes.fromhex(event.command_sha256),
        created_at=event.created_at,
    )


def _snapshot_source(event: MemoryEvent) -> ArchiveBatchSource:
    rows = [row for layer in seed_model_layers() for row in layer]
    event_row = _event_row(event)
    rows.append(event_row)
    recovery_rows: dict[str, tuple[ArchiveRecord, ...]] = {}
    recovery_primary_keys: dict[str, tuple[str, ...]] = {}
    for row in rows:
        table_name = type(row).__tablename__
        recovery_rows.setdefault(table_name, ())
        recovery_rows[table_name] += (archive_row_dto(row),)
        recovery_primary_keys[table_name] = tuple(
            column.name for column in inspect(type(row)).primary_key
        )
    return ArchiveBatchSource(
        tenant_id=str(event.tenant_id),
        archive_target_id=str(_event_uuid(500)),
        previous_checkpoint_id=None,
        previous_manifest_sha256=None,
        previous_git_commit_sha=None,
        source_high_water_sequence=1,
        first_event_sequence=1,
        last_event_sequence=1,
        event_count=1,
        export_timestamp=event.created_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        events=(archive_event_dto(event_row),),
        recovery_primary_keys=recovery_primary_keys,
        recovery_rows=recovery_rows,
    )


def _archive_batch(files: Mapping[str, bytes]) -> ArchiveBatch:
    return ArchiveBatch(
        manifest_bytes=files[MANIFEST_PATH],
        files={path: content for path, content in files.items() if path != MANIFEST_PATH},
    )


def _later_event_batch(
    *, first_files: Mapping[str, bytes], first_manifest_sha256: str, event: MemoryEvent
) -> ArchiveBatch:
    files = {
        path: content
        for path, content in first_files.items()
        if path == "archive-format.json" or path.startswith("schemas/")
    }
    event_path = (
        f"events/{event.created_at:%Y/%m/%d}/"
        f"{event.sequence:012d}-{event.event_id}.json"
    )
    files[event_path] = canonical_json_bytes(event.model_dump(mode="json"))
    schema_ids: dict[str, str] = {}
    for path, content in files.items():
        if not path.startswith("schemas/"):
            continue
        schema = json.loads(content)
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            raise AssertionError("checked-in archive schema identity is invalid")
        schema_ids[cast(str, schema["$id"])] = path
    manifest = build_manifest(
        files=files,
        first_event_sequence=event.sequence,
        last_event_sequence=event.sequence,
        previous_manifest_sha256=first_manifest_sha256,
        schema_ids=schema_ids,
        exporter_version="acceptance-v1",
        exported_at=event.created_at,
    )
    return ArchiveBatch(manifest_bytes=manifest.canonical_bytes, files=files)


@dataclass(frozen=True, slots=True)
class _ExpectedCommit:
    parent_sha: str | None
    message: str
    timestamp: str
    files: Mapping[str, bytes]


class _PinnedAcceptanceSigner:
    """Stand in only for the external Git/SSH trust operation in this DB gate."""

    def __init__(self, expected: Mapping[str, _ExpectedCommit]) -> None:
        self._expected = expected

    def verify_archive_commit(
        self,
        commit_sha: str,
        *,
        expected_parent_sha: str | None,
        expected_message: str,
        expected_timestamp: str,
        expected_files: Mapping[str, bytes],
    ) -> VerifiedGitCommit:
        expected = self._expected.get(commit_sha)
        if expected is None or (
            expected.parent_sha != expected_parent_sha
            or expected.message != expected_message
            or expected.timestamp != expected_timestamp
            or dict(expected.files) != dict(expected_files)
        ):
            raise GitSigningError("acceptance commit did not match its pinned fixture")
        tree_material = b"".join(
            path.encode("utf-8") + b"\0" + content
            for path, content in sorted(expected_files.items())
        )
        return VerifiedGitCommit(
            commit_sha=commit_sha,
            tree_sha=hashlib.sha1(tree_material, usedforsecurity=False).hexdigest(),
            parent_sha=expected_parent_sha,
        )


@dataclass(frozen=True, slots=True)
class _AggregateVerifier:
    tenant_id: UUID
    memory_id: UUID
    expected_aggregate: bytes

    async def verify(self, session: AsyncSession, plan: RestorePlan) -> None:
        assert plan.tenant_id == self.tenant_id
        assert plan.snapshot_high_water_sequence == 1
        assert plan.final_high_water_sequence == 2
        sequences = tuple(
            (
                await session.execute(
                    select(MemoryEventRow.sequence).order_by(MemoryEventRow.sequence)
                )
            ).scalars()
        )
        assert sequences == (1, 2)
        assert await session.scalar(select(MemoryEventCounter.next_sequence)) == 3
        assert (
            await load_canonical_aggregate_bytes(
                session,
                tenant_id=self.tenant_id,
                memory_id=self.memory_id,
            )
            == self.expected_aggregate
        )
        verified_events = await load_verified_events(session, tenant_id=self.tenant_id)
        replayed = rebuild_tenant(self.tenant_id, verified_events).projection
        assert canonical_aggregate_bytes(replayed, self.memory_id) == self.expected_aggregate


def test_builder_output_with_checked_in_schemas_passes_archive_preflight() -> None:
    branch_event = _branch_event()
    builder = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="acceptance-v1",
    )
    source = _snapshot_source(branch_event)
    built = builder.build(source)
    repeated = builder.build(source)
    assert built == repeated
    assert isinstance(built.payload, ArchivePayload)
    batch = _archive_batch(built.payload.files)
    signer = _PinnedAcceptanceSigner(
        {
            _FIRST_COMMIT: _ExpectedCommit(
                parent_sha=None,
                message="memory-export: events 1..1\n",
                timestamp=source.export_timestamp,
                files={MANIFEST_PATH: batch.manifest_bytes, **batch.files},
            )
        }
    )

    plan = preflight_restore(
        (ArchiveCommitBatch(commit_sha=_FIRST_COMMIT, batch=batch),),
        RestoreDestinationState(
            migrations_current=True,
            canonical_row_count=0,
            active_worker_count=0,
            is_disposable_recovery_database=True,
            is_freshly_created=True,
        ),
        signer=cast(GitCommitSigner, signer),
    )

    assert plan.snapshot_high_water_sequence == 1
    assert plan.final_high_water_sequence == 1
    assert plan.events_to_replay == ()


async def test_clean_database_restores_snapshot_then_later_event(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _seed_identifier("tenants", "tenant_id")
    branch_event = _branch_event()
    memory = _memory_state()
    later_event = _remembered_event(memory)
    expected_state = rebuild_tenant(tenant_id, (branch_event, later_event)).projection
    expected_aggregate = canonical_aggregate_bytes(expected_state, memory.memory_id)

    builder = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="acceptance-v1",
    )
    source = _snapshot_source(branch_event)
    first_build = builder.build(source)
    repeated_build = builder.build(source)
    assert first_build == repeated_build
    assert isinstance(first_build.payload, ArchivePayload)
    first_files = first_build.payload.files
    first_batch = _archive_batch(first_files)
    second_batch = _later_event_batch(
        first_files=first_files,
        first_manifest_sha256=first_build.manifest_sha256.hex(),
        event=later_event,
    )

    first_timestamp = branch_event.created_at.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    second_timestamp = later_event.created_at.isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
    signer = _PinnedAcceptanceSigner(
        {
            _FIRST_COMMIT: _ExpectedCommit(
                parent_sha=None,
                message="memory-export: events 1..1\n",
                timestamp=first_timestamp,
                files={MANIFEST_PATH: first_batch.manifest_bytes, **first_batch.files},
            ),
            _SECOND_COMMIT: _ExpectedCommit(
                parent_sha=_FIRST_COMMIT,
                message="memory-export: events 2..2\n",
                timestamp=second_timestamp,
                files={MANIFEST_PATH: second_batch.manifest_bytes, **second_batch.files},
            ),
        }
    )
    verified_plan = preflight_restore(
        (
            ArchiveCommitBatch(commit_sha=_FIRST_COMMIT, batch=first_batch),
            ArchiveCommitBatch(commit_sha=_SECOND_COMMIT, batch=second_batch),
        ),
        RestoreDestinationState(
            migrations_current=True,
            canonical_row_count=0,
            active_worker_count=0,
            is_disposable_recovery_database=True,
            is_freshly_created=True,
        ),
        signer=cast(GitCommitSigner, signer),
    )
    assert verified_plan.snapshot_high_water_sequence == 1
    assert tuple(event.sequence for event in verified_plan.events_to_replay) == (2,)

    database = Database(postgresql_server.database_url)
    try:
        async with database.tenant_session(tenant_id) as session:
            assert await session.scalar(select(func.count()).select_from(MemoryEventRow)) == 0
            result = await restore_validated_archive(
                session,
                verified_plan=verified_plan,
                decoder=CoreRestoreDecoder(),
                verifier=_AggregateVerifier(
                    tenant_id=tenant_id,
                    memory_id=memory.memory_id,
                    expected_aggregate=expected_aggregate,
                ),
            )
            assert result.tenant_id == tenant_id
            assert result.final_high_water_sequence == 2

        async with database.tenant_session(tenant_id) as session:
            assert await session.scalar(select(func.max(MemoryEventRow.sequence))) == 2
            assert (
                await load_canonical_aggregate_bytes(
                    session,
                    tenant_id=tenant_id,
                    memory_id=memory.memory_id,
                )
                == expected_aggregate
            )
    finally:
        await database.dispose()
