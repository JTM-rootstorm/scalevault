"""Database checkpoint reconstruction acceptance for new archive targets."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Protocol

import pytest
from kivra_memory.archive.adapters import ArchivePayload, DeterministicArchiveBuilder
from kivra_memory.archive.continuation import (
    DatabaseCheckpointReconstructor,
    reconstruct_new_target_checkpoint,
)
from kivra_memory.archive.git import VerifiedGitCommit
from kivra_memory.archive.models import MANIFEST_PATH
from kivra_memory.archive.verification import (
    ArchiveBatch,
    VerifiedArchive,
    VerifiedArchiveCommit,
    verify_archive_batch,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import (
    ArchiveExportCheckpoint,
    ArchiveTarget,
    MemoryEventCounter,
)
from sqlalchemy import select, update

from tests.fixtures.database_seed import seed_model_layers
from tests.integration.database.test_archive_restore_acceptance import (
    _branch_event,
    _event_row,
    _snapshot_source,
)

_ROOT = Path(__file__).resolve().parents[3]


class PostgreSQLTestServer(Protocol):
    database_url: str


@asynccontextmanager
async def _database(database_url: str) -> AsyncIterator[Database]:
    database = Database(database_url)
    try:
        yield database
    finally:
        await database.dispose()


@pytest.mark.database
async def test_verified_head_reconstructs_local_committed_checkpoint_on_disabled_target(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    event = _branch_event()
    source = _snapshot_source(event)
    built = DeterministicArchiveBuilder(
        schema_root=_ROOT / "schemas",
        exporter_version="test-v1",
    ).build(source)
    assert isinstance(built.payload, ArchivePayload)
    batch = verify_archive_batch(
        ArchiveBatch(
            manifest_bytes=built.payload.files[MANIFEST_PATH],
            files={
                path: content
                for path, content in built.payload.files.items()
                if path != MANIFEST_PATH
            },
        )
    )
    head = "a" * 40
    archive = VerifiedArchive(
        (VerifiedArchiveCommit(VerifiedGitCommit(head, "b" * 40, None), batch),)
    )
    target_id = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=810)
    checkpoint_id = new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=811)

    async with (
        _database(postgresql_server.database_url) as database,
        database.tenant_session(event.tenant_id) as session,
    ):
        for layer in seed_model_layers():
            session.add_all(layer)
            await session.flush()
        session.add(_event_row(event))
        await session.execute(
            update(MemoryEventCounter)
            .where(MemoryEventCounter.counter_id == 1)
            .values(next_sequence=2)
        )
        reconstructor = DatabaseCheckpointReconstructor(
            session=session,
            verified_archive=archive,
            tenant_id=event.tenant_id,
            checkpoint_id=checkpoint_id,
            target_name="recovered-primary",
            local_repository=_ROOT,
            repository_reference=_ROOT.as_uri(),
            branch_name="main",
        )
        plan = await reconstruct_new_target_checkpoint(
            archive,
            archive,
            archive_target_id=str(target_id),
            reconstructor=reconstructor,
        )

        target = await session.scalar(
            select(ArchiveTarget).where(ArchiveTarget.archive_target_id == target_id)
        )
        checkpoint = await session.scalar(
            select(ArchiveExportCheckpoint).where(
                ArchiveExportCheckpoint.checkpoint_id == checkpoint_id
            )
        )
        assert target is not None and target.state == "disabled"
        assert checkpoint is not None and checkpoint.state == "committed"
        assert checkpoint.git_commit_sha == plan.git_commit_sha
        assert checkpoint.remote_git_commit_sha is None
        assert bytes(checkpoint.manifest_sha256).hex() == plan.manifest_sha256
