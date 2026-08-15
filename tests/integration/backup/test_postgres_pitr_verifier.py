"""Real PostgreSQL coverage for the bounded PITR verifier input boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.events import MemoryEvent, MemoryState
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.domain.values import format_utc_datetime
from kivra_memory.storage.database import Database
from kivra_memory.storage.event_store import append_memory_event
from kivra_memory.storage.projector import rebuild_semantic_projections
from kivra_memory.storage.readiness import EXPECTED_ALEMBIC_HEAD, REQUIRED_EXTENSIONS
from kivra_memory.tools import postgres_pitr_verify
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import NullPool

from tests.fixtures.database_seed import seed_model_layers
from tests.integration.conftest import PostgreSQLTestServer
from tests.integration.database.conftest import (
    AlembicRunner,
    _sqlalchemy_url,
    bootstrap_required_extensions,
    installed_extensions,
)
from tests.integration.database.test_event_replay import (
    _branch_event,
    _memory_state,
    _remembered_event,
    _seed_identifier,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _target_sha256(kind: str, value: str) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "purpose": "scalevault-postgresql-pitr-target-v1",
                "kind": kind,
                "value": value,
            }
        )
    ).hexdigest()


def _protected_file(path: Path, value: bytes, *, mode: int) -> None:
    path.write_bytes(value)
    path.chmod(mode)


def _manifest(
    *, system_identifier: str, timeline_id: int, extensions: dict[str, str]
) -> dict[str, object]:
    started_at = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    target_kind = "name"
    target_value = "after-b"
    marker_a = "a" * 64
    marker_b = "b" * 64
    marker_c = "c" * 64
    synthetic_id = str(new_uuid7(timestamp_ms=1_786_262_400_000, random_bits=1))
    return {
        "version": 1,
        "system_identifier_sha256": _sha256(system_identifier),
        "timeline_id": timeline_id,
        "recovery_target": {
            "kind": target_kind,
            "value": target_value,
            "sha256": _target_sha256(target_kind, target_value),
        },
        "migration_revision": EXPECTED_ALEMBIC_HEAD,
        "compatibility": {
            "component": "memory_node",
            "contract_version": 11,
            "minimum_reader_revision": EXPECTED_ALEMBIC_HEAD,
            "minimum_writer_revision": EXPECTED_ALEMBIC_HEAD,
        },
        "extension_versions": extensions,
        "event_count": 2,
        "event_prefix_sha256": "d" * 64,
        "projection": {
            "counts": {
                "branches": 0,
                "memories": 0,
                "evidence": 0,
                "links": 0,
                "conflicts": 0,
                "conflict_members": 0,
            },
            "sha256": "e" * 64,
        },
        "markers": {
            "a": {"sequence": 1, "command_sha256": marker_a},
            "b": {"sequence": 2, "command_sha256": marker_b},
            "c": {"sequence": 3, "command_sha256": marker_c},
        },
        "synthetic": {
            "tenant_id": synthetic_id,
            "memory_id": str(new_uuid7(timestamp_ms=1_786_262_400_000, random_bits=2)),
            "drill_generation": "integration-pitr-verifier",
            "correlation_sha256": "f" * 64,
        },
        "embedding_requeue": {"count": 0, "sha256": "1" * 64},
        "provider_attachment_paths": ["/var/lib/scalevault-integration/provider-absent"],
        "destruction_ledger": {
            "root": "/var/lib/scalevault-integration/ledger",
            "anchor_path": "/var/lib/scalevault-integration/anchor.json",
            "accepted_entry_count": 0,
            "accepted_aggregate_sha256": "3" * 64,
        },
        "drill_started_at": format_utc_datetime(started_at),
        "rpo_reference_at": format_utc_datetime(started_at),
    }


async def _seed_projected_memory(
    database_url: str,
) -> tuple[MemoryState, MemoryEvent, MemoryEvent]:
    """Persist canonical events and their projections through the normal writer."""

    database = Database(database_url)
    tenant_id = _seed_identifier("tenants", "tenant_id")
    memory = _memory_state()
    try:
        async with database.tenant_session(tenant_id) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
            branch = await append_memory_event(session, _branch_event)
            remembered = await append_memory_event(
                session,
                lambda sequence: _remembered_event(sequence, memory),
            )
            await rebuild_semantic_projections(session, tenant_id=tenant_id)
        return memory, branch, remembered
    finally:
        await database.dispose()


@pytest.mark.database
def test_pitr_verifier_uses_real_migrated_pg17_and_fails_closed_without_recovery(
    postgresql_server: PostgreSQLTestServer,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A migrated primary is valid schema evidence, never recovery evidence."""

    bootstrap_required_extensions(postgresql_server.database_url)
    from sqlalchemy import create_engine

    engine = create_engine(
        _sqlalchemy_url(postgresql_server.database_url),
        hide_parameters=True,
        poolclass=NullPool,
    )
    runner = AlembicRunner(engine)
    probe = postgres_pitr_verify.PostgresPitrProbe(postgresql_server.database_url)
    try:
        runner.upgrade()
        memory, branch, remembered = asyncio.run(
            _seed_projected_memory(postgresql_server.database_url)
        )
        with runner.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == (EXPECTED_ALEMBIC_HEAD)
            assert connection.execute(
                text(
                    "SELECT contract_version, minimum_reader_revision, minimum_writer_revision "
                    "FROM alembic_compatibility WHERE component = 'memory_node'"
                )
            ).one() == (11, EXPECTED_ALEMBIC_HEAD, EXPECTED_ALEMBIC_HEAD)
            extensions = installed_extensions(connection)
            assert set(extensions) == REQUIRED_EXTENSIONS
            system_identifier = connection.execute(
                text("SELECT system_identifier::text FROM pg_catalog.pg_control_system()")
            ).scalar_one()
            timeline_id = connection.execute(
                text("SELECT timeline_id FROM pg_catalog.pg_control_checkpoint()")
            ).scalar_one()
            generated_search_document = connection.execute(
                text("SELECT search_document::text FROM memories")
            ).scalar_one()
            assert generated_search_document

        manifest_path = tmp_path / "pitr-manifest.json"
        connection_path = tmp_path / "pitr-connection"
        document = _manifest(
            system_identifier=str(system_identifier),
            timeline_id=int(timeline_id),
            extensions=extensions,
        )
        document["markers"] = {
            "a": {"sequence": branch.sequence, "command_sha256": branch.command_sha256},
            "b": {"sequence": remembered.sequence, "command_sha256": remembered.command_sha256},
            "c": {"sequence": remembered.sequence + 1, "command_sha256": "c" * 64},
        }
        document["synthetic"] = {
            "tenant_id": str(memory.tenant_id),
            "memory_id": str(memory.memory_id),
            "drill_generation": "integration-pitr-verifier",
            "correlation_sha256": "f" * 64,
        }
        _protected_file(manifest_path, canonical_json_bytes(document), mode=0o400)
        _protected_file(
            connection_path,
            b"postgresql://scalevault_test@%2Fscalevault-verifier-absent/postgres",
            mode=0o600,
        )
        manifest = postgres_pitr_verify.PitrManifest.load(manifest_path)

        async def synthetic_stub(
            _session: AsyncSession,
            expected: postgres_pitr_verify.SyntheticExpectation,
        ) -> str:
            assert expected.tenant_id == str(memory.tenant_id)
            assert expected.memory_id == str(memory.memory_id)
            return expected.correlation_sha256

        monkeypatch.setattr(postgres_pitr_verify, "_synthetic_correlation", synthetic_stub)
        application = asyncio.run(probe.application_snapshot(manifest))
        assert application.event_count == 2
        assert application.projection_counts["memories"] == 1
        assert application.projection_counts == application.rebuilt_projection_counts
        assert application.projection_sha256 == application.rebuilt_projection_sha256

        snapshot = asyncio.run(probe.server_snapshot(manifest))
        assert 170000 <= snapshot.server_version_num < 180000
        assert snapshot.system_identifier_sha256 == document["system_identifier_sha256"]
        assert snapshot.timeline_id == timeline_id
        assert not snapshot.in_recovery
        assert not snapshot.replay_paused
        assert not snapshot.transaction_read_only
        assert not snapshot.socket_connection

        assert (
            postgres_pitr_verify.main(
                [
                    "--manifest",
                    str(manifest_path),
                    "--database-connection-file",
                    str(connection_path),
                ]
            )
            == 3
        )
        first = capsys.readouterr()
        assert first.err == ""
        assert json.loads(first.out)["result_code"] == "database_unavailable"

        canary = "pitr-verifier-secret-canary"
        manifest_path.chmod(0o600)
        manifest_path.write_bytes(canonical_json_bytes(document) + canary.encode("ascii"))
        manifest_path.chmod(0o400)
        assert (
            postgres_pitr_verify.main(
                [
                    "--manifest",
                    str(manifest_path),
                    "--database-connection-file",
                    str(connection_path),
                ]
            )
            == 2
        )
        tampered_manifest = capsys.readouterr()
        assert tampered_manifest.err == ""
        assert canary not in tampered_manifest.out
        assert json.loads(tampered_manifest.out)["result_code"] == "configuration_invalid"

        _protected_file(manifest_path, canonical_json_bytes(document), mode=0o400)
        connection_path.chmod(0o600)
        connection_path.write_text(canary, encoding="ascii")
        connection_path.chmod(0o600)
        assert (
            postgres_pitr_verify.main(
                [
                    "--manifest",
                    str(manifest_path),
                    "--database-connection-file",
                    str(connection_path),
                ]
            )
            == 2
        )
        tampered_connection = capsys.readouterr()
        assert tampered_connection.err == ""
        assert canary not in tampered_connection.out
        assert json.loads(tampered_connection.out)["result_code"] == "configuration_invalid"
    finally:
        asyncio.run(probe.close())
        runner.dispose()
