"""PostgreSQL acceptance coverage for protected Genesis import persistence."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import UUID

import pytest
from kivra_memory.application.genesis_apply import (
    GenesisOperatorConfig,
    PreparedGenesisImport,
    prepare_genesis_import,
)
from kivra_memory.application.genesis_import import (
    GenesisCanonicalMappings,
    GenesisImportEngine,
    GenesisImporterAuthority,
    GenesisImportPlanContext,
    GenesisImportRunContext,
    GenesisSourceRecordContext,
    GenesisSubjectMapping,
)
from kivra_memory.application.mutations import CommandPrincipal
from kivra_memory.application.selection import SelectionExecutionError
from kivra_memory.domain.enums import (
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.ingress.processor import (
    GenesisNominationInput,
)
from kivra_memory.storage.database import Database
from kivra_memory.storage.genesis_import import (
    GenesisImportRepository,
    GenesisImportStorageError,
)
from kivra_memory.storage.models import (
    Client,
    CommandReceipt,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportRunResult,
    GenesisImportSource,
    Memory,
    MemoryEvent,
    SelectionDecision,
    TransportBinding,
)
from psycopg import Connection
from psycopg import sql as psycopg_sql
from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.pool import NullPool

from tests.fixtures.database_seed import seed_model_layers, seed_rows
from tests.unit.application.test_genesis_plan import _plan

from .conftest import (
    AlembicRunner,
    bootstrap_required_extensions,
    run_operator_sql_file,
)

_NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
_POLICY_SHA = bytes.fromhex("b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e")
_PARSER_VERSIONS = {
    "scalevault.ingress.proposal.v1": "proposal-v1.schema.1",
    "scalevault.ingress.genesis-checkpoint.v1": "checkpoint-v1.documented.1",
    "scalevault.ingress.genesis-checkpoint.v2": "checkpoint-v2.schema.1",
}
_SOURCE_PATH = "ingress/checkpoints/v2/genesis/2026/08/synthetic-genesis-source.json"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_ROLE_BOOTSTRAP = _REPOSITORY_ROOT / "deploy/memory-node/postgresql/bootstrap_roles.sql"


class PostgreSQLTestServer(Protocol):
    database_url: str


@dataclass(frozen=True, slots=True)
class _PlanRows:
    prepared: PreparedGenesisImport
    mappings: GenesisCanonicalMappings
    authority: GenesisImporterAuthority

    @property
    def run(self) -> GenesisImportRun:
        return self.prepared.run

    @property
    def source(self) -> GenesisImportSource:
        return self.prepared.sources[0]

    @property
    def record(self) -> GenesisImportRecord:
        return self.prepared.records[0]


@dataclass(frozen=True, slots=True)
class _ApplicationContext:
    principal: CommandPrincipal
    mappings: GenesisCanonicalMappings
    authority: GenesisImporterAuthority
    plan: GenesisImportPlanContext
    run: GenesisImportRunContext
    nominations: tuple[tuple[GenesisNominationInput, GenesisSourceRecordContext], ...]


def _seed_id(table: str, field: str) -> UUID:
    return cast(UUID, seed_rows()[table][0][field])


def _plan_rows() -> _PlanRows:
    tenant_id = _seed_id("tenants", "tenant_id")
    plan = _plan()
    subject_id = _seed_id("subjects", "subject_id")
    mappings = GenesisCanonicalMappings(
        contract_version="scalevault-genesis-canonical-mappings-v1",
        genesis_actor_reference="kivra:genesis",
        genesis_actor_id=cast(UUID, seed_rows()["actors"][1]["actor_id"]),
        persona_id=_seed_id("personas", "persona_id"),
        lineage_id=_seed_id("lineages", "lineage_id"),
        branch_id=_seed_id("branches", "branch_id"),
        subjects=(
            GenesisSubjectMapping(
                subject_kind=SubjectKind.RELATIONSHIP,
                source_reference="relationship:private",
                subject_id=subject_id,
            ),
            GenesisSubjectMapping(
                subject_kind=SubjectKind.GLOBAL,
                source_reference="genesis-import:terminal",
                subject_id=subject_id,
            ),
        ),
    )
    authority = GenesisImporterAuthority(
        contract_version="scalevault-genesis-importer-authority-v1",
        tenant_id=tenant_id,
        actor_id=cast(UUID, seed_rows()["actors"][0]["actor_id"]),
        client_id=new_uuid7(),
        transport_binding_id=new_uuid7(),
    )
    config = GenesisOperatorConfig(
        contract_version="scalevault-genesis-operator-config-v1",
        expected_plan_sha256=plan.manifest.digest,
        import_run_id=new_uuid7(),
        pre_state_sha256="73" * 32,
        backup_reference="synthetic-verified-backup",
        mappings=mappings,
        importer_authority=authority,
    )
    return _PlanRows(prepare_genesis_import(plan, config), mappings, authority)


async def _application_context(database: Database, rows: _PlanRows) -> _ApplicationContext:
    tenant_id = rows.run.tenant_id
    importer_actor_id = rows.authority.actor_id
    client_id = rows.authority.client_id
    binding_id = rows.authority.transport_binding_id
    async with database.tenant_session(tenant_id) as session:
        session.add(
            Client(
                client_id=client_id,
                tenant_id=tenant_id,
                public_id=f"synthetic-genesis-importer-{client_id}",
                display_name="Synthetic Genesis Importer",
                kind="operator",
                transport_kind="internal_service",
                scopes=["memory.write.genesis_import"],
                capability_profile={"profile": "synthetic-genesis-import"},
                created_at=_NOW,
                revoked_at=None,
            )
        )
        await session.flush()
        session.add(
            TransportBinding(
                transport_binding_id=binding_id,
                tenant_id=tenant_id,
                actor_id=importer_actor_id,
                client_id=client_id,
                transport_kind="internal_service",
                disclosure_boundary="internal",
                installation_id=None,
                authorized_operations={"operations": ["genesis_import"]},
                created_at=_NOW,
                valid_until=None,
            )
        )
    principal = CommandPrincipal(
        tenant_id=tenant_id,
        actor_id=importer_actor_id,
        client_id=client_id,
        transport_binding_id=binding_id,
        scopes=frozenset({"memory.write.genesis_import"}),
    )
    return _ApplicationContext(
        principal,
        rows.mappings,
        rows.authority,
        rows.prepared.plan_context,
        rows.prepared.run_context,
        rows.prepared.nominations,
    )


@asynccontextmanager
async def _seeded_database(database_url: str) -> AsyncIterator[Database]:
    database = Database(database_url)
    try:
        async with database.tenant_session(_seed_id("tenants", "tenant_id")) as session:
            for layer in seed_model_layers():
                session.add_all(layer)
                await session.flush()
        yield database
    finally:
        await database.dispose()


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def _set_role_password(server: PostgreSQLTestServer, role: str, password: str) -> None:
    with Connection.connect(server.database_url) as connection:
        connection.execute(
            psycopg_sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                psycopg_sql.Identifier(role),
                psycopg_sql.Literal(password),
            )
        )


def _login_engine(server: PostgreSQLTestServer, role: str, password: str) -> Engine:
    url = make_url(server.database_url).set(username=role, password=password)
    return create_engine(
        url.set(drivername="postgresql+psycopg"),
        hide_parameters=True,
        poolclass=NullPool,
    )


@pytest.fixture
def genesis_role_database(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> Iterator[AlembicRunner]:
    bootstrap_required_extensions(postgresql_server.database_url)
    run_operator_sql_file(postgresql_server, _ROLE_BOOTSTRAP)
    alembic_runner.upgrade_as_scalevault_migrator()
    run_operator_sql_file(postgresql_server, _ROLE_BOOTSTRAP)
    yield alembic_runner


def test_existing_0003_upgrades_to_genesis_provenance(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0003_selection_policy_lifecycle")
    with runner.connect() as connection:
        assert "genesis_import_runs" not in inspect(connection).get_table_names()

    runner.upgrade("0004_genesis_import_provenance")
    with runner.connect() as connection:
        inspector = inspect(connection)
        genesis_tables = {
            "genesis_import_runs",
            "genesis_import_sources",
            "genesis_import_records",
            "genesis_import_exclusions",
            "genesis_import_supersessions",
            "genesis_import_run_results",
        }
        assert genesis_tables <= set(inspector.get_table_names())
        assert {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT tablename FROM pg_policies "
                    "WHERE schemaname = 'public' AND tablename = ANY(:tables)"
                ),
                {"tables": sorted(genesis_tables)},
            )
        } == genesis_tables
        assert connection.execute(
            text(
                "SELECT contract_version, minimum_reader_revision, minimum_writer_revision "
                "FROM alembic_compatibility WHERE component = 'memory_node'"
            )
        ).one() == (4, "0004_genesis_import_provenance", "0004_genesis_import_provenance")


async def test_exact_plan_staging_replay_conflict_resume_and_candidate_ceiling(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _seed_id("tenants", "tenant_id")
    async with _seeded_database(postgresql_server.database_url) as database:
        rows = _plan_rows()
        async with database.tenant_session(tenant_id) as session:
            repository = GenesisImportRepository(session)
            status = await repository.stage_import_plan(
                run=rows.run,
                sources=rows.prepared.sources,
                records=rows.prepared.records,
                exclusions=rows.prepared.exclusions,
                supersessions=rows.prepared.supersessions,
            )
        assert status.source_count == 1
        assert status.planned_record_count == len(rows.prepared.records)
        assert status.terminal_record_count == 0
        assert status.canonical_mapping_sha256 == rows.run.canonical_mapping_sha256
        assert all(
            set(cast(dict[str, object], record.mapping_metadata["canonical_mapping"]))
            == {
                "persona_id",
                "lineage_id",
                "branch_id",
                "genesis_actor_id",
                "subject_id",
                "subject_kind",
                "logical_session_id",
            }
            for record in rows.prepared.records
        )

        async with database.tenant_session(tenant_id) as session:
            repository = GenesisImportRepository(session)
            replay = await repository.stage_import_plan(
                run=rows.run,
                sources=rows.prepared.sources,
                records=rows.prepared.records,
                exclusions=rows.prepared.exclusions,
                supersessions=rows.prepared.supersessions,
            )
            pending = await repository.pending_records(
                tenant_id=tenant_id,
                import_run_id=rows.run.import_run_id,
            )
            counts = {
                table: await session.scalar(text(f"SELECT count(*) FROM {table}"))
                for table in (
                    "genesis_import_runs",
                    "genesis_import_sources",
                    "genesis_import_records",
                    "genesis_import_exclusions",
                    "genesis_import_supersessions",
                )
            }
        assert replay == status
        assert {item.import_record_id for item in pending} == {
            record.import_record_id for record in rows.prepared.records
        }
        assert counts == {
            "genesis_import_runs": 1,
            "genesis_import_sources": len(rows.prepared.sources),
            "genesis_import_records": len(rows.prepared.records),
            "genesis_import_exclusions": len(rows.prepared.exclusions),
            "genesis_import_supersessions": len(rows.prepared.supersessions),
        }

        tampered_record = GenesisImportRecord(
            **{
                column.name: getattr(rows.record, column.name)
                for column in GenesisImportRecord.__table__.columns
                if column.name != "provenance_metadata"
            },
            provenance_metadata={**rows.record.provenance_metadata, "tampered": True},
        )
        async with database.tenant_session(tenant_id) as session:
            with pytest.raises(
                GenesisImportStorageError,
                match="import_plan_conflict",
            ):
                await GenesisImportRepository(session).stage_import_plan(
                    run=rows.run,
                    sources=rows.prepared.sources,
                    records=(tampered_record, *rows.prepared.records[1:]),
                    exclusions=rows.prepared.exclusions,
                    supersessions=rows.prepared.supersessions,
                )

        invalid = GenesisImportRecord(
            **{
                column.name: getattr(rows.record, column.name)
                for column in GenesisImportRecord.__table__.columns
                if column.name
                not in {
                    "import_record_id",
                    "source_item_identity",
                    "nomination_sha256",
                    "nomination_idempotency_key",
                    "requested_outcome_ceiling",
                }
            },
            import_record_id=new_uuid7(),
            source_item_identity="synthetic-active-attempt",
            nomination_sha256=b"x" * 32,
            nomination_idempotency_key=f"genesis-import-v1:{'d' * 64}",
            requested_outcome_ceiling="active",
        )
        async with database.tenant_session(tenant_id) as session:
            with pytest.raises(IntegrityError):
                async with session.begin_nested():
                    session.add(invalid)
                    await session.flush()

        terminal_on_insert = GenesisImportRecord(
            **{
                column.name: getattr(rows.record, column.name)
                for column in GenesisImportRecord.__table__.columns
                if column.name
                not in {
                    "import_record_id",
                    "source_item_identity",
                    "nomination_sha256",
                    "nomination_idempotency_key",
                    "processing_state",
                    "selection_decision_id",
                    "processed_at",
                }
            },
            import_record_id=new_uuid7(),
            source_item_identity="synthetic-premature-terminal",
            nomination_sha256=b"t" * 32,
            nomination_idempotency_key=f"genesis-import-v1:{'e' * 64}",
            processing_state="omit",
            selection_decision_id=new_uuid7(),
            processed_at=_NOW,
        )
        async with database.tenant_session(tenant_id) as session:
            with pytest.raises(IntegrityError):
                async with session.begin_nested():
                    session.add(terminal_on_insert)
                    await session.flush()

        premature_result = GenesisImportRunResult(
            tenant_id=tenant_id,
            import_run_id=rows.run.import_run_id,
            planned_record_count=len(rows.prepared.records),
            candidate_count=0,
            omit_count=len(rows.prepared.records),
            reject_count=0,
            replay_verified=True,
            completed_at=_NOW,
        )
        async with database.tenant_session(tenant_id) as session:
            with pytest.raises(IntegrityError):
                async with session.begin_nested():
                    session.add(premature_result)
                    await session.flush()


async def test_raw_archive_is_importer_only_and_rls_is_forced(
    postgresql_server: PostgreSQLTestServer,
    genesis_role_database: AlembicRunner,
) -> None:
    tenant_id = _seed_id("tenants", "tenant_id")
    async with _seeded_database(postgresql_server.database_url) as database:
        rows = _plan_rows()
        async with database.tenant_session(tenant_id) as session:
            await GenesisImportRepository(session).stage_import_plan(
                run=rows.run,
                sources=rows.prepared.sources,
                records=rows.prepared.records,
                exclusions=rows.prepared.exclusions,
                supersessions=rows.prepared.supersessions,
            )

    passwords = {
        role: secrets.token_urlsafe(24)
        for role in (
            "kivra_memory_api",
            "kivra_memory_worker",
            "kivra_memory_policy",
            "kivra_memory_genesis_importer",
        )
    }
    for role, password in passwords.items():
        _set_role_password(postgresql_server, role, password)

    for role in ("kivra_memory_api", "kivra_memory_worker", "kivra_memory_policy"):
        engine = _login_engine(postgresql_server, role, passwords[role])
        try:
            with pytest.raises(DBAPIError) as denied, engine.begin() as connection:
                connection.execute(text("SELECT raw_bytes FROM genesis_import_sources"))
            assert _sqlstate(denied.value) == "42501"
        finally:
            engine.dispose()

    importer = _login_engine(
        postgresql_server,
        "kivra_memory_genesis_importer",
        passwords["kivra_memory_genesis_importer"],
    )
    try:
        with importer.begin() as connection:
            connection.execute(
                text("SELECT set_config('scalevault.tenant_id', :tenant, true)"),
                {"tenant": str(tenant_id)},
            )
            assert (
                connection.execute(text("SELECT count(*) FROM genesis_import_sources")).scalar_one()
                == 1
            )
            for table_name in ("memories", "memory_evidence"):
                assert connection.execute(
                    text("SELECT has_table_privilege(current_user, :table, 'INSERT')"),
                    {"table": table_name},
                ).scalar_one()
                assert not connection.execute(
                    text("SELECT has_table_privilege(current_user, :table, 'UPDATE')"),
                    {"table": table_name},
                ).scalar_one()
        with importer.begin() as connection:
            connection.execute(
                text("SELECT set_config('scalevault.tenant_id', :tenant, true)"),
                {"tenant": str(new_uuid7())},
            )
            assert (
                connection.execute(text("SELECT count(*) FROM genesis_import_sources")).scalar_one()
                == 0
            )
    finally:
        importer.dispose()


async def test_application_commits_selection_receipt_event_projection_and_terminal_link_once(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _seed_id("tenants", "tenant_id")
    async with _seeded_database(postgresql_server.database_url) as database:
        rows = _plan_rows()
        async with database.tenant_session(tenant_id) as session:
            await GenesisImportRepository(session).stage_import_plan(
                run=rows.run,
                sources=rows.prepared.sources,
                records=rows.prepared.records,
                exclusions=rows.prepared.exclusions,
                supersessions=rows.prepared.supersessions,
            )
        context = await _application_context(database, rows)
        engine = GenesisImportEngine(
            database.session_factory,
            context.mappings,
            context.authority,
        )

        first_nomination, first_source = context.nominations[0]
        first = await engine.execute(
            context.principal,
            first_nomination,
            plan=context.plan,
            run=context.run,
            source_record=first_source,
        )
        assert first.outcome == "candidate"
        assert first.event_id is not None
        assert first.memory_id is not None
        assert first.idempotent_replay is False

        async with database.tenant_session(tenant_id) as session:
            record = await session.get(GenesisImportRecord, rows.record.import_record_id)
            assert record is not None
            pending = await GenesisImportRepository(session).pending_records(
                tenant_id=tenant_id,
                import_run_id=rows.run.import_run_id,
            )
            assert len(pending) == len(rows.prepared.records) - 1
            terminal_snapshot = (
                record.processing_state,
                record.selection_decision_id,
                record.event_id,
                record.memory_id,
                record.processed_at,
            )
            assert terminal_snapshot[:4] == (
                "candidate",
                first.decision_id,
                first.event_id,
                first.memory_id,
            )
            counts_before = {
                "decisions": await session.scalar(
                    select(func.count()).select_from(SelectionDecision)
                ),
                "receipts": await session.scalar(select(func.count()).select_from(CommandReceipt)),
                "events": await session.scalar(select(func.count()).select_from(MemoryEvent)),
                "memories": await session.scalar(select(func.count()).select_from(Memory)),
            }
        assert counts_before == dict.fromkeys(counts_before, 1)

        replay = await engine.execute(
            context.principal,
            first_nomination,
            plan=context.plan,
            run=context.run,
            source_record=first_source,
        )
        assert replay.idempotent_replay is True
        assert replay.receipt_id == first.receipt_id
        assert replay.decision_id == first.decision_id
        assert replay.event_id == first.event_id
        assert replay.memory_id == first.memory_id

        async with database.tenant_session(tenant_id) as session:
            replayed_record = await session.get(GenesisImportRecord, rows.record.import_record_id)
            assert replayed_record is not None
            assert (
                replayed_record.processing_state,
                replayed_record.selection_decision_id,
                replayed_record.event_id,
                replayed_record.memory_id,
                replayed_record.processed_at,
            ) == terminal_snapshot
            counts_after = {
                "decisions": await session.scalar(
                    select(func.count()).select_from(SelectionDecision)
                ),
                "receipts": await session.scalar(select(func.count()).select_from(CommandReceipt)),
                "events": await session.scalar(select(func.count()).select_from(MemoryEvent)),
                "memories": await session.scalar(select(func.count()).select_from(Memory)),
            }
        assert counts_after == counts_before

        second_nomination, second_source = context.nominations[1]
        async with database.tenant_session(tenant_id) as session:
            repository = GenesisImportRepository(session)
            with pytest.raises(GenesisImportStorageError, match="import_plan_mismatch"):
                await repository.terminalize_record(
                    tenant_id=tenant_id,
                    import_run_id=rows.run.import_run_id,
                    import_record_id=second_source.import_record_id,
                    nomination_sha256=b"w" * 32,
                    outcome="omit",
                    selection_decision_id=new_uuid7(),
                    processed_at=_NOW,
                )
            with pytest.raises(GenesisImportStorageError, match="replay_not_verified"):
                await repository.complete_run(
                    tenant_id=tenant_id,
                    import_run_id=rows.run.import_run_id,
                    plan_sha256=bytes(rows.run.plan_sha256),
                    pre_state_sha256=bytes(rows.run.pre_state_sha256),
                    backup_reference=rows.run.backup_reference,
                    replay_verified=False,
                    completed_at=_NOW,
                )

        second = await engine.execute(
            context.principal,
            second_nomination,
            plan=context.plan,
            run=context.run,
            source_record=second_source,
        )
        assert second.outcome == "candidate"

        async with database.tenant_session(tenant_id) as session:
            repository = GenesisImportRepository(session)
            completed = await repository.complete_run(
                tenant_id=tenant_id,
                import_run_id=rows.run.import_run_id,
                plan_sha256=bytes(rows.run.plan_sha256),
                pre_state_sha256=bytes(rows.run.pre_state_sha256),
                backup_reference=rows.run.backup_reference,
                replay_verified=True,
                completed_at=_NOW,
            )
        async with database.tenant_session(tenant_id) as session:
            later_replay = await GenesisImportRepository(session).complete_run(
                tenant_id=tenant_id,
                import_run_id=rows.run.import_run_id,
                plan_sha256=bytes(rows.run.plan_sha256),
                pre_state_sha256=bytes(rows.run.pre_state_sha256),
                backup_reference=rows.run.backup_reference,
                replay_verified=True,
                completed_at=_NOW + timedelta(days=1),
            )
        assert later_replay == completed
        assert later_replay.completed_at == _NOW


class _FailingTerminalRepository:
    def __init__(self, session: Any) -> None:
        self._delegate = GenesisImportRepository(session)

    async def verify_planned_record_context(self, **values: object) -> object:
        return await self._delegate.verify_planned_record_context(**values)  # type: ignore[arg-type]

    async def terminalize_record(self, **_values: object) -> object:
        raise GenesisImportStorageError("synthetic_participant_failure")


async def test_participant_failure_rolls_back_every_canonical_selection_write(
    postgresql_server: PostgreSQLTestServer,
    migrated_database: object,
) -> None:
    _ = migrated_database
    tenant_id = _seed_id("tenants", "tenant_id")
    async with _seeded_database(postgresql_server.database_url) as database:
        rows = _plan_rows()
        async with database.tenant_session(tenant_id) as session:
            await GenesisImportRepository(session).stage_import_plan(
                run=rows.run,
                sources=rows.prepared.sources,
                records=rows.prepared.records,
                exclusions=rows.prepared.exclusions,
                supersessions=rows.prepared.supersessions,
            )
        context = await _application_context(database, rows)
        engine = GenesisImportEngine(
            database.session_factory,
            context.mappings,
            context.authority,
            repository_factory=lambda session: cast(
                GenesisImportRepository, _FailingTerminalRepository(session)
            ),
        )

        nomination, source = context.nominations[0]
        with pytest.raises(SelectionExecutionError, match="provenance_conflict"):
            await engine.execute(
                context.principal,
                nomination,
                plan=context.plan,
                run=context.run,
                source_record=source,
            )

        async with database.tenant_session(tenant_id) as session:
            record = await session.get(GenesisImportRecord, rows.record.import_record_id)
            assert record is not None
            assert record.processing_state == "planned"
            assert record.selection_decision_id is None
            assert record.event_id is None
            assert record.memory_id is None
            assert record.processed_at is None
            assert await session.scalar(select(func.count()).select_from(SelectionDecision)) == 0
            assert await session.scalar(select(func.count()).select_from(CommandReceipt)) == 0
            assert await session.scalar(select(func.count()).select_from(MemoryEvent)) == 0
            assert await session.scalar(select(func.count()).select_from(Memory)) == 0
