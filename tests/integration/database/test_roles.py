from __future__ import annotations

import asyncio
import hmac
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from kivra_memory.admin import CredentialAdminService
from kivra_memory.auth import ClientCapabilityProfile
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage.archive import recovery_table_names
from kivra_memory.storage.credentials import CredentialAdminStorageRepository
from kivra_memory.storage.database import Database
from kivra_memory.storage.models import Actor, Client, TransportBinding, TransportInstallation
from psycopg import Connection
from psycopg import sql as psycopg_sql
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from tests.fixtures.database_seed import seed_model_layers, seed_rows

from .conftest import (
    AlembicRunner,
    PostgreSQLTestServer,
    bootstrap_required_extensions,
    run_operator_sql_file,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ROLE_BOOTSTRAP = REPOSITORY_ROOT / "deploy/memory-node/postgresql/bootstrap_roles.sql"
OWNER_ROLE = "kivra_memory_owner"
MIGRATOR_ROLE = "kivra_memory_migrator"
RUNTIME_ROLES = (
    "kivra_memory_credential_admin",
    "kivra_memory_api",
    "kivra_memory_policy",
    "kivra_memory_genesis_importer",
    "kivra_memory_worker",
    "kivra_memory_purge",
    "kivra_memory_ingress",
    "kivra_memory_exporter",
)
TENANT_A = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835c1")
TENANT_B = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835c2")


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def _set_role_password(
    postgresql_server: PostgreSQLTestServer,
    role: str,
    password: str,
    *,
    valid_until: str = "infinity",
) -> None:
    """Provision a disposable role without placing its secret in argv or output."""

    with Connection.connect(postgresql_server.database_url) as connection:
        connection.execute(
            psycopg_sql.SQL("ALTER ROLE {} PASSWORD {} VALID UNTIL {}").format(
                psycopg_sql.Identifier(role),
                psycopg_sql.Literal(password),
                psycopg_sql.Literal(valid_until),
            )
        )


def _login_engine(
    postgresql_server: PostgreSQLTestServer,
    role: str,
    password: str,
) -> Engine:
    url = make_url(postgresql_server.database_url).set(username=role, password=password)
    return create_engine(
        url.set(drivername="postgresql+psycopg"),
        hide_parameters=True,
        poolclass=NullPool,
    )


@pytest.fixture
def role_secured_database(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> Iterator[AlembicRunner]:
    bootstrap_required_extensions(postgresql_server.database_url)
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)
    alembic_runner.upgrade_as_scalevault_migrator()
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)
    yield alembic_runner


def test_role_bootstrap_refuses_an_unexpected_database_before_mutation(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> None:
    with pytest.raises(RuntimeError, match="does not match expected_database"):
        run_operator_sql_file(
            postgresql_server,
            ROLE_BOOTSTRAP,
            expected_database="not_the_connected_database",
        )

    with alembic_runner.engine.begin() as connection:
        created_roles = connection.execute(
            text("SELECT count(*) FROM pg_roles WHERE rolname = ANY(:roles)"),
            {"roles": [OWNER_ROLE, MIGRATOR_ROLE, *RUNTIME_ROLES]},
        ).scalar_one()

    assert created_roles == 0


def test_role_bootstrap_upgrades_m1_ownership_and_is_idempotent(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> None:
    password = secrets.token_urlsafe(32)
    valid_until = "2035-01-01 00:00:00+00"
    with alembic_runner.engine.begin() as connection:
        connection.execute(text("CREATE ROLE kivra_memory_api LOGIN"))
        connection.execute(text("ALTER DATABASE postgres OWNER TO kivra_memory_api"))
        connection.execute(text("ALTER SCHEMA public OWNER TO kivra_memory_api"))
        connection.execute(text("SET ROLE kivra_memory_api"))
        connection.execute(text("CREATE TABLE public.m1_owned_probe (id integer PRIMARY KEY)"))
        connection.execute(text("RESET ROLE"))

    _set_role_password(
        postgresql_server,
        "kivra_memory_api",
        password,
        valid_until=valid_until,
    )
    with alembic_runner.engine.begin() as connection:
        verifier_before, valid_until_before = connection.execute(
            text(
                "SELECT rolpassword, rolvaliduntil FROM pg_authid "
                "WHERE rolname = 'kivra_memory_api'"
            )
        ).one()

    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)

    with alembic_runner.engine.begin() as connection:
        database_owner = connection.execute(
            text(
                "SELECT owner.rolname FROM pg_database AS database "
                "JOIN pg_roles AS owner ON owner.oid = database.datdba "
                "WHERE database.datname = current_database()"
            )
        ).scalar_one()
        owner_rows = connection.execute(
            text(
                "SELECT class.relname, owner.rolname FROM pg_class AS class "
                "JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace "
                "JOIN pg_roles AS owner ON owner.oid = class.relowner "
                "WHERE namespace.nspname = 'public' "
                "AND class.relname = 'm1_owned_probe'"
            )
        )
        object_owners: dict[str, str] = {str(row[0]): str(row[1]) for row in owner_rows}
        schema_owner = connection.execute(
            text(
                "SELECT owner.rolname FROM pg_namespace AS namespace "
                "JOIN pg_roles AS owner ON owner.oid = namespace.nspowner "
                "WHERE namespace.nspname = 'public'"
            )
        ).scalar_one()
        raw_role_rows = connection.execute(
            text(
                "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                "rolreplication, rolinherit, rolbypassrls FROM pg_roles "
                "WHERE rolname = ANY(:roles) ORDER BY rolname"
            ),
            {"roles": [OWNER_ROLE, MIGRATOR_ROLE, *RUNTIME_ROLES]},
        )
        role_rows: list[tuple[str, bool, bool, bool, bool, bool, bool, bool]] = [
            (
                str(row[0]),
                bool(row[1]),
                bool(row[2]),
                bool(row[3]),
                bool(row[4]),
                bool(row[5]),
                bool(row[6]),
                bool(row[7]),
            )
            for row in raw_role_rows
        ]
        migration_setting = connection.execute(
            text(
                "SELECT setting FROM pg_db_role_setting AS settings "
                "JOIN pg_roles AS role ON role.oid = settings.setrole "
                "JOIN LATERAL unnest(settings.setconfig) AS setting ON true "
                "WHERE role.rolname = :role "
                "AND settings.setdatabase = ("
                "SELECT oid FROM pg_database WHERE datname = current_database()"
                ") AND setting = :setting"
            ),
            {"role": MIGRATOR_ROLE, "setting": f"role={OWNER_ROLE}"},
        ).scalar_one()
        membership = connection.execute(
            text(
                "SELECT membership.inherit_option, membership.set_option "
                "FROM pg_auth_members AS membership "
                "JOIN pg_roles AS granted ON granted.oid = membership.roleid "
                "JOIN pg_roles AS member ON member.oid = membership.member "
                "WHERE granted.rolname = :owner AND member.rolname = :migrator"
            ),
            {"owner": OWNER_ROLE, "migrator": MIGRATOR_ROLE},
        ).one()
        verifier_after, valid_until_after = connection.execute(
            text(
                "SELECT rolpassword, rolvaliduntil FROM pg_authid "
                "WHERE rolname = 'kivra_memory_api'"
            )
        ).one()

    assert database_owner == OWNER_ROLE
    assert schema_owner == OWNER_ROLE
    assert object_owners == {"m1_owned_probe": OWNER_ROLE}
    assert migration_setting == f"role={OWNER_ROLE}"
    assert membership == (False, True)
    if not hmac.compare_digest(str(verifier_before), str(verifier_after)):
        pytest.fail("role bootstrap changed an existing password verifier")
    assert valid_until_after == valid_until_before
    assert role_rows == [
        ("kivra_memory_api", True, False, False, False, False, False, False),
        ("kivra_memory_credential_admin", True, False, False, False, False, False, False),
        ("kivra_memory_exporter", True, False, False, False, False, False, False),
        ("kivra_memory_genesis_importer", True, False, False, False, False, False, False),
        ("kivra_memory_ingress", True, False, False, False, False, False, False),
        ("kivra_memory_migrator", True, False, False, False, False, False, False),
        ("kivra_memory_owner", False, False, False, False, False, False, False),
        ("kivra_memory_policy", True, False, False, False, False, False, False),
        ("kivra_memory_purge", True, False, False, False, False, False, False),
        ("kivra_memory_worker", True, False, False, False, False, False, False),
    ]


def test_role_bootstrap_is_safe_before_migrating_an_existing_0004_database(
    postgresql_server: PostgreSQLTestServer,
    alembic_runner: AlembicRunner,
) -> None:
    bootstrap_required_extensions(postgresql_server.database_url)
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)
    alembic_runner.upgrade_as_scalevault_migrator("0004_genesis_import_provenance")

    with alembic_runner.engine.begin() as connection:
        credential_columns = {
            str(column)
            for column in connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'client_credentials'"
                )
            ).scalars()
        }

    assert {
        "actor_id",
        "transport_binding_id",
        "secret_hash_key_id",
        "last_used_at",
    }.isdisjoint(credential_columns)

    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)

    with alembic_runner.engine.begin() as connection:
        assert not connection.execute(
            text(
                "SELECT has_table_privilege('kivra_memory_credential_admin', "
                "'public.client_credentials', 'SELECT,INSERT,UPDATE')"
            )
        ).scalar_one()

    alembic_runner.upgrade_as_scalevault_migrator()
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)

    with alembic_runner.engine.begin() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "0010_ingress_provider_heads"
        )
        assert connection.execute(
            text(
                "SELECT has_column_privilege('kivra_memory_credential_admin', "
                "'public.client_credentials', 'actor_id', 'SELECT')"
            )
        ).scalar_one()
        assert connection.execute(
            text(
                "SELECT has_column_privilege('kivra_memory_api', "
                "'public.client_credentials', 'last_used_at', 'UPDATE')"
            )
        ).scalar_one()


def test_migrations_run_as_nonlogin_owner_and_api_owns_nothing(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        application_owners = set(
            connection.execute(
                text(
                    "SELECT DISTINCT owner.rolname FROM pg_class AS class "
                    "JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace "
                    "JOIN pg_roles AS owner ON owner.oid = class.relowner "
                    "WHERE namespace.nspname = 'public' "
                    "AND class.relkind IN ('r', 'p', 'S') "
                    "AND NOT EXISTS ("
                    "SELECT 1 FROM pg_depend AS dependency "
                    "WHERE dependency.classid = 'pg_class'::regclass "
                    "AND dependency.objid = class.oid AND dependency.deptype = 'e'"
                    ")"
                )
            ).scalars()
        )
        api_owned_objects = connection.execute(
            text(
                "SELECT count(*) FROM pg_class AS class "
                "JOIN pg_roles AS owner ON owner.oid = class.relowner "
                "WHERE owner.rolname = 'kivra_memory_api'"
            )
        ).scalar_one()
        schema_create = {
            role: connection.execute(
                text("SELECT has_schema_privilege(:role, 'public', 'CREATE')"),
                {"role": role},
            ).scalar_one()
            for role in RUNTIME_ROLES
        }

    assert application_owners == {OWNER_ROLE}
    assert api_owned_objects == 0
    assert schema_create == dict.fromkeys(RUNTIME_ROLES, False)


@pytest.mark.parametrize(
    ("role", "table_name", "allowed", "denied"),
    (
        ("kivra_memory_api", "memory_events", "SELECT,INSERT", "UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_api", "memory_event_counter", "SELECT,UPDATE", "INSERT,DELETE"),
        (
            "kivra_memory_api",
            "selection_decisions",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "selection_decision_counter",
            "SELECT,UPDATE",
            "INSERT,DELETE,TRUNCATE",
        ),
        ("kivra_memory_api", "sessions", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        ("kivra_memory_api", "memories", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        ("kivra_memory_api", "memory_links", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        (
            "kivra_memory_api",
            "memory_conflicts",
            "SELECT,INSERT,UPDATE",
            "DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "memory_conflict_members",
            "SELECT,INSERT,UPDATE",
            "DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "memory_evidence",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "selection_decisions",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "selection_decision_counter",
            "SELECT,UPDATE",
            "INSERT,DELETE,TRUNCATE",
        ),
        ("kivra_memory_policy", "memory_events", "SELECT,INSERT", "UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_policy", "memories", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        (
            "kivra_memory_policy",
            "memory_evidence",
            "SELECT,INSERT,UPDATE",
            "DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "memory_links",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "memory_conflicts",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "client_credentials",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_credential_admin",
            "client_credentials",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_credential_admin",
            "memory_events",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_credential_admin",
            "memories",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "memory_content_keys",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "outbox_jobs",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "genesis_import_sources",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "genesis_import_records",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "selection_decisions",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "memory_events",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "memories",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_genesis_importer",
            "memory_evidence",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "genesis_import_sources",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_policy",
            "genesis_import_sources",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_worker",
            "genesis_import_sources",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_ingress",
            "genesis_import_sources",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_exporter",
            "genesis_import_sources",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "memory_content_keys",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "client_credentials",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_api",
            "memory_embeddings_v1",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_worker", "branches", "SELECT,INSERT", "UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_worker", "memory_events", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_worker",
            "selection_decisions",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_worker", "memories", "SELECT,INSERT,UPDATE,DELETE", "TRUNCATE"),
        (
            "kivra_memory_worker",
            "embedding_models",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_worker", "outbox_jobs", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        (
            "kivra_memory_worker",
            "memory_embeddings_v1",
            "SELECT,INSERT,UPDATE,DELETE",
            "TRUNCATE",
        ),
        (
            "kivra_memory_worker",
            "memory_content_keys",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_purge", "memory_events", "SELECT,INSERT", "UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_purge", "memories", "SELECT", "INSERT,DELETE,TRUNCATE"),
        (
            "kivra_memory_purge",
            "memory_content_keys",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_purge",
            "memory_embeddings_v1",
            "DELETE",
            "SELECT,INSERT,UPDATE,TRUNCATE",
        ),
        ("kivra_memory_purge", "outbox_jobs", "SELECT,INSERT", "DELETE,TRUNCATE"),
        (
            "kivra_memory_purge",
            "transport_installations",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_purge",
            "selection_decisions",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_ingress", "ingress_items", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_ingress",
            "ingress_provider_violations",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_ingress",
            "ingress_provider_heads",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_ingress", "memory_events", "", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_ingress",
            "memory_event_counter",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_ingress", "command_receipts", "", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_ingress", "outbox_jobs", "", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_ingress", "memories", "", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_ingress",
            "memory_embeddings_v1",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        ("kivra_memory_exporter", "memory_events", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_exporter",
            "memory_embeddings_v1",
            "",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_exporter",
            "ingress_provider_violations",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_exporter",
            "ingress_provider_heads",
            "SELECT",
            "INSERT,UPDATE,DELETE,TRUNCATE",
        ),
        (
            "kivra_memory_exporter",
            "archive_export_checkpoints",
            "SELECT,INSERT,UPDATE",
            "DELETE,TRUNCATE",
        ),
    ),
)
def test_runtime_table_privilege_matrix(
    role_secured_database: AlembicRunner,
    role: str,
    table_name: str,
    allowed: str,
    denied: str,
) -> None:
    with role_secured_database.engine.begin() as connection:
        if allowed:
            assert connection.execute(
                text("SELECT has_table_privilege(:role, :table_name, :privileges)"),
                {"role": role, "table_name": f"public.{table_name}", "privileges": allowed},
            ).scalar_one()
        assert not connection.execute(
            text("SELECT has_table_privilege(:role, :table_name, :privileges)"),
            {"role": role, "table_name": f"public.{table_name}", "privileges": denied},
        ).scalar_one()


def test_exporter_can_read_exact_recovery_allowlist_and_update_checkpoint_state(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        for table_name in recovery_table_names():
            assert connection.execute(
                text("SELECT has_table_privilege('kivra_memory_exporter', :table_name, 'SELECT')"),
                {"table_name": f"public.{table_name}"},
            ).scalar_one()
        for column in (
            "state",
            "git_commit_sha",
            "remote_git_commit_sha",
            "committed_at",
            "pushed_at",
        ):
            assert connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_exporter', 'public.archive_export_checkpoints', "
                    ":column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        for column in (
            "manifest_sha256",
            "first_event_sequence",
            "last_event_sequence",
            "previous_checkpoint_id",
        ):
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_exporter', 'public.archive_export_checkpoints', "
                    ":column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()


def test_genesis_importer_has_only_terminal_result_update_columns(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        for column in (
            "processing_state",
            "selection_decision_id",
            "event_id",
            "memory_id",
            "processed_at",
        ):
            assert connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_genesis_importer', "
                    "'public.genesis_import_records', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        for column in (
            "source_item_document",
            "nomination_sha256",
            "mapping_metadata",
            "provenance_metadata",
        ):
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_genesis_importer', "
                    "'public.genesis_import_records', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()


def test_content_key_roles_have_only_exact_lifecycle_update_columns(
    role_secured_database: AlembicRunner,
) -> None:
    expected = {
        "kivra_memory_api": {"state", "destruction_requested_at"},
        "kivra_memory_worker": set(),
        "kivra_memory_purge": {
            "state",
            "destroyed_at",
            "destruction_receipt_sha256",
        },
    }
    all_columns = {
        "content_key_id",
        "tenant_id",
        "lineage_id",
        "memory_id",
        "provider_name",
        "provider_key_reference",
        "state",
        "created_at",
        "destruction_requested_at",
        "destroyed_at",
        "destruction_receipt_sha256",
    }
    with role_secured_database.engine.begin() as connection:
        for role, allowed in expected.items():
            for column in all_columns:
                has_update = connection.execute(
                    text(
                        "SELECT has_column_privilege(:role, "
                        "'public.memory_content_keys', :column, 'UPDATE')"
                    ),
                    {"role": role, "column": column},
                ).scalar_one()
                assert bool(has_update) is (column in allowed)


def test_api_can_update_only_credential_last_used_audit() -> None:
    source = ROLE_BOOTSTRAP.read_text(encoding="utf-8")
    expected = (
        "GRANT UPDATE (\n            last_used_at\n        ) ON TABLE public.client_credentials"
    )
    assert expected in source


def test_api_credential_update_grant_is_exact(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        columns = tuple(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'client_credentials'"
                )
            ).scalars()
        )
        for column in columns:
            has_update = connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_api', "
                    "'public.client_credentials', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
            assert bool(has_update) is (column == "last_used_at")


def test_credential_admin_role_has_exact_secret_safe_identity_privileges(
    role_secured_database: AlembicRunner,
) -> None:
    credential_select = {
        "credential_id",
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "kind",
        "public_hint",
        "secret_hash_key_id",
        "created_at",
        "expires_at",
        "last_used_at",
        "revoked_at",
    }
    credential_insert = {
        "credential_id",
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "kind",
        "public_hint",
        "secret_hash",
        "secret_hash_key_id",
        "created_at",
        "expires_at",
    }
    with role_secured_database.engine.begin() as connection:
        columns = tuple(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'client_credentials'"
                )
            ).scalars()
        )
        for column in columns:
            for privilege, expected in (
                ("SELECT", column in credential_select),
                ("INSERT", column in credential_insert),
                ("UPDATE", column == "revoked_at"),
            ):
                assert (
                    bool(
                        connection.execute(
                            text(
                                "SELECT has_column_privilege("
                                "'kivra_memory_credential_admin', "
                                "'public.client_credentials', :column, :privilege)"
                            ),
                            {"column": column, "privilege": privilege},
                        ).scalar_one()
                    )
                    is expected
                )

        assert not connection.execute(
            text(
                "SELECT has_column_privilege('kivra_memory_credential_admin', "
                "'public.client_credentials', 'secret_hash', 'SELECT')"
            )
        ).scalar_one()
        identity_privileges = {
            "actors": {
                "SELECT": {
                    "tenant_id",
                    "actor_id",
                    "handle",
                    "display_name",
                    "kind",
                    "metadata",
                    "revoked_at",
                },
                "INSERT": {
                    "actor_id",
                    "tenant_id",
                    "handle",
                    "display_name",
                    "kind",
                    "metadata",
                    "created_at",
                },
            },
            "clients": {
                "SELECT": {
                    "tenant_id",
                    "client_id",
                    "public_id",
                    "display_name",
                    "kind",
                    "transport_kind",
                    "scopes",
                    "capability_profile",
                    "revoked_at",
                },
                "INSERT": {
                    "client_id",
                    "tenant_id",
                    "public_id",
                    "display_name",
                    "kind",
                    "transport_kind",
                    "scopes",
                    "capability_profile",
                    "created_at",
                },
            },
            "transport_bindings": {
                "SELECT": {
                    "transport_binding_id",
                    "tenant_id",
                    "actor_id",
                    "client_id",
                    "transport_kind",
                    "disclosure_boundary",
                    "installation_id",
                    "authorized_operations",
                    "valid_until",
                },
                "INSERT": {
                    "transport_binding_id",
                    "tenant_id",
                    "actor_id",
                    "client_id",
                    "transport_kind",
                    "disclosure_boundary",
                    "installation_id",
                    "authorized_operations",
                    "created_at",
                    "valid_until",
                },
            },
            "transport_installations": {
                "SELECT": {
                    "installation_id",
                    "tenant_id",
                    "route_key",
                    "capability_profile",
                    "revoked_at",
                },
                "INSERT": {
                    "installation_id",
                    "tenant_id",
                    "route_key",
                    "capability_profile",
                    "enrolled_at",
                    "health_state",
                },
            },
        }
        for table_name, privileges in identity_privileges.items():
            identity_columns = tuple(
                connection.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = :table_name"
                    ),
                    {"table_name": table_name},
                ).scalars()
            )
            for column in identity_columns:
                for privilege in ("SELECT", "INSERT", "UPDATE"):
                    expected = column in privileges.get(privilege, set())
                    assert (
                        bool(
                            connection.execute(
                                text(
                                    "SELECT has_column_privilege("
                                    "'kivra_memory_credential_admin', :table, "
                                    ":column, :privilege)"
                                ),
                                {
                                    "table": f"public.{table_name}",
                                    "column": column,
                                    "privilege": privilege,
                                },
                            ).scalar_one()
                        )
                        is expected
                    )
            assert not connection.execute(
                text(
                    "SELECT has_table_privilege('kivra_memory_credential_admin', "
                    ":table, 'DELETE,TRUNCATE')"
                ),
                {"table": f"public.{table_name}"},
            ).scalar_one()
        for table_name in ("memory_events", "memories", "memory_evidence"):
            assert not connection.execute(
                text(
                    "SELECT has_table_privilege('kivra_memory_credential_admin', "
                    ":table_name, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')"
                ),
                {"table_name": f"public.{table_name}"},
            ).scalar_one()


async def test_credential_admin_role_executes_create_list_rotate_and_revoke(
    postgresql_server: PostgreSQLTestServer,
    role_secured_database: AlembicRunner,
) -> None:
    rows = seed_rows()
    tenant_id = cast(UUID, rows["tenants"][0]["tenant_id"])
    restored_actor_id = new_uuid7()
    restored_client_id = new_uuid7()
    restored_binding_id = new_uuid7()
    restored_other_binding_id = new_uuid7()
    restored_installation_id = new_uuid7()
    restored_at = datetime(2026, 8, 9, 19, tzinfo=UTC)
    with Session(role_secured_database.engine) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            session.flush()
        session.add_all(
            (
                Actor(
                    actor_id=restored_actor_id,
                    tenant_id=tenant_id,
                    handle="chatgpt-restored",
                    display_name="ChatGPT secure tunnel (restored)",
                    kind="agent",
                    metadata_={"provisioning_contract": "scalevault-chatgpt-secure-tunnel-v1"},
                    created_at=restored_at,
                ),
                Client(
                    client_id=restored_client_id,
                    tenant_id=tenant_id,
                    public_id=f"chatgpt-secure-tunnel-restored-{tenant_id}",
                    display_name="ChatGPT secure tunnel (restored)",
                    kind="interactive",
                    transport_kind="secure_tunnel",
                    scopes=["memory.status.transport"],
                    capability_profile={
                        "contract_version": "scalevault-client-capability-v1",
                        "read": None,
                    },
                    created_at=restored_at,
                ),
                TransportInstallation(
                    installation_id=restored_installation_id,
                    tenant_id=tenant_id,
                    route_key=f"chatgpt-restored-{tenant_id}",
                    capability_profile={
                        "association_mode": "single_chatgpt_workspace",
                        "contract_version": "scalevault-secure-tunnel-installation-v1",
                    },
                    enrolled_at=restored_at,
                    health_state="unknown",
                ),
                TransportBinding(
                    transport_binding_id=restored_binding_id,
                    tenant_id=tenant_id,
                    actor_id=restored_actor_id,
                    client_id=restored_client_id,
                    transport_kind="secure_tunnel",
                    disclosure_boundary="openai_secure_tunnel",
                    installation_id=restored_installation_id,
                    authorized_operations={"operations": []},
                    created_at=restored_at,
                ),
                TransportBinding(
                    transport_binding_id=restored_other_binding_id,
                    tenant_id=tenant_id,
                    actor_id=restored_actor_id,
                    client_id=restored_client_id,
                    transport_kind="secure_tunnel",
                    disclosure_boundary="openai_secure_tunnel",
                    installation_id=restored_installation_id,
                    authorized_operations={"operations": []},
                    created_at=restored_at,
                ),
            )
        )
        session.commit()

    password = secrets.token_urlsafe(32)
    _set_role_password(
        postgresql_server,
        "kivra_memory_credential_admin",
        password,
    )
    admin_url = make_url(postgresql_server.database_url).set(
        username="kivra_memory_credential_admin",
        password=password,
    )
    database = Database(admin_url.render_as_string(hide_password=False))
    now = datetime(2026, 8, 9, 20, tzinfo=UTC)
    repository = CredentialAdminStorageRepository(database.session_factory)
    try:
        service = CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now,
        )
        reissue_authorization: str | None = None

        def load_or_create_reissue(proposed: str) -> str:
            nonlocal reissue_authorization
            reissue_authorization = reissue_authorization or proposed
            return reissue_authorization

        reissued, reissue_retry = await asyncio.gather(
            *(
                service.reissue_secure_tunnel(
                    tenant_id=tenant_id,
                    actor_id=restored_actor_id,
                    client_id=restored_client_id,
                    transport_binding_id=restored_binding_id,
                    installation_id=restored_installation_id,
                    authorization_artifact=load_or_create_reissue,
                )
                for _index in range(2)
            )
        )
        assert reissue_retry.credential_id == reissued.credential_id
        with pytest.raises(
            RuntimeError,
            match="credential_repository_rejected_after_secret_output",
        ):
            await service.reissue_secure_tunnel(
                tenant_id=tenant_id,
                actor_id=restored_actor_id,
                client_id=restored_client_id,
                transport_binding_id=restored_other_binding_id,
                installation_id=restored_installation_id,
                authorization_artifact=lambda proposed: proposed,
            )
        with pytest.raises(
            RuntimeError,
            match="credential_repository_rejected_after_secret_output",
        ):
            await service.reissue_secure_tunnel(
                tenant_id=tenant_id,
                actor_id=restored_actor_id,
                client_id=restored_client_id,
                transport_binding_id=restored_binding_id,
                installation_id=restored_installation_id,
                authorization_artifact=lambda proposed: proposed,
            )
        issued = await service.create(
            tenant_id=tenant_id,
            host_label="role-host",
            environment_label="integration",
            scopes=("memory.write.nominate",),
            capability_profile=ClientCapabilityProfile(
                contract_version="scalevault-client-capability-v1",
                read=None,
            ),
        )
        listed = await service.list_metadata(tenant_id=tenant_id)
        assert [row.credential_id for row in listed] == [issued.metadata.credential_id]

        authorization: str | None = None

        def load_or_create(proposed: str) -> str:
            nonlocal authorization
            authorization = authorization or proposed
            return authorization

        secure_installation_id = new_uuid7()
        secure = await service.create_or_load_secure_tunnel(
            tenant_id=tenant_id,
            actor_id=new_uuid7(),
            installation_id=secure_installation_id,
            tunnel_label="role-chatgpt",
            scopes=("memory.status.ingress", "memory.status.transport"),
            capability_profile=ClientCapabilityProfile(
                contract_version="scalevault-client-capability-v1",
                read=None,
            ),
            authorization_artifact=load_or_create,
        )
        retry = await service.create_or_load_secure_tunnel(
            tenant_id=tenant_id,
            actor_id=secure.actor_id,
            installation_id=secure_installation_id,
            tunnel_label="role-chatgpt",
            scopes=secure.scopes,
            capability_profile=secure.capability_profile,
            authorization_artifact=load_or_create,
        )
        assert retry.credential_id == secure.credential_id
        replacement_authorization: str | None = None

        def load_or_create_replacement(proposed: str) -> str:
            nonlocal replacement_authorization
            replacement_authorization = replacement_authorization or proposed
            return replacement_authorization

        secure_rotated = await CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now + timedelta(minutes=1),
        ).rotate_secure_tunnel(
            tenant_id=tenant_id,
            credential_id=secure.credential_id,
            authorization_artifact=load_or_create_replacement,
        )
        secure_rotation_retry = await CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now + timedelta(minutes=2),
        ).rotate_secure_tunnel(
            tenant_id=tenant_id,
            credential_id=secure.credential_id,
            authorization_artifact=load_or_create_replacement,
        )
        assert secure_rotation_retry.credential_id == secure_rotated.credential_id
        secure_revoked = await CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now + timedelta(minutes=3),
        ).revoke(
            tenant_id=tenant_id,
            credential_id=secure_rotated.credential_id,
        )
        assert secure_revoked.revoked_at == now + timedelta(minutes=3)

        rotated = await CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now + timedelta(minutes=1),
        ).rotate(
            tenant_id=tenant_id,
            credential_id=issued.metadata.credential_id,
        )
        revoked = await CredentialAdminService(
            repository,
            token_pepper=bytes(range(32)),
            secret_hash_key_id="role-test-v1",
            now=lambda: now + timedelta(minutes=2),
        ).revoke(
            tenant_id=tenant_id,
            credential_id=rotated.metadata.credential_id,
        )
        assert revoked.revoked_at == now + timedelta(minutes=2)
    finally:
        await database.dispose()


def test_purge_role_has_only_handler_required_table_and_column_privileges(
    role_secured_database: AlembicRunner,
) -> None:
    selectable = {
        "actors",
        "clients",
        "transport_installations",
        "transport_bindings",
        "branches",
        "memory_event_counter",
        "memory_events",
        "memories",
        "memory_content_keys",
        "outbox_jobs",
    }
    insertable = {"memory_events", "outbox_jobs"}
    table_updatable = {"memory_event_counter"}
    deletable = {"memory_embeddings_v1"}
    outbox_update_columns = {
        "state",
        "lease_owner",
        "lease_expires_at",
        "attempt_count",
        "available_at",
        "updated_at",
        "completed_at",
        "last_error_code",
        "last_error_summary",
    }
    memory_update_columns = {
        "revision",
        "content_protection",
        "updated_at",
        "last_event_id",
    }
    with role_secured_database.engine.begin() as connection:
        table_names = tuple(
            connection.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
                )
            ).scalars()
        )
        for table_name in table_names:
            qualified = f"public.{table_name}"
            for privilege, expected in (
                ("SELECT", table_name in selectable),
                ("INSERT", table_name in insertable),
                ("UPDATE", table_name in table_updatable),
                ("DELETE", table_name in deletable),
                ("TRUNCATE", False),
            ):
                actual = connection.execute(
                    text("SELECT has_table_privilege(:role, :table_name, :privilege)"),
                    {
                        "role": "kivra_memory_purge",
                        "table_name": qualified,
                        "privilege": privilege,
                    },
                ).scalar_one()
                assert bool(actual) is expected, (table_name, privilege)

        outbox_columns = tuple(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'outbox_jobs'"
                )
            ).scalars()
        )
        for column in outbox_columns:
            has_update = connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_purge', "
                    "'public.outbox_jobs', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
            assert bool(has_update) is (column in outbox_update_columns)

        memory_columns = tuple(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'memories'"
                )
            ).scalars()
        )
        for column in memory_columns:
            has_update = connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_purge', "
                    "'public.memories', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
            assert bool(has_update) is (column in memory_update_columns)

        embedding_columns = tuple(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = 'memory_embeddings_v1'"
                )
            ).scalars()
        )
        for column in embedding_columns:
            has_select = connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_purge', "
                    "'public.memory_embeddings_v1', :column, 'SELECT')"
                ),
                {"column": column},
            ).scalar_one()
            assert bool(has_select) is (column in {"tenant_id", "memory_id"})


def test_purge_role_can_execute_tenant_scoped_embedding_delete(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        connection.execute(text("SET ROLE kivra_memory_purge"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        result = connection.execute(
            text(
                "DELETE FROM memory_embeddings_v1 "
                "WHERE tenant_id = :tenant_id AND memory_id = :memory_id"
            ),
            {"tenant_id": TENANT_A, "memory_id": TENANT_B},
        )

    assert result.rowcount == 0


def test_ingress_can_only_append_content_free_provider_violation_columns(
    role_secured_database: AlembicRunner,
) -> None:
    insertable = {
        "tenant_id",
        "ingress_id",
        "violation_code",
        "expected_provenance_sha256",
        "observed_provenance_sha256",
    }
    with role_secured_database.engine.begin() as connection:
        for column in (*sorted(insertable), "detected_at"):
            has_insert = connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_ingress', "
                    "'public.ingress_provider_violations', :column, 'INSERT')"
                ),
                {"column": column},
            ).scalar_one()
            assert bool(has_insert) is (column in insertable)
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege('kivra_memory_ingress', "
                    "'public.ingress_provider_violations', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()


def test_other_runtime_roles_have_no_genesis_table_privileges(
    role_secured_database: AlembicRunner,
) -> None:
    genesis_tables = (
        "genesis_import_runs",
        "genesis_import_sources",
        "genesis_import_records",
        "genesis_import_exclusions",
        "genesis_import_supersessions",
        "genesis_import_run_results",
    )
    denied_roles = (
        "kivra_memory_api",
        "kivra_memory_policy",
        "kivra_memory_worker",
        "kivra_memory_purge",
        "kivra_memory_ingress",
    )
    with role_secured_database.engine.begin() as connection:
        for role in denied_roles:
            for table_name in genesis_tables:
                assert not connection.execute(
                    text(
                        "SELECT has_table_privilege(:role, :table_name, "
                        "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')"
                    ),
                    {"role": role, "table_name": f"public.{table_name}"},
                ).scalar_one()


def test_runtime_roles_cannot_create_ddl_disable_guards_or_bypass_rls(
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (tenant_id, slug, display_name) VALUES "
                "(:tenant_a, 'tenant-a', 'Tenant A'), "
                "(:tenant_b, 'tenant-b', 'Tenant B')"
            ),
            {"tenant_a": TENANT_A, "tenant_b": TENANT_B},
        )

    with role_secured_database.engine.begin() as connection:
        connection.execute(text("SET ROLE kivra_memory_api"))
        assert connection.execute(text("SELECT count(*) FROM tenants")).scalar_one() == 0
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        assert connection.execute(text("SELECT tenant_id FROM tenants")).scalar_one() == TENANT_A

    prohibited_statements = (
        "CREATE TABLE public.api_escape (id integer)",
        "ALTER TABLE public.memory_events DISABLE TRIGGER ALL",
        "ALTER TABLE public.tenants DISABLE ROW LEVEL SECURITY",
        "UPDATE public.memory_events SET sequence = sequence",
    )
    for statement in prohibited_statements:
        with (
            pytest.raises(DBAPIError) as prohibited,
            role_secured_database.engine.begin() as connection,
        ):
            connection.execute(text("SET ROLE kivra_memory_api"))
            connection.execute(text(statement))
        assert _sqlstate(prohibited.value) == "42501"

    with (
        pytest.raises(DBAPIError) as rls_bypass,
        role_secured_database.engine.begin() as connection,
    ):
        connection.execute(text("SET ROLE kivra_memory_api"))
        connection.execute(text("SET row_security = off"))
        connection.execute(text("SELECT count(*) FROM tenants"))
    assert _sqlstate(rls_bypass.value) == "42501"


def test_column_grants_keep_ingress_validation_separate_from_api_processing(
    role_secured_database: AlembicRunner,
) -> None:
    ingress_insert_columns = (
        "ingress_id",
        "tenant_id",
        "transport_binding_id",
        "installation_id",
        "actor_id",
        "client_id",
        "provider",
        "repository_external_id",
        "branch_name",
        "immutable_path",
        "external_object_id",
        "commit_id",
        "blob_id",
        "discovered_at",
    )
    ingress_update_columns = (
        "state",
        "declared_idempotency_key",
        "payload_sha256",
        "error_code",
        "safe_diagnostic",
        "validated_at",
        "processed_at",
    )
    api_update_columns = (
        "state",
        "result_event_id",
        "result_memory_id",
        "error_code",
        "safe_diagnostic",
        "processed_at",
    )

    with role_secured_database.engine.begin() as connection:
        for column in ingress_insert_columns:
            assert connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_ingress', 'public.ingress_items', :column, 'INSERT')"
                ),
                {"column": column},
            ).scalar_one()
        for column in ingress_update_columns:
            assert connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_ingress', 'public.ingress_items', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        for column in (
            "state",
            "result_event_id",
            "result_memory_id",
            "declared_idempotency_key",
            "payload_sha256",
        ):
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_ingress', 'public.ingress_items', :column, 'INSERT')"
                ),
                {"column": column},
            ).scalar_one()
        for column in ("result_event_id", "result_memory_id"):
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_ingress', 'public.ingress_items', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        for column in api_update_columns:
            assert connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_api', 'public.ingress_items', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        assert not connection.execute(
            text(
                "SELECT has_column_privilege("
                "'kivra_memory_api', 'public.ingress_items', 'validated_at', 'UPDATE')"
            )
        ).scalar_one()


def test_policy_outbox_updates_are_lease_columns_only(
    role_secured_database: AlembicRunner,
) -> None:
    allowed = {
        "state",
        "lease_owner",
        "lease_expires_at",
        "attempt_count",
        "available_at",
        "updated_at",
        "completed_at",
        "last_error_code",
        "last_error_summary",
    }
    denied = {"job_type", "payload", "deduplication_key", "aggregate_type", "aggregate_id"}
    with role_secured_database.engine.begin() as connection:
        for column in allowed:
            assert connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_policy', 'public.outbox_jobs', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()
        for column in denied:
            assert not connection.execute(
                text(
                    "SELECT has_column_privilege("
                    "'kivra_memory_policy', 'public.outbox_jobs', :column, 'UPDATE')"
                ),
                {"column": column},
            ).scalar_one()


def test_bootstrap_removes_existing_public_grants_and_uses_actual_outbox_sequence(
    postgresql_server: PostgreSQLTestServer,
    role_secured_database: AlembicRunner,
) -> None:
    with role_secured_database.engine.begin() as connection:
        sequence_name = connection.execute(
            text("SELECT pg_get_serial_sequence('public.outbox_jobs', 'job_id')")
        ).scalar_one()
        connection.execute(text("GRANT SELECT ON TABLE public.tenants TO PUBLIC"))
        connection.execute(text(f"GRANT USAGE ON SEQUENCE {sequence_name} TO PUBLIC"))

    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)

    with role_secured_database.engine.begin() as connection:
        assert not connection.execute(
            text("SELECT has_table_privilege('public', 'public.tenants', 'SELECT')")
        ).scalar_one()
        assert not connection.execute(
            text("SELECT has_sequence_privilege('public', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()
        assert connection.execute(
            text("SELECT has_sequence_privilege('kivra_memory_api', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()
        assert connection.execute(
            text("SELECT has_sequence_privilege('kivra_memory_worker', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()
        assert connection.execute(
            text("SELECT has_sequence_privilege('kivra_memory_purge', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()
        assert connection.execute(
            text("SELECT has_sequence_privilege('kivra_memory_policy', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()
        assert not connection.execute(
            text("SELECT has_sequence_privilege('kivra_memory_ingress', :sequence, 'USAGE')"),
            {"sequence": sequence_name},
        ).scalar_one()


def test_migrator_login_uses_database_local_owner_default_without_secret_output(
    postgresql_server: PostgreSQLTestServer,
    role_secured_database: AlembicRunner,
) -> None:
    password = secrets.token_urlsafe(32)
    _set_role_password(postgresql_server, MIGRATOR_ROLE, password)
    run_operator_sql_file(postgresql_server, ROLE_BOOTSTRAP)

    engine = _login_engine(postgresql_server, MIGRATOR_ROLE, password)
    try:
        with engine.begin() as connection:
            session_user, current_user = connection.execute(
                text("SELECT session_user, current_user")
            ).one()
    finally:
        engine.dispose()

    assert session_user == MIGRATOR_ROLE
    assert current_user == OWNER_ROLE


def test_ingress_validation_trigger_and_api_processing_dml(
    role_secured_database: AlembicRunner,
) -> None:
    rows = seed_rows()
    tenant_id = rows["tenants"][0]["tenant_id"]
    actor_id = rows["actors"][1]["actor_id"]
    client_id = rows["clients"][2]["client_id"]
    installation_id = rows["transport_installations"][0]["installation_id"]
    binding_id = rows["transport_bindings"][2]["transport_binding_id"]
    rejected_ingress_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=101)
    quarantined_ingress_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=102)
    processed_ingress_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=103)

    with Session(role_secured_database.engine) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            session.flush()
        session.commit()

    with role_secured_database.engine.begin() as connection:
        connection.execute(text("SET ROLE kivra_memory_ingress"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        for ordinal, ingress_id in enumerate(
            (rejected_ingress_id, quarantined_ingress_id, processed_ingress_id),
            start=1,
        ):
            connection.execute(
                text(
                    "INSERT INTO ingress_items ("
                    "ingress_id, tenant_id, transport_binding_id, installation_id, actor_id, "
                    "client_id, provider, repository_external_id, branch_name, immutable_path, "
                    "external_object_id, commit_id, blob_id) VALUES ("
                    ":ingress_id, :tenant_id, :binding_id, :installation_id, :actor_id, "
                    ":client_id, 'github', 'synthetic/repository', 'main', :immutable_path, "
                    ":external_object_id, :commit_id, :blob_id)"
                ),
                {
                    "ingress_id": ingress_id,
                    "tenant_id": tenant_id,
                    "binding_id": binding_id,
                    "installation_id": installation_id,
                    "actor_id": actor_id,
                    "client_id": client_id,
                    "immutable_path": f"proposals/synthetic-{ordinal}.json",
                    "external_object_id": f"synthetic-object-{ordinal}",
                    "commit_id": f"synthetic-commit-{ordinal}",
                    "blob_id": f"synthetic-blob-{ordinal}",
                },
            )
            connection.execute(
                text(
                    "UPDATE ingress_items SET state = 'validated', "
                    "declared_idempotency_key = :idempotency_key, "
                    "payload_sha256 = :digest, validated_at = CURRENT_TIMESTAMP "
                    "WHERE ingress_id = :ingress_id"
                ),
                {
                    "ingress_id": ingress_id,
                    "idempotency_key": f"synthetic-idempotency-{ordinal}",
                    "digest": bytes(32),
                },
            )
        for ingress_id, terminal_state in (
            (rejected_ingress_id, "rejected"),
            (quarantined_ingress_id, "quarantined"),
        ):
            connection.execute(
                text(
                    "UPDATE ingress_items SET state = :terminal_state, "
                    "error_code = :error_code, processed_at = CURRENT_TIMESTAMP "
                    "WHERE ingress_id = :ingress_id"
                ),
                {
                    "ingress_id": ingress_id,
                    "terminal_state": terminal_state,
                    "error_code": f"synthetic_{terminal_state}",
                },
            )

    with (
        pytest.raises(DBAPIError) as missing_processed_at,
        role_secured_database.engine.begin() as connection,
    ):
        connection.execute(text("SET ROLE kivra_memory_ingress"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        connection.execute(
            text("UPDATE ingress_items SET state = 'rejected' WHERE ingress_id = :ingress_id"),
            {"ingress_id": processed_ingress_id},
        )
    assert _sqlstate(missing_processed_at.value) == "23514"

    with (
        pytest.raises(DBAPIError) as forbidden_acceptance,
        role_secured_database.engine.begin() as connection,
    ):
        connection.execute(text("SET ROLE kivra_memory_ingress"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        connection.execute(
            text("UPDATE ingress_items SET state = 'accepted' WHERE ingress_id = :ingress_id"),
            {"ingress_id": processed_ingress_id},
        )
    assert _sqlstate(forbidden_acceptance.value) == "42501"

    with role_secured_database.engine.begin() as connection:
        connection.execute(text("SET ROLE kivra_memory_api"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        connection.execute(
            text(
                "UPDATE ingress_items SET state = 'conflict', "
                "error_code = 'synthetic_conflict', processed_at = CURRENT_TIMESTAMP "
                "WHERE ingress_id = :ingress_id"
            ),
            {"ingress_id": processed_ingress_id},
        )
        connection.execute(
            text("UPDATE memory_event_counter SET next_sequence = next_sequence + 1")
        )

    with role_secured_database.engine.begin() as connection:
        state_rows = connection.execute(
            text(
                "SELECT ingress_id, state, result_memory_id FROM ingress_items "
                "WHERE ingress_id = ANY(:ingress_ids)"
            ),
            {
                "ingress_ids": [
                    rejected_ingress_id,
                    quarantined_ingress_id,
                    processed_ingress_id,
                ]
            },
        )
        states = {row[0]: (row[1], row[2]) for row in state_rows}
        next_sequence = connection.execute(
            text("SELECT next_sequence FROM memory_event_counter WHERE counter_id = 1")
        ).scalar_one()

    assert states == {
        rejected_ingress_id: ("rejected", None),
        quarantined_ingress_id: ("quarantined", None),
        processed_ingress_id: ("conflict", None),
    }
    assert next_sequence == 2
