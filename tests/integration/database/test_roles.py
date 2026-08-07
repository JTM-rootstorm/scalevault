from __future__ import annotations

import hmac
import secrets
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest
from kivra_memory.domain.identifiers import new_uuid7
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
    "kivra_memory_api",
    "kivra_memory_worker",
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
        ("kivra_memory_exporter", True, False, False, False, False, False, False),
        ("kivra_memory_ingress", True, False, False, False, False, False, False),
        ("kivra_memory_migrator", True, False, False, False, False, False, False),
        ("kivra_memory_owner", False, False, False, False, False, False, False),
        ("kivra_memory_worker", True, False, False, False, False, False, False),
    ]


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
        ("kivra_memory_api", "sessions", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        ("kivra_memory_api", "memories", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_worker", "branches", "SELECT,INSERT", "UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_worker", "memory_events", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        ("kivra_memory_worker", "memories", "SELECT,INSERT,UPDATE,DELETE", "TRUNCATE"),
        ("kivra_memory_worker", "outbox_jobs", "SELECT,INSERT,UPDATE", "DELETE,TRUNCATE"),
        ("kivra_memory_ingress", "ingress_items", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
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
        ("kivra_memory_exporter", "memory_events", "SELECT", "INSERT,UPDATE,DELETE,TRUNCATE"),
        (
            "kivra_memory_exporter",
            "archive_export_checkpoints",
            "SELECT,INSERT",
            "UPDATE,DELETE,TRUNCATE",
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
        "declared_idempotency_key",
        "payload_sha256",
    )
    ingress_update_columns = (
        "state",
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
        for column in ("state", "result_event_id", "result_memory_id"):
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
                    "external_object_id, commit_id, blob_id, declared_idempotency_key, "
                    "payload_sha256) VALUES ("
                    ":ingress_id, :tenant_id, :binding_id, :installation_id, :actor_id, "
                    ":client_id, 'github', 'synthetic/repository', 'main', :immutable_path, "
                    ":external_object_id, :commit_id, :blob_id, :idempotency_key, :digest)"
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
                    "idempotency_key": f"synthetic-idempotency-{ordinal}",
                    "digest": bytes(32),
                },
            )
            connection.execute(
                text(
                    "UPDATE ingress_items SET state = 'validated', "
                    "validated_at = CURRENT_TIMESTAMP WHERE ingress_id = :ingress_id"
                ),
                {"ingress_id": ingress_id},
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
