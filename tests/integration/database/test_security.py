from __future__ import annotations

from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from .conftest import AlembicRunner

TENANT_A = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835c1")
TENANT_B = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835c2")
ACTOR_A = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835d1")
ACTOR_B = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835d2")
CLIENT_A = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835e1")
BINDING = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835f1")
PERSONA = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283601")
LINEAGE = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283611")
BRANCH = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283621")
SUBJECT = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283631")
EVENT = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283641")
MEMORY = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283651")
CORRELATION = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283661")
API_ROLE = "scalevault_test_api"


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(error.orig, "sqlstate", None)


def _seed_two_tenants(runner: AlembicRunner) -> None:
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (tenant_id, slug, display_name) "
                "VALUES (:tenant_id, :slug, :display_name)"
            ),
            [
                {"tenant_id": TENANT_A, "slug": "tenant-a", "display_name": "Tenant A"},
                {"tenant_id": TENANT_B, "slug": "tenant-b", "display_name": "Tenant B"},
            ],
        )


def _create_runtime_role(runner: AlembicRunner) -> None:
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                f"CREATE ROLE {API_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOINHERIT NOBYPASSRLS"
            )
        )
        connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {API_ROLE}"))
        connection.execute(text(f"GRANT SELECT ON public.alembic_version TO {API_ROLE}"))
        connection.execute(text(f"GRANT SELECT ON public.tenants TO {API_ROLE}"))
        connection.execute(text(f"GRANT INSERT ON public.actors TO {API_ROLE}"))


def _seed_branch_event_graph(runner: AlembicRunner) -> None:
    _seed_two_tenants(runner)
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO actors (actor_id, tenant_id, handle, display_name, kind) "
                "VALUES (:actor, :tenant, 'actor-a', 'Actor A', 'agent')"
            ),
            {"actor": ACTOR_A, "tenant": TENANT_A},
        )
        connection.execute(
            text(
                "INSERT INTO clients "
                "(client_id, tenant_id, public_id, display_name, kind, transport_kind, scopes) "
                "VALUES (:client, :tenant, 'client-a', 'Client A', "
                "'interactive', 'direct_private', ARRAY['memory:write'])"
            ),
            {"client": CLIENT_A, "tenant": TENANT_A},
        )
        connection.execute(
            text(
                "INSERT INTO transport_bindings "
                "(transport_binding_id, tenant_id, actor_id, client_id, transport_kind, "
                "disclosure_boundary, authorized_operations) VALUES "
                "(:binding, :tenant, :actor, :client, "
                "'direct_private', 'private_node', '{}'::jsonb)"
            ),
            {
                "binding": BINDING,
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "client": CLIENT_A,
            },
        )
        connection.execute(
            text(
                "INSERT INTO personas (persona_id, tenant_id, actor_id, slug, display_name) "
                "VALUES (:persona, :tenant, :actor, 'persona-a', 'Persona A')"
            ),
            {"persona": PERSONA, "tenant": TENANT_A, "actor": ACTOR_A},
        )
        connection.execute(
            text(
                "INSERT INTO lineages (lineage_id, tenant_id, persona_id, name) "
                "VALUES (:lineage, :tenant, :persona, 'Lineage A')"
            ),
            {"lineage": LINEAGE, "tenant": TENANT_A, "persona": PERSONA},
        )
        connection.execute(
            text(
                "INSERT INTO branches "
                "(branch_id, tenant_id, lineage_id, name, visibility_ceiling) "
                "VALUES (:branch, :tenant, :lineage, 'Root', 'private_root')"
            ),
            {"branch": BRANCH, "tenant": TENANT_A, "lineage": LINEAGE},
        )
        connection.execute(
            text(
                "INSERT INTO subjects "
                "(subject_id, tenant_id, lineage_id, kind, canonical_key, display_name) "
                "VALUES (:subject, :tenant, :lineage, 'global', 'global', 'Global')"
            ),
            {"subject": SUBJECT, "tenant": TENANT_A, "lineage": LINEAGE},
        )
        connection.execute(
            text(
                "INSERT INTO memory_events "
                "(sequence, event_id, tenant_id, lineage_id, branch_id, actor_id, client_id, "
                "transport_binding_id, operation, memory_id, correlation_id, idempotency_key, "
                "schema_version, payload_version, policy_version, normalization_version, "
                "payload, payload_canonical, payload_sha256, command_sha256) VALUES "
                "(1, :event, :tenant, :lineage, :branch, :actor, :client, :binding, "
                "'remembered', :memory, :correlation, 'fixture:remember:1', 1, 1, 1, 1, "
                "'{}'::jsonb, '{}'::bytea, :digest, :digest)"
            ),
            {
                "event": EVENT,
                "tenant": TENANT_A,
                "lineage": LINEAGE,
                "branch": BRANCH,
                "actor": ACTOR_A,
                "client": CLIENT_A,
                "binding": BINDING,
                "memory": MEMORY,
                "correlation": CORRELATION,
                "digest": bytes(32),
            },
        )


def _insert_memory(runner: AlembicRunner, visibility: str) -> None:
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO memories "
                "(memory_id, tenant_id, lineage_id, branch_id, subject_id, subject_kind, "
                "revision, category, ontological_status, scope, visibility, status, statement, "
                "reason_to_remember, interpretation_limits, confidence, salience, durability, "
                "sensitivity, authority_class, created_at, updated_at, normalized_fingerprint, "
                "fingerprint_version, metadata, last_event_id) VALUES "
                "(:memory, :tenant, :lineage, :branch, :subject, 'global', 1, 'stable_fact', "
                "'literal_technical_fact', 'global', :visibility, 'active', 'Synthetic fact', "
                "'Structural database fixture', '[]'::jsonb, 0.9, 0.5, 0.8, 1, "
                "'verified_project_source', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, :digest, 1, "
                "'{}'::jsonb, :event)"
            ),
            {
                "memory": MEMORY,
                "tenant": TENANT_A,
                "lineage": LINEAGE,
                "branch": BRANCH,
                "subject": SUBJECT,
                "visibility": visibility,
                "digest": bytes(32),
                "event": EVENT,
            },
        )


def test_runtime_role_is_non_owner_and_rls_is_enforced(
    migrated_database: AlembicRunner,
) -> None:
    _seed_two_tenants(migrated_database)
    _create_runtime_role(migrated_database)

    with migrated_database.engine.begin() as connection:
        role_flags = connection.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                "FROM pg_roles WHERE rolname = :role"
            ),
            {"role": API_ROLE},
        ).one()
        can_read_revision = connection.execute(
            text("SELECT has_table_privilege(:role, 'public.alembic_version', 'SELECT')"),
            {"role": API_ROLE},
        ).scalar_one()
        can_create = connection.execute(
            text("SELECT has_schema_privilege(:role, 'public', 'CREATE')"),
            {"role": API_ROLE},
        ).scalar_one()

        connection.execute(text(f"SET ROLE {API_ROLE}"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        visible_tenants = connection.execute(
            text("SELECT tenant_id FROM tenants ORDER BY tenant_id")
        ).scalars()
        assert list(visible_tenants) == [TENANT_A]

    assert role_flags == (False, False, False, False)
    assert can_read_revision is True
    assert can_create is False


def test_runtime_role_cannot_cross_tenants_or_mutate_schema_and_events(
    migrated_database: AlembicRunner,
) -> None:
    _seed_two_tenants(migrated_database)
    _create_runtime_role(migrated_database)

    with (
        pytest.raises(DBAPIError) as cross_tenant,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(text(f"SET ROLE {API_ROLE}"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        connection.execute(
            text(
                "INSERT INTO actors "
                "(actor_id, tenant_id, handle, display_name, kind) "
                "VALUES (:actor_id, :tenant_id, 'foreign', 'Foreign', 'agent')"
            ),
            {"actor_id": ACTOR_B, "tenant_id": TENANT_B},
        )
    assert _sqlstate(cross_tenant.value) == "42501"

    prohibited_statements = (
        "CREATE TABLE public.api_escape (id integer)",
        "UPDATE public.memory_events SET idempotency_key = idempotency_key",
        "DELETE FROM public.memory_events",
        "TRUNCATE public.memory_events",
    )
    for statement in prohibited_statements:
        with (
            pytest.raises(DBAPIError) as prohibited,
            migrated_database.engine.begin() as connection,
        ):
            connection.execute(text(f"SET ROLE {API_ROLE}"))
            connection.execute(text(statement))
        assert _sqlstate(prohibited.value) in {"42501", "55000"}


def test_uuid_and_cross_tenant_foreign_key_constraints_reject_invalid_rows(
    migrated_database: AlembicRunner,
) -> None:
    _seed_two_tenants(migrated_database)

    with (
        pytest.raises(DBAPIError) as invalid_uuid,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO tenants (tenant_id, slug, display_name) "
                "VALUES ('123e4567-e89b-42d3-a456-426614174000', 'uuid4', 'UUID4')"
            )
        )
    assert _sqlstate(invalid_uuid.value) == "23514"

    with migrated_database.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO actors (actor_id, tenant_id, handle, display_name, kind) VALUES "
                "(:actor_a, :tenant_a, 'actor-a', 'Actor A', 'agent'), "
                "(:actor_b, :tenant_b, 'actor-b', 'Actor B', 'agent')"
            ),
            {
                "actor_a": ACTOR_A,
                "tenant_a": TENANT_A,
                "actor_b": ACTOR_B,
                "tenant_b": TENANT_B,
            },
        )
        connection.execute(
            text(
                "INSERT INTO clients "
                "(client_id, tenant_id, public_id, display_name, kind, transport_kind, scopes) "
                "VALUES (:client_id, :tenant_id, 'client-a', 'Client A', "
                "'interactive', 'direct_private', ARRAY['memory:write'])"
            ),
            {"client_id": CLIENT_A, "tenant_id": TENANT_A},
        )

    with (
        pytest.raises(DBAPIError) as cross_tenant_fk,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO transport_bindings "
                "(transport_binding_id, tenant_id, actor_id, client_id, transport_kind, "
                "disclosure_boundary, authorized_operations) VALUES "
                "(:binding, :tenant, :foreign_actor, :client, "
                "'direct_private', 'private_node', '{}'::jsonb)"
            ),
            {
                "binding": BINDING,
                "tenant": TENANT_A,
                "foreign_actor": ACTOR_B,
                "client": CLIENT_A,
            },
        )
    assert _sqlstate(cross_tenant_fk.value) == "23503"


def test_database_barriers_reject_visibility_and_immutable_attacks(
    migrated_database: AlembicRunner,
) -> None:
    _seed_branch_event_graph(migrated_database)

    with pytest.raises(DBAPIError) as visibility_attack:
        _insert_memory(migrated_database, "restricted")
    assert _sqlstate(visibility_attack.value) == "23514"

    _insert_memory(migrated_database, "private_root")

    prohibited_statements = (
        "UPDATE branches SET visibility_ceiling = 'restricted' WHERE branch_id = :branch",
        "UPDATE subjects SET lineage_id = :other_lineage WHERE subject_id = :subject",
        "UPDATE transport_bindings SET valid_until = CURRENT_TIMESTAMP WHERE "
        "transport_binding_id = :binding",
        "DELETE FROM memory_events WHERE event_id = :event",
        "TRUNCATE command_receipts",
    )
    parameters = {
        "branch": BRANCH,
        "other_lineage": UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836f1"),
        "subject": SUBJECT,
        "binding": BINDING,
        "event": EVENT,
    }
    for statement in prohibited_statements:
        with (
            pytest.raises(DBAPIError) as immutable_attack,
            migrated_database.engine.begin() as connection,
        ):
            connection.execute(text(statement), parameters)
        assert _sqlstate(immutable_attack.value) == "55000"

    with migrated_database.engine.begin() as connection:
        connection.execute(
            text("UPDATE branches SET sealed_at = CURRENT_TIMESTAMP WHERE branch_id = :branch"),
            {"branch": BRANCH},
        )
        connection.execute(
            text("UPDATE subjects SET display_name = 'Renamed' WHERE subject_id = :subject"),
            {"subject": SUBJECT},
        )
