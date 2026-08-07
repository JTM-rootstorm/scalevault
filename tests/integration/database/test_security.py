from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from kivra_memory.domain.enums import EventOperation, MemoryVisibility
from kivra_memory.domain.events import BranchCreatedPayload, BranchState, event_hash_fields
from sqlalchemy import text
from sqlalchemy.engine import Connection
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
DIFFERENT_MEMORY = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283652")
CORRELATION = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283661")
SESSION_A = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283671")
SESSION_B = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283681")
SCENE_SUBJECT = UUID("01936d5a-8c4e-7b12-ae6c-4a41a2283691")
INSTALLATION = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836a1")
ALTERNATE_INSTALLATION = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836a2")
GITHUB_CLIENT = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836b1")
GITHUB_BINDING = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836c1")
ALTERNATE_GITHUB_BINDING = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836c2")
INGRESS = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836d1")
MISMATCHED_INSTALLATION_INGRESS = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836d2")
ATTACK_INGRESS = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836d3")
ATTACK_EVENT = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836e1")
ATTACK_EVENT_TWO = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836e2")
ATTACK_BINDING = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836f1")
EXPIRED_BINDING = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22836f2")
CREATED_AT = datetime(2026, 8, 3, 20, 0, 0, tzinfo=UTC)
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


def _grant_ingress_runtime_privileges(runner: AlembicRunner) -> None:
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                f"GRANT SELECT ON public.actors, public.clients, public.transport_installations, "
                f"public.transport_bindings, public.ingress_items, public.memory_events "
                f"TO {API_ROLE}"
            )
        )
        connection.execute(text(f"GRANT INSERT ON public.memory_events TO {API_ROLE}"))
        connection.execute(text(f"GRANT UPDATE ON public.ingress_items TO {API_ROLE}"))


def _insert_branch_event(
    connection: Connection,
    *,
    sequence: int,
    event_id: UUID,
    client_id: UUID,
    binding_id: UUID,
    ingress_id: UUID | None = None,
    idempotency_key: str,
    operation: EventOperation = EventOperation.BRANCH_CREATED,
    memory_id: UUID | None = None,
    payload_override: dict[str, object] | None = None,
    canonical_override: bytes | None = None,
    payload_sha256_override: bytes | None = None,
) -> None:
    branch = BranchState(
        branch_id=BRANCH,
        tenant_id=TENANT_A,
        lineage_id=LINEAGE,
        parent_branch_id=None,
        fork_event_sequence=None,
        name="Root",
        visibility_ceiling=MemoryVisibility.PRIVATE_ROOT,
        created_at=CREATED_AT,
        sealed_at=None,
    )
    payload, canonical, payload_sha256, command_sha256 = event_hash_fields(
        operation=operation,
        payload=BranchCreatedPayload(branch=branch),
        tenant_id=TENANT_A,
        lineage_id=LINEAGE,
        branch_id=BRANCH,
        actor_id=ACTOR_A,
        client_id=client_id,
        memory_id=memory_id,
        expected_revision=None,
        causation_event_id=None,
    )
    connection.execute(
        text(
            "INSERT INTO memory_events "
            "(sequence, event_id, tenant_id, lineage_id, branch_id, actor_id, client_id, "
            "transport_binding_id, ingress_id, operation, memory_id, correlation_id, "
            "idempotency_key, schema_version, payload_version, policy_version, "
            "normalization_version, payload, payload_canonical, payload_sha256, command_sha256, "
            "created_at) VALUES "
            "(:sequence, :event, :tenant, :lineage, :branch, :actor, :client, :binding, "
            ":ingress, :operation, :memory, :correlation, :idempotency_key, 1, 1, 1, 1, "
            "CAST(:payload AS jsonb), :canonical, :payload_sha256, :command_sha256, :created_at)"
        ),
        {
            "sequence": sequence,
            "event": event_id,
            "tenant": TENANT_A,
            "lineage": LINEAGE,
            "branch": BRANCH,
            "actor": ACTOR_A,
            "client": client_id,
            "binding": binding_id,
            "ingress": ingress_id,
            "operation": operation.value,
            "memory": memory_id,
            "correlation": CORRELATION,
            "idempotency_key": idempotency_key,
            "payload": json.dumps(
                payload_override if payload_override is not None else payload,
                separators=(",", ":"),
                sort_keys=True,
            ),
            "canonical": (
                canonical_override
                if canonical_override is not None
                else base64.b64decode(canonical, validate=True)
            ),
            "payload_sha256": (
                payload_sha256_override
                or (
                    hashlib.sha256(canonical_override).digest()
                    if canonical_override is not None
                    else bytes.fromhex(payload_sha256)
                )
            ),
            "command_sha256": bytes.fromhex(command_sha256),
            "created_at": CREATED_AT,
        },
    )


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
                "'direct_private', 'private_node', "
                '\'{"operations":["branch_created"]}\'::jsonb)'
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
                "(branch_id, tenant_id, lineage_id, name, visibility_ceiling, created_at) "
                "VALUES (:branch, :tenant, :lineage, 'Root', 'private_root', :created_at)"
            ),
            {
                "branch": BRANCH,
                "tenant": TENANT_A,
                "lineage": LINEAGE,
                "created_at": CREATED_AT,
            },
        )
        connection.execute(
            text(
                "INSERT INTO sessions "
                "(session_id, tenant_id, actor_id, client_id, lineage_id, branch_id, "
                "transport_binding_id, content_mode) VALUES "
                "(:session_a, :tenant, :actor, :client, :lineage, :branch, :binding, "
                "'technical'), "
                "(:session_b, :tenant, :actor, :client, :lineage, :branch, :binding, "
                "'technical')"
            ),
            {
                "session_a": SESSION_A,
                "session_b": SESSION_B,
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "client": CLIENT_A,
                "lineage": LINEAGE,
                "branch": BRANCH,
                "binding": BINDING,
            },
        )
        connection.execute(
            text(
                "INSERT INTO subjects "
                "(subject_id, tenant_id, lineage_id, kind, canonical_key, display_name, "
                "origin_session_id) VALUES "
                "(:subject, :tenant, :lineage, 'global', 'global', 'Global', NULL), "
                "(:scene_subject, :tenant, :lineage, 'scene', 'scene-a', 'Scene A', :session_a)"
            ),
            {
                "subject": SUBJECT,
                "scene_subject": SCENE_SUBJECT,
                "tenant": TENANT_A,
                "lineage": LINEAGE,
                "session_a": SESSION_A,
            },
        )
        _insert_branch_event(
            connection,
            sequence=1,
            event_id=EVENT,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="fixture:branch:1",
        )


def _seed_github_ingress_graph(runner: AlembicRunner) -> None:
    _seed_branch_event_graph(runner)
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO transport_installations "
                "(installation_id, tenant_id, route_key) VALUES "
                "(:installation, :tenant, 'github-primary'), "
                "(:alternate_installation, :tenant, 'github-alternate')"
            ),
            {
                "installation": INSTALLATION,
                "alternate_installation": ALTERNATE_INSTALLATION,
                "tenant": TENANT_A,
            },
        )
        connection.execute(
            text(
                "INSERT INTO clients "
                "(client_id, tenant_id, public_id, display_name, kind, transport_kind, scopes) "
                "VALUES (:client, :tenant, 'github-client', 'GitHub Client', "
                "'ingress', 'github_ingress', ARRAY['memory:write'])"
            ),
            {"client": GITHUB_CLIENT, "tenant": TENANT_A},
        )
        connection.execute(
            text(
                "INSERT INTO transport_bindings "
                "(transport_binding_id, tenant_id, actor_id, client_id, transport_kind, "
                "disclosure_boundary, installation_id, authorized_operations) VALUES "
                "(:binding, :tenant, :actor, :client, 'github_ingress', 'github_com', "
                ':installation, \'{"operations":["observed","remembered"]}\'::jsonb), '
                "(:alternate_binding, :tenant, :actor, :client, 'github_ingress', 'github_com', "
                ':installation, \'{"operations":["observed","remembered"]}\'::jsonb)'
            ),
            {
                "binding": GITHUB_BINDING,
                "alternate_binding": ALTERNATE_GITHUB_BINDING,
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "client": GITHUB_CLIENT,
                "installation": INSTALLATION,
            },
        )
        connection.execute(
            text(
                "INSERT INTO ingress_items "
                "(ingress_id, tenant_id, transport_binding_id, installation_id, actor_id, "
                "client_id, provider, repository_external_id, branch_name, immutable_path, "
                "external_object_id, commit_id, blob_id, declared_idempotency_key, "
                "payload_sha256) VALUES "
                "(:ingress, :tenant, :binding, :installation, :actor, :client, 'github', "
                "'repo-1', 'main', 'ingress/one.json', 'object-1', 'commit-1', 'blob-1', "
                "'ingress:one', :digest), "
                "(:mismatched_ingress, :tenant, :binding, :alternate_installation, :actor, "
                ":client, 'github', 'repo-1', 'main', 'ingress/two.json', 'object-2', "
                "'commit-2', 'blob-2', 'ingress:two', :digest)"
            ),
            {
                "ingress": INGRESS,
                "mismatched_ingress": MISMATCHED_INSTALLATION_INGRESS,
                "tenant": TENANT_A,
                "binding": GITHUB_BINDING,
                "installation": INSTALLATION,
                "alternate_installation": ALTERNATE_INSTALLATION,
                "actor": ACTOR_A,
                "client": GITHUB_CLIENT,
                "digest": bytes(32),
            },
        )


def _validate_ingress(connection: Connection, ingress_id: UUID) -> None:
    connection.execute(
        text(
            "UPDATE ingress_items SET state = 'validated', validated_at = CURRENT_TIMESTAMP "
            "WHERE ingress_id = :ingress"
        ),
        {"ingress": ingress_id},
    )


def _accept_ingress(
    connection: Connection,
    ingress_id: UUID,
    event_id: UUID,
    memory_id: UUID,
) -> None:
    connection.execute(
        text(
            "UPDATE ingress_items SET state = 'accepted', result_event_id = :event, "
            "result_memory_id = :memory, processed_at = CURRENT_TIMESTAMP "
            "WHERE ingress_id = :ingress"
        ),
        {"event": event_id, "memory": memory_id, "ingress": ingress_id},
    )


def _insert_memory(
    runner: AlembicRunner,
    visibility: str,
    *,
    category: str = "stable_fact",
    ontological_status: str = "literal_technical_fact",
    scope: str = "global",
    subject_id: UUID = SUBJECT,
    subject_kind: str = "global",
    origin_session_id: UUID | None = None,
) -> None:
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO memories "
                "(memory_id, tenant_id, lineage_id, branch_id, subject_id, subject_kind, "
                "origin_session_id, revision, category, ontological_status, scope, visibility, "
                "status, statement, reason_to_remember, interpretation_limits, confidence, "
                "salience, durability, sensitivity, authority_class, created_at, updated_at, "
                "normalized_fingerprint, fingerprint_version, metadata, last_event_id) VALUES "
                "(:memory, :tenant, :lineage, :branch, :subject, :subject_kind, :origin_session, "
                "1, :category, :ontological_status, :scope, :visibility, 'active', "
                "'Synthetic fact', "
                "'Structural database fixture', '[]'::jsonb, 0.9, 0.5, 0.8, 1, "
                "'verified_project_source', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, :digest, 1, "
                "'{}'::jsonb, :event)"
            ),
            {
                "memory": MEMORY,
                "tenant": TENANT_A,
                "lineage": LINEAGE,
                "branch": BRANCH,
                "subject": subject_id,
                "subject_kind": subject_kind,
                "origin_session": origin_session_id,
                "category": category,
                "ontological_status": ontological_status,
                "scope": scope,
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


def test_runtime_role_fails_closed_without_tenant_context(
    migrated_database: AlembicRunner,
) -> None:
    _seed_two_tenants(migrated_database)
    _create_runtime_role(migrated_database)

    with (
        pytest.raises(DBAPIError) as unset_tenant,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(text(f"SET ROLE {API_ROLE}"))
        connection.execute(
            text(
                "INSERT INTO actors (actor_id, tenant_id, handle, display_name, kind) "
                "VALUES (:actor, :tenant, 'unset-tenant', 'Unset Tenant', 'agent')"
            ),
            {"actor": ACTOR_A, "tenant": TENANT_A},
        )
    assert _sqlstate(unset_tenant.value) == "42501"


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


def test_database_rejects_invalid_ontology_scope_and_subject_session(
    migrated_database: AlembicRunner,
) -> None:
    _seed_branch_event_graph(migrated_database)

    with pytest.raises(DBAPIError) as invalid_ontology:
        _insert_memory(
            migrated_database,
            "private_root",
            category="stable_fact",
            ontological_status="hypothesis",
        )
    assert _sqlstate(invalid_ontology.value) == "23514"

    with pytest.raises(DBAPIError) as invalid_scope:
        _insert_memory(
            migrated_database,
            "private_root",
            scope="global",
            subject_id=SCENE_SUBJECT,
            subject_kind="scene",
            origin_session_id=SESSION_A,
        )
    assert _sqlstate(invalid_scope.value) == "23514"

    with pytest.raises(DBAPIError) as mismatched_session:
        _insert_memory(
            migrated_database,
            "private_root",
            scope="scene_local",
            subject_id=SCENE_SUBJECT,
            subject_kind="scene",
            origin_session_id=SESSION_B,
        )
    assert _sqlstate(mismatched_session.value) == "23503"

    _insert_memory(
        migrated_database,
        "private_root",
        scope="scene_local",
        subject_id=SCENE_SUBJECT,
        subject_kind="scene",
        origin_session_id=SESSION_A,
    )


def test_database_rejects_invalid_transport_and_event_ingress_provenance(
    migrated_database: AlembicRunner,
) -> None:
    _seed_github_ingress_graph(migrated_database)
    with migrated_database.engine.begin() as connection:
        _validate_ingress(connection, INGRESS)
        _validate_ingress(connection, MISMATCHED_INSTALLATION_INGRESS)

    with (
        pytest.raises(DBAPIError) as invalid_disclosure,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO transport_bindings "
                "(transport_binding_id, tenant_id, actor_id, client_id, transport_kind, "
                "disclosure_boundary, authorized_operations) VALUES "
                "(:binding, :tenant, :actor, :client, 'direct_private', 'public_relay', "
                "'{}'::jsonb)"
            ),
            {
                "binding": ATTACK_BINDING,
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "client": CLIENT_A,
            },
        )
    assert _sqlstate(invalid_disclosure.value) == "23514"

    attacks = (
        (GITHUB_CLIENT, GITHUB_BINDING, None, "github-without-ingress"),
        (CLIENT_A, BINDING, INGRESS, "direct-with-ingress"),
        (GITHUB_CLIENT, ALTERNATE_GITHUB_BINDING, INGRESS, "binding-mismatch"),
        (
            GITHUB_CLIENT,
            GITHUB_BINDING,
            MISMATCHED_INSTALLATION_INGRESS,
            "installation-mismatch",
        ),
    )
    for client_id, binding_id, ingress_id, idempotency_key in attacks:
        with (
            pytest.raises(DBAPIError) as invalid_provenance,
            migrated_database.engine.begin() as connection,
        ):
            _insert_branch_event(
                connection,
                sequence=2,
                event_id=ATTACK_EVENT,
                client_id=client_id,
                binding_id=binding_id,
                ingress_id=ingress_id,
                idempotency_key=idempotency_key,
                operation=EventOperation.REMEMBERED,
                memory_id=MEMORY,
            )
        assert _sqlstate(invalid_provenance.value) == "23514"

    with migrated_database.engine.begin() as connection:
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=GITHUB_CLIENT,
            binding_id=GITHUB_BINDING,
            ingress_id=INGRESS,
            idempotency_key="ingress:one",
            operation=EventOperation.REMEMBERED,
            memory_id=MEMORY,
        )
        _accept_ingress(connection, INGRESS, ATTACK_EVENT, MEMORY)

    with migrated_database.engine.begin() as connection:
        _validate_ingress(connection, MISMATCHED_INSTALLATION_INGRESS)
    with (
        pytest.raises(DBAPIError) as invalid_duplicate,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE ingress_items SET state = 'duplicate', result_event_id = :event, "
                "result_memory_id = :memory, processed_at = CURRENT_TIMESTAMP "
                "WHERE ingress_id = :ingress"
            ),
            {
                "event": ATTACK_EVENT,
                "memory": DIFFERENT_MEMORY,
                "ingress": MISMATCHED_INSTALLATION_INGRESS,
            },
        )
    assert _sqlstate(invalid_duplicate.value) == "23514"


def test_database_rejects_payload_hash_mismatch(migrated_database: AlembicRunner) -> None:
    _seed_branch_event_graph(migrated_database)

    with (
        pytest.raises(DBAPIError) as invalid_hash,
        migrated_database.engine.begin() as connection,
    ):
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="invalid-payload-hash",
            payload_sha256_override=bytes(32),
        )
    assert _sqlstate(invalid_hash.value) == "23514"


@pytest.mark.parametrize(
    ("payload", "canonical"),
    (
        ({"value": 1}, b'{"value":2}'),
        ({"value": 1}, b'{"value":'),
        ({"value": 1}, b'\xff{"value":1}'),
    ),
    ids=("semantic-mismatch", "invalid-json", "invalid-utf8"),
)
def test_database_rejects_invalid_canonical_payload_bytes_without_echoing_content(
    migrated_database: AlembicRunner,
    payload: dict[str, object],
    canonical: bytes,
) -> None:
    _seed_branch_event_graph(migrated_database)

    with (
        pytest.raises(DBAPIError) as invalid_payload,
        migrated_database.engine.begin() as connection,
    ):
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="invalid-canonical-payload",
            payload_override=payload,
            canonical_override=canonical,
        )
    assert _sqlstate(invalid_payload.value) == "23514"
    assert "value" not in str(invalid_payload.value)


def test_database_accepts_semantically_equal_json_payload_bytes(
    migrated_database: AlembicRunner,
) -> None:
    _seed_branch_event_graph(migrated_database)

    with migrated_database.engine.begin() as connection:
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="semantic-payload-equality",
            payload_override={"a": 1, "b": 2},
            canonical_override=b'{ "b": 2, "a": 1 }',
        )


def test_ingress_lifecycle_and_provenance_fields_fail_closed(
    migrated_database: AlembicRunner,
) -> None:
    _seed_github_ingress_graph(migrated_database)

    with (
        pytest.raises(DBAPIError) as non_discovered_insert,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO ingress_items "
                "(ingress_id, tenant_id, transport_binding_id, installation_id, actor_id, "
                "client_id, provider, repository_external_id, branch_name, immutable_path, "
                "external_object_id, commit_id, blob_id, declared_idempotency_key, "
                "payload_sha256, state, validated_at) VALUES "
                "(:ingress, :tenant, :binding, :installation, :actor, :client, 'github', "
                "'repo-1', 'main', 'ingress/attack.json', 'object-attack', 'commit-attack', "
                "'blob-attack', 'ingress:attack', :digest, 'validated', CURRENT_TIMESTAMP)"
            ),
            {
                "ingress": ATTACK_INGRESS,
                "tenant": TENANT_A,
                "binding": GITHUB_BINDING,
                "installation": INSTALLATION,
                "actor": ACTOR_A,
                "client": GITHUB_CLIENT,
                "digest": bytes(32),
            },
        )
    assert _sqlstate(non_discovered_insert.value) == "23514"

    with (
        pytest.raises(DBAPIError) as skipped_validation,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE ingress_items SET state = 'accepted', result_event_id = :event, "
                "result_memory_id = :memory, validated_at = CURRENT_TIMESTAMP, "
                "processed_at = CURRENT_TIMESTAMP WHERE ingress_id = :ingress"
            ),
            {"event": EVENT, "memory": MEMORY, "ingress": INGRESS},
        )
    assert _sqlstate(skipped_validation.value) == "23514"

    with (
        pytest.raises(DBAPIError) as provenance_mutation,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE ingress_items SET immutable_path = 'ingress/changed.json', "
                "state = 'validated', validated_at = CURRENT_TIMESTAMP "
                "WHERE ingress_id = :ingress"
            ),
            {"ingress": INGRESS},
        )
    assert _sqlstate(provenance_mutation.value) == "55000"

    with migrated_database.engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE ingress_items SET state = 'rejected', error_code = 'invalid_proposal', "
                "processed_at = CURRENT_TIMESTAMP WHERE ingress_id = :ingress"
            ),
            {"ingress": MISMATCHED_INSTALLATION_INGRESS},
        )

    with (
        pytest.raises(DBAPIError) as terminal_mutation,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE ingress_items SET state = 'quarantined', error_code = 'late_change' "
                "WHERE ingress_id = :ingress"
            ),
            {"ingress": MISMATCHED_INSTALLATION_INGRESS},
        )
    assert _sqlstate(terminal_mutation.value) == "23514"


def test_ingress_result_reciprocity_is_deferred_and_enforced(
    migrated_database: AlembicRunner,
) -> None:
    _seed_github_ingress_graph(migrated_database)
    with migrated_database.engine.begin() as connection:
        _validate_ingress(connection, INGRESS)

    with (
        pytest.raises(DBAPIError) as mismatched_result,
        migrated_database.engine.begin() as connection,
    ):
        _accept_ingress(connection, INGRESS, EVENT, MEMORY)
    assert _sqlstate(mismatched_result.value) == "23514"

    with migrated_database.engine.begin() as connection:
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=GITHUB_CLIENT,
            binding_id=GITHUB_BINDING,
            ingress_id=INGRESS,
            idempotency_key="ingress:one",
            operation=EventOperation.REMEMBERED,
            memory_id=MEMORY,
        )
        _accept_ingress(connection, INGRESS, ATTACK_EVENT, MEMORY)


def test_ingress_event_barrier_honors_binding_authorization_and_revocation(
    migrated_database: AlembicRunner,
) -> None:
    _seed_github_ingress_graph(migrated_database)

    attacks = (
        (
            "UPDATE actors SET revoked_at = CURRENT_TIMESTAMP WHERE actor_id = :target",
            ACTOR_A,
            EventOperation.BRANCH_CREATED,
            CLIENT_A,
            BINDING,
            None,
            "revoked-actor",
        ),
        (
            "UPDATE clients SET revoked_at = CURRENT_TIMESTAMP WHERE client_id = :target",
            CLIENT_A,
            EventOperation.BRANCH_CREATED,
            CLIENT_A,
            BINDING,
            None,
            "revoked-client",
        ),
        (
            "UPDATE transport_installations SET revoked_at = CURRENT_TIMESTAMP "
            "WHERE installation_id = :target",
            INSTALLATION,
            EventOperation.REMEMBERED,
            GITHUB_CLIENT,
            GITHUB_BINDING,
            INGRESS,
            "ingress:one",
        ),
    )
    for statement, target, operation, client_id, binding_id, ingress_id, key in attacks:
        # Each attack is rolled back together with its identity mutation.
        with (
            pytest.raises(DBAPIError) as rejected,
            migrated_database.engine.begin() as connection,
        ):
            if ingress_id is not None:
                _validate_ingress(connection, ingress_id)
            connection.execute(text(statement), {"target": target})
            _insert_branch_event(
                connection,
                sequence=2,
                event_id=ATTACK_EVENT,
                client_id=client_id,
                binding_id=binding_id,
                ingress_id=ingress_id,
                idempotency_key=key,
                operation=operation,
                memory_id=MEMORY if operation is EventOperation.REMEMBERED else None,
            )
        assert _sqlstate(rejected.value) == "23514"

    with migrated_database.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO transport_bindings "
                "(transport_binding_id, tenant_id, actor_id, client_id, transport_kind, "
                "disclosure_boundary, authorized_operations, created_at, valid_until) VALUES "
                "(:binding, :tenant, :actor, :client, 'direct_private', 'private_node', "
                '\'{"operations":["branch_created"]}\'::jsonb, '
                "'2026-08-03T00:00:00Z', '2026-08-04T00:00:00Z')"
            ),
            {
                "binding": EXPIRED_BINDING,
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "client": CLIENT_A,
            },
        )
    with (
        pytest.raises(DBAPIError) as expired_binding,
        migrated_database.engine.begin() as connection,
    ):
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=CLIENT_A,
            binding_id=EXPIRED_BINDING,
            idempotency_key="expired-binding",
        )
    assert _sqlstate(expired_binding.value) == "23514"

    with (
        pytest.raises(DBAPIError) as unauthorized_operation,
        migrated_database.engine.begin() as connection,
    ):
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT_TWO,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="unauthorized-operation",
            operation=EventOperation.REMEMBERED,
            memory_id=MEMORY,
        )
    assert _sqlstate(unauthorized_operation.value) == "23514"


def test_real_api_role_can_complete_only_tenant_scoped_ingress_transaction(
    migrated_database: AlembicRunner,
) -> None:
    _seed_github_ingress_graph(migrated_database)
    _create_runtime_role(migrated_database)
    _grant_ingress_runtime_privileges(migrated_database)
    with migrated_database.engine.begin() as connection:
        _validate_ingress(connection, INGRESS)

    with migrated_database.engine.begin() as connection:
        connection.execute(text(f"SET ROLE {API_ROLE}"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        _insert_branch_event(
            connection,
            sequence=2,
            event_id=ATTACK_EVENT,
            client_id=GITHUB_CLIENT,
            binding_id=GITHUB_BINDING,
            ingress_id=INGRESS,
            idempotency_key="ingress:one",
            operation=EventOperation.OBSERVED,
            memory_id=MEMORY,
        )
        _accept_ingress(connection, INGRESS, ATTACK_EVENT, MEMORY)

    with migrated_database.engine.connect() as connection:
        state = connection.execute(
            text("SELECT state FROM ingress_items WHERE ingress_id = :ingress"),
            {"ingress": INGRESS},
        ).scalar_one()
    assert state == "accepted"

    with (
        pytest.raises(DBAPIError) as role_payload_mismatch,
        migrated_database.engine.begin() as connection,
    ):
        connection.execute(text(f"SET ROLE {API_ROLE}"))
        connection.execute(
            text("SELECT set_config('scalevault.tenant_id', :tenant_id, true)"),
            {"tenant_id": str(TENANT_A)},
        )
        _insert_branch_event(
            connection,
            sequence=3,
            event_id=ATTACK_EVENT_TWO,
            client_id=CLIENT_A,
            binding_id=BINDING,
            idempotency_key="role-payload-mismatch",
            payload_override={"role_test": True},
            canonical_override=b'{"role_test":false}',
        )
    assert _sqlstate(role_payload_mismatch.value) == "23514"


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
