from __future__ import annotations

from typing import cast
from uuid import UUID

from kivra_memory.storage import TENANT_TABLE_NAMES, metadata
from sqlalchemy import text
from sqlalchemy.schema import Index, UniqueConstraint

from .conftest import AlembicRunner

VALID_UUID7 = UUID("01936d5a-8c4e-7b12-ae6c-4a41a22835cc")
UUID4 = UUID("123e4567-e89b-42d3-a456-426614174000")


def test_uuidv7_helper_checks_version_and_rfc_variant(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        result = connection.execute(
            text(
                "SELECT scalevault_is_uuid_v7(:valid), "
                "scalevault_is_uuid_v7(:uuid4), "
                "scalevault_is_uuid_v7("
                "'01936d5a-8c4e-7b12-7e6c-4a41a22835cc'::uuid)"
            ),
            {"valid": VALID_UUID7, "uuid4": UUID4},
        ).one()

    assert result == (True, False, False)


def test_every_tenant_table_has_forced_rls_and_one_tenant_policy(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        rls_rows = connection.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
                "FROM pg_class AS c "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relname = ANY(:table_names)"
            ),
            {"table_names": sorted(TENANT_TABLE_NAMES)},
        ).all()
        policy_rows = connection.execute(
            text(
                "SELECT tablename, policyname, qual, with_check "
                "FROM pg_policies "
                "WHERE schemaname = 'public' AND tablename = ANY(:table_names)"
            ),
            {"table_names": sorted(TENANT_TABLE_NAMES)},
        ).all()

    assert {str(row[0]) for row in rls_rows} == set(TENANT_TABLE_NAMES)
    assert all(bool(row[1]) and bool(row[2]) for row in rls_rows)
    assert {str(row[0]) for row in policy_rows} == set(TENANT_TABLE_NAMES)
    assert all(str(row[1]) == "scalevault_tenant_isolation" for row in policy_rows)
    assert all("scalevault.tenant_id" in str(row[2]) for row in policy_rows)
    assert all("scalevault.tenant_id" in str(row[3]) for row in policy_rows)


def test_tenant_owned_foreign_keys_include_tenant_id() -> None:
    tenant_tables = {metadata.tables[name] for name in TENANT_TABLE_NAMES}
    for table in tenant_tables:
        for constraint in table.foreign_key_constraints:
            referred_table = next(iter(constraint.elements)).column.table
            if referred_table not in tenant_tables:
                continue
            local_columns = {element.parent.name for element in constraint.elements}
            remote_columns = {element.column.name for element in constraint.elements}
            assert "tenant_id" in local_columns, (
                f"{table.name}.{constraint.name} is not tenant-safe"
            )
            assert "tenant_id" in remote_columns, (
                f"{table.name}.{constraint.name} is not tenant-safe"
            )


def test_index_backed_constraint_names_are_schema_unique() -> None:
    owners: dict[str, list[str]] = {}
    for table in metadata.tables.values():
        for item in (*table.constraints, *table.indexes):
            if not isinstance(item, (Index, UniqueConstraint)) or item.name is None:
                continue
            owners.setdefault(cast(str, item.name), []).append(table.name)

    duplicates = {name: tables for name, tables in owners.items() if len(tables) > 1}
    assert duplicates == {}


def test_immutable_relations_reject_row_mutation_and_truncate(
    migrated_database: AlembicRunner,
) -> None:
    immutable_tables = {
        table.name for table in metadata.tables.values() if table.info.get("scalevault_immutable")
    }
    with migrated_database.connect() as connection:
        triggers = connection.execute(
            text(
                "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) "
                "FROM pg_trigger AS t "
                "JOIN pg_class AS c ON c.oid = t.tgrelid "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' "
                "AND c.relname = ANY(:table_names) "
                "AND NOT t.tgisinternal"
            ),
            {"table_names": sorted(immutable_tables)},
        ).all()

    by_name = {
        (str(table), str(name)): " ".join(str(definition).upper().split())
        for table, name, definition in triggers
    }
    for table in immutable_tables:
        row_trigger = by_name[(table, f"trg_{table}_immutable")]
        truncate_trigger = by_name[(table, f"trg_{table}_immutable_truncate")]
        assert "BEFORE DELETE OR UPDATE" in row_trigger or "BEFORE UPDATE OR DELETE" in row_trigger
        assert "BEFORE TRUNCATE" in truncate_trigger


def test_identity_and_ancestry_fields_have_targeted_immutable_triggers(
    migrated_database: AlembicRunner,
) -> None:
    expected = {
        table.name: tuple(table.info["scalevault_immutable_fields"])
        for table in metadata.tables.values()
        if table.info.get("scalevault_immutable_fields")
    }
    ingress_immutable_fields = (
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
        "discovered_at",
    )
    assert expected["ingress_items"] == ingress_immutable_fields
    with migrated_database.connect() as connection:
        definitions = connection.execute(
            text(
                "SELECT c.relname, pg_get_triggerdef(t.oid) "
                "FROM pg_trigger AS t "
                "JOIN pg_class AS c ON c.oid = t.tgrelid "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' "
                "AND t.tgname = ('trg_' || c.relname || '_immutable_fields') "
                "AND NOT t.tgisinternal"
            )
        ).all()

    by_table = {
        str(table): " ".join(str(definition).lower().split()) for table, definition in definitions
    }
    assert set(by_table) == set(expected)
    for table, fields in expected.items():
        assert "before update of" in by_table[table]
        assert all(field in by_table[table] for field in fields)


def test_content_key_lifecycle_has_forward_only_audit_and_delete_barriers(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        definitions = {
            str(name): " ".join(str(definition).lower().split())
            for name, definition in connection.execute(
                text(
                    "SELECT t.tgname, pg_get_triggerdef(t.oid) "
                    "FROM pg_trigger AS t "
                    "JOIN pg_class AS c ON c.oid = t.tgrelid "
                    "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' "
                    "AND c.relname = 'memory_content_keys' "
                    "AND NOT t.tgisinternal"
                )
            ).all()
        }

    assert "before update of" in definitions["trg_memory_content_keys_immutable_fields"]
    assert "provider_key_reference" in definitions["trg_memory_content_keys_immutable_fields"]
    assert "before delete" in definitions["trg_memory_content_keys_delete_forbidden"]
    assert "before truncate" in definitions["trg_memory_content_keys_truncate_forbidden"]
    assert "before insert" in definitions["trg_memory_content_keys_lifecycle_insert"]
    lifecycle = definitions["trg_memory_content_keys_lifecycle"]
    assert "before update of state, destruction_requested_at, destroyed_at" in lifecycle
    assert "destruction_receipt_sha256" in lifecycle


def test_memories_has_branch_visibility_trigger(migrated_database: AlembicRunner) -> None:
    with migrated_database.connect() as connection:
        trigger = connection.execute(
            text(
                "SELECT pg_get_triggerdef(t.oid) "
                "FROM pg_trigger AS t "
                "JOIN pg_class AS c ON c.oid = t.tgrelid "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' "
                "AND c.relname = 'memories' "
                "AND t.tgname = 'trg_memories_branch_visibility' "
                "AND NOT t.tgisinternal"
            )
        ).scalar_one()

    normalized = " ".join(str(trigger).upper().split())
    assert "BEFORE INSERT OR UPDATE" in normalized


def test_memory_events_has_fail_closed_ingress_provenance_trigger(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        trigger, function = connection.execute(
            text(
                "SELECT pg_get_triggerdef(t.oid), pg_get_functiondef(p.oid) "
                "FROM pg_trigger AS t "
                "JOIN pg_class AS c ON c.oid = t.tgrelid "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "JOIN pg_proc AS p ON p.oid = t.tgfoid "
                "WHERE n.nspname = 'public' "
                "AND c.relname = 'memory_events' "
                "AND t.tgname = 'trg_memory_events_ingress_provenance' "
                "AND NOT t.tgisinternal"
            )
        ).one()

    normalized_trigger = " ".join(str(trigger).upper().split())
    normalized_function = " ".join(str(function).lower().split())
    assert "BEFORE INSERT" in normalized_trigger
    assert "github_ingress" in normalized_function
    assert "ingress_provider is distinct from 'github'" in normalized_function
    assert "ingress_installation_id is distinct from binding_installation_id" in normalized_function
    assert "binding_authorized_operations" in normalized_function
    assert "binding_valid_until" in normalized_function
    assert "ingress_state is distinct from 'validated'" in normalized_function


def test_event_payload_and_ingress_lifecycle_have_database_barriers(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT c.relname, t.tgname, t.tgdeferrable, t.tginitdeferred, "
                "pg_get_triggerdef(t.oid), p.proname "
                "FROM pg_trigger AS t "
                "JOIN pg_class AS c ON c.oid = t.tgrelid "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "JOIN pg_proc AS p ON p.oid = t.tgfoid "
                "WHERE n.nspname = 'public' "
                "AND t.tgname = ANY(:trigger_names) "
                "AND NOT t.tgisinternal"
            ),
            {
                "trigger_names": [
                    "trg_memory_events_payload_integrity",
                    "trg_ingress_items_lifecycle",
                    "trg_memory_events_ingress_reciprocity",
                    "trg_ingress_items_result_reciprocity",
                ]
            },
        ).all()

    by_name = {str(row[1]): row for row in rows}
    assert set(by_name) == {
        "trg_memory_events_payload_integrity",
        "trg_ingress_items_lifecycle",
        "trg_memory_events_ingress_reciprocity",
        "trg_ingress_items_result_reciprocity",
    }
    assert str(by_name["trg_memory_events_payload_integrity"][0]) == "memory_events"
    assert str(by_name["trg_ingress_items_lifecycle"][0]) == "ingress_items"
    for trigger_name in (
        "trg_memory_events_ingress_reciprocity",
        "trg_ingress_items_result_reciprocity",
    ):
        assert bool(by_name[trigger_name][2]) is True
        assert bool(by_name[trigger_name][3]) is True
        assert "DEFERRABLE INITIALLY DEFERRED" in " ".join(
            str(by_name[trigger_name][4]).upper().split()
        )


def test_scene_memory_origin_session_is_bound_to_subject_session(
    migrated_database: AlembicRunner,
) -> None:
    with migrated_database.connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'public.memories'::regclass "
                "AND conname = 'subject_origin_session'"
            )
        ).scalar_one()

    normalized = " ".join(str(definition).lower().split()).replace("public.", "")
    assert "foreign key (tenant_id, lineage_id, subject_id, subject_kind, origin_session_id)" in (
        normalized
    )
    assert "references subjects(tenant_id, lineage_id, subject_id, kind, origin_session_id)" in (
        normalized
    )
