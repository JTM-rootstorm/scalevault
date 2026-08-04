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
