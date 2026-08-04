from __future__ import annotations

from kivra_memory.storage import TENANT_TABLE_NAMES, Database, metadata
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Numeric, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.sqltypes import Enum

EXPECTED_TABLES = {
    "actors",
    "alembic_compatibility",
    "archive_export_checkpoints",
    "archive_targets",
    "branches",
    "client_credentials",
    "clients",
    "command_receipts",
    "embedding_models",
    "ingress_items",
    "lineages",
    "memories",
    "memory_conflict_members",
    "memory_conflicts",
    "memory_content_keys",
    "memory_event_counter",
    "memory_events",
    "memory_evidence",
    "memory_links",
    "outbox_jobs",
    "personas",
    "sessions",
    "subject_aliases",
    "subjects",
    "tenants",
    "transport_bindings",
    "transport_installations",
}


def test_metadata_registers_the_complete_initial_contract() -> None:
    assert set(metadata.tables) == EXPECTED_TABLES
    assert "memory_embeddings_v1" not in metadata.tables
    assert (
        EXPECTED_TABLES
        - {
            "alembic_compatibility",
            "memory_event_counter",
        }
        == TENANT_TABLE_NAMES
    )


def test_tenant_local_foreign_keys_are_tenant_qualified() -> None:
    for table_name in TENANT_TABLE_NAMES:
        table = metadata.tables[table_name]
        assert "tenant_id" in table.c
        for constraint in table.constraints:
            if not isinstance(constraint, ForeignKeyConstraint):
                continue
            remote_tables = {element.column.table.name for element in constraint.elements}
            if not remote_tables & TENANT_TABLE_NAMES:
                continue
            assert "tenant_id" in constraint.column_keys, (table_name, constraint.name)
            assert any(
                element.parent.name == "tenant_id" and element.column.name == "tenant_id"
                for element in constraint.elements
            ), (table_name, constraint.name)


def test_check_constraints_are_named_and_vocabularies_are_bounded_text() -> None:
    for table in metadata.tables.values():
        for constraint in table.constraints:
            if isinstance(constraint, CheckConstraint):
                assert constraint.name is not None
        assert all(not isinstance(column.type, Enum) for column in table.columns)


def test_schema_wide_unique_and_index_names_do_not_collide() -> None:
    names: list[str] = []
    for table in metadata.tables.values():
        names.extend(
            str(constraint.name)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        )
        names.extend(str(index.name) for index in table.indexes)
    assert len(names) == len(set(names))


def test_event_envelope_and_transactional_counter_are_explicit() -> None:
    event = metadata.tables["memory_events"]
    assert set(event.c.keys()) >= {
        "schema_version",
        "payload_version",
        "sequence",
        "event_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "session_id",
        "ingress_id",
        "memory_id",
        "expected_revision",
        "causation_event_id",
        "operation",
        "correlation_id",
        "idempotency_key",
        "policy_version",
        "normalization_version",
        "payload",
        "payload_canonical",
        "payload_sha256",
        "command_sha256",
        "created_at",
    }
    assert event.c.sequence.autoincrement is False
    assert event.info["scalevault_immutable"] is True
    checks = " ".join(
        str(constraint.sqltext)
        for constraint in event.constraints
        if isinstance(constraint, CheckConstraint)
    )
    assert "operation IN ('observed', 'remembered', 'evidence_attached'" in checks
    assert "'payload_purge_completed'" in checks
    assert "'conflict_resolved'" in checks
    counter = metadata.tables["memory_event_counter"]
    assert set(counter.c.keys()) == {"counter_id", "next_sequence"}


def test_projection_scores_use_exact_numeric_storage() -> None:
    memory = metadata.tables["memories"]
    for column_name in ("confidence", "salience", "durability"):
        column_type = memory.c[column_name].type
        assert isinstance(column_type, Numeric)
        assert (column_type.precision, column_type.scale) == (7, 6)
    assert set(memory.c.keys()) >= {
        "origin_session_id",
        "publication_approved_at",
        "publication_approved_by_actor_id",
        "content_protection",
        "content_key_id",
        "fingerprint_version",
    }
    assert memory.c.statement.nullable is True
    assert memory.c.reason_to_remember.nullable is True
    assert memory.c.normalized_fingerprint.nullable is True
    checks = " ".join(
        str(constraint.sqltext)
        for constraint in memory.constraints
        if isinstance(constraint, CheckConstraint)
    )
    assert "status = 'tombstoned'" in checks
    assert "interpretation_limits = '[]'::jsonb" in checks


def test_projection_children_match_canonical_after_images() -> None:
    evidence = metadata.tables["memory_evidence"]
    assert set(evidence.c.keys()) >= {
        "branch_id",
        "source_reference",
        "occurred_at",
        "status",
        "metadata",
    }
    assert {"ordinal", "observed_at"}.isdisjoint(evidence.c.keys())
    assert isinstance(evidence.c.source_reference.type, JSONB)
    assert evidence.c.source_reference.nullable is False
    assert evidence.c.content_sha256.nullable is True

    link = metadata.tables["memory_links"]
    assert set(link.c.keys()) >= {"status", "unlinked_at", "metadata"}
    assert {"state", "retired_at", "retired_event_id"}.isdisjoint(link.c.keys())

    conflict = metadata.tables["memory_conflicts"]
    assert set(conflict.c.keys()) >= {
        "status",
        "reason",
        "resolution_kind",
        "resolution_rationale",
        "metadata",
    }
    assert {"state", "resolution_basis", "resolution_memory_id"}.isdisjoint(conflict.c.keys())

    member = metadata.tables["memory_conflict_members"]
    assert set(member.c.keys()) >= {"disposition", "joined_at", "last_event_id"}
    assert {
        "state",
        "added_at",
        "disposed_at",
        "added_event_id",
        "disposition_event_id",
    }.isdisjoint(member.c.keys())


def test_lineage_anchors_and_parent_fork_are_structural() -> None:
    subjects = metadata.tables["subjects"]
    aliases = metadata.tables["subject_aliases"]
    assert "lineage_id" in subjects.c
    assert "lineage_id" in aliases.c

    memory_subject_fk = next(
        constraint
        for constraint in metadata.tables["memories"].foreign_key_constraints
        if constraint.referred_table.name == "subjects"
    )
    assert memory_subject_fk.column_keys == [
        "tenant_id",
        "lineage_id",
        "subject_id",
        "subject_kind",
    ]

    branch_fork_fk = next(
        constraint
        for constraint in metadata.tables["branches"].foreign_key_constraints
        if constraint.referred_table.name == "memory_events"
    )
    assert branch_fork_fk.column_keys == [
        "tenant_id",
        "lineage_id",
        "parent_branch_id",
        "fork_event_sequence",
    ]

    assert metadata.tables["transport_bindings"].info["scalevault_immutable"] is True
    assert metadata.tables["branches"].info["scalevault_immutable_fields"] == (
        "tenant_id",
        "lineage_id",
        "parent_branch_id",
        "fork_event_sequence",
        "created_at",
    )
    assert metadata.tables["subjects"].info["scalevault_immutable_fields"] == (
        "tenant_id",
        "lineage_id",
        "kind",
        "canonical_key",
        "persona_id",
        "relationship_actor_id",
        "project_ref",
        "episode_ref",
        "origin_session_id",
        "created_at",
    )


async def test_database_hides_bound_parameters() -> None:
    database = Database("postgresql://user:password@127.0.0.1:5432/scalevault")
    try:
        assert database.engine.sync_engine.hide_parameters is True
    finally:
        await database.dispose()
