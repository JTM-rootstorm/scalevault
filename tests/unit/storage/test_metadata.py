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
    "genesis_import_exclusions",
    "genesis_import_records",
    "genesis_import_run_results",
    "genesis_import_runs",
    "genesis_import_sources",
    "genesis_import_supersessions",
    "ingress_items",
    "ingress_provider_heads",
    "ingress_provider_violations",
    "lineages",
    "memories",
    "memory_conflict_members",
    "memory_conflicts",
    "memory_content_keys",
    "memory_event_counter",
    "memory_events",
    "memory_evidence",
    "memory_embeddings_v1",
    "memory_links",
    "outbox_jobs",
    "personas",
    "sessions",
    "selection_decision_counter",
    "selection_decisions",
    "subject_aliases",
    "subjects",
    "tenants",
    "transport_bindings",
    "transport_installations",
}


def test_metadata_registers_the_complete_initial_contract() -> None:
    assert set(metadata.tables) == EXPECTED_TABLES
    assert (
        EXPECTED_TABLES
        - {
            "alembic_compatibility",
            "memory_event_counter",
            "selection_decision_counter",
        }
        == TENANT_TABLE_NAMES
    )


def test_embedding_projection_has_fixed_v1_contract() -> None:
    embedding = metadata.tables["memory_embeddings_v1"]
    assert set(embedding.c.keys()) == {
        "tenant_id",
        "memory_id",
        "embedding_model_id",
        "lineage_id",
        "branch_id",
        "source_memory_revision",
        "source_event_id",
        "input_contract_version",
        "source_content_sha256",
        "input_truncated",
        "embedding",
        "created_at",
    }
    assert {column.name for column in embedding.primary_key.columns} == {
        "tenant_id",
        "memory_id",
        "embedding_model_id",
    }
    indexes = {str(index.name): index for index in embedding.indexes}
    assert set(indexes) == {
        "ix_memory_embeddings_v1_filter",
        "ix_memory_embeddings_v1_hnsw_cosine",
    }
    assert (
        indexes["ix_memory_embeddings_v1_hnsw_cosine"].dialect_options["postgresql"]["using"]
        == "hnsw"
    )


def test_ingress_provider_head_pins_bootstrap_and_immutable_identity() -> None:
    head = metadata.tables["ingress_provider_heads"]
    assert set(head.c.keys()) == {
        "tenant_id",
        "provider",
        "repository_external_id",
        "branch_name",
        "installation_id",
        "transport_binding_id",
        "bootstrap_commit_id",
        "bootstrap_tree_id",
        "last_verified_commit_id",
        "last_verified_tree_id",
        "etag",
        "created_at",
        "verified_at",
    }
    checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in head.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert (
        "84233835924ade0e3cf26bb995717c880c75ff5c"
        in checks["ck_ingress_provider_heads_bootstrap_commit_pin"]
    )
    assert (
        "2de813150fe3952e6538abc5db9c2254d835a70e"
        in checks["ck_ingress_provider_heads_bootstrap_tree_pin"]
    )
    assert set(head.info["scalevault_immutable_fields"]) >= {
        "tenant_id",
        "repository_external_id",
        "branch_name",
        "installation_id",
        "transport_binding_id",
        "bootstrap_commit_id",
        "bootstrap_tree_id",
    }


def test_hybrid_retrieval_indexes_and_model_lifecycle_are_explicit() -> None:
    event_indexes = {index.name for index in metadata.tables["memory_events"].indexes}
    session_indexes = {index.name for index in metadata.tables["sessions"].indexes}
    subject_indexes = {index.name for index in metadata.tables["subjects"].indexes}
    alias_indexes = {index.name for index in metadata.tables["subject_aliases"].indexes}
    assert "ix_memory_events_branch_created_at" in event_indexes
    assert "ix_sessions_project_ref" in session_indexes
    assert {
        "ix_subjects_display_name_trgm",
        "ix_subjects_canonical_key_trgm",
        "ix_subjects_project_ref",
        "ix_subjects_relationship_actor",
        "ix_subjects_origin_session",
    } <= subject_indexes
    assert "ix_subject_aliases_alias_trgm" in alias_indexes

    lifecycle = next(
        constraint
        for constraint in metadata.tables["embedding_models"].constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name == "ck_embedding_models_lifecycle_state"
    )
    lifecycle_sql = str(lifecycle.sqltext)
    assert "state = 'approved' AND activated_at IS NOT NULL" in lifecycle_sql
    assert "state = 'retired'" in lifecycle_sql
    assert "retired_at >= activated_at" in lifecycle_sql


def test_client_credentials_are_secret_safe_and_immutably_attributed() -> None:
    credentials = metadata.tables["client_credentials"]
    assert set(credentials.c.keys()) == {
        "credential_id",
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "kind",
        "public_hint",
        "secret_hash",
        "secret_hash_key_id",
        "certificate_sha256",
        "created_at",
        "expires_at",
        "last_used_at",
        "revoked_at",
    }
    checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in credentials.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert checks["ck_client_credentials_secret_hash_format"] == (
        "secret_hash IS NULL OR secret_hash ~ '^hmac-sha256-v1:[A-Za-z0-9_-]{43}$'"
    )
    assert "secret_hash_key_id IS NOT NULL" in checks["ck_client_credentials_material_matches_kind"]
    binding = next(
        constraint
        for constraint in credentials.constraints
        if isinstance(constraint, ForeignKeyConstraint) and constraint.name == "transport_binding"
    )
    assert binding.column_keys == [
        "tenant_id",
        "transport_binding_id",
        "actor_id",
        "client_id",
    ]
    active_binding = next(
        index
        for index in credentials.indexes
        if index.name == "uq_client_credentials_active_binding"
    )
    assert [column.name for column in active_binding.columns] == [
        "tenant_id",
        "client_id",
        "transport_binding_id",
    ]
    assert str(active_binding.dialect_options["postgresql"]["where"]) == (
        "revoked_at IS NULL AND kind = 'bearer_token'"
    )
    assert credentials.info["scalevault_contains_no_plaintext_secret"] is True
    assert credentials.info["scalevault_delete_forbidden"] is True
    assert set(credentials.info["scalevault_immutable_fields"]) >= {
        "tenant_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "secret_hash",
        "secret_hash_key_id",
    }


def test_secure_tunnel_bindings_require_an_installation() -> None:
    bindings = metadata.tables["transport_bindings"]
    checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in bindings.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert checks["ck_transport_bindings_remote_has_installation"] == (
        "transport_kind NOT IN ('secure_tunnel', 'relay') OR installation_id IS NOT NULL"
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
    payload_hash_constraint = next(
        constraint
        for constraint in event.constraints
        if isinstance(constraint, CheckConstraint)
        and str(constraint.name).endswith("payload_sha256_matches_canonical")
    )
    assert str(payload_hash_constraint.sqltext) == (
        "payload_sha256 = digest(payload_canonical, 'sha256')"
    )
    counter = metadata.tables["memory_event_counter"]
    assert set(counter.c.keys()) == {"counter_id", "next_sequence"}


def test_selection_decisions_are_bounded_immutable_and_authorization_anchored() -> None:
    decision = metadata.tables["selection_decisions"]
    assert set(decision.c.keys()) == {
        "selection_sequence",
        "decision_id",
        "tenant_id",
        "lineage_id",
        "branch_id",
        "persona_id",
        "actor_id",
        "client_id",
        "transport_binding_id",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "policy_rule_code",
        "input_sha256",
        "source_kind",
        "requested_operation",
        "outcome",
        "reason_codes",
        "matched_rule_ids",
        "selection_basis",
        "scope",
        "visibility",
        "sensitivity",
        "subject_id",
        "subject_kind",
        "memory_id",
        "event_id",
        "decided_at",
    }
    assert decision.info["scalevault_immutable"] is True
    assert decision.info["scalevault_tenant_owned"] is True
    assert decision.c.selection_sequence.autoincrement is False
    assert {index.name for index in decision.indexes} == {
        "ix_selection_decisions_branch_sequence",
        "ix_selection_decisions_memory",
    }
    checks = " ".join(
        str(constraint.sqltext)
        for constraint in decision.constraints
        if isinstance(constraint, CheckConstraint)
    )
    assert "policy_id = 'scalevault-memory-selection'" in checks
    assert "jsonb_array_length(reason_codes) BETWEEN 1 AND 8" in checks
    assert "jsonb_array_length(matched_rule_ids) BETWEEN 0 AND 16" in checks
    assert "outcome IN ('omit', 'reject')" in checks
    assert "scope = 'scene_local' AND subject_kind = 'scene'" in checks
    assert "'genesis_import'" in checks

    counter = metadata.tables["selection_decision_counter"]
    assert set(counter.c.keys()) == {"counter_id", "next_sequence"}


def test_receipts_support_selection_only_and_event_linked_terminal_results() -> None:
    receipt = metadata.tables["command_receipts"]
    assert receipt.c.event_id.nullable is True
    assert receipt.c.selection_decision_id.nullable is True
    shape = next(
        constraint
        for constraint in receipt.constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name == "ck_command_receipts_terminal_reference_shape"
    )
    assert "selection_decision_id IS NULL AND event_id IS NOT NULL" in str(shape.sqltext)
    assert "event_id IS NULL AND memory_id IS NULL AND memory_revision IS NULL" in str(
        shape.sqltext
    )


def test_ingress_provenance_is_immutable() -> None:
    ingress = metadata.tables["ingress_items"]
    assert ingress.info["scalevault_immutable_fields"] == (
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

    memory_subject_fks = {
        constraint.name: constraint.column_keys
        for constraint in metadata.tables["memories"].foreign_key_constraints
        if constraint.referred_table.name == "subjects"
    }
    assert memory_subject_fks["subject"] == [
        "tenant_id",
        "lineage_id",
        "subject_id",
        "subject_kind",
    ]
    assert memory_subject_fks["subject_origin_session"] == [
        "tenant_id",
        "lineage_id",
        "subject_id",
        "subject_kind",
        "origin_session_id",
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
        "visibility_ceiling",
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
        session = database.session_factory()
        assert session.bind is database.engine
        await session.close()
    finally:
        await database.dispose()
