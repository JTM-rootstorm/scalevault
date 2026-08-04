"""Create the initial canonical Memory Node domain schema.

Revision ID: 0001_initial_domain
Revises:
Create Date: 2026-08-03
"""

# Generated table and constraint definitions intentionally preserve reviewed SQL verbatim.
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_domain"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REQUIRED_EXTENSIONS = frozenset({"citext", "pg_trgm", "pgcrypto", "vector"})
TENANT_TABLES = (
    "actors",
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
)
IMMUTABLE_TABLES = ("command_receipts", "memory_events", "transport_bindings")
IMMUTABLE_FIELD_TABLES = (
    (
        "branches",
        (
            "tenant_id",
            "lineage_id",
            "parent_branch_id",
            "fork_event_sequence",
            "visibility_ceiling",
            "created_at",
        ),
    ),
    (
        "subjects",
        (
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
        ),
    ),
)


def _require_extensions() -> None:
    installed = set(
        op.get_bind()
        .execute(
            sa.text(
                "SELECT extname FROM pg_extension "
                "WHERE extname IN ('citext', 'pg_trgm', 'pgcrypto', 'vector')"
            )
        )
        .scalars()
    )
    missing = sorted(REQUIRED_EXTENSIONS - installed)
    if missing:
        raise RuntimeError(
            "required PostgreSQL extensions are not installed: " + ", ".join(missing)
        )


def _create_uuidv7_helper() -> None:
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_is_uuid_v7(value uuid)
        RETURNS boolean
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog
        AS $function$
            SELECT
                (pg_catalog.get_byte(pg_catalog.uuid_send(value), 6) >> 4) = 7
                AND (pg_catalog.get_byte(pg_catalog.uuid_send(value), 8) & 192) = 128
        $function$
    """)
    )


def _create_immutability_barriers() -> None:
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_reject_immutable_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            RAISE EXCEPTION 'immutable canonical relation cannot be mutated'
                USING ERRCODE = '55000';
        END
        $function$
    """)
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_reject_immutable_field_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            field_name text;
        BEGIN
            FOREACH field_name IN ARRAY TG_ARGV LOOP
                IF pg_catalog.to_jsonb(OLD) -> field_name
                    IS DISTINCT FROM pg_catalog.to_jsonb(NEW) -> field_name THEN
                    RAISE EXCEPTION 'immutable canonical field cannot be mutated'
                        USING ERRCODE = '55000';
                END IF;
            END LOOP;
            RETURN NEW;
        END
        $function$
    """)
    )
    for table_name in IMMUTABLE_TABLES:
        op.execute(
            sa.text(
                f"CREATE TRIGGER trg_{table_name}_immutable "
                f'BEFORE UPDATE OR DELETE ON public."{table_name}" '
                "FOR EACH ROW EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
            )
        )
        op.execute(
            sa.text(
                f"CREATE TRIGGER trg_{table_name}_immutable_truncate "
                f'BEFORE TRUNCATE ON public."{table_name}" '
                "FOR EACH STATEMENT EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
            )
        )
    for table_name, field_names in IMMUTABLE_FIELD_TABLES:
        update_columns = ", ".join(f'"{name}"' for name in field_names)
        trigger_arguments = ", ".join(f"'{name}'" for name in field_names)
        op.execute(
            sa.text(
                f"CREATE TRIGGER trg_{table_name}_immutable_fields "
                f'BEFORE UPDATE OF {update_columns} ON public."{table_name}" '
                "FOR EACH ROW EXECUTE FUNCTION "
                f"public.scalevault_reject_immutable_field_mutation({trigger_arguments})"
            )
        )


def _create_branch_visibility_barrier() -> None:
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_enforce_branch_visibility()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            branch_ceiling text;
        BEGIN
            SELECT visibility_ceiling
            INTO branch_ceiling
            FROM public.branches
            WHERE tenant_id = NEW.tenant_id
              AND lineage_id = NEW.lineage_id
              AND branch_id = NEW.branch_id;

            IF branch_ceiling IS NULL THEN
                RETURN NEW;
            END IF;

            IF NOT (
                (branch_ceiling = 'private_root' AND NEW.visibility = 'private_root')
                OR (branch_ceiling = 'restricted'
                    AND NEW.visibility IN ('private_root', 'restricted'))
                OR (branch_ceiling = 'shareable'
                    AND NEW.visibility IN ('private_root', 'restricted', 'shareable'))
                OR branch_ceiling = 'public_seed'
            ) THEN
                RAISE EXCEPTION 'memory visibility exceeds branch ceiling'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $function$
    """)
    )
    op.execute(
        sa.text("""
        CREATE TRIGGER trg_memories_branch_visibility
        BEFORE INSERT OR UPDATE OF tenant_id, lineage_id, branch_id, visibility
        ON public.memories
        FOR EACH ROW
        EXECUTE FUNCTION public.scalevault_enforce_branch_visibility()
    """)
    )


def _enable_tenant_rls() -> None:
    tenant_expression = (
        "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
    )
    for table_name in TENANT_TABLES:
        quoted_table = f'public."{table_name}"'
        op.execute(sa.text(f"ALTER TABLE {quoted_table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {quoted_table} FORCE ROW LEVEL SECURITY"))
        op.execute(
            sa.text(
                f"CREATE POLICY scalevault_tenant_isolation ON {quoted_table} "
                f"USING ({tenant_expression}) WITH CHECK ({tenant_expression})"
            )
        )


def upgrade() -> None:
    _require_extensions()
    _create_uuidv7_helper()
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "alembic_compatibility",
        sa.Column("component", sa.String(length=64), nullable=False),
        sa.Column("contract_version", sa.SmallInteger(), nullable=False),
        sa.Column("minimum_reader_revision", sa.String(length=64), nullable=False),
        sa.Column("minimum_writer_revision", sa.String(length=64), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "contract_version >= 1", name=op.f("ck_alembic_compatibility_contract_version_positive")
        ),
        sa.CheckConstraint(
            "length(component) BETWEEN 1 AND 64",
            name=op.f("ck_alembic_compatibility_component_length"),
        ),
        sa.PrimaryKeyConstraint("component", name=op.f("pk_alembic_compatibility")),
    )
    op.create_table(
        "branches",
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("parent_branch_id", sa.Uuid(), nullable=True),
        sa.Column("fork_event_sequence", sa.BigInteger(), nullable=True),
        sa.Column("name", postgresql.CITEXT(), nullable=False),
        sa.Column("visibility_ceiling", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "visibility_ceiling IN ('private_root', 'restricted', 'shareable', 'public_seed')",
            name=op.f("ck_branches_visibility_ceiling_values"),
        ),
        sa.CheckConstraint(
            "(parent_branch_id IS NULL AND fork_event_sequence IS NULL) OR (parent_branch_id IS NOT NULL AND fork_event_sequence IS NOT NULL)",
            name=op.f("ck_branches_parent_fork_pair"),
        ),
        sa.CheckConstraint(
            "fork_event_sequence IS NULL OR fork_event_sequence >= 1",
            name=op.f("ck_branches_fork_sequence_positive"),
        ),
        sa.CheckConstraint(
            "parent_branch_id IS NULL OR parent_branch_id <> branch_id",
            name=op.f("ck_branches_parent_not_self"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(branch_id)", name=op.f("ck_branches_branch_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "sealed_at IS NULL OR sealed_at >= created_at", name=op.f("ck_branches_seal_order")
        ),
        sa.PrimaryKeyConstraint("branch_id", name=op.f("pk_branches")),
        sa.UniqueConstraint("tenant_id", "lineage_id", "branch_id", name="tenant_lineage_branch"),
        sa.UniqueConstraint("tenant_id", "lineage_id", "name", name="tenant_lineage_name"),
        info={
            "scalevault_tenant_owned": True,
            "scalevault_immutable_fields": (
                "tenant_id",
                "lineage_id",
                "parent_branch_id",
                "fork_event_sequence",
                "created_at",
            ),
        },
    )
    op.create_index(
        "ix_branches_parent",
        "branches",
        ["tenant_id", "lineage_id", "parent_branch_id"],
        unique=False,
    )
    op.create_index(
        "uq_branches_one_root_per_lineage",
        "branches",
        ["tenant_id", "lineage_id"],
        unique=True,
        postgresql_where=sa.text("parent_branch_id IS NULL"),
    )
    op.create_table(
        "ingress_items",
        sa.Column("ingress_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("repository_external_id", sa.String(length=255), nullable=False),
        sa.Column("branch_name", sa.String(length=255), nullable=False),
        sa.Column("immutable_path", sa.Text(), nullable=False),
        sa.Column("external_object_id", sa.String(length=255), nullable=False),
        sa.Column("commit_id", sa.String(length=255), nullable=False),
        sa.Column("blob_id", sa.String(length=255), nullable=False),
        sa.Column("declared_idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("payload_sha256", sa.LargeBinary(), nullable=False),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'discovered'"), nullable=False
        ),
        sa.Column("result_event_id", sa.Uuid(), nullable=True),
        sa.Column("result_memory_id", sa.Uuid(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("safe_diagnostic", sa.String(length=512), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("provider IN ('github')", name=op.f("ck_ingress_items_provider_values")),
        sa.CheckConstraint(
            "state IN ('discovered', 'validated', 'accepted', 'duplicate', 'conflict', 'rejected', 'quarantined')",
            name=op.f("ck_ingress_items_state_values"),
        ),
        sa.CheckConstraint(
            "length(declared_idempotency_key) BETWEEN 1 AND 255",
            name=op.f("ck_ingress_items_idempotency_key_length"),
        ),
        sa.CheckConstraint(
            "octet_length(payload_sha256) = 32", name=op.f("ck_ingress_items_payload_sha256_length")
        ),
        sa.CheckConstraint(
            "processed_at IS NULL OR processed_at >= discovered_at",
            name=op.f("ck_ingress_items_processing_order"),
        ),
        sa.CheckConstraint(
            "safe_diagnostic IS NULL OR length(safe_diagnostic) <= 512",
            name=op.f("ck_ingress_items_diagnostic_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(ingress_id)", name=op.f("ck_ingress_items_ingress_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "validated_at IS NULL OR validated_at >= discovered_at",
            name=op.f("ck_ingress_items_validation_order"),
        ),
        sa.PrimaryKeyConstraint("ingress_id", name=op.f("pk_ingress_items")),
        sa.UniqueConstraint(
            "provider",
            "repository_external_id",
            "external_object_id",
            name="provider_repository_object",
        ),
        sa.UniqueConstraint("tenant_id", "ingress_id", name="tenant_ingress"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_index(
        "ix_ingress_items_claim",
        "ingress_items",
        ["tenant_id", "state", "discovered_at"],
        unique=False,
    )
    op.create_table(
        "memories",
        sa.Column("memory_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("subject_kind", sa.String(length=16), nullable=False),
        sa.Column("origin_session_id", sa.Uuid(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=48), nullable=False),
        sa.Column("ontological_status", sa.String(length=48), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("visibility", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("statement", sa.Text(), nullable=True),
        sa.Column("reason_to_remember", sa.Text(), nullable=True),
        sa.Column("interpretation_limits", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=7, scale=6), nullable=False),
        sa.Column("salience", sa.Numeric(precision=7, scale=6), nullable=False),
        sa.Column("durability", sa.Numeric(precision=7, scale=6), nullable=False),
        sa.Column("sensitivity", sa.SmallInteger(), nullable=False),
        sa.Column("authority_class", sa.String(length=48), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "search_document",
            postgresql.TSVECTOR(),
            sa.Computed(
                "to_tsvector('simple', coalesce(statement, '') || ' ' || coalesce(reason_to_remember, ''))",
                persisted=True,
            ),
            nullable=False,
        ),
        sa.Column("normalized_fingerprint", sa.LargeBinary(), nullable=True),
        sa.Column("fingerprint_version", sa.SmallInteger(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("publication_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("publication_approved_by_actor_id", sa.Uuid(), nullable=True),
        sa.Column(
            "content_protection",
            sa.String(length=32),
            server_default=sa.text("'plaintext'"),
            nullable=False,
        ),
        sa.Column("content_key_id", sa.Uuid(), nullable=True),
        sa.Column("last_event_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "(category = 'stable_fact' AND ontological_status IN ('literal_user_fact', 'literal_technical_fact')) OR (category = 'user_preference' AND ontological_status IN ('literal_user_fact', 'uncertain')) OR (category = 'assistant_preference_like_pattern' AND ontological_status IN ('assistant_self_description', 'observed_assistant_behavior', 'hypothesis', 'uncertain')) OR (category = 'boundary_or_permission' AND ontological_status IN ('literal_user_fact', 'interaction_convention', 'uncertain')) OR (category = 'interaction_convention' AND ontological_status IN ('interaction_convention', 'literal_user_fact', 'uncertain')) OR (category = 'relationship_pattern' AND ontological_status IN ('observed_assistant_behavior', 'interaction_convention', 'hypothesis', 'uncertain')) OR (category = 'emergent_tendency' AND ontological_status IN ('assistant_self_description', 'observed_assistant_behavior', 'hypothesis', 'uncertain')) OR (category = 'episodic_anchor' AND ontological_status <> 'hypothesis') OR (category IN ('project_decision', 'project_state') AND ontological_status IN ('literal_technical_fact', 'uncertain')) OR (category = 'procedure' AND ontological_status IN ('literal_technical_fact', 'interaction_convention', 'uncertain')) OR (category IN ('open_question', 'interpretation') AND ontological_status IN ('hypothesis', 'uncertain')) OR (category = 'external_fact' AND ontological_status IN ('literal_technical_fact', 'hypothesis', 'uncertain'))",
            name=op.f("ck_memories_category_ontology_compatible"),
        ),
        sa.CheckConstraint(
            "(content_protection = 'plaintext' AND content_key_id IS NULL) OR (content_protection IN ('envelope_encrypted', 'cryptographically_erased') AND content_key_id IS NOT NULL)",
            name=op.f("ck_memories_content_key_required"),
        ),
        sa.CheckConstraint(
            "(scope = 'global' AND subject_kind = 'global') OR (scope = 'persona' AND subject_kind = 'persona') OR (scope = 'relationship' AND subject_kind = 'relationship') OR (scope = 'project' AND subject_kind = 'project') OR (scope = 'episodic' AND subject_kind = 'episode') OR (scope = 'scene_local' AND subject_kind = 'scene')",
            name=op.f("ck_memories_scope_subject_kind"),
        ),
        sa.CheckConstraint(
            "(status = 'tombstoned' AND statement IS NULL AND reason_to_remember IS NULL AND normalized_fingerprint IS NULL AND interpretation_limits = '[]'::jsonb) OR (status <> 'tombstoned' AND statement IS NOT NULL AND reason_to_remember IS NOT NULL AND normalized_fingerprint IS NOT NULL)",
            name=op.f("ck_memories_tombstone_content_shape"),
        ),
        sa.CheckConstraint(
            "authority_class IN ('explicit_user_correction', 'explicit_user_statement', 'verified_project_source', 'assistant_observation', 'assistant_interpretation', 'external_source', 'imported_legacy_memory')",
            name=op.f("ck_memories_authority_class_values"),
        ),
        sa.CheckConstraint(
            "category IN ('stable_fact', 'user_preference', 'assistant_preference_like_pattern', 'boundary_or_permission', 'interaction_convention', 'relationship_pattern', 'emergent_tendency', 'episodic_anchor', 'project_decision', 'project_state', 'procedure', 'open_question', 'interpretation', 'external_fact')",
            name=op.f("ck_memories_category_values"),
        ),
        sa.CheckConstraint(
            "content_protection <> 'cryptographically_erased' OR status = 'tombstoned'",
            name=op.f("ck_memories_erasure_requires_tombstone"),
        ),
        sa.CheckConstraint(
            "content_protection IN ('plaintext', 'envelope_encrypted', 'cryptographically_erased')",
            name=op.f("ck_memories_content_protection_values"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(interpretation_limits) = 'array'",
            name=op.f("ck_memories_interpretation_limits_array"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_memories_metadata_object")
        ),
        sa.CheckConstraint(
            "ontological_status IN ('literal_user_fact', 'literal_technical_fact', 'assistant_self_description', 'observed_assistant_behavior', 'interaction_convention', 'fictional_or_roleplayed_scene', 'hypothesis', 'uncertain')",
            name=op.f("ck_memories_ontological_status_values"),
        ),
        sa.CheckConstraint(
            "scope <> 'scene_local' OR (origin_session_id IS NOT NULL AND visibility IN ('private_root', 'restricted'))",
            name=op.f("ck_memories_scene_local_boundary"),
        ),
        sa.CheckConstraint(
            "scope IN ('global', 'persona', 'relationship', 'project', 'episodic', 'scene_local')",
            name=op.f("ck_memories_scope_values"),
        ),
        sa.CheckConstraint(
            "status IN ('candidate', 'active', 'disputed', 'superseded', 'retired', 'tombstoned')",
            name=op.f("ck_memories_status_values"),
        ),
        sa.CheckConstraint(
            "subject_kind IN ('global', 'persona', 'relationship', 'project', 'episode', 'scene', 'concept')",
            name=op.f("ck_memories_subject_kind_values"),
        ),
        sa.CheckConstraint(
            "visibility <> 'public_seed' OR (status = 'active' AND sensitivity = 0 AND publication_approved_at IS NOT NULL)",
            name=op.f("ck_memories_public_seed_approval"),
        ),
        sa.CheckConstraint(
            "visibility <> 'shareable' OR sensitivity <= 1",
            name=op.f("ck_memories_shareable_sensitivity"),
        ),
        sa.CheckConstraint(
            "visibility IN ('private_root', 'restricted', 'shareable', 'public_seed')",
            name=op.f("ck_memories_visibility_values"),
        ),
        sa.CheckConstraint(
            "(publication_approved_at IS NULL) = (publication_approved_by_actor_id IS NULL)",
            name=op.f("ck_memories_publication_approval_pair"),
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 1", name=op.f("ck_memories_confidence_range")),
        sa.CheckConstraint("durability BETWEEN 0 AND 1", name=op.f("ck_memories_durability_range")),
        sa.CheckConstraint(
            "fingerprint_version >= 1", name=op.f("ck_memories_fingerprint_version_positive")
        ),
        sa.CheckConstraint(
            "jsonb_array_length(interpretation_limits) <= 32",
            name=op.f("ck_memories_interpretation_limits_count"),
        ),
        sa.CheckConstraint(
            "length(reason_to_remember) BETWEEN 1 AND 4096", name=op.f("ck_memories_reason_length")
        ),
        sa.CheckConstraint(
            "length(statement) BETWEEN 1 AND 8192", name=op.f("ck_memories_statement_length")
        ),
        sa.CheckConstraint(
            "octet_length(normalized_fingerprint) = 32", name=op.f("ck_memories_fingerprint_length")
        ),
        sa.CheckConstraint("revision >= 1", name=op.f("ck_memories_revision_positive")),
        sa.CheckConstraint("salience BETWEEN 0 AND 1", name=op.f("ck_memories_salience_range")),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(memory_id)", name=op.f("ck_memories_memory_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "sensitivity BETWEEN 0 AND 4", name=op.f("ck_memories_sensitivity_range")
        ),
        sa.CheckConstraint("updated_at >= created_at", name=op.f("ck_memories_update_order")),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name=op.f("ck_memories_validity_order"),
        ),
        sa.PrimaryKeyConstraint("memory_id", name=op.f("pk_memories")),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "memory_id", name="memories_tenant_lineage_memory"
        ),
        sa.UniqueConstraint("tenant_id", "memory_id", name="tenant_memory"),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memories_retrieval",
        "memories",
        ["tenant_id", "lineage_id", "branch_id", "status", "scope", "visibility"],
        unique=False,
    )
    op.create_index(
        "ix_memories_search_document",
        "memories",
        ["search_document"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_memories_statement_trgm",
        "memories",
        ["statement"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"statement": "gin_trgm_ops"},
    )
    op.create_index(
        "ix_memories_subject", "memories", ["tenant_id", "subject_id", "status"], unique=False
    )
    op.create_index(
        "uq_memories_live_fingerprint",
        "memories",
        ["tenant_id", "lineage_id", "branch_id", "subject_id", "scope", "normalized_fingerprint"],
        unique=True,
        postgresql_where=sa.text("status IN ('candidate', 'active', 'disputed')"),
    )
    op.create_table(
        "memory_content_keys",
        sa.Column("content_key_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=False),
        sa.Column("provider_name", sa.String(length=64), nullable=False),
        sa.Column("provider_key_reference", sa.String(length=512), nullable=False),
        sa.Column(
            "state", sa.String(length=32), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("destruction_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destruction_receipt_sha256", sa.LargeBinary(), nullable=True),
        sa.CheckConstraint(
            "state IN ('active', 'destruction_requested', 'destroyed', 'failed')",
            name=op.f("ck_memory_content_keys_state_values"),
        ),
        sa.CheckConstraint(
            "destroyed_at IS NULL OR (destruction_requested_at IS NOT NULL AND destroyed_at >= destruction_requested_at)",
            name=op.f("ck_memory_content_keys_destruction_order"),
        ),
        sa.CheckConstraint(
            "destruction_receipt_sha256 IS NULL OR octet_length(destruction_receipt_sha256) = 32",
            name=op.f("ck_memory_content_keys_destruction_receipt_length"),
        ),
        sa.CheckConstraint(
            "destruction_requested_at IS NULL OR destruction_requested_at >= created_at",
            name=op.f("ck_memory_content_keys_destruction_request_order"),
        ),
        sa.CheckConstraint(
            "length(provider_key_reference) BETWEEN 1 AND 512",
            name=op.f("ck_memory_content_keys_provider_reference_length"),
        ),
        sa.CheckConstraint(
            "length(provider_name) BETWEEN 1 AND 64",
            name=op.f("ck_memory_content_keys_provider_name_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(content_key_id)",
            name=op.f("ck_memory_content_keys_content_key_id_uuid_v7"),
        ),
        sa.PrimaryKeyConstraint("content_key_id", name=op.f("pk_memory_content_keys")),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "content_key_id", name="tenant_lineage_content_key"
        ),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "memory_id", name="memory_content_keys_tenant_lineage_memory"
        ),
        info={"scalevault_tenant_owned": True, "scalevault_contains_no_key_material": True},
    )
    op.create_table(
        "memory_event_counter",
        sa.Column("counter_id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("next_sequence", sa.BigInteger(), server_default=sa.text("1"), nullable=False),
        sa.CheckConstraint("counter_id = 1", name=op.f("ck_memory_event_counter_singleton_id")),
        sa.CheckConstraint(
            "next_sequence >= 1", name=op.f("ck_memory_event_counter_next_sequence_positive")
        ),
        sa.PrimaryKeyConstraint("counter_id", name=op.f("pk_memory_event_counter")),
    )
    op.create_table(
        "memory_events",
        sa.Column("sequence", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("ingress_id", sa.Uuid(), nullable=True),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=True),
        sa.Column("expected_revision", sa.BigInteger(), nullable=True),
        sa.Column("causation_event_id", sa.Uuid(), nullable=True),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("schema_version", sa.SmallInteger(), nullable=False),
        sa.Column("payload_version", sa.SmallInteger(), nullable=False),
        sa.Column("policy_version", sa.SmallInteger(), nullable=False),
        sa.Column("normalization_version", sa.SmallInteger(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("payload_canonical", sa.LargeBinary(), nullable=False),
        sa.Column("payload_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("command_sha256", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(operation IN ('observed', 'remembered', 'evidence_attached', 'evidence_redacted') AND memory_id IS NOT NULL AND expected_revision IS NULL) OR (operation IN ('revised', 'retired', 'visibility_changed', 'superseded', 'tombstoned', 'payload_purge_completed') AND memory_id IS NOT NULL AND expected_revision IS NOT NULL) OR (operation IN ('branch_created', 'linked', 'unlinked', 'conflict_opened', 'conflict_resolved') AND memory_id IS NULL AND expected_revision IS NULL)",
            name=op.f("ck_memory_events_operation_envelope_shape"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_memory_events_payload_object")
        ),
        sa.CheckConstraint(
            "operation IN ('observed', 'remembered', 'revised', 'linked', 'unlinked', 'evidence_attached', 'evidence_redacted', 'conflict_opened', 'conflict_resolved', 'superseded', 'retired', 'tombstoned', 'branch_created', 'visibility_changed', 'payload_purge_completed')",
            name=op.f("ck_memory_events_operation_values"),
        ),
        sa.CheckConstraint(
            "expected_revision IS NULL OR expected_revision >= 1",
            name=op.f("ck_memory_events_expected_revision_positive"),
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 255",
            name=op.f("ck_memory_events_idempotency_key_length"),
        ),
        sa.CheckConstraint(
            "normalization_version >= 1",
            name=op.f("ck_memory_events_normalization_version_positive"),
        ),
        sa.CheckConstraint(
            "octet_length(command_sha256) = 32", name=op.f("ck_memory_events_command_sha256_length")
        ),
        sa.CheckConstraint(
            "octet_length(payload_canonical) BETWEEN 2 AND 1048576",
            name=op.f("ck_memory_events_payload_canonical_length"),
        ),
        sa.CheckConstraint(
            "octet_length(payload_sha256) = 32", name=op.f("ck_memory_events_payload_sha256_length")
        ),
        sa.CheckConstraint(
            "policy_version >= 1", name=op.f("ck_memory_events_policy_version_positive")
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(correlation_id)",
            name=op.f("ck_memory_events_correlation_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(event_id)", name=op.f("ck_memory_events_event_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "schema_version >= 1 AND payload_version >= 1",
            name=op.f("ck_memory_events_versions_positive"),
        ),
        sa.CheckConstraint("sequence >= 1", name=op.f("ck_memory_events_sequence_positive")),
        sa.PrimaryKeyConstraint("sequence", name=op.f("pk_memory_events")),
        sa.UniqueConstraint("event_id", name="event_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "client_id",
            "idempotency_key",
            name="memory_events_tenant_client_idempotency",
        ),
        sa.UniqueConstraint("tenant_id", "event_id", name="tenant_event"),
        sa.UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "branch_id",
            "sequence",
            name="tenant_lineage_branch_sequence",
        ),
        sa.UniqueConstraint("tenant_id", "lineage_id", "event_id", name="tenant_lineage_event"),
        sa.UniqueConstraint("tenant_id", "lineage_id", "sequence", name="tenant_lineage_sequence"),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )
    op.create_index(
        "ix_memory_events_branch_sequence",
        "memory_events",
        ["tenant_id", "lineage_id", "branch_id", "sequence"],
        unique=False,
    )
    op.create_index(
        "ix_memory_events_correlation",
        "memory_events",
        ["tenant_id", "correlation_id"],
        unique=False,
    )
    op.create_index(
        "ix_memory_events_memory_sequence",
        "memory_events",
        ["tenant_id", "memory_id", "sequence"],
        unique=False,
    )
    op.create_table(
        "sessions",
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("conversation_ref", sa.Text(), nullable=True),
        sa.Column("project_ref", sa.Text(), nullable=True),
        sa.Column("content_mode", sa.String(length=16), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "content_mode IN ('technical', 'meta', 'roleplay', 'mixed')",
            name=op.f("ck_sessions_content_mode_values"),
        ),
        sa.CheckConstraint("last_seen_at >= started_at", name=op.f("ck_sessions_last_seen_order")),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(session_id)", name=op.f("ck_sessions_session_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_sessions")),
        sa.UniqueConstraint(
            "tenant_id", "session_id", "actor_id", "client_id", name="tenant_session_actor_client"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "session_id",
            "lineage_id",
            "branch_id",
            "actor_id",
            "client_id",
            name="tenant_session_branch_actor_client",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "session_id",
            "lineage_id",
            "branch_id",
            name="sessions_tenant_session_lineage_branch",
        ),
        sa.UniqueConstraint("tenant_id", "session_id", "lineage_id", name="tenant_session_lineage"),
        sa.UniqueConstraint("tenant_id", "session_id", name="tenant_session"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_index(
        "uq_sessions_conversation_ref",
        "sessions",
        ["tenant_id", "client_id", "conversation_ref"],
        unique=True,
        postgresql_where=sa.text("conversation_ref IS NOT NULL"),
    )
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("slug", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "state IN ('active', 'suspended', 'retired')", name=op.f("ck_tenants_state_values")
        ),
        sa.CheckConstraint(
            "length(btrim(display_name)) BETWEEN 1 AND 128",
            name=op.f("ck_tenants_display_name_length"),
        ),
        sa.CheckConstraint(
            "length(btrim(slug::text)) BETWEEN 1 AND 128", name=op.f("ck_tenants_slug_length")
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(tenant_id)", name=op.f("ck_tenants_tenant_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("slug", name=op.f("uq_tenants_slug")),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "actors",
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("handle", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_actors_metadata_object")
        ),
        sa.CheckConstraint(
            "kind IN ('user', 'persona', 'agent', 'service')", name=op.f("ck_actors_kind_values")
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_actors_revocation_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(actor_id)", name=op.f("ck_actors_actor_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("actor_id", name=op.f("pk_actors")),
        sa.UniqueConstraint("tenant_id", "actor_id", name="actors_tenant_actor"),
        sa.UniqueConstraint("tenant_id", "handle", name="tenant_handle"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "archive_targets",
        sa.Column("archive_target_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("repository_reference", sa.Text(), nullable=False),
        sa.Column("branch_name", sa.String(length=255), nullable=False),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('active', 'disabled', 'sealed')",
            name=op.f("ck_archive_targets_state_values"),
        ),
        sa.CheckConstraint(
            "target_kind IN ('forgejo_git')", name=op.f("ck_archive_targets_target_kind_values")
        ),
        sa.CheckConstraint(
            "length(branch_name) BETWEEN 1 AND 255",
            name=op.f("ck_archive_targets_branch_name_length"),
        ),
        sa.CheckConstraint(
            "length(repository_reference) BETWEEN 1 AND 1024",
            name=op.f("ck_archive_targets_repository_reference_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(archive_target_id)",
            name=op.f("ck_archive_targets_archive_target_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "sealed_at IS NULL OR sealed_at >= created_at",
            name=op.f("ck_archive_targets_seal_order"),
        ),
        sa.PrimaryKeyConstraint("archive_target_id", name=op.f("pk_archive_targets")),
        sa.UniqueConstraint("tenant_id", "archive_target_id", name="tenant_archive_target"),
        sa.UniqueConstraint("tenant_id", "name", name="tenant_name"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "clients",
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("public_id", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("transport_kind", sa.String(length=32), nullable=False),
        sa.Column("scopes", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column(
            "capability_profile",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(capability_profile) = 'object'",
            name=op.f("ck_clients_capability_profile_object"),
        ),
        sa.CheckConstraint(
            "kind IN ('interactive', 'ingress', 'worker', 'operator')",
            name=op.f("ck_clients_kind_values"),
        ),
        sa.CheckConstraint(
            "transport_kind IN ('direct_private', 'secure_tunnel', 'relay', 'github_ingress', 'internal_service', 'archive_restore')",
            name=op.f("ck_clients_transport_kind_values"),
        ),
        sa.CheckConstraint(
            "array_position(scopes, NULL) IS NULL", name=op.f("ck_clients_scopes_no_nulls")
        ),
        sa.CheckConstraint(
            "cardinality(scopes) BETWEEN 1 AND 64", name=op.f("ck_clients_scopes_count")
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_clients_revocation_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(client_id)", name=op.f("ck_clients_client_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("client_id", name=op.f("pk_clients")),
        sa.UniqueConstraint("public_id", name=op.f("uq_clients_public_id")),
        sa.UniqueConstraint(
            "tenant_id", "client_id", "transport_kind", name="tenant_client_transport"
        ),
        sa.UniqueConstraint("tenant_id", "client_id", name="tenant_client"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "embedding_models",
        sa.Column("embedding_model_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("model_name", sa.String(length=255), nullable=False),
        sa.Column("artifact_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("dimension", sa.Integer(), nullable=False),
        sa.Column("distance_metric", sa.String(length=16), nullable=False),
        sa.Column("tokenizer_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("runtime_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "normalization_settings", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'registered'"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "distance_metric IN ('cosine', 'inner_product', 'l2')",
            name=op.f("ck_embedding_models_distance_metric_values"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(normalization_settings) = 'object'",
            name=op.f("ck_embedding_models_normalization_settings_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(runtime_details) = 'object'",
            name=op.f("ck_embedding_models_runtime_details_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(tokenizer_details) = 'object'",
            name=op.f("ck_embedding_models_tokenizer_details_object"),
        ),
        sa.CheckConstraint(
            "state IN ('registered', 'evaluating', 'approved', 'retired', 'rejected')",
            name=op.f("ck_embedding_models_state_values"),
        ),
        sa.CheckConstraint(
            "activated_at IS NULL OR activated_at >= created_at",
            name=op.f("ck_embedding_models_activation_order"),
        ),
        sa.CheckConstraint(
            "dimension BETWEEN 1 AND 65535", name=op.f("ck_embedding_models_dimension_range")
        ),
        sa.CheckConstraint(
            "octet_length(artifact_sha256) = 32",
            name=op.f("ck_embedding_models_artifact_sha256_length"),
        ),
        sa.CheckConstraint(
            "retired_at IS NULL OR retired_at >= created_at",
            name=op.f("ck_embedding_models_retirement_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(embedding_model_id)",
            name=op.f("ck_embedding_models_embedding_model_id_uuid_v7"),
        ),
        sa.PrimaryKeyConstraint("embedding_model_id", name=op.f("pk_embedding_models")),
        sa.UniqueConstraint("tenant_id", "artifact_sha256", name="tenant_artifact"),
        sa.UniqueConstraint("tenant_id", "embedding_model_id", name="tenant_embedding_model"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_index(
        "uq_embedding_models_active",
        "embedding_models",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("state = 'approved' AND retired_at IS NULL"),
    )
    op.create_table(
        "memory_evidence",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=False),
        sa.Column("source_event_id", sa.Uuid(), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_reference", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("excerpt", sa.Text(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_sha256", sa.LargeBinary(), nullable=True),
        sa.Column("trust_classification", sa.String(length=64), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_memory_evidence_metadata_object")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_reference) = 'object'",
            name=op.f("ck_memory_evidence_source_reference_object"),
        ),
        sa.CheckConstraint("status IN ('active')", name=op.f("ck_memory_evidence_status_values")),
        sa.CheckConstraint(
            "excerpt IS NULL OR length(excerpt) <= 4096",
            name=op.f("ck_memory_evidence_excerpt_length"),
        ),
        sa.CheckConstraint(
            "length(source_type) BETWEEN 1 AND 64",
            name=op.f("ck_memory_evidence_source_type_length"),
        ),
        sa.CheckConstraint(
            "length(trust_classification) BETWEEN 1 AND 64",
            name=op.f("ck_memory_evidence_trust_classification_length"),
        ),
        sa.CheckConstraint(
            "octet_length(content_sha256) = 32",
            name=op.f("ck_memory_evidence_content_sha256_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(evidence_id)",
            name=op.f("ck_memory_evidence_evidence_id_uuid_v7"),
        ),
        sa.PrimaryKeyConstraint("evidence_id", name=op.f("pk_memory_evidence")),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "evidence_id", name="tenant_lineage_evidence"
        ),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memory_evidence_memory", "memory_evidence", ["tenant_id", "memory_id"], unique=False
    )
    op.create_table(
        "memory_links",
        sa.Column("link_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("source_memory_id", sa.Uuid(), nullable=False),
        sa.Column("target_memory_id", sa.Uuid(), nullable=False),
        sa.Column("link_type", sa.String(length=32), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'active'"), nullable=False
        ),
        sa.Column("created_event_id", sa.Uuid(), nullable=False),
        sa.Column("unlinked_event_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("unlinked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "(status = 'active' AND unlinked_event_id IS NULL AND unlinked_at IS NULL) OR (status = 'unlinked' AND unlinked_event_id IS NOT NULL AND unlinked_at IS NOT NULL)",
            name=op.f("ck_memory_links_unlink_status"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_memory_links_metadata_object")
        ),
        sa.CheckConstraint(
            "link_type IN ('supports', 'contradicts', 'refines', 'caused_by', 'associated_with', 'supersedes', 'part_of', 'forked_from')",
            name=op.f("ck_memory_links_link_type_values"),
        ),
        sa.CheckConstraint(
            "status IN ('active', 'unlinked')", name=op.f("ck_memory_links_status_values")
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(link_id)", name=op.f("ck_memory_links_link_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "source_memory_id <> target_memory_id", name=op.f("ck_memory_links_distinct_memories")
        ),
        sa.PrimaryKeyConstraint("link_id", name=op.f("pk_memory_links")),
        sa.UniqueConstraint("tenant_id", "lineage_id", "link_id", name="tenant_lineage_link"),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memory_links_target",
        "memory_links",
        ["tenant_id", "lineage_id", "target_memory_id"],
        unique=False,
    )
    op.create_index(
        "uq_memory_links_active",
        "memory_links",
        [
            "tenant_id",
            "lineage_id",
            "branch_id",
            "source_memory_id",
            "target_memory_id",
            "link_type",
        ],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_table(
        "outbox_jobs",
        sa.Column("job_id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("job_uuid", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("deduplication_key", sa.String(length=255), nullable=False),
        sa.Column("aggregate_type", sa.String(length=64), nullable=False),
        sa.Column("aggregate_id", sa.Uuid(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'pending'"), nullable=False
        ),
        sa.Column("priority", sa.SmallInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default=sa.text("8"), nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("last_error_summary", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL) OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)",
            name=op.f("ck_outbox_jobs_lease_state"),
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR state IN ('succeeded', 'dead')",
            name=op.f("ck_outbox_jobs_completion_state"),
        ),
        sa.CheckConstraint(
            "job_type IN ('embed_memory', 'check_duplicates', 'rebuild_projection', 'propose_consolidation', 'export_git_batch', 'expire_candidate', 'purge_payload', 'ingest_github_proposal', 'refresh_ingress_status', 'notify_relay_health')",
            name=op.f("ck_outbox_jobs_job_type_values"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_outbox_jobs_payload_object")
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'leased', 'succeeded', 'failed', 'dead')",
            name=op.f("ck_outbox_jobs_state_values"),
        ),
        sa.CheckConstraint(
            "attempt_count <= max_attempts", name=op.f("ck_outbox_jobs_attempts_bounded")
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 100",
            name=op.f("ck_outbox_jobs_attempts_range"),
        ),
        sa.CheckConstraint(
            "length(deduplication_key) BETWEEN 1 AND 255",
            name=op.f("ck_outbox_jobs_deduplication_key_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(job_uuid)", name=op.f("ck_outbox_jobs_job_uuid_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_outbox_jobs")),
        sa.UniqueConstraint(
            "tenant_id", "job_type", "deduplication_key", name="tenant_job_deduplication"
        ),
        sa.UniqueConstraint("tenant_id", "job_uuid", name="tenant_job_uuid"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_index(
        "ix_outbox_jobs_claim",
        "outbox_jobs",
        ["tenant_id", "available_at", "priority", "job_id"],
        unique=False,
        postgresql_where=sa.text("state = 'pending'"),
    )
    op.create_index(
        "ix_outbox_jobs_expired_lease",
        "outbox_jobs",
        ["lease_expires_at"],
        unique=False,
        postgresql_where=sa.text("state = 'leased'"),
    )
    op.create_table(
        "transport_installations",
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("route_key", postgresql.CITEXT(), nullable=False),
        sa.Column("relay_hostname", postgresql.CITEXT(), nullable=True),
        sa.Column("node_certificate_sha256", sa.LargeBinary(), nullable=True),
        sa.Column(
            "capability_profile",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "enrolled_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "health_state",
            sa.String(length=16),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "health_state IN ('unknown', 'healthy', 'degraded', 'offline')",
            name=op.f("ck_transport_installations_health_state_values"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(capability_profile) = 'object'",
            name=op.f("ck_transport_installations_capability_profile_object"),
        ),
        sa.CheckConstraint(
            "node_certificate_sha256 IS NULL OR octet_length(node_certificate_sha256) = 32",
            name=op.f("ck_transport_installations_certificate_hash_length"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= enrolled_at",
            name=op.f("ck_transport_installations_revocation_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(installation_id)",
            name=op.f("ck_transport_installations_installation_id_uuid_v7"),
        ),
        sa.PrimaryKeyConstraint("installation_id", name=op.f("pk_transport_installations")),
        sa.UniqueConstraint("route_key", name=op.f("uq_transport_installations_route_key")),
        sa.UniqueConstraint("tenant_id", "installation_id", name="tenant_installation"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "archive_export_checkpoints",
        sa.Column("checkpoint_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("archive_target_id", sa.Uuid(), nullable=False),
        sa.Column("previous_checkpoint_id", sa.Uuid(), nullable=True),
        sa.Column(
            "state", sa.String(length=16), server_default=sa.text("'preparing'"), nullable=False
        ),
        sa.Column("source_high_water_sequence", sa.BigInteger(), nullable=False),
        sa.Column("first_event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_count", sa.BigInteger(), nullable=False),
        sa.Column("previous_manifest_sha256", sa.LargeBinary(), nullable=True),
        sa.Column("manifest_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("manifest_path", sa.Text(), nullable=False),
        sa.Column("exporter_version", sa.String(length=64), nullable=False),
        sa.Column("postgres_timeline_id", sa.Integer(), nullable=True),
        sa.Column("git_commit_sha", sa.String(length=64), nullable=True),
        sa.Column("remote_git_commit_sha", sa.String(length=64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("safe_error_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "git_commit_sha IS NULL OR git_commit_sha ~ '^[0-9a-f]{40,64}$'",
            name=op.f("ck_archive_export_checkpoints_git_commit_sha_format"),
        ),
        sa.CheckConstraint(
            "remote_git_commit_sha IS NULL OR remote_git_commit_sha ~ '^[0-9a-f]{40,64}$'",
            name=op.f("ck_archive_export_checkpoints_remote_git_commit_sha_format"),
        ),
        sa.CheckConstraint(
            "state IN ('preparing', 'committed', 'pushed', 'failed')",
            name=op.f("ck_archive_export_checkpoints_state_values"),
        ),
        sa.CheckConstraint(
            "committed_at IS NULL OR committed_at >= started_at",
            name=op.f("ck_archive_export_checkpoints_commit_order"),
        ),
        sa.CheckConstraint(
            "event_count BETWEEN 1 AND (last_event_sequence - first_event_sequence + 1)",
            name=op.f("ck_archive_export_checkpoints_event_count_range"),
        ),
        sa.CheckConstraint(
            "first_event_sequence >= 1 AND last_event_sequence >= first_event_sequence",
            name=op.f("ck_archive_export_checkpoints_event_range"),
        ),
        sa.CheckConstraint(
            "octet_length(manifest_sha256) = 32",
            name=op.f("ck_archive_export_checkpoints_manifest_sha256_length"),
        ),
        sa.CheckConstraint(
            "previous_manifest_sha256 IS NULL OR octet_length(previous_manifest_sha256) = 32",
            name=op.f("ck_archive_export_checkpoints_previous_manifest_hash_length"),
        ),
        sa.CheckConstraint(
            "pushed_at IS NULL OR (committed_at IS NOT NULL AND pushed_at >= committed_at)",
            name=op.f("ck_archive_export_checkpoints_push_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(checkpoint_id)",
            name=op.f("ck_archive_export_checkpoints_checkpoint_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "source_high_water_sequence >= 0",
            name=op.f("ck_archive_export_checkpoints_high_water_nonnegative"),
        ),
        sa.CheckConstraint(
            "source_high_water_sequence >= last_event_sequence",
            name=op.f("ck_archive_export_checkpoints_high_water_covers_range"),
        ),
        sa.PrimaryKeyConstraint("checkpoint_id", name=op.f("pk_archive_export_checkpoints")),
        sa.UniqueConstraint(
            "tenant_id", "archive_target_id", "checkpoint_id", name="tenant_target_checkpoint"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "archive_target_id",
            "first_event_sequence",
            "last_event_sequence",
            name="tenant_target_range",
        ),
        sa.UniqueConstraint(
            "tenant_id", "archive_target_id", "manifest_sha256", name="tenant_target_manifest"
        ),
        sa.UniqueConstraint("tenant_id", "checkpoint_id", name="tenant_checkpoint"),
        info={"scalevault_tenant_owned": True, "scalevault_append_only": True},
    )
    op.create_index(
        "ix_archive_export_checkpoints_latest",
        "archive_export_checkpoints",
        ["tenant_id", "archive_target_id", "last_event_sequence"],
        unique=False,
    )
    op.create_index(
        "uq_archive_export_checkpoints_remote_commit",
        "archive_export_checkpoints",
        ["tenant_id", "archive_target_id", "remote_git_commit_sha"],
        unique=True,
        postgresql_where=sa.text("remote_git_commit_sha IS NOT NULL"),
    )
    op.create_table(
        "client_credentials",
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("public_hint", sa.String(length=128), nullable=True),
        sa.Column("secret_hash", sa.Text(), nullable=True),
        sa.Column("certificate_sha256", sa.LargeBinary(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(kind = 'bearer_token' AND secret_hash IS NOT NULL AND certificate_sha256 IS NULL) OR (kind = 'client_certificate' AND secret_hash IS NULL AND certificate_sha256 IS NOT NULL)",
            name=op.f("ck_client_credentials_material_matches_kind"),
        ),
        sa.CheckConstraint(
            "kind IN ('bearer_token', 'client_certificate')",
            name=op.f("ck_client_credentials_kind_values"),
        ),
        sa.CheckConstraint(
            "certificate_sha256 IS NULL OR octet_length(certificate_sha256) = 32",
            name=op.f("ck_client_credentials_certificate_hash_length"),
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name=op.f("ck_client_credentials_expiry_order"),
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_client_credentials_revocation_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(credential_id)",
            name=op.f("ck_client_credentials_credential_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "secret_hash IS NULL OR length(secret_hash) BETWEEN 16 AND 512",
            name=op.f("ck_client_credentials_secret_hash_length"),
        ),
        sa.PrimaryKeyConstraint("credential_id", name=op.f("pk_client_credentials")),
        sa.UniqueConstraint("tenant_id", "credential_id", name="tenant_credential"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_index(
        "uq_client_credentials_active_public_hint",
        "client_credentials",
        ["tenant_id", "kind", "public_hint"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL AND public_hint IS NOT NULL"),
    )
    op.create_table(
        "command_receipts",
        sa.Column("receipt_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("command_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=True),
        sa.Column("memory_revision", sa.BigInteger(), nullable=True),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("result_canonical", sa.LargeBinary(), nullable=False),
        sa.Column("result_sha256", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(result) = 'object'", name=op.f("ck_command_receipts_result_object")
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 255",
            name=op.f("ck_command_receipts_idempotency_key_length"),
        ),
        sa.CheckConstraint(
            "memory_revision IS NULL OR memory_revision >= 1",
            name=op.f("ck_command_receipts_memory_revision_positive"),
        ),
        sa.CheckConstraint(
            "octet_length(command_sha256) = 32",
            name=op.f("ck_command_receipts_command_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(result_canonical) BETWEEN 2 AND 1048576",
            name=op.f("ck_command_receipts_result_canonical_length"),
        ),
        sa.CheckConstraint(
            "octet_length(result_sha256) = 32",
            name=op.f("ck_command_receipts_result_sha256_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(receipt_id)", name=op.f("ck_command_receipts_receipt_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f("pk_command_receipts")),
        sa.UniqueConstraint(
            "tenant_id",
            "client_id",
            "idempotency_key",
            name="command_receipts_tenant_client_idempotency",
        ),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="tenant_receipt"),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )
    op.create_table(
        "personas",
        sa.Column("persona_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("slug", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column(
            "baseline_policy",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(baseline_policy) = 'object'",
            name=op.f("ck_personas_baseline_policy_object"),
        ),
        sa.CheckConstraint(
            "retired_at IS NULL OR retired_at >= created_at",
            name=op.f("ck_personas_retirement_order"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(persona_id)", name=op.f("ck_personas_persona_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("persona_id", name=op.f("pk_personas")),
        sa.UniqueConstraint("tenant_id", "actor_id", name="personas_tenant_actor"),
        sa.UniqueConstraint("tenant_id", "persona_id", name="tenant_persona"),
        sa.UniqueConstraint("tenant_id", "slug", name="tenant_slug"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "transport_bindings",
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("transport_kind", sa.String(length=32), nullable=False),
        sa.Column("disclosure_boundary", sa.String(length=32), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=True),
        sa.Column("authorized_operations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(transport_kind = 'direct_private' AND disclosure_boundary = 'private_node') OR (transport_kind = 'secure_tunnel' AND disclosure_boundary = 'openai_secure_tunnel') OR (transport_kind = 'relay' AND disclosure_boundary = 'public_relay') OR (transport_kind = 'github_ingress' AND disclosure_boundary = 'github_com') OR (transport_kind = 'internal_service' AND disclosure_boundary = 'internal') OR (transport_kind = 'archive_restore' AND disclosure_boundary = 'archive')",
            name=op.f("ck_transport_bindings_transport_disclosure_pair"),
        ),
        sa.CheckConstraint(
            "disclosure_boundary IN ('private_node', 'openai_secure_tunnel', 'public_relay', 'github_com', 'internal', 'archive')",
            name=op.f("ck_transport_bindings_disclosure_boundary_values"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(authorized_operations) = 'object'",
            name=op.f("ck_transport_bindings_authorized_operations_object"),
        ),
        sa.CheckConstraint(
            "transport_kind <> 'relay' OR installation_id IS NOT NULL",
            name=op.f("ck_transport_bindings_relay_has_installation"),
        ),
        sa.CheckConstraint(
            "transport_kind IN ('direct_private', 'secure_tunnel', 'relay', 'github_ingress', 'internal_service', 'archive_restore')",
            name=op.f("ck_transport_bindings_transport_kind_values"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(transport_binding_id)",
            name=op.f("ck_transport_bindings_binding_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "valid_until IS NULL OR valid_until > created_at",
            name=op.f("ck_transport_bindings_validity_order"),
        ),
        sa.PrimaryKeyConstraint("transport_binding_id", name=op.f("pk_transport_bindings")),
        sa.UniqueConstraint(
            "tenant_id",
            "transport_binding_id",
            "actor_id",
            "client_id",
            name="tenant_binding_actor_client",
        ),
        sa.UniqueConstraint("tenant_id", "transport_binding_id", name="tenant_binding"),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )
    op.create_table(
        "lineages",
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("persona_id", sa.Uuid(), nullable=False),
        sa.Column("name", postgresql.CITEXT(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(lineage_id)", name=op.f("ck_lineages_lineage_id_uuid_v7")
        ),
        sa.CheckConstraint(
            "sealed_at IS NULL OR sealed_at >= created_at", name=op.f("ck_lineages_seal_order")
        ),
        sa.PrimaryKeyConstraint("lineage_id", name=op.f("pk_lineages")),
        sa.UniqueConstraint("tenant_id", "lineage_id", "persona_id", name="tenant_lineage_persona"),
        sa.UniqueConstraint("tenant_id", "lineage_id", name="tenant_lineage"),
        sa.UniqueConstraint("tenant_id", "persona_id", "name", name="tenant_persona_name"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "subjects",
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("canonical_key", postgresql.CITEXT(), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("persona_id", sa.Uuid(), nullable=True),
        sa.Column("relationship_actor_id", sa.Uuid(), nullable=True),
        sa.Column("project_ref", sa.Text(), nullable=True),
        sa.Column("episode_ref", sa.Text(), nullable=True),
        sa.Column("origin_session_id", sa.Uuid(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(kind IN ('global', 'concept') AND persona_id IS NULL AND relationship_actor_id IS NULL AND project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR (kind = 'persona' AND persona_id IS NOT NULL AND relationship_actor_id IS NULL AND project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR (kind = 'relationship' AND persona_id IS NULL AND relationship_actor_id IS NOT NULL AND project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR (kind = 'project' AND persona_id IS NULL AND relationship_actor_id IS NULL AND project_ref IS NOT NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR (kind = 'episode' AND persona_id IS NULL AND relationship_actor_id IS NULL AND project_ref IS NULL AND episode_ref IS NOT NULL AND origin_session_id IS NULL) OR (kind = 'scene' AND persona_id IS NULL AND relationship_actor_id IS NULL AND project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NOT NULL)",
            name=op.f("ck_subjects_kind_anchor_shape"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_subjects_metadata_object")
        ),
        sa.CheckConstraint(
            "kind IN ('global', 'persona', 'relationship', 'project', 'episode', 'scene', 'concept')",
            name=op.f("ck_subjects_kind_values"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(subject_id)", name=op.f("ck_subjects_subject_id_uuid_v7")
        ),
        sa.PrimaryKeyConstraint("subject_id", name=op.f("pk_subjects")),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "kind", "canonical_key", name="tenant_lineage_kind_key"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "subject_id",
            "kind",
            "origin_session_id",
            name="tenant_lineage_subject_kind_session",
        ),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "subject_id", "kind", name="tenant_lineage_subject_kind"
        ),
        sa.UniqueConstraint("tenant_id", "lineage_id", "subject_id", name="tenant_lineage_subject"),
        info={
            "scalevault_tenant_owned": True,
            "scalevault_immutable_fields": (
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
            ),
        },
    )
    op.create_table(
        "memory_conflicts",
        sa.Column("conflict_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default=sa.text("'open'"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("resolution_kind", sa.String(length=64), nullable=True),
        sa.Column("resolution_rationale", sa.Text(), nullable=True),
        sa.Column("opened_event_id", sa.Uuid(), nullable=False),
        sa.Column("resolution_event_id", sa.Uuid(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "(status = 'open' AND resolution_event_id IS NULL AND resolved_at IS NULL AND resolution_kind IS NULL AND resolution_rationale IS NULL) OR (status = 'resolved' AND resolution_event_id IS NOT NULL AND resolved_at IS NOT NULL AND resolution_kind IS NOT NULL)",
            name=op.f("ck_memory_conflicts_resolution_status"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_memory_conflicts_metadata_object")
        ),
        sa.CheckConstraint(
            "status IN ('open', 'resolved')", name=op.f("ck_memory_conflicts_status_values")
        ),
        sa.CheckConstraint(
            "length(reason) BETWEEN 1 AND 4096", name=op.f("ck_memory_conflicts_reason_length")
        ),
        sa.CheckConstraint(
            "resolution_kind IS NULL OR length(resolution_kind) BETWEEN 1 AND 64",
            name=op.f("ck_memory_conflicts_resolution_kind_length"),
        ),
        sa.CheckConstraint(
            "resolution_rationale IS NULL OR length(resolution_rationale) <= 4096",
            name=op.f("ck_memory_conflicts_resolution_rationale_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(conflict_id)",
            name=op.f("ck_memory_conflicts_conflict_id_uuid_v7"),
        ),
        sa.PrimaryKeyConstraint("conflict_id", name=op.f("pk_memory_conflicts")),
        sa.UniqueConstraint(
            "tenant_id", "lineage_id", "conflict_id", name="tenant_lineage_conflict"
        ),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memory_conflicts_open",
        "memory_conflicts",
        ["tenant_id", "lineage_id", "branch_id", "subject_id"],
        unique=False,
        postgresql_where=sa.text("status = 'open'"),
    )
    op.create_table(
        "subject_aliases",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("alias", postgresql.CITEXT(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(btrim(alias::text)) BETWEEN 1 AND 256",
            name=op.f("ck_subject_aliases_alias_length"),
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "lineage_id", "subject_id", "alias", name=op.f("pk_subject_aliases")
        ),
        sa.UniqueConstraint("tenant_id", "lineage_id", "alias", name="tenant_lineage_alias"),
        info={"scalevault_tenant_owned": True},
    )
    op.create_table(
        "memory_conflict_members",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("conflict_id", sa.Uuid(), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=False),
        sa.Column("disposition", sa.String(length=64), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "length(disposition) BETWEEN 1 AND 64",
            name=op.f("ck_memory_conflict_members_disposition_length"),
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "lineage_id",
            "conflict_id",
            "memory_id",
            name=op.f("pk_memory_conflict_members"),
        ),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memory_conflict_members_memory",
        "memory_conflict_members",
        ["tenant_id", "lineage_id", "memory_id"],
        unique=False,
    )
    op.create_foreign_key(
        "lineage",
        "branches",
        "lineages",
        ["tenant_id", "lineage_id"],
        ["tenant_id", "lineage_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fork_event",
        "branches",
        "memory_events",
        ["tenant_id", "lineage_id", "parent_branch_id", "fork_event_sequence"],
        ["tenant_id", "lineage_id", "branch_id", "sequence"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "parent_branch",
        "branches",
        "branches",
        ["tenant_id", "lineage_id", "parent_branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "result_event",
        "ingress_items",
        "memory_events",
        ["tenant_id", "result_event_id"],
        ["tenant_id", "event_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "installation",
        "ingress_items",
        "transport_installations",
        ["tenant_id", "installation_id"],
        ["tenant_id", "installation_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "transport_binding",
        "ingress_items",
        "transport_bindings",
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "last_event",
        "memories",
        "memory_events",
        ["tenant_id", "lineage_id", "last_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "origin_session",
        "memories",
        "sessions",
        ["tenant_id", "origin_session_id", "lineage_id", "branch_id"],
        ["tenant_id", "session_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "content_key",
        "memories",
        "memory_content_keys",
        ["tenant_id", "lineage_id", "content_key_id"],
        ["tenant_id", "lineage_id", "content_key_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "subject",
        "memories",
        "subjects",
        ["tenant_id", "lineage_id", "subject_id", "subject_kind"],
        ["tenant_id", "lineage_id", "subject_id", "kind"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "publication_actor",
        "memories",
        "actors",
        ["tenant_id", "publication_approved_by_actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "memories",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "memory",
        "memory_content_keys",
        "memories",
        ["tenant_id", "lineage_id", "memory_id"],
        ["tenant_id", "lineage_id", "memory_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "actor",
        "memory_events",
        "actors",
        ["tenant_id", "actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "client",
        "memory_events",
        "clients",
        ["tenant_id", "client_id"],
        ["tenant_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "transport_binding",
        "memory_events",
        "transport_bindings",
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "ingress",
        "memory_events",
        "ingress_items",
        ["tenant_id", "ingress_id"],
        ["tenant_id", "ingress_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "session",
        "memory_events",
        "sessions",
        ["tenant_id", "session_id", "lineage_id", "branch_id", "actor_id", "client_id"],
        ["tenant_id", "session_id", "lineage_id", "branch_id", "actor_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "causation_event",
        "memory_events",
        "memory_events",
        ["tenant_id", "lineage_id", "causation_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "memory_events",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
        initially="DEFERRED",
        deferrable=True,
    )
    op.create_foreign_key(
        "actor",
        "sessions",
        "actors",
        ["tenant_id", "actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "transport_binding",
        "sessions",
        "transport_bindings",
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "sessions",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "client",
        "sessions",
        "clients",
        ["tenant_id", "client_id"],
        ["tenant_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "tenant", "actors", "tenants", ["tenant_id"], ["tenant_id"], ondelete="RESTRICT"
    )
    op.create_foreign_key(
        "tenant", "archive_targets", "tenants", ["tenant_id"], ["tenant_id"], ondelete="RESTRICT"
    )
    op.create_foreign_key(
        "tenant", "clients", "tenants", ["tenant_id"], ["tenant_id"], ondelete="RESTRICT"
    )
    op.create_foreign_key(
        "tenant", "embedding_models", "tenants", ["tenant_id"], ["tenant_id"], ondelete="RESTRICT"
    )
    op.create_foreign_key(
        "source_event",
        "memory_evidence",
        "memory_events",
        ["tenant_id", "lineage_id", "source_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "memory_evidence",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "memory",
        "memory_evidence",
        "memories",
        ["tenant_id", "lineage_id", "memory_id"],
        ["tenant_id", "lineage_id", "memory_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "created_event",
        "memory_links",
        "memory_events",
        ["tenant_id", "lineage_id", "created_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "memory_links",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "target_memory",
        "memory_links",
        "memories",
        ["tenant_id", "lineage_id", "target_memory_id"],
        ["tenant_id", "lineage_id", "memory_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "source_memory",
        "memory_links",
        "memories",
        ["tenant_id", "lineage_id", "source_memory_id"],
        ["tenant_id", "lineage_id", "memory_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "unlinked_event",
        "memory_links",
        "memory_events",
        ["tenant_id", "lineage_id", "unlinked_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "tenant", "outbox_jobs", "tenants", ["tenant_id"], ["tenant_id"], ondelete="RESTRICT"
    )
    op.create_foreign_key(
        "tenant",
        "transport_installations",
        "tenants",
        ["tenant_id"],
        ["tenant_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "previous_checkpoint",
        "archive_export_checkpoints",
        "archive_export_checkpoints",
        ["tenant_id", "archive_target_id", "previous_checkpoint_id"],
        ["tenant_id", "archive_target_id", "checkpoint_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "archive_target",
        "archive_export_checkpoints",
        "archive_targets",
        ["tenant_id", "archive_target_id"],
        ["tenant_id", "archive_target_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "client",
        "client_credentials",
        "clients",
        ["tenant_id", "client_id"],
        ["tenant_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "event",
        "command_receipts",
        "memory_events",
        ["tenant_id", "event_id"],
        ["tenant_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "client",
        "command_receipts",
        "clients",
        ["tenant_id", "client_id"],
        ["tenant_id", "client_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "actor",
        "personas",
        "actors",
        ["tenant_id", "actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "installation",
        "transport_bindings",
        "transport_installations",
        ["tenant_id", "installation_id"],
        ["tenant_id", "installation_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "actor",
        "transport_bindings",
        "actors",
        ["tenant_id", "actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "client_transport",
        "transport_bindings",
        "clients",
        ["tenant_id", "client_id", "transport_kind"],
        ["tenant_id", "client_id", "transport_kind"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "persona",
        "lineages",
        "personas",
        ["tenant_id", "persona_id"],
        ["tenant_id", "persona_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "origin_session",
        "subjects",
        "sessions",
        ["tenant_id", "origin_session_id", "lineage_id"],
        ["tenant_id", "session_id", "lineage_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "lineage_persona",
        "subjects",
        "lineages",
        ["tenant_id", "lineage_id", "persona_id"],
        ["tenant_id", "lineage_id", "persona_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "lineage",
        "subjects",
        "lineages",
        ["tenant_id", "lineage_id"],
        ["tenant_id", "lineage_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "relationship_actor",
        "subjects",
        "actors",
        ["tenant_id", "relationship_actor_id"],
        ["tenant_id", "actor_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "subject",
        "memory_conflicts",
        "subjects",
        ["tenant_id", "lineage_id", "subject_id"],
        ["tenant_id", "lineage_id", "subject_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "resolution_event",
        "memory_conflicts",
        "memory_events",
        ["tenant_id", "lineage_id", "resolution_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "branch",
        "memory_conflicts",
        "branches",
        ["tenant_id", "lineage_id", "branch_id"],
        ["tenant_id", "lineage_id", "branch_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "opened_event",
        "memory_conflicts",
        "memory_events",
        ["tenant_id", "lineage_id", "opened_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "subject",
        "subject_aliases",
        "subjects",
        ["tenant_id", "lineage_id", "subject_id"],
        ["tenant_id", "lineage_id", "subject_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "last_event",
        "memory_conflict_members",
        "memory_events",
        ["tenant_id", "lineage_id", "last_event_id"],
        ["tenant_id", "lineage_id", "event_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "conflict",
        "memory_conflict_members",
        "memory_conflicts",
        ["tenant_id", "lineage_id", "conflict_id"],
        ["tenant_id", "lineage_id", "conflict_id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "memory",
        "memory_conflict_members",
        "memories",
        ["tenant_id", "lineage_id", "memory_id"],
        ["tenant_id", "lineage_id", "memory_id"],
        ondelete="RESTRICT",
    )
    # ### end Alembic commands ###
    op.execute(
        sa.text("INSERT INTO memory_event_counter (counter_id, next_sequence) VALUES (1, 1)")
    )
    op.execute(
        sa.text(
            "INSERT INTO alembic_compatibility "
            "(component, contract_version, minimum_reader_revision, minimum_writer_revision) "
            "VALUES ('memory_node', 1, '0001_initial_domain', '0001_initial_domain')"
        )
    )
    _create_immutability_barriers()
    _create_branch_visibility_barrier()
    _enable_tenant_rls()


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint("memory", "memory_conflict_members", type_="foreignkey")
    op.drop_constraint("conflict", "memory_conflict_members", type_="foreignkey")
    op.drop_constraint("last_event", "memory_conflict_members", type_="foreignkey")
    op.drop_constraint("subject", "subject_aliases", type_="foreignkey")
    op.drop_constraint("opened_event", "memory_conflicts", type_="foreignkey")
    op.drop_constraint("branch", "memory_conflicts", type_="foreignkey")
    op.drop_constraint("resolution_event", "memory_conflicts", type_="foreignkey")
    op.drop_constraint("subject", "memory_conflicts", type_="foreignkey")
    op.drop_constraint("relationship_actor", "subjects", type_="foreignkey")
    op.drop_constraint("lineage", "subjects", type_="foreignkey")
    op.drop_constraint("lineage_persona", "subjects", type_="foreignkey")
    op.drop_constraint("origin_session", "subjects", type_="foreignkey")
    op.drop_constraint("persona", "lineages", type_="foreignkey")
    op.drop_constraint("client_transport", "transport_bindings", type_="foreignkey")
    op.drop_constraint("actor", "transport_bindings", type_="foreignkey")
    op.drop_constraint("installation", "transport_bindings", type_="foreignkey")
    op.drop_constraint("actor", "personas", type_="foreignkey")
    op.drop_constraint("client", "command_receipts", type_="foreignkey")
    op.drop_constraint("event", "command_receipts", type_="foreignkey")
    op.drop_constraint("client", "client_credentials", type_="foreignkey")
    op.drop_constraint("archive_target", "archive_export_checkpoints", type_="foreignkey")
    op.drop_constraint("previous_checkpoint", "archive_export_checkpoints", type_="foreignkey")
    op.drop_constraint("tenant", "transport_installations", type_="foreignkey")
    op.drop_constraint("tenant", "outbox_jobs", type_="foreignkey")
    op.drop_constraint("unlinked_event", "memory_links", type_="foreignkey")
    op.drop_constraint("source_memory", "memory_links", type_="foreignkey")
    op.drop_constraint("target_memory", "memory_links", type_="foreignkey")
    op.drop_constraint("branch", "memory_links", type_="foreignkey")
    op.drop_constraint("created_event", "memory_links", type_="foreignkey")
    op.drop_constraint("memory", "memory_evidence", type_="foreignkey")
    op.drop_constraint("branch", "memory_evidence", type_="foreignkey")
    op.drop_constraint("source_event", "memory_evidence", type_="foreignkey")
    op.drop_constraint("tenant", "embedding_models", type_="foreignkey")
    op.drop_constraint("tenant", "clients", type_="foreignkey")
    op.drop_constraint("tenant", "archive_targets", type_="foreignkey")
    op.drop_constraint("tenant", "actors", type_="foreignkey")
    op.drop_constraint("client", "sessions", type_="foreignkey")
    op.drop_constraint("branch", "sessions", type_="foreignkey")
    op.drop_constraint("transport_binding", "sessions", type_="foreignkey")
    op.drop_constraint("actor", "sessions", type_="foreignkey")
    op.drop_constraint("branch", "memory_events", type_="foreignkey")
    op.drop_constraint("causation_event", "memory_events", type_="foreignkey")
    op.drop_constraint("session", "memory_events", type_="foreignkey")
    op.drop_constraint("ingress", "memory_events", type_="foreignkey")
    op.drop_constraint("transport_binding", "memory_events", type_="foreignkey")
    op.drop_constraint("client", "memory_events", type_="foreignkey")
    op.drop_constraint("actor", "memory_events", type_="foreignkey")
    op.drop_constraint("memory", "memory_content_keys", type_="foreignkey")
    op.drop_constraint("branch", "memories", type_="foreignkey")
    op.drop_constraint("publication_actor", "memories", type_="foreignkey")
    op.drop_constraint("subject", "memories", type_="foreignkey")
    op.drop_constraint("content_key", "memories", type_="foreignkey")
    op.drop_constraint("origin_session", "memories", type_="foreignkey")
    op.drop_constraint("last_event", "memories", type_="foreignkey")
    op.drop_constraint("transport_binding", "ingress_items", type_="foreignkey")
    op.drop_constraint("installation", "ingress_items", type_="foreignkey")
    op.drop_constraint("result_event", "ingress_items", type_="foreignkey")
    op.drop_constraint("parent_branch", "branches", type_="foreignkey")
    op.drop_constraint("fork_event", "branches", type_="foreignkey")
    op.drop_constraint("lineage", "branches", type_="foreignkey")
    op.drop_index("ix_memory_conflict_members_memory", table_name="memory_conflict_members")
    op.drop_table("memory_conflict_members")
    op.drop_table("subject_aliases")
    op.drop_index(
        "ix_memory_conflicts_open",
        table_name="memory_conflicts",
        postgresql_where=sa.text("status = 'open'"),
    )
    op.drop_table("memory_conflicts")
    op.drop_table("subjects")
    op.drop_table("lineages")
    op.drop_table("transport_bindings")
    op.drop_table("personas")
    op.drop_table("command_receipts")
    op.drop_index(
        "uq_client_credentials_active_public_hint",
        table_name="client_credentials",
        postgresql_where=sa.text("revoked_at IS NULL AND public_hint IS NOT NULL"),
    )
    op.drop_table("client_credentials")
    op.drop_index(
        "uq_archive_export_checkpoints_remote_commit",
        table_name="archive_export_checkpoints",
        postgresql_where=sa.text("remote_git_commit_sha IS NOT NULL"),
    )
    op.drop_index("ix_archive_export_checkpoints_latest", table_name="archive_export_checkpoints")
    op.drop_table("archive_export_checkpoints")
    op.drop_table("transport_installations")
    op.drop_index(
        "ix_outbox_jobs_expired_lease",
        table_name="outbox_jobs",
        postgresql_where=sa.text("state = 'leased'"),
    )
    op.drop_index(
        "ix_outbox_jobs_claim",
        table_name="outbox_jobs",
        postgresql_where=sa.text("state = 'pending'"),
    )
    op.drop_table("outbox_jobs")
    op.drop_index(
        "uq_memory_links_active",
        table_name="memory_links",
        postgresql_where=sa.text("status = 'active'"),
    )
    op.drop_index("ix_memory_links_target", table_name="memory_links")
    op.drop_table("memory_links")
    op.drop_index("ix_memory_evidence_memory", table_name="memory_evidence")
    op.drop_table("memory_evidence")
    op.drop_index(
        "uq_embedding_models_active",
        table_name="embedding_models",
        postgresql_where=sa.text("state = 'approved' AND retired_at IS NULL"),
    )
    op.drop_table("embedding_models")
    op.drop_table("clients")
    op.drop_table("archive_targets")
    op.drop_table("actors")
    op.drop_table("tenants")
    op.drop_index(
        "uq_sessions_conversation_ref",
        table_name="sessions",
        postgresql_where=sa.text("conversation_ref IS NOT NULL"),
    )
    op.drop_table("sessions")
    op.drop_index("ix_memory_events_memory_sequence", table_name="memory_events")
    op.drop_index("ix_memory_events_correlation", table_name="memory_events")
    op.drop_index("ix_memory_events_branch_sequence", table_name="memory_events")
    op.drop_table("memory_events")
    op.drop_table("memory_event_counter")
    op.drop_table("memory_content_keys")
    op.drop_index(
        "uq_memories_live_fingerprint",
        table_name="memories",
        postgresql_where=sa.text("status IN ('candidate', 'active', 'disputed')"),
    )
    op.drop_index("ix_memories_subject", table_name="memories")
    op.drop_index(
        "ix_memories_statement_trgm",
        table_name="memories",
        postgresql_using="gin",
        postgresql_ops={"statement": "gin_trgm_ops"},
    )
    op.drop_index("ix_memories_search_document", table_name="memories", postgresql_using="gin")
    op.drop_index("ix_memories_retrieval", table_name="memories")
    op.drop_table("memories")
    op.drop_index("ix_ingress_items_claim", table_name="ingress_items")
    op.drop_table("ingress_items")
    op.drop_index(
        "uq_branches_one_root_per_lineage",
        table_name="branches",
        postgresql_where=sa.text("parent_branch_id IS NULL"),
    )
    op.drop_index("ix_branches_parent", table_name="branches")
    op.drop_table("branches")
    op.drop_table("alembic_compatibility")
    # ### end Alembic commands ###
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_branch_visibility()"))
    op.execute(sa.text("DROP FUNCTION public.scalevault_reject_immutable_field_mutation()"))
    op.execute(sa.text("DROP FUNCTION public.scalevault_reject_immutable_mutation()"))
    op.execute(sa.text("DROP FUNCTION public.scalevault_is_uuid_v7(uuid)"))
