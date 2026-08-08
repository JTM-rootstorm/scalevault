"""Add fixed-dimension hybrid retrieval storage.

Revision ID: 0002_hybrid_retrieval
Revises: 0001_initial_domain
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision: str = "0002_hybrid_retrieval"
down_revision: str | None = "0001_initial_domain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_EXPRESSION = (
    "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
)


def upgrade() -> None:
    op.create_check_constraint(
        op.f("ck_embedding_models_lifecycle_state"),
        "embedding_models",
        "(state IN ('registered', 'evaluating') AND activated_at IS NULL "
        "AND retired_at IS NULL) OR "
        "(state = 'approved' AND activated_at IS NOT NULL AND retired_at IS NULL) OR "
        "(state = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL "
        "AND retired_at >= activated_at) OR "
        "(state = 'rejected' AND activated_at IS NULL AND retired_at IS NULL)",
    )
    op.create_index(
        "ix_memory_events_branch_created_at",
        "memory_events",
        ["tenant_id", "lineage_id", "branch_id", "created_at", "sequence"],
        unique=False,
    )
    op.create_index(
        "ix_sessions_project_ref",
        "sessions",
        ["tenant_id", "lineage_id", "branch_id", "project_ref"],
        unique=False,
        postgresql_where=sa.text("project_ref IS NOT NULL"),
    )
    op.create_index(
        "ix_subjects_display_name_trgm",
        "subjects",
        ["display_name"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"display_name": "gin_trgm_ops"},
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_subjects_canonical_key_trgm ON public.subjects "
            "USING gin ((canonical_key::text) gin_trgm_ops)"
        )
    )
    op.create_index(
        "ix_subjects_project_ref",
        "subjects",
        ["tenant_id", "lineage_id", "project_ref"],
        unique=False,
        postgresql_where=sa.text("project_ref IS NOT NULL"),
    )
    op.create_index(
        "ix_subjects_relationship_actor",
        "subjects",
        ["tenant_id", "lineage_id", "relationship_actor_id"],
        unique=False,
        postgresql_where=sa.text("relationship_actor_id IS NOT NULL"),
    )
    op.create_index(
        "ix_subjects_origin_session",
        "subjects",
        ["tenant_id", "lineage_id", "origin_session_id"],
        unique=False,
        postgresql_where=sa.text("origin_session_id IS NOT NULL"),
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_subject_aliases_alias_trgm ON public.subject_aliases "
            "USING gin ((alias::text) gin_trgm_ops)"
        )
    )

    op.create_table(
        "memory_embeddings_v1",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=False),
        sa.Column("embedding_model_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("source_memory_revision", sa.Integer(), nullable=False),
        sa.Column("source_event_id", sa.Uuid(), nullable=False),
        sa.Column("input_contract_version", sa.String(length=64), nullable=False),
        sa.Column("source_content_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("input_truncated", sa.Boolean(), nullable=False),
        sa.Column("embedding", Vector(384), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "vector_dims(embedding) = 384",
            name=op.f("ck_memory_embeddings_v1_embedding_dimension"),
        ),
        sa.CheckConstraint(
            "abs(vector_norm(embedding) - 1.0) <= 0.001",
            name=op.f("ck_memory_embeddings_v1_embedding_unit_norm"),
        ),
        sa.CheckConstraint(
            "input_contract_version = 'memory-statement-embedding-v1'",
            name=op.f("ck_memory_embeddings_v1_input_contract_version"),
        ),
        sa.CheckConstraint(
            "octet_length(source_content_sha256) = 32",
            name=op.f("ck_memory_embeddings_v1_source_content_sha256_length"),
        ),
        sa.CheckConstraint(
            "source_memory_revision >= 1",
            name=op.f("ck_memory_embeddings_v1_source_memory_revision_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "embedding_model_id"],
            ["embedding_models.tenant_id", "embedding_models.embedding_model_id"],
            name="embedding_model",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "source_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="source_event",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id", "memory_id", "embedding_model_id", name=op.f("pk_memory_embeddings_v1")
        ),
        info={"scalevault_tenant_owned": True, "scalevault_projection": True},
    )
    op.create_index(
        "ix_memory_embeddings_v1_filter",
        "memory_embeddings_v1",
        ["tenant_id", "lineage_id", "branch_id", "embedding_model_id"],
        unique=False,
    )
    op.create_index(
        "ix_memory_embeddings_v1_hnsw_cosine",
        "memory_embeddings_v1",
        ["embedding"],
        unique=False,
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
        postgresql_with={"m": 16, "ef_construction": 64},
    )
    op.execute(sa.text("ALTER TABLE public.memory_embeddings_v1 ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.memory_embeddings_v1 FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY scalevault_tenant_isolation ON public.memory_embeddings_v1 "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 2, "
            "minimum_reader_revision = '0002_hybrid_retrieval', "
            "minimum_writer_revision = '0002_hybrid_retrieval' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 1, "
            "minimum_reader_revision = '0001_initial_domain', "
            "minimum_writer_revision = '0001_initial_domain' "
            "WHERE component = 'memory_node'"
        )
    )
    op.drop_table("memory_embeddings_v1")
    op.execute(sa.text("DROP INDEX public.ix_subject_aliases_alias_trgm"))
    op.drop_index(
        "ix_subjects_origin_session",
        table_name="subjects",
        postgresql_where=sa.text("origin_session_id IS NOT NULL"),
    )
    op.drop_index(
        "ix_subjects_relationship_actor",
        table_name="subjects",
        postgresql_where=sa.text("relationship_actor_id IS NOT NULL"),
    )
    op.drop_index(
        "ix_subjects_project_ref",
        table_name="subjects",
        postgresql_where=sa.text("project_ref IS NOT NULL"),
    )
    op.execute(sa.text("DROP INDEX public.ix_subjects_canonical_key_trgm"))
    op.drop_index(
        "ix_subjects_display_name_trgm",
        table_name="subjects",
        postgresql_using="gin",
        postgresql_ops={"display_name": "gin_trgm_ops"},
    )
    op.drop_index(
        "ix_sessions_project_ref",
        table_name="sessions",
        postgresql_where=sa.text("project_ref IS NOT NULL"),
    )
    op.drop_index("ix_memory_events_branch_created_at", table_name="memory_events")
    op.drop_constraint(
        op.f("ck_embedding_models_lifecycle_state"),
        "embedding_models",
        type_="check",
    )
