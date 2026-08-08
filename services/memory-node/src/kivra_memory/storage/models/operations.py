"""Embedding registry, outbox delivery, and archive checkpoint models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY, Base
from kivra_memory.storage.models._shared import (
    TENANT_TABLE_ARGS,
    json_object_check,
    sha256_check,
    uuid_v7_check,
    values_check,
)


class EmbeddingModel(Base):
    __tablename__ = "embedding_models"
    __table_args__ = (
        UniqueConstraint("tenant_id", "embedding_model_id", name="tenant_embedding_model"),
        UniqueConstraint("tenant_id", "artifact_sha256", name="tenant_artifact"),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check(
            "state",
            ("registered", "evaluating", "approved", "retired", "rejected"),
            name="state_values",
        ),
        values_check(
            "distance_metric", ("cosine", "inner_product", "l2"), name="distance_metric_values"
        ),
        CheckConstraint("dimension BETWEEN 1 AND 65535", name="dimension_range"),
        CheckConstraint(
            "activated_at IS NULL OR activated_at >= created_at", name="activation_order"
        ),
        CheckConstraint("retired_at IS NULL OR retired_at >= created_at", name="retirement_order"),
        CheckConstraint(
            "(state IN ('registered', 'evaluating') AND activated_at IS NULL "
            "AND retired_at IS NULL) OR "
            "(state = 'approved' AND activated_at IS NOT NULL AND retired_at IS NULL) OR "
            "(state = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL "
            "AND retired_at >= activated_at) OR "
            "(state = 'rejected' AND activated_at IS NULL AND retired_at IS NULL)",
            name="lifecycle_state",
        ),
        sha256_check("artifact_sha256", name="artifact_sha256_length"),
        json_object_check("tokenizer_details", name="tokenizer_details_object"),
        json_object_check("runtime_details", name="runtime_details_object"),
        json_object_check("normalization_settings", name="normalization_settings_object"),
        uuid_v7_check("embedding_model_id", name="embedding_model_id_uuid_v7"),
        Index(
            "uq_embedding_models_active",
            "tenant_id",
            unique=True,
            postgresql_where=text("state = 'approved' AND retired_at IS NULL"),
        ),
        TENANT_TABLE_ARGS,
    )

    embedding_model_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    artifact_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    dimension: Mapped[int] = mapped_column(Integer(), nullable=False)
    distance_metric: Mapped[str] = mapped_column(String(16), nullable=False)
    tokenizer_details: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    runtime_details: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    normalization_settings: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'registered'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MemoryEmbeddingV1(Base):
    """Current 384-dimensional embedding for one memory and model."""

    __tablename__ = "memory_embeddings_v1"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "embedding_model_id"],
            ["embedding_models.tenant_id", "embedding_models.embedding_model_id"],
            name="embedding_model",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "source_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="source_event",
            ondelete="RESTRICT",
        ),
        CheckConstraint("source_memory_revision >= 1", name="source_memory_revision_positive"),
        CheckConstraint(
            "input_contract_version = 'memory-statement-embedding-v1'",
            name="input_contract_version",
        ),
        sha256_check("source_content_sha256", name="source_content_sha256_length"),
        CheckConstraint("vector_dims(embedding) = 384", name="embedding_dimension"),
        CheckConstraint(
            "abs(vector_norm(embedding) - 1.0) <= 0.001",
            name="embedding_unit_norm",
        ),
        Index(
            "ix_memory_embeddings_v1_filter",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "embedding_model_id",
        ),
        Index(
            "ix_memory_embeddings_v1_hnsw_cosine",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
            postgresql_with={"m": 16, "ef_construction": 64},
        ),
        TENANT_TABLE_ARGS,
    )

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    memory_id: Mapped[UUID] = mapped_column(primary_key=True)
    embedding_model_id: Mapped[UUID] = mapped_column(primary_key=True)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    source_memory_revision: Mapped[int] = mapped_column(Integer(), nullable=False)
    source_event_id: Mapped[UUID] = mapped_column(nullable=False)
    input_contract_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_content_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    input_truncated: Mapped[bool] = mapped_column(Boolean(), nullable=False)
    embedding: Mapped[list[float]] = mapped_column(Vector(384), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class OutboxJob(Base):
    __tablename__ = "outbox_jobs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "job_uuid", name="tenant_job_uuid"),
        UniqueConstraint(
            "tenant_id", "job_type", "deduplication_key", name="tenant_job_deduplication"
        ),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check(
            "job_type",
            (
                "embed_memory",
                "check_duplicates",
                "rebuild_projection",
                "propose_consolidation",
                "export_git_batch",
                "expire_candidate",
                "purge_payload",
                "ingest_github_proposal",
                "refresh_ingress_status",
                "notify_relay_health",
            ),
            name="job_type_values",
        ),
        values_check(
            "state", ("pending", "leased", "succeeded", "failed", "dead"), name="state_values"
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 100", name="attempts_range"
        ),
        CheckConstraint("attempt_count <= max_attempts", name="attempts_bounded"),
        CheckConstraint(
            "(state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL) OR "
            "(state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)",
            name="lease_state",
        ),
        CheckConstraint(
            "completed_at IS NULL OR state IN ('succeeded', 'dead')", name="completion_state"
        ),
        CheckConstraint(
            "length(deduplication_key) BETWEEN 1 AND 255", name="deduplication_key_length"
        ),
        json_object_check("payload", name="payload_object"),
        uuid_v7_check("job_uuid", name="job_uuid_uuid_v7"),
        Index(
            "ix_outbox_jobs_claim",
            "tenant_id",
            "available_at",
            "priority",
            "job_id",
            postgresql_where=text("state = 'pending'"),
        ),
        Index(
            "ix_outbox_jobs_expired_lease",
            "lease_expires_at",
            postgresql_where=text("state = 'leased'"),
        ),
        TENANT_TABLE_ARGS,
    )

    job_id: Mapped[int] = mapped_column(BigInteger(), primary_key=True, autoincrement=True)
    job_uuid: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    deduplication_key: Mapped[str] = mapped_column(String(255), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[UUID | None] = mapped_column()
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'pending'"))
    priority: Mapped[int] = mapped_column(SmallInteger(), nullable=False, server_default=text("0"))
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_count: Mapped[int] = mapped_column(Integer(), nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer(), nullable=False, server_default=text("8"))
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    last_error_summary: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ArchiveTarget(Base):
    __tablename__ = "archive_targets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "archive_target_id", name="tenant_archive_target"),
        UniqueConstraint("tenant_id", "name", name="tenant_name"),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        values_check("target_kind", ("forgejo_git",), name="target_kind_values"),
        values_check("state", ("active", "disabled", "sealed"), name="state_values"),
        CheckConstraint(
            "length(repository_reference) BETWEEN 1 AND 1024", name="repository_reference_length"
        ),
        CheckConstraint("length(branch_name) BETWEEN 1 AND 255", name="branch_name_length"),
        CheckConstraint("sealed_at IS NULL OR sealed_at >= created_at", name="seal_order"),
        uuid_v7_check("archive_target_id", name="archive_target_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    archive_target_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_reference: Mapped[str] = mapped_column(Text(), nullable=False)
    branch_name: Mapped[str] = mapped_column(String(255), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'active'"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ArchiveExportCheckpoint(Base):
    __tablename__ = "archive_export_checkpoints"
    __table_args__ = (
        UniqueConstraint("tenant_id", "checkpoint_id", name="tenant_checkpoint"),
        UniqueConstraint(
            "tenant_id", "archive_target_id", "checkpoint_id", name="tenant_target_checkpoint"
        ),
        UniqueConstraint(
            "tenant_id",
            "archive_target_id",
            "first_event_sequence",
            "last_event_sequence",
            name="tenant_target_range",
        ),
        UniqueConstraint(
            "tenant_id", "archive_target_id", "manifest_sha256", name="tenant_target_manifest"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "archive_target_id"],
            ["archive_targets.tenant_id", "archive_targets.archive_target_id"],
            name="archive_target",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "archive_target_id", "previous_checkpoint_id"],
            [
                "archive_export_checkpoints.tenant_id",
                "archive_export_checkpoints.archive_target_id",
                "archive_export_checkpoints.checkpoint_id",
            ],
            name="previous_checkpoint",
            ondelete="RESTRICT",
        ),
        values_check("state", ("preparing", "committed", "pushed", "failed"), name="state_values"),
        CheckConstraint("source_high_water_sequence >= 0", name="high_water_nonnegative"),
        CheckConstraint(
            "first_event_sequence >= 1 AND last_event_sequence >= first_event_sequence",
            name="event_range",
        ),
        CheckConstraint(
            "source_high_water_sequence >= last_event_sequence", name="high_water_covers_range"
        ),
        CheckConstraint(
            "event_count BETWEEN 1 AND (last_event_sequence - first_event_sequence + 1)",
            name="event_count_range",
        ),
        CheckConstraint(
            "previous_manifest_sha256 IS NULL OR octet_length(previous_manifest_sha256) = 32",
            name="previous_manifest_hash_length",
        ),
        sha256_check("manifest_sha256", name="manifest_sha256_length"),
        CheckConstraint(
            "git_commit_sha IS NULL OR git_commit_sha ~ '^[0-9a-f]{40,64}$'",
            name="git_commit_sha_format",
        ),
        CheckConstraint(
            "remote_git_commit_sha IS NULL OR remote_git_commit_sha ~ '^[0-9a-f]{40,64}$'",
            name="remote_git_commit_sha_format",
        ),
        CheckConstraint("committed_at IS NULL OR committed_at >= started_at", name="commit_order"),
        CheckConstraint(
            "pushed_at IS NULL OR (committed_at IS NOT NULL AND pushed_at >= committed_at)",
            name="push_order",
        ),
        uuid_v7_check("checkpoint_id", name="checkpoint_id_uuid_v7"),
        Index(
            "uq_archive_export_checkpoints_remote_commit",
            "tenant_id",
            "archive_target_id",
            "remote_git_commit_sha",
            unique=True,
            postgresql_where=text("remote_git_commit_sha IS NOT NULL"),
        ),
        Index(
            "ix_archive_export_checkpoints_latest",
            "tenant_id",
            "archive_target_id",
            "last_event_sequence",
        ),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_append_only": True}},
    )

    checkpoint_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    archive_target_id: Mapped[UUID] = mapped_column(nullable=False)
    previous_checkpoint_id: Mapped[UUID | None] = mapped_column()
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'preparing'")
    )
    source_high_water_sequence: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    first_event_sequence: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    last_event_sequence: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    event_count: Mapped[int] = mapped_column(BigInteger(), nullable=False)
    previous_manifest_sha256: Mapped[bytes | None] = mapped_column(LargeBinary())
    manifest_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    manifest_path: Mapped[str] = mapped_column(Text(), nullable=False)
    exporter_version: Mapped[str] = mapped_column(String(64), nullable=False)
    postgres_timeline_id: Mapped[int | None] = mapped_column(Integer())
    git_commit_sha: Mapped[str | None] = mapped_column(String(64))
    remote_git_commit_sha: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    safe_error_code: Mapped[str | None] = mapped_column(String(64))
