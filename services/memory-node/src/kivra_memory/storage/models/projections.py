"""Rebuildable semantic memory projection models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY, Base
from kivra_memory.storage.models._shared import (
    AUTHORITY_CLASSES,
    MEMORY_CATEGORIES,
    MEMORY_SCOPES,
    MEMORY_STATUSES,
    MEMORY_VISIBILITIES,
    ONTOLOGICAL_STATUSES,
    json_array_check,
    json_object_check,
    sha256_check,
    uuid_v7_check,
    values_check,
)

PROJECTION_INFO = {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_projection": True}}

_CATEGORY_ONTOLOGY_CHECK = (
    "(category = 'stable_fact' AND ontological_status IN "
    "('literal_user_fact', 'literal_technical_fact')) OR "
    "(category = 'user_preference' AND ontological_status IN "
    "('literal_user_fact', 'uncertain')) OR "
    "(category = 'assistant_preference_like_pattern' AND ontological_status IN "
    "('assistant_self_description', 'observed_assistant_behavior', 'hypothesis', 'uncertain')) OR "
    "(category = 'boundary_or_permission' AND ontological_status IN "
    "('literal_user_fact', 'interaction_convention', 'uncertain')) OR "
    "(category = 'interaction_convention' AND ontological_status IN "
    "('interaction_convention', 'literal_user_fact', 'uncertain')) OR "
    "(category = 'relationship_pattern' AND ontological_status IN "
    "('observed_assistant_behavior', 'interaction_convention', 'hypothesis', 'uncertain')) OR "
    "(category = 'emergent_tendency' AND ontological_status IN "
    "('assistant_self_description', 'observed_assistant_behavior', 'hypothesis', 'uncertain')) OR "
    "(category = 'episodic_anchor' AND ontological_status <> 'hypothesis') OR "
    "(category IN ('project_decision', 'project_state') AND ontological_status IN "
    "('literal_technical_fact', 'uncertain')) OR "
    "(category = 'procedure' AND ontological_status IN "
    "('literal_technical_fact', 'interaction_convention', 'uncertain')) OR "
    "(category IN ('open_question', 'interpretation') AND ontological_status IN "
    "('hypothesis', 'uncertain')) OR "
    "(category = 'external_fact' AND ontological_status IN "
    "('literal_technical_fact', 'hypothesis', 'uncertain'))"
)


class Memory(Base):
    __tablename__ = "memories"
    __table_args__ = (
        UniqueConstraint("tenant_id", "memory_id", name="tenant_memory"),
        UniqueConstraint(
            "tenant_id", "lineage_id", "memory_id", name="memories_tenant_lineage_memory"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "subject_id", "subject_kind"],
            [
                "subjects.tenant_id",
                "subjects.lineage_id",
                "subjects.subject_id",
                "subjects.kind",
            ],
            name="subject",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "tenant_id",
                "lineage_id",
                "subject_id",
                "subject_kind",
                "origin_session_id",
            ],
            [
                "subjects.tenant_id",
                "subjects.lineage_id",
                "subjects.subject_id",
                "subjects.kind",
                "subjects.origin_session_id",
            ],
            name="subject_origin_session",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "origin_session_id", "lineage_id", "branch_id"],
            [
                "sessions.tenant_id",
                "sessions.session_id",
                "sessions.lineage_id",
                "sessions.branch_id",
            ],
            name="origin_session",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "publication_approved_by_actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="publication_actor",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "last_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="last_event",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "content_key_id"],
            [
                "memory_content_keys.tenant_id",
                "memory_content_keys.lineage_id",
                "memory_content_keys.content_key_id",
            ],
            name="content_key",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        values_check("category", MEMORY_CATEGORIES, name="category_values"),
        values_check("ontological_status", ONTOLOGICAL_STATUSES, name="ontological_status_values"),
        values_check("scope", MEMORY_SCOPES, name="scope_values"),
        values_check("visibility", MEMORY_VISIBILITIES, name="visibility_values"),
        values_check("status", MEMORY_STATUSES, name="status_values"),
        values_check("authority_class", AUTHORITY_CLASSES, name="authority_class_values"),
        values_check(
            "subject_kind",
            ("global", "persona", "relationship", "project", "episode", "scene", "concept"),
            name="subject_kind_values",
        ),
        values_check(
            "content_protection",
            ("plaintext", "envelope_encrypted", "cryptographically_erased"),
            name="content_protection_values",
        ),
        CheckConstraint(_CATEGORY_ONTOLOGY_CHECK, name="category_ontology_compatible"),
        CheckConstraint(
            "(scope = 'global' AND subject_kind = 'global') OR "
            "(scope = 'persona' AND subject_kind = 'persona') OR "
            "(scope = 'relationship' AND subject_kind = 'relationship') OR "
            "(scope = 'project' AND subject_kind = 'project') OR "
            "(scope = 'episodic' AND subject_kind = 'episode') OR "
            "(scope = 'scene_local' AND subject_kind = 'scene')",
            name="scope_subject_kind",
        ),
        CheckConstraint(
            "scope <> 'scene_local' OR (origin_session_id IS NOT NULL AND "
            "visibility IN ('private_root', 'restricted'))",
            name="scene_local_boundary",
        ),
        CheckConstraint(
            "(publication_approved_at IS NULL) = (publication_approved_by_actor_id IS NULL)",
            name="publication_approval_pair",
        ),
        CheckConstraint(
            "visibility <> 'public_seed' OR (status = 'active' AND sensitivity = 0 AND "
            "publication_approved_at IS NOT NULL)",
            name="public_seed_approval",
        ),
        CheckConstraint(
            "visibility <> 'shareable' OR sensitivity <= 1",
            name="shareable_sensitivity",
        ),
        CheckConstraint(
            "(content_protection = 'plaintext' AND content_key_id IS NULL) OR "
            "(content_protection IN ('envelope_encrypted', 'cryptographically_erased') AND "
            "content_key_id IS NOT NULL)",
            name="content_key_required",
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint("length(statement) BETWEEN 1 AND 8192", name="statement_length"),
        CheckConstraint("length(reason_to_remember) BETWEEN 1 AND 4096", name="reason_length"),
        CheckConstraint(
            "(status = 'tombstoned' AND statement IS NULL AND reason_to_remember IS NULL AND "
            "normalized_fingerprint IS NULL AND interpretation_limits = '[]'::jsonb) OR "
            "(status <> 'tombstoned' AND statement IS NOT NULL AND reason_to_remember IS NOT NULL "
            "AND normalized_fingerprint IS NOT NULL)",
            name="tombstone_content_shape",
        ),
        CheckConstraint(
            "content_protection <> 'cryptographically_erased' OR status = 'tombstoned'",
            name="erasure_requires_tombstone",
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="confidence_range"),
        CheckConstraint("salience BETWEEN 0 AND 1", name="salience_range"),
        CheckConstraint("durability BETWEEN 0 AND 1", name="durability_range"),
        CheckConstraint("sensitivity BETWEEN 0 AND 4", name="sensitivity_range"),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from",
            name="validity_order",
        ),
        CheckConstraint("updated_at >= created_at", name="update_order"),
        CheckConstraint(
            "(status = 'candidate' AND "
            "(candidate_expires_at IS NULL OR candidate_expires_at > created_at)) OR "
            "(status <> 'candidate' AND candidate_expires_at IS NULL)",
            name="candidate_expiry_shape",
        ),
        json_array_check("interpretation_limits", name="interpretation_limits_array"),
        CheckConstraint(
            "jsonb_array_length(interpretation_limits) <= 32",
            name="interpretation_limits_count",
        ),
        json_object_check("metadata", name="metadata_object"),
        sha256_check("normalized_fingerprint", name="fingerprint_length"),
        CheckConstraint("fingerprint_version >= 1", name="fingerprint_version_positive"),
        uuid_v7_check("memory_id", name="memory_id_uuid_v7"),
        Index(
            "uq_memories_live_fingerprint",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "subject_id",
            "scope",
            "normalized_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('candidate', 'active', 'disputed')"),
        ),
        Index(
            "ix_memories_retrieval",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "status",
            "scope",
            "visibility",
        ),
        Index("ix_memories_subject", "tenant_id", "subject_id", "status"),
        Index(
            "ix_memories_candidate_expiry",
            "tenant_id",
            "candidate_expires_at",
            postgresql_where=text("status = 'candidate' AND candidate_expires_at IS NOT NULL"),
        ),
        Index("ix_memories_search_document", "search_document", postgresql_using="gin"),
        Index(
            "ix_memories_statement_trgm",
            "statement",
            postgresql_using="gin",
            postgresql_ops={"statement": "gin_trgm_ops"},
        ),
        PROJECTION_INFO,
    )

    memory_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    subject_id: Mapped[UUID] = mapped_column(nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    origin_session_id: Mapped[UUID | None] = mapped_column()
    revision: Mapped[int] = mapped_column(nullable=False)
    category: Mapped[str] = mapped_column(String(48), nullable=False)
    ontological_status: Mapped[str] = mapped_column(String(48), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    statement: Mapped[str | None] = mapped_column(Text())
    reason_to_remember: Mapped[str | None] = mapped_column(Text())
    interpretation_limits: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(7, 6), nullable=False)
    salience: Mapped[Decimal] = mapped_column(Numeric(7, 6), nullable=False)
    durability: Mapped[Decimal] = mapped_column(Numeric(7, 6), nullable=False)
    sensitivity: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    authority_class: Mapped[str] = mapped_column(String(48), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    candidate_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    search_document: Mapped[str] = mapped_column(
        TSVECTOR(),
        Computed(
            "to_tsvector('simple', coalesce(statement, '') || ' ' || "
            "coalesce(reason_to_remember, ''))",
            persisted=True,
        ),
    )
    normalized_fingerprint: Mapped[bytes | None] = mapped_column(LargeBinary())
    fingerprint_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    metadata_: Mapped[dict[str, object]] = mapped_column("metadata", JSONB, nullable=False)
    publication_approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    publication_approved_by_actor_id: Mapped[UUID | None] = mapped_column()
    content_protection: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default=text("'plaintext'")
    )
    content_key_id: Mapped[UUID | None] = mapped_column()
    last_event_id: Mapped[UUID] = mapped_column(nullable=False)


class MemoryEvidence(Base):
    __tablename__ = "memory_evidence"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", "evidence_id", name="tenant_lineage_evidence"),
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
            ["tenant_id", "lineage_id", "source_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="source_event",
            ondelete="RESTRICT",
        ),
        CheckConstraint("length(source_type) BETWEEN 1 AND 64", name="source_type_length"),
        CheckConstraint(
            "length(trust_classification) BETWEEN 1 AND 64",
            name="trust_classification_length",
        ),
        values_check("status", ("active",), name="status_values"),
        CheckConstraint("excerpt IS NULL OR length(excerpt) <= 4096", name="excerpt_length"),
        sha256_check("content_sha256", name="content_sha256_length"),
        json_object_check("source_reference", name="source_reference_object"),
        json_object_check("metadata", name="metadata_object"),
        uuid_v7_check("evidence_id", name="evidence_id_uuid_v7"),
        Index("ix_memory_evidence_memory", "tenant_id", "memory_id"),
        PROJECTION_INFO,
    )

    evidence_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    memory_id: Mapped[UUID] = mapped_column(nullable=False)
    source_event_id: Mapped[UUID] = mapped_column(nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_reference: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    excerpt: Mapped[str | None] = mapped_column(Text())
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_sha256: Mapped[bytes | None] = mapped_column(LargeBinary())
    trust_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'active'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_: Mapped[dict[str, object]] = mapped_column("metadata", JSONB, nullable=False)


class MemoryLink(Base):
    __tablename__ = "memory_links"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", "link_id", name="tenant_lineage_link"),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "source_memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="source_memory",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "target_memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="target_memory",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "created_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="created_event",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "unlinked_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="unlinked_event",
            ondelete="RESTRICT",
        ),
        values_check(
            "link_type",
            (
                "supports",
                "contradicts",
                "refines",
                "caused_by",
                "associated_with",
                "supersedes",
                "part_of",
                "forked_from",
            ),
            name="link_type_values",
        ),
        values_check("status", ("active", "unlinked"), name="status_values"),
        CheckConstraint("source_memory_id <> target_memory_id", name="distinct_memories"),
        CheckConstraint(
            "(status = 'active' AND unlinked_event_id IS NULL AND unlinked_at IS NULL) OR "
            "(status = 'unlinked' AND unlinked_event_id IS NOT NULL AND unlinked_at IS NOT NULL)",
            name="unlink_status",
        ),
        json_object_check("metadata", name="metadata_object"),
        uuid_v7_check("link_id", name="link_id_uuid_v7"),
        Index(
            "uq_memory_links_active",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "source_memory_id",
            "target_memory_id",
            "link_type",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        Index("ix_memory_links_target", "tenant_id", "lineage_id", "target_memory_id"),
        PROJECTION_INFO,
    )

    link_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    source_memory_id: Mapped[UUID] = mapped_column(nullable=False)
    target_memory_id: Mapped[UUID] = mapped_column(nullable=False)
    link_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'active'"))
    created_event_id: Mapped[UUID] = mapped_column(nullable=False)
    unlinked_event_id: Mapped[UUID | None] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    unlinked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict[str, object]] = mapped_column("metadata", JSONB, nullable=False)


class MemoryConflict(Base):
    __tablename__ = "memory_conflicts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", "conflict_id", name="tenant_lineage_conflict"),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "subject_id"],
            ["subjects.tenant_id", "subjects.lineage_id", "subjects.subject_id"],
            name="subject",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "opened_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="opened_event",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "resolution_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="resolution_event",
            ondelete="RESTRICT",
        ),
        values_check("status", ("open", "resolved"), name="status_values"),
        CheckConstraint(
            "(status = 'open' AND resolution_event_id IS NULL AND resolved_at IS NULL AND "
            "resolution_kind IS NULL AND resolution_rationale IS NULL) OR "
            "(status = 'resolved' AND resolution_event_id IS NOT NULL AND resolved_at IS NOT NULL "
            "AND resolution_kind IS NOT NULL)",
            name="resolution_status",
        ),
        CheckConstraint("length(reason) BETWEEN 1 AND 4096", name="reason_length"),
        CheckConstraint(
            "resolution_kind IS NULL OR length(resolution_kind) BETWEEN 1 AND 64",
            name="resolution_kind_length",
        ),
        CheckConstraint(
            "resolution_rationale IS NULL OR length(resolution_rationale) <= 4096",
            name="resolution_rationale_length",
        ),
        json_object_check("metadata", name="metadata_object"),
        uuid_v7_check("conflict_id", name="conflict_id_uuid_v7"),
        Index(
            "ix_memory_conflicts_open",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "subject_id",
            postgresql_where=text("status = 'open'"),
        ),
        PROJECTION_INFO,
    )

    conflict_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    subject_id: Mapped[UUID] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'open'"))
    reason: Mapped[str] = mapped_column(Text(), nullable=False)
    resolution_kind: Mapped[str | None] = mapped_column(String(64))
    resolution_rationale: Mapped[str | None] = mapped_column(Text())
    opened_event_id: Mapped[UUID] = mapped_column(nullable=False)
    resolution_event_id: Mapped[UUID | None] = mapped_column()
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_: Mapped[dict[str, object]] = mapped_column("metadata", JSONB, nullable=False)


class MemoryConflictMember(Base):
    __tablename__ = "memory_conflict_members"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "conflict_id"],
            [
                "memory_conflicts.tenant_id",
                "memory_conflicts.lineage_id",
                "memory_conflicts.conflict_id",
            ],
            name="conflict",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "last_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="last_event",
            ondelete="RESTRICT",
        ),
        CheckConstraint("length(disposition) BETWEEN 1 AND 64", name="disposition_length"),
        Index("ix_memory_conflict_members_memory", "tenant_id", "lineage_id", "memory_id"),
        PROJECTION_INFO,
    )

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    lineage_id: Mapped[UUID] = mapped_column(primary_key=True)
    conflict_id: Mapped[UUID] = mapped_column(primary_key=True)
    memory_id: Mapped[UUID] = mapped_column(primary_key=True)
    disposition: Mapped[str] = mapped_column(String(64), nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_id: Mapped[UUID] = mapped_column(nullable=False)


class MemoryContentKey(Base):
    __tablename__ = "memory_content_keys"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "lineage_id", "content_key_id", name="tenant_lineage_content_key"
        ),
        UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "memory_id",
            name="memory_content_keys_tenant_lineage_memory",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        values_check(
            "state", ("active", "destruction_requested", "destroyed", "failed"), name="state_values"
        ),
        CheckConstraint("length(provider_name) BETWEEN 1 AND 64", name="provider_name_length"),
        CheckConstraint(
            "length(provider_key_reference) BETWEEN 1 AND 512", name="provider_reference_length"
        ),
        CheckConstraint(
            "destruction_requested_at IS NULL OR destruction_requested_at >= created_at",
            name="destruction_request_order",
        ),
        CheckConstraint(
            "destroyed_at IS NULL OR (destruction_requested_at IS NOT NULL AND "
            "destroyed_at >= destruction_requested_at)",
            name="destruction_order",
        ),
        CheckConstraint(
            "destruction_receipt_sha256 IS NULL OR octet_length(destruction_receipt_sha256) = 32",
            name="destruction_receipt_length",
        ),
        uuid_v7_check("content_key_id", name="content_key_id_uuid_v7"),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_contains_no_key_material": True}},
    )

    content_key_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    memory_id: Mapped[UUID] = mapped_column(nullable=False)
    provider_name: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_key_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default=text("'active'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    destruction_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destruction_receipt_sha256: Mapped[bytes | None] = mapped_column(LargeBinary())
