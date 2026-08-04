"""Persona lineage, branch, logical-session, and typed-subject models."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY, Base
from kivra_memory.storage.models._shared import (
    MEMORY_VISIBILITIES,
    TENANT_TABLE_ARGS,
    json_object_check,
    uuid_v7_check,
    values_check,
)

_SUBJECT_KIND_ANCHOR_CHECK = (
    "(kind IN ('global', 'concept') AND persona_id IS NULL AND "
    "relationship_actor_id IS NULL AND project_ref IS NULL AND episode_ref IS NULL AND "
    "origin_session_id IS NULL) OR "
    "(kind = 'persona' AND persona_id IS NOT NULL AND relationship_actor_id IS NULL AND "
    "project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR "
    "(kind = 'relationship' AND persona_id IS NULL AND relationship_actor_id IS NOT NULL AND "
    "project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR "
    "(kind = 'project' AND persona_id IS NULL AND relationship_actor_id IS NULL AND "
    "project_ref IS NOT NULL AND episode_ref IS NULL AND origin_session_id IS NULL) OR "
    "(kind = 'episode' AND persona_id IS NULL AND relationship_actor_id IS NULL AND "
    "project_ref IS NULL AND episode_ref IS NOT NULL AND origin_session_id IS NULL) OR "
    "(kind = 'scene' AND persona_id IS NULL AND relationship_actor_id IS NULL AND "
    "project_ref IS NULL AND episode_ref IS NULL AND origin_session_id IS NOT NULL)"
)


class Persona(Base):
    __tablename__ = "personas"
    __table_args__ = (
        UniqueConstraint("tenant_id", "persona_id", name="tenant_persona"),
        UniqueConstraint("tenant_id", "slug", name="tenant_slug"),
        UniqueConstraint("tenant_id", "actor_id", name="personas_tenant_actor"),
        ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="actor",
            ondelete="RESTRICT",
        ),
        json_object_check("baseline_policy", name="baseline_policy_object"),
        CheckConstraint("retired_at IS NULL OR retired_at >= created_at", name="retirement_order"),
        uuid_v7_check("persona_id", name="persona_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    persona_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    slug: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    baseline_policy: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Lineage(Base):
    __tablename__ = "lineages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", name="tenant_lineage"),
        UniqueConstraint("tenant_id", "lineage_id", "persona_id", name="tenant_lineage_persona"),
        UniqueConstraint("tenant_id", "persona_id", "name", name="tenant_persona_name"),
        ForeignKeyConstraint(
            ["tenant_id", "persona_id"],
            ["personas.tenant_id", "personas.persona_id"],
            name="persona",
            ondelete="RESTRICT",
        ),
        CheckConstraint("sealed_at IS NULL OR sealed_at >= created_at", name="seal_order"),
        uuid_v7_check("lineage_id", name="lineage_id_uuid_v7"),
        TENANT_TABLE_ARGS,
    )

    lineage_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    persona_id: Mapped[UUID] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Branch(Base):
    __tablename__ = "branches"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", "branch_id", name="tenant_lineage_branch"),
        UniqueConstraint("tenant_id", "lineage_id", "name", name="tenant_lineage_name"),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id"],
            ["lineages.tenant_id", "lineages.lineage_id"],
            name="lineage",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "parent_branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="parent_branch",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "parent_branch_id", "fork_event_sequence"],
            [
                "memory_events.tenant_id",
                "memory_events.lineage_id",
                "memory_events.branch_id",
                "memory_events.sequence",
            ],
            name="fork_event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        values_check("visibility_ceiling", MEMORY_VISIBILITIES, name="visibility_ceiling_values"),
        CheckConstraint(
            "(parent_branch_id IS NULL AND fork_event_sequence IS NULL) OR "
            "(parent_branch_id IS NOT NULL AND fork_event_sequence IS NOT NULL)",
            name="parent_fork_pair",
        ),
        CheckConstraint(
            "parent_branch_id IS NULL OR parent_branch_id <> branch_id", name="parent_not_self"
        ),
        CheckConstraint(
            "fork_event_sequence IS NULL OR fork_event_sequence >= 1", name="fork_sequence_positive"
        ),
        CheckConstraint("sealed_at IS NULL OR sealed_at >= created_at", name="seal_order"),
        uuid_v7_check("branch_id", name="branch_id_uuid_v7"),
        Index(
            "uq_branches_one_root_per_lineage",
            "tenant_id",
            "lineage_id",
            unique=True,
            postgresql_where=text("parent_branch_id IS NULL"),
        ),
        Index("ix_branches_parent", "tenant_id", "lineage_id", "parent_branch_id"),
        {
            "info": {
                TENANT_OWNED_INFO_KEY: True,
                "scalevault_immutable_fields": (
                    "tenant_id",
                    "lineage_id",
                    "parent_branch_id",
                    "fork_event_sequence",
                    "created_at",
                ),
            }
        },
    )

    branch_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    parent_branch_id: Mapped[UUID | None] = mapped_column()
    fork_event_sequence: Mapped[int | None] = mapped_column(BigInteger())
    name: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    visibility_ceiling: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LogicalSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "session_id", name="tenant_session"),
        UniqueConstraint(
            "tenant_id", "session_id", "actor_id", "client_id", name="tenant_session_actor_client"
        ),
        UniqueConstraint("tenant_id", "session_id", "lineage_id", name="tenant_session_lineage"),
        UniqueConstraint(
            "tenant_id",
            "session_id",
            "lineage_id",
            "branch_id",
            name="sessions_tenant_session_lineage_branch",
        ),
        UniqueConstraint(
            "tenant_id",
            "session_id",
            "lineage_id",
            "branch_id",
            "actor_id",
            "client_id",
            name="tenant_session_branch_actor_client",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="actor",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "client_id"],
            ["clients.tenant_id", "clients.client_id"],
            name="client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
            [
                "transport_bindings.tenant_id",
                "transport_bindings.transport_binding_id",
                "transport_bindings.actor_id",
                "transport_bindings.client_id",
            ],
            name="transport_binding",
            ondelete="RESTRICT",
        ),
        values_check(
            "content_mode", ("technical", "meta", "roleplay", "mixed"), name="content_mode_values"
        ),
        CheckConstraint("last_seen_at >= started_at", name="last_seen_order"),
        uuid_v7_check("session_id", name="session_id_uuid_v7"),
        Index(
            "uq_sessions_conversation_ref",
            "tenant_id",
            "client_id",
            "conversation_ref",
            unique=True,
            postgresql_where=text("conversation_ref IS NOT NULL"),
        ),
        TENANT_TABLE_ARGS,
    )

    session_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    conversation_ref: Mapped[str | None] = mapped_column(Text())
    project_ref: Mapped[str | None] = mapped_column(Text())
    content_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class Subject(Base):
    __tablename__ = "subjects"
    __table_args__ = (
        UniqueConstraint("tenant_id", "lineage_id", "subject_id", name="tenant_lineage_subject"),
        UniqueConstraint(
            "tenant_id", "lineage_id", "subject_id", "kind", name="tenant_lineage_subject_kind"
        ),
        UniqueConstraint(
            "tenant_id", "lineage_id", "kind", "canonical_key", name="tenant_lineage_kind_key"
        ),
        UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "subject_id",
            "kind",
            "origin_session_id",
            name="tenant_lineage_subject_kind_session",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id"],
            ["lineages.tenant_id", "lineages.lineage_id"],
            name="lineage",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "persona_id"],
            ["lineages.tenant_id", "lineages.lineage_id", "lineages.persona_id"],
            name="lineage_persona",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "relationship_actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="relationship_actor",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "origin_session_id", "lineage_id"],
            ["sessions.tenant_id", "sessions.session_id", "sessions.lineage_id"],
            name="origin_session",
            ondelete="RESTRICT",
        ),
        values_check(
            "kind",
            ("global", "persona", "relationship", "project", "episode", "scene", "concept"),
            name="kind_values",
        ),
        CheckConstraint(_SUBJECT_KIND_ANCHOR_CHECK, name="kind_anchor_shape"),
        json_object_check("metadata", name="metadata_object"),
        uuid_v7_check("subject_id", name="subject_id_uuid_v7"),
        {
            "info": {
                TENANT_OWNED_INFO_KEY: True,
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
            }
        },
    )

    subject_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    canonical_key: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    persona_id: Mapped[UUID | None] = mapped_column()
    relationship_actor_id: Mapped[UUID | None] = mapped_column()
    project_ref: Mapped[str | None] = mapped_column(Text())
    episode_ref: Mapped[str | None] = mapped_column(Text())
    origin_session_id: Mapped[UUID | None] = mapped_column()
    metadata_: Mapped[dict[str, object]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class SubjectAlias(Base):
    __tablename__ = "subject_aliases"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "subject_id"],
            ["subjects.tenant_id", "subjects.lineage_id", "subjects.subject_id"],
            name="subject",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "lineage_id", "alias", name="tenant_lineage_alias"),
        CheckConstraint("length(btrim(alias::text)) BETWEEN 1 AND 256", name="alias_length"),
        TENANT_TABLE_ARGS,
    )

    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    lineage_id: Mapped[UUID] = mapped_column(primary_key=True)
    subject_id: Mapped[UUID] = mapped_column(primary_key=True)
    alias: Mapped[str] = mapped_column(CITEXT(), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
