"""Ingress bookkeeping, gap-free event ordering, events, and command receipts."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
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
    MEMORY_OPERATIONS,
    json_object_check,
    sha256_check,
    uuid_v7_check,
    values_check,
)


class IngressItem(Base):
    __tablename__ = "ingress_items"
    __table_args__ = (
        UniqueConstraint("tenant_id", "ingress_id", name="tenant_ingress"),
        UniqueConstraint(
            "provider",
            "repository_external_id",
            "external_object_id",
            name="provider_repository_object",
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
        ForeignKeyConstraint(
            ["tenant_id", "installation_id"],
            ["transport_installations.tenant_id", "transport_installations.installation_id"],
            name="installation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "result_event_id"],
            ["memory_events.tenant_id", "memory_events.event_id"],
            name="result_event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        values_check("provider", ("github",), name="provider_values"),
        values_check(
            "state",
            (
                "discovered",
                "validated",
                "accepted",
                "duplicate",
                "conflict",
                "rejected",
                "quarantined",
            ),
            name="state_values",
        ),
        sha256_check("payload_sha256", name="payload_sha256_length"),
        CheckConstraint(
            "length(declared_idempotency_key) BETWEEN 1 AND 255", name="idempotency_key_length"
        ),
        CheckConstraint(
            "validated_at IS NULL OR validated_at >= discovered_at", name="validation_order"
        ),
        CheckConstraint(
            "processed_at IS NULL OR processed_at >= discovered_at", name="processing_order"
        ),
        CheckConstraint(
            "safe_diagnostic IS NULL OR length(safe_diagnostic) <= 512", name="diagnostic_length"
        ),
        uuid_v7_check("ingress_id", name="ingress_id_uuid_v7"),
        Index("ix_ingress_items_claim", "tenant_id", "state", "discovered_at"),
        {
            "info": {
                TENANT_OWNED_INFO_KEY: True,
                "scalevault_immutable_fields": (
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
                ),
            }
        },
    )

    ingress_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    installation_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    repository_external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    branch_name: Mapped[str] = mapped_column(String(255), nullable=False)
    immutable_path: Mapped[str] = mapped_column(Text(), nullable=False)
    external_object_id: Mapped[str] = mapped_column(String(255), nullable=False)
    commit_id: Mapped[str] = mapped_column(String(255), nullable=False)
    blob_id: Mapped[str] = mapped_column(String(255), nullable=False)
    declared_idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'discovered'")
    )
    result_event_id: Mapped[UUID | None] = mapped_column()
    result_memory_id: Mapped[UUID | None] = mapped_column()
    error_code: Mapped[str | None] = mapped_column(String(64))
    safe_diagnostic: Mapped[str | None] = mapped_column(String(512))
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MemoryEventCounter(Base):
    __tablename__ = "memory_event_counter"
    __table_args__ = (
        CheckConstraint("counter_id = 1", name="singleton_id"),
        CheckConstraint("next_sequence >= 1", name="next_sequence_positive"),
    )

    counter_id: Mapped[int] = mapped_column(
        SmallInteger(), primary_key=True, server_default=text("1")
    )
    next_sequence: Mapped[int] = mapped_column(
        BigInteger(), nullable=False, server_default=text("1")
    )


class MemoryEvent(Base):
    __tablename__ = "memory_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="event_id"),
        UniqueConstraint("tenant_id", "event_id", name="tenant_event"),
        UniqueConstraint("tenant_id", "lineage_id", "event_id", name="tenant_lineage_event"),
        UniqueConstraint("tenant_id", "lineage_id", "sequence", name="tenant_lineage_sequence"),
        UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "branch_id",
            "sequence",
            name="tenant_lineage_branch_sequence",
        ),
        UniqueConstraint(
            "tenant_id",
            "client_id",
            "idempotency_key",
            name="memory_events_tenant_client_idempotency",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
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
        ForeignKeyConstraint(
            ["tenant_id", "session_id", "lineage_id", "branch_id", "actor_id", "client_id"],
            [
                "sessions.tenant_id",
                "sessions.session_id",
                "sessions.lineage_id",
                "sessions.branch_id",
                "sessions.actor_id",
                "sessions.client_id",
            ],
            name="session",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "ingress_id"],
            ["ingress_items.tenant_id", "ingress_items.ingress_id"],
            name="ingress",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "causation_event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="causation_event",
            ondelete="RESTRICT",
        ),
        values_check("operation", MEMORY_OPERATIONS, name="operation_values"),
        CheckConstraint(
            "(operation IN ('observed', 'remembered', 'evidence_attached', "
            "'evidence_redacted') AND memory_id IS NOT NULL AND expected_revision IS NULL) OR "
            "(operation IN ('revised', 'retired', 'visibility_changed', 'superseded', "
            "'tombstoned', 'payload_purge_completed') AND memory_id IS NOT NULL AND "
            "expected_revision IS NOT NULL) OR "
            "(operation IN ('branch_created', 'linked', 'unlinked', 'conflict_opened', "
            "'conflict_resolved') AND memory_id IS NULL AND expected_revision IS NULL)",
            name="operation_envelope_shape",
        ),
        CheckConstraint("schema_version >= 1 AND payload_version >= 1", name="versions_positive"),
        CheckConstraint("sequence >= 1", name="sequence_positive"),
        CheckConstraint(
            "expected_revision IS NULL OR expected_revision >= 1", name="expected_revision_positive"
        ),
        CheckConstraint("length(idempotency_key) BETWEEN 1 AND 255", name="idempotency_key_length"),
        CheckConstraint("policy_version >= 1", name="policy_version_positive"),
        CheckConstraint("normalization_version >= 1", name="normalization_version_positive"),
        CheckConstraint(
            "octet_length(payload_canonical) BETWEEN 2 AND 1048576", name="payload_canonical_length"
        ),
        json_object_check("payload", name="payload_object"),
        sha256_check("payload_sha256", name="payload_sha256_length"),
        CheckConstraint(
            "payload_sha256 = digest(payload_canonical, 'sha256')",
            name="payload_sha256_matches_canonical",
        ),
        sha256_check("command_sha256", name="command_sha256_length"),
        uuid_v7_check("event_id", name="event_id_uuid_v7"),
        uuid_v7_check("correlation_id", name="correlation_id_uuid_v7"),
        Index(
            "ix_memory_events_branch_sequence", "tenant_id", "lineage_id", "branch_id", "sequence"
        ),
        Index(
            "ix_memory_events_branch_created_at",
            "tenant_id",
            "lineage_id",
            "branch_id",
            "created_at",
            "sequence",
        ),
        Index("ix_memory_events_memory_sequence", "tenant_id", "memory_id", "sequence"),
        Index("ix_memory_events_correlation", "tenant_id", "correlation_id"),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_immutable": True}},
    )

    sequence: Mapped[int] = mapped_column(BigInteger(), primary_key=True, autoincrement=False)
    event_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    session_id: Mapped[UUID | None] = mapped_column()
    ingress_id: Mapped[UUID | None] = mapped_column()
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    memory_id: Mapped[UUID | None] = mapped_column()
    expected_revision: Mapped[int | None] = mapped_column(BigInteger())
    causation_event_id: Mapped[UUID | None] = mapped_column()
    correlation_id: Mapped[UUID] = mapped_column(nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    schema_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    payload_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    policy_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    normalization_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    payload_canonical: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    payload_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    command_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class CommandReceipt(Base):
    __tablename__ = "command_receipts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "receipt_id", name="tenant_receipt"),
        UniqueConstraint(
            "tenant_id",
            "client_id",
            "idempotency_key",
            name="command_receipts_tenant_client_idempotency",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "client_id"],
            ["clients.tenant_id", "clients.client_id"],
            name="client",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "event_id"],
            ["memory_events.tenant_id", "memory_events.event_id"],
            name="event",
            ondelete="RESTRICT",
        ),
        CheckConstraint("length(idempotency_key) BETWEEN 1 AND 255", name="idempotency_key_length"),
        CheckConstraint(
            "memory_revision IS NULL OR memory_revision >= 1", name="memory_revision_positive"
        ),
        CheckConstraint(
            "octet_length(result_canonical) BETWEEN 2 AND 1048576", name="result_canonical_length"
        ),
        json_object_check("result", name="result_object"),
        sha256_check("command_sha256", name="command_sha256_length"),
        sha256_check("result_sha256", name="result_sha256_length"),
        uuid_v7_check("receipt_id", name="receipt_id_uuid_v7"),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_immutable": True}},
    )

    receipt_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    command_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    event_id: Mapped[UUID] = mapped_column(nullable=False)
    memory_id: Mapped[UUID | None] = mapped_column()
    memory_revision: Mapped[int | None] = mapped_column(BigInteger())
    result: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    result_canonical: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    result_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
