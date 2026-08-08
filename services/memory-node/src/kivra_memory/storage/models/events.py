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
    MEMORY_SCOPES,
    MEMORY_VISIBILITIES,
    json_object_check,
    sha256_check,
    uuid_v7_check,
    values_check,
)

_SELECTION_BASES = (
    "routine_banter",
    "explicit_user_correction",
    "explicit_user_preference",
    "explicit_user_permission",
    "verified_project_decision",
    "assistant_observation",
    "assistant_interpretation",
    "imported_legacy",
    "meaningful_episodic_anchor",
    "explicit_user_request",
)
_SELECTION_SOURCE_KINDS = (
    "live_interaction",
    "reviewed_seed",
    "github_proposal",
    "candidate_reassessment",
    "candidate_expiry",
)
_SELECTION_OPERATIONS = ("nominate", "promote", "expire")
_SELECTION_OUTCOMES = (
    "omit",
    "reject",
    "candidate",
    "active",
    "promoted",
    "expired",
)
_SUBJECT_KINDS = (
    "global",
    "persona",
    "relationship",
    "project",
    "episode",
    "scene",
    "concept",
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


class SelectionDecisionCounter(Base):
    __tablename__ = "selection_decision_counter"
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
            "'tombstoned', 'payload_purge_completed', 'candidate_promoted', "
            "'candidate_expired') AND memory_id IS NOT NULL AND "
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


class SelectionDecision(Base):
    __tablename__ = "selection_decisions"
    __table_args__ = (
        UniqueConstraint("decision_id", name="selection_decision_id"),
        UniqueConstraint("tenant_id", "decision_id", name="tenant_selection_decision"),
        UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "selection_sequence",
            name="tenant_lineage_selection_sequence",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "persona_id"],
            ["lineages.tenant_id", "lineages.lineage_id", "lineages.persona_id"],
            name="lineage_persona",
            ondelete="RESTRICT",
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
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint("selection_sequence >= 1", name="selection_sequence_positive"),
        CheckConstraint("policy_id = 'scalevault-memory-selection'", name="policy_id_value"),
        CheckConstraint("policy_version = 1", name="policy_version_value"),
        sha256_check("policy_sha256", name="policy_sha256_length"),
        CheckConstraint(
            "policy_rule_code ~ '^[a-z][a-z0-9_]{0,63}$'", name="policy_rule_code_safe"
        ),
        sha256_check("input_sha256", name="input_sha256_length"),
        values_check("source_kind", _SELECTION_SOURCE_KINDS, name="source_kind_values"),
        values_check(
            "requested_operation", _SELECTION_OPERATIONS, name="requested_operation_values"
        ),
        values_check("outcome", _SELECTION_OUTCOMES, name="outcome_values"),
        CheckConstraint(
            "(requested_operation = 'nominate' AND "
            "outcome IN ('omit', 'reject', 'candidate', 'active')) OR "
            "(requested_operation = 'promote' AND "
            "outcome IN ('omit', 'reject', 'promoted')) OR "
            "(requested_operation = 'expire' AND "
            "outcome IN ('omit', 'reject', 'expired'))",
            name="operation_outcome_compatible",
        ),
        CheckConstraint(
            "(source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal') "
            "AND requested_operation = 'nominate') OR "
            "(source_kind = 'candidate_reassessment' AND requested_operation = 'promote') OR "
            "(source_kind = 'candidate_expiry' AND requested_operation = 'expire')",
            name="source_operation_compatible",
        ),
        values_check("selection_basis", _SELECTION_BASES, name="selection_basis_values"),
        values_check("scope", MEMORY_SCOPES, name="scope_values"),
        values_check("visibility", MEMORY_VISIBILITIES, name="visibility_values"),
        values_check("subject_kind", _SUBJECT_KINDS, name="subject_kind_values"),
        CheckConstraint("sensitivity BETWEEN 0 AND 4", name="sensitivity_range"),
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
            "jsonb_typeof(reason_codes) = 'array' AND "
            "jsonb_array_length(reason_codes) BETWEEN 1 AND 8",
            name="reason_codes_shape",
        ),
        CheckConstraint(
            "NOT jsonb_path_exists(reason_codes, "
            '\'$[*] ? (@.type() != "string" || '
            '!(@ like_regex "^[a-z][a-z0-9_]{0,63}$"))\')',
            name="reason_codes_safe",
        ),
        CheckConstraint(
            "jsonb_typeof(matched_rule_ids) = 'array' AND "
            "jsonb_array_length(matched_rule_ids) BETWEEN 0 AND 16",
            name="matched_rule_ids_shape",
        ),
        CheckConstraint(
            "NOT jsonb_path_exists(matched_rule_ids, "
            '\'$[*] ? (@.type() != "string" || '
            '!(@ like_regex "^[a-z][a-z0-9_.-]{0,127}$"))\')',
            name="matched_rule_ids_safe",
        ),
        CheckConstraint(
            "(outcome IN ('candidate', 'active', 'promoted', 'expired') "
            "AND memory_id IS NOT NULL AND event_id IS NOT NULL) OR "
            "(outcome IN ('omit', 'reject') "
            "AND memory_id IS NULL AND event_id IS NULL)",
            name="outcome_link_shape",
        ),
        uuid_v7_check("decision_id", name="decision_id_uuid_v7"),
        Index(
            "ix_selection_decisions_branch_sequence",
            "tenant_id",
            "lineage_id",
            "branch_id",
            text("selection_sequence DESC"),
        ),
        Index(
            "ix_selection_decisions_memory",
            "tenant_id",
            "lineage_id",
            "memory_id",
            postgresql_where=text("memory_id IS NOT NULL"),
        ),
        {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_immutable": True}},
    )

    selection_sequence: Mapped[int] = mapped_column(
        BigInteger(), primary_key=True, autoincrement=False
    )
    decision_id: Mapped[UUID] = mapped_column(nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    persona_id: Mapped[UUID] = mapped_column(nullable=False)
    actor_id: Mapped[UUID] = mapped_column(nullable=False)
    client_id: Mapped[UUID] = mapped_column(nullable=False)
    transport_binding_id: Mapped[UUID] = mapped_column(nullable=False)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    policy_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    policy_rule_code: Mapped[str] = mapped_column(String(64), nullable=False)
    input_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_operation: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_codes: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    matched_rule_ids: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    selection_basis: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False)
    sensitivity: Mapped[int] = mapped_column(SmallInteger(), nullable=False)
    subject_id: Mapped[UUID] = mapped_column(nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    memory_id: Mapped[UUID | None] = mapped_column()
    event_id: Mapped[UUID | None] = mapped_column()
    decided_at: Mapped[datetime] = mapped_column(
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
            ["tenant_id", "selection_decision_id"],
            ["selection_decisions.tenant_id", "selection_decisions.decision_id"],
            name="selection_decision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        CheckConstraint(
            "(selection_decision_id IS NULL AND event_id IS NOT NULL) OR "
            "(selection_decision_id IS NOT NULL AND "
            "((event_id IS NOT NULL AND memory_id IS NOT NULL AND memory_revision IS NOT NULL) OR "
            "(event_id IS NULL AND memory_id IS NULL AND memory_revision IS NULL)))",
            name="terminal_reference_shape",
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
    event_id: Mapped[UUID | None] = mapped_column()
    selection_decision_id: Mapped[UUID | None] = mapped_column()
    memory_id: Mapped[UUID | None] = mapped_column()
    memory_revision: Mapped[int | None] = mapped_column(BigInteger())
    result: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    result_canonical: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    result_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
