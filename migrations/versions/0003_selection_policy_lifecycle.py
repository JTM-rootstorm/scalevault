"""Add immutable selection history and candidate lifecycle storage.

Revision ID: 0003_selection_policy_lifecycle
Revises: 0002_hybrid_retrieval
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_selection_policy_lifecycle"
down_revision: str | None = "0002_hybrid_retrieval"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_EXPRESSION = (
    "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
)


def upgrade() -> None:
    op.drop_constraint(op.f("ck_memory_events_operation_values"), "memory_events", type_="check")
    op.drop_constraint(
        op.f("ck_memory_events_operation_envelope_shape"), "memory_events", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_memory_events_operation_values"),
        "memory_events",
        "operation IN ('observed', 'remembered', 'revised', 'linked', 'unlinked', "
        "'evidence_attached', 'evidence_redacted', 'conflict_opened', 'conflict_resolved', "
        "'superseded', 'retired', 'tombstoned', 'branch_created', 'visibility_changed', "
        "'payload_purge_completed', 'candidate_promoted', 'candidate_expired')",
    )
    op.create_check_constraint(
        op.f("ck_memory_events_operation_envelope_shape"),
        "memory_events",
        "(operation IN ('observed', 'remembered', 'evidence_attached', 'evidence_redacted') "
        "AND memory_id IS NOT NULL AND expected_revision IS NULL) OR "
        "(operation IN ('revised', 'retired', 'visibility_changed', 'superseded', "
        "'tombstoned', 'payload_purge_completed', 'candidate_promoted', 'candidate_expired') "
        "AND memory_id IS NOT NULL AND expected_revision IS NOT NULL) OR "
        "(operation IN ('branch_created', 'linked', 'unlinked', 'conflict_opened', "
        "'conflict_resolved') AND memory_id IS NULL AND expected_revision IS NULL)",
    )

    op.add_column(
        "memories",
        sa.Column("candidate_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_memories_candidate_expiry_shape"),
        "memories",
        "(status = 'candidate' AND "
        "(candidate_expires_at IS NULL OR candidate_expires_at > created_at)) OR "
        "(status <> 'candidate' AND candidate_expires_at IS NULL)",
    )
    op.create_index(
        "ix_memories_candidate_expiry",
        "memories",
        ["tenant_id", "candidate_expires_at"],
        unique=False,
        postgresql_where=sa.text("status = 'candidate' AND candidate_expires_at IS NOT NULL"),
    )

    op.create_table(
        "selection_decision_counter",
        sa.Column("counter_id", sa.SmallInteger(), server_default=sa.text("1"), nullable=False),
        sa.Column("next_sequence", sa.BigInteger(), server_default=sa.text("1"), nullable=False),
        sa.CheckConstraint(
            "counter_id = 1",
            name=op.f("ck_selection_decision_counter_singleton_id"),
        ),
        sa.CheckConstraint(
            "next_sequence >= 1",
            name=op.f("ck_selection_decision_counter_next_sequence_positive"),
        ),
        sa.PrimaryKeyConstraint("counter_id", name=op.f("pk_selection_decision_counter")),
    )
    op.execute(
        sa.text("INSERT INTO selection_decision_counter (counter_id, next_sequence) VALUES (1, 1)")
    )

    op.create_table(
        "selection_decisions",
        sa.Column("selection_sequence", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("decision_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("persona_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.SmallInteger(), nullable=False),
        sa.Column("policy_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("policy_rule_code", sa.String(length=64), nullable=False),
        sa.Column("input_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("source_kind", sa.String(length=32), nullable=False),
        sa.Column("requested_operation", sa.String(length=16), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("matched_rule_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("selection_basis", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("visibility", sa.String(length=16), nullable=False),
        sa.Column("sensitivity", sa.SmallInteger(), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("subject_kind", sa.String(length=16), nullable=False),
        sa.Column("memory_id", sa.Uuid(), nullable=True),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(decision_id)",
            name=op.f("ck_selection_decisions_decision_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "octet_length(input_sha256) = 32",
            name=op.f("ck_selection_decisions_input_sha256_length"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(matched_rule_ids) = 'array' AND "
            "jsonb_array_length(matched_rule_ids) BETWEEN 0 AND 16",
            name=op.f("ck_selection_decisions_matched_rule_ids_shape"),
        ),
        sa.CheckConstraint(
            "NOT jsonb_path_exists(matched_rule_ids, "
            '\'$[*] ? (@.type() != "string" || '
            '!(@ like_regex "^[a-z][a-z0-9_.-]{0,127}$"))\')',
            name=op.f("ck_selection_decisions_matched_rule_ids_safe"),
        ),
        sa.CheckConstraint(
            "(outcome IN ('candidate', 'active', 'promoted', 'expired') "
            "AND memory_id IS NOT NULL AND event_id IS NOT NULL) OR "
            "(outcome IN ('omit', 'reject') "
            "AND memory_id IS NULL AND event_id IS NULL)",
            name=op.f("ck_selection_decisions_outcome_link_shape"),
        ),
        sa.CheckConstraint(
            "outcome IN ('omit', 'reject', 'candidate', 'active', 'promoted', 'expired')",
            name=op.f("ck_selection_decisions_outcome_values"),
        ),
        sa.CheckConstraint(
            "(requested_operation = 'nominate' AND "
            "outcome IN ('omit', 'reject', 'candidate', 'active')) OR "
            "(requested_operation = 'promote' AND "
            "outcome IN ('omit', 'reject', 'promoted')) OR "
            "(requested_operation = 'expire' AND "
            "outcome IN ('omit', 'reject', 'expired'))",
            name=op.f("ck_selection_decisions_operation_outcome_compatible"),
        ),
        sa.CheckConstraint(
            "policy_id = 'scalevault-memory-selection'",
            name=op.f("ck_selection_decisions_policy_id_value"),
        ),
        sa.CheckConstraint(
            "policy_rule_code ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=op.f("ck_selection_decisions_policy_rule_code_safe"),
        ),
        sa.CheckConstraint(
            "octet_length(policy_sha256) = 32",
            name=op.f("ck_selection_decisions_policy_sha256_length"),
        ),
        sa.CheckConstraint(
            "policy_version = 1", name=op.f("ck_selection_decisions_policy_version_value")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reason_codes) = 'array' AND "
            "jsonb_array_length(reason_codes) BETWEEN 1 AND 8",
            name=op.f("ck_selection_decisions_reason_codes_shape"),
        ),
        sa.CheckConstraint(
            "NOT jsonb_path_exists(reason_codes, "
            '\'$[*] ? (@.type() != "string" || '
            '!(@ like_regex "^[a-z][a-z0-9_]{0,63}$"))\')',
            name=op.f("ck_selection_decisions_reason_codes_safe"),
        ),
        sa.CheckConstraint(
            "requested_operation IN ('nominate', 'promote', 'expire')",
            name=op.f("ck_selection_decisions_requested_operation_values"),
        ),
        sa.CheckConstraint(
            "scope IN ('global', 'persona', 'relationship', 'project', 'episodic', 'scene_local')",
            name=op.f("ck_selection_decisions_scope_values"),
        ),
        sa.CheckConstraint(
            "(scope = 'global' AND subject_kind = 'global') OR "
            "(scope = 'persona' AND subject_kind = 'persona') OR "
            "(scope = 'relationship' AND subject_kind = 'relationship') OR "
            "(scope = 'project' AND subject_kind = 'project') OR "
            "(scope = 'episodic' AND subject_kind = 'episode') OR "
            "(scope = 'scene_local' AND subject_kind = 'scene')",
            name=op.f("ck_selection_decisions_scope_subject_kind"),
        ),
        sa.CheckConstraint(
            "selection_basis IN ('routine_banter', 'explicit_user_correction', "
            "'explicit_user_preference', 'explicit_user_permission', "
            "'verified_project_decision', 'assistant_observation', "
            "'assistant_interpretation', 'imported_legacy', "
            "'meaningful_episodic_anchor', 'explicit_user_request')",
            name=op.f("ck_selection_decisions_selection_basis_values"),
        ),
        sa.CheckConstraint(
            "selection_sequence >= 1",
            name=op.f("ck_selection_decisions_selection_sequence_positive"),
        ),
        sa.CheckConstraint(
            "sensitivity BETWEEN 0 AND 4",
            name=op.f("ck_selection_decisions_sensitivity_range"),
        ),
        sa.CheckConstraint(
            "source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal', "
            "'candidate_reassessment', 'candidate_expiry')",
            name=op.f("ck_selection_decisions_source_kind_values"),
        ),
        sa.CheckConstraint(
            "(source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal') "
            "AND requested_operation = 'nominate') OR "
            "(source_kind = 'candidate_reassessment' AND requested_operation = 'promote') OR "
            "(source_kind = 'candidate_expiry' AND requested_operation = 'expire')",
            name=op.f("ck_selection_decisions_source_operation_compatible"),
        ),
        sa.CheckConstraint(
            "subject_kind IN ('global', 'persona', 'relationship', 'project', 'episode', "
            "'scene', 'concept')",
            name=op.f("ck_selection_decisions_subject_kind_values"),
        ),
        sa.CheckConstraint(
            "visibility IN ('private_root', 'restricted', 'shareable', 'public_seed')",
            name=op.f("ck_selection_decisions_visibility_values"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "actor_id"],
            ["actors.tenant_id", "actors.actor_id"],
            name="actor",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "client_id"],
            ["clients.tenant_id", "clients.client_id"],
            name="client",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "persona_id"],
            ["lineages.tenant_id", "lineages.lineage_id", "lineages.persona_id"],
            name="lineage_persona",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "subject_id", "subject_kind"],
            ["subjects.tenant_id", "subjects.lineage_id", "subjects.subject_id", "subjects.kind"],
            name="subject",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
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
        sa.PrimaryKeyConstraint("selection_sequence", name=op.f("pk_selection_decisions")),
        sa.UniqueConstraint("decision_id", name="selection_decision_id"),
        sa.UniqueConstraint("tenant_id", "decision_id", name="tenant_selection_decision"),
        sa.UniqueConstraint(
            "tenant_id",
            "lineage_id",
            "selection_sequence",
            name="tenant_lineage_selection_sequence",
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )
    op.create_index(
        "ix_selection_decisions_branch_sequence",
        "selection_decisions",
        ["tenant_id", "lineage_id", "branch_id", sa.text("selection_sequence DESC")],
        unique=False,
    )
    op.create_index(
        "ix_selection_decisions_memory",
        "selection_decisions",
        ["tenant_id", "lineage_id", "memory_id"],
        unique=False,
        postgresql_where=sa.text("memory_id IS NOT NULL"),
    )
    op.execute(sa.text("ALTER TABLE public.selection_decisions ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.selection_decisions FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY scalevault_tenant_isolation ON public.selection_decisions "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_selection_decisions_immutable "
            "BEFORE UPDATE OR DELETE ON public.selection_decisions FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_selection_decisions_immutable_truncate "
            "BEFORE TRUNCATE ON public.selection_decisions FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )

    op.alter_column("command_receipts", "event_id", existing_type=sa.Uuid(), nullable=True)
    op.add_column("command_receipts", sa.Column("selection_decision_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "selection_decision",
        "command_receipts",
        "selection_decisions",
        ["tenant_id", "selection_decision_id"],
        ["tenant_id", "decision_id"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_check_constraint(
        op.f("ck_command_receipts_terminal_reference_shape"),
        "command_receipts",
        "(selection_decision_id IS NULL AND event_id IS NOT NULL) OR "
        "(selection_decision_id IS NOT NULL AND "
        "((event_id IS NOT NULL AND memory_id IS NOT NULL AND memory_revision IS NOT NULL) OR "
        "(event_id IS NULL AND memory_id IS NULL AND memory_revision IS NULL)))",
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 3, "
            "minimum_reader_revision = '0003_selection_policy_lifecycle', "
            "minimum_writer_revision = '0003_selection_policy_lifecycle' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 2, "
            "minimum_reader_revision = '0002_hybrid_retrieval', "
            "minimum_writer_revision = '0002_hybrid_retrieval' "
            "WHERE component = 'memory_node'"
        )
    )
    op.drop_constraint(
        op.f("ck_command_receipts_terminal_reference_shape"),
        "command_receipts",
        type_="check",
    )
    op.drop_constraint("selection_decision", "command_receipts", type_="foreignkey")
    op.drop_column("command_receipts", "selection_decision_id")
    op.alter_column("command_receipts", "event_id", existing_type=sa.Uuid(), nullable=False)

    op.drop_table("selection_decisions")
    op.drop_table("selection_decision_counter")
    op.drop_index(
        "ix_memories_candidate_expiry",
        table_name="memories",
        postgresql_where=sa.text("status = 'candidate' AND candidate_expires_at IS NOT NULL"),
    )
    op.drop_constraint(op.f("ck_memories_candidate_expiry_shape"), "memories", type_="check")
    op.drop_column("memories", "candidate_expires_at")

    op.drop_constraint(
        op.f("ck_memory_events_operation_envelope_shape"), "memory_events", type_="check"
    )
    op.drop_constraint(op.f("ck_memory_events_operation_values"), "memory_events", type_="check")
    op.create_check_constraint(
        op.f("ck_memory_events_operation_values"),
        "memory_events",
        "operation IN ('observed', 'remembered', 'revised', 'linked', 'unlinked', "
        "'evidence_attached', 'evidence_redacted', 'conflict_opened', 'conflict_resolved', "
        "'superseded', 'retired', 'tombstoned', 'branch_created', 'visibility_changed', "
        "'payload_purge_completed')",
    )
    op.create_check_constraint(
        op.f("ck_memory_events_operation_envelope_shape"),
        "memory_events",
        "(operation IN ('observed', 'remembered', 'evidence_attached', 'evidence_redacted') "
        "AND memory_id IS NOT NULL AND expected_revision IS NULL) OR "
        "(operation IN ('revised', 'retired', 'visibility_changed', 'superseded', "
        "'tombstoned', 'payload_purge_completed') AND memory_id IS NOT NULL AND "
        "expected_revision IS NOT NULL) OR "
        "(operation IN ('branch_created', 'linked', 'unlinked', 'conflict_opened', "
        "'conflict_resolved') AND memory_id IS NULL AND expected_revision IS NULL)",
    )
