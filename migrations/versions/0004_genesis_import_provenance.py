"""Add protected provenance for the pinned Genesis first import.

Revision ID: 0004_genesis_import_provenance
Revises: 0003_selection_policy_lifecycle
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_genesis_import_provenance"
down_revision: str | None = "0003_selection_policy_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_EXPRESSION = (
    "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
)
_GENESIS_TABLES = (
    "genesis_import_runs",
    "genesis_import_sources",
    "genesis_import_records",
    "genesis_import_exclusions",
    "genesis_import_supersessions",
    "genesis_import_run_results",
)


def _protect_immutable_table(table_name: str) -> None:
    op.execute(sa.text(f"ALTER TABLE public.{table_name} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE public.{table_name} FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            f"CREATE POLICY scalevault_tenant_isolation ON public.{table_name} "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    op.execute(
        sa.text(
            f"CREATE TRIGGER trg_{table_name}_immutable "
            f"BEFORE UPDATE OR DELETE ON public.{table_name} FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            f"CREATE TRIGGER trg_{table_name}_immutable_truncate "
            f"BEFORE TRUNCATE ON public.{table_name} FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )


def _create_run() -> None:
    op.create_table(
        "genesis_import_runs",
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("source_repository", sa.String(255), nullable=False),
        sa.Column("snapshot_commit", sa.String(40), nullable=False),
        sa.Column("plan_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("canonical_mapping_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("manifest_version", sa.String(64), nullable=False),
        sa.Column("mapping_version", sa.String(64), nullable=False),
        sa.Column("compatibility_version", sa.String(64), nullable=False),
        sa.Column("parser_schema_versions", postgresql.JSONB(), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("policy_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column("pre_state_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("backup_reference", sa.String(255), nullable=False),
        sa.Column(
            "planned_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "source_repository = 'JTM-rootstorm/scalevault-memory-ingress'",
            name=op.f("ck_genesis_import_runs_source_repository_value"),
        ),
        sa.CheckConstraint(
            "snapshot_commit = '7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9'",
            name=op.f("ck_genesis_import_runs_snapshot_commit_value"),
        ),
        sa.CheckConstraint(
            "manifest_version = 'scalevault.genesis-import-manifest.v1'",
            name=op.f("ck_genesis_import_runs_manifest_version_value"),
        ),
        sa.CheckConstraint(
            "mapping_version = 'genesis-import-mapping-v1'",
            name=op.f("ck_genesis_import_runs_mapping_version_value"),
        ),
        sa.CheckConstraint(
            "compatibility_version = 'genesis-first-import-compat-v1'",
            name=op.f("ck_genesis_import_runs_compatibility_version_value"),
        ),
        sa.CheckConstraint(
            "parser_schema_versions = "
            '\'{"scalevault.ingress.proposal.v1":"proposal-v1.schema.1",'
            '"scalevault.ingress.genesis-checkpoint.v1":'
            '"checkpoint-v1.documented.1",'
            '"scalevault.ingress.genesis-checkpoint.v2":'
            '"checkpoint-v2.schema.1"}\'::jsonb',
            name=op.f("ck_genesis_import_runs_parser_schema_versions_value"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(parser_schema_versions) = 'object'",
            name=op.f("ck_genesis_import_runs_parser_schema_versions_object"),
        ),
        sa.CheckConstraint(
            "policy_id = 'scalevault-memory-selection'",
            name=op.f("ck_genesis_import_runs_policy_id_value"),
        ),
        sa.CheckConstraint(
            "policy_version = 'selection-v1'",
            name=op.f("ck_genesis_import_runs_policy_version_value"),
        ),
        sa.CheckConstraint(
            "encode(policy_sha256, 'hex') = "
            "'b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e'",
            name=op.f("ck_genesis_import_runs_policy_sha256_value"),
        ),
        sa.CheckConstraint(
            "octet_length(plan_sha256) = 32",
            name=op.f("ck_genesis_import_runs_plan_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(canonical_mapping_sha256) = 32",
            name=op.f("ck_genesis_import_runs_canonical_mapping_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(policy_sha256) = 32",
            name=op.f("ck_genesis_import_runs_policy_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(pre_state_sha256) = 32",
            name=op.f("ck_genesis_import_runs_pre_state_sha256_length"),
        ),
        sa.CheckConstraint(
            "length(backup_reference) BETWEEN 1 AND 255",
            name=op.f("ck_genesis_import_runs_backup_reference_length"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(import_run_id)",
            name=op.f("ck_genesis_import_runs_import_run_id_uuid_v7"),
        ),
        sa.CheckConstraint(
            "source_count >= 1", name=op.f("ck_genesis_import_runs_source_count_positive")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("import_run_id", name=op.f("pk_genesis_import_runs")),
        sa.UniqueConstraint("tenant_id", "import_run_id", name="tenant_genesis_import_run"),
        sa.UniqueConstraint("tenant_id", "plan_sha256", name="tenant_genesis_import_plan"),
        sa.UniqueConstraint(
            "tenant_id",
            "source_repository",
            "snapshot_commit",
            "mapping_version",
            name="tenant_genesis_import_source_mapping",
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )


def _create_source() -> None:
    op.create_table(
        "genesis_import_sources",
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_contract_version", sa.String(64), nullable=False),
        sa.Column("source_identity", sa.String(255), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("blob_object_id", sa.String(40), nullable=False),
        sa.Column("raw_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("raw_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("introducing_commit", sa.String(40), nullable=True),
        sa.Column("parsed_document", postgresql.JSONB(), nullable=False),
        sa.Column("parsed_canonical_json", sa.LargeBinary(), nullable=False),
        sa.Column("parsed_canonical_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("proposal_id", sa.String(255), nullable=True),
        sa.Column("checkpoint_id", sa.String(255), nullable=True),
        sa.Column("previous_checkpoint_id", sa.String(255), nullable=True),
        sa.Column("declared_idempotency_key", sa.String(512), nullable=True),
        sa.Column("origin_actor_ref", sa.String(255), nullable=True),
        sa.Column("runtime_ref", sa.String(255), nullable=True),
        sa.Column("trigger_identity", sa.String(255), nullable=True),
        sa.Column("source_conversation_ref", sa.Text(), nullable=True),
        sa.Column("owner_ref", sa.String(255), nullable=True),
        sa.Column("perspective_ref", sa.String(255), nullable=True),
        sa.Column("subject_ref", sa.String(255), nullable=True),
        sa.Column("participant_refs", postgresql.JSONB(), nullable=False),
        sa.Column("relationship_ref", sa.String(255), nullable=True),
        sa.Column("interaction_ref", sa.String(255), nullable=True),
        sa.Column("original_visibility", sa.String(64), nullable=True),
        sa.Column("binding_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("provenance_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("compatibility_correction_version", sa.String(64), nullable=True),
        sa.Column("raw_compatibility_values", postgresql.JSONB(), nullable=True),
        sa.Column(
            "archived_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "source_kind IN ('proposal_v1', 'checkpoint_v1', 'checkpoint_v2')",
            name=op.f("ck_genesis_import_sources_kind_values"),
        ),
        sa.CheckConstraint(
            "(source_kind = 'proposal_v1' AND "
            "source_contract_version = 'proposal-v1.schema.1' AND "
            "source_path ~ '^ingress/v1/[^/]+/[0-9]{4}/[0-9]{2}/[^/]+[.]json$') OR "
            "(source_kind = 'checkpoint_v1' AND "
            "source_contract_version = 'checkpoint-v1.documented.1' AND "
            "source_path ~ '^ingress/checkpoints/v1/genesis/[0-9]{4}/[0-9]{2}/"
            "[^/]+[.]json$') OR "
            "(source_kind = 'checkpoint_v2' AND "
            "source_contract_version = 'checkpoint-v2.schema.1' AND "
            "source_path ~ '^ingress/checkpoints/v2/genesis/[0-9]{4}/[0-9]{2}/"
            "[^/]+[.]json$')",
            name=op.f("ck_genesis_import_sources_kind_contract_path"),
        ),
        sa.CheckConstraint(
            "blob_object_id ~ '^[0-9a-f]{40}$'",
            name=op.f("ck_genesis_import_sources_blob_object_id_shape"),
        ),
        sa.CheckConstraint(
            "introducing_commit IS NULL OR introducing_commit ~ '^[0-9a-f]{40}$'",
            name=op.f("ck_genesis_import_sources_introducing_commit_shape"),
        ),
        sa.CheckConstraint(
            "octet_length(raw_bytes) BETWEEN 1 AND 16777216",
            name=op.f("ck_genesis_import_sources_raw_bytes_size"),
        ),
        sa.CheckConstraint(
            "digest(raw_bytes, 'sha256') = raw_sha256",
            name=op.f("ck_genesis_import_sources_raw_sha256_matches"),
        ),
        sa.CheckConstraint(
            "octet_length(raw_sha256) = 32",
            name=op.f("ck_genesis_import_sources_raw_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(parsed_canonical_json) BETWEEN 2 AND 16777216",
            name=op.f("ck_genesis_import_sources_parsed_canonical_json_size"),
        ),
        sa.CheckConstraint(
            "digest(parsed_canonical_json, 'sha256') = parsed_canonical_sha256",
            name=op.f("ck_genesis_import_sources_parsed_canonical_sha256_matches"),
        ),
        sa.CheckConstraint(
            "octet_length(parsed_canonical_sha256) = 32",
            name=op.f("ck_genesis_import_sources_parsed_canonical_sha256_length"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(parsed_document) = 'object'",
            name=op.f("ck_genesis_import_sources_parsed_document_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(participant_refs) = 'array'",
            name=op.f("ck_genesis_import_sources_participant_refs_array"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(binding_metadata) = 'object'",
            name=op.f("ck_genesis_import_sources_binding_metadata_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(provenance_metadata) = 'object'",
            name=op.f("ck_genesis_import_sources_provenance_metadata_object"),
        ),
        sa.CheckConstraint(
            "source_conversation_ref IS NULL OR length(source_conversation_ref) <= 2048",
            name=op.f("ck_genesis_import_sources_source_conversation_ref_length"),
        ),
        sa.CheckConstraint(
            "(source_kind = 'proposal_v1' AND proposal_id IS NOT NULL AND "
            "checkpoint_id IS NULL) OR "
            "(source_kind IN ('checkpoint_v1', 'checkpoint_v2') AND "
            "checkpoint_id IS NOT NULL AND proposal_id IS NULL)",
            name=op.f("ck_genesis_import_sources_document_identity_shape"),
        ),
        sa.CheckConstraint(
            "(compatibility_correction_version IS NULL AND "
            "raw_compatibility_values IS NULL) OR "
            "(compatibility_correction_version = 'genesis-first-import-compat-v1' AND "
            "source_path = 'ingress/checkpoints/v2/genesis/2026/08/"
            "genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-"
            "c24031dcce20.json' AND "
            "blob_object_id = '76214f303012d756c34a3b5bdf9948267a1418e3' AND "
            "encode(raw_sha256, 'hex') = "
            "'f0f147d1ee8c748c7080ee821f1a48751b50d31c78912cbd3e1b358da39f83e7' AND "
            "checkpoint_id = "
            "'genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20' "
            "AND raw_compatibility_values = "
            '\'{"/candidates/1/disposition":"federation_shared_candidate",'
            '"/candidates/1/scope":"federation",'
            '"/candidates/1/binding/visibility":"federation_shared_candidate",'
            '"/exclusions/0/scope":"federation",'
            '"/exclusions/1/scope":"federation"}\'::jsonb)',
            name=op.f("ck_genesis_import_sources_compatibility_correction_shape"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(source_id)",
            name=op.f("ck_genesis_import_sources_source_id_uuid_v7"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id"],
            ["genesis_import_runs.tenant_id", "genesis_import_runs.import_run_id"],
            name="import_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("source_id", name=op.f("pk_genesis_import_sources")),
        sa.UniqueConstraint(
            "tenant_id", "import_run_id", "source_id", name="genesis_source_run_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id", "import_run_id", "source_path", name="genesis_source_run_path"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_identity",
            name="genesis_source_run_external_identity",
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )
    op.create_index(
        "ix_genesis_sources_run",
        "genesis_import_sources",
        ["tenant_id", "import_run_id", "source_id"],
        unique=False,
    )


def _create_record() -> None:
    op.create_table(
        "genesis_import_records",
        sa.Column("import_record_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("lineage_id", sa.Uuid(), nullable=False),
        sa.Column("branch_id", sa.Uuid(), nullable=False),
        sa.Column("record_kind", sa.String(16), nullable=False),
        sa.Column("source_item_identity", sa.String(255), nullable=False),
        sa.Column("source_item_document", postgresql.JSONB(), nullable=False),
        sa.Column("nomination_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("nomination_idempotency_key", sa.String(255), nullable=False),
        sa.Column("mapping_version", sa.String(64), nullable=False),
        sa.Column("selection_basis", sa.String(64), nullable=False),
        sa.Column("qualifier", sa.String(64), nullable=True),
        sa.Column("requested_outcome_ceiling", sa.String(16), nullable=False),
        sa.Column("effective_visibility", sa.String(16), nullable=False),
        sa.Column("unresolved_legacy_binding", sa.Boolean(), nullable=False),
        sa.Column("original_candidate_type", sa.String(64), nullable=True),
        sa.Column("original_disposition", sa.String(64), nullable=True),
        sa.Column("original_confidence", sa.String(64), nullable=True),
        sa.Column("original_scope", sa.String(64), nullable=True),
        sa.Column("original_ontology", sa.String(64), nullable=True),
        sa.Column("original_visibility", sa.String(64), nullable=True),
        sa.Column("review_recommendation", sa.String(64), nullable=True),
        sa.Column("evidence_references", postgresql.JSONB(), nullable=False),
        sa.Column("interpretation_limits", postgresql.JSONB(), nullable=False),
        sa.Column("mapping_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("provenance_metadata", postgresql.JSONB(), nullable=False),
        sa.Column(
            "processing_state",
            sa.String(16),
            server_default=sa.text("'planned'"),
            nullable=False,
        ),
        sa.Column("selection_decision_id", sa.Uuid(), nullable=True),
        sa.Column("event_id", sa.Uuid(), nullable=True),
        sa.Column("memory_id", sa.Uuid(), nullable=True),
        sa.Column(
            "planned_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "record_kind IN ('proposal', 'candidate')",
            name=op.f("ck_genesis_import_records_record_kind_values"),
        ),
        sa.CheckConstraint(
            "processing_state IN ('planned', 'candidate', 'omit', 'reject')",
            name=op.f("ck_genesis_import_records_processing_state_values"),
        ),
        sa.CheckConstraint(
            "mapping_version = 'genesis-import-mapping-v1'",
            name=op.f("ck_genesis_import_records_mapping_version_value"),
        ),
        sa.CheckConstraint(
            "selection_basis = 'imported_legacy'",
            name=op.f("ck_genesis_import_records_selection_basis_value"),
        ),
        sa.CheckConstraint(
            "requested_outcome_ceiling = 'candidate'",
            name=op.f("ck_genesis_import_records_outcome_ceiling_value"),
        ),
        sa.CheckConstraint(
            "effective_visibility = 'private_root'",
            name=op.f("ck_genesis_import_records_visibility_value"),
        ),
        sa.CheckConstraint(
            "(processing_state = 'planned' AND selection_decision_id IS NULL AND "
            "event_id IS NULL AND memory_id IS NULL AND processed_at IS NULL) OR "
            "(processing_state IN ('omit', 'reject') AND "
            "selection_decision_id IS NOT NULL AND event_id IS NULL AND "
            "memory_id IS NULL AND processed_at IS NOT NULL) OR "
            "(processing_state = 'candidate' AND selection_decision_id IS NOT NULL AND "
            "event_id IS NOT NULL AND memory_id IS NOT NULL AND processed_at IS NOT NULL)",
            name=op.f("ck_genesis_import_records_terminal_result_shape"),
        ),
        sa.CheckConstraint(
            "octet_length(nomination_sha256) = 32",
            name=op.f("ck_genesis_import_records_nomination_sha256_length"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_item_document) = 'object'",
            name=op.f("ck_genesis_import_records_source_item_document_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence_references) = 'array'",
            name=op.f("ck_genesis_import_records_evidence_references_array"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(interpretation_limits) = 'array'",
            name=op.f("ck_genesis_import_records_interpretation_limits_array"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(mapping_metadata) = 'object'",
            name=op.f("ck_genesis_import_records_mapping_metadata_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(provenance_metadata) = 'object'",
            name=op.f("ck_genesis_import_records_provenance_metadata_object"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(import_record_id)",
            name=op.f("ck_genesis_import_records_import_record_id_uuid_v7"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "selection_decision_id"],
            ["selection_decisions.tenant_id", "selection_decisions.decision_id"],
            name="selection_decision",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
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
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("import_record_id", name=op.f("pk_genesis_import_records")),
        sa.UniqueConstraint(
            "tenant_id", "import_run_id", "import_record_id", name="genesis_record_run_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_id",
            "source_item_identity",
            name="genesis_record_source_item",
        ),
        sa.UniqueConstraint(
            "tenant_id", "nomination_sha256", name="tenant_genesis_nomination_digest"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "nomination_idempotency_key",
            name="tenant_genesis_nomination_idempotency",
        ),
        info={
            "scalevault_tenant_owned": True,
            "scalevault_immutable_fields": (
                "import_record_id",
                "tenant_id",
                "import_run_id",
                "source_id",
                "lineage_id",
                "branch_id",
                "record_kind",
                "source_item_identity",
                "source_item_document",
                "nomination_sha256",
                "nomination_idempotency_key",
                "mapping_version",
                "selection_basis",
                "qualifier",
                "requested_outcome_ceiling",
                "effective_visibility",
                "unresolved_legacy_binding",
                "original_candidate_type",
                "original_disposition",
                "original_confidence",
                "original_scope",
                "original_ontology",
                "original_visibility",
                "review_recommendation",
                "evidence_references",
                "interpretation_limits",
                "mapping_metadata",
                "provenance_metadata",
                "planned_at",
            ),
        },
    )
    op.create_index(
        "ix_genesis_records_pending",
        "genesis_import_records",
        ["tenant_id", "import_run_id", "import_record_id"],
        unique=False,
        postgresql_where=sa.text("processing_state = 'planned'"),
    )


def _create_exclusion() -> None:
    op.create_table(
        "genesis_import_exclusions",
        sa.Column("exclusion_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("applies_to_record_id", sa.Uuid(), nullable=True),
        sa.Column("source_exclusion_identity", sa.String(255), nullable=False),
        sa.Column("claim", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("raw_scope", sa.String(64), nullable=True),
        sa.Column("actor_ref", sa.String(255), nullable=True),
        sa.Column("relationship_ref", sa.String(255), nullable=True),
        sa.Column("binding_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("provenance_metadata", postgresql.JSONB(), nullable=False),
        sa.Column("blocks_automatic_promotion", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(claim) BETWEEN 1 AND 4096",
            name=op.f("ck_genesis_import_exclusions_claim_length"),
        ),
        sa.CheckConstraint(
            "length(reason) BETWEEN 1 AND 4096",
            name=op.f("ck_genesis_import_exclusions_reason_length"),
        ),
        sa.CheckConstraint(
            "blocks_automatic_promotion",
            name=op.f("ck_genesis_import_exclusions_blocks_automatic_promotion_true"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(binding_metadata) = 'object'",
            name=op.f("ck_genesis_import_exclusions_binding_metadata_object"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(provenance_metadata) = 'object'",
            name=op.f("ck_genesis_import_exclusions_provenance_metadata_object"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(exclusion_id)",
            name=op.f("ck_genesis_import_exclusions_exclusion_id_uuid_v7"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "applies_to_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="applies_to_record",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("exclusion_id", name=op.f("pk_genesis_import_exclusions")),
        sa.UniqueConstraint(
            "tenant_id", "import_run_id", "exclusion_id", name="genesis_exclusion_run_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_id",
            "source_exclusion_identity",
            name="genesis_exclusion_source_identity",
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )


def _create_supersession() -> None:
    op.create_table(
        "genesis_import_supersessions",
        sa.Column("supersession_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("predecessor_record_id", sa.Uuid(), nullable=True),
        sa.Column("predecessor_exclusion_id", sa.Uuid(), nullable=True),
        sa.Column("successor_record_id", sa.Uuid(), nullable=True),
        sa.Column("successor_exclusion_id", sa.Uuid(), nullable=True),
        sa.Column("provenance_metadata", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(predecessor_record_id IS NULL) <> (predecessor_exclusion_id IS NULL)",
            name=op.f("ck_genesis_import_supersessions_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "(successor_record_id IS NULL) <> (successor_exclusion_id IS NULL)",
            name=op.f("ck_genesis_import_supersessions_successor_shape"),
        ),
        sa.CheckConstraint(
            "predecessor_record_id IS DISTINCT FROM successor_record_id OR "
            "predecessor_exclusion_id IS DISTINCT FROM successor_exclusion_id",
            name=op.f("ck_genesis_import_supersessions_not_self"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(provenance_metadata) = 'object'",
            name=op.f("ck_genesis_import_supersessions_provenance_metadata_object"),
        ),
        sa.CheckConstraint(
            "scalevault_is_uuid_v7(supersession_id)",
            name=op.f("ck_genesis_import_supersessions_supersession_id_uuid_v7"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "predecessor_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="predecessor_record",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "predecessor_exclusion_id"],
            [
                "genesis_import_exclusions.tenant_id",
                "genesis_import_exclusions.import_run_id",
                "genesis_import_exclusions.exclusion_id",
            ],
            name="predecessor_exclusion",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "successor_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="successor_record",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "successor_exclusion_id"],
            [
                "genesis_import_exclusions.tenant_id",
                "genesis_import_exclusions.import_run_id",
                "genesis_import_exclusions.exclusion_id",
            ],
            name="successor_exclusion",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("supersession_id", name=op.f("pk_genesis_import_supersessions")),
        sa.UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "predecessor_record_id",
            "predecessor_exclusion_id",
            "successor_record_id",
            "successor_exclusion_id",
            name="genesis_supersession_edge",
            postgresql_nulls_not_distinct=True,
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )


def _create_run_result() -> None:
    op.create_table(
        "genesis_import_run_results",
        sa.Column("import_run_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("planned_record_count", sa.Integer(), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False),
        sa.Column("omit_count", sa.Integer(), nullable=False),
        sa.Column("reject_count", sa.Integer(), nullable=False),
        sa.Column("replay_verified", sa.Boolean(), nullable=False),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "planned_record_count >= 0",
            name=op.f("ck_genesis_import_run_results_planned_record_count_nonnegative"),
        ),
        sa.CheckConstraint(
            "candidate_count >= 0 AND omit_count >= 0 AND reject_count >= 0",
            name=op.f("ck_genesis_import_run_results_outcome_counts_nonnegative"),
        ),
        sa.CheckConstraint(
            "planned_record_count = candidate_count + omit_count + reject_count",
            name=op.f("ck_genesis_import_run_results_outcome_counts_complete"),
        ),
        sa.CheckConstraint(
            "replay_verified",
            name=op.f("ck_genesis_import_run_results_replay_verified_true"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "import_run_id"],
            ["genesis_import_runs.tenant_id", "genesis_import_runs.import_run_id"],
            name="import_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "import_run_id", "tenant_id", name=op.f("pk_genesis_import_run_results")
        ),
        info={"scalevault_tenant_owned": True, "scalevault_immutable": True},
    )


def _protect_run_completion() -> None:
    op.execute(
        sa.text(
            "CREATE FUNCTION public.scalevault_enforce_genesis_run_completion() "
            "RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $function$ "
            "DECLARE actual_planned bigint; actual_candidate bigint; "
            "actual_omit bigint; actual_reject bigint; "
            "BEGIN "
            "SELECT count(*) FILTER (WHERE processing_state = 'planned'), "
            "count(*) FILTER (WHERE processing_state = 'candidate'), "
            "count(*) FILTER (WHERE processing_state = 'omit'), "
            "count(*) FILTER (WHERE processing_state = 'reject') "
            "INTO actual_planned, actual_candidate, actual_omit, actual_reject "
            "FROM public.genesis_import_records "
            "WHERE tenant_id = NEW.tenant_id AND import_run_id = NEW.import_run_id; "
            "IF actual_planned <> 0 OR NEW.planned_record_count <> "
            "actual_candidate + actual_omit + actual_reject "
            "OR NEW.candidate_count <> actual_candidate "
            "OR NEW.omit_count <> actual_omit OR NEW.reject_count <> actual_reject "
            "OR NOT NEW.replay_verified THEN "
            "RAISE EXCEPTION 'genesis import completion counts are not verified' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "IF EXISTS ("
            "SELECT 1 FROM public.genesis_import_records AS r "
            "LEFT JOIN public.selection_decisions AS d ON "
            "d.tenant_id = r.tenant_id AND d.decision_id = r.selection_decision_id "
            "LEFT JOIN public.memory_events AS e ON "
            "e.tenant_id = r.tenant_id AND e.event_id = r.event_id "
            "LEFT JOIN public.memories AS m ON "
            "m.tenant_id = r.tenant_id AND m.memory_id = r.memory_id "
            "WHERE r.tenant_id = NEW.tenant_id AND r.import_run_id = NEW.import_run_id "
            "AND (d.decision_id IS NULL OR d.source_kind <> 'genesis_import' "
            "OR d.requested_operation <> 'nominate' OR d.selection_basis <> 'imported_legacy' "
            "OR d.outcome <> r.processing_state OR d.lineage_id <> r.lineage_id "
            "OR d.branch_id <> r.branch_id OR d.event_id IS DISTINCT FROM r.event_id "
            "OR d.memory_id IS DISTINCT FROM r.memory_id "
            "OR (SELECT count(*) FROM public.command_receipts AS cr "
            "WHERE cr.tenant_id = r.tenant_id "
            "AND cr.selection_decision_id = r.selection_decision_id "
            "AND cr.idempotency_key = r.nomination_idempotency_key "
            "AND cr.event_id IS NOT DISTINCT FROM r.event_id "
            "AND cr.memory_id IS NOT DISTINCT FROM r.memory_id) <> 1 "
            "OR (r.processing_state = 'candidate' AND (e.event_id IS NULL "
            "OR e.lineage_id <> r.lineage_id OR e.branch_id <> r.branch_id "
            "OR e.memory_id <> r.memory_id OR e.idempotency_key <> r.nomination_idempotency_key "
            "OR e.operation <> 'observed' OR m.memory_id IS NULL "
            "OR m.lineage_id <> r.lineage_id OR m.branch_id <> r.branch_id "
            "OR m.status <> 'candidate' OR m.last_event_id <> r.event_id)))) THEN "
            "RAISE EXCEPTION 'genesis import completion linkage is not verified' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "RETURN NEW; END; $function$"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_genesis_import_run_results_verified "
            "BEFORE INSERT ON public.genesis_import_run_results FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_enforce_genesis_run_completion()"
        )
    )


def _protect_record_terminalization() -> None:
    op.execute(sa.text("ALTER TABLE public.genesis_import_records ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.genesis_import_records FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY scalevault_tenant_isolation ON public.genesis_import_records "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    immutable_fields = (
        "import_record_id",
        "tenant_id",
        "import_run_id",
        "source_id",
        "lineage_id",
        "branch_id",
        "record_kind",
        "source_item_identity",
        "source_item_document",
        "nomination_sha256",
        "nomination_idempotency_key",
        "mapping_version",
        "selection_basis",
        "qualifier",
        "requested_outcome_ceiling",
        "effective_visibility",
        "unresolved_legacy_binding",
        "original_candidate_type",
        "original_disposition",
        "original_confidence",
        "original_scope",
        "original_ontology",
        "original_visibility",
        "review_recommendation",
        "evidence_references",
        "interpretation_limits",
        "mapping_metadata",
        "provenance_metadata",
        "planned_at",
    )
    arguments = ", ".join(f"'{field}'" for field in immutable_fields)
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_genesis_import_records_immutable_fields "
            "BEFORE UPDATE ON public.genesis_import_records FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_field_mutation("
            f"{arguments})"
        )
    )
    op.execute(
        sa.text(
            "CREATE FUNCTION public.scalevault_enforce_genesis_record_terminalization() "
            "RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $function$ "
            "BEGIN "
            "IF TG_OP = 'INSERT' THEN "
            "IF NEW.processing_state <> 'planned' OR NEW.selection_decision_id IS NOT NULL "
            "OR NEW.event_id IS NOT NULL OR NEW.memory_id IS NOT NULL "
            "OR NEW.processed_at IS NOT NULL THEN "
            "RAISE EXCEPTION 'genesis import record must be inserted as planned' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "RETURN NEW; "
            "END IF; "
            "IF OLD.processing_state <> 'planned' THEN "
            "RAISE EXCEPTION 'genesis import record is already terminal' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "IF NEW.processing_state NOT IN ('candidate', 'omit', 'reject') THEN "
            "RAISE EXCEPTION 'invalid genesis import terminal state' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "RETURN NEW; END; $function$"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_genesis_import_records_terminal_transition "
            "BEFORE INSERT OR UPDATE ON public.genesis_import_records FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_enforce_genesis_record_terminalization()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_genesis_import_records_immutable_delete "
            "BEFORE DELETE ON public.genesis_import_records FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_genesis_import_records_immutable_truncate "
            "BEFORE TRUNCATE ON public.genesis_import_records FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )


def _extend_selection_source_kind() -> None:
    op.drop_constraint(
        op.f("ck_selection_decisions_source_operation_compatible"),
        "selection_decisions",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_selection_decisions_source_kind_values"),
        "selection_decisions",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_selection_decisions_source_kind_values"),
        "selection_decisions",
        "source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal', "
        "'candidate_reassessment', 'candidate_expiry', 'genesis_import')",
    )
    op.create_check_constraint(
        op.f("ck_selection_decisions_source_operation_compatible"),
        "selection_decisions",
        "(source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal', "
        "'genesis_import') AND requested_operation = 'nominate') OR "
        "(source_kind = 'candidate_reassessment' AND requested_operation = 'promote') OR "
        "(source_kind = 'candidate_expiry' AND requested_operation = 'expire')",
    )


def upgrade() -> None:
    _extend_selection_source_kind()
    _create_run()
    _create_source()
    _create_record()
    _create_exclusion()
    _create_supersession()
    _create_run_result()
    _protect_run_completion()
    for table_name in _GENESIS_TABLES:
        if table_name == "genesis_import_records":
            _protect_record_terminalization()
        else:
            _protect_immutable_table(table_name)
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 4, "
            "minimum_reader_revision = '0004_genesis_import_provenance', "
            "minimum_writer_revision = '0004_genesis_import_provenance' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DO $guard$ BEGIN "
            "IF EXISTS (SELECT 1 FROM public.selection_decisions "
            "WHERE source_kind = 'genesis_import') THEN "
            "RAISE EXCEPTION 'cannot downgrade while Genesis selection decisions exist' "
            "USING ERRCODE = '55000'; "
            "END IF; END $guard$"
        )
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 3, "
            "minimum_reader_revision = '0003_selection_policy_lifecycle', "
            "minimum_writer_revision = '0003_selection_policy_lifecycle' "
            "WHERE component = 'memory_node'"
        )
    )
    for table_name in reversed(_GENESIS_TABLES):
        op.drop_table(table_name)
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_genesis_run_completion()"))
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_genesis_record_terminalization()"))
    op.drop_constraint(
        op.f("ck_selection_decisions_source_operation_compatible"),
        "selection_decisions",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_selection_decisions_source_kind_values"),
        "selection_decisions",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_selection_decisions_source_kind_values"),
        "selection_decisions",
        "source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal', "
        "'candidate_reassessment', 'candidate_expiry')",
    )
    op.create_check_constraint(
        op.f("ck_selection_decisions_source_operation_compatible"),
        "selection_decisions",
        "(source_kind IN ('live_interaction', 'reviewed_seed', 'github_proposal') "
        "AND requested_operation = 'nominate') OR "
        "(source_kind = 'candidate_reassessment' AND requested_operation = 'promote') OR "
        "(source_kind = 'candidate_expiry' AND requested_operation = 'expire')",
    )
