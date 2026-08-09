"""Protected provenance storage for the pinned Genesis first import."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from kivra_memory.storage.base import TENANT_OWNED_INFO_KEY, Base
from kivra_memory.storage.models._shared import (
    json_array_check,
    json_object_check,
    sha256_check,
    uuid_v7_check,
    values_check,
)

GENESIS_REPOSITORY = "JTM-rootstorm/scalevault-memory-ingress"
GENESIS_SNAPSHOT = "7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9"
GENESIS_MANIFEST_VERSION = "scalevault.genesis-import-manifest.v1"
GENESIS_MAPPING_VERSION = "genesis-import-mapping-v1"
GENESIS_COMPATIBILITY_VERSION = "genesis-first-import-compat-v1"
GENESIS_POLICY_ID = "scalevault-memory-selection"
GENESIS_POLICY_VERSION = "selection-v1"
GENESIS_POLICY_SHA256 = "b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"

_PARSER_SCHEMA_VERSIONS = (
    '\'{"scalevault.ingress.proposal.v1":"proposal-v1.schema.1",'
    '"scalevault.ingress.genesis-checkpoint.v1":"checkpoint-v1.documented.1",'
    '"scalevault.ingress.genesis-checkpoint.v2":"checkpoint-v2.schema.1"}\'::jsonb'
)
_TENANT_IMMUTABLE = {"info": {TENANT_OWNED_INFO_KEY: True, "scalevault_immutable": True}}


class GenesisImportRun(Base):
    __tablename__ = "genesis_import_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "import_run_id", name="tenant_genesis_import_run"),
        UniqueConstraint("tenant_id", "plan_sha256", name="tenant_genesis_import_plan"),
        UniqueConstraint(
            "tenant_id",
            "source_repository",
            "snapshot_commit",
            "mapping_version",
            name="tenant_genesis_import_source_mapping",
        ),
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.tenant_id"], name="tenant", ondelete="RESTRICT"
        ),
        CheckConstraint(
            f"source_repository = '{GENESIS_REPOSITORY}'", name="source_repository_value"
        ),
        CheckConstraint(f"snapshot_commit = '{GENESIS_SNAPSHOT}'", name="snapshot_commit_value"),
        CheckConstraint(
            f"manifest_version = '{GENESIS_MANIFEST_VERSION}'", name="manifest_version_value"
        ),
        CheckConstraint(
            f"mapping_version = '{GENESIS_MAPPING_VERSION}'", name="mapping_version_value"
        ),
        CheckConstraint(
            f"compatibility_version = '{GENESIS_COMPATIBILITY_VERSION}'",
            name="compatibility_version_value",
        ),
        CheckConstraint(
            f"parser_schema_versions = {_PARSER_SCHEMA_VERSIONS}",
            name="parser_schema_versions_value",
        ),
        CheckConstraint(f"policy_id = '{GENESIS_POLICY_ID}'", name="policy_id_value"),
        CheckConstraint(
            f"policy_version = '{GENESIS_POLICY_VERSION}'", name="policy_version_value"
        ),
        CheckConstraint(
            f"encode(policy_sha256, 'hex') = '{GENESIS_POLICY_SHA256}'",
            name="policy_sha256_value",
        ),
        CheckConstraint("source_count >= 1", name="source_count_positive"),
        CheckConstraint(
            "length(backup_reference) BETWEEN 1 AND 255", name="backup_reference_length"
        ),
        sha256_check("plan_sha256", name="plan_sha256_length"),
        sha256_check("canonical_mapping_sha256", name="canonical_mapping_sha256_length"),
        sha256_check("policy_sha256", name="policy_sha256_length"),
        sha256_check("pre_state_sha256", name="pre_state_sha256_length"),
        json_object_check("parser_schema_versions", name="parser_schema_versions_object"),
        uuid_v7_check("import_run_id", name="import_run_id_uuid_v7"),
        _TENANT_IMMUTABLE,
    )

    import_run_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    source_repository: Mapped[str] = mapped_column(String(255), nullable=False)
    snapshot_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    plan_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    canonical_mapping_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    manifest_version: Mapped[str] = mapped_column(String(64), nullable=False)
    mapping_version: Mapped[str] = mapped_column(String(64), nullable=False)
    compatibility_version: Mapped[str] = mapped_column(String(64), nullable=False)
    parser_schema_versions: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    source_count: Mapped[int] = mapped_column(Integer(), nullable=False)
    pre_state_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    backup_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    planned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class GenesisImportSource(Base):
    __tablename__ = "genesis_import_sources"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "import_run_id", "source_id", name="genesis_source_run_identity"
        ),
        UniqueConstraint(
            "tenant_id", "import_run_id", "source_path", name="genesis_source_run_path"
        ),
        UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_identity",
            name="genesis_source_run_external_identity",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id"],
            ["genesis_import_runs.tenant_id", "genesis_import_runs.import_run_id"],
            name="import_run",
            ondelete="RESTRICT",
        ),
        values_check(
            "source_kind", ("proposal_v1", "checkpoint_v1", "checkpoint_v2"), name="kind_values"
        ),
        CheckConstraint(
            "(source_kind = 'proposal_v1' AND "
            "source_contract_version = 'proposal-v1.schema.1' AND "
            "source_path ~ '^ingress/v1/[^/]+/[0-9]{4}/[0-9]{2}/[^/]+[.]json$') OR "
            "(source_kind = 'checkpoint_v1' AND "
            "source_contract_version = 'checkpoint-v1.documented.1' AND "
            "source_path ~ '^ingress/checkpoints/v1/genesis/[0-9]{4}/[0-9]{2}/[^/]+[.]json$') OR "
            "(source_kind = 'checkpoint_v2' AND "
            "source_contract_version = 'checkpoint-v2.schema.1' AND "
            "source_path ~ '^ingress/checkpoints/v2/genesis/[0-9]{4}/[0-9]{2}/[^/]+[.]json$')",
            name="kind_contract_path",
        ),
        CheckConstraint("blob_object_id ~ '^[0-9a-f]{40}$'", name="blob_object_id_shape"),
        CheckConstraint(
            "introducing_commit IS NULL OR introducing_commit ~ '^[0-9a-f]{40}$'",
            name="introducing_commit_shape",
        ),
        CheckConstraint("octet_length(raw_bytes) BETWEEN 1 AND 16777216", name="raw_bytes_size"),
        CheckConstraint("digest(raw_bytes, 'sha256') = raw_sha256", name="raw_sha256_matches"),
        CheckConstraint(
            "octet_length(parsed_canonical_json) BETWEEN 2 AND 16777216",
            name="parsed_canonical_json_size",
        ),
        CheckConstraint(
            "digest(parsed_canonical_json, 'sha256') = parsed_canonical_sha256",
            name="parsed_canonical_sha256_matches",
        ),
        CheckConstraint(
            "source_conversation_ref IS NULL OR length(source_conversation_ref) <= 2048",
            name="source_conversation_ref_length",
        ),
        CheckConstraint(
            "(source_kind = 'proposal_v1' AND proposal_id IS NOT NULL AND "
            "checkpoint_id IS NULL) OR "
            "(source_kind IN ('checkpoint_v1', 'checkpoint_v2') AND "
            "checkpoint_id IS NOT NULL AND proposal_id IS NULL)",
            name="document_identity_shape",
        ),
        CheckConstraint(
            "(compatibility_correction_version IS NULL AND "
            "raw_compatibility_values IS NULL) OR "
            f"(compatibility_correction_version = '{GENESIS_COMPATIBILITY_VERSION}' AND "
            "source_path = 'ingress/checkpoints/v2/genesis/2026/08/"
            "genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20.json' "
            "AND blob_object_id = '76214f303012d756c34a3b5bdf9948267a1418e3' "
            "AND encode(raw_sha256, 'hex') = "
            "'f0f147d1ee8c748c7080ee821f1a48751b50d31c78912cbd3e1b358da39f83e7' "
            "AND checkpoint_id = "
            "'genesis-checkpoint-20260807T124400-0500-4cb2fa62-a30e-4e46-a165-c24031dcce20' "
            "AND raw_compatibility_values = "
            "'{\"/candidates/1/disposition\":\"federation_shared_candidate\","
            "\"/candidates/1/scope\":\"federation\","
            "\"/candidates/1/binding/visibility\":\"federation_shared_candidate\","
            "\"/exclusions/0/scope\":\"federation\","
            "\"/exclusions/1/scope\":\"federation\"}'::jsonb)",
            name="compatibility_correction_shape",
        ),
        sha256_check("raw_sha256", name="raw_sha256_length"),
        sha256_check("parsed_canonical_sha256", name="parsed_canonical_sha256_length"),
        json_object_check("parsed_document", name="parsed_document_object"),
        json_array_check("participant_refs", name="participant_refs_array"),
        json_object_check("binding_metadata", name="binding_metadata_object"),
        json_object_check("provenance_metadata", name="provenance_metadata_object"),
        uuid_v7_check("source_id", name="source_id_uuid_v7"),
        Index("ix_genesis_sources_run", "tenant_id", "import_run_id", "source_id"),
        _TENANT_IMMUTABLE,
    )

    source_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    import_run_id: Mapped[UUID] = mapped_column(nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_contract_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    source_path: Mapped[str] = mapped_column(Text(), nullable=False)
    blob_object_id: Mapped[str] = mapped_column(String(40), nullable=False)
    raw_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    raw_bytes: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    introducing_commit: Mapped[str | None] = mapped_column(String(40))
    parsed_document: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    parsed_canonical_json: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    parsed_canonical_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    proposal_id: Mapped[str | None] = mapped_column(String(255))
    checkpoint_id: Mapped[str | None] = mapped_column(String(255))
    previous_checkpoint_id: Mapped[str | None] = mapped_column(String(255))
    declared_idempotency_key: Mapped[str | None] = mapped_column(String(512))
    origin_actor_ref: Mapped[str | None] = mapped_column(String(255))
    runtime_ref: Mapped[str | None] = mapped_column(String(255))
    trigger_identity: Mapped[str | None] = mapped_column(String(255))
    source_conversation_ref: Mapped[str | None] = mapped_column(Text())
    owner_ref: Mapped[str | None] = mapped_column(String(255))
    perspective_ref: Mapped[str | None] = mapped_column(String(255))
    subject_ref: Mapped[str | None] = mapped_column(String(255))
    participant_refs: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    relationship_ref: Mapped[str | None] = mapped_column(String(255))
    interaction_ref: Mapped[str | None] = mapped_column(String(255))
    original_visibility: Mapped[str | None] = mapped_column(String(64))
    binding_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    provenance_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    compatibility_correction_version: Mapped[str | None] = mapped_column(String(64))
    raw_compatibility_values: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    archived_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class GenesisImportRecord(Base):
    __tablename__ = "genesis_import_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "import_run_id", "import_record_id", name="genesis_record_run_identity"
        ),
        UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_id",
            "source_item_identity",
            name="genesis_record_source_item",
        ),
        UniqueConstraint("tenant_id", "nomination_sha256", name="tenant_genesis_nomination_digest"),
        UniqueConstraint(
            "tenant_id",
            "nomination_idempotency_key",
            name="tenant_genesis_nomination_idempotency",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "branch_id"],
            ["branches.tenant_id", "branches.lineage_id", "branches.branch_id"],
            name="branch",
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
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "event_id"],
            ["memory_events.tenant_id", "memory_events.lineage_id", "memory_events.event_id"],
            name="event",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "memory_id"],
            ["memories.tenant_id", "memories.lineage_id", "memories.memory_id"],
            name="memory",
            ondelete="RESTRICT",
        ),
        values_check("record_kind", ("proposal", "candidate"), name="record_kind_values"),
        values_check(
            "processing_state",
            ("planned", "candidate", "omit", "reject"),
            name="processing_state_values",
        ),
        CheckConstraint(
            f"mapping_version = '{GENESIS_MAPPING_VERSION}'", name="mapping_version_value"
        ),
        CheckConstraint("selection_basis = 'imported_legacy'", name="selection_basis_value"),
        CheckConstraint("requested_outcome_ceiling = 'candidate'", name="outcome_ceiling_value"),
        CheckConstraint("effective_visibility = 'private_root'", name="visibility_value"),
        CheckConstraint(
            "(processing_state = 'planned' AND selection_decision_id IS NULL AND "
            "event_id IS NULL AND memory_id IS NULL AND processed_at IS NULL) OR "
            "(processing_state IN ('omit', 'reject') AND selection_decision_id IS NOT NULL AND "
            "event_id IS NULL AND memory_id IS NULL AND processed_at IS NOT NULL) OR "
            "(processing_state = 'candidate' AND selection_decision_id IS NOT NULL "
            "AND event_id IS NOT NULL AND memory_id IS NOT NULL AND processed_at IS NOT NULL)",
            name="terminal_result_shape",
        ),
        sha256_check("nomination_sha256", name="nomination_sha256_length"),
        json_object_check("source_item_document", name="source_item_document_object"),
        json_array_check("evidence_references", name="evidence_references_array"),
        json_array_check("interpretation_limits", name="interpretation_limits_array"),
        json_object_check("mapping_metadata", name="mapping_metadata_object"),
        json_object_check("provenance_metadata", name="provenance_metadata_object"),
        uuid_v7_check("import_record_id", name="import_record_id_uuid_v7"),
        Index(
            "ix_genesis_records_pending",
            "tenant_id",
            "import_run_id",
            "import_record_id",
            postgresql_where=text("processing_state = 'planned'"),
        ),
        {
            "info": {
                TENANT_OWNED_INFO_KEY: True,
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
            }
        },
    )

    import_record_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    import_run_id: Mapped[UUID] = mapped_column(nullable=False)
    source_id: Mapped[UUID] = mapped_column(nullable=False)
    lineage_id: Mapped[UUID] = mapped_column(nullable=False)
    branch_id: Mapped[UUID] = mapped_column(nullable=False)
    record_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_item_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    source_item_document: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    nomination_sha256: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    nomination_idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    mapping_version: Mapped[str] = mapped_column(String(64), nullable=False)
    selection_basis: Mapped[str] = mapped_column(String(64), nullable=False)
    qualifier: Mapped[str | None] = mapped_column(String(64))
    requested_outcome_ceiling: Mapped[str] = mapped_column(String(16), nullable=False)
    effective_visibility: Mapped[str] = mapped_column(String(16), nullable=False)
    unresolved_legacy_binding: Mapped[bool] = mapped_column(Boolean(), nullable=False)
    original_candidate_type: Mapped[str | None] = mapped_column(String(64))
    original_disposition: Mapped[str | None] = mapped_column(String(64))
    original_confidence: Mapped[str | None] = mapped_column(String(64))
    original_scope: Mapped[str | None] = mapped_column(String(64))
    original_ontology: Mapped[str | None] = mapped_column(String(64))
    original_visibility: Mapped[str | None] = mapped_column(String(64))
    review_recommendation: Mapped[str | None] = mapped_column(String(64))
    evidence_references: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    interpretation_limits: Mapped[list[object]] = mapped_column(JSONB, nullable=False)
    mapping_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    provenance_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    processing_state: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'planned'")
    )
    selection_decision_id: Mapped[UUID | None] = mapped_column()
    event_id: Mapped[UUID | None] = mapped_column()
    memory_id: Mapped[UUID | None] = mapped_column()
    planned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GenesisImportExclusion(Base):
    __tablename__ = "genesis_import_exclusions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "exclusion_id",
            name="genesis_exclusion_run_identity",
        ),
        UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "source_id",
            "source_exclusion_identity",
            name="genesis_exclusion_source_identity",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "applies_to_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="applies_to_record",
            ondelete="RESTRICT",
        ),
        CheckConstraint("blocks_automatic_promotion", name="blocks_automatic_promotion_true"),
        CheckConstraint("length(claim) BETWEEN 1 AND 4096", name="claim_length"),
        CheckConstraint("length(reason) BETWEEN 1 AND 4096", name="reason_length"),
        json_object_check("binding_metadata", name="binding_metadata_object"),
        json_object_check("provenance_metadata", name="provenance_metadata_object"),
        uuid_v7_check("exclusion_id", name="exclusion_id_uuid_v7"),
        _TENANT_IMMUTABLE,
    )

    exclusion_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    import_run_id: Mapped[UUID] = mapped_column(nullable=False)
    source_id: Mapped[UUID] = mapped_column(nullable=False)
    applies_to_record_id: Mapped[UUID | None] = mapped_column()
    source_exclusion_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    claim: Mapped[str] = mapped_column(Text(), nullable=False)
    reason: Mapped[str] = mapped_column(Text(), nullable=False)
    raw_scope: Mapped[str | None] = mapped_column(String(64))
    actor_ref: Mapped[str | None] = mapped_column(String(255))
    relationship_ref: Mapped[str | None] = mapped_column(String(255))
    binding_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    provenance_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    blocks_automatic_promotion: Mapped[bool] = mapped_column(Boolean(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class GenesisImportSupersession(Base):
    __tablename__ = "genesis_import_supersessions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "source_id"],
            [
                "genesis_import_sources.tenant_id",
                "genesis_import_sources.import_run_id",
                "genesis_import_sources.source_id",
            ],
            name="source",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "predecessor_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="predecessor_record",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "predecessor_exclusion_id"],
            [
                "genesis_import_exclusions.tenant_id",
                "genesis_import_exclusions.import_run_id",
                "genesis_import_exclusions.exclusion_id",
            ],
            name="predecessor_exclusion",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "successor_record_id"],
            [
                "genesis_import_records.tenant_id",
                "genesis_import_records.import_run_id",
                "genesis_import_records.import_record_id",
            ],
            name="successor_record",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id", "successor_exclusion_id"],
            [
                "genesis_import_exclusions.tenant_id",
                "genesis_import_exclusions.import_run_id",
                "genesis_import_exclusions.exclusion_id",
            ],
            name="successor_exclusion",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "(predecessor_record_id IS NULL) <> (predecessor_exclusion_id IS NULL)",
            name="predecessor_shape",
        ),
        CheckConstraint(
            "(successor_record_id IS NULL) <> (successor_exclusion_id IS NULL)",
            name="successor_shape",
        ),
        CheckConstraint(
            "predecessor_record_id IS DISTINCT FROM successor_record_id OR "
            "predecessor_exclusion_id IS DISTINCT FROM successor_exclusion_id",
            name="not_self",
        ),
        json_object_check("provenance_metadata", name="provenance_metadata_object"),
        uuid_v7_check("supersession_id", name="supersession_id_uuid_v7"),
        UniqueConstraint(
            "tenant_id",
            "import_run_id",
            "predecessor_record_id",
            "predecessor_exclusion_id",
            "successor_record_id",
            "successor_exclusion_id",
            name="genesis_supersession_edge",
            postgresql_nulls_not_distinct=True,
        ),
        _TENANT_IMMUTABLE,
    )

    supersession_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(nullable=False)
    import_run_id: Mapped[UUID] = mapped_column(nullable=False)
    source_id: Mapped[UUID] = mapped_column(nullable=False)
    predecessor_record_id: Mapped[UUID | None] = mapped_column()
    predecessor_exclusion_id: Mapped[UUID | None] = mapped_column()
    successor_record_id: Mapped[UUID | None] = mapped_column()
    successor_exclusion_id: Mapped[UUID | None] = mapped_column()
    provenance_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class GenesisImportRunResult(Base):
    __tablename__ = "genesis_import_run_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "import_run_id"],
            ["genesis_import_runs.tenant_id", "genesis_import_runs.import_run_id"],
            name="import_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint("planned_record_count >= 0", name="planned_record_count_nonnegative"),
        CheckConstraint(
            "candidate_count >= 0 AND omit_count >= 0 AND reject_count >= 0",
            name="outcome_counts_nonnegative",
        ),
        CheckConstraint(
            "planned_record_count = candidate_count + omit_count + reject_count",
            name="outcome_counts_complete",
        ),
        CheckConstraint("replay_verified", name="replay_verified_true"),
        _TENANT_IMMUTABLE,
    )

    import_run_id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(primary_key=True)
    planned_record_count: Mapped[int] = mapped_column(Integer(), nullable=False)
    candidate_count: Mapped[int] = mapped_column(Integer(), nullable=False)
    omit_count: Mapped[int] = mapped_column(Integer(), nullable=False)
    reject_count: Mapped[int] = mapped_column(Integer(), nullable=False)
    replay_verified: Mapped[bool] = mapped_column(Boolean(), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )
