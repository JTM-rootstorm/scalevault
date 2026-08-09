"""Permit honest GitHub ingress discovery before semantic validation.

Revision ID: 0005_github_ingress_v2_runtime
Revises: 0004_genesis_import_provenance
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_github_ingress_v2_runtime"
down_revision: str | None = "0004_genesis_import_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVENANCE_FIELDS = (
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
    "discovered_at",
)


def _replace_immutable_fields_trigger(*, include_semantic_fields: bool) -> None:
    op.execute(sa.text("DROP TRIGGER trg_ingress_items_immutable_fields ON ingress_items"))
    fields = _PROVENANCE_FIELDS + (
        ("declared_idempotency_key", "payload_sha256") if include_semantic_fields else ()
    )
    columns = ", ".join(f'"{field}"' for field in fields)
    arguments = ", ".join(f"'{field}'" for field in fields)
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_items_immutable_fields "
            f"BEFORE UPDATE OF {columns} ON public.ingress_items "
            "FOR EACH ROW EXECUTE FUNCTION "
            f"public.scalevault_reject_immutable_field_mutation({arguments})"
        )
    )


def _create_v2_lifecycle_function() -> None:
    op.execute(
        sa.text("""
        CREATE OR REPLACE FUNCTION public.scalevault_enforce_ingress_lifecycle()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state IS DISTINCT FROM 'discovered'
                    OR NEW.declared_idempotency_key IS NOT NULL
                    OR NEW.payload_sha256 IS NOT NULL
                    OR NEW.validated_at IS NOT NULL
                    OR NEW.processed_at IS NOT NULL
                    OR NEW.result_event_id IS NOT NULL
                    OR NEW.result_memory_id IS NOT NULL
                    OR NEW.error_code IS NOT NULL
                    OR NEW.safe_diagnostic IS NOT NULL THEN
                    RAISE EXCEPTION 'ingress item must begin in discovered state'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;

            IF NEW.declared_idempotency_key IS DISTINCT FROM OLD.declared_idempotency_key
                OR NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256 THEN
                IF NOT (
                    OLD.state = 'discovered'
                    AND NEW.state = 'validated'
                    AND OLD.declared_idempotency_key IS NULL
                    AND OLD.payload_sha256 IS NULL
                    AND NEW.declared_idempotency_key IS NOT NULL
                    AND NEW.payload_sha256 IS NOT NULL
                ) THEN
                    RAISE EXCEPTION 'ingress semantic identity mutation is invalid'
                        USING ERRCODE = '55000';
                END IF;
            END IF;

            IF NEW.state IS NOT DISTINCT FROM OLD.state
                OR NOT (
                    (OLD.state = 'discovered'
                        AND NEW.state IN ('validated', 'quarantined'))
                    OR (OLD.state = 'validated'
                        AND NEW.state IN (
                            'accepted', 'duplicate', 'conflict', 'rejected', 'quarantined'
                        ))
                ) THEN
                RAISE EXCEPTION 'ingress state transition is invalid'
                    USING ERRCODE = '23514';
            END IF;

            IF NEW.state <> 'quarantined' AND (
                NEW.declared_idempotency_key IS NULL OR NEW.payload_sha256 IS NULL
            ) THEN
                RAISE EXCEPTION 'processed ingress requires validated semantic identity'
                    USING ERRCODE = '23514';
            END IF;

            IF NEW.state = 'validated' AND NOT (
                NEW.validated_at IS NOT NULL
                AND NEW.processed_at IS NULL
                AND NEW.result_event_id IS NULL
                AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NULL
                AND NEW.safe_diagnostic IS NULL
            ) THEN
                RAISE EXCEPTION 'validated ingress result shape is invalid'
                    USING ERRCODE = '23514';
            ELSIF NEW.state IN ('accepted', 'duplicate') AND NOT (
                NEW.validated_at IS NOT NULL
                AND NEW.processed_at IS NOT NULL
                AND NEW.processed_at >= NEW.validated_at
                AND NEW.result_event_id IS NOT NULL
                AND NEW.result_memory_id IS NOT NULL
                AND NEW.error_code IS NULL
                AND NEW.safe_diagnostic IS NULL
            ) THEN
                RAISE EXCEPTION 'successful ingress result shape is invalid'
                    USING ERRCODE = '23514';
            ELSIF NEW.state = 'conflict' AND NOT (
                NEW.validated_at IS NOT NULL
                AND NEW.processed_at IS NOT NULL
                AND NEW.processed_at >= NEW.validated_at
                AND NEW.result_event_id IS NULL
                AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'conflicted ingress result shape is invalid'
                    USING ERRCODE = '23514';
            ELSIF NEW.state IN ('rejected', 'quarantined') AND NOT (
                NEW.processed_at IS NOT NULL
                AND (NEW.validated_at IS NULL OR NEW.processed_at >= NEW.validated_at)
                AND NEW.result_event_id IS NULL
                AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'failed ingress result shape is invalid'
                    USING ERRCODE = '23514';
            END IF;

            RETURN NEW;
        END
        $function$
        """)
    )


def _create_result_reciprocity_function(*, allow_promoted: bool) -> None:
    promoted = (
        """
                OR EXISTS (
                    SELECT 1
                    FROM public.command_receipts AS receipt
                    JOIN public.selection_decisions AS decision
                      ON decision.tenant_id = receipt.tenant_id
                     AND decision.decision_id = receipt.selection_decision_id
                    WHERE receipt.tenant_id = NEW.tenant_id
                      AND receipt.client_id = NEW.client_id
                      AND receipt.idempotency_key = NEW.declared_idempotency_key
                      AND receipt.event_id = NEW.result_event_id
                      AND receipt.memory_id = NEW.result_memory_id
                      AND decision.event_id = NEW.result_event_id
                      AND decision.memory_id = NEW.result_memory_id
                      AND decision.actor_id = NEW.actor_id
                      AND decision.client_id = NEW.client_id
                      AND decision.transport_binding_id = NEW.transport_binding_id
                      AND decision.source_kind = 'candidate_reassessment'
                      AND decision.requested_operation = 'promote'
                      AND decision.outcome = 'promoted'
                )
    """
        if allow_promoted
        else ""
    )
    op.execute(
        sa.text(f"""
        CREATE OR REPLACE FUNCTION public.scalevault_enforce_ingress_result_reciprocity()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF NEW.state = 'accepted' AND NOT (
                EXISTS (
                    SELECT 1
                    FROM public.memory_events AS event
                    WHERE event.tenant_id = NEW.tenant_id
                      AND event.event_id = NEW.result_event_id
                      AND event.ingress_id = NEW.ingress_id
                      AND event.memory_id = NEW.result_memory_id
                      AND event.transport_binding_id = NEW.transport_binding_id
                      AND event.actor_id = NEW.actor_id
                      AND event.client_id = NEW.client_id
                      AND event.idempotency_key = NEW.declared_idempotency_key
                      AND event.operation IN ('observed', 'remembered')
                )
                {promoted}
            ) THEN
                RAISE EXCEPTION 'accepted ingress result is not reciprocal'
                    USING ERRCODE = '23514';
            ELSIF NEW.state = 'duplicate' AND NOT EXISTS (
                SELECT 1
                FROM public.memory_events AS event
                WHERE event.tenant_id = NEW.tenant_id
                  AND event.event_id = NEW.result_event_id
                  AND event.memory_id = NEW.result_memory_id
                  AND event.operation IN ('observed', 'remembered')
            ) THEN
                RAISE EXCEPTION 'duplicate ingress result is invalid'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NULL;
        END
        $function$
        """)
    )


def upgrade() -> None:
    op.alter_column("ingress_items", "declared_idempotency_key", nullable=True)
    op.alter_column("ingress_items", "payload_sha256", nullable=True)
    op.drop_constraint(
        op.f("ck_ingress_items_idempotency_key_length"), "ingress_items", type_="check"
    )
    op.drop_constraint(
        op.f("ck_ingress_items_payload_sha256_length"), "ingress_items", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_ingress_items_idempotency_key_length"),
        "ingress_items",
        "declared_idempotency_key IS NULL OR length(declared_idempotency_key) BETWEEN 1 AND 255",
    )
    op.create_check_constraint(
        op.f("ck_ingress_items_payload_sha256_length"),
        "ingress_items",
        "payload_sha256 IS NULL OR octet_length(payload_sha256) = 32",
    )
    _replace_immutable_fields_trigger(include_semantic_fields=False)
    _create_v2_lifecycle_function()
    _create_result_reciprocity_function(allow_promoted=True)
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 5, "
            "minimum_reader_revision = '0005_github_ingress_v2_runtime', "
            "minimum_writer_revision = '0005_github_ingress_v2_runtime' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DO $guard$ BEGIN "
            "IF EXISTS (SELECT 1 FROM public.ingress_items "
            "WHERE declared_idempotency_key IS NULL OR payload_sha256 IS NULL) THEN "
            "RAISE EXCEPTION 'cannot downgrade while unvalidated ingress items exist' "
            "USING ERRCODE = '55000'; "
            "END IF; END $guard$"
        )
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 4, "
            "minimum_reader_revision = '0004_genesis_import_provenance', "
            "minimum_writer_revision = '0004_genesis_import_provenance' "
            "WHERE component = 'memory_node'"
        )
    )
    op.alter_column("ingress_items", "declared_idempotency_key", nullable=False)
    op.alter_column("ingress_items", "payload_sha256", nullable=False)
    op.drop_constraint(
        op.f("ck_ingress_items_idempotency_key_length"), "ingress_items", type_="check"
    )
    op.drop_constraint(
        op.f("ck_ingress_items_payload_sha256_length"), "ingress_items", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_ingress_items_idempotency_key_length"),
        "ingress_items",
        "length(declared_idempotency_key) BETWEEN 1 AND 255",
    )
    op.create_check_constraint(
        op.f("ck_ingress_items_payload_sha256_length"),
        "ingress_items",
        "octet_length(payload_sha256) = 32",
    )
    _replace_immutable_fields_trigger(include_semantic_fields=True)
    _create_result_reciprocity_function(allow_promoted=False)
    op.execute(
        sa.text("""
        CREATE OR REPLACE FUNCTION public.scalevault_enforce_ingress_lifecycle()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state IS DISTINCT FROM 'discovered'
                    OR NEW.validated_at IS NOT NULL OR NEW.processed_at IS NOT NULL
                    OR NEW.result_event_id IS NOT NULL OR NEW.result_memory_id IS NOT NULL
                    OR NEW.error_code IS NOT NULL OR NEW.safe_diagnostic IS NOT NULL THEN
                    RAISE EXCEPTION 'ingress item must begin in discovered state'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;
            IF NEW.state IS NOT DISTINCT FROM OLD.state OR NOT (
                (OLD.state = 'discovered' AND NEW.state IN ('validated', 'rejected', 'quarantined'))
                OR (OLD.state = 'validated' AND NEW.state IN (
                    'accepted', 'duplicate', 'conflict', 'rejected', 'quarantined'
                ))
            ) THEN
                RAISE EXCEPTION 'ingress state transition is invalid' USING ERRCODE = '23514';
            END IF;
            IF NEW.state = 'validated' AND NOT (
                NEW.validated_at IS NOT NULL AND NEW.processed_at IS NULL
                AND NEW.result_event_id IS NULL AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NULL AND NEW.safe_diagnostic IS NULL
            ) THEN
                RAISE EXCEPTION 'validated ingress result shape is invalid' USING ERRCODE = '23514';
            ELSIF NEW.state IN ('accepted', 'duplicate') AND NOT (
                NEW.validated_at IS NOT NULL AND NEW.processed_at IS NOT NULL
                AND NEW.processed_at >= NEW.validated_at
                AND NEW.result_event_id IS NOT NULL AND NEW.result_memory_id IS NOT NULL
                AND NEW.error_code IS NULL AND NEW.safe_diagnostic IS NULL
            ) THEN
                RAISE EXCEPTION 'successful ingress result shape is invalid'
                    USING ERRCODE = '23514';
            ELSIF NEW.state = 'conflict' AND NOT (
                NEW.validated_at IS NOT NULL AND NEW.processed_at IS NOT NULL
                AND NEW.processed_at >= NEW.validated_at
                AND NEW.result_event_id IS NULL AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'conflicted ingress result shape is invalid'
                    USING ERRCODE = '23514';
            ELSIF NEW.state IN ('rejected', 'quarantined') AND NOT (
                NEW.processed_at IS NOT NULL
                AND (NEW.validated_at IS NULL OR NEW.processed_at >= NEW.validated_at)
                AND NEW.result_event_id IS NULL AND NEW.result_memory_id IS NULL
                AND NEW.error_code IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'failed ingress result shape is invalid' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $function$
        """)
    )
