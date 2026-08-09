"""Harden ingress provenance and content-key lifecycle persistence.

Revision ID: 0007_persistence_hardening
Revises: 0006_sealed_canonical_content
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_persistence_hardening"
down_revision: str | None = "0006_sealed_canonical_content"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_EXPRESSION = (
    "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
)
_CONTENT_KEY_IDENTITY_FIELDS = (
    "content_key_id",
    "tenant_id",
    "lineage_id",
    "memory_id",
    "provider_name",
    "provider_key_reference",
    "created_at",
)


def _create_ingress_provider_violations() -> None:
    op.create_table(
        "ingress_provider_violations",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("ingress_id", sa.Uuid(), nullable=False),
        sa.Column("violation_code", sa.String(length=64), nullable=False),
        sa.Column("expected_provenance_sha256", sa.LargeBinary(), nullable=False),
        sa.Column("observed_provenance_sha256", sa.LargeBinary(), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "violation_code ~ '^[a-z][a-z0-9_]{0,63}$'",
            name=op.f("ck_ingress_provider_violations_violation_code_format"),
        ),
        sa.CheckConstraint(
            "octet_length(expected_provenance_sha256) = 32",
            name=op.f("ck_ingress_provider_violations_expected_provenance_sha256_length"),
        ),
        sa.CheckConstraint(
            "octet_length(observed_provenance_sha256) = 32",
            name=op.f("ck_ingress_provider_violations_observed_provenance_sha256_length"),
        ),
        sa.CheckConstraint(
            "expected_provenance_sha256 <> observed_provenance_sha256",
            name=op.f("ck_ingress_provider_violations_provenance_hashes_differ"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "ingress_id"],
            ["ingress_items.tenant_id", "ingress_items.ingress_id"],
            name="ingress_item",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "ingress_id",
            "violation_code",
            "expected_provenance_sha256",
            "observed_provenance_sha256",
            name=op.f("pk_ingress_provider_violations"),
        ),
        info={
            "scalevault_tenant_owned": True,
            "scalevault_immutable": True,
            "scalevault_append_only": True,
            "scalevault_content_free": True,
        },
    )
    op.create_index(
        "ix_ingress_provider_violations_detected",
        "ingress_provider_violations",
        ["tenant_id", "detected_at"],
        unique=False,
    )
    op.execute(sa.text("ALTER TABLE public.ingress_provider_violations ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.ingress_provider_violations FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY scalevault_tenant_isolation "
            "ON public.ingress_provider_violations "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_violations_immutable "
            "BEFORE UPDATE OR DELETE ON public.ingress_provider_violations "
            "FOR EACH ROW EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_violations_immutable_truncate "
            "BEFORE TRUNCATE ON public.ingress_provider_violations FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )


def _harden_content_key_lifecycle() -> None:
    op.create_check_constraint(
        op.f("ck_memory_content_keys_lifecycle_shape"),
        "memory_content_keys",
        "(state = 'active' AND destruction_requested_at IS NULL "
        "AND destroyed_at IS NULL AND destruction_receipt_sha256 IS NULL) OR "
        "(state IN ('destruction_requested', 'failed') "
        "AND destruction_requested_at IS NOT NULL AND destroyed_at IS NULL "
        "AND destruction_receipt_sha256 IS NULL) OR "
        "(state = 'destroyed' AND destruction_requested_at IS NOT NULL "
        "AND destroyed_at IS NOT NULL AND destruction_receipt_sha256 IS NOT NULL)",
    )
    columns = ", ".join(f'"{field}"' for field in _CONTENT_KEY_IDENTITY_FIELDS)
    arguments = ", ".join(f"'{field}'" for field in _CONTENT_KEY_IDENTITY_FIELDS)
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_memory_content_keys_immutable_fields "
            f"BEFORE UPDATE OF {columns} ON public.memory_content_keys "
            "FOR EACH ROW EXECUTE FUNCTION "
            f"public.scalevault_reject_immutable_field_mutation({arguments})"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_memory_content_keys_delete_forbidden "
            "BEFORE DELETE ON public.memory_content_keys FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_memory_content_keys_truncate_forbidden "
            "BEFORE TRUNCATE ON public.memory_content_keys FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_enforce_content_key_lifecycle()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.state = 'active'
                    AND NEW.destruction_requested_at IS NULL
                    AND NEW.destroyed_at IS NULL
                    AND NEW.destruction_receipt_sha256 IS NULL THEN
                    RETURN NEW;
                END IF;
                RAISE EXCEPTION 'content key must begin in active state'
                    USING ERRCODE = '23514';
            END IF;

            IF NEW.state IS NOT DISTINCT FROM OLD.state
                AND NEW.destruction_requested_at IS NOT DISTINCT FROM OLD.destruction_requested_at
                AND NEW.destroyed_at IS NOT DISTINCT FROM OLD.destroyed_at
                AND NEW.destruction_receipt_sha256
                    IS NOT DISTINCT FROM OLD.destruction_receipt_sha256 THEN
                RETURN NEW;
            END IF;

            IF OLD.destruction_requested_at IS NOT NULL
                AND NEW.destruction_requested_at IS DISTINCT FROM OLD.destruction_requested_at THEN
                RAISE EXCEPTION 'content key destruction request audit is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.destroyed_at IS NOT NULL
                AND NEW.destroyed_at IS DISTINCT FROM OLD.destroyed_at THEN
                RAISE EXCEPTION 'content key destruction completion audit is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.destruction_receipt_sha256 IS NOT NULL
                AND NEW.destruction_receipt_sha256
                    IS DISTINCT FROM OLD.destruction_receipt_sha256 THEN
                RAISE EXCEPTION 'content key destruction receipt audit is immutable'
                    USING ERRCODE = '55000';
            END IF;

            IF OLD.state = 'active' AND NEW.state = 'destruction_requested' AND
                OLD.destruction_requested_at IS NULL AND
                NEW.destruction_requested_at IS NOT NULL AND
                NEW.destroyed_at IS NULL AND NEW.destruction_receipt_sha256 IS NULL THEN
                RETURN NEW;
            END IF;
            IF OLD.state = 'destruction_requested'
                AND NEW.state = 'destroyed'
                AND NEW.destruction_requested_at IS NOT DISTINCT
                    FROM OLD.destruction_requested_at
                AND OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL
                AND OLD.destruction_receipt_sha256 IS NULL
                AND NEW.destruction_receipt_sha256 IS NOT NULL THEN
                RETURN NEW;
            END IF;
            IF OLD.state = 'destruction_requested'
                AND NEW.state = 'failed'
                AND NEW.destruction_requested_at IS NOT DISTINCT
                    FROM OLD.destruction_requested_at
                AND NEW.destroyed_at IS NULL
                AND NEW.destruction_receipt_sha256 IS NULL THEN
                RETURN NEW;
            END IF;

            RAISE EXCEPTION 'content key lifecycle transition is invalid'
                USING ERRCODE = '23514';
        END
        $function$
        """)
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_memory_content_keys_lifecycle_insert "
            "BEFORE INSERT ON public.memory_content_keys FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_enforce_content_key_lifecycle()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_memory_content_keys_lifecycle "
            "BEFORE UPDATE OF state, destruction_requested_at, destroyed_at, "
            "destruction_receipt_sha256 ON public.memory_content_keys "
            "FOR EACH ROW EXECUTE FUNCTION public.scalevault_enforce_content_key_lifecycle()"
        )
    )


def upgrade() -> None:
    _create_ingress_provider_violations()
    _harden_content_key_lifecycle()
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 7, "
            "minimum_reader_revision = '0007_persistence_hardening', "
            "minimum_writer_revision = '0007_persistence_hardening' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 6, "
            "minimum_reader_revision = '0006_sealed_canonical_content', "
            "minimum_writer_revision = '0006_sealed_canonical_content' "
            "WHERE component = 'memory_node'"
        )
    )
    op.execute(sa.text("DROP TRIGGER trg_memory_content_keys_lifecycle ON memory_content_keys"))
    op.execute(
        sa.text("DROP TRIGGER trg_memory_content_keys_lifecycle_insert ON memory_content_keys")
    )
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_content_key_lifecycle()"))
    op.execute(
        sa.text("DROP TRIGGER trg_memory_content_keys_truncate_forbidden ON memory_content_keys")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_memory_content_keys_delete_forbidden ON memory_content_keys")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_memory_content_keys_immutable_fields ON memory_content_keys")
    )
    op.drop_constraint(
        op.f("ck_memory_content_keys_lifecycle_shape"),
        "memory_content_keys",
        type_="check",
    )
    op.drop_index(
        "ix_ingress_provider_violations_detected",
        table_name="ingress_provider_violations",
    )
    op.drop_table("ingress_provider_violations")
