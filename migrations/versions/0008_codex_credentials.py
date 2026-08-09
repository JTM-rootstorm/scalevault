"""Bind versioned bearer credentials to immutable request provenance.

Revision ID: 0008_codex_credentials
Revises: 0007_persistence_hardening
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_codex_credentials"
down_revision: str | None = "0007_persistence_hardening"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_FIELDS = (
    "credential_id",
    "tenant_id",
    "actor_id",
    "client_id",
    "transport_binding_id",
    "kind",
    "public_hint",
    "secret_hash",
    "secret_hash_key_id",
    "certificate_sha256",
    "created_at",
    "expires_at",
)


def _add_credential_attribution() -> None:
    op.add_column("client_credentials", sa.Column("actor_id", sa.Uuid(), nullable=True))
    op.add_column(
        "client_credentials",
        sa.Column("transport_binding_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "client_credentials",
        sa.Column("secret_hash_key_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "client_credentials",
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )

    # A pre-M7 credential did not carry audit attribution. It is safe to infer
    # that attribution only when its tenant/client pair has exactly one binding.
    op.execute(
        sa.text("""
        WITH unambiguous_bindings AS (
            SELECT
                credential.credential_id,
                min(binding.transport_binding_id::text)::uuid AS transport_binding_id,
                min(binding.actor_id::text)::uuid AS actor_id
            FROM public.client_credentials AS credential
            JOIN public.transport_bindings AS binding
              ON binding.tenant_id = credential.tenant_id
             AND binding.client_id = credential.client_id
            GROUP BY credential.credential_id
            HAVING count(*) = 1
        )
        UPDATE public.client_credentials AS credential
        SET transport_binding_id = binding.transport_binding_id,
            actor_id = binding.actor_id
        FROM unambiguous_bindings AS binding
        WHERE credential.credential_id = binding.credential_id
        """)
    )
    op.execute(
        sa.text("""
        DO $guard$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM public.client_credentials
                WHERE actor_id IS NULL OR transport_binding_id IS NULL
            ) THEN
                RAISE EXCEPTION 'credential attribution migration requires operator reissue'
                    USING ERRCODE = '55000';
            END IF;
            IF EXISTS (
                SELECT 1
                FROM public.client_credentials
                WHERE kind = 'bearer_token'
            ) THEN
                RAISE EXCEPTION 'legacy bearer credentials require operator reissue'
                    USING ERRCODE = '55000';
            END IF;
        END
        $guard$
        """)
    )

    op.alter_column("client_credentials", "actor_id", nullable=False)
    op.alter_column("client_credentials", "transport_binding_id", nullable=False)
    op.create_foreign_key(
        "transport_binding",
        "client_credentials",
        "transport_bindings",
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ["tenant_id", "transport_binding_id", "actor_id", "client_id"],
        ondelete="RESTRICT",
    )


def _replace_credential_constraints() -> None:
    op.drop_constraint(
        op.f("ck_client_credentials_material_matches_kind"),
        "client_credentials",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_client_credentials_secret_hash_length"),
        "client_credentials",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_material_matches_kind"),
        "client_credentials",
        "(kind = 'bearer_token' AND secret_hash IS NOT NULL "
        "AND secret_hash_key_id IS NOT NULL AND certificate_sha256 IS NULL) OR "
        "(kind = 'client_certificate' AND secret_hash IS NULL "
        "AND secret_hash_key_id IS NULL AND certificate_sha256 IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_secret_hash_format"),
        "client_credentials",
        "secret_hash IS NULL OR secret_hash ~ '^hmac-sha256-v1:[A-Za-z0-9_-]{43}$'",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_secret_hash_key_id_format"),
        "client_credentials",
        "secret_hash_key_id IS NULL OR secret_hash_key_id ~ '^[a-z][a-z0-9_.-]{0,63}$'",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_last_used_order"),
        "client_credentials",
        "last_used_at IS NULL OR (last_used_at >= created_at "
        "AND (revoked_at IS NULL OR last_used_at <= revoked_at))",
    )
    op.create_index(
        "uq_client_credentials_active_binding",
        "client_credentials",
        ["tenant_id", "client_id", "transport_binding_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL AND kind = 'bearer_token'"),
    )


def _create_credential_lifecycle_barriers() -> None:
    columns = ", ".join(f'"{field}"' for field in _IMMUTABLE_FIELDS)
    arguments = ", ".join(f"'{field}'" for field in _IMMUTABLE_FIELDS)
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_client_credentials_immutable_fields "
            f"BEFORE UPDATE OF {columns} ON public.client_credentials "
            "FOR EACH ROW EXECUTE FUNCTION "
            f"public.scalevault_reject_immutable_field_mutation({arguments})"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_client_credentials_delete_forbidden "
            "BEFORE DELETE ON public.client_credentials FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_client_credentials_truncate_forbidden "
            "BEFORE TRUNCATE ON public.client_credentials FOR EACH STATEMENT "
            "EXECUTE FUNCTION public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text("""
        CREATE FUNCTION public.scalevault_enforce_client_credential_lifecycle()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog
        AS $function$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.last_used_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
                    RAISE EXCEPTION 'credential must begin unused and active'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;

            IF NEW.last_used_at IS NOT DISTINCT FROM OLD.last_used_at
                AND NEW.revoked_at IS NOT DISTINCT FROM OLD.revoked_at THEN
                RETURN NEW;
            END IF;
            IF OLD.revoked_at IS NOT NULL THEN
                RAISE EXCEPTION 'revoked credential lifecycle is immutable'
                    USING ERRCODE = '55000';
            END IF;
            IF OLD.last_used_at IS NOT NULL
                AND (
                    NEW.last_used_at IS NULL
                    OR NEW.last_used_at < OLD.last_used_at
                ) THEN
                RAISE EXCEPTION 'credential last-used audit cannot move backward'
                    USING ERRCODE = '55000';
            END IF;
            IF NEW.last_used_at IS NOT NULL AND NEW.last_used_at < NEW.created_at THEN
                RAISE EXCEPTION 'credential last-used audit precedes creation'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.revoked_at IS NOT NULL AND (
                NEW.revoked_at < NEW.created_at
                OR (
                    NEW.last_used_at IS NOT NULL
                    AND NEW.revoked_at < NEW.last_used_at
                )
            ) THEN
                RAISE EXCEPTION 'credential revocation audit is out of order'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $function$
        """)
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_client_credentials_lifecycle_insert "
            "BEFORE INSERT ON public.client_credentials FOR EACH ROW "
            "EXECUTE FUNCTION public.scalevault_enforce_client_credential_lifecycle()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_client_credentials_lifecycle "
            "BEFORE UPDATE OF last_used_at, revoked_at ON public.client_credentials "
            "FOR EACH ROW EXECUTE FUNCTION "
            "public.scalevault_enforce_client_credential_lifecycle()"
        )
    )


def upgrade() -> None:
    _add_credential_attribution()
    _replace_credential_constraints()
    _create_credential_lifecycle_barriers()
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 8, "
            "minimum_reader_revision = '0008_codex_credentials', "
            "minimum_writer_revision = '0008_codex_credentials' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text("""
        DO $guard$
        BEGIN
            IF EXISTS (SELECT 1 FROM public.client_credentials) THEN
                RAISE EXCEPTION 'credential attribution downgrade would lose audit data'
                    USING ERRCODE = '55000';
            END IF;
        END
        $guard$
        """)
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 7, "
            "minimum_reader_revision = '0007_persistence_hardening', "
            "minimum_writer_revision = '0007_persistence_hardening' "
            "WHERE component = 'memory_node'"
        )
    )
    op.execute(
        sa.text("DROP TRIGGER trg_client_credentials_lifecycle ON public.client_credentials")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_client_credentials_lifecycle_insert ON public.client_credentials")
    )
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_client_credential_lifecycle()"))
    op.execute(
        sa.text(
            "DROP TRIGGER trg_client_credentials_truncate_forbidden ON public.client_credentials"
        )
    )
    op.execute(
        sa.text("DROP TRIGGER trg_client_credentials_delete_forbidden ON public.client_credentials")
    )
    op.execute(
        sa.text("DROP TRIGGER trg_client_credentials_immutable_fields ON public.client_credentials")
    )
    op.drop_index(
        "uq_client_credentials_active_binding",
        table_name="client_credentials",
        postgresql_where=sa.text("revoked_at IS NULL AND kind = 'bearer_token'"),
    )
    op.drop_constraint(
        op.f("ck_client_credentials_last_used_order"),
        "client_credentials",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_client_credentials_secret_hash_key_id_format"),
        "client_credentials",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_client_credentials_secret_hash_format"),
        "client_credentials",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_client_credentials_material_matches_kind"),
        "client_credentials",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_material_matches_kind"),
        "client_credentials",
        "(kind = 'bearer_token' AND secret_hash IS NOT NULL "
        "AND certificate_sha256 IS NULL) OR "
        "(kind = 'client_certificate' AND secret_hash IS NULL "
        "AND certificate_sha256 IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_client_credentials_secret_hash_length"),
        "client_credentials",
        "secret_hash IS NULL OR length(secret_hash) BETWEEN 16 AND 512",
    )
    op.drop_constraint("transport_binding", "client_credentials", type_="foreignkey")
    op.drop_column("client_credentials", "last_used_at")
    op.drop_column("client_credentials", "secret_hash_key_id")
    op.drop_column("client_credentials", "transport_binding_id")
    op.drop_column("client_credentials", "actor_id")
