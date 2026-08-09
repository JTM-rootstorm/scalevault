"""Persist the verified additive GitHub ingress history head.

Revision ID: 0010_ingress_provider_heads
Revises: 0009_secure_tunnel_binding
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_ingress_provider_heads"
down_revision: str | None = "0009_secure_tunnel_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BOOTSTRAP_COMMIT = "84233835924ade0e3cf26bb995717c880c75ff5c"
_BOOTSTRAP_TREE = "2de813150fe3952e6538abc5db9c2254d835a70e"
_TENANT_EXPRESSION = (
    "tenant_id = NULLIF(pg_catalog.current_setting('scalevault.tenant_id', true), '')::uuid"
)


def upgrade() -> None:
    op.create_table(
        "ingress_provider_heads",
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("repository_external_id", sa.String(length=255), nullable=False),
        sa.Column("branch_name", sa.String(length=255), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("transport_binding_id", sa.Uuid(), nullable=False),
        sa.Column("bootstrap_commit_id", sa.String(length=40), nullable=False),
        sa.Column("bootstrap_tree_id", sa.String(length=40), nullable=False),
        sa.Column("last_verified_commit_id", sa.String(length=40), nullable=False),
        sa.Column("last_verified_tree_id", sa.String(length=40), nullable=False),
        sa.Column("etag", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "verified_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "provider = 'github'",
            name=op.f("ck_ingress_provider_heads_provider_values"),
        ),
        sa.CheckConstraint(
            "repository_external_id ~ '^[1-9][0-9]*$'",
            name=op.f("ck_ingress_provider_heads_repository_external_id_format"),
        ),
        sa.CheckConstraint(
            f"bootstrap_commit_id = '{_BOOTSTRAP_COMMIT}'",
            name=op.f("ck_ingress_provider_heads_bootstrap_commit_pin"),
        ),
        sa.CheckConstraint(
            f"bootstrap_tree_id = '{_BOOTSTRAP_TREE}'",
            name=op.f("ck_ingress_provider_heads_bootstrap_tree_pin"),
        ),
        sa.CheckConstraint(
            "last_verified_commit_id ~ '^[0-9a-f]{40}$'",
            name=op.f("ck_ingress_provider_heads_last_commit_format"),
        ),
        sa.CheckConstraint(
            "last_verified_tree_id ~ '^[0-9a-f]{40}$'",
            name=op.f("ck_ingress_provider_heads_last_tree_format"),
        ),
        sa.CheckConstraint(
            "length(branch_name) BETWEEN 1 AND 255",
            name=op.f("ck_ingress_provider_heads_branch_name_length"),
        ),
        sa.CheckConstraint(
            "etag IS NULL OR length(etag) BETWEEN 1 AND 1024",
            name=op.f("ck_ingress_provider_heads_etag_length"),
        ),
        sa.CheckConstraint(
            "verified_at >= created_at",
            name=op.f("ck_ingress_provider_heads_verified_at_order"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "installation_id"],
            ["transport_installations.tenant_id", "transport_installations.installation_id"],
            name="installation",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "transport_binding_id"],
            ["transport_bindings.tenant_id", "transport_bindings.transport_binding_id"],
            name="transport_binding",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "tenant_id",
            "provider",
            "repository_external_id",
            "branch_name",
            name=op.f("pk_ingress_provider_heads"),
        ),
        info={
            "scalevault_tenant_owned": True,
            "scalevault_immutable_fields": (
                "tenant_id",
                "provider",
                "repository_external_id",
                "branch_name",
                "installation_id",
                "transport_binding_id",
                "bootstrap_commit_id",
                "bootstrap_tree_id",
                "created_at",
            ),
        },
    )
    op.execute(sa.text("ALTER TABLE public.ingress_provider_heads ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE public.ingress_provider_heads FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY scalevault_tenant_isolation ON public.ingress_provider_heads "
            f"USING ({_TENANT_EXPRESSION}) WITH CHECK ({_TENANT_EXPRESSION})"
        )
    )
    immutable_columns = (
        "tenant_id, provider, repository_external_id, branch_name, installation_id, "
        "transport_binding_id, bootstrap_commit_id, bootstrap_tree_id, created_at"
    )
    immutable_arguments = (
        "'tenant_id', 'provider', 'repository_external_id', 'branch_name', "
        "'installation_id', 'transport_binding_id', 'bootstrap_commit_id', "
        "'bootstrap_tree_id', 'created_at'"
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_heads_immutable_fields "
            f"BEFORE UPDATE OF {immutable_columns} ON public.ingress_provider_heads "
            "FOR EACH ROW EXECUTE FUNCTION "
            f"public.scalevault_reject_immutable_field_mutation({immutable_arguments})"
        )
    )
    op.execute(
        sa.text(
            "CREATE FUNCTION public.scalevault_enforce_ingress_provider_head_lifecycle() "
            "RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $function$ "
            "BEGIN "
            "IF TG_OP = 'INSERT' THEN "
            "IF NOT EXISTS (SELECT 1 FROM public.transport_bindings AS binding "
            "WHERE binding.tenant_id = NEW.tenant_id "
            "AND binding.transport_binding_id = NEW.transport_binding_id "
            "AND binding.installation_id = NEW.installation_id "
            "AND binding.transport_kind = 'github_ingress') THEN "
            "RAISE EXCEPTION 'ingress provider head binding identity mismatch' "
            "USING ERRCODE = '23503'; END IF; "
            "IF NEW.last_verified_commit_id = NEW.bootstrap_commit_id "
            "AND NEW.last_verified_tree_id = NEW.bootstrap_tree_id "
            "AND NEW.etag IS NULL THEN RETURN NEW; END IF; "
            "RAISE EXCEPTION 'ingress provider head must begin at bootstrap' "
            "USING ERRCODE = '23514'; "
            "END IF; "
            "IF NEW.last_verified_commit_id IS NOT DISTINCT FROM OLD.last_verified_commit_id "
            "AND NEW.last_verified_tree_id IS NOT DISTINCT FROM OLD.last_verified_tree_id "
            "AND NEW.etag IS NOT DISTINCT FROM OLD.etag "
            "AND NEW.verified_at IS NOT DISTINCT FROM OLD.verified_at THEN RETURN NEW; END IF; "
            "IF NEW.verified_at < OLD.verified_at THEN "
            "RAISE EXCEPTION 'ingress provider verification time cannot move backward' "
            "USING ERRCODE = '23514'; END IF; "
            "RETURN NEW; END $function$"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_heads_lifecycle_insert "
            "BEFORE INSERT ON public.ingress_provider_heads FOR EACH ROW EXECUTE FUNCTION "
            "public.scalevault_enforce_ingress_provider_head_lifecycle()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_heads_lifecycle_update "
            "BEFORE UPDATE OF last_verified_commit_id, last_verified_tree_id, etag, verified_at "
            "ON public.ingress_provider_heads FOR EACH ROW EXECUTE FUNCTION "
            "public.scalevault_enforce_ingress_provider_head_lifecycle()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_heads_delete_forbidden "
            "BEFORE DELETE ON public.ingress_provider_heads FOR EACH ROW EXECUTE FUNCTION "
            "public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER trg_ingress_provider_heads_truncate_forbidden "
            "BEFORE TRUNCATE ON public.ingress_provider_heads FOR EACH STATEMENT EXECUTE FUNCTION "
            "public.scalevault_reject_immutable_mutation()"
        )
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 10, "
            "minimum_reader_revision = '0010_ingress_provider_heads', "
            "minimum_writer_revision = '0010_ingress_provider_heads' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 9, "
            "minimum_reader_revision = '0009_secure_tunnel_binding', "
            "minimum_writer_revision = '0009_secure_tunnel_binding' "
            "WHERE component = 'memory_node'"
        )
    )
    op.drop_table("ingress_provider_heads")
    op.execute(sa.text("DROP FUNCTION public.scalevault_enforce_ingress_provider_head_lifecycle"))
