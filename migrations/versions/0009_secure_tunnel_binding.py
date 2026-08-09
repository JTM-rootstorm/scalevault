"""Require secure-tunnel identities to bind an installation.

Revision ID: 0009_secure_tunnel_binding
Revises: 0008_codex_credentials
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_secure_tunnel_binding"
down_revision: str | None = "0008_codex_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_transport_bindings_relay_has_installation"),
        "transport_bindings",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_transport_bindings_remote_has_installation"),
        "transport_bindings",
        "transport_kind NOT IN ('secure_tunnel', 'relay') OR installation_id IS NOT NULL",
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 9, "
            "minimum_reader_revision = '0009_secure_tunnel_binding', "
            "minimum_writer_revision = '0009_secure_tunnel_binding' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 8, "
            "minimum_reader_revision = '0008_codex_credentials', "
            "minimum_writer_revision = '0008_codex_credentials' "
            "WHERE component = 'memory_node'"
        )
    )
    op.drop_constraint(
        op.f("ck_transport_bindings_remote_has_installation"),
        "transport_bindings",
        type_="check",
    )
    op.create_check_constraint(
        op.f("ck_transport_bindings_relay_has_installation"),
        "transport_bindings",
        "transport_kind <> 'relay' OR installation_id IS NOT NULL",
    )
