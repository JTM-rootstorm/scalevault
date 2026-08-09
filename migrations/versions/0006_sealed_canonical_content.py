"""Add sealed canonical content projection storage.

Revision ID: 0006_sealed_canonical_content
Revises: 0005_github_ingress_v2_runtime
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_sealed_canonical_content"
down_revision: str | None = "0005_github_ingress_v2_runtime"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("memories", sa.Column("sealed_envelope_version", sa.SmallInteger()))
    op.add_column("memories", sa.Column("sealed_algorithm", sa.String(length=32)))
    op.add_column("memories", sa.Column("sealed_nonce", sa.LargeBinary()))
    op.add_column("memories", sa.Column("sealed_ciphertext", sa.LargeBinary()))
    op.add_column("memories", sa.Column("sealed_aad_sha256", sa.LargeBinary()))
    op.add_column("memories", sa.Column("safe_summary", sa.Text()))

    op.drop_constraint(op.f("ck_memories_tombstone_content_shape"), "memories", type_="check")
    op.create_check_constraint(
        op.f("ck_memories_tombstone_content_shape"),
        "memories",
        "(status = 'tombstoned' AND statement IS NULL AND reason_to_remember IS NULL AND "
        "normalized_fingerprint IS NULL AND interpretation_limits = '[]'::jsonb) OR "
        "(status <> 'tombstoned' AND content_protection = 'plaintext' AND "
        "statement IS NOT NULL AND reason_to_remember IS NOT NULL AND "
        "normalized_fingerprint IS NOT NULL) OR "
        "(status <> 'tombstoned' AND content_protection = 'envelope_encrypted' AND "
        "statement IS NULL AND reason_to_remember IS NULL AND normalized_fingerprint IS NULL "
        "AND interpretation_limits = '[]'::jsonb AND metadata = '{}'::jsonb)",
    )
    op.create_check_constraint(
        op.f("ck_memories_sealed_envelope_shape"),
        "memories",
        "(content_protection = 'plaintext' AND sealed_envelope_version IS NULL AND "
        "sealed_algorithm IS NULL AND sealed_nonce IS NULL AND sealed_ciphertext IS NULL "
        "AND sealed_aad_sha256 IS NULL AND safe_summary IS NULL) OR "
        "(content_protection IN ('envelope_encrypted', 'cryptographically_erased') AND "
        "sealed_envelope_version = 1 AND sealed_algorithm = 'AES-256-GCM' AND "
        "sealed_nonce IS NOT NULL AND sealed_ciphertext IS NOT NULL AND "
        "sealed_aad_sha256 IS NOT NULL AND safe_summary IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_memories_sealed_nonce_length"),
        "memories",
        "sealed_nonce IS NULL OR octet_length(sealed_nonce) = 12",
    )
    op.create_check_constraint(
        op.f("ck_memories_sealed_ciphertext_length"),
        "memories",
        "sealed_ciphertext IS NULL OR octet_length(sealed_ciphertext) BETWEEN 17 AND 716816",
    )
    op.create_check_constraint(
        op.f("ck_memories_sealed_aad_sha256_length"),
        "memories",
        "sealed_aad_sha256 IS NULL OR octet_length(sealed_aad_sha256) = 32",
    )
    op.create_check_constraint(
        op.f("ck_memories_safe_summary_length"),
        "memories",
        "safe_summary IS NULL OR length(safe_summary) BETWEEN 1 AND 1024",
    )
    op.create_check_constraint(
        op.f("ck_memories_sealed_plaintext_absence"),
        "memories",
        "content_protection = 'plaintext' OR (statement IS NULL AND "
        "reason_to_remember IS NULL AND normalized_fingerprint IS NULL AND "
        "interpretation_limits = '[]'::jsonb AND metadata = '{}'::jsonb)",
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 6, "
            "minimum_reader_revision = '0006_sealed_canonical_content', "
            "minimum_writer_revision = '0006_sealed_canonical_content' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 5, "
            "minimum_reader_revision = '0005_github_ingress_v2_runtime', "
            "minimum_writer_revision = '0005_github_ingress_v2_runtime' "
            "WHERE component = 'memory_node'"
        )
    )
    op.drop_constraint(op.f("ck_memories_sealed_plaintext_absence"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_safe_summary_length"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_sealed_aad_sha256_length"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_sealed_ciphertext_length"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_sealed_nonce_length"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_sealed_envelope_shape"), "memories", type_="check")
    op.drop_constraint(op.f("ck_memories_tombstone_content_shape"), "memories", type_="check")
    op.create_check_constraint(
        op.f("ck_memories_tombstone_content_shape"),
        "memories",
        "(status = 'tombstoned' AND statement IS NULL AND reason_to_remember IS NULL AND "
        "normalized_fingerprint IS NULL AND interpretation_limits = '[]'::jsonb) OR "
        "(status <> 'tombstoned' AND statement IS NOT NULL AND reason_to_remember IS NOT NULL "
        "AND normalized_fingerprint IS NOT NULL)",
    )
    op.drop_column("memories", "safe_summary")
    op.drop_column("memories", "sealed_aad_sha256")
    op.drop_column("memories", "sealed_ciphertext")
    op.drop_column("memories", "sealed_nonce")
    op.drop_column("memories", "sealed_algorithm")
    op.drop_column("memories", "sealed_envelope_version")
