from __future__ import annotations

from kivra_memory.storage import metadata
from sqlalchemy import CheckConstraint


def test_memory_projection_has_complete_sealed_envelope_tuple() -> None:
    memory = metadata.tables["memories"]

    assert {
        "sealed_envelope_version",
        "sealed_algorithm",
        "sealed_nonce",
        "sealed_ciphertext",
        "sealed_aad_sha256",
        "safe_summary",
    } <= set(memory.c.keys())
    assert all(
        memory.c[name].nullable
        for name in (
            "sealed_envelope_version",
            "sealed_algorithm",
            "sealed_nonce",
            "sealed_ciphertext",
            "sealed_aad_sha256",
            "safe_summary",
        )
    )

    checks = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in memory.constraints
        if isinstance(constraint, CheckConstraint)
    }
    shape = checks["ck_memories_sealed_envelope_shape"]
    assert "content_protection = 'plaintext'" in shape
    assert "sealed_envelope_version IS NULL" in shape
    assert "content_protection IN ('envelope_encrypted', 'cryptographically_erased')" in shape
    assert "sealed_envelope_version = 1" in shape
    assert "sealed_algorithm = 'AES-256-GCM'" in shape
    assert "safe_summary IS NOT NULL" in shape
    assert "octet_length(sealed_nonce) = 12" in checks["ck_memories_sealed_nonce_length"]
    assert "octet_length(sealed_aad_sha256) = 32" in checks["ck_memories_sealed_aad_sha256_length"]
    plaintext_absence = checks["ck_memories_sealed_plaintext_absence"]
    assert "statement IS NULL" in plaintext_absence
    assert "reason_to_remember IS NULL" in plaintext_absence
    assert "normalized_fingerprint IS NULL" in plaintext_absence
    assert "metadata = '{}'::jsonb" in plaintext_absence


def test_key_reference_table_explicitly_contains_no_key_material() -> None:
    content_keys = metadata.tables["memory_content_keys"]

    assert content_keys.info["scalevault_contains_no_key_material"] is True
    assert set(content_keys.c.keys()) == {
        "content_key_id",
        "tenant_id",
        "lineage_id",
        "memory_id",
        "provider_name",
        "provider_key_reference",
        "state",
        "created_at",
        "destruction_requested_at",
        "destroyed_at",
        "destruction_receipt_sha256",
    }
