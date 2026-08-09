from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.storage import genesis_import as genesis_storage
from kivra_memory.storage.genesis_import import (
    GenesisImportRepository,
    GenesisImportStorageError,
    GenesisRecordStatus,
    GenesisRunStatus,
    PendingGenesisRecord,
)
from kivra_memory.storage.models import metadata
from sqlalchemy import CheckConstraint
from sqlalchemy.ext.asyncio import AsyncSession

GENESIS_TABLES = {
    "genesis_import_runs",
    "genesis_import_sources",
    "genesis_import_records",
    "genesis_import_exclusions",
    "genesis_import_supersessions",
    "genesis_import_run_results",
}


def uid(value: int) -> UUID:
    return UUID(f"019c0000-0000-7000-8000-{value:012x}")


def checks(table_name: str) -> str:
    return " ".join(
        str(constraint.sqltext)
        for constraint in metadata.tables[table_name].constraints
        if isinstance(constraint, CheckConstraint)
    )


def _bound_synthetic_plan() -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    raw = b'{"contract":"synthetic"}'
    parsed = {"contract": "synthetic"}
    source = SimpleNamespace(
        source_id=uid(2),
        source_kind="checkpoint_v2",
        source_identity="synthetic-source",
        source_path="ingress/checkpoints/v2/genesis/2026/08/synthetic-source.json",
        blob_object_id=hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest(),
        raw_sha256=hashlib.sha256(raw).digest(),
        raw_bytes=raw,
        parsed_document=parsed,
        parsed_canonical_json=canonical_json_bytes(parsed),
        parsed_canonical_sha256=hashlib.sha256(canonical_json_bytes(parsed)).digest(),
    )
    run = SimpleNamespace(
        manifest_version="scalevault.genesis-import-manifest.v1",
        source_repository="JTM-rootstorm/scalevault-memory-ingress",
        snapshot_commit="7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9",
        parser_schema_versions={
            "scalevault.ingress.genesis-checkpoint.v2": "checkpoint-v2.schema.1"
        },
        mapping_version="genesis-import-mapping-v1",
        compatibility_version="genesis-first-import-compat-v1",
        policy_version="selection-v1",
        policy_sha256=bytes.fromhex(
            "b12dd83889d2a273e260c5b990eea5a0b6531ab38be76fca47642f471d2bf85e"
        ),
        plan_sha256=b"\x00" * 32,
    )
    semantics = {
        "subject": {"subject_kind": "persona", "source_reference": "kivra:genesis"},
        "category": "stable_fact",
        "ontological_status": "literal_user_fact",
        "scope": "persona",
        "visibility": "private_root",
        "statement": "synthetic",
        "reason_to_remember": "synthetic test binding",
        "interpretation_limits": ["synthetic test only"],
        "confidence": 0.5,
        "salience": 0.5,
        "durability": 0.5,
        "sensitivity": 4,
    }
    nomination_material = {
        "mapping_version": run.mapping_version,
        "source_repository": run.source_repository,
        "source_snapshot_commit": run.snapshot_commit,
        "source_path": source.source_path,
        "source_raw_sha256": source.raw_sha256.hex(),
        "source_record_id": "synthetic-record",
        "semantics": semantics,
        "selection_basis": "imported_legacy",
        "epistemic_qualifiers": ["imported_source_unreconciled"],
    }
    nomination_sha = hashlib.sha256(
        b"scalevault.genesis-import.nomination.v1\x00" + canonical_json_bytes(nomination_material)
    ).digest()
    idempotency_sha = hashlib.sha256(
        b"scalevault.genesis-import.idempotency.v1\x00" + canonical_json_bytes(nomination_material)
    ).hexdigest()
    record = SimpleNamespace(
        import_record_id=uid(3),
        source_id=source.source_id,
        lineage_id=uid(4),
        branch_id=uid(5),
        record_kind="candidate",
        source_item_identity="synthetic-record",
        source_item_document={"binding": {"owner_actor_id": "kivra:genesis"}},
        nomination_sha256=nomination_sha,
        nomination_idempotency_key=f"genesis-import-v1:{idempotency_sha}",
        mapping_metadata={
            "semantics": semantics,
            "review_controls": {"automatic_promotion_allowed": False},
            "canonical_mapping": {
                "genesis_actor_id": str(uid(6)),
                "persona_id": str(uid(7)),
                "lineage_id": str(uid(4)),
                "branch_id": str(uid(5)),
                "subject_id": str(uid(8)),
                "subject_kind": "persona",
                "logical_session_id": None,
            },
        },
    )
    material = genesis_storage._manifest_material(run, (source,), (record,), (), ())
    run.plan_sha256 = hashlib.sha256(canonical_json_bytes(material)).digest()
    return run, source, record


def test_plan_digest_is_recomputed_from_exact_children() -> None:
    run, source, record = _bound_synthetic_plan()

    assert genesis_storage._verify_plan_digest(run, (source,), (record,), (), ()) == (
        run.plan_sha256
    )

    semantics = cast(dict[str, object], record.mapping_metadata["semantics"])
    semantics["statement"] = "tampered"
    with pytest.raises(GenesisImportStorageError, match="nomination_binding_mismatch"):
        genesis_storage._verify_plan_digest(run, (source,), (record,), (), ())


def test_plan_digest_rejects_an_unbound_approved_digest() -> None:
    run, source, record = _bound_synthetic_plan()
    run.plan_sha256 = b"x" * 32

    with pytest.raises(GenesisImportStorageError, match="import_plan_digest_mismatch"):
        genesis_storage._verify_plan_digest(run, (source,), (record,), (), ())


def test_genesis_storage_is_tenant_owned_and_protected() -> None:
    assert set(metadata.tables) >= GENESIS_TABLES
    for table_name in GENESIS_TABLES:
        table = metadata.tables[table_name]
        assert table.info["scalevault_tenant_owned"] is True
        assert "tenant_id" in table.c
    assert metadata.tables["genesis_import_runs"].info["scalevault_immutable"] is True
    assert metadata.tables["genesis_import_sources"].info["scalevault_immutable"] is True
    assert (
        "processing_state"
        not in metadata.tables["genesis_import_records"].info["scalevault_immutable_fields"]
    )


def test_run_contract_is_exact_and_recovery_evidence_precedes_apply() -> None:
    run_checks = checks("genesis_import_runs")
    assert "JTM-rootstorm/scalevault-memory-ingress" in run_checks
    assert "7dc1cae4b9a99173d2d227be1dd1d10c7f267ce9" in run_checks
    assert "scalevault.genesis-import-manifest.v1" in run_checks
    assert "genesis-import-mapping-v1" in run_checks
    assert "genesis-first-import-compat-v1" in run_checks
    assert "scalevault.ingress.proposal.v1" in run_checks
    assert "proposal-v1.schema.1" in run_checks
    assert "selection-v1" in run_checks
    assert set(metadata.tables["genesis_import_runs"].c.keys()).issuperset(
        {"canonical_mapping_sha256", "pre_state_sha256", "backup_reference"}
    )
    assert "octet_length(canonical_mapping_sha256) = 32" in run_checks


def test_source_archive_preserves_bytes_json_hashes_and_source_bounds() -> None:
    source = metadata.tables["genesis_import_sources"]
    source_checks = checks(source.name)
    assert source.c.declared_idempotency_key.type.length == 512
    assert source.c.source_conversation_ref.type.__class__.__name__ == "Text"
    assert "length(source_conversation_ref) <= 2048" in source_checks
    assert "digest(raw_bytes, 'sha256') = raw_sha256" in source_checks
    assert "digest(parsed_canonical_json, 'sha256') = parsed_canonical_sha256" in source_checks
    assert "genesis-first-import-compat-v1" in source_checks
    assert "genesis-checkpoint-20260807T124400-0500" in source_checks
    assert "76214f303012d756c34a3b5bdf9948267a1418e3" in source_checks
    assert "f0f147d1ee8c748c7080ee821f1a48751b50d31c78912cbd3e1b358da39f83e7" in source_checks
    assert "/candidates/1/binding/visibility" in source_checks


def test_records_exclusions_and_completion_fail_closed() -> None:
    record = metadata.tables["genesis_import_records"]
    assert record.c.original_confidence.type.__class__.__name__ == "String"
    record_checks = checks(record.name)
    assert "effective_visibility = 'private_root'" in record_checks
    assert "requested_outcome_ceiling = 'candidate'" in record_checks
    assert "processing_state IN ('planned', 'candidate', 'omit', 'reject')" in record_checks
    assert "selection_decision_id IS NOT NULL" in record_checks
    assert "blocks_automatic_promotion" in checks("genesis_import_exclusions")
    assert "replay_verified" in checks("genesis_import_run_results")


def test_safe_status_dtos_have_no_source_content_fields() -> None:
    for dto in (GenesisRecordStatus, PendingGenesisRecord, GenesisRunStatus):
        fields = set(dto.__dataclass_fields__)
        assert not fields & {
            "raw_bytes",
            "parsed_document",
            "parsed_canonical_json",
            "source_item_document",
            "claim",
            "reason",
            "binding_metadata",
            "provenance_metadata",
        }


async def test_terminalization_rejects_invalid_shape_before_database_access() -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    repository = GenesisImportRepository(cast(AsyncSession, session))

    with pytest.raises(GenesisImportStorageError) as error:
        await repository.terminalize_record(
            tenant_id=uid(1),
            import_run_id=uid(2),
            import_record_id=uid(3),
            nomination_sha256=b"x" * 32,
            outcome="candidate",
            selection_decision_id=uid(4),
            processed_at=datetime(2026, 8, 8, tzinfo=UTC),
        )

    assert error.value.code == "invalid_terminal_result"
    session.execute.assert_not_awaited()


async def test_context_verification_rejects_bad_digests_without_database_access() -> None:
    session = MagicMock(spec=AsyncSession)
    session.execute = AsyncMock()
    repository = GenesisImportRepository(cast(AsyncSession, session))

    with pytest.raises(GenesisImportStorageError) as error:
        await repository.verify_planned_record_context(
            tenant_id=uid(1),
            import_run_id=uid(2),
            import_record_id=uid(3),
            plan_sha256=b"short",
            source_id=uid(4),
            source_path="ingress/checkpoints/v2/genesis/2026/08/example.json",
            blob_object_id="a" * 40,
            raw_sha256=b"r" * 32,
            nomination_sha256=b"n" * 32,
            nomination_idempotency_key="genesis:test",
            mapping_metadata_sha256=b"m" * 32,
        )

    assert error.value.code == "invalid_context_digest"
    session.execute.assert_not_awaited()
