from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
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
        {"pre_state_sha256", "backup_reference"}
    )


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
        )

    assert error.value.code == "invalid_context_digest"
    session.execute.assert_not_awaited()
