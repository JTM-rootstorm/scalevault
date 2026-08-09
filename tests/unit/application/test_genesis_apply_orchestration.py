from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from kivra_memory.application.genesis_apply import (
    GenesisApplyError,
    GenesisOperatorConfig,
    preflight_genesis_import,
    prepare_genesis_import,
)
from kivra_memory.application.genesis_import import (
    GenesisCanonicalMappings,
    GenesisImporterAuthority,
    GenesisSubjectMapping,
    canonical_genesis_mappings_sha256,
)
from kivra_memory.domain.enums import SubjectKind
from kivra_memory.storage.genesis_import import _verify_plan_digest
from kivra_memory.storage.models import (
    Actor,
    Branch,
    Client,
    Lineage,
    Persona,
    Subject,
    Tenant,
    TransportBinding,
)

from tests.unit.application.test_genesis_plan import _plan


def _id(value: int) -> UUID:
    return UUID(f"019c0000-0000-7000-8000-{value:012x}")


def _config(digest: str) -> GenesisOperatorConfig:
    return GenesisOperatorConfig(
        contract_version="scalevault-genesis-operator-config-v1",
        expected_plan_sha256=digest,
        import_run_id=_id(1),
        pre_state_sha256="b" * 64,
        backup_reference="verified-backup-reference",
        mappings=GenesisCanonicalMappings(
            contract_version="scalevault-genesis-canonical-mappings-v1",
            genesis_actor_reference="kivra:genesis",
            genesis_actor_id=_id(2),
            persona_id=_id(3),
            lineage_id=_id(4),
            branch_id=_id(5),
            subjects=(
                GenesisSubjectMapping(
                    subject_kind=SubjectKind.RELATIONSHIP,
                    source_reference="relationship:private",
                    subject_id=_id(6),
                ),
                GenesisSubjectMapping(
                    subject_kind=SubjectKind.GLOBAL,
                    source_reference="genesis-import:terminal",
                    subject_id=_id(7),
                ),
            ),
        ),
        importer_authority=GenesisImporterAuthority(
            contract_version="scalevault-genesis-importer-authority-v1",
            tenant_id=_id(8),
            actor_id=_id(9),
            client_id=_id(10),
            transport_binding_id=_id(11),
        ),
    )


def test_prepare_builds_replay_stable_rows_and_frozen_canonical_mapping() -> None:
    plan = _plan()
    config = _config(plan.manifest.digest)

    first = prepare_genesis_import(plan, config)
    second = prepare_genesis_import(plan, config)

    assert [row.import_record_id for row in first.records] == [
        row.import_record_id for row in second.records
    ]
    assert len(first.sources) == 1
    assert len(first.records) == 2
    assert len(first.exclusions) == 2
    assert len(first.supersessions) == 2
    assert first.run.canonical_mapping_sha256 == canonical_genesis_mappings_sha256(config.mappings)
    assert _verify_plan_digest(
        first.run,
        first.sources,
        first.records,
        first.exclusions,
        first.supersessions,
    ) == bytes.fromhex(plan.manifest.digest)
    for record in first.records:
        canonical_mapping = record.mapping_metadata["canonical_mapping"]
        assert isinstance(canonical_mapping, dict)
        assert canonical_mapping == {
            "persona_id": str(config.mappings.persona_id),
            "lineage_id": str(config.mappings.lineage_id),
            "branch_id": str(config.mappings.branch_id),
            "genesis_actor_id": str(config.mappings.genesis_actor_id),
            "subject_id": str(_id(6)),
            "subject_kind": "relationship",
            "logical_session_id": None,
        }
        assert record.effective_visibility == "private_root"
        assert record.requested_outcome_ceiling == "candidate"


def test_prepare_rejects_any_expected_plan_digest_mismatch() -> None:
    plan = _plan()

    with pytest.raises(GenesisApplyError, match="genesis_plan_digest_mismatch"):
        prepare_genesis_import(plan, _config("f" * 64))


class _PreflightSession:
    def __init__(self, rows: dict[tuple[type[object], UUID], object]) -> None:
        self.rows = rows

    async def get(self, model: type[object], identity: UUID) -> object | None:
        return self.rows.get((model, identity))


class _PreflightDatabase:
    def __init__(self, session: _PreflightSession) -> None:
        self.session = session

    @asynccontextmanager
    async def tenant_session(self, _tenant_id: UUID) -> Any:
        yield self.session


def _preflight_rows(config: GenesisOperatorConfig) -> dict[tuple[type[object], UUID], object]:
    authority = config.importer_authority
    mappings = config.mappings
    return {
        (Tenant, authority.tenant_id): SimpleNamespace(state="active"),
        (Actor, authority.actor_id): SimpleNamespace(
            actor_id=authority.actor_id,
            tenant_id=authority.tenant_id,
            kind="service",
            revoked_at=None,
        ),
        (Actor, mappings.genesis_actor_id): SimpleNamespace(
            actor_id=mappings.genesis_actor_id,
            tenant_id=authority.tenant_id,
            kind="persona",
            revoked_at=None,
        ),
        (Client, authority.client_id): SimpleNamespace(
            client_id=authority.client_id,
            tenant_id=authority.tenant_id,
            kind="operator",
            transport_kind="internal_service",
            scopes=["memory.write.genesis_import"],
            revoked_at=None,
        ),
        (TransportBinding, authority.transport_binding_id): SimpleNamespace(
            tenant_id=authority.tenant_id,
            actor_id=authority.actor_id,
            client_id=authority.client_id,
            transport_kind="internal_service",
            disclosure_boundary="internal",
            installation_id=None,
            valid_until=None,
            authorized_operations={"operations": ["observed"]},
        ),
        (Persona, mappings.persona_id): SimpleNamespace(
            persona_id=mappings.persona_id,
            tenant_id=authority.tenant_id,
            actor_id=mappings.genesis_actor_id,
            retired_at=None,
        ),
        (Lineage, mappings.lineage_id): SimpleNamespace(
            lineage_id=mappings.lineage_id,
            tenant_id=authority.tenant_id,
            persona_id=mappings.persona_id,
            sealed_at=None,
        ),
        (Branch, mappings.branch_id): SimpleNamespace(
            branch_id=mappings.branch_id,
            tenant_id=authority.tenant_id,
            lineage_id=mappings.lineage_id,
            sealed_at=None,
        ),
        (Subject, mappings.subjects[0].subject_id): SimpleNamespace(
            subject_id=mappings.subjects[0].subject_id,
            tenant_id=authority.tenant_id,
            lineage_id=mappings.lineage_id,
            kind="relationship",
            persona_id=None,
            relationship_actor_id=_id(12),
            project_ref=None,
            episode_ref=None,
            origin_session_id=None,
        ),
        (Subject, mappings.subjects[1].subject_id): SimpleNamespace(
            subject_id=mappings.subjects[1].subject_id,
            tenant_id=authority.tenant_id,
            lineage_id=mappings.lineage_id,
            kind="global",
            persona_id=None,
            relationship_actor_id=None,
            project_ref=None,
            episode_ref=None,
            origin_session_id=None,
        ),
    }


async def test_preflight_validates_complete_existing_identity_graph() -> None:
    plan = _plan()
    config = _config(plan.manifest.digest)
    prepared = prepare_genesis_import(plan, config)
    database = _PreflightDatabase(_PreflightSession(_preflight_rows(config)))

    await preflight_genesis_import(database, prepared, config)  # type: ignore[arg-type]


async def test_preflight_fails_before_staging_on_widened_client_scope() -> None:
    plan = _plan()
    config = _config(plan.manifest.digest)
    prepared = prepare_genesis_import(plan, config)
    rows = _preflight_rows(config)
    client = rows[(Client, config.importer_authority.client_id)]
    client.scopes.append("memory.write")  # type: ignore[attr-defined]
    database = _PreflightDatabase(_PreflightSession(rows))

    with pytest.raises(GenesisApplyError, match="genesis_identity_preflight_failed"):
        await preflight_genesis_import(database, prepared, config)  # type: ignore[arg-type]
