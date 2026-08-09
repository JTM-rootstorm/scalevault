"""Content-free persistence seam for protected Genesis import application code."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.ingress.processor import MappedNominationSemantics
from kivra_memory.storage.models import (
    CommandReceipt,
    GenesisImportExclusion,
    GenesisImportRecord,
    GenesisImportRun,
    GenesisImportRunResult,
    GenesisImportSource,
    GenesisImportSupersession,
    Memory,
    MemoryEvent,
    SelectionDecision,
)

GenesisTerminalOutcome = Literal["candidate", "omit", "reject"]

_NOMINATION_DOMAIN = b"scalevault.genesis-import.nomination.v1\x00"
_NOMINATION_IDEMPOTENCY_DOMAIN = b"scalevault.genesis-import.idempotency.v1\x00"
_EXCLUSION_DOMAIN = b"scalevault.genesis-import.exclusion.v1\x00"
_SUPERSESSION_DOMAIN = b"scalevault.genesis-import.supersession.v1\x00"
_PLAN_RECORD_IDEMPOTENCY_DOMAIN = b"scalevault.genesis-import.plan-record.v1\x00"
_SOURCE_CONTRACTS = {
    "proposal_v1": "scalevault.ingress.proposal.v1",
    "checkpoint_v1": "scalevault.ingress.genesis-checkpoint.v1",
    "checkpoint_v2": "scalevault.ingress.genesis-checkpoint.v2",
}


class GenesisImportStorageError(RuntimeError):
    """A stable content-free Genesis persistence failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class GenesisRecordStatus:
    import_record_id: UUID
    processing_state: Literal["planned", "candidate", "omit", "reject"]
    selection_decision_id: UUID | None
    event_id: UUID | None
    memory_id: UUID | None
    processed_at: datetime | None


@dataclass(frozen=True, slots=True)
class PendingGenesisRecord:
    import_record_id: UUID
    source_id: UUID
    nomination_sha256: bytes
    nomination_idempotency_key: str


@dataclass(frozen=True, slots=True)
class GenesisRunStatus:
    import_run_id: UUID
    plan_sha256: bytes
    canonical_mapping_sha256: bytes
    source_count: int
    planned_record_count: int
    terminal_record_count: int
    completed: bool


@dataclass(frozen=True, slots=True)
class GenesisRunResultStatus:
    import_run_id: UUID
    planned_record_count: int
    candidate_count: int
    omit_count: int
    reject_count: int
    replay_verified: bool
    completed_at: datetime


def _record_status(row: GenesisImportRecord) -> GenesisRecordStatus:
    return GenesisRecordStatus(
        import_record_id=row.import_record_id,
        processing_state=row.processing_state,  # type: ignore[arg-type]
        selection_decision_id=row.selection_decision_id,
        event_id=row.event_id,
        memory_id=row.memory_id,
        processed_at=row.processed_at,
    )


def _digest(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _record_owner(row: GenesisImportRecord) -> str | None:
    if row.record_kind != "candidate":
        return None
    binding = row.source_item_document.get("binding")
    if not isinstance(binding, dict):
        raise GenesisImportStorageError("invalid_nomination_binding")
    owner = binding.get("owner_actor_id")
    if owner is None:
        return None
    if not isinstance(owner, str) or not owner:
        raise GenesisImportStorageError("invalid_nomination_binding")
    return owner


def _verify_nomination(
    run: GenesisImportRun,
    source: GenesisImportSource,
    record: GenesisImportRecord,
) -> None:
    semantics = record.mapping_metadata.get("semantics")
    canonical_mapping = record.mapping_metadata.get("canonical_mapping")
    expected_mapping_keys = {
        "genesis_actor_id",
        "persona_id",
        "lineage_id",
        "branch_id",
        "subject_id",
        "subject_kind",
        "logical_session_id",
    }
    if (
        not isinstance(semantics, dict)
        or not isinstance(canonical_mapping, dict)
        or set(canonical_mapping) != expected_mapping_keys
    ):
        raise GenesisImportStorageError("invalid_nomination_mapping")
    try:
        normalized_semantics = MappedNominationSemantics.model_validate_json(
            canonical_json_bytes(semantics)
        ).model_dump(mode="python")
    except ValidationError:
        raise GenesisImportStorageError("invalid_nomination_mapping") from None
    try:
        mapped_ids = {
            key: UUID(str(canonical_mapping[key]))
            for key in (
                "genesis_actor_id",
                "persona_id",
                "lineage_id",
                "branch_id",
                "subject_id",
            )
        }
        logical_session = canonical_mapping["logical_session_id"]
        if logical_session is not None:
            UUID(str(logical_session))
    except (TypeError, ValueError):
        raise GenesisImportStorageError("invalid_nomination_mapping") from None
    if (
        mapped_ids["lineage_id"] != record.lineage_id
        or mapped_ids["branch_id"] != record.branch_id
        or not isinstance(canonical_mapping["subject_kind"], str)
        or not canonical_mapping["subject_kind"]
    ):
        raise GenesisImportStorageError("invalid_nomination_mapping")
    material = {
        "mapping_version": run.mapping_version,
        "source_repository": run.source_repository,
        "source_snapshot_commit": run.snapshot_commit,
        "source_path": source.source_path,
        "source_raw_sha256": bytes(source.raw_sha256).hex(),
        "source_record_id": record.source_item_identity,
        "semantics": normalized_semantics,
        "selection_basis": "imported_legacy",
        "epistemic_qualifiers": ["imported_source_unreconciled"],
    }
    nomination = _digest(_NOMINATION_DOMAIN, material)
    idempotency = f"genesis-import-v1:{_digest(_NOMINATION_IDEMPOTENCY_DOMAIN, material)}"
    if bytes(record.nomination_sha256).hex() != nomination or (
        record.nomination_idempotency_key != idempotency
    ):
        raise GenesisImportStorageError("nomination_binding_mismatch")


def _manifest_material(
    run: GenesisImportRun,
    sources: tuple[GenesisImportSource, ...],
    records: tuple[GenesisImportRecord, ...],
    exclusions: tuple[GenesisImportExclusion, ...],
    supersessions: tuple[GenesisImportSupersession, ...],
) -> dict[str, object]:
    sources_by_id = {source.source_id: source for source in sources}
    records_by_id = {record.import_record_id: record for record in records}
    exclusions_by_id = {exclusion.exclusion_id: exclusion for exclusion in exclusions}
    if len(sources_by_id) != len(sources):
        raise GenesisImportStorageError("duplicate_plan_identity")

    source_values: list[dict[str, object]] = []
    for source in sources:
        raw_sha = hashlib.sha256(source.raw_bytes).digest()
        parsed_canonical = canonical_json_bytes(source.parsed_document)
        blob_sha = hashlib.sha1(
            f"blob {len(source.raw_bytes)}\0".encode() + source.raw_bytes,
            usedforsecurity=False,
        ).hexdigest()
        if (
            raw_sha != bytes(source.raw_sha256)
            or parsed_canonical != bytes(source.parsed_canonical_json)
            or hashlib.sha256(parsed_canonical).digest() != bytes(source.parsed_canonical_sha256)
            or blob_sha != source.blob_object_id
        ):
            raise GenesisImportStorageError("source_content_digest_mismatch")
        contract = _SOURCE_CONTRACTS.get(source.source_kind)
        if contract is None:
            raise GenesisImportStorageError("invalid_source_contract")
        source_values.append(
            {
                "source_repository": run.source_repository,
                "source_snapshot_commit": run.snapshot_commit,
                "source_path": source.source_path,
                "source_git_blob_sha": source.blob_object_id,
                "source_raw_sha256": bytes(source.raw_sha256).hex(),
                "source_contract": contract,
                "source_id": source.source_identity,
            }
        )

    planned_values: list[dict[str, object]] = []
    for record in records:
        record_source = sources_by_id.get(record.source_id)
        if record_source is None:
            raise GenesisImportStorageError("record_plan_mismatch")
        _verify_nomination(run, record_source, record)
        planned_values.append(
            {
                "source_path": record_source.source_path,
                "record_kind": "nomination",
                "source_record_id": record.source_item_identity,
                "owner_actor_id": _record_owner(record),
                "derived_record_sha256": bytes(record.nomination_sha256).hex(),
                "idempotency_key": record.nomination_idempotency_key,
            }
        )

    for exclusion in exclusions:
        exclusion_source = sources_by_id.get(exclusion.source_id)
        if exclusion_source is None:
            raise GenesisImportStorageError("exclusion_plan_mismatch")
        material = {
            "mapping_version": run.mapping_version,
            "source_raw_sha256": bytes(exclusion_source.raw_sha256).hex(),
            "source_record_id": exclusion.source_exclusion_identity,
            "exclusion": exclusion.provenance_metadata,
        }
        derived = _digest(_EXCLUSION_DOMAIN, material)
        planned_values.append(
            {
                "source_path": exclusion_source.source_path,
                "record_kind": "exclusion",
                "source_record_id": exclusion.source_exclusion_identity,
                "owner_actor_id": None,
                "derived_record_sha256": derived,
                "idempotency_key": (
                    f"genesis-plan-v1:{_digest(_PLAN_RECORD_IDEMPOTENCY_DOMAIN, material)}"
                ),
            }
        )

    def external_identity(record_id: UUID | None, exclusion_id: UUID | None) -> str:
        if record_id is not None:
            record_row = records_by_id.get(record_id)
            if record_row is None:
                raise GenesisImportStorageError("supersession_plan_mismatch")
            return record_row.source_item_identity
        if exclusion_id is not None:
            exclusion_row = exclusions_by_id.get(exclusion_id)
            if exclusion_row is None:
                raise GenesisImportStorageError("supersession_plan_mismatch")
            return exclusion_row.source_exclusion_identity
        raise GenesisImportStorageError("supersession_plan_mismatch")

    for edge in supersessions:
        edge_source = sources_by_id.get(edge.source_id)
        origin_kind = edge.provenance_metadata.get("origin_kind")
        if edge_source is None or origin_kind not in {"candidate", "exclusion"}:
            raise GenesisImportStorageError("supersession_plan_mismatch")
        origin_id = external_identity(edge.successor_record_id, edge.successor_exclusion_id)
        target_id = external_identity(edge.predecessor_record_id, edge.predecessor_exclusion_id)
        material = {
            "mapping_version": run.mapping_version,
            "source_raw_sha256": bytes(edge_source.raw_sha256).hex(),
            "origin_kind": origin_kind,
            "origin_id": origin_id,
            "target_id": target_id,
        }
        derived = _digest(_SUPERSESSION_DOMAIN, material)
        owner = None
        if origin_kind == "candidate":
            if edge.successor_record_id is None:
                raise GenesisImportStorageError("supersession_plan_mismatch")
            owner = _record_owner(records_by_id[edge.successor_record_id])
        planned_values.append(
            {
                "source_path": edge_source.source_path,
                "record_kind": f"{origin_kind}_supersession",
                "source_record_id": derived,
                "owner_actor_id": owner,
                "derived_record_sha256": derived,
                "idempotency_key": (
                    f"genesis-plan-v1:{_digest(_PLAN_RECORD_IDEMPOTENCY_DOMAIN, material)}"
                ),
            }
        )

    return {
        "manifest_version": run.manifest_version,
        "source_repository": run.source_repository,
        "source_snapshot_commit": run.snapshot_commit,
        "parser_schema_versions": run.parser_schema_versions,
        "mapping_version": run.mapping_version,
        "compatibility_version": run.compatibility_version,
        "selection_policy_version": run.policy_version,
        "selection_policy_sha256": bytes(run.policy_sha256).hex(),
        "source_items": sorted(source_values, key=lambda value: str(value["source_path"])),
        "planned_records": sorted(
            planned_values,
            key=lambda value: (
                str(value["source_path"]),
                str(value["record_kind"]),
                str(value["source_record_id"]),
            ),
        ),
    }


def _verify_plan_digest(
    run: GenesisImportRun,
    sources: tuple[GenesisImportSource, ...],
    records: tuple[GenesisImportRecord, ...],
    exclusions: tuple[GenesisImportExclusion, ...],
    supersessions: tuple[GenesisImportSupersession, ...],
) -> bytes:
    material = _manifest_material(run, sources, records, exclusions, supersessions)
    digest = hashlib.sha256(canonical_json_bytes(material)).digest()
    if digest != bytes(run.plan_sha256):
        raise GenesisImportStorageError("import_plan_digest_mismatch")
    return digest


def _normalized_fingerprint_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _normalized_fingerprint_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list | tuple):
        return [_normalized_fingerprint_value(item) for item in value]
    return value


def _row_fingerprint(row: object, *, excluded: frozenset[str]) -> str:
    table = cast(Any, row).__table__
    material = {
        column.name: _normalized_fingerprint_value(getattr(row, column.name))
        for column in table.columns
        if column.name not in excluded
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _children_fingerprint(
    sources: tuple[GenesisImportSource, ...],
    records: tuple[GenesisImportRecord, ...],
    exclusions: tuple[GenesisImportExclusion, ...],
    supersessions: tuple[GenesisImportSupersession, ...],
) -> tuple[tuple[str, str, str], ...]:
    values: list[tuple[str, str, str]] = []
    for kind, rows, identity, excluded in (
        ("source", sources, "source_id", frozenset({"archived_at"})),
        (
            "record",
            records,
            "import_record_id",
            frozenset(
                {
                    "processing_state",
                    "selection_decision_id",
                    "event_id",
                    "memory_id",
                    "planned_at",
                    "processed_at",
                }
            ),
        ),
        ("exclusion", exclusions, "exclusion_id", frozenset({"created_at"})),
        ("supersession", supersessions, "supersession_id", frozenset({"created_at"})),
    ):
        values.extend(
            (kind, str(getattr(row, identity)), _row_fingerprint(row, excluded=excluded))
            for row in rows
        )
    return tuple(sorted(values))


class GenesisImportRepository:
    """Persist terminal links in the caller's existing SERIALIZABLE transaction.

    This repository never commits, rolls back, logs, or returns archived source
    bytes or parsed source documents.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _load_plan_children(
        self, *, tenant_id: UUID, import_run_id: UUID
    ) -> tuple[
        tuple[GenesisImportSource, ...],
        tuple[GenesisImportRecord, ...],
        tuple[GenesisImportExclusion, ...],
        tuple[GenesisImportSupersession, ...],
    ]:
        loaded: list[tuple[object, ...]] = []
        for model, identity in (
            (GenesisImportSource, GenesisImportSource.source_id),
            (GenesisImportRecord, GenesisImportRecord.import_record_id),
            (GenesisImportExclusion, GenesisImportExclusion.exclusion_id),
            (GenesisImportSupersession, GenesisImportSupersession.supersession_id),
        ):
            rows = tuple(
                (
                    await self._session.scalars(
                        select(model)
                        .where(
                            model.tenant_id == tenant_id,
                            model.import_run_id == import_run_id,
                        )
                        .order_by(identity)
                    )
                ).all()
            )
            loaded.append(rows)
        return cast(
            tuple[
                tuple[GenesisImportSource, ...],
                tuple[GenesisImportRecord, ...],
                tuple[GenesisImportExclusion, ...],
                tuple[GenesisImportSupersession, ...],
            ],
            tuple(loaded),
        )

    async def _verified_existing_plan(
        self,
        *,
        existing_run: GenesisImportRun,
        requested_run: GenesisImportRun,
        sources: tuple[GenesisImportSource, ...],
        records: tuple[GenesisImportRecord, ...],
        exclusions: tuple[GenesisImportExclusion, ...],
        supersessions: tuple[GenesisImportSupersession, ...],
    ) -> GenesisRunStatus:
        if (
            existing_run.import_run_id != requested_run.import_run_id
            or existing_run.source_repository != requested_run.source_repository
            or existing_run.snapshot_commit != requested_run.snapshot_commit
            or existing_run.manifest_version != requested_run.manifest_version
            or existing_run.mapping_version != requested_run.mapping_version
            or existing_run.compatibility_version != requested_run.compatibility_version
            or existing_run.parser_schema_versions != requested_run.parser_schema_versions
            or existing_run.policy_id != requested_run.policy_id
            or existing_run.policy_version != requested_run.policy_version
            or bytes(existing_run.policy_sha256) != bytes(requested_run.policy_sha256)
            or bytes(existing_run.canonical_mapping_sha256)
            != bytes(requested_run.canonical_mapping_sha256)
            or existing_run.source_count != requested_run.source_count
            or bytes(existing_run.pre_state_sha256) != bytes(requested_run.pre_state_sha256)
            or existing_run.backup_reference != requested_run.backup_reference
        ):
            raise GenesisImportStorageError("import_plan_conflict")
        stored_children = await self._load_plan_children(
            tenant_id=existing_run.tenant_id,
            import_run_id=existing_run.import_run_id,
        )
        _verify_plan_digest(existing_run, *stored_children)
        if _children_fingerprint(*stored_children) != _children_fingerprint(
            sources, records, exclusions, supersessions
        ):
            raise GenesisImportStorageError("import_plan_conflict")
        existing = await self.run_status(
            tenant_id=existing_run.tenant_id,
            plan_sha256=bytes(existing_run.plan_sha256),
        )
        if existing is None:
            raise GenesisImportStorageError("import_plan_conflict")
        return existing

    async def verify_planned_record_context(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        import_record_id: UUID,
        plan_sha256: bytes,
        source_id: UUID,
        source_path: str,
        blob_object_id: str,
        raw_sha256: bytes,
        nomination_sha256: bytes,
        nomination_idempotency_key: str,
        mapping_metadata_sha256: bytes,
    ) -> PendingGenesisRecord:
        """Fail closed unless every frozen archive and mapping identity matches."""

        if (
            len(plan_sha256) != 32
            or len(raw_sha256) != 32
            or len(nomination_sha256) != 32
            or len(mapping_metadata_sha256) != 32
        ):
            raise GenesisImportStorageError("invalid_context_digest")
        row = (
            await self._session.execute(
                select(
                    GenesisImportRecord.import_record_id,
                    GenesisImportRecord.source_id,
                    GenesisImportRecord.nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key,
                    GenesisImportRecord.mapping_metadata,
                )
                .join(
                    GenesisImportRun,
                    (GenesisImportRun.tenant_id == GenesisImportRecord.tenant_id)
                    & (GenesisImportRun.import_run_id == GenesisImportRecord.import_run_id),
                )
                .join(
                    GenesisImportSource,
                    (GenesisImportSource.tenant_id == GenesisImportRecord.tenant_id)
                    & (GenesisImportSource.import_run_id == GenesisImportRecord.import_run_id)
                    & (GenesisImportSource.source_id == GenesisImportRecord.source_id),
                )
                .where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == import_run_id,
                    GenesisImportRecord.import_record_id == import_record_id,
                    GenesisImportRecord.source_id == source_id,
                    GenesisImportRecord.processing_state == "planned",
                    GenesisImportRecord.nomination_sha256 == nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key == nomination_idempotency_key,
                    GenesisImportRun.plan_sha256 == plan_sha256,
                    GenesisImportSource.source_path == source_path,
                    GenesisImportSource.blob_object_id == blob_object_id,
                    GenesisImportSource.raw_sha256 == raw_sha256,
                )
            )
        ).one_or_none()
        if row is None:
            raise GenesisImportStorageError("planned_record_context_mismatch")
        actual_mapping_sha256 = hashlib.sha256(canonical_json_bytes(row.mapping_metadata)).digest()
        if actual_mapping_sha256 != mapping_metadata_sha256:
            raise GenesisImportStorageError("planned_record_mapping_mismatch")
        return PendingGenesisRecord(
            import_record_id=row.import_record_id,
            source_id=row.source_id,
            nomination_sha256=bytes(row.nomination_sha256),
            nomination_idempotency_key=row.nomination_idempotency_key,
        )

    async def stage_import_plan(
        self,
        *,
        run: GenesisImportRun,
        sources: tuple[GenesisImportSource, ...],
        records: tuple[GenesisImportRecord, ...],
        exclusions: tuple[GenesisImportExclusion, ...],
        supersessions: tuple[GenesisImportSupersession, ...],
    ) -> GenesisRunStatus:
        """Atomically archive one exact protected plan without returning content."""

        if (
            len(run.plan_sha256) != 32
            or len(run.canonical_mapping_sha256) != 32
            or run.source_count != len(sources)
        ):
            raise GenesisImportStorageError("invalid_import_plan")
        _verify_plan_digest(run, sources, records, exclusions, supersessions)
        tenant_id = run.tenant_id
        import_run_id = run.import_run_id
        source_ids = {source.source_id for source in sources}
        record_ids = {record.import_record_id for record in records}
        exclusion_ids = {exclusion.exclusion_id for exclusion in exclusions}
        if len(source_ids) != len(sources) or len(record_ids) != len(records):
            raise GenesisImportStorageError("duplicate_plan_identity")
        if len(exclusion_ids) != len(exclusions):
            raise GenesisImportStorageError("duplicate_plan_identity")
        if any(
            source.tenant_id != tenant_id or source.import_run_id != import_run_id
            for source in sources
        ):
            raise GenesisImportStorageError("source_plan_mismatch")
        if any(
            record.tenant_id != tenant_id
            or record.import_run_id != import_run_id
            or record.source_id not in source_ids
            or record.processing_state != "planned"
            or record.selection_decision_id is not None
            or record.event_id is not None
            or record.memory_id is not None
            or record.processed_at is not None
            for record in records
        ):
            raise GenesisImportStorageError("record_plan_mismatch")
        if any(
            exclusion.tenant_id != tenant_id
            or exclusion.import_run_id != import_run_id
            or exclusion.source_id not in source_ids
            or (
                exclusion.applies_to_record_id is not None
                and exclusion.applies_to_record_id not in record_ids
            )
            for exclusion in exclusions
        ):
            raise GenesisImportStorageError("exclusion_plan_mismatch")
        if any(
            edge.tenant_id != tenant_id
            or edge.import_run_id != import_run_id
            or edge.source_id not in source_ids
            or (
                edge.predecessor_record_id is not None
                and edge.predecessor_record_id not in record_ids
            )
            or (edge.successor_record_id is not None and edge.successor_record_id not in record_ids)
            or (
                edge.predecessor_exclusion_id is not None
                and edge.predecessor_exclusion_id not in exclusion_ids
            )
            or (
                edge.successor_exclusion_id is not None
                and edge.successor_exclusion_id not in exclusion_ids
            )
            for edge in supersessions
        ):
            raise GenesisImportStorageError("supersession_plan_mismatch")
        corrected_sources = {
            source.source_id
            for source in sources
            if source.compatibility_correction_version is not None
        }
        if corrected_sources:
            corrected_record_ids = {
                record.source_item_identity
                for record in records
                if record.source_id in corrected_sources and record.record_kind == "candidate"
            }
            corrected_exclusion_ids = {
                exclusion.source_exclusion_identity
                for exclusion in exclusions
                if exclusion.source_id in corrected_sources
            }
            if (
                "candidate-0b388348-39d8-46da-b78c-956dbe1e02e5" not in corrected_record_ids
                or not {
                    "exclusion-dca9d34c-7b22-4ce2-885d-e3ba8f1c4f54",
                    "exclusion-087d1403-46ed-43d3-93e2-14e5bbf3794c",
                }
                <= corrected_exclusion_ids
            ):
                raise GenesisImportStorageError("compatibility_identity_mismatch")

        existing_run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.plan_sha256 == run.plan_sha256,
            )
        )
        if existing_run is not None:
            return await self._verified_existing_plan(
                existing_run=existing_run,
                requested_run=run,
                sources=sources,
                records=records,
                exclusions=exclusions,
                supersessions=supersessions,
            )
        conflicting_plan = await self._session.scalar(
            select(GenesisImportRun.import_run_id).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.source_repository == run.source_repository,
                GenesisImportRun.snapshot_commit == run.snapshot_commit,
                GenesisImportRun.mapping_version == run.mapping_version,
            )
        )
        if conflicting_plan is not None:
            raise GenesisImportStorageError("import_plan_conflict")

        try:
            async with self._session.begin_nested():
                self._session.add(run)
                await self._session.flush()
                self._session.add_all(sources)
                await self._session.flush()
                self._session.add_all(records)
                await self._session.flush()
                self._session.add_all(exclusions)
                await self._session.flush()
                self._session.add_all(supersessions)
                await self._session.flush()
        except IntegrityError:
            raced_run = await self._session.scalar(
                select(GenesisImportRun).where(
                    GenesisImportRun.tenant_id == tenant_id,
                    GenesisImportRun.plan_sha256 == run.plan_sha256,
                )
            )
            if raced_run is None:
                raise GenesisImportStorageError("import_plan_conflict") from None
            return await self._verified_existing_plan(
                existing_run=raced_run,
                requested_run=run,
                sources=sources,
                records=records,
                exclusions=exclusions,
                supersessions=supersessions,
            )
        return GenesisRunStatus(
            import_run_id=import_run_id,
            plan_sha256=bytes(run.plan_sha256),
            canonical_mapping_sha256=bytes(run.canonical_mapping_sha256),
            source_count=len(sources),
            planned_record_count=len(records),
            terminal_record_count=0,
            completed=False,
        )

    async def terminalize_record(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        import_record_id: UUID,
        nomination_sha256: bytes,
        outcome: GenesisTerminalOutcome,
        selection_decision_id: UUID,
        event_id: UUID | None = None,
        memory_id: UUID | None = None,
        processed_at: datetime,
    ) -> GenesisRecordStatus:
        if len(nomination_sha256) != 32:
            raise GenesisImportStorageError("invalid_nomination_digest")
        linked = event_id is not None and memory_id is not None
        if (outcome == "candidate") != linked or ((event_id is None) != (memory_id is None)):
            raise GenesisImportStorageError("invalid_terminal_result")

        result = await self._session.execute(
            update(GenesisImportRecord)
            .where(
                GenesisImportRecord.tenant_id == tenant_id,
                GenesisImportRecord.import_run_id == import_run_id,
                GenesisImportRecord.import_record_id == import_record_id,
                GenesisImportRecord.nomination_sha256 == nomination_sha256,
                GenesisImportRecord.processing_state == "planned",
            )
            .values(
                processing_state=outcome,
                selection_decision_id=selection_decision_id,
                event_id=event_id,
                memory_id=memory_id,
                processed_at=processed_at,
            )
        )
        if cast(CursorResult[Any], result).rowcount == 1:
            return GenesisRecordStatus(
                import_record_id=import_record_id,
                processing_state=outcome,
                selection_decision_id=selection_decision_id,
                event_id=event_id,
                memory_id=memory_id,
                processed_at=processed_at,
            )

        row = await self._session.scalar(
            select(GenesisImportRecord).where(
                GenesisImportRecord.tenant_id == tenant_id,
                GenesisImportRecord.import_run_id == import_run_id,
                GenesisImportRecord.import_record_id == import_record_id,
            )
        )
        if row is None:
            raise GenesisImportStorageError("import_record_not_found")
        if bytes(row.nomination_sha256) != nomination_sha256:
            raise GenesisImportStorageError("import_plan_mismatch")
        status = _record_status(row)
        expected = GenesisRecordStatus(
            import_record_id=import_record_id,
            processing_state=outcome,
            selection_decision_id=selection_decision_id,
            event_id=event_id,
            memory_id=memory_id,
            processed_at=processed_at,
        )
        if status != expected:
            raise GenesisImportStorageError("terminal_result_conflict")
        return status

    async def pending_records(
        self, *, tenant_id: UUID, import_run_id: UUID, limit: int = 500
    ) -> tuple[PendingGenesisRecord, ...]:
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise GenesisImportStorageError("invalid_limit")
        rows = (
            await self._session.execute(
                select(
                    GenesisImportRecord.import_record_id,
                    GenesisImportRecord.source_id,
                    GenesisImportRecord.nomination_sha256,
                    GenesisImportRecord.nomination_idempotency_key,
                )
                .where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == import_run_id,
                    GenesisImportRecord.processing_state == "planned",
                )
                .order_by(GenesisImportRecord.import_record_id)
                .limit(limit)
            )
        ).all()
        return tuple(
            PendingGenesisRecord(record_id, source_id, bytes(digest), idempotency_key)
            for record_id, source_id, digest, idempotency_key in rows
        )

    async def run_status(self, *, tenant_id: UUID, plan_sha256: bytes) -> GenesisRunStatus | None:
        if len(plan_sha256) != 32:
            raise GenesisImportStorageError("invalid_plan_digest")
        run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.plan_sha256 == plan_sha256,
            )
        )
        if run is None:
            return None
        planned, terminal = (
            await self._session.execute(
                select(
                    func.count().filter(GenesisImportRecord.processing_state == "planned"),
                    func.count().filter(GenesisImportRecord.processing_state != "planned"),
                ).where(
                    GenesisImportRecord.tenant_id == tenant_id,
                    GenesisImportRecord.import_run_id == run.import_run_id,
                )
            )
        ).one()
        completed = await self._session.scalar(
            select(GenesisImportRunResult.import_run_id).where(
                GenesisImportRunResult.tenant_id == tenant_id,
                GenesisImportRunResult.import_run_id == run.import_run_id,
            )
        )
        return GenesisRunStatus(
            import_run_id=run.import_run_id,
            plan_sha256=bytes(run.plan_sha256),
            canonical_mapping_sha256=bytes(run.canonical_mapping_sha256),
            source_count=run.source_count,
            planned_record_count=int(planned),
            terminal_record_count=int(terminal),
            completed=completed is not None,
        )

    async def _verified_completion_counts(
        self, *, tenant_id: UUID, import_run_id: UUID
    ) -> tuple[int, int, int]:
        records = tuple(
            (
                await self._session.scalars(
                    select(GenesisImportRecord).where(
                        GenesisImportRecord.tenant_id == tenant_id,
                        GenesisImportRecord.import_run_id == import_run_id,
                    )
                )
            ).all()
        )
        if not records or any(record.processing_state == "planned" for record in records):
            raise GenesisImportStorageError("import_plan_incomplete")
        decision_ids = tuple(
            record.selection_decision_id
            for record in records
            if record.selection_decision_id is not None
        )
        decisions = {
            row.decision_id: row
            for row in (
                await self._session.scalars(
                    select(SelectionDecision).where(
                        SelectionDecision.tenant_id == tenant_id,
                        SelectionDecision.decision_id.in_(decision_ids),
                    )
                )
            ).all()
        }
        receipt_rows = tuple(
            (
                await self._session.scalars(
                    select(CommandReceipt).where(
                        CommandReceipt.tenant_id == tenant_id,
                        CommandReceipt.selection_decision_id.in_(decision_ids),
                    )
                )
            ).all()
        )
        receipts_by_decision: dict[UUID, list[CommandReceipt]] = {}
        for receipt in receipt_rows:
            if receipt.selection_decision_id is not None:
                receipts_by_decision.setdefault(receipt.selection_decision_id, []).append(receipt)
        event_ids = tuple(record.event_id for record in records if record.event_id is not None)
        memory_ids = tuple(record.memory_id for record in records if record.memory_id is not None)
        events = {
            row.event_id: row
            for row in (
                await self._session.scalars(
                    select(MemoryEvent).where(
                        MemoryEvent.tenant_id == tenant_id,
                        MemoryEvent.event_id.in_(event_ids),
                    )
                )
            ).all()
        }
        memories = {
            row.memory_id: row
            for row in (
                await self._session.scalars(
                    select(Memory).where(
                        Memory.tenant_id == tenant_id,
                        Memory.memory_id.in_(memory_ids),
                    )
                )
            ).all()
        }

        for record in records:
            decision_id = record.selection_decision_id
            if decision_id is None:
                raise GenesisImportStorageError("completion_linkage_mismatch")
            decision = decisions.get(decision_id)
            receipts = receipts_by_decision.get(decision_id, [])
            if (
                decision is None
                or len(receipts) != 1
                or decision.source_kind != "genesis_import"
                or decision.requested_operation != "nominate"
                or decision.selection_basis != "imported_legacy"
                or decision.outcome != record.processing_state
                or decision.lineage_id != record.lineage_id
                or decision.branch_id != record.branch_id
                or decision.event_id != record.event_id
                or decision.memory_id != record.memory_id
            ):
                raise GenesisImportStorageError("completion_linkage_mismatch")
            receipt = receipts[0]
            if (
                receipt.idempotency_key != record.nomination_idempotency_key
                or receipt.event_id != record.event_id
                or receipt.memory_id != record.memory_id
            ):
                raise GenesisImportStorageError("completion_linkage_mismatch")
            if record.processing_state == "candidate":
                if record.event_id is None or record.memory_id is None:
                    raise GenesisImportStorageError("completion_linkage_mismatch")
                event = events.get(record.event_id)
                memory = memories.get(record.memory_id)
                if (
                    event is None
                    or memory is None
                    or event.lineage_id != record.lineage_id
                    or event.branch_id != record.branch_id
                    or event.memory_id != record.memory_id
                    or event.idempotency_key != record.nomination_idempotency_key
                    or event.operation != "observed"
                    or memory.lineage_id != record.lineage_id
                    or memory.branch_id != record.branch_id
                    or memory.status != "candidate"
                    or memory.last_event_id != record.event_id
                ):
                    raise GenesisImportStorageError("completion_linkage_mismatch")

        return (
            sum(record.processing_state == "candidate" for record in records),
            sum(record.processing_state == "omit" for record in records),
            sum(record.processing_state == "reject" for record in records),
        )

    async def complete_run(
        self,
        *,
        tenant_id: UUID,
        import_run_id: UUID,
        plan_sha256: bytes,
        pre_state_sha256: bytes,
        backup_reference: str,
        replay_verified: bool,
        completed_at: datetime,
    ) -> GenesisRunResultStatus:
        if len(plan_sha256) != 32 or len(pre_state_sha256) != 32:
            raise GenesisImportStorageError("invalid_completion_digest")
        run = await self._session.scalar(
            select(GenesisImportRun).where(
                GenesisImportRun.tenant_id == tenant_id,
                GenesisImportRun.import_run_id == import_run_id,
                GenesisImportRun.plan_sha256 == plan_sha256,
            )
        )
        if run is None:
            raise GenesisImportStorageError("import_plan_not_found")
        if (
            bytes(run.pre_state_sha256) != pre_state_sha256
            or run.backup_reference != backup_reference
        ):
            raise GenesisImportStorageError("recovery_evidence_mismatch")
        if not replay_verified:
            raise GenesisImportStorageError("replay_not_verified")
        candidate_count, omit_count, reject_count = await self._verified_completion_counts(
            tenant_id=tenant_id, import_run_id=import_run_id
        )
        planned_record_count = candidate_count + omit_count + reject_count

        existing = await self._session.get(
            GenesisImportRunResult,
            {"tenant_id": tenant_id, "import_run_id": import_run_id},
        )
        if existing is not None:
            if (
                existing.planned_record_count != planned_record_count
                or existing.candidate_count != candidate_count
                or existing.omit_count != omit_count
                or existing.reject_count != reject_count
                or not existing.replay_verified
            ):
                raise GenesisImportStorageError("completion_result_conflict")
            return GenesisRunResultStatus(
                import_run_id=existing.import_run_id,
                planned_record_count=existing.planned_record_count,
                candidate_count=existing.candidate_count,
                omit_count=existing.omit_count,
                reject_count=existing.reject_count,
                replay_verified=existing.replay_verified,
                completed_at=existing.completed_at,
            )

        await self._session.execute(
            insert(GenesisImportRunResult).values(
                tenant_id=tenant_id,
                import_run_id=import_run_id,
                planned_record_count=planned_record_count,
                candidate_count=candidate_count,
                omit_count=omit_count,
                reject_count=reject_count,
                replay_verified=True,
                completed_at=completed_at,
            )
        )
        return GenesisRunResultStatus(
            import_run_id=import_run_id,
            planned_record_count=planned_record_count,
            candidate_count=candidate_count,
            omit_count=omit_count,
            reject_count=reject_count,
            replay_verified=True,
            completed_at=completed_at,
        )
